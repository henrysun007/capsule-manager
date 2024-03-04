// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{storage_engine::StorageEngine, DataMeta, PolicyMeta};
use crate::core::model;
use crate::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use crate::{cm_assert, errno, return_errno};
use capsule_manager_tonic::secretflowapis::v2::sdc::capsule_manager::*;
use log::warn;
use sled::Db;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tonic::async_trait;

const DATA_POLICY_PATH: &str = "data_policy";
const DATA_KEY_PATH: &str = "data_key";
const PUBLIC_KEY_PATH: &str = "public_key";
// To run on occlum, ROOT_PATH should be in the encrypted file system
const ROOT_PATH: &str = "/db";

/// local file system storage implementation
// The lock is to keep consistent with that of InMemoryStorage
#[derive(Debug)]
pub struct LocalFsStorage {
    /// key: scope/data_uuid
    /// value: PolicyMeta
    data_policy: Arc<Mutex<Db>>,
    /// key: data_uuid
    /// value: DataMeta
    data_key: Arc<Mutex<Db>>,
    /// key: party_id
    /// value: String, public key
    public_key: Arc<Mutex<Db>>,
}

impl Default for LocalFsStorage {
    fn default() -> Self {
        let policy_db = sled::open(Path::new(ROOT_PATH).join(DATA_POLICY_PATH)).unwrap();
        let data_policy = Arc::new(Mutex::new(policy_db));

        let key_db = sled::open(Path::new(ROOT_PATH).join(DATA_KEY_PATH)).unwrap();
        let data_key = Arc::new(Mutex::new(key_db));

        let public_key_db = sled::open(Path::new(ROOT_PATH).join(PUBLIC_KEY_PATH)).unwrap();
        let public_key = Arc::new(Mutex::new(public_key_db));

        Self {
            data_policy,
            data_key,
            public_key,
        }
    }
}

fn dfs(
    data_uuid: Arc<String>,
    data_keys: &Db,
    result: &mut HashSet<String>,
    visited: &mut HashSet<Arc<String>>,
) -> AuthResult<()> {
    let data_meta_raw = data_keys.get(&*data_uuid)?.ok_or(errno!(
        ErrorCode::NotFound,
        "data_uuid {} has be not stored",
        data_uuid
    ))?;
    if visited.contains(&*data_uuid) {
        return Ok(());
    }
    visited.insert(data_uuid);

    let data_meta: DataMeta = serde_json::from_slice(&data_meta_raw)?;
    if data_meta.parents.is_empty() {
        result.insert(data_meta.party_id.clone());
    }
    for parent_data_uuid in data_meta.parents.iter() {
        let data_uuid = Arc::new(parent_data_uuid.clone());
        dfs(data_uuid, data_keys, result, visited)?;
    }
    Ok(())
}

#[async_trait]
impl StorageEngine for LocalFsStorage {
    async fn store_data_keys(
        &self,
        owner_party_id: &str,
        data_keys: &Vec<DataKey>,
    ) -> AuthResult<()> {
        let data_key_map = self.data_key.lock().unwrap();
        // judge whether data_key has ready existed in data_key vector
        for data_key in data_keys.iter() {
            let resource_uri_inner: model::ResourceUri = data_key.resource_uri.parse()?;
            let data =
                if let Some(data_meta_bytes) = data_key_map.get(&resource_uri_inner.data_uuid)? {
                    let mut data_meta: DataMeta = serde_json::from_slice(&data_meta_bytes)?;
                    cm_assert!(
                        data_meta.party_id == owner_party_id,
                        "party_id {} is wrong",
                        owner_party_id
                    );
                    data_meta
                        .data_keys
                        .contains_key(&data_key.resource_uri)
                        .then(|| {
                            warn!(
                                "resource_uri {} data_key will be overwrite",
                                &data_key.resource_uri
                            );
                        });
                    data_meta.data_keys.insert(
                        data_key.resource_uri.to_string(),
                        data_key.data_key_b64.clone(),
                    );

                    data_meta.party_id = owner_party_id.to_string();
                    data_meta
                } else {
                    let mut data_keys = HashMap::new();
                    data_keys.insert(
                        data_key.resource_uri.to_string(),
                        data_key.data_key_b64.clone(),
                    );

                    DataMeta {
                        data_keys,
                        party_id: owner_party_id.to_string(),
                        parents: vec![],
                    }
                };

            data_key_map.insert(
                resource_uri_inner.data_uuid,
                serde_json::to_string(&data)?.as_str(),
            )?;
        }
        Ok(())
    }

    async fn store_data_key(
        &self,
        resource_uri: &str,
        owner_party_id: &str,
        data_key: &str,
        ancestor_uuids: &Vec<String>,
    ) -> AuthResult<()> {
        let data_key_map = self.data_key.lock().unwrap();
        let resource_uri_inner: model::ResourceUri = resource_uri.parse()?;
        let data = if let Some(data_meta_bytes) = data_key_map.get(&resource_uri_inner.data_uuid)? {
            let mut data_meta: DataMeta = serde_json::from_slice(&data_meta_bytes)?;
            cm_assert!(
                data_meta.party_id == owner_party_id,
                "party_id {} is wrong",
                owner_party_id
            );
            data_meta
                .data_keys
                .insert(resource_uri.to_string(), data_key.to_string());

            data_meta.party_id = owner_party_id.to_string();

            data_meta.parents.append(&mut ancestor_uuids.clone());
            data_meta.parents.sort();
            data_meta.parents.dedup();

            data_meta
        } else {
            let mut data_keys = HashMap::new();
            data_keys.insert(resource_uri.to_string(), data_key.to_string());

            DataMeta {
                data_keys,
                party_id: owner_party_id.to_string(),
                parents: ancestor_uuids.clone(),
            }
        };

        data_key_map.insert(
            resource_uri_inner.data_uuid,
            serde_json::to_string(&data)?.as_str(),
        )?;
        Ok(())
    }

    // the func will verify whether owner_party_id is the real owner
    async fn delete_data_key(&self, owner_party_id: &str, resource_uri: &str) -> AuthResult<()> {
        let data_key_map = self.data_key.lock().unwrap();
        let resource_uri_inner: model::ResourceUri = resource_uri.parse()?;
        if let Some(data_meta_bytes) = data_key_map.get(&resource_uri_inner.data_uuid)? {
            let mut data_meta: DataMeta = serde_json::from_slice(&data_meta_bytes)?;
            cm_assert!(
                data_meta.party_id == owner_party_id,
                "party_id {} is wrong",
                owner_party_id,
            );
            data_meta.data_keys.remove(resource_uri);
            data_key_map.insert(
                &resource_uri_inner.data_uuid,
                serde_json::to_string(&data_meta)?.as_str(),
            )?;
        }
        Ok(())
    }

    async fn get_data_keys(&self, resource_uris: &Vec<&str>) -> AuthResult<Vec<DataKey>> {
        let data_key_map = self.data_key.lock().unwrap();
        // collect data keys
        let mut result = vec![];
        for resource_uri in resource_uris.iter() {
            let resource_uri_inner: model::ResourceUri = resource_uri.parse()?;
            if let Some(data_meta_bytes) = data_key_map.get(&resource_uri_inner.data_uuid)? {
                let data_meta: DataMeta = serde_json::from_slice(&data_meta_bytes)?;
                if let Some(data_key_b64) = data_meta.data_keys.get(*resource_uri) {
                    result.push(DataKey {
                        resource_uri: resource_uri.to_string(),
                        data_key_b64: data_key_b64.clone(),
                    });
                }
            }
        }
        if result.is_empty() {
            return_errno!(ErrorCode::NotFound, "data_keys not found.");
        }
        Ok(result)
    }

    async fn get_data_party(&self, resource_uri: &str) -> AuthResult<String> {
        let data_key_map = self.data_key.lock().unwrap();
        let data_meta_bytes = data_key_map
            .get(resource_uri)?
            .ok_or(errno!(ErrorCode::NotFound, "party id is not existed"))?;
        let data_meta: DataMeta = serde_json::from_slice(&data_meta_bytes)?;
        Ok(data_meta.party_id)
    }

    async fn add_data_rule(
        &self,
        owner_party_id: &str,
        scope: &str,
        data_uuid: &str,
        rule: &Rule,
    ) -> AuthResult<()> {
        let key = format!("{}/{}", scope, data_uuid);
        let data_policy_map = self.data_policy.lock().unwrap();
        let policy = if !data_policy_map.contains_key(&key)? {
            PolicyMeta {
                policy: Policy {
                    data_uuid: data_uuid.to_string(),
                    rules: vec![rule.clone()],
                },
                scope: scope.to_string(),
                party_id: owner_party_id.to_string(),
            }
        } else {
            let policy_meta_bytes = data_policy_map.get(&key)?.unwrap();
            let mut policy_meta: PolicyMeta = serde_json::from_slice(&policy_meta_bytes)?;
            cm_assert!(policy_meta.party_id == owner_party_id, "party_id is wrong");
            cm_assert!(
                policy_meta.policy.data_uuid == data_uuid,
                "data_uuid is wrong"
            );
            policy_meta.policy.rules.push(rule.clone());
            policy_meta
        };

        data_policy_map.insert(&key, serde_json::to_string(&policy)?.as_str())?;
        Ok(())
    }

    async fn delete_data_rule(
        &self,
        owner_party_id: &str,
        scope: &str,
        data_uuid: &str,
        rule_id: &str,
    ) -> AuthResult<()> {
        let key = format!("{}/{}", scope, data_uuid);
        let data_policy_map = self.data_policy.lock().unwrap();
        // judge whether data_policy has existed
        if !data_policy_map.contains_key(&key)? {
            warn!(
                "party_id {} scope {} policy has not stored.",
                owner_party_id, scope
            );
        } else {
            let policy_meta_bytes = data_policy_map.get(&key)?.unwrap();
            let mut policy_meta: PolicyMeta = serde_json::from_slice(&policy_meta_bytes)?;
            cm_assert!(policy_meta.party_id == owner_party_id, "party_id is wrong");
            cm_assert!(
                policy_meta.policy.data_uuid == data_uuid,
                "data_uuid is wrong"
            );
            policy_meta
                .policy
                .rules
                .retain_mut(|x| x.rule_id != rule_id);
            data_policy_map.insert(&key, serde_json::to_string(&policy_meta)?.as_str())?;
        }
        Ok(())
    }

    async fn store_data_policy(
        &self,
        owner_party_id: &str,
        scope: &str,
        policy: &Policy,
    ) -> AuthResult<()> {
        let data_uuid = &policy.data_uuid;
        let key = format!("{}/{}", scope, data_uuid);
        let data_policy_map = self.data_policy.lock().unwrap();
        data_policy_map.contains_key(&key)?.then(|| {
            warn!(
                "data_uuid {} scope {} has policy, will be overwrite",
                data_uuid, scope
            )
        });
        let policy = PolicyMeta {
            policy: policy.clone(),
            party_id: owner_party_id.to_string(),
            scope: scope.to_string(),
        };
        data_policy_map.insert(&key, serde_json::to_string(&policy)?.as_str())?;
        Ok(())
    }

    async fn get_data_policys(&self, owner_party_id: &str, scope: &str) -> AuthResult<Vec<Policy>> {
        let data_policy_map = self.data_policy.lock().unwrap();
        let mut policy_vec = vec![];
        for result in data_policy_map.iter() {
            let (_, policy_meta_bytes) = result?;
            let policy_meta: PolicyMeta = serde_json::from_slice(&policy_meta_bytes)?;
            if policy_meta.scope == scope && policy_meta.party_id == owner_party_id {
                policy_vec.push(policy_meta.policy);
            }
        }
        Ok(policy_vec)
    }

    async fn get_data_policy_by_id(&self, data_uuid: &str, scope: &str) -> AuthResult<Policy> {
        let key = format!("{}/{}", scope, data_uuid);
        let data_policy_map = self.data_policy.lock().unwrap();
        let policy_meta_bytes = data_policy_map
            .get(&key)?
            .ok_or(errno!(ErrorCode::NotFound, "data policy is empty."))?;
        let policy_meta: PolicyMeta = serde_json::from_slice(&policy_meta_bytes)?;
        Ok(policy_meta.policy)
    }

    async fn delete_data_policy(
        &self,
        owner_party_id: &str,
        scope: &str,
        data_uuid: &str,
    ) -> AuthResult<()> {
        let key = format!("{}/{}", scope, data_uuid);
        let data_policy_map = self.data_policy.lock().unwrap();
        if !data_policy_map.contains_key(&key)? {
            warn!(
                "party_id {} scope {} policy has not stored.",
                owner_party_id, scope
            );
        } else {
            let policy_meta_bytes = data_policy_map.get(&key)?.unwrap();
            let policy_meta: PolicyMeta = serde_json::from_slice(&policy_meta_bytes)?;
            cm_assert!(policy_meta.party_id == owner_party_id, "party_id is wrong");
            cm_assert!(
                policy_meta.policy.data_uuid == data_uuid,
                "data_uuid is wrong"
            );
            data_policy_map.remove(&key)?;
        }
        Ok(())
    }

    async fn get_policy_party_by_id(&self, data_uuid: &str, scope: &str) -> AuthResult<String> {
        let key = format!("{}/{}", scope, data_uuid);
        let data_policy_map = self.data_policy.lock().unwrap();
        let policy_meta_bytes = data_policy_map
            .get(&key)?
            .ok_or(errno!(ErrorCode::NotFound, "data policy is empty."))?;
        let policy_meta: PolicyMeta = serde_json::from_slice(&policy_meta_bytes)?;
        Ok(policy_meta.party_id)
    }

    async fn get_original_parties(&self, data_uuid: &str) -> AuthResult<Vec<String>> {
        let mut visited: HashSet<Arc<String>> = HashSet::new();
        let mut result: HashSet<String> = HashSet::new();
        let data_key_map = self.data_key.lock().unwrap();
        dfs(
            Arc::new(data_uuid.to_owned()),
            &data_key_map,
            &mut result,
            &mut visited,
        )?;
        Ok(result.into_iter().collect())
    }

    async fn store_public_key(&self, owner_party_id: &str, public_key: &str) -> AuthResult<()> {
        let public_key_map = self.public_key.lock().unwrap();
        (!public_key_map.contains_key(owner_party_id)?)
            .then(|| 0)
            .ok_or(errno!(
                ErrorCode::AlreadyExists,
                "party_id {} public_key has stored.",
                owner_party_id
            ))?;
        public_key_map.insert(owner_party_id, public_key)?;
        Ok(())
    }

    async fn get_public_key(&self, owner_party_id: &str) -> AuthResult<String> {
        let public_key_map = self.public_key.lock().unwrap();
        if let Some(public_key_bytes) = public_key_map.get(owner_party_id)? {
            let public_key = String::from_utf8(public_key_bytes.as_ref().to_vec())?;
            return Ok(public_key);
        } else {
            return_errno!(
                ErrorCode::NotFound,
                "party_id {} public_key has not stored.",
                owner_party_id
            );
        }
    }
}
