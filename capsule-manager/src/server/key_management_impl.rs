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

use super::CapsuleManagerImpl;
use crate::server::constant::SEPARATOR;
use capsule_manager::core::model;
use capsule_manager::core::model::policy;
use capsule_manager::core::model::request::TeeIdentity;
use capsule_manager::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use capsule_manager::proto::{
    CreateDataKeysRequest, CreateResultDataKeyRequest, DeleteDataKeyRequest, EncryptedRequest,
    EncryptedResponse, GetDataKeysRequest, GetDataKeysResponse, GetExportDataKeyRequest,
    GetExportDataKeyResponse, RegisterCertRequest,
};
use capsule_manager::remote_attestation::unified_attestation_wrapper::runified_attestation_verify_auth_report;
use capsule_manager::utils::jwt::jwa::Secret;
use capsule_manager::utils::tool::{
    get_public_key_from_cert_chain, sha256, vec_str_to_vec_u8, verify_cert_chain,
};
use capsule_manager::utils::type_convert::from;
use capsule_manager::{cm_assert, errno, proto, return_errno};
use capsule_manager_tonic::secretflowapis::v2::sdc::{
    UnifiedAttestationAttributes, UnifiedAttestationPolicy,
};
use capsule_manager_tonic::secretflowapis::v2::{Code, Status};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hex::encode_upper;
use prost::Message;
use serde_json::json;
use verifier::{to_verifier, InitDataHash, ReportData};

pub async fn ra_verify(request: &GetDataKeysRequest) -> AuthResult<()> {
    // NOTICE: hex must be uppercase
    let resource_request = request
        .resource_request
        .as_ref()
        .ok_or(errno!(ErrorCode::InvalidArgument, "request is empty"))?;

    // get report data
    let data = [
        request.cert.as_bytes(),
        resource_request.encode_to_vec().as_ref(),
    ]
    .join(SEPARATOR.as_bytes());
    let hex_report_data = encode_upper(sha256(&data));

    let ua_report = if let Some(report) = &request.attestation_report {
        report
    } else {
        return_errno!(ErrorCode::InternalErr, "No attestation report is found");
    };

    if ua_report.str_report_type != "JD" {
        return_errno!(ErrorCode::InvalidArgument, "report type is not JD");
    };

    if ua_report.str_tee_platform != "SGX_DCAP" {
        return_errno!(ErrorCode::InvalidArgument, "tee platform is not SGX_DCAP");
    };

    let evidence = json!({"quote": ua_report.json_report});

    let coco_verifier = to_verifier(&kbs_types::Tee::Sgx).map_err(|e| {
        errno!(
            ErrorCode::InternalErr,
            "failed to get the sgx verifier: {:?}",
            e
        )
    })?;
    let claims = coco_verifier
        .evaluate(
            &serde_json::to_vec(&evidence)?,
            &ReportData::Value(hex_report_data.as_bytes()),
            &InitDataHash::NotProvided,
        )
        .await
        .map_err(|e| errno!(ErrorCode::InternalErr, "quote verification failed: {:?}", e))?;

    // get mr info
    let resource_request_innner: model::request::ResourceRequest = from(&resource_request)?;
    if let Some(env) = resource_request_innner.global_attributes.env {
        if let Some(tee) = env.tee {
            match tee {
                TeeIdentity::SGX {
                    mr_enclave,
                    mr_signer,
                } => {
                    if claims["mr_enclave"] != mr_enclave {
                        return_errno!(ErrorCode::InvalidArgument, "mr_enclaves mismatch");
                    };
                    if claims["mr_signer"] != mr_signer {
                        return_errno!(ErrorCode::InvalidArgument, "mr_signers mismatch");
                    };
                }
                _ => return_errno!(ErrorCode::InvalidArgument, "env tee field invalid"),
            };
        }
    }

    Ok(())
}

impl CapsuleManagerImpl {
    pub async fn get_data_keys_impl(
        &self,
        encrypt_request: &EncryptedRequest,
    ) -> AuthResult<EncryptedResponse> {
        let (request_content, _) =
            super::get_request::<GetDataKeysRequest>(&self.kek_pri, encrypt_request)?;
        // 1. verify RA
        if self.mode == "production" {
            ra_verify(&request_content).await?;
        }

        // 2. enforce data policy
        let resource_request_innner: model::request::ResourceRequest =
            from(&request_content.resource_request)?;
        log::debug!("resource request {:?}", resource_request_innner);

        // each resource uri should follow data policy
        for single_request in resource_request_innner.iter() {
            let resource_uri: model::ResourceUri = single_request.resource_uri.parse()?;
            let ref scope = single_request.global_attributes.scope;
            // judge whether the owner of data key is equal to the owner of data policy
            let data_key_party = self
                .storage_engine
                .get_data_party(&single_request.resource_uri)
                .await?;
            let policy_party = self
                .storage_engine
                .get_policy_party_by_id(&resource_uri.data_uuid, &scope)
                .await?;
            cm_assert!(
                data_key_party == policy_party,
                "the owner of data key {} != the owner of data policy {}",
                &data_key_party,
                &policy_party
            );

            // execute data policy
            let policy = self
                .storage_engine
                .get_data_policy_by_id(&resource_uri.data_uuid, scope)
                .await?;
            let policy_inner: policy::Policy = from(&policy)?;
            self.policy_enforcer
                .enforce(&single_request, &policy_inner)?;
        }

        // 3. query data key
        let resource_uris: Vec<&str> = resource_request_innner
            .iter()
            .map(|x| x.resource_uri.as_str())
            .collect();

        let data_keys = self.storage_engine.get_data_keys(&resource_uris).await?;

        let response = GetDataKeysResponse {
            data_keys,
            // FIXME: change to certificate
            cert: String::from_utf8(self.kek_cert.to_owned())?,
        };
        let secret = Secret::public_key_from_cert_pem(request_content.cert.as_bytes())?;
        super::encrypt_response(secret, &response)
    }

    pub async fn create_data_keys_impl(
        &self,
        encrypt_request: &EncryptedRequest,
    ) -> AuthResult<EncryptedResponse> {
        let (request_content, jws) =
            super::get_request::<CreateDataKeysRequest>(&self.kek_pri, encrypt_request)?;
        let jws = jws.ok_or(errno!(ErrorCode::InvalidArgument, "Missing signature"))?;
        // NOTE: Here, we assume the `x5c` of JWS is filled a public key.
        // We will support to read a public key from a data source also.
        super::verify_signature(&request_content.owner_party_id, None, &jws)?;

        self.storage_engine
            .store_data_keys(&request_content.owner_party_id, &request_content.data_keys)
            .await?;

        Ok(EncryptedResponse {
            status: Some(Status {
                code: Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            message: None,
        })
    }

    pub async fn delete_data_key_impl(
        &self,
        encrypt_request: &EncryptedRequest,
    ) -> AuthResult<EncryptedResponse> {
        let (request_content, jws) =
            super::get_request::<DeleteDataKeyRequest>(&self.kek_pri, encrypt_request)?;
        let jws = jws.ok_or(errno!(ErrorCode::InvalidArgument, "Missing signature"))?;
        // NOTE: Here, we assume the `x5c` of JWS is filled a public key.
        // We will support to read a public key from a data source also.
        super::verify_signature(&request_content.owner_party_id, None, &jws)?;

        self.storage_engine
            .delete_data_key(
                &request_content.owner_party_id,
                &request_content.resource_uri,
            )
            .await?;

        Ok(EncryptedResponse {
            status: Some(Status {
                code: Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            message: None,
        })
    }

    pub async fn get_export_data_key_impl(
        &self,
        encrypt_request: &EncryptedRequest,
    ) -> AuthResult<EncryptedResponse> {
        let (request_content, jws) =
            super::get_request::<GetExportDataKeyRequest>(&self.kek_pri, encrypt_request)?;
        let jws = jws.ok_or(errno!(ErrorCode::InvalidArgument, "Missing signature"))?;
        // NOTE: Here, we assume the `x5c` of JWS is filled a public key.
        // We will support to read a public key from a data source also.
        super::verify_signature(&request_content.request_party_id, None, &jws)?;

        log::info!("Start to verify vote result");
        // 1. verify identifier
        let vote_result: model::request::VoteResult =
            serde_json::from_str(&request_content.data_export_certificate)?;
        vote_result.verify_identifier(&request_content.request_party_id)?;

        // 2. verify signature
        vote_result.verify_request(&request_content.resource_uri)?;

        // 3. verify vote result
        let resource_uri: model::ResourceUri = request_content.resource_uri.parse()?;
        let ancestors = self
            .storage_engine
            .get_original_parties(&resource_uri.data_uuid)
            .await?;
        let other_ancestors: Vec<String> = ancestors
            .iter()
            .filter(|&x| *x != request_content.request_party_id)
            .cloned()
            .collect();
        log::info!("other_ancestors: {:?}", other_ancestors);
        vote_result.verify_vote(&other_ancestors)?;

        // 4. get data key
        let data_keys = self
            .storage_engine
            .get_data_keys(&vec![&request_content.resource_uri])
            .await?;
        let response = GetExportDataKeyResponse {
            data_key: data_keys.get(0).cloned(),
        };
        let secret = Secret::PublicKey(jws.public_key()?);
        super::encrypt_response(secret, &response)
    }

    pub async fn register_cert_impl(
        &self,
        encrypt_request: &EncryptedRequest,
    ) -> AuthResult<EncryptedResponse> {
        let (request_content, _) =
            super::get_request::<RegisterCertRequest>(&self.kek_pri, encrypt_request)?;
        cm_assert!(
            !request_content.certs.is_empty() && !request_content.owner_party_id.is_empty(),
            "certs or party_id is empty"
        );

        verify_cert_chain(&vec_str_to_vec_u8(&request_content.certs), "PEM")?;

        self.storage_engine
            .store_public_key(
                request_content.owner_party_id.as_str(),
                &String::from_utf8(
                    get_public_key_from_cert_chain(
                        &vec_str_to_vec_u8(&request_content.certs),
                        request_content.certs.len() - 1,
                        "PEM",
                    )?
                    .public_key_to_pem()?,
                )?,
            )
            .await?;
        Ok(EncryptedResponse {
            status: Some(Status {
                code: Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            message: None,
        })
    }

    pub async fn create_result_data_key_impl(
        &self,
        encrypt_request: &EncryptedRequest,
    ) -> AuthResult<EncryptedResponse> {
        let (request_content, _) =
            super::get_request::<CreateResultDataKeyRequest>(&self.kek_pri, encrypt_request)?;
        // 1. verify RA
        // NOTICE: hex must be uppercase
        let body = request_content
            .body
            .as_ref()
            .ok_or(errno!(ErrorCode::InvalidArgument, "request body is empty"))?;

        //  UAL verification
        if self.mode == "production" {
            let hex_report_data = encode_upper(sha256(body.encode_to_vec().as_slice()));
            // fill policy
            let mut attribute1 = UnifiedAttestationAttributes::default();
            attribute1.str_tee_platform = "SGX_DCAP".to_string();
            attribute1.bool_debug_disabled = "1".to_string();
            attribute1.hex_user_data = hex_report_data.clone();

            let policy = UnifiedAttestationPolicy {
                pem_public_key: "".to_owned(),
                main_attributes: vec![attribute1],
                nested_policies: vec![],
            };

            // UAL verification
            let str_policy = serde_json::to_string(&policy).map_err(|e| {
                errno!(
                    ErrorCode::InternalErr,
                    "report_policy {:?} to json err: {:?}",
                    &policy,
                    e
                )
            })?;
            let str_report =
                serde_json::to_string(&request_content.attestation_report).map_err(|e| {
                    errno!(
                        ErrorCode::InternalErr,
                        "report {:?} to json err: {:?}",
                        &request_content.attestation_report,
                        e
                    )
                })?;
            runified_attestation_verify_auth_report(str_report.as_str(), str_policy.as_str())?;
        }

        self.storage_engine
            .store_data_key(
                &body.resource_uri,
                &body.owner_id,
                &body.data_key_b64,
                &body.ancestor_uuids,
            )
            .await?;

        let mut policy = policy::Policy::default();
        let mut first = true;
        for ancestor_uuid in body.ancestor_uuids.iter() {
            let policy_right: policy::Policy = from(
                &self
                    .storage_engine
                    .get_data_policy_by_id(ancestor_uuid, &body.scope)
                    .await?,
            )?;
            if first {
                policy = policy_right;
                first = false;
            } else {
                policy = policy.merge(&policy_right);
            }
        }
        let mut policy: proto::Policy = from(&policy)?;
        let resource_uri: model::ResourceUri = body.resource_uri.parse()?;

        policy.data_uuid = resource_uri.data_uuid;
        self.storage_engine
            .store_data_policy(&body.owner_id, &body.scope, &policy)
            .await?;

        Ok(EncryptedResponse {
            status: Some(Status {
                code: Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            message: None,
        })
    }
}
