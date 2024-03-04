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

use capsule_manager_tonic::secretflowapis::v2::sdc::capsule_manager::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod in_memory_storage;
pub mod local_fs_storage;
pub mod storage_engine;

#[derive(Debug, Serialize, Deserialize)]
pub struct DataMeta {
    // All data keys under the data uuid
    // resource_uri -> data_key
    data_keys: HashMap<String, String>,

    // owner party id
    party_id: String,

    // Record the data from which the data uuid is directly derived
    parents: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyMeta {
    // data policy
    policy: Policy,
    // policy party_id
    party_id: String,
    // policy scope
    scope: String,
}
