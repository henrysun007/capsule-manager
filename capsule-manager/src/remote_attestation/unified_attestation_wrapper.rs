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

use crate::errno;
use crate::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};

use log::info;
use std::ffi::{CStr, CString};

pub fn runified_attestation_verify_auth_report(
    auth_json: &str,
    rules_json: &str,
) -> AuthResult<()> {
    unimplemented!();
}

pub fn runified_attestation_generate_auth_report(
    tee_identity: &str,
    report_type: &str,
    report_hex_nonce: &str,
    report_params: &str,
) -> AuthResult<String> {
    unimplemented!();
}
