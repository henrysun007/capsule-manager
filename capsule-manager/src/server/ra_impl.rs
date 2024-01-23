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
use ::capsule_manager::errno;
use ::capsule_manager::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use ::capsule_manager::utils::tool::sha256;
use capsule_manager_tonic::secretflowapis::v2::sdc::capsule_manager::{
    GetRaCertRequest, GetRaCertResponse,
};
use capsule_manager_tonic::secretflowapis::v2::sdc::{
    UnifiedAttestationReport, UnifiedAttestationReportParams,
};
use capsule_manager_tonic::secretflowapis::v2::{Code, Status};

use attester::BoxedAttester;
use hex::encode_upper;
use log::debug;

impl CapsuleManagerImpl {
    pub async fn get_ra_cert_impl(
        &self,
        request: &GetRaCertRequest,
    ) -> AuthResult<GetRaCertResponse> {
        let attestation_report: Option<UnifiedAttestationReport> = match self.mode.as_str() {
            // get RA report
            "production" => {
                let data = [&self.kek_cert, request.nonce.as_bytes()].join(SEPARATOR.as_bytes());
                let hex_user_data = encode_upper(sha256(&data));
                let boxed_attester =
                    BoxedAttester::try_from(attester::detect_tee_type()).map_err(|e| {
                        errno!(ErrorCode::UnsupportedErr, "unsupported TEE type: {:?}", e)
                    })?;
                // get base64-encoded quote
                let evidence = boxed_attester
                    .get_evidence(hex_user_data.as_bytes().to_vec())
                    .await
                    .map_err(|e| {
                        errno!(
                            ErrorCode::InternalErr,
                            "failed to get sgx quote err: {:?}",
                            e
                        )
                    })?;
                let report = UnifiedAttestationReport {
                    str_report_version: "1.0".to_string(),
                    str_report_type: "JD".to_string(),
                    str_tee_platform: "SGX_DCAP".to_string(),
                    json_report: evidence,
                    json_nested_reports: String::new(),
                };
                Some(report)
            }
            // simulation mode doesn't need report
            "simulation" => None,
            _ => {
                return Err(errno!(
                    ErrorCode::InvalidArgument,
                    "mode {} not supported",
                    &self.mode
                ));
            }
        };
        let response = GetRaCertResponse {
            status: Some(Status {
                code: Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            attestation_report,
            cert: String::from_utf8(self.kek_cert.clone())?,
        };

        Ok(response)
    }
}
