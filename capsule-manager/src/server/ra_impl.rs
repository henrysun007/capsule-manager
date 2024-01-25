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

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hex::encode_upper;
use log::{debug, info};
use occlum_dcap::{sgx_report_data_t, DcapQuote};

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
                let user_data = hex::decode(hex_user_data).unwrap();

                let mut handler = DcapQuote::new().map_err(|e| {
                    errno!(ErrorCode::InternalErr, "failed to open /dev/sgx {:?}", e)
                })?;

                let quote_size = handler.get_quote_size().map_err(|e| {
                    errno!(
                        ErrorCode::InternalErr,
                        "failed to get sgx quote size err: {:?}",
                        e
                    )
                })? as usize;
                let mut occlum_quote = Vec::new();

                occlum_quote.resize(quote_size, b'\0');
                let mut report_data = sgx_report_data_t::default();
                if user_data.len() > 64 {
                    return Err(errno!(
                        ErrorCode::InvalidArgument,
                        "the data is too long: {}",
                        data.len()
                    ));
                }

                report_data.d[..user_data.len()].copy_from_slice(&user_data);
                assert_eq!(
                    handler
                        .generate_quote(occlum_quote.as_mut_ptr(), &report_data)
                        .map_err(|e| {
                            errno!(
                                ErrorCode::InternalErr,
                                "failed to get sgx quote err: {:?}",
                                e
                            )
                        })?,
                    0
                );

                let report = UnifiedAttestationReport {
                    str_report_version: "1.0".to_string(),
                    str_report_type: "JD".to_string(),
                    str_tee_platform: "SGX_DCAP".to_string(),
                    json_report: STANDARD.encode(occlum_quote),
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
