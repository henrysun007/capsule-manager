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
use hex::encode;
use log::{debug, warn};
use occlum_dcap::{sgx_ql_qv_result_t, DcapQuote, IoctlGenDCAPQuoteArg, IoctlVerDCAPQuoteArg};
use prost::Message;
use serde_json::json;
use verifier::{to_verifier, InitDataHash, ReportData, TeeEvidenceParsedClaim};

pub fn ra_verify(request: &GetDataKeysRequest) -> AuthResult<()> {
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
    let hex_report_data = encode(sha256(&data));

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

    let quote = STANDARD.decode(ua_report.json_report.clone())?;
    let (target_mr_enclave, target_mr_signer) = verify_in_occlum(&quote, hex_report_data.as_str())?;

    // get mr info
    let resource_request_innner: model::request::ResourceRequest = from(&resource_request)?;
    if let Some(env) = resource_request_innner.global_attributes.env {
        if let Some(tee) = env.tee {
            match tee {
                TeeIdentity::SGX {
                    mr_enclave,
                    mr_signer,
                } => {
                    if encode(&target_mr_enclave) != mr_enclave {
                        return_errno!(
                            ErrorCode::InvalidArgument,
                            "mr_enclave {:x?} and {} mismatch",
                            target_mr_enclave,
                            mr_enclave
                        );
                    };
                    if encode(&target_mr_signer) != mr_signer {
                        return_errno!(
                            ErrorCode::InvalidArgument,
                            "mr_signers {:x?} and {} mismatch",
                            target_mr_signer,
                            mr_signer
                        );
                    };
                }
                _ => return_errno!(ErrorCode::InvalidArgument, "env tee field invalid"),
            };
        }
    }

    Ok(())
}

// reference
// https://github.com/confidential-containers/kbs/blob/main/attestation-service/verifier/src/sgx/mod.rs
pub fn verify_in_occlum(quote: &[u8], data: &str) -> AuthResult<(Vec<u8>, Vec<u8>)> {
    if data.len() > 64 {
        return_errno!(
            ErrorCode::InvalidArgument,
            "the data is too long: {}",
            data.len()
        );
    }

    let mut handler = DcapQuote::new()
        .map_err(|e| errno!(ErrorCode::InternalErr, "failed to open /dev/sgx {:?}", e))?;
    let mut result = sgx_ql_qv_result_t::default();
    let mut collateral_expiration_status: u32 = 0;
    let mut arg = IoctlVerDCAPQuoteArg {
        quote_buf: quote.as_ptr(),
        quote_size: quote.len() as u32,
        collateral_expiration_status: &mut collateral_expiration_status,
        quote_verification_result: &mut result,
        supplemental_data_size: 0,
        supplemental_data: std::ptr::null_mut(),
    };

    let code = handler.verify_quote(&mut arg).map_err(|e| {
        errno!(
            ErrorCode::InternalErr,
            "failed to verify quote, error is {:?}",
            e
        )
    })?;
    if code < 0 {
        return_errno!(
            ErrorCode::InternalErr,
            "quote verification failed {:?}",
            code
        );
    }

    // check verification result
    match result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            if collateral_expiration_status == 0 {
                debug!("Verification completed successfully.");
            } else {
                warn!("Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
            }
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            warn!(
                "Verification completed with Non-terminal result: {:x}",
                result as u32
            );
        }
        _ => {
            return_errno!(
                ErrorCode::InternalErr,
                "Verification completed with Terminal result: {:x}",
                result as u32
            );
        }
    }

    let sgx_quote = verifier::sgx::parse_sgx_quote(quote).map_err(|e| {
        errno!(
            ErrorCode::InternalErr,
            "failed to parse quote, error is {:?}",
            e
        )
    })?;

    let report_data = sgx_quote.report_body.report_data;
    if &report_data[..data.len()] != data.as_bytes() {
        return_errno!(
            ErrorCode::InternalErr,
            "user data {:?} and {:?} mismatch",
            report_data,
            data
        );
    }

    Ok((
        sgx_quote.report_body.mr_enclave.to_vec(),
        sgx_quote.report_body.mr_signer.to_vec(),
    ))
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
            ra_verify(&request_content)?;
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
        let body = request_content
            .body
            .as_ref()
            .ok_or(errno!(ErrorCode::InvalidArgument, "request body is empty"))?;

        //  UAL verification
        if self.mode == "production" {
            let ua_report = if let Some(report) = &request_content.attestation_report {
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

            let quote = STANDARD.decode(ua_report.json_report.clone())?;
            let hex_report_data = encode(sha256(body.encode_to_vec().as_slice()));
            let _ = verify_in_occlum(&quote, hex_report_data.as_str())?;
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
