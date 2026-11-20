//! Signed job envelope types (spec §9.9) and privileged IPC messages.

use serde::{Deserialize, Serialize};

use crate::ProtocolError;

pub const MAX_JOB_RESPONSE_BYTES: u64 = 256 * 1024;
pub const IPC_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobEnvelope {
    pub job_id: String,
    pub device_id: String,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
    pub package_digest: String,
    pub catalogue_version_id: String,
    pub policy_revision: Option<i64>,
    pub request_binding_hash: String,
    pub request_id: String,
    pub installer_type: String,
    pub source_type: String,
    pub source_reference: String,
    pub package_identifier: String,
    pub package_version: String,
    pub os_family: String,
    pub architecture: String,
    pub signature_publisher: Option<String>,
    pub verification_method: String,
    pub package_size_bytes: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedJobResponse {
    pub envelope: JobEnvelope,
    pub signature: String,
    pub software_slug: String,
    pub display_name: String,
}

impl SignedJobResponse {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::Malformed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PrivilegedRequest {
    InstallPkg {
        protocol_version: u16,
        job_id: String,
        pkg_path: String,
        package_identifier: String,
        expected_version: String,
        package_digest: String,
    },
    Ping {
        protocol_version: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegedResponse {
    pub ok: bool,
    pub code: String,
    pub message: String,
    pub exit_code: Option<i32>,
    pub installed_version: Option<String>,
}

impl PrivilegedResponse {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::Malformed)
    }
}
