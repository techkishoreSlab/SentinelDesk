//! Signed job envelope types (spec §9.9) and privileged IPC messages.

use serde::{Deserialize, Serialize};

use crate::ProtocolError;

pub const MAX_JOB_RESPONSE_BYTES: u64 = 256 * 1024;
pub const IPC_PROTOCOL_VERSION: u16 = 1;

/// Installer kinds understood by this protocol crate.
pub const KIND_PKG: &str = "MACOS_PKG";
pub const KIND_DMG_APP: &str = "MACOS_DMG_APP";
pub const KIND_DMG_PKG: &str = "MACOS_DMG_PKG";
pub const KIND_ZIP_APP: &str = "MACOS_ZIP_APP";
pub const ARCHIVE_KINDS: [&str; 3] = [KIND_DMG_APP, KIND_DMG_PKG, KIND_ZIP_APP];

pub fn is_archive_kind(kind: &str) -> bool {
    ARCHIVE_KINDS.contains(&kind)
}

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
    /// Archive kinds only (absent for flat .pkg envelopes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_team_id: Option<String>,
    /// Archive kinds only: the single top-level `.app` / `.pkg` inside the DMG or ZIP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_path: Option<String>,
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
    /// Which installer kinds this daemon supports. Older daemons reject the op, which the
    /// agent treats as "flat .pkg only".
    Capabilities {
        protocol_version: u16,
    },
    InstallArchive {
        protocol_version: u16,
        job_id: String,
        kind: String,
        archive_path: String,
        payload_path: String,
        package_identifier: String,
        expected_version: String,
        expected_team_id: String,
        package_digest: String,
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
    /// Set only for `Capabilities` replies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installers: Option<Vec<String>>,
}

impl PrivilegedResponse {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_envelope() -> serde_json::Value {
        serde_json::json!({
            "job_id": "j", "device_id": "d", "nonce": "n",
            "issued_at": "t", "expires_at": "t", "package_digest": "a",
            "catalogue_version_id": "c", "policy_revision": 1,
            "request_binding_hash": "", "request_id": "r",
            "installer_type": "MACOS_PKG", "source_type": "INTERNAL_ARTIFACT_STORE",
            "source_reference": "artifact://sha256/a.pkg", "package_identifier": "com.x",
            "package_version": "1.0", "os_family": "macos", "architecture": "universal",
            "signature_publisher": null, "verification_method": "MACOS_PKG_RECEIPT",
            "package_size_bytes": 10
        })
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn pkg_envelope_parses_without_archive_fields() -> TestResult {
        let env: JobEnvelope = serde_json::from_value(base_envelope())?;
        assert!(env.expected_team_id.is_none() && env.payload_path.is_none());
        let back = serde_json::to_value(&env)?;
        assert!(back.get("expected_team_id").is_none());
        Ok(())
    }

    #[test]
    fn archive_envelope_parses_new_fields() -> TestResult {
        let mut value = base_envelope();
        value["installer_type"] = "MACOS_DMG_APP".into();
        value["expected_team_id"] = "BQR82RBBHL".into();
        value["payload_path"] = "Slack.app".into();
        let env: JobEnvelope = serde_json::from_value(value)?;
        assert_eq!(env.payload_path.as_deref(), Some("Slack.app"));
        assert!(is_archive_kind(&env.installer_type));
        Ok(())
    }

    #[test]
    fn unknown_envelope_fields_are_still_rejected() {
        let mut value = base_envelope();
        value["surprise"] = 1.into();
        assert!(serde_json::from_value::<JobEnvelope>(value).is_err());
    }

    #[test]
    fn old_daemon_response_without_installers_parses() -> TestResult {
        let raw =
            br#"{"ok":true,"code":"PONG","message":"","exit_code":null,"installed_version":null}"#;
        let resp = PrivilegedResponse::parse(raw).map_err(|e| e.to_string())?;
        assert!(resp.installers.is_none());
        Ok(())
    }
}
