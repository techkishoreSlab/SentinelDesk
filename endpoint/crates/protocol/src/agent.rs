//! Agent ↔ backend messages for enrollment, heartbeat and credential rotation (spec §12.3).
//!
//! Outbound facts are validated against the same bounds the backend enforces, so the agent
//! never sends data the server would reject. Inbound messages reject unknown fields.

use serde::{Deserialize, Serialize};

use crate::{PROTOCOL_VERSION, ProtocolError};

pub const MAX_INSTALLED_ITEMS: usize = 1000;
pub const CREDENTIAL_PREFIX: &str = "sdc_";
pub const ENROLLMENT_PREFIX: &str = "sde_";
/// Prefix plus 43 characters of URL-safe base64 (32 random bytes).
pub const SECRET_LEN: usize = 47;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsFamily {
    Macos,
    Windows,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Arm64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareSource {
    AppBundle,
    PkgReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstalledSoftware {
    pub identifier: String,
    pub version: String,
    pub source: SoftwareSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceFacts {
    pub device_name: String,
    pub os_family: OsFamily,
    pub os_version: String,
    pub os_build: String,
    pub architecture: Architecture,
    pub cpu_cores: u32,
    pub memory_total_bytes: u64,
    pub disk_free_bytes: u64,
    pub installed_software: Vec<InstalledSoftware>,
}

/// Installer kinds this endpoint can execute (agent ∩ privileged daemon).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceCapabilities {
    pub installers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct EnrollRequest<'a> {
    pub protocol_version: u16,
    pub enrollment_token: &'a str,
    pub agent_version: &'a str,
    pub facts: &'a DeviceFacts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<&'a DeviceCapabilities>,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatRequest<'a> {
    pub protocol_version: u16,
    pub agent_version: &'a str,
    pub facts: &'a DeviceFacts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<&'a DeviceCapabilities>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollResponse {
    pub protocol_version: u16,
    pub device_id: String,
    pub device_credential: String,
    pub credential_expires_at: String,
    pub heartbeat_interval_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatResponse {
    pub protocol_version: u16,
    pub device_id: String,
    pub device_status: String,
    pub next_heartbeat_seconds: u64,
    pub credential_expires_at: String,
    pub rotate_credential: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateResponse {
    pub protocol_version: u16,
    pub device_credential: String,
    pub credential_expires_at: String,
}

fn is_printable(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(char::is_control)
}

fn charset(s: &str, extra: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

fn bounded(s: &str, max: usize) -> bool {
    s.chars().count() <= max
}

/// Bounds mirror `backend/app/devices/schemas.py`.
pub fn valid_identifier(s: &str) -> bool {
    bounded(s, 200) && charset(s, "._+-")
}

pub fn valid_version(s: &str) -> bool {
    bounded(s, 64) && charset(s, "._+-~: ()")
}

pub fn valid_agent_version(s: &str) -> bool {
    bounded(s, 32) && charset(s, ".+-")
}

/// Remove control characters, trim, and cut to `max` characters. Returns None if empty.
pub fn clean_text(raw: &str, max: usize) -> Option<String> {
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).collect();
    let trimmed: String = cleaned.trim().chars().take(max).collect();
    let trimmed = trimmed.trim().to_string();
    (!trimmed.is_empty()).then_some(trimmed)
}

impl DeviceFacts {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let checks: [(&'static str, bool); 6] = [
            (
                "device_name",
                is_printable(&self.device_name) && bounded(&self.device_name, 120),
            ),
            (
                "os_version",
                is_printable(&self.os_version) && bounded(&self.os_version, 40),
            ),
            (
                "os_build",
                is_printable(&self.os_build) && bounded(&self.os_build, 40),
            ),
            ("cpu_cores", (1..=1024).contains(&self.cpu_cores)),
            ("memory_total_bytes", self.memory_total_bytes <= 1 << 50),
            (
                "installed_software",
                self.installed_software.len() <= MAX_INSTALLED_ITEMS,
            ),
        ];
        if let Some((field, _)) = checks.iter().find(|(_, ok)| !ok) {
            return Err(ProtocolError::FieldTooLong(field));
        }
        if self.disk_free_bytes > 1 << 55 {
            return Err(ProtocolError::FieldTooLong("disk_free_bytes"));
        }
        for item in &self.installed_software {
            if !valid_identifier(&item.identifier) || !valid_version(&item.version) {
                return Err(ProtocolError::FieldTooLong("installed_software"));
            }
        }
        Ok(())
    }
}

pub fn well_formed_secret(secret: &str, prefix: &str) -> bool {
    secret.len() == SECRET_LEN
        && secret.starts_with(prefix)
        && secret[prefix.len()..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, ProtocolError> {
    serde_json::from_slice(bytes).map_err(|_| ProtocolError::Malformed)
}

fn check_version(v: u16) -> Result<(), ProtocolError> {
    if v == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedVersion(v))
    }
}

fn check_uuid(s: &str) -> Result<(), ProtocolError> {
    let ok = s.len() == 36
        && s.char_indices().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        });
    if ok {
        Ok(())
    } else {
        Err(ProtocolError::Malformed)
    }
}

fn check_short(field: &'static str, s: &str, max: usize) -> Result<(), ProtocolError> {
    if bounded(s, max) {
        Ok(())
    } else {
        Err(ProtocolError::FieldTooLong(field))
    }
}

impl EnrollResponse {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let r: Self = parse(bytes)?;
        check_version(r.protocol_version)?;
        check_uuid(&r.device_id)?;
        if !well_formed_secret(&r.device_credential, CREDENTIAL_PREFIX) {
            return Err(ProtocolError::Malformed);
        }
        check_short("credential_expires_at", &r.credential_expires_at, 40)?;
        if !(10..=3600).contains(&r.heartbeat_interval_seconds) {
            return Err(ProtocolError::Malformed);
        }
        Ok(r)
    }
}

impl HeartbeatResponse {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let r: Self = parse(bytes)?;
        check_version(r.protocol_version)?;
        check_uuid(&r.device_id)?;
        check_short("device_status", &r.device_status, 16)?;
        check_short("credential_expires_at", &r.credential_expires_at, 40)?;
        if !(10..=3600).contains(&r.next_heartbeat_seconds) {
            return Err(ProtocolError::Malformed);
        }
        Ok(r)
    }
}

impl RotateResponse {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let r: Self = parse(bytes)?;
        check_version(r.protocol_version)?;
        if !well_formed_secret(&r.device_credential, CREDENTIAL_PREFIX) {
            return Err(ProtocolError::Malformed);
        }
        check_short("credential_expires_at", &r.credential_expires_at, 40)?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CRED: &str = "sdc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const DEV: &str = "6b0c3c54-2f87-4d43-9c0e-1d1a8c3b2e10";

    fn facts() -> DeviceFacts {
        DeviceFacts {
            device_name: "Mac".into(),
            os_family: OsFamily::Macos,
            os_version: "26.5".into(),
            os_build: "25F71".into(),
            architecture: Architecture::X86_64,
            cpu_cores: 12,
            memory_total_bytes: 17_179_869_184,
            disk_free_bytes: 1,
            installed_software: vec![InstalledSoftware {
                identifier: "com.microsoft.VSCode".into(),
                version: "1.138.0".into(),
                source: SoftwareSource::AppBundle,
            }],
        }
    }

    #[test]
    fn facts_serialize_to_backend_shape() {
        let json = serde_json::to_value(facts()).ok();
        let json = json.as_ref();
        assert_eq!(json.and_then(|j| j["os_family"].as_str()), Some("macos"));
        assert_eq!(
            json.and_then(|j| j["architecture"].as_str()),
            Some("x86_64")
        );
        assert_eq!(
            json.and_then(|j| j["installed_software"][0]["source"].as_str()),
            Some("app_bundle")
        );
    }

    #[test]
    fn facts_validation_rejects_bad_values() {
        assert_eq!(facts().validate(), Ok(()));
        let mut f = facts();
        f.device_name = "evil\u{1b}[31m".into();
        assert!(f.validate().is_err());
        let mut f = facts();
        f.installed_software[0].identifier = "a; rm -rf /".into();
        assert!(f.validate().is_err());
        let mut f = facts();
        f.cpu_cores = 0;
        assert!(f.validate().is_err());
    }

    #[test]
    fn clean_text_strips_controls_and_bounds() {
        assert_eq!(clean_text("  My\u{0}Mac\n ", 120), Some("MyMac".into()));
        assert_eq!(clean_text("\u{7}\u{1b}", 10), None);
        assert_eq!(
            clean_text(&"x".repeat(300), 120).map(|s| s.len()),
            Some(120)
        );
    }

    #[test]
    fn secrets_must_be_well_formed() {
        assert!(well_formed_secret(CRED, CREDENTIAL_PREFIX));
        assert!(!well_formed_secret(CRED, ENROLLMENT_PREFIX));
        assert!(!well_formed_secret("sdc_short", CREDENTIAL_PREFIX));
        assert!(!well_formed_secret(
            "sdc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/A",
            CREDENTIAL_PREFIX
        ));
    }

    #[test]
    fn enroll_response_strict_parsing() {
        let ok = format!(
            r#"{{"protocol_version":1,"device_id":"{DEV}","device_credential":"{CRED}","credential_expires_at":"2026-12-17T00:00:00Z","heartbeat_interval_seconds":60}}"#
        );
        assert!(EnrollResponse::parse(ok.as_bytes()).is_ok());
        let extra = ok.replace(
            r#""heartbeat_interval_seconds":60"#,
            r#""heartbeat_interval_seconds":60,"run":"sh""#,
        );
        assert_eq!(
            EnrollResponse::parse(extra.as_bytes()).err(),
            Some(ProtocolError::Malformed)
        );
        let v2 = ok.replace(r#""protocol_version":1"#, r#""protocol_version":2"#);
        assert_eq!(
            EnrollResponse::parse(v2.as_bytes()).err(),
            Some(ProtocolError::UnsupportedVersion(2))
        );
        let tight = ok.replace(":60}", ":0}");
        assert!(EnrollResponse::parse(tight.as_bytes()).is_err());
        let bad_id = ok.replace(DEV, "../../etc/passwd");
        assert!(EnrollResponse::parse(bad_id.as_bytes()).is_err());
    }

    #[test]
    fn heartbeat_and_rotate_parsing() {
        let hb = format!(
            r#"{{"protocol_version":1,"device_id":"{DEV}","device_status":"ACTIVE","next_heartbeat_seconds":60,"credential_expires_at":"x","rotate_credential":true}}"#
        );
        assert!(HeartbeatResponse::parse(hb.as_bytes()).is_ok_and(|r| r.rotate_credential));
        let rot = format!(
            r#"{{"protocol_version":1,"device_credential":"{CRED}","credential_expires_at":"x"}}"#
        );
        assert!(RotateResponse::parse(rot.as_bytes()).is_ok());
        assert!(
            RotateResponse::parse(
                br#"{"protocol_version":1,"device_credential":"x","credential_expires_at":"x"}"#
            )
            .is_err()
        );
    }
}
