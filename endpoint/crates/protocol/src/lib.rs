//! Wire types shared by the SentinelDesk endpoint components.
//!
//! Every inbound message is parsed into a closed, versioned type. Unknown
//! fields are rejected so the backend cannot smuggle extra instructions.

use serde::{Deserialize, Serialize};

pub mod agent;
pub mod job;

pub const PROTOCOL_VERSION: u16 = 1;

/// Upper bound on any response body the agent will read from the backend.
pub const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

const MAX_VERSION_CHARS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LiveState {
    Ok,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveStatus {
    pub status: LiveState,
    pub version: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolError {
    Malformed,
    FieldTooLong(&'static str),
    UnsupportedVersion(u16),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed message"),
            Self::FieldTooLong(field) => write!(f, "field `{field}` is invalid or out of bounds"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version {v}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl LiveStatus {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let status: Self = serde_json::from_slice(bytes).map_err(|_| ProtocolError::Malformed)?;
        if status.version.chars().count() > MAX_VERSION_CHARS {
            return Err(ProtocolError::FieldTooLong("version"));
        }
        Ok(status)
    }
}

/// Standard backend error envelope (spec §12.4). `details` is intentionally not
/// modelled: the agent never acts on it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ApiErrorEnvelope {
    pub error: ApiErrorDetail,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ApiErrorDetail {
    pub code: String,
    pub message: String,
    pub correlation_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_live_status() {
        let parsed = LiveStatus::parse(br#"{"status":"ok","version":"0.1.0"}"#);
        assert_eq!(
            parsed,
            Ok(LiveStatus {
                status: LiveState::Ok,
                version: "0.1.0".into()
            })
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let parsed = LiveStatus::parse(br#"{"status":"ok","version":"1","command":"rm -rf /"}"#);
        assert_eq!(parsed, Err(ProtocolError::Malformed));
    }

    #[test]
    fn rejects_unknown_status_value() {
        assert_eq!(
            LiveStatus::parse(br#"{"status":"pwned","version":"1"}"#),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn rejects_oversized_version() {
        let body = format!(r#"{{"status":"ok","version":"{}"}}"#, "9".repeat(33));
        assert_eq!(
            LiveStatus::parse(body.as_bytes()),
            Err(ProtocolError::FieldTooLong("version"))
        );
    }

    #[test]
    fn rejects_non_json() {
        assert_eq!(LiveStatus::parse(b"<html>"), Err(ProtocolError::Malformed));
    }

    #[test]
    fn parses_error_envelope_ignoring_details() {
        let env: Result<ApiErrorEnvelope, _> = serde_json::from_str(
            r#"{"error":{"code":"SERVICE_UNAVAILABLE","message":"m","correlation_id":"c","details":{"x":1}}}"#,
        );
        assert!(matches!(env, Ok(e) if e.error.code == "SERVICE_UNAVAILABLE"));
    }
}
