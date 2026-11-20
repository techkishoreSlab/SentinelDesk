//! Minimal non-secret agent state (spec §16.2: persist only what recovery needs).
//!
//! The device credential is never written here; it lives in the credential store.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const STATE_FILE: &str = "agent-state.json";
const MAX_STATE_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum StoreKind {
    /// macOS login Keychain (default on macOS).
    Keychain,
    /// Mode-0600 file in the agent config directory. Weaker; for platforms without a
    /// supported OS store and for automated tests.
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentState {
    pub backend_url: String,
    pub ca_file: Option<PathBuf>,
    pub device_id: String,
    pub credential_store: StoreKind,
    pub credential_expires_at: String,
    pub heartbeat_interval_seconds: u64,
}

#[derive(Debug)]
pub enum StateError {
    NotEnrolled,
    Io(std::io::Error),
    Corrupt,
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEnrolled => write!(
                f,
                "this device is not enrolled; run `sentinel-agent enroll`"
            ),
            Self::Io(e) => write!(f, "agent state I/O error: {e}"),
            Self::Corrupt => write!(f, "agent state file is invalid; re-enroll the device"),
        }
    }
}

impl std::error::Error for StateError {}

/// Create (or tighten) the config directory so only the current user can access it.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Atomically write `bytes` to `path` with owner-only permissions.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)
}

/// Read a small regular file, refusing symlinks and oversized content.
pub fn read_private(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() || meta.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a regular file or too large",
        ));
    }
    fs::read(path)
}

impl AgentState {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join(STATE_FILE)
    }

    pub fn load(dir: &Path) -> Result<Self, StateError> {
        let path = Self::path(dir);
        let bytes = match read_private(&path, MAX_STATE_BYTES) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StateError::NotEnrolled);
            }
            Err(e) => return Err(StateError::Io(e)),
        };
        serde_json::from_slice(&bytes).map_err(|_| StateError::Corrupt)
    }

    pub fn save(&self, dir: &Path) -> Result<(), StateError> {
        ensure_private_dir(dir).map_err(StateError::Io)?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| StateError::Corrupt)?;
        write_private(&Self::path(dir), &bytes).map_err(StateError::Io)
    }

    pub fn remove(dir: &Path) -> Result<(), StateError> {
        match fs::remove_file(Self::path(dir)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StateError::Io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AgentState {
        AgentState {
            backend_url: "https://localhost:8443".into(),
            ca_file: None,
            device_id: "6b0c3c54-2f87-4d43-9c0e-1d1a8c3b2e10".into(),
            credential_store: StoreKind::File,
            credential_expires_at: "2026-12-17T00:00:00Z".into(),
            heartbeat_interval_seconds: 60,
        }
    }

    #[test]
    fn roundtrip_with_private_permissions() {
        let Ok(dir) = tempfile::tempdir() else { return };
        let cfg = dir.path().join("cfg");
        assert!(matches!(
            AgentState::load(&cfg),
            Err(StateError::NotEnrolled)
        ));
        assert!(sample().save(&cfg).is_ok());
        assert_eq!(AgentState::load(&cfg).ok(), Some(sample()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).map(|m| m.permissions().mode() & 0o777).ok();
            assert_eq!(mode(&cfg), Some(0o700));
            assert_eq!(mode(&AgentState::path(&cfg)), Some(0o600));
        }
        assert!(AgentState::remove(&cfg).is_ok());
        assert!(matches!(
            AgentState::load(&cfg),
            Err(StateError::NotEnrolled)
        ));
    }

    #[test]
    fn rejects_corrupt_or_tampered_state() {
        let Ok(dir) = tempfile::tempdir() else { return };
        assert!(fs::write(AgentState::path(dir.path()), b"{\"device_id\":1}").is_ok());
        assert!(matches!(
            AgentState::load(dir.path()),
            Err(StateError::Corrupt)
        ));
        let mut json = serde_json::to_value(sample()).unwrap_or_default();
        json["install_command"] = "curl | sh".into();
        assert!(fs::write(AgentState::path(dir.path()), json.to_string()).is_ok());
        assert!(matches!(
            AgentState::load(dir.path()),
            Err(StateError::Corrupt)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_state() {
        let Ok(dir) = tempfile::tempdir() else { return };
        let target = dir.path().join("elsewhere.json");
        assert!(fs::write(&target, serde_json::to_vec(&sample()).unwrap_or_default()).is_ok());
        assert!(std::os::unix::fs::symlink(&target, AgentState::path(dir.path())).is_ok());
        assert!(matches!(
            AgentState::load(dir.path()),
            Err(StateError::Io(_))
        ));
    }
}
