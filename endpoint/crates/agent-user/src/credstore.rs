//! Device credential storage (spec §9.8: OS-protected storage where available).
//!
//! macOS uses the login Keychain. Other platforms have no supported OS store yet and must
//! opt in to the file store explicitly; it is never chosen silently.

use std::path::{Path, PathBuf};

use sentinel_protocol::agent::{CREDENTIAL_PREFIX, SECRET_LEN, well_formed_secret};

use crate::state::{StoreKind, ensure_private_dir, read_private, write_private};

pub const KEYCHAIN_SERVICE: &str = "com.sentineldesk.agent.device-credential";
const CREDENTIAL_FILE: &str = "device-credential";

#[derive(Debug)]
pub enum StoreError {
    Unavailable(&'static str),
    NotFound,
    Invalid,
    Backend(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(why) => write!(f, "credential store unavailable: {why}"),
            Self::NotFound => write!(f, "device credential not found; re-enroll the device"),
            Self::Invalid => write!(f, "stored device credential is malformed; re-enroll"),
            Self::Backend(msg) => write!(f, "credential store error: {msg}"),
        }
    }
}

impl std::error::Error for StoreError {}

pub struct CredentialStore {
    kind: StoreKind,
    dir: PathBuf,
}

impl CredentialStore {
    pub fn new(kind: StoreKind, config_dir: &Path) -> Result<Self, StoreError> {
        if kind == StoreKind::Keychain && !cfg!(target_os = "macos") {
            return Err(StoreError::Unavailable(
                "the Keychain store is macOS-only; pass --credential-store file explicitly",
            ));
        }
        Ok(Self {
            kind,
            dir: config_dir.to_path_buf(),
        })
    }

    fn file_path(&self, device_id: &str) -> PathBuf {
        self.dir.join(format!("{CREDENTIAL_FILE}-{device_id}"))
    }

    pub fn save(&self, device_id: &str, secret: &str) -> Result<(), StoreError> {
        if !well_formed_secret(secret, CREDENTIAL_PREFIX) {
            return Err(StoreError::Invalid);
        }
        match self.kind {
            StoreKind::File => {
                ensure_private_dir(&self.dir).map_err(|e| StoreError::Backend(e.to_string()))?;
                write_private(&self.file_path(device_id), secret.as_bytes())
                    .map_err(|e| StoreError::Backend(e.to_string()))
            }
            StoreKind::Keychain => keychain::save(device_id, secret),
        }
    }

    pub fn load(&self, device_id: &str) -> Result<String, StoreError> {
        let bytes = match self.kind {
            StoreKind::File => match read_private(&self.file_path(device_id), SECRET_LEN as u64) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(StoreError::NotFound);
                }
                Err(e) => return Err(StoreError::Backend(e.to_string())),
            },
            StoreKind::Keychain => keychain::load(device_id)?,
        };
        let secret = String::from_utf8(bytes).map_err(|_| StoreError::Invalid)?;
        if well_formed_secret(&secret, CREDENTIAL_PREFIX) {
            Ok(secret)
        } else {
            Err(StoreError::Invalid)
        }
    }

    pub fn delete(&self, device_id: &str) -> Result<(), StoreError> {
        match self.kind {
            StoreKind::File => match std::fs::remove_file(self.file_path(device_id)) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(StoreError::Backend(e.to_string())),
            },
            StoreKind::Keychain => keychain::delete(device_id),
        }
    }
}

#[cfg(target_os = "macos")]
mod keychain {
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };

    use super::{KEYCHAIN_SERVICE, StoreError};

    // errSecItemNotFound
    const NOT_FOUND: i32 = -25300;

    pub fn save(device_id: &str, secret: &str) -> Result<(), StoreError> {
        set_generic_password(KEYCHAIN_SERVICE, device_id, secret.as_bytes())
            .map_err(|e| StoreError::Backend(format!("keychain write failed ({})", e.code())))
    }

    pub fn load(device_id: &str) -> Result<Vec<u8>, StoreError> {
        get_generic_password(KEYCHAIN_SERVICE, device_id).map_err(|e| {
            if e.code() == NOT_FOUND {
                StoreError::NotFound
            } else {
                StoreError::Backend(format!("keychain read failed ({})", e.code()))
            }
        })
    }

    pub fn delete(device_id: &str) -> Result<(), StoreError> {
        match delete_generic_password(KEYCHAIN_SERVICE, device_id) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == NOT_FOUND => Ok(()),
            Err(e) => Err(StoreError::Backend(format!(
                "keychain delete failed ({})",
                e.code()
            ))),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod keychain {
    use super::StoreError;

    pub fn save(_: &str, _: &str) -> Result<(), StoreError> {
        Err(StoreError::Unavailable(
            "no OS credential store on this platform",
        ))
    }

    pub fn load(_: &str) -> Result<Vec<u8>, StoreError> {
        Err(StoreError::Unavailable(
            "no OS credential store on this platform",
        ))
    }

    pub fn delete(_: &str) -> Result<(), StoreError> {
        Err(StoreError::Unavailable(
            "no OS credential store on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CRED: &str = "sdc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const DEV: &str = "6b0c3c54-2f87-4d43-9c0e-1d1a8c3b2e10";

    #[test]
    fn file_store_roundtrip_is_private_and_validated() {
        let Ok(dir) = tempfile::tempdir() else { return };
        let Ok(store) = CredentialStore::new(StoreKind::File, dir.path()) else {
            return;
        };
        assert!(matches!(store.load(DEV), Err(StoreError::NotFound)));
        assert!(matches!(
            store.save(DEV, "sdc_short"),
            Err(StoreError::Invalid)
        ));
        assert!(store.save(DEV, CRED).is_ok());
        assert_eq!(store.load(DEV).ok().as_deref(), Some(CRED));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.file_path(DEV))
                .map(|m| m.permissions().mode() & 0o777)
                .ok();
            assert_eq!(mode, Some(0o600));
        }
        assert!(std::fs::write(store.file_path(DEV), b"sde_tampered").is_ok());
        assert!(matches!(store.load(DEV), Err(StoreError::Invalid)));
        assert!(store.delete(DEV).is_ok());
        assert!(store.delete(DEV).is_ok());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn keychain_refused_off_macos() {
        assert!(matches!(
            CredentialStore::new(StoreKind::Keychain, Path::new("/tmp")),
            Err(StoreError::Unavailable(_))
        ));
    }
}
