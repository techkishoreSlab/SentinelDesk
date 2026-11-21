//! Demo-friendly agent status file for the macOS menu bar helper.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AgentStatus {
    pub state: &'static str,
    pub detail: String,
    pub device_id: Option<String>,
    pub updated_at_unix: u64,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn status_path(config_dir: &Path) -> PathBuf {
    config_dir.join("status.json")
}

pub fn write_status(
    config_dir: &Path,
    state: &'static str,
    detail: impl Into<String>,
    device_id: Option<&str>,
) {
    let payload = AgentStatus {
        state,
        detail: detail.into(),
        device_id: device_id.map(str::to_owned),
        updated_at_unix: now_unix(),
    };
    let path = status_path(config_dir);
    if let Ok(bytes) = serde_json::to_vec_pretty(&payload) {
        let _ = fs::create_dir_all(config_dir);
        let tmp = path.with_extension("json.tmp");
        if fs::write(&tmp, bytes).is_ok() {
            let _ = fs::rename(tmp, path);
        }
    }
}
