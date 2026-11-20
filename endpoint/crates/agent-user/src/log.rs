//! Structured JSON log lines on stderr. Callers must never pass secrets (tokens,
//! credentials) as fields; only identifiers, statuses and error codes.

use std::time::{SystemTime, UNIX_EPOCH};

fn emit(level: &str, event: &str, fields: serde_json::Value) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut line = serde_json::json!({ "ts": ts, "level": level, "event": event });
    if let (Some(obj), serde_json::Value::Object(extra)) = (line.as_object_mut(), fields) {
        for (k, v) in extra {
            obj.entry(k).or_insert(v);
        }
    }
    eprintln!("{line}");
}

pub fn info(event: &str, fields: serde_json::Value) {
    emit("info", event, fields);
}

pub fn warn(event: &str, fields: serde_json::Value) {
    emit("warn", event, fields);
}

pub fn error(event: &str, fields: serde_json::Value) {
    emit("error", event, fields);
}
