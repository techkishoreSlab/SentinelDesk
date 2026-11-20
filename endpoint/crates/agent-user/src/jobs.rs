//! Claim signed jobs, verify Ed25519 envelopes, download packages, call privileged IPC.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sentinel_protocol::job::{
    IPC_PROTOCOL_VERSION, MAX_JOB_RESPONSE_BYTES, PrivilegedRequest, PrivilegedResponse,
    SignedJobResponse,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::agent::{AgentError, Session};
use crate::log;

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

pub struct JobPaths {
    pub public_key_pem: PathBuf,
    pub privileged_socket: PathBuf,
    pub package_dir: PathBuf,
}

impl JobPaths {
    pub fn from_env(config_dir: &Path) -> Self {
        let public_key_pem = std::env::var_os("SENTINEL_JOB_PUBLIC_KEY")
            .map(PathBuf::from)
            .unwrap_or_else(|| config_dir.join("job_signing_public.pem"));
        let privileged_socket = std::env::var_os("SENTINEL_PRIVILEGED_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/run/sentineldesk/privileged.sock"));
        let package_dir = std::env::var_os("SENTINEL_PACKAGE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Users/Shared/SentinelDesk/packages"));
        Self {
            public_key_pem,
            privileged_socket,
            package_dir,
        }
    }

    pub fn ready_to_claim(&self) -> bool {
        self.public_key_pem.is_file()
    }
}

pub struct JobRunner<'a> {
    pub session: &'a Session,
    pub paths: &'a JobPaths,
}

impl JobRunner<'_> {
    /// Claim at most one job. Returns `Ok(false)` when the queue is empty.
    pub fn run_once(&self) -> Result<bool, AgentError> {
        if !self.paths.ready_to_claim() {
            log::warn(
                "job_public_key_missing",
                serde_json::json!({
                    "path": self.paths.public_key_pem,
                    "hint": "copy JOB_SIGNING public PEM or set SENTINEL_JOB_PUBLIC_KEY",
                }),
            );
            return Ok(false);
        }
        let credential = self.session.store.load(&self.session.state.device_id)?;
        let response = self
            .session
            .client
            .get("/api/v1/agent/jobs/next", Some(&credential))?;
        if response.status == 204 {
            return Ok(false);
        }
        if response.status != 200 {
            return Err(AgentError::HttpStatus(response.status));
        }
        if response.body.len() as u64 > MAX_JOB_RESPONSE_BYTES {
            return Err(AgentError::Protocol(
                sentinel_protocol::ProtocolError::Malformed,
            ));
        }

        let root: Value = serde_json::from_slice(&response.body)
            .map_err(|_| AgentError::Protocol(sentinel_protocol::ProtocolError::Malformed))?;
        let envelope_value = root.get("envelope").ok_or(AgentError::Protocol(
            sentinel_protocol::ProtocolError::Malformed,
        ))?;
        let signature =
            root.get("signature")
                .and_then(Value::as_str)
                .ok_or(AgentError::Protocol(
                    sentinel_protocol::ProtocolError::Malformed,
                ))?;
        verify_signature(&self.paths.public_key_pem, envelope_value, signature)?;

        let job = SignedJobResponse::parse(&response.body).map_err(AgentError::Protocol)?;
        let job_id = job.envelope.job_id.clone();
        crate::status::write_status(
            &self.session.config_dir,
            "installing",
            format!("Online · installing {}…", job.software_slug),
            Some(&self.session.state.device_id),
        );
        self.post_started(&credential, &job_id)?;

        match self.execute(&job) {
            Ok(report) => {
                self.post_result(&credential, &job_id, &report)?;
                log::info(
                    "job_finished",
                    serde_json::json!({
                        "job_id": job_id,
                        "result_code": report.result_code,
                        "software_slug": job.software_slug,
                    }),
                );
            }
            Err(err) => {
                let code = match &err {
                    AgentError::PrivilegedUnavailable => "PRIVILEGED_SERVICE_UNAVAILABLE",
                    AgentError::DigestMismatch => "DIGEST_MISMATCH",
                    AgentError::DownloadFailed => "DOWNLOAD_FAILED",
                    AgentError::SignatureInvalid => "SIGNATURE_INVALID",
                    _ => "INSTALL_FAILED",
                };
                let failure = JobReport {
                    result_code: code.into(),
                    result_summary: err.to_string(),
                    exit_code: None,
                    installed_version: None,
                    verification_status: "NOT_ATTEMPTED",
                };
                let _ = self.post_result(&credential, &job_id, &failure);
                return Err(err);
            }
        }
        Ok(true)
    }

    fn post_started(&self, credential: &str, job_id: &str) -> Result<(), AgentError> {
        let path = format!("/api/v1/agent/jobs/{job_id}/started");
        let body = serde_json::json!({"protocol_version": 1});
        let response = self
            .session
            .client
            .post_json(&path, Some(credential), &body)?;
        if response.status != 204 {
            return Err(AgentError::HttpStatus(response.status));
        }
        Ok(())
    }

    fn post_result(
        &self,
        credential: &str,
        job_id: &str,
        report: &JobReport,
    ) -> Result<(), AgentError> {
        let path = format!("/api/v1/agent/jobs/{job_id}/result");
        let body = serde_json::json!({
            "protocol_version": 1,
            "result_code": report.result_code,
            "result_summary": report.result_summary,
            "exit_code": report.exit_code,
            "installed_version": report.installed_version,
            "verification_status": report.verification_status,
            "details": {}
        });
        let response = self
            .session
            .client
            .post_json(&path, Some(credential), &body)?;
        if response.status != 200 {
            return Err(AgentError::HttpStatus(response.status));
        }
        Ok(())
    }

    fn execute(&self, job: &SignedJobResponse) -> Result<JobReport, AgentError> {
        fs::create_dir_all(&self.paths.package_dir).map_err(AgentError::Io)?;
        let pkg_path = download_package(
            &job.envelope.source_reference,
            &job.envelope.package_digest,
            job.envelope.package_size_bytes,
            &self.paths.package_dir,
        )?;
        let response = call_privileged(
            &self.paths.privileged_socket,
            PrivilegedRequest::InstallPkg {
                protocol_version: IPC_PROTOCOL_VERSION,
                job_id: job.envelope.job_id.clone(),
                pkg_path: pkg_path.to_string_lossy().into_owned(),
                package_identifier: job.envelope.package_identifier.clone(),
                expected_version: job.envelope.package_version.clone(),
                package_digest: job.envelope.package_digest.clone(),
            },
        )?;
        let verification_status = if response.ok && response.code == "SUCCEEDED" {
            "VERIFIED"
        } else if response.code == "FAILED_VERIFICATION" {
            "FAILED"
        } else {
            "NOT_ATTEMPTED"
        };
        let result_code = if response.ok {
            "SUCCEEDED".to_owned()
        } else {
            sanitize_result_code(&response.code)
        };
        Ok(JobReport {
            result_code,
            result_summary: response.message,
            exit_code: response.exit_code,
            installed_version: response.installed_version,
            verification_status,
        })
    }
}

struct JobReport {
    result_code: String,
    result_summary: String,
    exit_code: Option<i32>,
    installed_version: Option<String>,
    verification_status: &'static str,
}

fn sanitize_result_code(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty()
        || !cleaned
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase())
    {
        "INSTALL_FAILED".into()
    } else {
        cleaned.chars().take(60).collect()
    }
}

fn verify_signature(
    public_key_pem: &Path,
    envelope: &Value,
    signature_b64: &str,
) -> Result<(), AgentError> {
    let pem = fs::read_to_string(public_key_pem).map_err(AgentError::Io)?;
    let key = VerifyingKey::from_public_key_pem(&pem).map_err(|_| AgentError::SignatureInvalid)?;
    let payload = canonical_json(envelope).map_err(|_| AgentError::SignatureInvalid)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.as_bytes())
        .map_err(|_| AgentError::SignatureInvalid)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| AgentError::SignatureInvalid)?;
    let signature = Signature::from_bytes(&sig_arr);
    key.verify(&payload, &signature)
        .map_err(|_| AgentError::SignatureInvalid)?;
    Ok(())
}

/// Match Python `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), ()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => {
            // serde_json string encoding; envelopes are ASCII so this matches ensure_ascii.
            let escaped = serde_json::to_string(s).map_err(|_| ())?;
            out.extend_from_slice(escaped.as_bytes());
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let key_json = serde_json::to_string(key).map_err(|_| ())?;
                out.extend_from_slice(key_json.as_bytes());
                out.push(b':');
                write_canonical(&map[*key], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<(String, u64), AgentError> {
    let mut file = File::open(path).map_err(AgentError::Io)?;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 8192];
    let mut total = 0_u64;
    loop {
        let n = file.read(&mut buf).map_err(AgentError::Io)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        hasher.update(&buf[..n]);
    }
    Ok((format!("{:x}", hasher.finalize()), total))
}

fn download_package(
    source: &str,
    expected_digest: &str,
    max_size: Option<i64>,
    package_dir: &Path,
) -> Result<PathBuf, AgentError> {
    let limit = max_size
        .unwrap_or(100 * 1024 * 1024)
        .clamp(1, 200 * 1024 * 1024) as u64;
    let name = source
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty() && (s.ends_with(".pkg") || s.contains('.')))
        .unwrap_or("package.pkg");
    let dest = package_dir.join(name);

    // Prefer an already-staged package (catalogue upload / stage scripts).
    if dest.is_file() {
        let (digest, total) = hash_file(&dest)?;
        if digest.eq_ignore_ascii_case(expected_digest) && total <= limit {
            log::info(
                "package_cached",
                serde_json::json!({ "path": dest, "bytes": total, "sha256": digest }),
            );
            return Ok(dest);
        }
    }

    if !(source.starts_with("https://") || source.starts_with("http://")) {
        return Err(AgentError::DownloadFailed);
    }

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(DOWNLOAD_TIMEOUT))
        .http_status_as_error(false)
        .max_redirects(3)
        .user_agent(concat!("SentinelDesk-Agent/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let mut response = agent
        .get(source)
        .call()
        .map_err(|_| AgentError::DownloadFailed)?;
    if !(200..300).contains(&response.status().as_u16()) {
        return Err(AgentError::DownloadFailed);
    }
    let mut reader = response.body_mut().as_reader();
    let mut file = File::create(&dest).map_err(AgentError::Io)?;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 8192];
    let mut total = 0_u64;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|_| AgentError::DownloadFailed)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > limit {
            let _ = fs::remove_file(&dest);
            return Err(AgentError::DownloadFailed);
        }
        file.write_all(&buf[..n]).map_err(AgentError::Io)?;
        hasher.update(&buf[..n]);
    }
    let digest = format!("{:x}", hasher.finalize());
    if !digest.eq_ignore_ascii_case(expected_digest) {
        let _ = fs::remove_file(&dest);
        return Err(AgentError::DigestMismatch);
    }
    log::info(
        "package_downloaded",
        serde_json::json!({ "path": dest, "bytes": total, "sha256": digest }),
    );
    Ok(dest)
}

fn call_privileged(
    socket: &Path,
    request: PrivilegedRequest,
) -> Result<PrivilegedResponse, AgentError> {
    let mut stream = UnixStream::connect(socket).map_err(|_| AgentError::PrivilegedUnavailable)?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(600)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let body = serde_json::to_vec(&request).map_err(|_| AgentError::PrivilegedUnavailable)?;
    stream
        .write_all(&body)
        .map_err(|_| AgentError::PrivilegedUnavailable)?;
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|_| AgentError::PrivilegedUnavailable)?;
    PrivilegedResponse::parse(&buf).map_err(|_| AgentError::PrivilegedUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_keys_and_compacts() {
        let value = json!({
            "b": 2,
            "a": null,
            "nested": {"z": true, "y": "x"}
        });
        let bytes = canonical_json(&value).unwrap_or_default();
        assert_eq!(
            bytes,
            br#"{"a":null,"b":2,"nested":{"y":"x","z":true}}"#
        );
    }

    #[test]
    fn sanitize_result_code_keeps_backend_pattern() {
        assert_eq!(sanitize_result_code("DIGEST_MISMATCH"), "DIGEST_MISMATCH");
        assert_eq!(sanitize_result_code("bad-code"), "INSTALL_FAILED");
        assert_eq!(
            sanitize_result_code("PKG_PATH_REJECTED"),
            "PKG_PATH_REJECTED"
        );
    }
}
