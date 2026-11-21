//! Claim signed jobs, verify Ed25519 envelopes, download packages, call privileged IPC.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine;
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sentinel_protocol::job::{
    ARCHIVE_KINDS, IPC_PROTOCOL_VERSION, JobEnvelope, KIND_PKG, KIND_ZIP_APP,
    MAX_JOB_RESPONSE_BYTES, PrivilegedRequest, PrivilegedResponse, SignedJobResponse,
    is_archive_kind,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::agent::{AgentError, Session};
use crate::log;

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const PKG_IPC_TIMEOUT: Duration = Duration::from_secs(600);
const ARCHIVE_IPC_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const PROBE_IPC_TIMEOUT: Duration = Duration::from_secs(5);
/// Legacy envelopes without `package_size_bytes` keep the old ceiling.
const LEGACY_MAX_BYTES: u64 = 200 * 1024 * 1024;
const MAX_PACKAGE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Without a reachable (or new enough) daemon the agent still claims what it always did.
const FALLBACK_INSTALLERS: [&str; 1] = [KIND_PKG];
/// Throttle download progress POSTs so large packages do not flood the control plane.
const PROGRESS_MIN_INTERVAL: Duration = Duration::from_secs(2);
const PROGRESS_MIN_BYTES: u64 = 8 * 1024 * 1024;

/// Installer kinds this agent build can route.
pub fn agent_installers() -> Vec<&'static str> {
    std::iter::once(KIND_PKG).chain(ARCHIVE_KINDS).collect()
}

/// Ask the privileged daemon which installer kinds it supports, intersected with ours.
/// Old daemons reject the op and unreachable daemons fail to connect: both mean "pkg only".
pub fn probe_installers(socket: &Path) -> Vec<String> {
    let request = PrivilegedRequest::Capabilities {
        protocol_version: IPC_PROTOCOL_VERSION,
    };
    let daemon = match call_privileged(socket, &request, PROBE_IPC_TIMEOUT) {
        Ok(resp) if resp.ok => resp.installers.unwrap_or_default(),
        _ => Vec::new(),
    };
    let mut kinds: Vec<String> = agent_installers()
        .into_iter()
        .filter(|k| daemon.iter().any(|d| d == k))
        .map(str::to_owned)
        .collect();
    if kinds.is_empty() {
        kinds = FALLBACK_INSTALLERS
            .iter()
            .map(|k| (*k).to_owned())
            .collect();
    }
    kinds
}

pub fn extension_for(kind: &str) -> &'static str {
    match kind {
        KIND_PKG => "pkg",
        KIND_ZIP_APP => "zip",
        _ => "dmg",
    }
}

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
        let label = sentinel_protocol::agent::clean_text(&job.display_name, 60)
            .unwrap_or_else(|| job.software_slug.clone());
        crate::status::write_status(
            &self.session.config_dir,
            "installing",
            format!("Installing {label}…"),
            Some(&self.session.state.device_id),
        );
        self.post_started(&credential, &job_id)?;
        // If the process is killed mid-install, startup clears this and reports failure
        // so the console does not sit on RUNNING until the job TTL expires.
        mark_in_flight(&self.session.config_dir, &job_id);

        match self.execute(&job) {
            Ok(report) => {
                self.post_result(&credential, &job_id, &report)?;
                clear_in_flight(&self.session.config_dir);
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
                    AgentError::InstallerUnsupported => "INSTALLER_UNSUPPORTED",
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
                clear_in_flight(&self.session.config_dir);
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

    /// Best-effort progress for the console. Failures never abort the install.
    fn post_progress(
        &self,
        credential: &str,
        job_id: &str,
        phase: &str,
        bytes_done: Option<u64>,
        bytes_total: Option<u64>,
    ) {
        let path = format!("/api/v1/agent/jobs/{job_id}/progress");
        let mut body = serde_json::json!({
            "protocol_version": 1,
            "phase": phase,
        });
        if let Some(n) = bytes_done {
            body["bytes_done"] = serde_json::json!(n);
        }
        if let Some(n) = bytes_total {
            body["bytes_total"] = serde_json::json!(n);
        }
        match self
            .session
            .client
            .post_json_progress(&path, Some(credential), &body)
        {
            Ok(resp) if resp.status == 200 => {}
            Ok(resp) => log::warn(
                "progress_rejected",
                serde_json::json!({ "job_id": job_id, "http_status": resp.status }),
            ),
            Err(err) => log::warn(
                "progress_unreachable",
                serde_json::json!({ "job_id": job_id, "message": err.to_string() }),
            ),
        }
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
        let env = &job.envelope;
        // Refuse unroutable envelopes before spending bandwidth on the download.
        let timeout = ipc_timeout(env)?;
        fs::create_dir_all(&self.paths.package_dir).map_err(AgentError::Io)?;
        let credential = self.session.store.load(&self.session.state.device_id)?;
        let job_id = env.job_id.as_str();
        let total = env
            .package_size_bytes
            .and_then(|n| u64::try_from(n).ok())
            .filter(|&n| n > 0);
        self.post_progress(&credential, job_id, "DOWNLOADING", Some(0), total);
        let package = self.fetch_package(env, &credential, job_id)?;
        self.post_progress(&credential, job_id, "INSTALLING", None, None);
        let request = build_request(env, &package)?;
        let response = call_privileged(&self.paths.privileged_socket, &request, timeout)?;
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

    /// Local cache, then the control plane's artifact store, then the catalogue source URL.
    fn fetch_package(
        &self,
        env: &JobEnvelope,
        credential: &str,
        job_id: &str,
    ) -> Result<PathBuf, AgentError> {
        let digest = env.package_digest.to_ascii_lowercase();
        if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AgentError::DigestMismatch);
        }
        let expected = expected_size(env.package_size_bytes)?;
        let dir = &self.paths.package_dir;
        let dest = dir.join(format!("{digest}.{}", extension_for(&env.installer_type)));

        let mut candidates = vec![dest.clone()];
        if let Some(name) = legacy_cache_name(&env.source_reference) {
            candidates.push(dir.join(name));
        }
        for path in candidates {
            if cached_matches(&path, &digest, expected)? {
                log::info("package_cached", serde_json::json!({ "path": path }));
                if let ExpectedSize::Exact(n) = expected {
                    self.post_progress(credential, job_id, "DOWNLOADING", Some(n), Some(n));
                }
                return Ok(path);
            }
        }

        let total = match expected {
            ExpectedSize::Exact(n) => Some(n),
            ExpectedSize::AtMost(_) => None,
        };
        let mut on_progress = |done: u64| {
            self.post_progress(credential, job_id, "DOWNLOADING", Some(done), total);
        };

        match self
            .session
            .client
            .open_download(&format!("/api/v1/agent/packages/{digest}"), credential)
        {
            Ok(mut reader) => {
                save_verified(&mut reader, &dest, &digest, expected, Some(&mut on_progress))?;
                log::info(
                    "package_downloaded",
                    serde_json::json!({ "path": dest, "source": "control_plane" }),
                );
                return Ok(dest);
            }
            Err(err) => log::warn(
                "artifact_download_unavailable",
                serde_json::json!({ "message": err.to_string(), "http_status": err.status() }),
            ),
        }

        let source = &env.source_reference;
        if !source.starts_with("https://") {
            return Err(AgentError::DownloadFailed);
        }
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(DOWNLOAD_TIMEOUT))
            .http_status_as_error(false)
            .https_only(true)
            .max_redirects(5)
            .user_agent(concat!("SentinelDesk-Agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        let mut response = agent
            .get(source)
            .call()
            .map_err(|_| AgentError::DownloadFailed)?;
        if response.status().as_u16() != 200 {
            return Err(AgentError::DownloadFailed);
        }
        let mut reader = response.body_mut().as_reader();
        save_verified(&mut reader, &dest, &digest, expected, Some(&mut on_progress))?;
        log::info(
            "package_downloaded",
            serde_json::json!({ "path": dest, "source": "catalogue_url" }),
        );
        Ok(dest)
    }
}

/// Exact byte count when the catalogue knows it; otherwise the legacy ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedSize {
    Exact(u64),
    AtMost(u64),
}

impl ExpectedSize {
    fn limit(self) -> u64 {
        match self {
            Self::Exact(n) | Self::AtMost(n) => n,
        }
    }

    fn accepts(self, total: u64) -> bool {
        match self {
            Self::Exact(n) => total == n,
            Self::AtMost(n) => total <= n,
        }
    }
}

fn expected_size(raw: Option<i64>) -> Result<ExpectedSize, AgentError> {
    match raw {
        None => Ok(ExpectedSize::AtMost(LEGACY_MAX_BYTES)),
        Some(n) => match u64::try_from(n) {
            Ok(n) if (1..=MAX_PACKAGE_BYTES).contains(&n) => Ok(ExpectedSize::Exact(n)),
            _ => Err(AgentError::DownloadFailed),
        },
    }
}

/// Pre-content-addressing caches were keyed by the source URL's file name.
fn legacy_cache_name(source: &str) -> Option<&str> {
    let name = source.rsplit('/').next()?;
    let ok = !name.is_empty()
        && name.len() <= 200
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
        && [".pkg", ".dmg", ".zip"]
            .iter()
            .any(|ext| name.ends_with(ext));
    ok.then_some(name)
}

fn cached_matches(path: &Path, digest: &str, expected: ExpectedSize) -> Result<bool, AgentError> {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return Ok(false);
    };
    if !meta.file_type().is_file() || !expected.accepts(meta.len()) {
        return Ok(false);
    }
    let (actual, total) = hash_file(path)?;
    Ok(actual.eq_ignore_ascii_case(digest) && expected.accepts(total))
}

/// Stream into a private temp file next to `dest`, verify size and digest, then rename.
fn save_verified(
    reader: &mut dyn Read,
    dest: &Path,
    digest: &str,
    expected: ExpectedSize,
    on_progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), AgentError> {
    let file_name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let partial = dest.with_file_name(format!(".{file_name}.{}.part", std::process::id()));
    let result = write_verified(reader, &partial, digest, expected, on_progress)
        .and_then(|()| fs::rename(&partial, dest).map_err(AgentError::Io));
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result
}

fn write_verified(
    reader: &mut dyn Read,
    partial: &Path,
    digest: &str,
    expected: ExpectedSize,
    mut on_progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(), AgentError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(partial)
        .map_err(AgentError::Io)?;
    let limit = expected.limit();
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; 64 * 1024];
    let mut total = 0_u64;
    let mut last_report: Option<Instant> = None;
    let mut last_bytes = 0_u64;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|_| AgentError::DownloadFailed)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > limit {
            return Err(AgentError::DownloadFailed);
        }
        file.write_all(&buf[..n]).map_err(AgentError::Io)?;
        hasher.update(&buf[..n]);
        if let Some(cb) = on_progress.as_mut() {
            let due = match last_report {
                None => true,
                Some(at) => {
                    at.elapsed() >= PROGRESS_MIN_INTERVAL
                        || total.saturating_sub(last_bytes) >= PROGRESS_MIN_BYTES
                }
            };
            if due {
                cb(total);
                last_report = Some(Instant::now());
                last_bytes = total;
            }
        }
    }
    file.sync_all().map_err(AgentError::Io)?;
    if !expected.accepts(total) {
        return Err(AgentError::DownloadFailed);
    }
    if !format!("{:x}", hasher.finalize()).eq_ignore_ascii_case(digest) {
        return Err(AgentError::DigestMismatch);
    }
    if let Some(cb) = on_progress.as_mut() {
        cb(total);
    }
    Ok(())
}

fn ipc_timeout(env: &JobEnvelope) -> Result<Duration, AgentError> {
    if env.installer_type == KIND_PKG {
        Ok(PKG_IPC_TIMEOUT)
    } else if is_archive_kind(&env.installer_type)
        && env.expected_team_id.is_some()
        && env.payload_path.is_some()
    {
        Ok(ARCHIVE_IPC_TIMEOUT)
    } else {
        Err(AgentError::InstallerUnsupported)
    }
}

fn build_request(env: &JobEnvelope, package: &Path) -> Result<PrivilegedRequest, AgentError> {
    let path = package.to_string_lossy().into_owned();
    if env.installer_type == KIND_PKG {
        return Ok(PrivilegedRequest::InstallPkg {
            protocol_version: IPC_PROTOCOL_VERSION,
            job_id: env.job_id.clone(),
            pkg_path: path,
            package_identifier: env.package_identifier.clone(),
            expected_version: env.package_version.clone(),
            package_digest: env.package_digest.clone(),
        });
    }
    let (Some(team), Some(payload)) = (&env.expected_team_id, &env.payload_path) else {
        return Err(AgentError::InstallerUnsupported);
    };
    if !is_archive_kind(&env.installer_type) {
        return Err(AgentError::InstallerUnsupported);
    }
    Ok(PrivilegedRequest::InstallArchive {
        protocol_version: IPC_PROTOCOL_VERSION,
        job_id: env.job_id.clone(),
        kind: env.installer_type.clone(),
        archive_path: path,
        payload_path: payload.clone(),
        package_identifier: env.package_identifier.clone(),
        expected_version: env.package_version.clone(),
        expected_team_id: team.clone(),
        package_digest: env.package_digest.clone(),
    })
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

fn in_flight_path(config_dir: &Path) -> PathBuf {
    config_dir.join("in_flight_job.json")
}

fn mark_in_flight(config_dir: &Path, job_id: &str) {
    let path = in_flight_path(config_dir);
    let body = serde_json::json!({ "job_id": job_id });
    if let Ok(bytes) = serde_json::to_vec(&body) {
        let _ = fs::create_dir_all(config_dir);
        let tmp = path.with_extension("json.tmp");
        if fs::write(&tmp, bytes).is_ok() {
            let _ = fs::rename(&tmp, &path);
        }
    }
}

fn clear_in_flight(config_dir: &Path) {
    let _ = fs::remove_file(in_flight_path(config_dir));
}

/// After a crash/restart: close any job the previous process left mid-install.
pub fn fail_interrupted_job(session: &Session) {
    let path = in_flight_path(&session.config_dir);
    let Ok(bytes) = fs::read(&path) else {
        return;
    };
    let _ = fs::remove_file(&path);
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return;
    };
    let Some(job_id) = value.get("job_id").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return;
    };
    let Ok(credential) = session.store.load(&session.state.device_id) else {
        return;
    };
    let paths = JobPaths::from_env(&session.config_dir);
    let runner = JobRunner {
        session,
        paths: &paths,
    };
    let failure = JobReport {
        result_code: "INSTALL_INTERRUPTED".into(),
        result_summary: "agent restarted before the install finished; try again".into(),
        exit_code: None,
        installed_version: None,
        verification_status: "NOT_ATTEMPTED",
    };
    match runner.post_result(&credential, job_id, &failure) {
        Ok(()) => log::warn(
            "interrupted_job_closed",
            serde_json::json!({ "job_id": job_id }),
        ),
        Err(err) => log::warn(
            "interrupted_job_close_failed",
            serde_json::json!({ "job_id": job_id, "message": err.to_string() }),
        ),
    }
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

fn call_privileged(
    socket: &Path,
    request: &PrivilegedRequest,
    read_timeout: Duration,
) -> Result<PrivilegedResponse, AgentError> {
    let mut stream = UnixStream::connect(socket).map_err(|_| AgentError::PrivilegedUnavailable)?;
    let _ = stream.set_read_timeout(Some(read_timeout));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let body = serde_json::to_vec(request).map_err(|_| AgentError::PrivilegedUnavailable)?;
    stream
        .write_all(&body)
        .map_err(|_| AgentError::PrivilegedUnavailable)?;
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut buf = Vec::new();
    stream
        .take(64 * 1024)
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
        assert_eq!(bytes, br#"{"a":null,"b":2,"nested":{"y":"x","z":true}}"#);
    }

    fn envelope(kind: &str, team: Option<&str>, payload: Option<&str>) -> JobEnvelope {
        JobEnvelope {
            job_id: "6b0c3c54-2f87-4d43-9c0e-1d1a8c3b2e10".into(),
            device_id: "d".into(),
            nonce: "n".into(),
            issued_at: "t".into(),
            expires_at: "t".into(),
            package_digest: "a".repeat(64),
            catalogue_version_id: "v".into(),
            policy_revision: None,
            request_binding_hash: "h".into(),
            request_id: "r".into(),
            installer_type: kind.into(),
            source_type: "CONTROLLED_UPLOAD".into(),
            source_reference: "artifact://sha256/x.dmg".into(),
            package_identifier: "com.tinyspeck.slackmacgap".into(),
            package_version: "4.47.69".into(),
            os_family: "macos".into(),
            architecture: "universal".into(),
            signature_publisher: None,
            verification_method: "APP_BUNDLE".into(),
            package_size_bytes: Some(10),
            expected_team_id: team.map(Into::into),
            payload_path: payload.map(Into::into),
        }
    }

    #[test]
    fn routes_by_installer_type() {
        let pkg = envelope(KIND_PKG, None, None);
        assert!(matches!(
            build_request(&pkg, Path::new("/p/a.pkg")),
            Ok(PrivilegedRequest::InstallPkg { .. })
        ));
        assert_eq!(ipc_timeout(&pkg).ok(), Some(PKG_IPC_TIMEOUT));

        let dmg = envelope("MACOS_DMG_APP", Some("BQR82RBBHL"), Some("Slack.app"));
        assert!(matches!(
            build_request(&dmg, Path::new("/p/a.dmg")),
            Ok(PrivilegedRequest::InstallArchive { ref kind, ref expected_team_id, .. })
                if kind == "MACOS_DMG_APP" && expected_team_id == "BQR82RBBHL"
        ));
        assert_eq!(ipc_timeout(&dmg).ok(), Some(ARCHIVE_IPC_TIMEOUT));

        let missing = envelope("MACOS_ZIP_APP", None, Some("Code.app"));
        assert!(matches!(
            ipc_timeout(&missing),
            Err(AgentError::InstallerUnsupported)
        ));
        let unknown = envelope("WINDOWS_MSI", Some("BQR82RBBHL"), Some("x.app"));
        assert!(matches!(
            build_request(&unknown, Path::new("/p/a")),
            Err(AgentError::InstallerUnsupported)
        ));
    }

    #[test]
    fn extensions_and_legacy_names() {
        assert_eq!(extension_for(KIND_PKG), "pkg");
        assert_eq!(extension_for(KIND_ZIP_APP), "zip");
        assert_eq!(extension_for("MACOS_DMG_PKG"), "dmg");
        assert_eq!(
            legacy_cache_name("https://cdn.example.com/a/Zoom-6.1.pkg"),
            Some("Zoom-6.1.pkg")
        );
        assert_eq!(legacy_cache_name("https://x/../../etc/passwd"), None);
        assert_eq!(legacy_cache_name("https://x/.hidden.pkg"), None);
        assert_eq!(legacy_cache_name("https://x/run.sh"), None);
    }

    #[test]
    fn expected_size_is_exact_when_known() {
        assert_eq!(expected_size(Some(10)).ok(), Some(ExpectedSize::Exact(10)));
        assert_eq!(
            expected_size(None).ok(),
            Some(ExpectedSize::AtMost(LEGACY_MAX_BYTES))
        );
        assert!(expected_size(Some(0)).is_err());
        assert!(expected_size(Some(-1)).is_err());
        assert!(ExpectedSize::Exact(10).accepts(10));
        assert!(!ExpectedSize::Exact(10).accepts(9));
    }

    #[test]
    fn save_verified_checks_size_and_digest_and_cleans_up() {
        let Ok(dir) = tempfile::tempdir() else { return };
        let body = b"0123456789";
        let digest = format!("{:x}", Sha256::digest(body));
        let dest = dir.path().join(format!("{digest}.dmg"));

        let short = save_verified(&mut &body[..9], &dest, &digest, ExpectedSize::Exact(10), None);
        assert!(matches!(short, Err(AgentError::DownloadFailed)));
        let long = save_verified(&mut &body[..], &dest, &digest, ExpectedSize::Exact(9), None);
        assert!(matches!(long, Err(AgentError::DownloadFailed)));
        let wrong = save_verified(
            &mut &body[..],
            &dest,
            &"b".repeat(64),
            ExpectedSize::Exact(10),
            None,
        );
        assert!(matches!(wrong, Err(AgentError::DigestMismatch)));
        assert!(!dest.exists());
        assert_eq!(fs::read_dir(dir.path()).map(Iterator::count).ok(), Some(0));

        assert!(save_verified(&mut &body[..], &dest, &digest, ExpectedSize::Exact(10), None).is_ok());
        assert!(matches!(
            cached_matches(&dest, &digest, ExpectedSize::Exact(10)),
            Ok(true)
        ));
        assert!(matches!(
            cached_matches(&dest, &digest, ExpectedSize::Exact(11)),
            Ok(false)
        ));
    }

    #[test]
    fn unreachable_daemon_still_advertises_pkg() {
        let kinds = probe_installers(Path::new("/nonexistent/sentinel.sock"));
        assert_eq!(kinds, vec![KIND_PKG.to_owned()]);
        assert_eq!(agent_installers().len(), 4);
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
