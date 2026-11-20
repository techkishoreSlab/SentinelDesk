//! Enrollment, heartbeat, credential rotation and the long-running agent loop.
//!
//! Phase 8: claimed jobs are signature-verified, downloaded, and handed to the privileged
//! service over a Unix socket. Without the job public key or socket the agent fails closed.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use sentinel_protocol::PROTOCOL_VERSION;
use sentinel_protocol::agent::{
    ENROLLMENT_PREFIX, EnrollRequest, EnrollResponse, HeartbeatRequest, HeartbeatResponse,
    RotateResponse, well_formed_secret,
};

use crate::backend_url::{BackendOrigin, UrlError};
use crate::credstore::{CredentialStore, StoreError};
use crate::facts::{self, FactsError};
use crate::http::{Client, HttpError};
use crate::jobs::{JobPaths, JobRunner};
use crate::log;
use crate::state::{AgentState, StateError, StoreKind};

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const BASE_BACKOFF: Duration = Duration::from_secs(5);
const SLEEP_SLICE: Duration = Duration::from_millis(250);

#[derive(Debug)]
pub enum AgentError {
    Url(UrlError),
    State(StateError),
    Store(StoreError),
    Facts(FactsError),
    Http(HttpError),
    Protocol(sentinel_protocol::ProtocolError),
    AlreadyEnrolled,
    TokenInvalidFormat,
    DeviceMismatch,
    Io(std::io::Error),
    HttpStatus(u16),
    SignatureInvalid,
    DigestMismatch,
    DownloadFailed,
    PrivilegedUnavailable,
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url(e) => write!(f, "{e}"),
            Self::State(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Facts(e) => write!(f, "{e}"),
            Self::Http(e) => write!(f, "{e}"),
            Self::Protocol(e) => write!(f, "invalid backend response: {e}"),
            Self::AlreadyEnrolled => {
                write!(
                    f,
                    "device is already enrolled; pass --force to replace the local enrollment"
                )
            }
            Self::TokenInvalidFormat => write!(f, "enrollment token is not in the expected format"),
            Self::DeviceMismatch => write!(f, "backend answered for a different device id"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::HttpStatus(status) => write!(f, "backend returned HTTP {status}"),
            Self::SignatureInvalid => write!(f, "job signature verification failed"),
            Self::DigestMismatch => write!(f, "downloaded package digest mismatch"),
            Self::DownloadFailed => write!(f, "package download failed"),
            Self::PrivilegedUnavailable => {
                write!(f, "privileged install service is unavailable")
            }
        }
    }
}

impl std::error::Error for AgentError {}

impl From<HttpError> for AgentError {
    fn from(e: HttpError) -> Self {
        Self::Http(e)
    }
}
impl From<StateError> for AgentError {
    fn from(e: StateError) -> Self {
        Self::State(e)
    }
}
impl From<StoreError> for AgentError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<FactsError> for AgentError {
    fn from(e: FactsError) -> Self {
        Self::Facts(e)
    }
}
impl From<sentinel_protocol::ProtocolError> for AgentError {
    fn from(e: sentinel_protocol::ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

impl AgentError {
    /// Revoked/expired credential or quarantined device: the loop must stop, not retry.
    pub fn is_fatal_auth(&self) -> bool {
        matches!(self, Self::Http(e) if e.is_fatal_auth())
    }

    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::Http(e) => e.status(),
            Self::HttpStatus(status) => Some(*status),
            _ => None,
        }
    }
}

/// An enrolled device: persisted state, its credential store and an HTTP client.
pub struct Session {
    pub config_dir: PathBuf,
    pub state: AgentState,
    pub(crate) store: CredentialStore,
    pub(crate) client: Client,
}

impl Session {
    pub fn open(config_dir: &Path) -> Result<Self, AgentError> {
        let state = AgentState::load(config_dir)?;
        let origin = BackendOrigin::parse(&state.backend_url).map_err(AgentError::Url)?;
        let client = Client::new(origin, state.ca_file.as_deref())?;
        let store = CredentialStore::new(state.credential_store, config_dir)?;
        Ok(Self {
            config_dir: config_dir.to_path_buf(),
            state,
            store,
            client,
        })
    }

    pub fn credential_present(&self) -> Result<bool, AgentError> {
        match self.store.load(&self.state.device_id) {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub fn heartbeat(&mut self) -> Result<HeartbeatResponse, AgentError> {
        let credential = self.store.load(&self.state.device_id)?;
        let facts = facts::collect()?;
        let body = HeartbeatRequest {
            protocol_version: PROTOCOL_VERSION,
            agent_version: AGENT_VERSION,
            facts: &facts,
        };
        let response =
            self.client
                .post_json("/api/v1/agent/heartbeat", Some(&credential), &body)?;
        let hb = HeartbeatResponse::parse(&response.body)?;
        if hb.device_id != self.state.device_id {
            return Err(AgentError::DeviceMismatch);
        }
        if self.state.heartbeat_interval_seconds != hb.next_heartbeat_seconds
            || self.state.credential_expires_at != hb.credential_expires_at
        {
            self.state.heartbeat_interval_seconds = hb.next_heartbeat_seconds;
            self.state
                .credential_expires_at
                .clone_from(&hb.credential_expires_at);
            self.state.save(&self.config_dir)?;
        }
        Ok(hb)
    }

    /// Obtain a new credential and persist it. The backend revokes the old credential on the
    /// first request authenticated with the new one (10-minute grace period otherwise).
    pub fn rotate(&mut self) -> Result<(), AgentError> {
        let credential = self.store.load(&self.state.device_id)?;
        let response = self
            .client
            .post_empty("/api/v1/agent/credential/rotate", &credential)?;
        let rotated = RotateResponse::parse(&response.body)?;
        self.store
            .save(&self.state.device_id, &rotated.device_credential)?;
        self.state.credential_expires_at = rotated.credential_expires_at;
        self.state.save(&self.config_dir)?;
        log::info(
            "credential_rotated",
            serde_json::json!({
                "device_id": self.state.device_id,
                "credential_expires_at": self.state.credential_expires_at,
            }),
        );
        Ok(())
    }

    /// Claim and execute at most one signed job. Returns true when a job was processed.
    pub fn run_job_once(&self) -> Result<bool, AgentError> {
        let paths = JobPaths::from_env(&self.config_dir);
        JobRunner {
            session: self,
            paths: &paths,
        }
        .run_once()
    }

    pub fn forget(self) -> Result<(), AgentError> {
        self.store.delete(&self.state.device_id)?;
        AgentState::remove(&self.config_dir)?;
        Ok(())
    }
}

pub struct EnrollOptions<'a> {
    pub backend: &'a str,
    pub ca_file: Option<&'a Path>,
    pub store: StoreKind,
    pub config_dir: &'a Path,
    pub force: bool,
}

pub fn enroll(opts: &EnrollOptions<'_>, token: &str) -> Result<AgentState, AgentError> {
    if !well_formed_secret(token, ENROLLMENT_PREFIX) {
        return Err(AgentError::TokenInvalidFormat);
    }
    // The previous enrollment stays usable until the new one is fully persisted.
    let previous = match Session::open(opts.config_dir) {
        Ok(existing) if opts.force => Some(existing),
        Ok(_) => return Err(AgentError::AlreadyEnrolled),
        Err(AgentError::State(StateError::NotEnrolled)) => None,
        Err(_) if opts.force => None,
        Err(e) => return Err(e),
    };
    let origin = BackendOrigin::parse(opts.backend).map_err(AgentError::Url)?;
    let ca_file = opts
        .ca_file
        .map(std::fs::canonicalize)
        .transpose()
        .map_err(AgentError::Io)?;
    let client = Client::new(origin.clone(), ca_file.as_deref())?;
    let store = CredentialStore::new(opts.store, opts.config_dir)?;
    let facts = facts::collect()?;
    let body = EnrollRequest {
        protocol_version: PROTOCOL_VERSION,
        enrollment_token: token,
        agent_version: AGENT_VERSION,
        facts: &facts,
    };
    let response = client.post_json("/api/v1/agent/enroll", None, &body)?;
    let enrolled = EnrollResponse::parse(&response.body)?;
    store.save(&enrolled.device_id, &enrolled.device_credential)?;
    let state = AgentState {
        backend_url: origin.as_str().to_owned(),
        ca_file,
        device_id: enrolled.device_id,
        credential_store: opts.store,
        credential_expires_at: enrolled.credential_expires_at,
        heartbeat_interval_seconds: enrolled.heartbeat_interval_seconds,
    };
    if let Err(e) = state.save(opts.config_dir) {
        let _ = store.delete(&state.device_id);
        return Err(e.into());
    }
    if let Some(old) = previous.filter(|old| old.state.device_id != state.device_id)
        && let Err(e) = old.store.delete(&old.state.device_id)
    {
        log::warn(
            "old_credential_not_deleted",
            serde_json::json!({
                "device_id": old.state.device_id,
                "message": e.to_string(),
            }),
        );
    }
    Ok(state)
}

/// Uniform random fraction in [0, 1). Falls back to 0.5 if the OS RNG is unavailable, which
/// only weakens jitter, never security.
fn random_unit() -> f64 {
    getrandom::u64().map_or(0.5, |v| (v >> 11) as f64 / (1u64 << 53) as f64)
}

/// Interval with ±10% jitter so a fleet does not heartbeat in lockstep.
pub fn jittered(interval_secs: u64) -> Duration {
    let base = interval_secs as f64;
    Duration::from_secs_f64(base * (0.9 + 0.2 * random_unit()))
}

/// Exponential backoff with full jitter, capped at `MAX_BACKOFF`.
pub fn backoff(attempt: u32) -> Duration {
    let ceiling = BASE_BACKOFF
        .saturating_mul(1u32 << attempt.min(16))
        .min(MAX_BACKOFF);
    ceiling.mul_f64(0.5 + 0.5 * random_unit())
}

fn sleep_unless_stopped(duration: Duration, stop: &AtomicBool) {
    let deadline = Instant::now() + duration;
    while !stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        std::thread::sleep(SLEEP_SLICE.min(deadline - now));
    }
}

pub enum RunOutcome {
    Stopped,
    AuthRevoked,
}

pub fn run(mut session: Session, stop: &Arc<AtomicBool>, max_cycles: Option<u64>) -> RunOutcome {
    let config_dir = session.config_dir.clone();
    let device_id = session.state.device_id.clone();
    crate::status::write_status(
        &config_dir,
        "online",
        "Online · waiting for jobs",
        Some(&device_id),
    );
    log::info(
        "agent_started",
        serde_json::json!({
            "device_id": session.state.device_id,
            "backend": session.state.backend_url,
            "agent_version": AGENT_VERSION,
        }),
    );
    let mut failures: u32 = 0;
    let mut cycles: u64 = 0;
    while !stop.load(Ordering::SeqCst) {
        let wait = match cycle(&mut session) {
            Ok(next) => {
                failures = 0;
                crate::status::write_status(
                    &config_dir,
                    "online",
                    "Online · waiting for jobs",
                    Some(&device_id),
                );
                jittered(next)
            }
            Err(e) if e.is_fatal_auth() => {
                crate::status::write_status(
                    &config_dir,
                    "error",
                    "Auth revoked — re-enroll required",
                    Some(&device_id),
                );
                log::error(
                    "agent_auth_revoked",
                    serde_json::json!({
                        "device_id": session.state.device_id,
                        "message": e.to_string(),
                    }),
                );
                return RunOutcome::AuthRevoked;
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                let wait = backoff(failures - 1);
                crate::status::write_status(
                    &config_dir,
                    "degraded",
                    format!("Offline · retry in {}s", wait.as_secs()),
                    Some(&device_id),
                );
                log::warn(
                    "heartbeat_failed",
                    serde_json::json!({
                        "message": e.to_string(),
                        "http_status": e.http_status(),
                        "retry_in_seconds": wait.as_secs(),
                    }),
                );
                wait
            }
        };
        cycles += 1;
        if max_cycles.is_some_and(|m| cycles >= m) {
            break;
        }
        sleep_unless_stopped(wait, stop);
    }
    crate::status::write_status(&config_dir, "stopped", "Stopped", Some(&device_id));
    log::info(
        "agent_stopped",
        serde_json::json!({ "device_id": session.state.device_id }),
    );
    RunOutcome::Stopped
}

fn cycle(session: &mut Session) -> Result<u64, AgentError> {
    let hb = session.heartbeat()?;
    log::info(
        "heartbeat_ok",
        serde_json::json!({
            "device_status": hb.device_status,
            "next_heartbeat_seconds": hb.next_heartbeat_seconds,
        }),
    );
    if hb.rotate_credential {
        session.rotate()?;
    }
    crate::status::write_status(
        &session.config_dir,
        "online",
        "Online · checking jobs",
        Some(&session.state.device_id),
    );
    match session.run_job_once() {
        Ok(true) => {
            crate::status::write_status(
                &session.config_dir,
                "installing",
                "Online · installing…",
                Some(&session.state.device_id),
            );
        }
        Ok(false) => {}
        Err(e) => {
            // Non-auth job failures should not stop the heartbeat loop; report and continue.
            if e.is_fatal_auth() {
                return Err(e);
            }
            crate::status::write_status(
                &session.config_dir,
                "degraded",
                format!("Online · job issue: {e}"),
                Some(&session.state.device_id),
            );
            log::warn(
                "job_failed",
                serde_json::json!({
                    "message": e.to_string(),
                    "http_status": e.http_status(),
                }),
            );
        }
    }
    Ok(hb.next_heartbeat_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_within_ten_percent() {
        for _ in 0..200 {
            let d = jittered(60).as_secs_f64();
            assert!((54.0..=66.0).contains(&d), "{d}");
        }
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        for attempt in 0..40 {
            let d = backoff(attempt);
            let ceiling = BASE_BACKOFF
                .saturating_mul(1u32 << attempt.min(16))
                .min(MAX_BACKOFF);
            assert!(d <= ceiling && d >= ceiling / 2, "attempt {attempt}: {d:?}");
        }
        assert!(backoff(30) <= MAX_BACKOFF);
    }

    #[test]
    fn enroll_rejects_malformed_tokens_before_any_io() {
        let Ok(dir) = tempfile::tempdir() else { return };
        let opts = EnrollOptions {
            backend: "https://localhost:1",
            ca_file: None,
            store: StoreKind::File,
            config_dir: dir.path(),
            force: false,
        };
        for bad in [
            "",
            "sdc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "sde_short",
            "sde_$$$",
        ] {
            assert!(matches!(
                enroll(&opts, bad),
                Err(AgentError::TokenInvalidFormat)
            ));
        }
    }

    #[test]
    fn stop_flag_interrupts_sleep() {
        let stop = AtomicBool::new(true);
        let start = Instant::now();
        sleep_unless_stopped(Duration::from_secs(30), &stop);
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
