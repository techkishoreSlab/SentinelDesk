//! SentinelDesk user-mode agent.
//!
//! Enrollment, heartbeat, credential rotation, and Phase 8 signed-job execution via the
//! privileged install service (Unix socket IPC).

mod agent;
mod backend_url;
mod credstore;
mod facts;
mod http;
mod jobs;
mod log;
mod state;
mod status;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use clap::{Args, Parser, Subcommand};
use sentinel_protocol::{LiveStatus, PROTOCOL_VERSION};

use crate::agent::{AgentError, EnrollOptions, RunOutcome, Session};
use crate::backend_url::BackendOrigin;
use crate::http::Client;
use crate::state::StoreKind;

const TOKEN_ENV: &str = "SENTINEL_ENROLLMENT_TOKEN";
const EXIT_AUTH_REVOKED: u8 = 3;

#[derive(Parser)]
#[command(
    name = "sentinel-agent",
    version,
    about = "SentinelDesk endpoint agent"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct ConfigArgs {
    /// Directory for agent state (default: the per-user application config directory).
    #[arg(long, env = "SENTINEL_AGENT_CONFIG_DIR")]
    config_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Check that the SentinelDesk backend is reachable and healthy.
    CheckBackend {
        /// Backend origin, e.g. https://sentinel.example.com (http allowed for loopback only).
        #[arg(long, env = "SENTINEL_BACKEND_URL")]
        backend: String,
        /// PEM CA certificate to trust exclusively for the backend's TLS certificate.
        #[arg(long, env = "SENTINEL_CA_CERT")]
        ca_cert: Option<PathBuf>,
    },
    /// Enroll this device with a one-time token issued by an administrator.
    ///
    /// The token is read from the SENTINEL_ENROLLMENT_TOKEN environment variable or prompted
    /// for without echo; it is never accepted as a command-line argument.
    Enroll {
        #[arg(long, env = "SENTINEL_BACKEND_URL")]
        backend: String,
        #[arg(long, env = "SENTINEL_CA_CERT")]
        ca_cert: Option<PathBuf>,
        /// Where to keep the device credential (default: keychain on macOS; required elsewhere).
        #[arg(long, value_enum)]
        credential_store: Option<StoreKind>,
        /// Replace an existing local enrollment.
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        config: ConfigArgs,
    },
    /// Send a single heartbeat with current device facts.
    Heartbeat {
        #[command(flatten)]
        config: ConfigArgs,
    },
    /// Run continuously: heartbeat, rotate when asked, and poll for jobs.
    Run {
        /// Stop after this many cycles (for testing).
        #[arg(long, hide = true)]
        max_cycles: Option<u64>,
        #[command(flatten)]
        config: ConfigArgs,
    },
    /// Rotate the device credential now.
    RotateCredential {
        #[command(flatten)]
        config: ConfigArgs,
    },
    /// Show local enrollment state (never prints the credential).
    Status {
        #[command(flatten)]
        config: ConfigArgs,
    },
    /// Delete the local enrollment and stored credential. Does not revoke it server-side.
    Forget {
        /// Confirm deletion.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        config: ConfigArgs,
    },
}

#[derive(Debug)]
enum CliError {
    Agent(AgentError),
    NoConfigDir,
    StoreRequired,
    TokenUnavailable,
    NotConfirmed,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Agent(e) => write!(f, "{e}"),
            Self::NoConfigDir => {
                write!(f, "cannot determine a config directory; pass --config-dir")
            }
            Self::StoreRequired => write!(
                f,
                "no OS credential store is supported on this platform; pass --credential-store file"
            ),
            Self::TokenUnavailable => {
                write!(
                    f,
                    "enrollment token not provided (set {TOKEN_ENV} or run interactively)"
                )
            }
            Self::NotConfirmed => write!(f, "refusing to delete local enrollment without --yes"),
        }
    }
}

impl<E: Into<AgentError>> From<E> for CliError {
    fn from(e: E) -> Self {
        Self::Agent(e.into())
    }
}

fn config_dir(args: &ConfigArgs) -> Result<PathBuf, CliError> {
    if let Some(dir) = &args.config_dir {
        return Ok(dir.clone());
    }
    directories::ProjectDirs::from("com", "SentinelDesk", "Agent")
        .map(|p| p.config_dir().to_path_buf())
        .ok_or(CliError::NoConfigDir)
}

fn default_store() -> Option<StoreKind> {
    cfg!(target_os = "macos").then_some(StoreKind::Keychain)
}

fn read_token() -> Result<String, CliError> {
    if let Ok(token) = std::env::var(TOKEN_ENV) {
        return Ok(token.trim().to_owned());
    }
    rpassword::prompt_password("Enrollment token: ")
        .map(|t| t.trim().to_owned())
        .map_err(|_| CliError::TokenUnavailable)
}

fn print(value: &serde_json::Value) {
    println!("{value}");
}

fn check_backend(raw_url: &str, ca: Option<&Path>) -> Result<LiveStatus, CliError> {
    let origin = BackendOrigin::parse(raw_url).map_err(|e| CliError::Agent(AgentError::Url(e)))?;
    let client = Client::new(origin, ca)?;
    let response = client.get("/health/live", None)?;
    Ok(LiveStatus::parse(&response.body)?)
}

fn execute(command: Command) -> Result<ExitCode, CliError> {
    match command {
        Command::CheckBackend { backend, ca_cert } => {
            let live = check_backend(&backend, ca_cert.as_deref())?;
            print(&serde_json::json!({
                "event": "backend_check",
                "result": "ok",
                "backend_version": live.version,
                "protocol_version": PROTOCOL_VERSION,
            }));
        }
        Command::Enroll {
            backend,
            ca_cert,
            credential_store,
            force,
            config,
        } => {
            let store = credential_store
                .or_else(default_store)
                .ok_or(CliError::StoreRequired)?;
            let dir = config_dir(&config)?;
            let token = read_token()?;
            let state = agent::enroll(
                &EnrollOptions {
                    backend: &backend,
                    ca_file: ca_cert.as_deref(),
                    store,
                    config_dir: &dir,
                    force,
                },
                &token,
            )?;
            print(&serde_json::json!({
                "event": "enrolled",
                "device_id": state.device_id,
                "credential_store": state.credential_store,
                "credential_expires_at": state.credential_expires_at,
                "config_dir": dir,
            }));
        }
        Command::Heartbeat { config } => {
            let mut session = Session::open(&config_dir(&config)?)?;
            let hb = session.heartbeat()?;
            if hb.rotate_credential {
                session.rotate()?;
            }
            print(&serde_json::json!({
                "event": "heartbeat",
                "device_id": hb.device_id,
                "device_status": hb.device_status,
                "next_heartbeat_seconds": hb.next_heartbeat_seconds,
                "rotated": hb.rotate_credential,
            }));
        }
        Command::Run { max_cycles, config } => {
            let session = Session::open(&config_dir(&config)?)?;
            let stop = Arc::new(AtomicBool::new(false));
            let handler_stop = Arc::clone(&stop);
            if ctrlc::set_handler(move || handler_stop.store(true, Ordering::SeqCst)).is_err() {
                log::warn("signal_handler_unavailable", serde_json::json!({}));
            }
            if let RunOutcome::AuthRevoked = agent::run(session, &stop, max_cycles) {
                return Ok(ExitCode::from(EXIT_AUTH_REVOKED));
            }
        }
        Command::RotateCredential { config } => {
            let mut session = Session::open(&config_dir(&config)?)?;
            session.rotate()?;
            // Authenticate once with the new credential so the backend retires the old one.
            session.heartbeat()?;
            print(&serde_json::json!({
                "event": "credential_rotated",
                "device_id": session.state.device_id,
                "credential_expires_at": session.state.credential_expires_at,
            }));
        }
        Command::Status { config } => {
            let session = Session::open(&config_dir(&config)?)?;
            let present = session.credential_present()?;
            print(&serde_json::json!({
                "event": "status",
                "device_id": session.state.device_id,
                "backend": session.state.backend_url,
                "ca_file": session.state.ca_file,
                "credential_store": session.state.credential_store,
                "credential_present": present,
                "credential_expires_at": session.state.credential_expires_at,
                "heartbeat_interval_seconds": session.state.heartbeat_interval_seconds,
            }));
        }
        Command::Forget { yes, config } => {
            if !yes {
                return Err(CliError::NotConfirmed);
            }
            Session::open(&config_dir(&config)?)?.forget()?;
            print(&serde_json::json!({ "event": "forgotten" }));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match execute(cli.command) {
        Ok(code) => code,
        Err(err) => {
            let fatal = matches!(&err, CliError::Agent(e) if e.is_fatal_auth());
            log::error(
                "command_failed",
                serde_json::json!({ "message": err.to_string() }),
            );
            if fatal {
                ExitCode::from(EXIT_AUTH_REVOKED)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
