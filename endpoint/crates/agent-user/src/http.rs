//! HTTPS client for the control plane.
//!
//! When a CA file is configured the agent trusts *only* that CA (no OS or Mozilla roots), so
//! a certificate from any other issuer is rejected. Responses are size-bounded, redirects are
//! refused, and every request has a global timeout.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use sentinel_protocol::{ApiErrorEnvelope, MAX_RESPONSE_BYTES};
use ureq::tls::{Certificate, RootCerts, TlsConfig};

use crate::backend_url::BackendOrigin;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Progress POSTs must never stall an install if the control plane is slow.
const PROGRESS_TIMEOUT: Duration = Duration::from_secs(3);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_CA_FILE_BYTES: u64 = 64 * 1024;

#[derive(Debug)]
pub enum HttpError {
    CaFile(String),
    Unreachable,
    TooLarge,
    /// Non-success HTTP status with the backend's public error code, if any.
    Status {
        status: u16,
        code: Option<String>,
    },
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CaFile(msg) => write!(f, "CA certificate file: {msg}"),
            Self::Unreachable => write!(f, "backend unreachable or TLS verification failed"),
            Self::TooLarge => write!(f, "backend response exceeded size limit"),
            Self::Status { status, code } => {
                write!(f, "backend returned HTTP {status}")?;
                if let Some(code) = code {
                    write!(f, " ({code})")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for HttpError {}

impl HttpError {
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Status { code, .. } => code.as_deref(),
            _ => None,
        }
    }

    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Credential revoked/expired or device quarantined: retrying will not help.
    pub fn is_fatal_auth(&self) -> bool {
        matches!(
            self.code(),
            Some("DEVICE_UNAUTHENTICATED" | "DEVICE_NOT_ACTIVE")
        )
    }
}

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

pub struct Client {
    origin: BackendOrigin,
    agent: ureq::Agent,
    /// Short-timeout client for best-effort mid-job progress (never blocks install long).
    progress_agent: ureq::Agent,
    /// Same TLS trust as `agent`, but with a timeout sized for package downloads.
    download_agent: ureq::Agent,
}

fn load_ca(path: &Path) -> Result<Certificate<'static>, HttpError> {
    let meta = std::fs::metadata(path).map_err(|e| HttpError::CaFile(e.to_string()))?;
    if !meta.is_file() || meta.len() > MAX_CA_FILE_BYTES {
        return Err(HttpError::CaFile("not a regular file or too large".into()));
    }
    let pem = std::fs::read(path).map_err(|e| HttpError::CaFile(e.to_string()))?;
    Certificate::from_pem(&pem).map_err(|_| HttpError::CaFile("not a PEM certificate".into()))
}

impl Client {
    pub fn new(origin: BackendOrigin, ca_file: Option<&Path>) -> Result<Self, HttpError> {
        let mut tls = TlsConfig::builder();
        if let Some(path) = ca_file {
            tls = tls.root_certs(RootCerts::new_with_certs(&[load_ca(path)?]));
        }
        let tls = tls.build();
        let build = |timeout: Duration| -> ureq::Agent {
            ureq::Agent::config_builder()
                .timeout_global(Some(timeout))
                .http_status_as_error(false)
                .max_redirects(0)
                .https_only(origin.is_https())
                .user_agent(concat!("sentinel-agent/", env!("CARGO_PKG_VERSION")))
                .tls_config(tls.clone())
                .build()
                .into()
        };
        let agent = build(REQUEST_TIMEOUT);
        let progress_agent = build(PROGRESS_TIMEOUT);
        let download_agent = build(DOWNLOAD_TIMEOUT);
        Ok(Self {
            origin,
            agent,
            progress_agent,
            download_agent,
        })
    }

    /// Stream a binary body from the control plane. Non-200 answers become `HttpError::Status`.
    pub fn open_download(
        &self,
        path: &str,
        bearer: &str,
    ) -> Result<ureq::BodyReader<'static>, HttpError> {
        let response = self
            .download_agent
            .get(self.origin.endpoint(path))
            .header("Accept", "application/octet-stream")
            .header("Authorization", format!("Bearer {bearer}"))
            .call()
            .map_err(|_| HttpError::Unreachable)?;
        if response.status().as_u16() != 200 {
            return Self::finish(response).and(Err(HttpError::Unreachable));
        }
        Ok(response.into_body().into_reader())
    }

    fn finish(mut response: ureq::http::Response<ureq::Body>) -> Result<Response, HttpError> {
        let status = response.status().as_u16();
        let mut body = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| HttpError::Unreachable)?;
        if body.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(HttpError::TooLarge);
        }
        if !(200..300).contains(&status) {
            let code = serde_json::from_slice::<ApiErrorEnvelope>(&body)
                .ok()
                .map(|e| e.error.code)
                .filter(|c| c.len() <= 64);
            return Err(HttpError::Status { status, code });
        }
        Ok(Response { status, body })
    }

    pub fn get(&self, path: &str, bearer: Option<&str>) -> Result<Response, HttpError> {
        let mut req = self
            .agent
            .get(self.origin.endpoint(path))
            .header("Accept", "application/json");
        if let Some(token) = bearer {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        Self::finish(req.call().map_err(|_| HttpError::Unreachable)?)
    }

    pub fn post_json<T: serde::Serialize>(
        &self,
        path: &str,
        bearer: Option<&str>,
        body: &T,
    ) -> Result<Response, HttpError> {
        self.post_json_with(&self.agent, path, bearer, body)
    }

    /// Best-effort progress: same wire format, hard 3s cap so a stuck API cannot hang installs.
    pub fn post_json_progress<T: serde::Serialize>(
        &self,
        path: &str,
        bearer: Option<&str>,
        body: &T,
    ) -> Result<Response, HttpError> {
        self.post_json_with(&self.progress_agent, path, bearer, body)
    }

    fn post_json_with<T: serde::Serialize>(
        &self,
        agent: &ureq::Agent,
        path: &str,
        bearer: Option<&str>,
        body: &T,
    ) -> Result<Response, HttpError> {
        let mut req = agent
            .post(self.origin.endpoint(path))
            .header("Accept", "application/json");
        if let Some(token) = bearer {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        Self::finish(req.send_json(body).map_err(|_| HttpError::Unreachable)?)
    }

    pub fn post_empty(&self, path: &str, bearer: &str) -> Result<Response, HttpError> {
        let req = self
            .agent
            .post(self.origin.endpoint(path))
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {bearer}"));
        Self::finish(req.send_empty().map_err(|_| HttpError::Unreachable)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_or_invalid_ca_files() {
        let origin = BackendOrigin::parse("https://localhost:8443");
        let Ok(origin) = origin else { return };
        let dir = tempfile::tempdir().ok();
        let Some(dir) = dir else { return };
        let missing = dir.path().join("nope.pem");
        assert!(matches!(
            Client::new(origin.clone(), Some(&missing)),
            Err(HttpError::CaFile(_))
        ));
        let junk = dir.path().join("junk.pem");
        assert!(std::fs::write(&junk, b"not a cert").is_ok());
        assert!(matches!(
            Client::new(origin, Some(&junk)),
            Err(HttpError::CaFile(_))
        ));
    }

    #[test]
    fn fatal_auth_codes() {
        let e = HttpError::Status {
            status: 401,
            code: Some("DEVICE_UNAUTHENTICATED".into()),
        };
        assert!(e.is_fatal_auth());
        let e = HttpError::Status {
            status: 429,
            code: Some("RATE_LIMITED".into()),
        };
        assert!(!e.is_fatal_auth());
        assert!(!HttpError::Unreachable.is_fatal_auth());
    }
}
