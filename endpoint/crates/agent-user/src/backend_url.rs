//! Backend URL policy: TLS is mandatory except for loopback development hosts.

use std::net::IpAddr;

use url::{Host, Url};

#[derive(Debug, PartialEq, Eq)]
pub enum UrlError {
    Invalid,
    UnsupportedScheme,
    PlaintextToNonLoopback,
    HasCredentials,
    HasPathOrQuery,
}

impl std::fmt::Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::Invalid => "backend URL is not a valid absolute URL",
            Self::UnsupportedScheme => "backend URL must use https (or http for loopback only)",
            Self::PlaintextToNonLoopback => "plain http is only allowed for loopback hosts",
            Self::HasCredentials => "backend URL must not embed credentials",
            Self::HasPathOrQuery => "backend URL must be an origin without path, query or fragment",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for UrlError {}

fn is_loopback(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => false,
    }
}

/// Validated backend origin. Endpoint paths are joined from fixed constants only.
#[derive(Debug, Clone)]
pub struct BackendOrigin(Url);

impl BackendOrigin {
    pub fn parse(raw: &str) -> Result<Self, UrlError> {
        let url = Url::parse(raw.trim()).map_err(|_| UrlError::Invalid)?;
        match url.scheme() {
            "https" => {}
            "http" if is_loopback(url.host()) => {}
            "http" => return Err(UrlError::PlaintextToNonLoopback),
            _ => return Err(UrlError::UnsupportedScheme),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(UrlError::HasCredentials);
        }
        if (url.path() != "/" && !url.path().is_empty())
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(UrlError::HasPathOrQuery);
        }
        Ok(Self(url))
    }

    pub fn is_https(&self) -> bool {
        self.0.scheme() == "https"
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str().trim_end_matches('/')
    }

    pub fn endpoint(&self, path: &str) -> String {
        let base = self.0.as_str().trim_end_matches('/');
        format!("{base}{path}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_and_loopback_http() {
        for ok in [
            "https://sentinel.example.com",
            "https://sentinel.example.com:8443/",
            "http://127.0.0.1:8000",
            "http://localhost:8000",
            "http://[::1]:8000",
        ] {
            assert!(BackendOrigin::parse(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn rejects_plaintext_to_remote_hosts() {
        assert_eq!(
            BackendOrigin::parse("http://10.0.0.5:8000").err(),
            Some(UrlError::PlaintextToNonLoopback)
        );
        assert_eq!(
            BackendOrigin::parse("http://localhost.evil.com").err(),
            Some(UrlError::PlaintextToNonLoopback)
        );
    }

    #[test]
    fn rejects_other_schemes_credentials_and_paths() {
        assert_eq!(
            BackendOrigin::parse("file:///etc/passwd").err(),
            Some(UrlError::UnsupportedScheme)
        );
        assert_eq!(
            BackendOrigin::parse("https://u:p@example.com").err(),
            Some(UrlError::HasCredentials)
        );
        assert_eq!(
            BackendOrigin::parse("https://example.com/api?x=1").err(),
            Some(UrlError::HasPathOrQuery)
        );
        assert_eq!(
            BackendOrigin::parse("not a url").err(),
            Some(UrlError::Invalid)
        );
    }

    #[test]
    fn joins_fixed_paths() {
        let origin = BackendOrigin::parse("http://127.0.0.1:8000/").ok();
        assert_eq!(
            origin.map(|o| o.endpoint("/health/live")),
            Some("http://127.0.0.1:8000/health/live".to_string())
        );
    }
}
