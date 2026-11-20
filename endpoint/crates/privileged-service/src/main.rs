//! Privileged install service: typed Unix-socket IPC only (spec §9.8, §11.3–11.6).
//!
//! Does not listen on the network. Installs only after verifying digest and using a
//! fixed `/usr/sbin/installer` argv. LaunchDaemon packaging is separate and requires
//! explicit owner approval (decision D2).

#![deny(unsafe_code)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;
use sentinel_protocol::job::{IPC_PROTOCOL_VERSION, PrivilegedRequest, PrivilegedResponse};
use sha2::{Digest, Sha256};

#[derive(Debug, Parser)]
#[command(
    name = "sentinel-privileged",
    about = "SentinelDesk privileged install service"
)]
struct Cli {
    /// Unix domain socket path (must be created with restrictive permissions).
    #[arg(long, env = "SENTINEL_PRIVILEGED_SOCKET")]
    socket: PathBuf,

    /// Directory that package paths must stay under (prevents arbitrary file install).
    #[arg(long, env = "SENTINEL_PACKAGE_ROOT")]
    package_root: PathBuf,

    /// Group allowed to connect to the socket (mode 660). Default: staff on macOS.
    #[arg(long, env = "SENTINEL_SOCKET_GROUP", default_value = "staff")]
    socket_group: String,
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(&cli) {
        eprintln!("sentinel-privileged error: {err}");
        std::process::exit(1);
    }
}

fn run(cli: &Cli) -> Result<(), String> {
    let root = fs::canonicalize(&cli.package_root).map_err(|e| format!("package_root: {e}"))?;
    if cli.socket.exists() {
        let _ = fs::remove_file(&cli.socket);
    }
    if let Some(parent) = cli.socket.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("socket parent: {e}"))?;
    }
    let listener = UnixListener::bind(&cli.socket).map_err(|e| format!("bind: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&cli.socket, fs::Permissions::from_mode(0o660));
        // Root daemon; allow the configured local group (default staff) to connect.
        let socket_path = cli.socket.display().to_string();
        let _ = Command::new("/usr/bin/chgrp")
            .args([cli.socket_group.as_str(), socket_path.as_str()])
            .status();
    }
    eprintln!(
        "sentinel-privileged listening on {} (package_root={})",
        cli.socket.display(),
        root.display()
    );
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(err) = handle_client(stream, &root) {
                    eprintln!("client error: {err}");
                }
            }
            Err(err) => eprintln!("accept error: {err}"),
        }
    }
    Ok(())
}

fn handle_client(mut stream: UnixStream, package_root: &Path) -> Result<(), String> {
    let mut buf = vec![0_u8; 64 * 1024];
    let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
    let req: PrivilegedRequest =
        serde_json::from_slice(&buf[..n]).map_err(|e| format!("bad request: {e}"))?;
    let response = match req {
        PrivilegedRequest::Ping { protocol_version } => {
            if protocol_version != IPC_PROTOCOL_VERSION {
                fail("UNSUPPORTED_VERSION", "ipc protocol mismatch", None)
            } else {
                ok("PONG", "alive", None, None)
            }
        }
        PrivilegedRequest::InstallPkg {
            protocol_version,
            job_id: _,
            pkg_path,
            package_identifier,
            expected_version,
            package_digest,
        } => {
            if protocol_version != IPC_PROTOCOL_VERSION {
                fail("UNSUPPORTED_VERSION", "ipc protocol mismatch", None)
            } else {
                install_pkg(
                    package_root,
                    &pkg_path,
                    &package_identifier,
                    &expected_version,
                    &package_digest,
                )
            }
        }
    };
    let body = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
    stream.write_all(&body).map_err(|e| e.to_string())?;
    Ok(())
}

fn install_pkg(
    package_root: &Path,
    pkg_path: &str,
    package_identifier: &str,
    expected_version: &str,
    package_digest: &str,
) -> PrivilegedResponse {
    let path = PathBuf::from(pkg_path);
    let canonical = match fs::canonicalize(&path) {
        Ok(p) => p,
        Err(_) => return fail("PKG_NOT_FOUND", "package path not found", None),
    };
    if !canonical.starts_with(package_root) {
        return fail(
            "PKG_PATH_REJECTED",
            "package path outside package_root",
            None,
        );
    }
    if canonical.extension().and_then(|e| e.to_str()) != Some("pkg") {
        return fail("PKG_TYPE_REJECTED", "only .pkg is supported", None);
    }
    let digest = match file_sha256(&canonical) {
        Ok(d) => d,
        Err(_) => return fail("DIGEST_READ_FAILED", "could not hash package", None),
    };
    if !digest.eq_ignore_ascii_case(package_digest) {
        return fail("DIGEST_MISMATCH", "package digest mismatch", None);
    }

    // Fixed argv only — never shell.
    let status = Command::new("/usr/sbin/installer")
        .args(["-pkg", &canonical.to_string_lossy(), "-target", "/"])
        .status();
    let exit = match status {
        Ok(s) => s.code().unwrap_or(-1),
        Err(_) => return fail("INSTALLER_SPAWN_FAILED", "could not run installer", None),
    };
    if exit != 0 {
        return fail("INSTALLER_FAILED", "installer exited non-zero", Some(exit));
    }

    match read_pkg_version(package_identifier) {
        Some(version) if version == expected_version => ok(
            "SUCCEEDED",
            "installed and verified",
            Some(exit),
            Some(version),
        ),
        Some(version) => PrivilegedResponse {
            ok: false,
            code: "FAILED_VERIFICATION".into(),
            message: "installed version mismatch".into(),
            exit_code: Some(exit),
            installed_version: Some(version),
        },
        None => fail(
            "FAILED_VERIFICATION",
            "package receipt not found after install",
            Some(exit),
        ),
    }
}

fn file_sha256(path: &Path) -> Result<String, std::io::Error> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_pkg_version(identifier: &str) -> Option<String> {
    let output = Command::new("/usr/sbin/pkgutil")
        .args(["--pkg-info", identifier])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("version: ") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn ok(
    code: &str,
    message: &str,
    exit_code: Option<i32>,
    installed_version: Option<String>,
) -> PrivilegedResponse {
    PrivilegedResponse {
        ok: true,
        code: code.into(),
        message: message.into(),
        exit_code,
        installed_version,
    }
}

fn fail(code: &str, message: &str, exit_code: Option<i32>) -> PrivilegedResponse {
    PrivilegedResponse {
        ok: false,
        code: code.into(),
        message: message.into(),
        exit_code,
        installed_version: None,
    }
}
