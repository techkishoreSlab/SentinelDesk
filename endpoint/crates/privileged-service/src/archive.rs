//! Archive installs (DMG with .app, DMG with .pkg, ZIP with .app) for the root daemon.
//!
//! Only a private, root-owned copy of the archive is ever opened: the package root is
//! world-writable, so the original file could be swapped after it was checked. Every tool is
//! an absolute path with a fixed argv (never a shell) and a timeout. Staging and mounts are
//! always cleaned up by a drop guard.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use sentinel_protocol::job::{
    KIND_DMG_APP, KIND_DMG_PKG, KIND_PKG, KIND_ZIP_APP, PrivilegedResponse, is_archive_kind,
};
use sha2::{Digest, Sha256};

use crate::{fail, ok, read_pkg_version};

const HDIUTIL: &str = "/usr/bin/hdiutil";
const DITTO: &str = "/usr/bin/ditto";
const CODESIGN: &str = "/usr/bin/codesign";
const SPCTL: &str = "/usr/sbin/spctl";
const PKGUTIL: &str = "/usr/sbin/pkgutil";
const PLUTIL: &str = "/usr/bin/plutil";
const INSTALLER: &str = "/usr/sbin/installer";
const CHOWN: &str = "/usr/sbin/chown";
const CHMOD: &str = "/bin/chmod";
const PS: &str = "/bin/ps";
const DF: &str = "/bin/df";

const T_ATTACH: Duration = Duration::from_secs(300);
const T_DETACH: Duration = Duration::from_secs(60);
const T_COPY: Duration = Duration::from_secs(900);
const T_VERIFY: Duration = Duration::from_secs(300);
const T_SHORT: Duration = Duration::from_secs(60);
const T_INSTALLER: Duration = Duration::from_secs(1200);
const MAX_ZIP_ENTRIES: usize = 500_000;
const DISK_FACTOR: u64 = 3;

pub struct ArchiveRequest<'a> {
    pub job_id: &'a str,
    pub kind: &'a str,
    pub archive_path: &'a str,
    pub payload_path: &'a str,
    pub package_identifier: &'a str,
    pub expected_version: &'a str,
    pub expected_team_id: &'a str,
    pub package_digest: &'a str,
}

/// Where staging copies and app installs go. Overridable for tests.
pub struct Layout {
    pub package_root: PathBuf,
    pub staging_root: PathBuf,
    pub applications: PathBuf,
}

/// Installer kinds this daemon can handle on this machine.
pub fn supported_installers() -> Vec<String> {
    let mut kinds = vec![KIND_PKG.to_owned()];
    let tools = [HDIUTIL, DITTO, CODESIGN, SPCTL, PKGUTIL, PLUTIL, PS, DF];
    if tools.iter().all(|t| Path::new(t).is_file()) {
        kinds.extend([KIND_DMG_APP, KIND_DMG_PKG, KIND_ZIP_APP].map(str::to_owned));
    }
    kinds
}

// ------------------------------------------------------------------ validation

pub fn valid_payload_name(name: &str, kind: &str) -> bool {
    let suffix = if kind == KIND_DMG_PKG { ".pkg" } else { ".app" };
    !name.is_empty()
        && name.len() <= 200
        && name.ends_with(suffix)
        && name.len() > suffix.len()
        && !name.starts_with('.')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " ._+()-".contains(c))
}

fn valid_team_id(team: &str) -> bool {
    team.len() == 10
        && team
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

fn valid_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
}

fn valid_job_id(job_id: &str) -> bool {
    job_id.len() == 36 && job_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn expected_extension(kind: &str) -> &'static str {
    if kind == KIND_ZIP_APP { "zip" } else { "dmg" }
}

// --------------------------------------------------------------------- running

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    timed_out: bool,
}

impl Run {
    fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }
}

fn drain(mut pipe: impl Read + Send + 'static) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.by_ref().take(4 * 1024 * 1024).read_to_end(&mut buf);
        // Keep reading so the child never blocks on a full pipe.
        let _ = std::io::copy(&mut pipe, &mut std::io::sink());
        buf
    })
}

fn run(program: &str, args: &[&str], timeout: Duration) -> Run {
    let spawned = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(_) => {
            return Run {
                code: None,
                stdout: String::new(),
                stderr: format!("could not run {program}"),
                timed_out: false,
            };
        }
    };
    let out = child.stdout.take().map(drain);
    let err = child.stderr.take().map(drain);
    let started = Instant::now();
    let mut timed_out = false;
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                timed_out = true;
                break None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(_) => break None,
        }
    };
    let collect = |h: Option<thread::JoinHandle<Vec<u8>>>| {
        h.and_then(|h| h.join().ok())
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    };
    Run {
        code,
        stdout: collect(out),
        stderr: collect(err),
        timed_out,
    }
}

// --------------------------------------------------------------------- staging

/// Owns the private staging directory and any attached image. Always cleans up on drop.
struct Staging {
    dir: PathBuf,
    device: Option<String>,
}

impl Staging {
    fn create(root: &Path, job_id: &str) -> Result<Self, PrivilegedResponse> {
        fs::create_dir_all(root).map_err(|_| fail("STAGING_FAILED", "staging root", None))?;
        let _ = fs::set_permissions(root, fs::Permissions::from_mode(0o700));
        let dir = root.join(job_id);
        if fs::symlink_metadata(&dir).is_ok() {
            let _ = fs::remove_dir_all(&dir);
        }
        fs::create_dir(&dir).map_err(|_| fail("STAGING_FAILED", "staging dir", None))?;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        Ok(Self { dir, device: None })
    }

    fn detach(&mut self) -> bool {
        let Some(device) = self.device.take() else {
            return true;
        };
        if run(HDIUTIL, &["detach", &device, "-quiet"], T_DETACH).success() {
            return true;
        }
        let forced = run(HDIUTIL, &["detach", &device, "-force", "-quiet"], T_DETACH).success();
        if !forced {
            self.device = Some(device);
        }
        forced
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if self.detach() {
            let _ = fs::remove_dir_all(&self.dir);
        } else {
            // Never recurse into a still-mounted image; drop only our private copy.
            let _ = fs::remove_file(self.dir.join("archive"));
        }
    }
}

/// Copy the archive into staging, hashing as we go. Refuses symlinks and swapped files.
fn private_copy(
    layout: &Layout,
    staging: &Staging,
    source: &str,
    kind: &str,
    digest: &str,
) -> Result<(PathBuf, u64), PrivilegedResponse> {
    let path = PathBuf::from(source);
    let meta = fs::symlink_metadata(&path)
        .map_err(|_| fail("PKG_NOT_FOUND", "package path not found", None))?;
    if !meta.file_type().is_file() {
        return Err(fail(
            "PKG_PATH_REJECTED",
            "package must be a regular file",
            None,
        ));
    }
    let parent = path
        .parent()
        .and_then(|p| fs::canonicalize(p).ok())
        .ok_or_else(|| fail("PKG_PATH_REJECTED", "package parent", None))?;
    if !parent.starts_with(&layout.package_root) {
        return Err(fail(
            "PKG_PATH_REJECTED",
            "package path outside package_root",
            None,
        ));
    }
    if path.extension().and_then(|e| e.to_str()) != Some(expected_extension(kind)) {
        return Err(fail(
            "PKG_TYPE_REJECTED",
            "extension does not match kind",
            None,
        ));
    }
    let mut input =
        File::open(&path).map_err(|_| fail("PKG_NOT_FOUND", "package open failed", None))?;
    let opened = input
        .metadata()
        .map_err(|_| fail("PKG_NOT_FOUND", "package stat failed", None))?;
    if opened.dev() != meta.dev() || opened.ino() != meta.ino() || !opened.is_file() {
        return Err(fail(
            "PKG_PATH_REJECTED",
            "package changed while opening",
            None,
        ));
    }

    let dest = staging.dir.join("archive");
    let mut out = File::create(&dest).map_err(|_| fail("STAGING_FAILED", "copy", None))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; 1024 * 1024];
    let mut total = 0_u64;
    loop {
        let n = input
            .read(&mut buf)
            .map_err(|_| fail("DIGEST_READ_FAILED", "could not read package", None))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])
            .map_err(|_| fail("STAGING_FAILED", "copy write", None))?;
        total = total.saturating_add(n as u64);
    }
    out.sync_all()
        .map_err(|_| fail("STAGING_FAILED", "copy sync", None))?;
    if !format!("{:x}", hasher.finalize()).eq_ignore_ascii_case(digest) {
        return Err(fail("DIGEST_MISMATCH", "package digest mismatch", None));
    }
    // hdiutil wants a recognisable extension on the image.
    let named = staging
        .dir
        .join(format!("archive.{}", expected_extension(kind)));
    fs::rename(&dest, &named).map_err(|_| fail("STAGING_FAILED", "rename", None))?;
    Ok((named, total))
}

fn free_bytes(path: &Path) -> Option<u64> {
    let probe = path.to_string_lossy();
    let out = run(DF, &["-k", "-P", &probe], T_SHORT);
    if !out.success() {
        return None;
    }
    let line = out.stdout.lines().nth(1)?;
    let available_kb: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
    Some(available_kb.saturating_mul(1024))
}

// ------------------------------------------------------------------ containers

/// Pull `(mount points, whole-disk device)` out of `hdiutil attach -plist` output.
pub fn parse_attach_plist(xml: &str) -> (Vec<String>, Option<String>) {
    let mut mounts = Vec::new();
    let mut devices = Vec::new();
    let mut rest = xml;
    while let Some(idx) = rest.find("<key>") {
        rest = &rest[idx + 5..];
        let Some(end) = rest.find("</key>") else {
            break;
        };
        let key = &rest[..end];
        rest = &rest[end + 6..];
        let value = rest
            .trim_start()
            .strip_prefix("<string>")
            .and_then(|v| v.split_once("</string>"))
            .map(|(v, _)| v.to_owned());
        match (key, value) {
            ("mount-point", Some(v)) => mounts.push(v),
            ("dev-entry", Some(v)) => devices.push(v),
            _ => {}
        }
    }
    let whole = devices
        .into_iter()
        .filter(|d| d.starts_with("/dev/disk"))
        .min_by_key(String::len);
    (mounts, whole)
}

fn attach_dmg(staging: &mut Staging, image: &Path) -> Result<PathBuf, PrivilegedResponse> {
    let mnt = staging.dir.join("mnt");
    fs::create_dir(&mnt).map_err(|_| fail("STAGING_FAILED", "mount dir", None))?;
    // hdiutil reports resolved paths (/var -> /private/var).
    let mnt = fs::canonicalize(&mnt).map_err(|_| fail("STAGING_FAILED", "mount dir", None))?;
    let image_s = image.to_string_lossy();
    let mnt_s = mnt.to_string_lossy();
    // Never -noverify: hdiutil checks the image checksums before mounting.
    let out = run(
        HDIUTIL,
        &[
            "attach",
            "-nobrowse",
            "-readonly",
            "-noautoopen",
            "-mountrandom",
            &mnt_s,
            "-plist",
            &image_s,
        ],
        T_ATTACH,
    );
    let (mounts, device) = parse_attach_plist(&out.stdout);
    staging.device = device;
    if out.timed_out {
        return Err(fail(
            "DMG_LICENSE_PROMPT",
            "disk image did not attach silently (license prompt?)",
            None,
        ));
    }
    if !out.success() {
        let text = out.stderr.to_ascii_lowercase();
        if text.contains("license") || text.contains("agreement") {
            return Err(fail(
                "DMG_LICENSE_PROMPT",
                "disk image requires a license prompt",
                None,
            ));
        }
        return Err(fail(
            "DMG_ATTACH_FAILED",
            "could not attach disk image",
            out.code,
        ));
    }
    mounts
        .into_iter()
        .map(PathBuf::from)
        .find(|m| m.starts_with(&mnt))
        .ok_or_else(|| fail("DMG_ATTACH_FAILED", "no mounted volume", None))
}

/// Lexically resolve `target` relative to `link_dir`; true when it stays inside `root`.
pub fn link_stays_inside(root: &Path, link_dir: &Path, target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    let mut parts: Vec<Component<'_>> = link_dir.components().collect();
    for comp in target.components() {
        match comp {
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return false;
                }
            }
            Component::Normal(_) => parts.push(comp),
            Component::CurDir => {}
            _ => return false,
        }
    }
    let resolved: PathBuf = parts.iter().collect();
    resolved.starts_with(root)
}

fn check_tree_links(root: &Path) -> Result<(), PrivilegedResponse> {
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0_usize;
    while let Some(dir) = stack.pop() {
        let entries =
            fs::read_dir(&dir).map_err(|_| fail("ZIP_PATH_REJECTED", "unreadable tree", None))?;
        for entry in entries.flatten() {
            seen += 1;
            if seen > MAX_ZIP_ENTRIES {
                return Err(fail("ZIP_PATH_REJECTED", "too many entries", None));
            }
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)
                .map_err(|_| fail("ZIP_PATH_REJECTED", "unreadable entry", None))?;
            if meta.file_type().is_symlink() {
                let target = fs::read_link(&path)
                    .map_err(|_| fail("ZIP_PATH_REJECTED", "unreadable link", None))?;
                if !link_stays_inside(root, &dir, &target) {
                    return Err(fail("ZIP_PATH_REJECTED", "link escapes the archive", None));
                }
            } else if meta.is_dir() {
                stack.push(path);
            }
        }
    }
    Ok(())
}

fn extract_zip(staging: &Staging, archive: &Path) -> Result<PathBuf, PrivilegedResponse> {
    let out_dir = staging.dir.join("x");
    fs::create_dir(&out_dir).map_err(|_| fail("STAGING_FAILED", "extract dir", None))?;
    let a = archive.to_string_lossy();
    let o = out_dir.to_string_lossy();
    let res = run(DITTO, &["-x", "-k", &a, &o], T_COPY);
    if !res.success() {
        return Err(fail(
            "ZIP_EXTRACT_FAILED",
            "could not extract archive",
            res.code,
        ));
    }
    check_tree_links(&out_dir)?;
    Ok(out_dir)
}

// ---------------------------------------------------------------- verification

fn plist_value(plist: &Path, key: &str) -> Option<String> {
    let p = plist.to_string_lossy();
    let out = run(PLUTIL, &["-extract", key, "raw", "-o", "-", &p], T_SHORT);
    if !out.success() {
        return None;
    }
    let value = out.stdout.trim().to_owned();
    (!value.is_empty() && value.len() <= 200).then_some(value)
}

pub struct BundleInfo {
    pub identifier: String,
    pub version: String,
}

fn bundle_info(app: &Path) -> Option<BundleInfo> {
    let plist = app.join("Contents/Info.plist");
    let meta = fs::symlink_metadata(&plist).ok()?;
    if !meta.is_file() {
        return None;
    }
    let identifier = plist_value(&plist, "CFBundleIdentifier")?;
    let version = plist_value(&plist, "CFBundleShortVersionString")
        .filter(|v| valid_token(v, 40))
        .or_else(|| plist_value(&plist, "CFBundleVersion"))?;
    Some(BundleInfo {
        identifier,
        version,
    })
}

/// `TeamIdentifier=ABCDE12345` line from `codesign -dv` (written to stderr).
pub fn parse_team_identifier(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("TeamIdentifier="))
        .map(|t| t.trim().to_owned())
        .filter(|t| valid_team_id(t))
}

/// Team ID of the leaf certificate from `pkgutil --check-signature`, if trusted.
pub fn parse_pkgutil_signature(text: &str) -> Option<String> {
    let signed = text.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("Status: signed by") && !t.contains("untrusted")
    });
    if !signed {
        return None;
    }
    let leaf = text.lines().map(str::trim).find(|l| l.starts_with("1. "))?;
    let open = leaf.rfind('(')?;
    let team = leaf[open + 1..].trim_end_matches(')').trim();
    valid_team_id(team).then(|| team.to_owned())
}

/// Cryptographic deep verify without `--strict`.
///
/// `--strict` rejects resource-fork / Finder-info xattrs on nested helpers. Real-world
/// Developer ID apps (notably Chrome) ship that way and are still notarized; Gatekeeper
/// accepts them. We require a valid deep signature + expected Team ID + Gatekeeper instead.
fn codesign_verify_deep(app: &Path) -> Run {
    let a = app.to_string_lossy();
    run(CODESIGN, &["--verify", "--deep", &a], T_VERIFY)
}

fn verify_app_signature(app: &Path, team_id: &str) -> Result<(), PrivilegedResponse> {
    let a = app.to_string_lossy();
    let deep = codesign_verify_deep(app);
    if !deep.success() {
        return Err(fail(
            "SIGNATURE_INVALID",
            "code signature invalid",
            deep.code,
        ));
    }
    let details = run(CODESIGN, &["-dv", "--verbose=2", &a], T_SHORT);
    match parse_team_identifier(&format!("{}\n{}", details.stderr, details.stdout)) {
        Some(found) if found == team_id => {}
        _ => {
            return Err(fail(
                "TEAM_ID_MISMATCH",
                "signer is not the expected publisher",
                None,
            ));
        }
    }
    let gate = run(SPCTL, &["-a", "-t", "execute", "-vv", &a], T_VERIFY);
    let text = format!("{}\n{}", gate.stderr, gate.stdout);
    if !gate.success() || !text.contains("Developer ID") {
        return Err(fail(
            "GATEKEEPER_REJECTED",
            "Gatekeeper rejected the app",
            gate.code,
        ));
    }
    Ok(())
}

fn verify_pkg_signature(pkg: &Path, team_id: &str) -> Result<(), PrivilegedResponse> {
    let p = pkg.to_string_lossy();
    let sig = run(PKGUTIL, &["--check-signature", &p], T_VERIFY);
    match parse_pkgutil_signature(&sig.stdout) {
        Some(found) if found == team_id => {}
        Some(_) => {
            return Err(fail(
                "TEAM_ID_MISMATCH",
                "signer is not the expected publisher",
                None,
            ));
        }
        None => return Err(fail("SIGNATURE_INVALID", "package is not signed", sig.code)),
    }
    let gate = run(SPCTL, &["-a", "-t", "install", "-vv", &p], T_VERIFY);
    if !gate.success() {
        return Err(fail(
            "GATEKEEPER_REJECTED",
            "Gatekeeper rejected the package",
            gate.code,
        ));
    }
    Ok(())
}

/// Numeric dotted comparison. `None` when either side is not purely numeric.
pub fn compare_versions(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    let parse =
        |s: &str| -> Option<Vec<u64>> { s.split('.').map(|p| p.parse::<u64>().ok()).collect() };
    let (mut x, mut y) = (parse(a)?, parse(b)?);
    let width = x.len().max(y.len());
    x.resize(width, 0);
    y.resize(width, 0);
    Some(x.cmp(&y))
}

fn app_in_use(dest: &Path) -> bool {
    let out = run(PS, &["-axo", "comm="], T_SHORT);
    let prefix = format!("{}/", dest.to_string_lossy());
    out.stdout
        .lines()
        .any(|l| l.trim_start().starts_with(&prefix))
}

// --------------------------------------------------------------- app install

/// Move `staged` to `dest`, keeping the previous bundle at `backup` until the caller commits.
pub fn swap_into_place(staged: &Path, dest: &Path, backup: &Path) -> std::io::Result<bool> {
    let had_previous = fs::symlink_metadata(dest).is_ok();
    if had_previous {
        fs::rename(dest, backup)?;
    }
    if let Err(err) = fs::rename(staged, dest) {
        if had_previous {
            let _ = fs::rename(backup, dest);
        }
        return Err(err);
    }
    Ok(had_previous)
}

/// Undo `swap_into_place`: remove the new bundle and restore the backup.
pub fn roll_back(dest: &Path, backup: &Path, had_previous: bool) {
    let _ = fs::remove_dir_all(dest);
    if had_previous {
        let _ = fs::rename(backup, dest);
    }
}

fn install_app(layout: &Layout, req: &ArchiveRequest<'_>, source_app: &Path) -> PrivilegedResponse {
    let dest = layout.applications.join(req.payload_path);
    if let Ok(meta) = fs::symlink_metadata(&dest) {
        if !meta.is_dir() {
            return fail(
                "DESTINATION_CONFLICT",
                "destination is not an app bundle",
                None,
            );
        }
        match bundle_info(&dest) {
            Some(existing) if existing.identifier == req.package_identifier => {
                if let Some(order) = compare_versions(&existing.version, req.expected_version) {
                    if order == std::cmp::Ordering::Greater {
                        return fail("DOWNGRADE_REFUSED", "a newer version is installed", None);
                    }
                    if order == std::cmp::Ordering::Equal
                        && verify_app_signature(&dest, req.expected_team_id).is_ok()
                    {
                        return ok(
                            "SUCCEEDED",
                            "requested version already installed",
                            Some(0),
                            Some(existing.version),
                        );
                    }
                }
            }
            Some(_) => {
                return fail(
                    "DESTINATION_CONFLICT",
                    "a different app already uses this name",
                    None,
                );
            }
            None => return fail("DESTINATION_CONFLICT", "existing app is unreadable", None),
        }
        if app_in_use(&dest) {
            return fail("APP_IN_USE", "quit the app and retry", None);
        }
    }

    let staged = layout
        .applications
        .join(format!(".sentineldesk-{}.app", req.job_id));
    let backup = layout
        .applications
        .join(format!(".sentineldesk-{}-old.app", req.job_id));
    let _ = fs::remove_dir_all(&staged);
    let _ = fs::remove_dir_all(&backup);
    let (src, tmp) = (source_app.to_string_lossy(), staged.to_string_lossy());
    let copied = run(DITTO, &[&src, &tmp], T_COPY);
    if !copied.success() {
        let _ = fs::remove_dir_all(&staged);
        return fail("COPY_FAILED", "could not copy app", copied.code);
    }
    let _ = run(CHOWN, &["-R", "root:admin", &tmp], T_COPY);
    let _ = run(CHMOD, &["-R", "o-w", &tmp], T_COPY);
    if let Err(resp) = verify_app_signature(&staged, req.expected_team_id) {
        let _ = fs::remove_dir_all(&staged);
        return resp;
    }

    let had_previous = match swap_into_place(&staged, &dest, &backup) {
        Ok(v) => v,
        Err(_) => {
            let _ = fs::remove_dir_all(&staged);
            return fail("INSTALL_FAILED", "could not move app into place", None);
        }
    };
    let verified = bundle_info(&dest)
        .filter(|b| b.identifier == req.package_identifier && b.version == req.expected_version);
    let signed = verified.is_some() && codesign_verify_deep(&dest).success();
    match verified {
        Some(info) if signed => {
            let _ = fs::remove_dir_all(&backup);
            ok(
                "SUCCEEDED",
                "installed and verified",
                Some(0),
                Some(info.version),
            )
        }
        _ => {
            roll_back(&dest, &backup, had_previous);
            fail(
                "FAILED_VERIFICATION",
                "installed app failed verification; previous version restored",
                None,
            )
        }
    }
}

fn install_inner_pkg(req: &ArchiveRequest<'_>, pkg: &Path) -> PrivilegedResponse {
    if let Err(resp) = verify_pkg_signature(pkg, req.expected_team_id) {
        return resp;
    }
    let p = pkg.to_string_lossy();
    let res = run(INSTALLER, &["-pkg", &p, "-target", "/"], T_INSTALLER);
    if res.timed_out {
        return fail(
            "INSTALLER_TIMEOUT",
            "installer did not finish in time",
            None,
        );
    }
    let exit = res.code.unwrap_or(-1);
    if exit != 0 {
        return fail("INSTALLER_FAILED", "installer exited non-zero", Some(exit));
    }
    match read_pkg_version(req.package_identifier) {
        Some(version) if version == req.expected_version => ok(
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
            installers: None,
        },
        None => fail(
            "FAILED_VERIFICATION",
            "package receipt not found after install",
            Some(exit),
        ),
    }
}

// ------------------------------------------------------------------- entry

pub fn install_archive(layout: &Layout, req: &ArchiveRequest<'_>) -> PrivilegedResponse {
    if !is_archive_kind(req.kind) {
        return fail("KIND_UNSUPPORTED", "unsupported installer kind", None);
    }
    if !valid_job_id(req.job_id)
        || !valid_payload_name(req.payload_path, req.kind)
        || !valid_team_id(req.expected_team_id)
        || !valid_token(req.package_identifier, 200)
        || !valid_token(req.expected_version, 40)
        || !valid_digest(req.package_digest)
    {
        return fail("REQUEST_REJECTED", "invalid archive install request", None);
    }

    let mut staging = match Staging::create(&layout.staging_root, req.job_id) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let (archive, size) = match private_copy(
        layout,
        &staging,
        req.archive_path,
        req.kind,
        req.package_digest,
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    match free_bytes(&layout.applications) {
        Some(free) if free >= size.saturating_mul(DISK_FACTOR) => {}
        Some(_) => return fail("INSUFFICIENT_DISK", "not enough free disk space", None),
        None => return fail("INSUFFICIENT_DISK", "could not check free disk space", None),
    }

    let root = if req.kind == KIND_ZIP_APP {
        extract_zip(&staging, &archive)
    } else {
        attach_dmg(&mut staging, &archive)
    };
    let root = match root {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let payload = root.join(req.payload_path);
    let meta = match fs::symlink_metadata(&payload) {
        Ok(m) => m,
        Err(_) => return fail("PAYLOAD_NOT_FOUND", "payload not found in archive", None),
    };
    if meta.file_type().is_symlink() {
        return fail("SYMLINK_REJECTED", "payload is a symbolic link", None);
    }

    let response = if req.kind == KIND_DMG_PKG {
        if !meta.is_file() {
            return fail("PAYLOAD_NOT_FOUND", "payload is not a package", None);
        }
        install_inner_pkg(req, &payload)
    } else {
        if !meta.is_dir() {
            return fail("PAYLOAD_NOT_FOUND", "payload is not an app bundle", None);
        }
        match bundle_info(&payload) {
            Some(info) if info.identifier != req.package_identifier => {
                return fail("BUNDLE_ID_MISMATCH", "bundle identifier mismatch", None);
            }
            Some(info) if info.version != req.expected_version => {
                return fail("VERSION_MISMATCH", "bundle version mismatch", None);
            }
            Some(_) => {}
            None => return fail("APP_INFO_UNREADABLE", "could not read app Info.plist", None),
        }
        if let Err(resp) = verify_app_signature(&payload, req.expected_team_id) {
            return resp;
        }
        install_app(layout, req, &payload)
    };
    drop(staging);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_names_are_single_safe_components() {
        assert!(valid_payload_name("Slack.app", KIND_DMG_APP));
        assert!(valid_payload_name("Visual Studio Code.app", KIND_ZIP_APP));
        assert!(valid_payload_name("Install Go.pkg", KIND_DMG_PKG));
        assert!(!valid_payload_name("Slack.pkg", KIND_DMG_APP));
        assert!(!valid_payload_name("Slack.app", KIND_DMG_PKG));
        assert!(!valid_payload_name("../Slack.app", KIND_DMG_APP));
        assert!(!valid_payload_name("a/Slack.app", KIND_DMG_APP));
        assert!(!valid_payload_name(".hidden.app", KIND_DMG_APP));
        assert!(!valid_payload_name(".app", KIND_DMG_APP));
        assert!(!valid_payload_name("x\u{0}.app", KIND_DMG_APP));
    }

    #[test]
    fn team_identifier_is_parsed_from_codesign_output() {
        let text =
            "Executable=/x\nIdentifier=com.tinyspeck.slackmacgap\nTeamIdentifier=BQR82RBBHL\n";
        assert_eq!(parse_team_identifier(text).as_deref(), Some("BQR82RBBHL"));
        assert_eq!(parse_team_identifier("TeamIdentifier=not set\n"), None);
    }

    #[test]
    fn pkgutil_signature_requires_trusted_status() {
        let good = "Package \"Go.pkg\":\n   Status: signed by a developer certificate issued by Apple for distribution\n   Notarization: trusted by the Apple notary service\n   Certificate Chain:\n    1. Developer ID Installer: Google LLC (EQHXZ8M8AV)\n       Expires: 2027\n    2. Developer ID Certification Authority\n";
        assert_eq!(parse_pkgutil_signature(good).as_deref(), Some("EQHXZ8M8AV"));
        assert_eq!(
            parse_pkgutil_signature("Package \"x.pkg\":\n   Status: no signature\n"),
            None
        );
        let untrusted = good.replace("issued by Apple for distribution", "untrusted");
        assert_eq!(parse_pkgutil_signature(&untrusted), None);
    }

    #[test]
    fn attach_plist_yields_mount_and_whole_disk() {
        let xml = r#"<plist><dict><key>system-entities</key><array>
            <dict><key>dev-entry</key><string>/dev/disk7</string></dict>
            <dict><key>dev-entry</key><string>/dev/disk7s1</string>
            <key>mount-point</key><string>/var/db/sentineldesk/staging/j/mnt/dmg.Ab12</string></dict>
            </array></dict></plist>"#;
        let (mounts, dev) = parse_attach_plist(xml);
        assert_eq!(
            mounts,
            vec!["/var/db/sentineldesk/staging/j/mnt/dmg.Ab12".to_owned()]
        );
        assert_eq!(dev.as_deref(), Some("/dev/disk7"));
    }

    #[test]
    fn versions_compare_numerically() {
        use std::cmp::Ordering::*;
        assert_eq!(compare_versions("4.41.105", "4.41.97"), Some(Greater));
        assert_eq!(compare_versions("1.0", "1.0.0"), Some(Equal));
        assert_eq!(compare_versions("1.2", "1.10"), Some(Less));
        assert_eq!(compare_versions("1.0b2", "1.0"), None);
    }

    #[test]
    fn symlinks_must_stay_inside_the_tree() {
        let root = Path::new("/s/x");
        let fw = Path::new("/s/x/A.app/Contents/Frameworks/E.framework");
        assert!(link_stays_inside(root, fw, Path::new("Versions/Current/E")));
        assert!(link_stays_inside(root, fw, Path::new("../../MacOS/A")));
        assert!(!link_stays_inside(
            root,
            fw,
            Path::new("../../../../../etc/passwd")
        ));
        assert!(!link_stays_inside(root, fw, Path::new("/etc/passwd")));
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sentinel-archive-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).map(|_| dir).unwrap_or_default()
    }

    #[test]
    fn swap_replaces_and_rollback_restores() {
        let apps = temp_dir("swap");
        let dest = apps.join("Demo.app");
        let staged = apps.join(".sentineldesk-j.app");
        let backup = apps.join(".sentineldesk-j-old.app");
        assert!(fs::create_dir_all(dest.join("old")).is_ok());
        assert!(fs::create_dir_all(staged.join("new")).is_ok());

        let had = swap_into_place(&staged, &dest, &backup).unwrap_or(false);
        assert!(had);
        assert!(dest.join("new").is_dir());
        assert!(backup.join("old").is_dir());

        roll_back(&dest, &backup, had);
        assert!(dest.join("old").is_dir());
        assert!(!backup.exists());
        let _ = fs::remove_dir_all(&apps);
    }

    #[test]
    fn swap_into_empty_destination_has_nothing_to_restore() {
        let apps = temp_dir("fresh");
        let dest = apps.join("Demo.app");
        let staged = apps.join(".sentineldesk-k.app");
        let backup = apps.join(".sentineldesk-k-old.app");
        assert!(fs::create_dir_all(staged.join("new")).is_ok());
        let had = swap_into_place(&staged, &dest, &backup).unwrap_or(true);
        assert!(!had);
        roll_back(&dest, &backup, had);
        assert!(!dest.exists());
        let _ = fs::remove_dir_all(&apps);
    }

    #[test]
    fn invalid_requests_are_rejected_before_touching_disk() {
        let layout = Layout {
            package_root: PathBuf::from("/nonexistent"),
            staging_root: PathBuf::from("/nonexistent/staging"),
            applications: PathBuf::from("/nonexistent/apps"),
        };
        let req = ArchiveRequest {
            job_id: "00000000-0000-0000-0000-000000000000",
            kind: KIND_DMG_APP,
            archive_path: "/nonexistent/a.dmg",
            payload_path: "../evil.app",
            package_identifier: "com.x",
            expected_version: "1.0",
            expected_team_id: "BQR82RBBHL",
            package_digest: &"a".repeat(64),
        };
        let resp = install_archive(&layout, &req);
        assert_eq!(resp.code, "REQUEST_REJECTED");
        let pkg = ArchiveRequest {
            kind: KIND_PKG,
            ..req
        };
        assert_eq!(install_archive(&layout, &pkg).code, "KIND_UNSUPPORTED");
    }
}
