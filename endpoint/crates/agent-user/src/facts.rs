//! Device facts collection (spec §9.4). Read-only; every value is sanitized to the bounds
//! the backend enforces, and anything that cannot be sanitized is dropped rather than sent.

use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::path::Path;

use sentinel_protocol::agent::{
    Architecture, DeviceFacts, InstalledSoftware, MAX_INSTALLED_ITEMS, OsFamily, SoftwareSource,
    clean_text, valid_identifier, valid_version,
};

const MAX_PLIST_BYTES: u64 = 1024 * 1024;
const MAX_DIR_ENTRIES: usize = 5000;

#[derive(Debug)]
pub enum FactsError {
    UnsupportedPlatform(&'static str),
    Invalid(sentinel_protocol::ProtocolError),
}

impl std::fmt::Display for FactsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPlatform(what) => write!(f, "unsupported platform: {what}"),
            Self::Invalid(e) => write!(f, "collected facts failed validation: {e}"),
        }
    }
}

impl std::error::Error for FactsError {}

fn architecture() -> Result<Architecture, FactsError> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(Architecture::X86_64),
        "aarch64" => Ok(Architecture::Arm64),
        other => Err(FactsError::UnsupportedPlatform(if other.is_empty() {
            "unknown architecture"
        } else {
            "architecture is not x86_64 or arm64"
        })),
    }
}

fn os_family() -> Result<OsFamily, FactsError> {
    match std::env::consts::OS {
        "macos" => Ok(OsFamily::Macos),
        "windows" => Ok(OsFamily::Windows),
        "linux" => Ok(OsFamily::Linux),
        _ => Err(FactsError::UnsupportedPlatform("operating system")),
    }
}

fn read_plist(path: &Path) -> Option<plist::Dictionary> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_PLIST_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    plist::Value::from_reader(Cursor::new(bytes))
        .ok()?
        .into_dictionary()
}

fn plist_str<'a>(dict: &'a plist::Dictionary, key: &str) -> Option<&'a str> {
    dict.get(key).and_then(plist::Value::as_string)
}

fn first_valid_version(dict: &plist::Dictionary, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|k| plist_str(dict, k))
        .map(str::trim)
        .find(|v| valid_version(v))
        .map(str::to_owned)
}

/// `<root>/*.app/Contents/Info.plist` → bundle identifier and version.
pub fn scan_app_bundles(root: &Path) -> Vec<InstalledSoftware> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .take(MAX_DIR_ENTRIES)
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "app"))
        .filter_map(|e| {
            let dict = read_plist(&e.path().join("Contents/Info.plist"))?;
            let identifier = plist_str(&dict, "CFBundleIdentifier")?.trim();
            if !valid_identifier(identifier) {
                return None;
            }
            let version =
                first_valid_version(&dict, &["CFBundleShortVersionString", "CFBundleVersion"])?;
            Some(InstalledSoftware {
                identifier: identifier.to_owned(),
                version,
                source: SoftwareSource::AppBundle,
            })
        })
        .collect()
}

/// `<root>/*.plist` installer receipts → package identifier and version.
pub fn scan_pkg_receipts(root: &Path) -> Vec<InstalledSoftware> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .take(MAX_DIR_ENTRIES)
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "plist"))
        .filter_map(|e| {
            let dict = read_plist(&e.path())?;
            let identifier = plist_str(&dict, "PackageIdentifier")?.trim();
            if !valid_identifier(identifier) {
                return None;
            }
            let version = first_valid_version(&dict, &["PackageVersion"])?;
            Some(InstalledSoftware {
                identifier: identifier.to_owned(),
                version,
                source: SoftwareSource::PkgReceipt,
            })
        })
        .collect()
}

/// Deduplicate by (source, identifier), sort deterministically, and cap the list size so
/// identical inventories always serialize identically.
pub fn normalize_inventory(items: Vec<InstalledSoftware>) -> Vec<InstalledSoftware> {
    let mut unique: BTreeMap<(u8, String), InstalledSoftware> = BTreeMap::new();
    for item in items {
        let rank = match item.source {
            SoftwareSource::AppBundle => 0,
            SoftwareSource::PkgReceipt => 1,
        };
        unique
            .entry((rank, item.identifier.clone()))
            .or_insert(item);
    }
    unique.into_values().take(MAX_INSTALLED_ITEMS).collect()
}

fn macos_version() -> (String, String) {
    let dict = read_plist(Path::new(
        "/System/Library/CoreServices/SystemVersion.plist",
    ));
    let get = |key: &str| {
        dict.as_ref()
            .and_then(|d| plist_str(d, key))
            .and_then(|v| clean_text(v, 40))
            .unwrap_or_else(|| "unknown".to_owned())
    };
    (get("ProductVersion"), get("ProductBuildVersion"))
}

fn generic_version() -> (String, String) {
    let version = sysinfo::System::os_version()
        .ok()
        .and_then(|v| clean_text(&v, 40))
        .unwrap_or_else(|| "unknown".to_owned());
    let build = sysinfo::System::kernel_version()
        .ok()
        .and_then(|v| clean_text(&v, 40))
        .unwrap_or_else(|| "unknown".to_owned());
    (version, build)
}

fn memory_total() -> u64 {
    sysinfo::System::new()
        .map(|mut s| {
            s.refresh_memory();
            s.total_memory()
        })
        .unwrap_or(0)
}

fn disk_free() -> u64 {
    let Ok(disks) = sysinfo::Disks::new_with_refreshed_list() else {
        return 0;
    };
    disks
        .iter()
        .find(|d| d.mount_point() == Path::new("/"))
        .or_else(|| disks.iter().next())
        .map_or(0, sysinfo::Disk::available_space)
}

pub fn collect() -> Result<DeviceFacts, FactsError> {
    let os_family = os_family()?;
    let architecture = architecture()?;
    let (os_version, os_build, installed_software) = match os_family {
        OsFamily::Macos => {
            let (version, build) = macos_version();
            let mut items = scan_app_bundles(Path::new("/Applications"));
            items.extend(scan_pkg_receipts(Path::new("/var/db/receipts")));
            (version, build, normalize_inventory(items))
        }
        OsFamily::Windows | OsFamily::Linux => {
            let (version, build) = generic_version();
            (version, build, Vec::new())
        }
    };
    let device_name = sysinfo::System::host_name()
        .ok()
        .and_then(|h| clean_text(&h, 120))
        .unwrap_or_else(|| "unknown-device".to_owned());
    let cpu_cores = std::thread::available_parallelism()
        .ok()
        .and_then(|n| u32::try_from(n.get()).ok())
        .unwrap_or(1)
        .clamp(1, 1024);
    let facts = DeviceFacts {
        device_name,
        os_family,
        os_version,
        os_build,
        architecture,
        cpu_cores,
        memory_total_bytes: memory_total().min(1 << 50),
        disk_free_bytes: disk_free().min(1 << 55),
        installed_software,
    };
    facts.validate().map_err(FactsError::Invalid)?;
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_plist(path: &Path, entries: &[(&str, &str)]) {
        let mut dict = plist::Dictionary::new();
        for (k, v) in entries {
            dict.insert((*k).to_owned(), plist::Value::String((*v).to_owned()));
        }
        if let Some(parent) = path.parent() {
            assert!(fs::create_dir_all(parent).is_ok());
        }
        assert!(plist::Value::Dictionary(dict).to_file_xml(path).is_ok());
    }

    #[test]
    fn scans_app_bundles_and_drops_unsafe_values() {
        let Ok(dir) = tempfile::tempdir() else { return };
        let root = dir.path();
        write_plist(
            &root.join("Good.app/Contents/Info.plist"),
            &[
                ("CFBundleIdentifier", "com.example.good"),
                ("CFBundleShortVersionString", "1.2.3"),
            ],
        );
        write_plist(
            &root.join("Fallback.app/Contents/Info.plist"),
            &[
                ("CFBundleIdentifier", "com.example.fallback"),
                ("CFBundleShortVersionString", "1.0\n; rm -rf /"),
                ("CFBundleVersion", "42"),
            ],
        );
        write_plist(
            &root.join("Evil.app/Contents/Info.plist"),
            &[
                ("CFBundleIdentifier", "com.example/../evil"),
                ("CFBundleVersion", "1"),
            ],
        );
        write_plist(
            &root.join("NoId.app/Contents/Info.plist"),
            &[("CFBundleVersion", "1")],
        );
        assert!(fs::create_dir_all(root.join("NotAnApp/Contents")).is_ok());

        let found = normalize_inventory(scan_app_bundles(root));
        let ids: Vec<(&str, &str)> = found
            .iter()
            .map(|s| (s.identifier.as_str(), s.version.as_str()))
            .collect();
        assert_eq!(
            ids,
            vec![
                ("com.example.fallback", "42"),
                ("com.example.good", "1.2.3")
            ]
        );
        assert!(found.iter().all(|s| s.source == SoftwareSource::AppBundle));
    }

    #[test]
    fn scans_pkg_receipts_and_ignores_oversized_files() {
        let Ok(dir) = tempfile::tempdir() else { return };
        let root = dir.path();
        write_plist(
            &root.join("com.example.tool.plist"),
            &[
                ("PackageIdentifier", "com.example.tool"),
                ("PackageVersion", "2.0"),
            ],
        );
        assert!(fs::write(root.join("huge.plist"), vec![b' '; 2 * 1024 * 1024]).is_ok());
        assert!(fs::write(root.join("garbage.plist"), b"not a plist").is_ok());
        let found = scan_pkg_receipts(root);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].identifier, "com.example.tool");
        assert_eq!(found[0].source, SoftwareSource::PkgReceipt);
    }

    #[test]
    fn missing_directories_yield_empty_inventory() {
        assert!(scan_app_bundles(Path::new("/nonexistent/sentinel")).is_empty());
        assert!(scan_pkg_receipts(Path::new("/nonexistent/sentinel")).is_empty());
    }

    #[test]
    fn normalize_dedupes_sorts_and_caps() {
        let item = |id: String, src| InstalledSoftware {
            identifier: id,
            version: "1".into(),
            source: src,
        };
        let mut items: Vec<_> = (0..1500)
            .rev()
            .map(|i| item(format!("com.example.p{i:04}"), SoftwareSource::PkgReceipt))
            .collect();
        items.push(item("com.example.p0001".into(), SoftwareSource::PkgReceipt));
        items.push(item("com.example.app".into(), SoftwareSource::AppBundle));
        let out = normalize_inventory(items);
        assert_eq!(out.len(), MAX_INSTALLED_ITEMS);
        assert_eq!(out[0].identifier, "com.example.app");
        assert_eq!(out[1].identifier, "com.example.p0000");
        assert_eq!(out[2].identifier, "com.example.p0001");
    }

    #[test]
    fn collects_valid_facts_on_this_host() {
        let facts = collect();
        assert!(facts.is_ok(), "{:?}", facts.err());
        if let Ok(f) = facts {
            assert!(f.validate().is_ok());
            assert!(f.cpu_cores >= 1);
        }
    }
}
