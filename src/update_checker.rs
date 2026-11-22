//! GitHub release update checker and SHA-256 verified self-updater.
use crate::maven_version;
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const MAX_RESPONSE_BYTES: u64 = 256 * 1024;
const MAX_CHECKSUMS_BYTES: u64 = 64 * 1024;
const MAX_BINARY_BYTES: u64 = 128 * 1024 * 1024;
pub const DEFAULT_REPOSITORY: &str = "Tear1338/G-Earth-Rust";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateInfo {
    pub latest_version: String,
    pub release_url: String,
    pub outdated: bool,
    pub asset_name: Option<String>,
    pub asset_download_url: Option<String>,
    pub checksums_url: Option<String>,
    pub setup_asset_name: Option<String>,
    pub setup_download_url: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateApplyOutcome {
    RestartedPortable,
    LaunchedInstaller,
}

/// Returns the CI-injected GitHub release tag (e.g. `development-485`) or crate version.
pub fn current_build_tag() -> &'static str {
    option_env!("GEARTH_BUILD_TAG")
        .filter(|s| !s.is_empty())
        .unwrap_or(env!("CARGO_PKG_VERSION"))
}

fn platform_asset_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "G-Earth-Rust-Windows.exe"
    } else if cfg!(target_os = "macos") {
        "G-Earth-Rust-macOS"
    } else {
        "G-Earth-Rust-Linux"
    }
}

fn normalize_tag(tag: &str) -> &str {
    let trimmed = tag.trim();
    trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed)
}

fn parse_dev_build_number(tag: &str) -> Option<u64> {
    tag.trim()
        .strip_prefix("development-")
        .and_then(|rest| rest.parse::<u64>().ok())
}

fn is_newer_version(latest_tag: &str, current_tag: &str) -> bool {
    if let (Some(latest_num), Some(current_num)) = (
        parse_dev_build_number(latest_tag),
        parse_dev_build_number(current_tag),
    ) {
        return latest_num > current_num;
    }
    maven_version::compare(normalize_tag(latest_tag), normalize_tag(current_tag))
        == Ordering::Greater
}

fn valid_release_url(url: &str, repository: &str) -> bool {
    let expected_prefix = format!("https://github.com/{repository}/");
    url.starts_with(&expected_prefix)
}

fn valid_download_url(url: &str, repository: &str) -> bool {
    let expected_prefix = format!("https://github.com/{repository}/releases/download/");
    url.starts_with(&expected_prefix)
}

fn find_asset_url(
    entry: &serde_json::Value,
    repository: &str,
    expected_name: &str,
) -> Option<String> {
    entry["assets"].as_array()?.iter().find_map(|asset| {
        let name = asset["name"].as_str()?.trim();
        let url = asset["browser_download_url"].as_str()?.trim();
        (name == expected_name && valid_download_url(url, repository)).then(|| url.to_owned())
    })
}

pub fn parse_release_response(
    repository: &str,
    current_version: &str,
    json_bytes: &[u8],
) -> io::Result<UpdateInfo> {
    let value: serde_json::Value = serde_json::from_slice(json_bytes).map_err(io::Error::other)?;
    let entry = if value.is_array() {
        value
            .as_array()
            .and_then(|items| items.first())
            .ok_or_else(|| io::Error::other("no releases published yet"))?
    } else {
        &value
    };
    let tag = entry["tag_name"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| io::Error::other("release response missing tag_name"))?;
    let release_url = entry["html_url"]
        .as_str()
        .map(str::trim)
        .filter(|url| valid_release_url(url, repository))
        .map(str::to_owned)
        .unwrap_or_else(|| format!("https://github.com/{repository}/releases/latest"));

    let asset_target = platform_asset_name();
    let asset_download_url = find_asset_url(entry, repository, asset_target);
    let asset_name = asset_download_url.as_ref().map(|_| asset_target.to_owned());
    let checksums_url = find_asset_url(entry, repository, "SHA256SUMS.txt");
    let setup_download_url = if cfg!(target_os = "windows") {
        find_asset_url(entry, repository, "G-Earth-Rust-Setup-x64.exe")
    } else {
        None
    };
    let setup_asset_name = setup_download_url
        .as_ref()
        .map(|_| "G-Earth-Rust-Setup-x64.exe".to_owned());

    let outdated = is_newer_version(tag, current_version);
    Ok(UpdateInfo {
        latest_version: tag.to_owned(),
        release_url,
        outdated,
        asset_name,
        asset_download_url,
        checksums_url,
        setup_asset_name,
        setup_download_url,
    })
}

pub fn parse_sha256sums(contents: &str, asset_name: &str) -> Option<String> {
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let hash = parts.next()?.trim();
        let file = parts
            .next()?
            .trim()
            .trim_start_matches('*')
            .trim_start_matches("./");
        if file == asset_name && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(hash.to_ascii_lowercase());
        }
    }
    None
}

fn validate_repo_slug(repository: &str) -> io::Result<()> {
    if !repository
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
        || repository.matches('/').count() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid GitHub repository slug",
        ));
    }
    Ok(())
}

/// Check the latest GitHub release for `repository`.
pub fn check_github_updates(repository: &str, current_version: &str) -> io::Result<UpdateInfo> {
    validate_repo_slug(repository)?;
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();
    let latest_url = format!("https://api.github.com/repos/{repository}/releases/latest");
    let response = match agent
        .get(&latest_url)
        .set("User-Agent", "G-Earth-Rust")
        .set("Accept", "application/vnd.github+json")
        .call()
    {
        Ok(response) => response,
        Err(ureq::Error::Status(404, _)) => {
            // Fall back to the newest pre-release when no stable release exists yet.
            let list_url = format!("https://api.github.com/repos/{repository}/releases?per_page=1");
            agent
                .get(&list_url)
                .set("User-Agent", "G-Earth-Rust")
                .set("Accept", "application/vnd.github+json")
                .call()
                .map_err(io::Error::other)?
        }
        Err(error) => return Err(io::Error::other(error)),
    };
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(io::Error::other("GitHub release response exceeds 256 KiB"));
    }
    parse_release_response(repository, current_version, &bytes)
}

fn backup_exe_path(current_exe: &Path) -> PathBuf {
    let mut os = current_exe.as_os_str().to_os_string();
    os.push(".old");
    PathBuf::from(os)
}

/// Best-effort cleanup of `<current_exe>.old` left behind by a previous self-update.
pub fn cleanup_old_binary() {
    if let Ok(exe) = std::env::current_exe() {
        let old = backup_exe_path(&exe);
        if old.is_file() {
            let _ = fs::remove_file(old);
        }
    }
}

/// Atomically replace `current_exe` with `staged_binary`, rolling back if the move fails.
pub fn apply_binary_replacement(current_exe: &Path, staged_binary: &Path) -> io::Result<()> {
    if !staged_binary.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "staged update binary not found",
        ));
    }
    let backup = backup_exe_path(current_exe);
    if backup.exists() {
        let _ = fs::remove_file(&backup);
    }
    fs::rename(current_exe, &backup)?;
    if let Err(move_err) = fs::rename(staged_binary, current_exe) {
        // Cross-device fallback: copy into place, then delete staged file.
        if let Err(copy_err) = fs::copy(staged_binary, current_exe) {
            let _ = fs::rename(&backup, current_exe);
            return Err(io::Error::other(format!(
                "could not replace binary ({move_err}; copy fallback failed: {copy_err})"
            )));
        }
        let _ = fs::remove_file(staged_binary);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(current_exe, fs::Permissions::from_mode(0o755));
    }
    Ok(())
}

fn fetch_expected_sha256(
    agent: &ureq::Agent,
    checksums_url: &str,
    asset_name: &str,
) -> io::Result<String> {
    let response = agent
        .get(checksums_url)
        .set("User-Agent", "G-Earth-Rust")
        .call()
        .map_err(io::Error::other)?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_CHECKSUMS_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CHECKSUMS_BYTES {
        return Err(io::Error::other("SHA256SUMS.txt exceeds 64 KiB"));
    }
    let text = String::from_utf8(bytes).map_err(io::Error::other)?;
    parse_sha256sums(&text, asset_name).ok_or_else(|| {
        io::Error::other(format!("SHA256SUMS.txt missing checksum for {asset_name}"))
    })
}

fn download_verified_file(
    agent: &ureq::Agent,
    download_url: &str,
    expected_sha256: &str,
    dest_path: &Path,
) -> io::Result<()> {
    let response = agent
        .get(download_url)
        .set("User-Agent", "G-Earth-Rust")
        .call()
        .map_err(io::Error::other)?;
    let mut reader = response.into_reader();
    let mut file = fs::File::create(dest_path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > MAX_BINARY_BYTES {
            drop(file);
            let _ = fs::remove_file(dest_path);
            return Err(io::Error::other("update asset exceeds 128 MiB limit"));
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n])?;
    }
    file.sync_all()?;
    drop(file);

    let actual_hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if actual_hex != expected_sha256 {
        let _ = fs::remove_file(dest_path);
        return Err(io::Error::other(format!(
            "SHA-256 verification failed (expected {expected_sha256}, got {actual_hex})"
        )));
    }
    Ok(())
}

/// Download, SHA-256 verify, apply the update, and relaunch G-Earth Rust.
pub fn download_and_apply_update(info: &UpdateInfo) -> io::Result<UpdateApplyOutcome> {
    let checksums_url = info
        .checksums_url
        .as_deref()
        .ok_or_else(|| io::Error::other("release does not provide SHA256SUMS.txt"))?;
    let current_exe = std::env::current_exe()?;
    let exe_dir = current_exe
        .parent()
        .ok_or_else(|| io::Error::other("could not determine executable directory"))?;
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(120))
        .build();

    let staged_path = exe_dir.join(format!(".gearth-update-{}.tmp", std::process::id()));
    let dir_writable = fs::File::create(&staged_path).is_ok();
    if dir_writable {
        let _ = fs::remove_file(&staged_path);
        let asset_name = info
            .asset_name
            .as_deref()
            .ok_or_else(|| io::Error::other("release does not contain a binary for this OS"))?;
        let asset_url = info
            .asset_download_url
            .as_deref()
            .ok_or_else(|| io::Error::other("release missing binary download URL"))?;
        let expected = fetch_expected_sha256(&agent, checksums_url, asset_name)?;
        download_verified_file(&agent, asset_url, &expected, &staged_path)?;
        apply_binary_replacement(&current_exe, &staged_path)?;
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        Command::new(&current_exe).args(args).spawn()?;
        return Ok(UpdateApplyOutcome::RestartedPortable);
    }

    // Fallback on Windows when installed in a read-only folder (e.g. Program Files):
    // download the SHA-256 verified Inno Setup installer to %TEMP% and launch silently.
    if cfg!(target_os = "windows") {
        if let (Some(setup_name), Some(setup_url)) = (
            info.setup_asset_name.as_deref(),
            info.setup_download_url.as_deref(),
        ) {
            let expected = fetch_expected_sha256(&agent, checksums_url, setup_name)?;
            let installer_path =
                std::env::temp_dir().join(format!("G-Earth-Rust-Setup-{}.exe", std::process::id()));
            download_verified_file(&agent, setup_url, &expected, &installer_path)?;
            Command::new(&installer_path)
                .args(["/SILENT", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS"])
                .spawn()?;
            return Ok(UpdateApplyOutcome::LaunchedInstaller);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("cannot write update into {}", exe_dir.display()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_newer_equal_and_older_releases_using_maven_versioning() {
        let newer = br#"{"tag_name":"v0.2.0","html_url":"https://github.com/Tear1338/G-Earth-Rust/releases/tag/v0.2.0"}"#;
        let info = parse_release_response(DEFAULT_REPOSITORY, "0.1.0", newer).unwrap();
        assert!(info.outdated);
        assert_eq!(info.latest_version, "v0.2.0");
        assert_eq!(
            info.release_url,
            "https://github.com/Tear1338/G-Earth-Rust/releases/tag/v0.2.0"
        );

        let same = br#"{"tag_name":"v0.1.0","html_url":"https://evil.example/fake"}"#;
        let info = parse_release_response(DEFAULT_REPOSITORY, "0.1.0", same).unwrap();
        assert!(!info.outdated);
        assert_eq!(
            info.release_url,
            "https://github.com/Tear1338/G-Earth-Rust/releases/latest"
        );

        let prerelease_array = br#"[{"tag_name":"0.1.0-beta-2","html_url":"https://github.com/Tear1338/G-Earth-Rust/releases/tag/0.1.0-beta-2"}]"#;
        let info =
            parse_release_response(DEFAULT_REPOSITORY, "0.1.0-beta-1", prerelease_array).unwrap();
        assert!(info.outdated);
        let older = parse_release_response(DEFAULT_REPOSITORY, "0.1.0", prerelease_array).unwrap();
        assert!(!older.outdated);
    }

    #[test]
    fn compares_development_build_tags_numerically_and_extracts_verified_assets() {
        let asset = platform_asset_name();
        let json = format!(
            r#"[{{"tag_name":"development-1000","html_url":"https://github.com/Tear1338/G-Earth-Rust/releases/tag/development-1000","assets":[
                {{"name":"{asset}","browser_download_url":"https://github.com/Tear1338/G-Earth-Rust/releases/download/development-1000/{asset}"}},
                {{"name":"SHA256SUMS.txt","browser_download_url":"https://github.com/Tear1338/G-Earth-Rust/releases/download/development-1000/SHA256SUMS.txt"}}
            ]}}]"#
        );
        let info =
            parse_release_response(DEFAULT_REPOSITORY, "development-999", json.as_bytes()).unwrap();
        assert!(info.outdated);
        assert_eq!(info.asset_name.as_deref(), Some(asset));
        assert!(info.asset_download_url.is_some());
        assert!(info.checksums_url.is_some());

        let same = parse_release_response(DEFAULT_REPOSITORY, "development-1000", json.as_bytes())
            .unwrap();
        assert!(!same.outdated);

        // Untrusted third-party download URLs must be rejected
        let evil = format!(
            r#"{{"tag_name":"development-1001","html_url":"https://github.com/Tear1338/G-Earth-Rust/releases/tag/development-1001","assets":[
                {{"name":"{asset}","browser_download_url":"https://evil.example/{asset}"}}
            ]}}"#
        );
        let info = parse_release_response(DEFAULT_REPOSITORY, "development-1000", evil.as_bytes())
            .unwrap();
        assert!(info.asset_download_url.is_none());
    }

    #[test]
    fn parses_sha256sums_lines_strictly() {
        let valid_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let body = format!(
            "{valid_hash}  G-Earth-Rust-Windows.exe\n\
             ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789 *G-Earth-Rust-Linux\n\
             short  bad.exe\n"
        );
        assert_eq!(
            parse_sha256sums(&body, "G-Earth-Rust-Windows.exe").as_deref(),
            Some(valid_hash)
        );
        assert_eq!(
            parse_sha256sums(&body, "G-Earth-Rust-Linux").as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );
        assert!(parse_sha256sums(&body, "bad.exe").is_none());
        assert!(parse_sha256sums(&body, "missing.exe").is_none());
    }

    #[test]
    fn binary_replacement_swaps_atomically_and_creates_old_backup() {
        let dir = std::env::temp_dir().join(format!(
            "gearth-update-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let current = dir.join("gearth-desktop.exe");
        let staged = dir.join("staged.tmp");
        fs::write(&current, b"old-binary").unwrap();
        fs::write(&staged, b"new-binary").unwrap();

        apply_binary_replacement(&current, &staged).unwrap();
        assert_eq!(fs::read(&current).unwrap(), b"new-binary");
        assert_eq!(fs::read(backup_exe_path(&current)).unwrap(), b"old-binary");
        assert!(!staged.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_invalid_repository_slugs_and_empty_responses() {
        assert!(check_github_updates("not-a-valid-repo", "0.1.0").is_err());
        assert!(parse_release_response(DEFAULT_REPOSITORY, "0.1.0", b"[]").is_err());
        assert!(parse_release_response(DEFAULT_REPOSITORY, "0.1.0", b"{}").is_err());
    }
}
