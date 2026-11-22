//! Opt-in GitHub release update checker, ported from beta-29 UpdateChecker.java.
use crate::maven_version;
use std::{
    cmp::Ordering,
    io::{self, Read},
    time::Duration,
};

const MAX_RESPONSE_BYTES: u64 = 256 * 1024;
pub const DEFAULT_REPOSITORY: &str = "Tear1338/G-Earth-Rust";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateInfo {
    pub latest_version: String,
    pub release_url: String,
    pub outdated: bool,
}

fn normalize_tag(tag: &str) -> &str {
    let trimmed = tag.trim();
    trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed)
}

fn valid_release_url(url: &str, repository: &str) -> bool {
    let expected_prefix = format!("https://github.com/{repository}/");
    url.starts_with(&expected_prefix)
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

    let outdated = maven_version::compare(normalize_tag(tag), normalize_tag(current_version))
        == Ordering::Greater;
    Ok(UpdateInfo {
        latest_version: tag.to_owned(),
        release_url,
        outdated,
    })
}

/// Check the latest GitHub release for `repository`. Only invoked when explicitly requested.
pub fn check_github_updates(repository: &str, current_version: &str) -> io::Result<UpdateInfo> {
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
    fn rejects_invalid_repository_slugs_and_empty_responses() {
        assert!(check_github_updates("not-a-valid-repo", "0.1.0").is_err());
        assert!(parse_release_response(DEFAULT_REPOSITORY, "0.1.0", b"[]").is_err());
        assert!(parse_release_response(DEFAULT_REPOSITORY, "0.1.0", b"{}").is_err());
    }
}
