//! Original extension-store catalogue, native queries and versioned installations.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    fs,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};
pub const STORE_SOURCE: &str = "sirjonasxx/G-ExtensionStore";
pub const CUSTOM_STORE_SOURCE: &str = "Tear1338/G-ExtensionStore";
pub const STORE_VERSION: &str = "1.5.3";
const MAX_JSON: usize = 8 * 1024 * 1024;
const MAX_ARCHIVE: usize = 64 * 1024 * 1024;
const SOURCES_FILE: &str = "store-sources.json";

fn default_enabled() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreSource {
    pub repo: String,
    pub version: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

impl StoreSource {
    pub fn new(repo: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            repo: repo.into(),
            version: version.into(),
            enabled: true,
        }
    }

    pub fn display_tag(&self) -> &str {
        self.repo.split('/').next().unwrap_or(&self.repo)
    }
}

pub fn default_sources() -> Vec<StoreSource> {
    vec![
        StoreSource::new(STORE_SOURCE, STORE_VERSION),
        StoreSource::new(CUSTOM_STORE_SOURCE, STORE_VERSION),
    ]
}

pub fn validate_source(repo: &str, version: &str) -> io::Result<()> {
    if !source_valid(repo)
        || version.is_empty()
        || version.len() > 100
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid store repository (expected owner/repo) or branch/version",
        ));
    }
    Ok(())
}

pub fn load_sources(root: &Path) -> Vec<StoreSource> {
    let path = root.join(SOURCES_FILE);
    let Ok(bytes) = fs::read(&path) else {
        return default_sources();
    };
    if bytes.len() > MAX_JSON {
        return default_sources();
    }
    let Ok(parsed) = serde_json::from_slice::<Vec<StoreSource>>(&bytes) else {
        return default_sources();
    };
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for item in parsed {
        let repo = item.repo.trim().to_owned();
        let version = item.version.trim().to_owned();
        if validate_source(&repo, &version).is_ok() && seen.insert(repo.to_ascii_lowercase()) {
            out.push(StoreSource {
                repo,
                version,
                enabled: item.enabled,
            });
        }
    }
    if out.is_empty() {
        default_sources()
    } else {
        out
    }
}

pub fn save_sources(root: &Path, sources: &[StoreSource]) -> io::Result<()> {
    let mut cleaned = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for item in sources {
        let repo = item.repo.trim().to_owned();
        let version = item.version.trim().to_owned();
        validate_source(&repo, &version)?;
        if seen.insert(repo.to_ascii_lowercase()) {
            cleaned.push(StoreSource {
                repo,
                version,
                enabled: item.enabled,
            });
        }
    }
    fs::create_dir_all(root)?;
    let bytes = serde_json::to_vec_pretty(&cleaned).map_err(io::Error::other)?;
    fs::write(root.join(SOURCES_FILE), bytes)
}

#[derive(Clone, Debug)]
pub struct SourceStatus {
    pub repo: String,
    pub version: String,
    pub loaded_ref: Option<String>,
    pub extension_count: usize,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct MultiCatalog {
    pub catalogs: Vec<Catalog>,
    pub statuses: Vec<SourceStatus>,
}

fn compare_extensions(
    a: &StoreExtension,
    b: &StoreExtension,
    sort: Sort,
    reverse: bool,
) -> Ordering {
    let ordering = match sort {
        Sort::Rating => b.rating.cmp(&a.rating),
        Sort::Alphabetical => a.title.to_lowercase().cmp(&b.title.to_lowercase()),
        Sort::LastUpdated => date_key(&b.update_date)
            .unwrap()
            .cmp(&date_key(&a.update_date).unwrap()),
        Sort::NewReleases => date_key(&b.submission_date)
            .unwrap()
            .cmp(&date_key(&a.submission_date).unwrap()),
    };
    if reverse {
        ordering.reverse()
    } else {
        ordering
    }
}

fn git_ref_for_version(version: &str) -> String {
    if version == "main" || version == "master" {
        version.to_owned()
    } else {
        format!("repo/{version}")
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Category {
    pub name: String,
    pub description: String,
    pub icon: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrameworkInstallation {
    pub required: bool,
    pub instructions: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Framework {
    pub name: String,
    pub developers: Vec<String>,
    pub languages: Vec<String>,
    pub source: String,
    pub installation: FrameworkInstallation,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoreConfig {
    pub categories: Vec<Category>,
    pub frameworks: Vec<Framework>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Author {
    pub name: String,
    pub discord: Option<String>,
    pub hotel: Option<String>,
    pub username: Option<String>,
    pub twitter: Option<String>,
    pub extensions_count: i32,
    pub reputation: i32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtensionFramework {
    pub name: String,
    pub version: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commands {
    #[serde(rename = "default")]
    pub common: Vec<String>,
    pub windows: Option<Vec<String>>,
    pub linux: Option<Vec<String>>,
    pub mac: Option<Vec<String>>,
}
impl Commands {
    pub fn for_platform(&self) -> &[String] {
        let platform = if cfg!(windows) {
            &self.windows
        } else if cfg!(target_os = "macos") {
            &self.mac
        } else {
            &self.linux
        };
        platform.as_deref().unwrap_or(&self.common)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Compatibility {
    pub systems: Vec<String>,
    pub clients: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreExtension {
    pub title: String,
    pub description: String,
    pub authors: Vec<Author>,
    pub version: String,
    pub categories: Vec<String>,
    pub source: String,
    pub readme: Option<String>,
    pub releases: Option<String>,
    pub stable: bool,
    pub framework: ExtensionFramework,
    pub language: String,
    pub commands: Commands,
    pub compatibility: Compatibility,
    pub submission_date: String,
    pub update_date: String,
    #[serde(rename = "isOutdated")]
    pub outdated: bool,
    pub rating: i32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Catalog {
    pub source: String,
    pub version: String,
    pub config: StoreConfig,
    pub extensions: Vec<StoreExtension>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Sort {
    #[default]
    Rating,
    Alphabetical,
    LastUpdated,
    NewReleases,
}
#[derive(Default)]
pub struct Query<'a> {
    pub text: &'a str,
    pub os: Option<&'a str>,
    pub client: Option<&'a str>,
    pub framework: Option<&'a str>,
    pub category: Option<&'a str>,
    pub include_outdated: bool,
    pub sort: Sort,
    pub reverse: bool,
}
fn bounded(text: &str, maximum: usize) -> io::Result<()> {
    if text.is_empty() || text.len() > maximum || text.contains('\0') {
        return Err(io::Error::other("invalid store text field"));
    }
    Ok(())
}
fn source_valid(source: &str) -> bool {
    let pieces = source.split('/').collect::<Vec<_>>();
    pieces.len() == 2
        && pieces.iter().all(|piece| {
            !piece.is_empty()
                && piece.len() <= 100
                && piece
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
        && !pieces.contains(&"..")
}
fn date_key(value: &str) -> io::Result<[u32; 6]> {
    let numbers = value
        .split(['-', ' ', ':'])
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    if numbers.len() != 6
        || numbers[0] == 0
        || numbers[0] > 31
        || numbers[1] == 0
        || numbers[1] > 12
        || numbers[2] < 1970
        || numbers[3] > 23
        || numbers[4] > 59
        || numbers[5] > 59
    {
        return Err(io::Error::other("invalid store date"));
    }
    Ok([
        numbers[2], numbers[1], numbers[0], numbers[3], numbers[4], numbers[5],
    ])
}
pub fn uri_component(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            output.push(byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}
impl Catalog {
    pub fn parse(
        source: &str,
        version: &str,
        config: &[u8],
        extensions: &[u8],
    ) -> io::Result<Self> {
        if !source_valid(source)
            || version.is_empty()
            || version.len() > 100
            || !version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || config.len() > MAX_JSON
            || extensions.len() > MAX_JSON
        {
            return Err(io::Error::other(
                "invalid store source/version or oversized catalogue",
            ));
        }
        let config: StoreConfig = serde_json::from_slice(config).map_err(io::Error::other)?;
        let extensions: Vec<StoreExtension> =
            serde_json::from_slice(extensions).map_err(io::Error::other)?;
        if config.categories.len() > 256 || config.frameworks.len() > 256 || extensions.len() > 4096
        {
            return Err(io::Error::other("store catalogue exceeds item limits"));
        }
        let mut titles = std::collections::HashSet::new();
        for extension in &extensions {
            bounded(&extension.title, 256)?;
            bounded(&extension.version, 128)?;
            if extension.description.len() > 65536
                || !titles.insert(&extension.title)
                || !config
                    .frameworks
                    .iter()
                    .any(|framework| framework.name == extension.framework.name)
            {
                return Err(io::Error::other("invalid or duplicate store extension"));
            }
            date_key(&extension.submission_date)?;
            date_key(&extension.update_date)?;
            for command in [
                &extension.commands.common,
                extension
                    .commands
                    .windows
                    .as_ref()
                    .unwrap_or(&extension.commands.common),
                extension
                    .commands
                    .linux
                    .as_ref()
                    .unwrap_or(&extension.commands.common),
                extension
                    .commands
                    .mac
                    .as_ref()
                    .unwrap_or(&extension.commands.common),
            ] {
                if command.is_empty()
                    || command.len() > 128
                    || command
                        .iter()
                        .any(|arg| arg.len() > 16384 || arg.contains('\0'))
                    || command[0].is_empty()
                {
                    return Err(io::Error::other("invalid extension launch command"));
                }
            }
        }
        Ok(Self {
            source: source.into(),
            version: version.into(),
            config,
            extensions,
        })
    }
    pub fn resource_url(&self, path: &[&str]) -> String {
        format!(
            "https://raw.githubusercontent.com/{}/{}/{}",
            self.source,
            git_ref_for_version(&self.version),
            path.iter()
                .map(|part| uri_component(part))
                .collect::<Vec<_>>()
                .join("/")
        )
    }
    pub fn fetch(source: &str, version: &str) -> io::Result<Self> {
        Self::fetch_with_fallback(source, version, None)
    }
    pub fn fetch_with_fallback(
        source: &str,
        version: &str,
        fallback_config: Option<&StoreConfig>,
    ) -> io::Result<Self> {
        validate_source(source, version)?;
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(20))
            .build();
        let read_url = |url: &str| -> io::Result<Vec<u8>> {
            let response = agent.get(url).call().map_err(io::Error::other)?;
            let mut bytes = Vec::new();
            response
                .into_reader()
                .take((MAX_JSON + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > MAX_JSON {
                return Err(io::Error::other("store response exceeds 8 MiB"));
            }
            Ok(bytes)
        };
        let try_version = |candidate_version: &str| -> io::Result<Self> {
            let git_ref = git_ref_for_version(candidate_version);
            let prefix = format!("https://raw.githubusercontent.com/{source}/{git_ref}");
            let extensions_bytes = read_url(&format!("{prefix}/.auto-generated/extensions.json"))
                .or_else(|primary_err| {
                if source != STORE_SOURCE {
                    read_url(&format!("{prefix}/extensions.json")).map_err(|_| primary_err)
                } else {
                    Err(primary_err)
                }
            })?;
            let config_bytes = match read_url(&format!("{prefix}/store/config.json")) {
                Ok(bytes) => bytes,
                Err(err) => {
                    if let Some(fallback) = fallback_config {
                        serde_json::to_vec(fallback).map_err(io::Error::other)?
                    } else {
                        return Err(err);
                    }
                }
            };
            Self::parse(source, candidate_version, &config_bytes, &extensions_bytes)
        };
        match try_version(version) {
            Ok(catalog) => Ok(catalog),
            Err(primary_err) if version != "main" && source != STORE_SOURCE => {
                try_version("main").map_err(|_| primary_err)
            }
            Err(err) => Err(err),
        }
    }
    pub fn query(&self, query: &Query<'_>) -> Vec<&StoreExtension> {
        let needle = query.text.to_lowercase();
        let mut entries = self
            .extensions
            .iter()
            .filter(|extension| {
                let text = std::iter::once(extension.title.as_str())
                    .chain(std::iter::once(extension.description.as_str()))
                    .chain(extension.authors.iter().flat_map(|author| {
                        [Some(author.name.as_str()), author.username.as_deref()]
                            .into_iter()
                            .flatten()
                    }))
                    .chain(extension.categories.iter().map(String::as_str))
                    .chain([
                        extension.framework.name.as_str(),
                        extension.language.as_str(),
                    ])
                    .chain(extension.compatibility.systems.iter().map(String::as_str))
                    .chain(extension.compatibility.clients.iter().map(String::as_str))
                    .any(|value| value.to_lowercase().contains(&needle));
                text && (query.include_outdated || !extension.outdated)
                    && query.os.is_none_or(|os| {
                        extension
                            .compatibility
                            .systems
                            .iter()
                            .any(|value| value == os)
                    })
                    && query.client.is_none_or(|client| {
                        extension
                            .compatibility
                            .clients
                            .iter()
                            .any(|value| value == client)
                    })
                    && query
                        .framework
                        .is_none_or(|framework| extension.framework.name == framework)
                    && query.category.is_none_or(|category| {
                        extension.categories.iter().any(|value| value == category)
                    })
            })
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| compare_extensions(a, b, query.sort, query.reverse));
        entries
    }
    pub fn archive_url(&self, extension: &StoreExtension) -> String {
        self.resource_url(&["store", "extensions", &extension.title, "extension.zip"])
    }
    pub fn icon_url(&self, extension: &StoreExtension) -> String {
        self.resource_url(&["store", "extensions", &extension.title, "icon.png"])
    }
    pub fn screenshot_url(&self, extension: &StoreExtension) -> String {
        self.resource_url(&["store", "extensions", &extension.title, "screenshot.png"])
    }
}

impl MultiCatalog {
    pub fn from_catalogs(catalogs: Vec<Catalog>) -> Self {
        let statuses = catalogs
            .iter()
            .map(|c| SourceStatus {
                repo: c.source.clone(),
                version: c.version.clone(),
                loaded_ref: Some(git_ref_for_version(&c.version)),
                extension_count: c.extensions.len(),
                error: None,
            })
            .collect();
        Self { catalogs, statuses }
    }

    pub fn fetch_many(sources: &[StoreSource]) -> io::Result<Self> {
        let enabled: Vec<&StoreSource> = sources.iter().filter(|s| s.enabled).collect();
        if enabled.is_empty() {
            return Err(io::Error::other("no extension store sources are enabled"));
        }
        let mut catalogs: Vec<Catalog> = Vec::new();
        let mut statuses: Vec<SourceStatus> = Vec::new();
        let mut first_error: Option<io::Error> = None;

        for source in enabled {
            let fallback_config = catalogs.first().map(|c| &c.config);
            match Catalog::fetch_with_fallback(&source.repo, &source.version, fallback_config) {
                Ok(catalog) => {
                    statuses.push(SourceStatus {
                        repo: source.repo.clone(),
                        version: source.version.clone(),
                        loaded_ref: Some(git_ref_for_version(&catalog.version)),
                        extension_count: catalog.extensions.len(),
                        error: None,
                    });
                    catalogs.push(catalog);
                }
                Err(error) => {
                    statuses.push(SourceStatus {
                        repo: source.repo.clone(),
                        version: source.version.clone(),
                        loaded_ref: None,
                        extension_count: 0,
                        error: Some(error.to_string()),
                    });
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        if catalogs.is_empty() {
            return Err(first_error
                .unwrap_or_else(|| io::Error::other("failed to load extension catalogues")));
        }
        Ok(Self { catalogs, statuses })
    }

    pub fn total_extensions(&self) -> usize {
        self.catalogs.iter().map(|c| c.extensions.len()).sum()
    }

    pub fn merged_categories(&self) -> Vec<Category> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for catalog in &self.catalogs {
            for cat in &catalog.config.categories {
                if seen.insert(cat.name.clone()) {
                    out.push(cat.clone());
                }
            }
        }
        out
    }

    pub fn merged_frameworks(&self) -> Vec<Framework> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for catalog in &self.catalogs {
            for fw in &catalog.config.frameworks {
                if seen.insert(fw.name.clone()) {
                    out.push(fw.clone());
                }
            }
        }
        out
    }

    pub fn find(&self, source: &str, title: &str) -> Option<(&Catalog, &StoreExtension)> {
        self.catalogs
            .iter()
            .find(|c| c.source == source)
            .and_then(|c| {
                c.extensions
                    .iter()
                    .find(|e| e.title == title)
                    .map(|e| (c, e))
            })
    }

    pub fn query<'a>(
        &'a self,
        query: &Query<'_>,
        source_filter: Option<&str>,
    ) -> Vec<(&'a Catalog, &'a StoreExtension)> {
        let mut entries: Vec<(&'a Catalog, &'a StoreExtension)> = Vec::new();
        for catalog in &self.catalogs {
            if source_filter.is_some_and(|filter| catalog.source != filter) {
                continue;
            }
            for ext in catalog.query(query) {
                entries.push((catalog, ext));
            }
        }
        entries.sort_by(|(_, a), (_, b)| compare_extensions(a, b, query.sort, query.reverse));
        entries
    }
}

const MAX_IMAGE_BYTES: usize = 2 * 1024 * 1024;

/// Download a bounded store icon/screenshot from GitHub raw content.
pub fn fetch_image_bytes(url: &str) -> io::Result<Vec<u8>> {
    if !url.starts_with("https://raw.githubusercontent.com/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "image URL must point to raw.githubusercontent.com",
        ));
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let response = agent.get(url).call().map_err(io::Error::other)?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take((MAX_IMAGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(io::Error::other("store image exceeds 2 MiB"));
    }
    Ok(bytes)
}

/// Convert a beta-29 store date (`dd-MM-yyyy HH:mm:ss`) into a relative `(amount, unit_key_prefix)`.
/// Unit key prefixes match `ext.store.elapsedtime.<unit>.single` / `.multiple`.
pub fn elapsed_since(date_str: &str, now_unix_secs: u64) -> Option<(u64, &'static str)> {
    let [year, month, day, hour, minute, second] = date_key(date_str).ok()?;
    let days = days_from_civil(year as i64, month, day)?;
    let then_secs = (days as u64)
        .checked_mul(86_400)?
        .checked_add(u64::from(hour) * 3600 + u64::from(minute) * 60 + u64::from(second))?;
    let diff = now_unix_secs.saturating_sub(then_secs);
    let (amount, unit) = if diff < 60 {
        (diff.max(1), "second")
    } else if diff < 3600 {
        (diff / 60, "minute")
    } else if diff < 86_400 {
        (diff / 3600, "hour")
    } else if diff < 86_400 * 7 {
        (diff / 86_400, "day")
    } else if diff < 86_400 * 30 {
        (diff / (86_400 * 7), "week")
    } else if diff < 86_400 * 365 {
        (diff / (86_400 * 30), "month")
    } else {
        (diff / (86_400 * 365), "year")
    };
    Some((amount, unit))
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = u64::from(month);
    let d = u64::from(day);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    (days >= 0).then_some(days)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Installed {
    pub schema: u32,
    pub source: String,
    pub title: String,
    pub version: String,
    pub archive_sha256: String,
    pub command: Vec<String>,
    pub files: Vec<String>,
    #[serde(skip)]
    pub directory: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallStatus {
    NotInstalled,
    Installed,
    UpdateAvailable,
    OlderVersion,
}

/// Describe this catalogue version relative to the newest matching installation.
pub fn install_status(
    catalog: &Catalog,
    extension: &StoreExtension,
    installed: &[Installed],
) -> InstallStatus {
    let mut newest: Option<&str> = None;
    for record in installed
        .iter()
        .filter(|record| record.source == catalog.source && record.title == extension.title)
    {
        if record.version == extension.version {
            return InstallStatus::Installed;
        }
        if newest.is_none_or(|version| compare_versions(&record.version, version).is_gt()) {
            newest = Some(&record.version);
        }
    }
    match newest.map(|version| compare_versions(&extension.version, version)) {
        Some(Ordering::Greater) => InstallStatus::UpdateAvailable,
        Some(Ordering::Less) => InstallStatus::OlderVersion,
        _ => InstallStatus::NotInstalled,
    }
}
fn install_id(catalog: &Catalog, extension: &StoreExtension) -> String {
    let digest = Sha256::digest(
        format!(
            "{}\n{}\n{}",
            catalog.source, extension.title, extension.version
        )
        .as_bytes(),
    );
    format!(
        "extension-{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}
fn archive_path(name: &str) -> io::Result<PathBuf> {
    if name.len() > 1024 || name.contains('\\') || name.contains(':') || name.contains('\0') {
        return Err(io::Error::other("invalid archive member path"));
    }
    let path = Path::new(name);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.components().any(|component| {
            let value = component.as_os_str().to_string_lossy();
            value.ends_with([' ', '.']) || value.contains(['<', '>', '"', '|', '?', '*'])
        })
    {
        return Err(io::Error::other("archive member escapes its installation"));
    }
    Ok(path.into())
}
pub fn installed(root: &Path) -> io::Result<Vec<Installed>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir()
            || !entry
                .file_name()
                .to_string_lossy()
                .starts_with("extension-")
        {
            continue;
        }
        let path = entry.path();
        let Ok(file) = fs::File::open(path.join("gearth-install.json")) else {
            continue;
        };
        let mut bytes = Vec::new();
        file.take((MAX_JSON + 1) as u64).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_JSON {
            continue;
        }
        let Ok(mut record) = serde_json::from_slice::<Installed>(&bytes) else {
            continue;
        };
        if record.schema != 1
            || record.files.len() > 4096
            || record.files.iter().any(|file| archive_path(file).is_err())
        {
            continue;
        }
        record.directory = path;
        result.push(record);
    }
    Ok(result)
}
pub fn install(
    catalog: &Catalog,
    extension: &StoreExtension,
    root: &Path,
) -> io::Result<Installed> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(60))
        .build();
    let response = agent
        .get(&catalog.archive_url(extension))
        .call()
        .map_err(io::Error::other)?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take((MAX_ARCHIVE + 1) as u64)
        .read_to_end(&mut bytes)?;
    install_archive(catalog, extension, root, &bytes)
}
pub fn install_archive(
    catalog: &Catalog,
    extension: &StoreExtension,
    root: &Path,
    bytes: &[u8],
) -> io::Result<Installed> {
    if bytes.len() > MAX_ARCHIVE {
        return Err(io::Error::other("extension archive exceeds 64 MiB"));
    }
    let extension = catalog
        .extensions
        .iter()
        .find(|value| value.title == extension.title && value.version == extension.version)
        .ok_or_else(|| io::Error::other("extension is not in this catalogue"))?;
    fs::create_dir_all(root)?;
    let root = root.canonicalize()?;
    let id = install_id(catalog, extension);
    let destination = root.join(id);
    if destination.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "this extension version is already installed",
        ));
    }
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
    let temporary = root.join(format!(
        ".install-{}",
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    fs::create_dir(&temporary)?;
    let result = (|| -> io::Result<Installed> {
        let contents = temporary.join("extension");
        fs::create_dir(&contents)?;
        let mut zip = zip::ZipArchive::new(io::Cursor::new(bytes)).map_err(io::Error::other)?;
        if zip.len() > 4096 {
            return Err(io::Error::other("extension archive has too many entries"));
        }
        let mut files = Vec::new();
        let mut size = 0u64;
        for index in 0..zip.len() {
            let mut file = zip.by_index(index).map_err(io::Error::other)?;
            let relative = archive_path(file.name().trim_end_matches('/'))?;
            if file
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
            {
                return Err(io::Error::other("extension archive contains a symlink"));
            }
            let path = contents.join(&relative);
            if file.is_dir() {
                fs::create_dir_all(&path)?;
                continue;
            }
            if file.size() > 64 * 1024 * 1024 {
                return Err(io::Error::other("extension member exceeds 64 MiB"));
            }
            size = size
                .checked_add(file.size())
                .filter(|size| *size <= 256 * 1024 * 1024)
                .ok_or_else(|| io::Error::other("extension archive expands beyond 256 MiB"))?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut output = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)?;
            let length = io::copy(&mut file.by_ref().take(64 * 1024 * 1024 + 1), &mut output)?;
            if length != file.size() {
                return Err(io::Error::other("extension member length mismatch"));
            }
            output.sync_all()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(file.unix_mode().unwrap_or(0o644) & 0o777),
                )?;
            }
            files.push(relative.to_string_lossy().replace('\\', "/"));
        }
        let record = Installed {
            schema: 1,
            source: catalog.source.clone(),
            title: extension.title.clone(),
            version: extension.version.clone(),
            archive_sha256: Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            command: extension.commands.for_platform().to_vec(),
            files,
            directory: destination.clone(),
        };
        let manifest = serde_json::to_vec_pretty(&record).map_err(io::Error::other)?;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(temporary.join("gearth-install.json"))?;
        file.write_all(&manifest)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &destination)?;
        Ok(record)
    })();
    if result.is_err() {
        remove_staging(&root, &temporary)?;
    }
    result
}
fn remove_staging(root: &Path, path: &Path) -> io::Result<()> {
    let path = path.canonicalize()?;
    if !path.starts_with(root)
        || path.parent() != Some(root)
        || !path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(".install-"))
    {
        return Err(io::Error::other("invalid extension staging cleanup path"));
    }
    fs::remove_dir_all(path)
}
pub fn uninstall(root: &Path, record: &Installed) -> io::Result<()> {
    let root = root.canonicalize()?;
    let path = record.directory.canonicalize()?;
    if path.parent() != Some(root.as_path())
        || !path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("extension-"))
    {
        return Err(io::Error::other(
            "installation is outside the extension directory",
        ));
    }
    let verified = installed(&root)?
        .into_iter()
        .find(|value| {
            value.directory == path
                && value.title == record.title
                && value.version == record.version
        })
        .ok_or_else(|| io::Error::other("installation manifest does not match"))?;
    let contents = path.join("extension");
    for file in &verified.files {
        let relative = archive_path(file)?;
        let target = contents.join(relative);
        if let Ok(metadata) = fs::symlink_metadata(&target) {
            if !metadata.file_type().is_file() {
                return Err(io::Error::other(
                    "installed extension member was replaced by another file type",
                ));
            }
        }
    }
    fs::remove_dir_all(path)
}
/// Compare extension versions using Maven's ComparableVersion rules.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    crate::maven_version::compare(a, b)
}

#[cfg(test)]
mod store_helper_tests {
    use super::elapsed_since;

    #[test]
    fn elapsed_since_formats_beta29_dates_into_relative_units() {
        // 2026-01-01 00:00:00 UTC = 1767225600
        let base = 1_767_225_600u64;
        assert_eq!(
            elapsed_since("01-01-2026 00:00:00", base + 45),
            Some((45, "second"))
        );
        assert_eq!(
            elapsed_since("01-01-2026 00:00:00", base + 3 * 7 * 86_400),
            Some((3, "week"))
        );
        assert_eq!(
            elapsed_since("01-01-2026 00:00:00", base + 65 * 86_400),
            Some((2, "month"))
        );
        assert_eq!(elapsed_since("bad-date", base), None);
    }
}
