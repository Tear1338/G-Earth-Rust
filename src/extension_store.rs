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
pub const STORE_VERSION: &str = "1.5.3";
const MAX_JSON: usize = 8 * 1024 * 1024;
const MAX_ARCHIVE: usize = 64 * 1024 * 1024;
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
            "https://raw.githubusercontent.com/{}/repo/{}/{}",
            self.source,
            self.version,
            path.iter()
                .map(|part| uri_component(part))
                .collect::<Vec<_>>()
                .join("/")
        )
    }
    pub fn fetch(source: &str, version: &str) -> io::Result<Self> {
        if !source_valid(source)
            || version.len() > 100
            || !version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(io::Error::other("invalid extension store source"));
        }
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(20))
            .build();
        let prefix = format!("https://raw.githubusercontent.com/{source}/repo/{version}");
        let read = |suffix: &str| -> io::Result<Vec<u8>> {
            let response = agent
                .get(&format!("{prefix}/{suffix}"))
                .call()
                .map_err(io::Error::other)?;
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
        Self::parse(
            source,
            version,
            &read("store/config.json")?,
            &read(".auto-generated/extensions.json")?,
        )
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
        entries.sort_by(|a, b| {
            let ordering = match query.sort {
                Sort::Rating => b.rating.cmp(&a.rating),
                Sort::Alphabetical => a.title.to_lowercase().cmp(&b.title.to_lowercase()),
                Sort::LastUpdated => date_key(&b.update_date)
                    .unwrap()
                    .cmp(&date_key(&a.update_date).unwrap()),
                Sort::NewReleases => date_key(&b.submission_date)
                    .unwrap()
                    .cmp(&date_key(&a.submission_date).unwrap()),
            };
            if query.reverse {
                ordering.reverse()
            } else {
                ordering
            }
        });
        entries
    }
    pub fn archive_url(&self, extension: &StoreExtension) -> String {
        self.resource_url(&["store", "extensions", &extension.title, "extension.zip"])
    }
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
    if !catalog
        .extensions
        .iter()
        .any(|value| value.title == extension.title && value.version == extension.version)
    {
        return Err(io::Error::other("extension is not in this catalogue"));
    }
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
