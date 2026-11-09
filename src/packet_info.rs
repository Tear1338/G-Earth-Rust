//! Packet identifiers shared with beta-29's extension IPC.
use crate::packet::{error, Direction, Packet, Result};
use std::collections::HashMap;

fn valid_sulek_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 200
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn resolve_sulek_version(
    requested: &str,
    origins: bool,
    discover: impl FnOnce() -> std::io::Result<Vec<u8>>,
) -> std::io::Result<String> {
    if origins {
        let latest = discover().and_then(|bytes| {
            let json: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
            let version = json[0]["version"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("no Origins release found"))?;
            if !valid_sulek_version(version) {
                return Err(std::io::Error::other("invalid Origins release version"));
            }
            Ok(version.to_owned())
        });
        match latest {
            Ok(version) => return Ok(version),
            Err(error) if requested.is_empty() => return Err(error),
            Err(_) => {}
        }
    }
    if valid_sulek_version(requested) {
        Ok(requested.to_owned())
    } else {
        Err(std::io::Error::other("enter a valid hotel version"))
    }
}

// Only the most recently started refresh for a path may publish its result.
// Entries live only while a refresh is in progress.
struct RefreshGuard {
    path: std::path::PathBuf,
    generation: u64,
}
impl RefreshGuard {
    fn active() -> &'static std::sync::Mutex<HashMap<std::path::PathBuf, u64>> {
        static ACTIVE: std::sync::OnceLock<std::sync::Mutex<HashMap<std::path::PathBuf, u64>>> =
            std::sync::OnceLock::new();
        ACTIVE.get_or_init(Default::default)
    }
    fn new(path: &std::path::Path) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let mut active = Self::active().lock().unwrap_or_else(|e| e.into_inner());
        let guard = Self {
            path: path.to_owned(),
            generation: NEXT.fetch_add(1, Ordering::Relaxed),
        };
        active.insert(guard.path.clone(), guard.generation);
        guard
    }
    fn save_if_current(&self, database: &PacketInfoManager) {
        let active = Self::active().lock().unwrap_or_else(|e| e.into_inner());
        if active.get(&self.path) == Some(&self.generation) {
            let _ = database.save_cache(&self.path);
        }
    }
}
impl Drop for RefreshGuard {
    fn drop(&mut self) {
        let mut active = Self::active().lock().unwrap_or_else(|e| e.into_inner());
        if active.get(&self.path) == Some(&self.generation) {
            active.remove(&self.path);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketInfo {
    pub header: u16,
    pub hash: Option<String>,
    pub name: Option<String>,
    pub structure: Option<String>,
    pub direction: Direction,
    pub source: String,
}
#[derive(Debug, Clone, Default)]
pub struct PacketInfoManager {
    pub version: String,
    entries: Vec<PacketInfo>,
    names: HashMap<(Direction, String), usize>,
    headers: HashMap<(Direction, u16), Vec<usize>>,
}
impl PacketInfoManager {
    /// Read the upstream Sulek response or G-Earth's Unity messages.json schema.
    pub fn from_json(version: impl Into<String>, bytes: &[u8]) -> Result<Self> {
        let json: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| error(&e.to_string()))?;
        let sulek = json.get("messages").is_some();
        let root = if sulek { &json["messages"] } else { &json };
        let mut entries = Vec::new();
        for (key, direction) in [
            (
                if sulek { "incoming" } else { "Incoming" },
                Direction::ToClient,
            ),
            (
                if sulek { "outgoing" } else { "Outgoing" },
                Direction::ToServer,
            ),
        ] {
            let list = root[key]
                .as_array()
                .ok_or_else(|| error("packet database is missing direction arrays"))?;
            if entries.len() + list.len() > 65536 {
                return Err(error("too many packet identifiers"));
            }
            for item in list {
                let id = item[if sulek { "id" } else { "Id" }]
                    .as_u64()
                    .ok_or_else(|| error("invalid packet identifier"))?;
                let header =
                    u16::try_from(id).map_err(|_| error("packet identifier exceeds 65535"))?;
                let name = item[if sulek { "name" } else { "Name" }]
                    .as_str()
                    .ok_or_else(|| error("missing packet name"))?;
                let name = if sulek {
                    ["MessageComposer", "Composer", "MessageEvent", "Event"]
                        .iter()
                        .find_map(|suffix| name.strip_suffix(suffix))
                        .unwrap_or(name)
                } else {
                    name
                };
                if name.is_empty() || name.len() > 4096 {
                    return Err(error("invalid packet name"));
                }
                entries.push(PacketInfo {
                    header,
                    hash: None,
                    name: Some(name.into()),
                    structure: None,
                    direction,
                    source: if sulek {
                        "Sulek".into()
                    } else {
                        "G-Earth".into()
                    },
                });
            }
        }
        Ok(Self::new(version, entries))
    }
    /// HTTPS lookup on a worker thread; never call this on the UI event loop.
    pub fn fetch_sulek(version: &str, origins: bool) -> std::io::Result<Self> {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .build();
        let version = resolve_sulek_version(version, origins, || {
            download_json(
                &agent,
                "https://api.sulek.dev/releases?variant=shockwave-windows",
            )
        })?;
        let url = if origins {
            format!("https://api.sulek.dev/releases/shockwave-windows/{version}/messages")
        } else {
            format!("https://api.sulek.dev/releases/{version}/messages")
        };
        let cache = crate::settings::Settings::default_path()
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("packet-identifiers")
            .join(format!(
                "{}-{version}.bin",
                if origins { "SHOCKWAVE" } else { "FLASH" }
            ));
        Self::load_or_refresh(&cache, &version, std::time::SystemTime::now(), || {
            Self::from_json(&version, &download_json(&agent, &url)?).map_err(std::io::Error::other)
        })
    }
    pub(crate) fn load_or_refresh(
        path: &std::path::Path,
        version: &str,
        now: std::time::SystemTime,
        fetch: impl FnOnce() -> std::io::Result<Self>,
    ) -> std::io::Result<Self> {
        let cached = Self::load_cache(path, version).ok();
        let fresh = std::fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .map(|modified| {
                now.duration_since(modified)
                    .map_or(true, |age| age < std::time::Duration::from_secs(300))
            })
            .unwrap_or(false);
        if fresh {
            if let Some(database) = cached.as_ref() {
                return Ok(database.clone());
            }
        }
        let refresh = RefreshGuard::new(path);
        match fetch() {
            Ok(database) => {
                refresh.save_if_current(&database);
                Ok(database)
            }
            Err(error) => cached.ok_or(error),
        }
    }
    pub fn load_cache(path: &std::path::Path, version: &str) -> std::io::Result<Self> {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(std::io::Error::other("packet cache exceeds 8 MiB"));
        }
        let mut packet = Packet::from_bytes(bytes).map_err(std::io::Error::other)?;
        if packet.header() != 1 || packet.read_string().map_err(std::io::Error::other)? != version {
            return Err(std::io::Error::other("packet cache version mismatch"));
        }
        let database = Self::read_from(version, &mut packet).map_err(std::io::Error::other)?;
        if packet.remaining() != 0 {
            return Err(std::io::Error::other("trailing packet cache data"));
        }
        Ok(database)
    }
    pub fn save_cache(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        let mut packet = Packet::new(1);
        packet
            .put_string(&self.version)
            .map_err(std::io::Error::other)?;
        self.append_to(&mut packet).map_err(std::io::Error::other)?;
        if packet.bytes().len() > 8 * 1024 * 1024 {
            return Err(std::io::Error::other("packet cache exceeds 8 MiB"));
        }
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|e| std::io::Error::other(e.to_string()))?;
        let suffix = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let temporary = parent.join(format!(".packet-info-{suffix}.tmp"));
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            file.write_all(packet.bytes())?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temporary, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
    pub fn new(version: impl Into<String>, entries: Vec<PacketInfo>) -> Self {
        let mut names = HashMap::new();
        let mut headers: HashMap<(Direction, u16), Vec<usize>> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            headers.entry((e.direction, e.header)).or_default().push(i);
            for name in [&e.name, &e.hash].into_iter().flatten() {
                names.entry((e.direction, name.clone())).or_insert(i);
            }
        }
        Self {
            version: version.into(),
            entries,
            names,
            headers,
        }
    }
    pub fn entries(&self) -> &[PacketInfo] {
        &self.entries
    }
    pub fn by_name(&self, direction: Direction, name: &str) -> Option<&PacketInfo> {
        self.names
            .get(&(direction, name.to_owned()))
            .map(|i| &self.entries[*i])
    }
    pub fn by_header(
        &self,
        direction: Direction,
        header: u16,
    ) -> impl Iterator<Item = &PacketInfo> {
        self.headers
            .get(&(direction, header))
            .into_iter()
            .flatten()
            .map(|index| &self.entries[*index])
    }
    pub fn append_to(&self, p: &mut Packet) -> Result<()> {
        p.put_i32(
            i32::try_from(self.entries.len()).map_err(|_| error("too many packet identifiers"))?,
        )?;
        for e in &self.entries {
            p.put_i32(i32::from(e.header))?
                .put_string(e.hash.as_deref().unwrap_or("NULL"))?
                .put_string(e.name.as_deref().unwrap_or("NULL"))?
                .put_string(e.structure.as_deref().unwrap_or("NULL"))?
                .put_bool(e.direction == Direction::ToServer)?
                .put_string(&e.source)?;
        }
        Ok(())
    }
    pub fn read_from(version: impl Into<String>, p: &mut Packet) -> Result<Self> {
        let count = p.read_i32()?;
        if count < 0 || count as usize > p.remaining() / 13 {
            return Err(error("invalid packet identifier count"));
        }
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let header =
                u16::try_from(p.read_i32()?).map_err(|_| error("invalid packet header"))?;
            let optional = |s: String| if s == "NULL" { None } else { Some(s) };
            let hash = optional(p.read_string()?);
            let name = optional(p.read_string()?);
            let structure = optional(p.read_string()?);
            let direction = if p.read_bool()? {
                Direction::ToServer
            } else {
                Direction::ToClient
            };
            let source = p.read_string()?;
            entries.push(PacketInfo {
                header,
                hash,
                name,
                structure,
                direction,
                source,
            });
        }
        Ok(Self::new(version, entries))
    }
    /// Portable tab-separated database: direction, header, name, hash, structure, source.
    pub fn from_tsv(version: impl Into<String>, text: &str) -> Result<Self> {
        let mut entries = Vec::new();
        for line in text
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 6 {
                return Err(error("packet database requires six tab-separated fields"));
            }
            let optional = |s: &str| {
                if s.is_empty() || s == "NULL" {
                    None
                } else {
                    Some(s.to_owned())
                }
            };
            entries.push(PacketInfo {
                direction: Direction::parse(fields[0])?,
                header: fields[1]
                    .parse()
                    .map_err(|_| error("invalid database header"))?,
                name: optional(fields[2]),
                hash: optional(fields[3]),
                structure: optional(fields[4]),
                source: fields[5].to_owned(),
            });
        }
        Ok(Self::new(version, entries))
    }
}
pub(crate) fn download_json(agent: &ureq::Agent, url: &str) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let response = agent
        .get(url)
        .set("Accept", "application/json")
        .call()
        .map_err(std::io::Error::other)?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(std::io::Error::other("packet database exceeds 8 MiB"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod cache_refresh_tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn origins_discovery_uses_latest_or_falls_back_to_requested_version() {
        let releases = || Ok(br#"[{"version":"LATEST-2"}]"#.to_vec());
        assert_eq!(
            resolve_sulek_version("OLD", true, releases).unwrap(),
            "LATEST-2"
        );
        assert_eq!(
            resolve_sulek_version("", true, releases).unwrap(),
            "LATEST-2"
        );
        assert_eq!(
            resolve_sulek_version("FLASH", false, || panic!("Flash must not query Origins"))
                .unwrap(),
            "FLASH"
        );
        for data in [
            &b"not json"[..],
            &b"[]"[..],
            &b"[{\"version\":\"../invalid\"}]"[..],
        ] {
            assert_eq!(
                resolve_sulek_version("OLD", true, || Ok(data.to_vec())).unwrap(),
                "OLD"
            );
            assert!(resolve_sulek_version("", true, || Ok(data.to_vec())).is_err());
        }
        assert_eq!(
            resolve_sulek_version("OLD", true, || Err(std::io::Error::other("offline"))).unwrap(),
            "OLD"
        );
        assert!(resolve_sulek_version("", true, || Err(std::io::Error::other("offline"))).is_err());
        assert!(
            resolve_sulek_version("../invalid", true, || Err(std::io::Error::other("offline")))
                .is_err()
        );
    }

    #[test]
    fn older_refresh_cannot_replace_newer_refresh_even_after_it_finishes() {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let name = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let path = std::env::temp_dir().join(format!("gearth-refresh-race-{name}.bin"));
        let database = |id| {
            PacketInfoManager::from_json("REV", format!(r#"{{"messages":{{"incoming":[{{"id":{id},"name":"TestEvent"}}],"outgoing":[]}}}}"#).as_bytes()).unwrap()
        };
        database(1).save_cache(&path).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let old_path = path.clone();
        let worker = std::thread::spawn(move || {
            PacketInfoManager::load_or_refresh(
                &old_path,
                "REV",
                SystemTime::now() + Duration::from_secs(301),
                || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(database(2))
                },
            )
            .unwrap()
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        PacketInfoManager::load_or_refresh(
            &path,
            "REV",
            SystemTime::now() + Duration::from_secs(301),
            || Ok(database(3)),
        )
        .unwrap();
        release_tx.send(()).unwrap();
        assert_eq!(worker.join().unwrap().entries()[0].header, 2);
        assert_eq!(
            PacketInfoManager::load_cache(&path, "REV")
                .unwrap()
                .entries()[0]
                .header,
            3
        );
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let old_path = path.clone();
        let worker = std::thread::spawn(move || {
            PacketInfoManager::load_or_refresh(
                &old_path,
                "REV",
                SystemTime::now() + Duration::from_secs(301),
                || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(database(4))
                },
            )
            .unwrap()
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let fallback = PacketInfoManager::load_or_refresh(
            &path,
            "REV",
            SystemTime::now() + Duration::from_secs(301),
            || Err(std::io::Error::other("offline")),
        )
        .unwrap();
        assert_eq!(fallback.entries()[0].header, 3);
        release_tx.send(()).unwrap();
        assert_eq!(worker.join().unwrap().entries()[0].header, 4);
        assert_eq!(
            PacketInfoManager::load_cache(&path, "REV")
                .unwrap()
                .entries()[0]
                .header,
            3
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn refreshes_expired_cache_and_falls_back_only_to_valid_matching_data() {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let name = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let path = std::env::temp_dir().join(format!("gearth-refresh-{name}.bin"));
        let old = PacketInfoManager::from_json(
            "REV",
            br#"{"messages":{"incoming":[{"id":1,"name":"OldEvent"}],"outgoing":[]}}"#,
        )
        .unwrap();
        let new = PacketInfoManager::from_json(
            "REV",
            br#"{"messages":{"incoming":[{"id":2,"name":"NewEvent"}],"outgoing":[]}}"#,
        )
        .unwrap();
        old.save_cache(&path).unwrap();
        let now = SystemTime::now();
        let loaded =
            PacketInfoManager::load_or_refresh(&path, "REV", now, || panic!("fresh cache fetched"))
                .unwrap();
        assert_eq!(loaded.entries()[0].header, 1);
        let future = now + Duration::from_secs(301);
        let loaded = PacketInfoManager::load_or_refresh(&path, "REV", future, || {
            PacketInfoManager::from_json("REV", b"not json").map_err(std::io::Error::other)
        })
        .unwrap();
        assert_eq!(loaded.entries()[0].header, 1);
        assert_eq!(
            PacketInfoManager::load_cache(&path, "REV")
                .unwrap()
                .entries()[0]
                .header,
            1
        );
        let loaded = PacketInfoManager::load_or_refresh(&path, "REV", future, || {
            Err(std::io::Error::other("offline"))
        })
        .unwrap();
        assert_eq!(loaded.entries()[0].header, 1);
        let loaded =
            PacketInfoManager::load_or_refresh(&path, "REV", future, || Ok(new.clone())).unwrap();
        assert_eq!(loaded.entries()[0].header, 2);
        assert_eq!(
            PacketInfoManager::load_cache(&path, "REV")
                .unwrap()
                .entries()[0]
                .header,
            2
        );
        assert!(
            PacketInfoManager::load_or_refresh(&path, "OTHER", future, || Err(
                std::io::Error::other("offline")
            ))
            .is_err()
        );
        std::fs::write(&path, b"invalid").unwrap();
        assert!(
            PacketInfoManager::load_or_refresh(&path, "REV", future, || Err(
                std::io::Error::other("offline")
            ))
            .is_err()
        );
        std::fs::remove_file(&path).unwrap();
        assert!(
            PacketInfoManager::load_or_refresh(&path, "REV", future, || Err(
                std::io::Error::other("offline")
            ))
            .is_err()
        );
    }
}
