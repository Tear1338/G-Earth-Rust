//! Packet identifiers shared with beta-29's extension IPC.
use crate::packet::{error, Direction, Packet, Result};
use std::collections::HashMap;

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
        let version = if version.is_empty() && origins {
            let bytes = download_json(
                &agent,
                "https://api.sulek.dev/releases?variant=shockwave-windows",
            )?;
            let json: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
            json[0]["version"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("no Origins release found"))?
                .to_owned()
        } else {
            version.to_owned()
        };
        if version.is_empty()
            || version.len() > 200
            || !version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(std::io::Error::other("enter a valid hotel version"));
        }
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
        if let Ok(database) = Self::load_cache(&cache, &version) {
            return Ok(database);
        }
        let database = Self::from_json(version, &download_json(&agent, &url)?)
            .map_err(std::io::Error::other)?;
        let _ = database.save_cache(&cache);
        Ok(database)
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
        for (i, e) in entries.iter().enumerate() {
            for name in [&e.name, &e.hash].into_iter().flatten() {
                names.entry((e.direction, name.clone())).or_insert(i);
            }
        }
        Self {
            version: version.into(),
            entries,
            names,
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
        self.entries
            .iter()
            .filter(move |e| e.direction == direction && e.header == header)
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
fn download_json(agent: &ureq::Agent, url: &str) -> std::io::Result<Vec<u8>> {
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
