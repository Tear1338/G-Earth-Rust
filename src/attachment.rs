//! Scoped hosts-file attachment. Only this application's marked lines are restored.
use crate::relay::{Config, Event, Relay, RelayOptions};
use std::{
    fs::OpenOptions,
    io::{self, Read, Seek, SeekFrom, Write},
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::mpsc::Receiver,
};
const MARKER: &str = " # G-Earth-Rust:";
pub const FLASH_HOTELS: &[&str] = &[
    "game-br.habbo.com",
    "game-de.habbo.com",
    "game-es.habbo.com",
    "game-fi.habbo.com",
    "game-fr.habbo.com",
    "game-it.habbo.com",
    "game-nl.habbo.com",
    "game-tr.habbo.com",
    "game-us.habbo.com",
    "game-s2.habbo.com",
];
pub const ORIGINS_HOTELS: &[&str] = &[
    "game-od.habbo.com",
    "game-ous.habbo.com",
    "game-obr.habbo.com",
    "game-oes.habbo.com",
];
pub struct HostsRedirect {
    path: PathBuf,
    token: String,
    active: bool,
}
fn edit(path: &Path, change: impl FnOnce(&str) -> io::Result<String>) -> io::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    file.lock()?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(io::Error::other("hosts file exceeds 1 MiB"));
    }
    let text = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
    let updated = change(text)?;
    if updated != text {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(updated.as_bytes())?;
        file.set_len(updated.len() as u64)?;
        file.sync_all()?;
    }
    Ok(())
}
fn valid_domain(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn owned(line: &str, token: Option<&str>) -> bool {
    let Some((_, id)) = line.trim_end_matches(['\r', '\n']).rsplit_once(MARKER) else {
        return false;
    };
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) && token.is_none_or(|t| id == t)
}
impl HostsRedirect {
    pub fn install(path: &Path, host: &str, address: Ipv4Addr) -> io::Result<Self> {
        if !valid_domain(host) || !address.is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "redirect requires a domain and loopback address",
            ));
        }
        let mut random = [0; 32];
        getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
        let token = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        edit(path, |text| {
            if text.lines().any(|l| owned(l, None)) {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists,"a G-Earth Rust redirect already exists; stop that instance or recover stale redirects"));
            }
            for line in text.lines() {
                let line = line.split('#').next().unwrap_or("");
                if line
                    .split_whitespace()
                    .skip(1)
                    .any(|h| h.eq_ignore_ascii_case(host))
                {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "this domain already has a hosts entry; it was left unchanged",
                    ));
                }
            }
            let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
            let mut result = text.to_owned();
            if !result.is_empty() && !result.ends_with('\n') {
                result.push_str(newline);
            }
            result.push_str(&format!("{address} {host}{MARKER}{token}{newline}"));
            Ok(result)
        })?;
        Ok(Self {
            path: path.into(),
            token,
            active: true,
        })
    }
    pub fn restore(&mut self) -> io::Result<()> {
        if self.active {
            edit(&self.path, |text| {
                Ok(text
                    .split_inclusive('\n')
                    .filter(|l| !owned(l, Some(&self.token)))
                    .collect())
            })?;
            self.active = false;
        }
        Ok(())
    }
    pub fn recover_stale(path: &Path) -> io::Result<()> {
        edit(path, |text| {
            Ok(text
                .split_inclusive('\n')
                .filter(|l| !owned(l, None))
                .collect())
        })
    }
    pub fn system_path() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
                .join("System32/drivers/etc/hosts")
        } else {
            PathBuf::from("/etc/hosts")
        }
    }
}
impl Drop for HostsRedirect {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
pub struct Attachment {
    pub relay: Relay,
    pub events: Receiver<Event>,
    pub redirect: HostsRedirect,
}
impl Attachment {
    pub fn start(
        host: &str,
        port: u16,
        mut options: RelayOptions,
        path: &Path,
    ) -> io::Result<Self> {
        if !valid_domain(host) || host.parse::<std::net::IpAddr>().is_ok() {
            return Err(io::Error::other(
                "automatic attachment requires a hostname; raw-IP interception is not implemented",
            ));
        }
        let remote=(host,port).to_socket_addrs()?.find(|a|a.is_ipv4()&&!a.ip().is_loopback()).ok_or_else(||io::Error::other("hotel did not resolve to a non-loopback IPv4 address; check other running proxies"))?;
        let listen = SocketAddr::from(([127, 0, 0, 2], port));
        if let Some(details) = &mut options.connection {
            details.host = host.into();
            details.port = port;
        }
        let (relay, events) = Relay::start_with_options(
            Config {
                listen,
                remote: remote.to_string(),
            },
            options,
        )?;
        let redirect = HostsRedirect::install(path, host, Ipv4Addr::new(127, 0, 0, 2))?;
        Ok(Self {
            relay,
            events,
            redirect,
        })
    }
}
