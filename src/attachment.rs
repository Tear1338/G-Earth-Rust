//! Scoped hosts-file attachment. Only this application's marked lines are restored.
use crate::{
    raw_ip_lease::RawIpLease,
    relay::{Config, Event, ListenerRoute, Relay, RelayOptions},
};
use gearth_platform::IpMapper;
use std::{
    collections::VecDeque,
    fs::OpenOptions,
    io::{self, Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::mpsc::Receiver,
    thread,
    time::Duration,
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
    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(mut file) => {
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
        Err(err) if cfg!(target_os = "macos") && err.kind() == io::ErrorKind::PermissionDenied => {
            let mut bytes = Vec::new();
            std::fs::File::open(path)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 1024 * 1024 {
                return Err(io::Error::other("hosts file exceeds 1 MiB"));
            }
            let text = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
            let updated = change(text)?;
            if updated != text {
                gearth_platform::write_macos_hosts_privileged(path, &updated)?;
            }
            Ok(())
        }
        Err(err) => Err(err),
    }
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
        Self::install_many(path, &[(host.to_owned(), address)])
    }
    pub fn install_many(path: &Path, entries: &[(String, Ipv4Addr)]) -> io::Result<Self> {
        if entries.is_empty()
            || entries
                .iter()
                .any(|(host, address)| !valid_domain(host) || !address.is_loopback())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "redirect requires valid domains and loopback addresses",
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
                for (host, _) in entries {
                    if line
                        .split_whitespace()
                        .skip(1)
                        .any(|h| h.eq_ignore_ascii_case(host))
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            format!(
                                "domain {host} already has a hosts entry; it was left unchanged"
                            ),
                        ));
                    }
                }
            }
            let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
            let mut result = text.to_owned();
            if !result.is_empty() && !result.ends_with('\n') {
                result.push_str(newline);
            }
            for (host, address) in entries {
                result.push_str(&format!("{address} {host}{MARKER}{token}{newline}"));
            }
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
pub struct RawIpRedirect {
    mapper: Box<dyn IpMapper>,
    ip: Ipv4Addr,
    port: u16,
    active: bool,
    keep_on_connect: bool,
    lease: Option<RawIpLease>,
}
impl RawIpRedirect {
    fn install(ip: Ipv4Addr, port: u16) -> io::Result<Self> {
        let mapper = gearth_platform::system_ip_mapper()?;
        if cfg!(windows) {
            let path = crate::settings::Settings::default_path()
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("rawip_connections.json");
            let _mapping_lock = RawIpLease::mapping_lock(&path)?;
            let (lease, others_active) = RawIpLease::acquire(&path, ip)?;
            Self::with_mapper_and_lease(ip, port, mapper, true, Some(lease), others_active)
        } else {
            Self::with_mapper_and_lease(ip, port, mapper, false, None, false)
        }
    }
    #[cfg(test)]
    fn with_mapper(
        ip: Ipv4Addr,
        port: u16,
        mapper: Box<dyn IpMapper>,
        keep_on_connect: bool,
    ) -> io::Result<Self> {
        Self::with_mapper_and_lease(ip, port, mapper, keep_on_connect, None, false)
    }
    fn with_mapper_and_lease(
        ip: Ipv4Addr,
        port: u16,
        mut mapper: Box<dyn IpMapper>,
        keep_on_connect: bool,
        lease: Option<RawIpLease>,
        others_active: bool,
    ) -> io::Result<Self> {
        if !others_active {
            mapper.enable()?;
            mapper.add_mapping(ip, port, port)?;
        }
        Ok(Self {
            mapper,
            ip,
            port,
            active: true,
            keep_on_connect,
            lease,
        })
    }
    pub fn restore(&mut self) -> io::Result<()> {
        if self.active {
            let _mapping_lock = self
                .lease
                .as_ref()
                .map(RawIpLease::lock_mapping)
                .transpose()?;
            let should_delete = match &self.lease {
                Some(lease) => !lease.others_active()?,
                None => true,
            };
            if should_delete {
                self.mapper.delete_mapping(self.ip, self.port, self.port)?;
            }
            if let Some(lease) = &mut self.lease {
                lease.release()?;
            }
            self.lease = None;
            self.active = false;
        }
        Ok(())
    }
    pub fn restore_on_connect(&self) -> bool {
        !self.keep_on_connect
    }
}
impl Drop for RawIpRedirect {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
pub enum AttachmentRedirect {
    Hosts(HostsRedirect),
    RawIp(RawIpRedirect),
}
impl AttachmentRedirect {
    pub fn restore(&mut self) -> io::Result<()> {
        match self {
            Self::Hosts(redirect) => redirect.restore(),
            Self::RawIp(redirect) => redirect.restore(),
        }
    }
    pub fn restore_on_connect(&self) -> bool {
        match self {
            Self::Hosts(_) => true,
            Self::RawIp(redirect) => redirect.restore_on_connect(),
        }
    }
}
pub struct Attachment {
    pub relay: Relay,
    pub events: Receiver<Event>,
    pub redirect: AttachmentRedirect,
}
impl Attachment {
    pub fn start(host: &str, port: u16, options: RelayOptions, path: &Path) -> io::Result<Self> {
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => Self::start_raw(ip, port, options),
            Ok(IpAddr::V6(_)) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Raw-IP attachment currently requires an IPv4 hotel address",
            )),
            Err(_) => Self::start_hosts(host, port, options, path),
        }
    }
    /// Auto-detect across multiple Habbo hotels simultaneously, matching beta-29 ConnectionInterceptor.
    pub fn start_auto_detect(
        candidates: &[(String, u16)],
        options: RelayOptions,
        path: &Path,
    ) -> io::Result<Self> {
        let mut routes = Vec::new();
        let mut host_entries = Vec::new();
        let mut loopback_index: u16 = 0;
        for (host, port) in candidates {
            let trimmed = host.trim();
            if *port == 0 || trimmed.parse::<IpAddr>().is_ok() || !valid_domain(trimmed) {
                continue;
            }
            if host_entries
                .iter()
                .any(|(existing, _): &(String, Ipv4Addr)| existing.eq_ignore_ascii_case(trimmed))
            {
                continue;
            }
            let resolved = match (trimmed, *port).to_socket_addrs() {
                Ok(mut addrs) => addrs.find(|a| a.is_ipv4() && !a.ip().is_loopback()),
                Err(_) => None,
            };
            let Some(remote) = resolved else {
                continue;
            };
            loopback_index = loopback_index.saturating_add(1);
            let octet3 = (loopback_index / 254) as u8;
            let octet4 = 1u8.saturating_add((loopback_index % 254) as u8);
            let loopback_ip = Ipv4Addr::new(127, 0, octet3, octet4);
            routes.push(ListenerRoute {
                listen: SocketAddr::from((loopback_ip, *port)),
                remote: remote.to_string(),
                host_label: Some((trimmed.to_owned(), *port)),
            });
            host_entries.push((trimmed.to_owned(), loopback_ip));
        }
        if routes.is_empty() {
            return Err(io::Error::other(
                "no hotel domains resolved to a non-loopback IPv4 address; check your network or other running proxies",
            ));
        }
        let (relay, events) = Relay::start_multi(routes, options)?;
        let redirect = HostsRedirect::install_many(path, &host_entries)?;
        Ok(Self {
            relay,
            events,
            redirect: AttachmentRedirect::Hosts(redirect),
        })
    }
    fn start_hosts(
        host: &str,
        port: u16,
        mut options: RelayOptions,
        path: &Path,
    ) -> io::Result<Self> {
        if !valid_domain(host) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "automatic attachment requires a valid hostname or IPv4 address",
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
            redirect: AttachmentRedirect::Hosts(redirect),
        })
    }
    fn start_raw(ip: Ipv4Addr, port: u16, mut options: RelayOptions) -> io::Result<Self> {
        if options.shockwave {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Raw-IP attachment is only available for Flash/EVA_WIRE",
            ));
        }
        if port == 0 || ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Raw-IP attachment requires a non-loopback hotel IPv4 address and fixed port",
            ));
        }
        let remote = SocketAddr::from((ip, port));
        let mut upstream = VecDeque::new();
        if options.socks.is_none() {
            // The mapping would otherwise intercept our own upstream connections.
            for _ in 0..3 {
                upstream.push_back(TcpStream::connect_timeout(
                    &remote,
                    Duration::from_millis(1200),
                )?);
                thread::sleep(Duration::from_millis(50));
            }
        }
        if let Some(details) = &mut options.connection {
            details.host = ip.to_string();
            details.port = port;
        }
        let (relay, events) = Relay::start_raw(
            Config {
                listen: SocketAddr::from(([0, 0, 0, 0], port)),
                remote: remote.to_string(),
            },
            options,
            upstream,
        )?;
        let redirect = RawIpRedirect::install(ip, port)?;
        Ok(Self {
            relay,
            events,
            redirect: AttachmentRedirect::RawIp(redirect),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    #[derive(Clone, Default)]
    struct FakeMapper {
        calls: Arc<Mutex<Vec<String>>>,
        fail_delete: Arc<AtomicBool>,
    }
    impl IpMapper for FakeMapper {
        fn enable(&mut self) -> io::Result<()> {
            self.calls.lock().unwrap().push("enable".into());
            Ok(())
        }
        fn add_mapping(&mut self, ip: Ipv4Addr, _: u16, _: u16) -> io::Result<()> {
            self.calls.lock().unwrap().push(format!("add:{ip}"));
            Ok(())
        }
        fn delete_mapping(&mut self, ip: Ipv4Addr, _: u16, _: u16) -> io::Result<()> {
            self.calls.lock().unwrap().push(format!("delete:{ip}"));
            if self.fail_delete.load(Ordering::Relaxed) {
                Err(io::Error::other("fixture delete failure"))
            } else {
                Ok(())
            }
        }
    }
    fn ip() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 40)
    }
    #[test]
    fn raw_redirect_restores_exactly_once_and_honours_windows_policy() {
        let mapper = FakeMapper::default();
        let calls = mapper.calls.clone();
        let mut redirect = RawIpRedirect::with_mapper(ip(), 30000, Box::new(mapper), true).unwrap();
        assert!(!redirect.restore_on_connect());
        redirect.restore().unwrap();
        redirect.restore().unwrap();
        drop(redirect);
        assert_eq!(
            *calls.lock().unwrap(),
            ["enable", "add:192.0.2.40", "delete:192.0.2.40"]
        );
    }
    #[test]
    fn raw_redirect_drop_cleans_up_and_non_windows_restores_on_connect() {
        let mapper = FakeMapper::default();
        let calls = mapper.calls.clone();
        {
            let redirect =
                RawIpRedirect::with_mapper(ip(), 30000, Box::new(mapper), false).unwrap();
            assert!(redirect.restore_on_connect());
        }
        assert_eq!(
            *calls.lock().unwrap(),
            ["enable", "add:192.0.2.40", "delete:192.0.2.40"]
        );
    }
    #[test]
    fn failed_raw_cleanup_remains_active_for_retry() {
        let mapper = FakeMapper::default();
        mapper.fail_delete.store(true, Ordering::Relaxed);
        let fail_delete = mapper.fail_delete.clone();
        let calls = mapper.calls.clone();
        let mut redirect =
            RawIpRedirect::with_mapper(ip(), 30000, Box::new(mapper), false).unwrap();
        assert!(redirect.restore().is_err());
        assert!(redirect.active);
        fail_delete.store(false, Ordering::Relaxed);
        redirect.restore().unwrap();
        assert!(!redirect.active);
        assert_eq!(
            calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| call.starts_with("delete"))
                .count(),
            2
        );
    }
    #[test]
    fn only_the_last_windows_lease_removes_the_shared_mapping() {
        struct LeaseFile(PathBuf);
        impl Drop for LeaseFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let name = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let file = LeaseFile(std::env::temp_dir().join(format!("gearth-raw-map-{name}.json")));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mapper = || FakeMapper {
            calls: calls.clone(),
            ..Default::default()
        };
        let (first_lease, others) = RawIpLease::acquire(&file.0, ip()).unwrap();
        assert!(!others);
        let mut first = RawIpRedirect::with_mapper_and_lease(
            ip(),
            30000,
            Box::new(mapper()),
            true,
            Some(first_lease),
            others,
        )
        .unwrap();
        let (second_lease, others) = RawIpLease::acquire(&file.0, ip()).unwrap();
        assert!(others);
        let mut second = RawIpRedirect::with_mapper_and_lease(
            ip(),
            30000,
            Box::new(mapper()),
            true,
            Some(second_lease),
            others,
        )
        .unwrap();
        first.restore().unwrap();
        assert_eq!(*calls.lock().unwrap(), ["enable", "add:192.0.2.40"]);
        second.restore().unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            ["enable", "add:192.0.2.40", "delete:192.0.2.40"]
        );
    }

    #[test]
    fn hosts_redirect_install_many_adds_and_restores_all_entries_cleanly() {
        let dir = std::env::temp_dir().join(format!(
            "gearth-hosts-many-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let hosts = dir.join("hosts");
        std::fs::write(&hosts, "127.0.0.1 localhost\n").unwrap();
        let entries = vec![
            ("game-fr.habbo.com".to_owned(), Ipv4Addr::new(127, 0, 0, 2)),
            ("game-us.habbo.com".to_owned(), Ipv4Addr::new(127, 0, 0, 3)),
        ];
        let mut redirect = HostsRedirect::install_many(&hosts, &entries).unwrap();
        let installed = std::fs::read_to_string(&hosts).unwrap();
        assert!(installed.contains("127.0.0.2 game-fr.habbo.com"));
        assert!(installed.contains("127.0.0.3 game-us.habbo.com"));
        redirect.restore().unwrap();
        assert_eq!(
            std::fs::read_to_string(&hosts).unwrap(),
            "127.0.0.1 localhost\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
