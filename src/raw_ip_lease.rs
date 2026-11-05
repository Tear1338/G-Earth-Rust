//! Cross-process Raw-IP leases compatible with the beta-29 heartbeat policy.
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_LEASE_FILE: usize = 1024 * 1024;
const EXPIRY_MS: u64 = 60_000;
const HEARTBEAT: Duration = Duration::from_secs(55);

fn now_ms() -> io::Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    u64::try_from(elapsed.as_millis()).map_err(io::Error::other)
}

fn edit<T>(path: &Path, change: impl FnOnce(&mut Value, u64) -> io::Result<T>) -> io::Result<T> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    file.lock()?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_LEASE_FILE as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_LEASE_FILE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Raw-IP lease file exceeds 1 MiB",
        ));
    }
    let mut root = if bytes.iter().all(u8::is_ascii_whitespace) {
        json!({})
    } else {
        serde_json::from_slice::<Value>(&bytes).map_err(io::Error::other)?
    };
    if !root.is_object() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Raw-IP lease file must contain an object",
        ));
    }
    let now = now_ms()?;
    let result = change(&mut root, now)?;
    let updated = serde_json::to_vec(&root).map_err(io::Error::other)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&updated)?;
    file.set_len(updated.len() as u64)?;
    file.sync_all()?;
    Ok(result)
}

fn connections<'a>(
    root: &'a mut Value,
    hotel: &str,
    now: u64,
) -> io::Result<&'a mut serde_json::Map<String, Value>> {
    let root = root.as_object_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Raw-IP lease root must be an object",
        )
    })?;
    let connections = root
        .entry(hotel.to_owned())
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "hotel Raw-IP leases must be an object",
            )
        })?;
    for lease in connections.values() {
        if lease["timestamp"].as_u64().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Raw-IP lease timestamp must be an unsigned integer",
            ));
        }
    }
    connections.retain(|_, lease| {
        lease["timestamp"]
            .as_u64()
            .is_some_and(|timestamp| timestamp >= now.saturating_sub(EXPIRY_MS))
    });
    Ok(connections)
}

pub(crate) struct RawIpLease {
    path: PathBuf,
    hotel: String,
    id: String,
    running: Arc<AtomicBool>,
    heartbeat_error: Arc<Mutex<Option<String>>>,
    worker: Option<JoinHandle<()>>,
    released: bool,
}
impl RawIpLease {
    /// Serializes mapping changes across processes, independently of the lease-file lock.
    pub(crate) fn mapping_lock(path: &Path) -> io::Result<fs::File> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let lock_path = path.with_extension("mapping.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        file.lock()?;
        Ok(file)
    }

    pub(crate) fn lock_mapping(&self) -> io::Result<fs::File> {
        Self::mapping_lock(&self.path)
    }
    /// Returns the lease and whether another unexpired instance already owns the hotel mapping.
    pub(crate) fn acquire(path: &Path, hotel: Ipv4Addr) -> io::Result<(Self, bool)> {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
        let id = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let hotel = hotel.to_string();
        let others_active = edit(path, |root, now| {
            let connections = connections(root, &hotel, now)?;
            let others_active = connections.keys().any(|existing| existing != &id);
            connections.insert(id.clone(), json!({"timestamp": now}));
            Ok(others_active)
        })?;
        let running = Arc::new(AtomicBool::new(true));
        let heartbeat_error = Arc::new(Mutex::new(None));
        let worker = {
            let path = path.to_owned();
            let hotel = hotel.clone();
            let id = id.clone();
            let running = running.clone();
            let heartbeat_error = heartbeat_error.clone();
            thread::spawn(move || {
                while running.load(Ordering::Acquire) {
                    thread::park_timeout(HEARTBEAT);
                    if !running.load(Ordering::Acquire) {
                        break;
                    }
                    let result = edit(&path, |root, now| {
                        connections(root, &hotel, now)?
                            .insert(id.clone(), json!({"timestamp": now}));
                        Ok(())
                    });
                    if let Ok(mut slot) = heartbeat_error.lock() {
                        *slot = result.err().map(|error| error.to_string());
                    }
                }
            })
        };
        Ok((
            Self {
                path: path.into(),
                hotel,
                id,
                running,
                heartbeat_error,
                worker: Some(worker),
                released: false,
            },
            others_active,
        ))
    }
    pub(crate) fn others_active(&self) -> io::Result<bool> {
        if let Some(error) = self
            .heartbeat_error
            .lock()
            .map_err(|_| io::Error::other("Raw-IP heartbeat lock poisoned"))?
            .clone()
        {
            return Err(io::Error::other(format!(
                "Raw-IP heartbeat failed: {error}"
            )));
        }
        edit(&self.path, |root, now| {
            Ok(connections(root, &self.hotel, now)?
                .keys()
                .any(|existing| existing != &self.id))
        })
    }
    pub(crate) fn release(&mut self) -> io::Result<()> {
        if self.released {
            return Ok(());
        }
        self.running.store(false, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            worker
                .join()
                .map_err(|_| io::Error::other("Raw-IP heartbeat thread panicked"))?;
        }
        edit(&self.path, |root, now| {
            connections(root, &self.hotel, now)?.remove(&self.id);
            if root[&self.hotel]
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
            {
                root.as_object_mut()
                    .expect("lease root was validated")
                    .remove(&self.hotel);
            }
            Ok(())
        })?;
        self.released = true;
        Ok(())
    }
}
impl Drop for RawIpLease {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct LeaseFile(PathBuf);
    impl LeaseFile {
        fn new() -> Self {
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let name = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            Self(std::env::temp_dir().join(format!("gearth-raw-leases-{name}.json")))
        }
    }
    impl Drop for LeaseFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(self.0.with_extension("mapping.lock"));
        }
    }
    fn hotel() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 50)
    }
    #[test]
    fn leases_coordinate_multiple_instances_and_expiry() {
        let file = LeaseFile::new();
        let (first, others) = RawIpLease::acquire(&file.0, hotel()).unwrap();
        assert!(!others);
        let (second, others) = RawIpLease::acquire(&file.0, hotel()).unwrap();
        assert!(others);
        assert!(first.others_active().unwrap());
        drop(second);
        assert!(!first.others_active().unwrap());
        drop(first);

        edit(&file.0, |root, _| {
            connections(root, &hotel().to_string(), 0)?
                .insert("expired".into(), json!({"timestamp": 1}));
            Ok(())
        })
        .unwrap();
        let (current, others) = RawIpLease::acquire(&file.0, hotel()).unwrap();
        assert!(!others);
        drop(current);
        assert_eq!(fs::read_to_string(&file.0).unwrap(), "{}");
    }
    #[test]
    fn malformed_lease_data_is_not_overwritten() {
        let file = LeaseFile::new();
        fs::write(&file.0, b"{\"hotel\":[]").unwrap();
        let original = fs::read(&file.0).unwrap();
        assert!(RawIpLease::acquire(&file.0, hotel()).is_err());
        assert_eq!(fs::read(&file.0).unwrap(), original);
    }

    #[test]
    fn mapping_changes_are_serialized() {
        let file = LeaseFile::new();
        let guard = RawIpLease::mapping_lock(&file.0).unwrap();
        let path = file.0.clone();
        let (send, receive) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let _guard = RawIpLease::mapping_lock(&path).unwrap();
            send.send(()).unwrap();
        });
        assert!(receive.recv_timeout(Duration::from_millis(100)).is_err());
        drop(guard);
        receive.recv_timeout(Duration::from_secs(5)).unwrap();
        worker.join().unwrap();
    }
}
