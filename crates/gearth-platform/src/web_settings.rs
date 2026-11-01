//! Windows proxy ownership and public-CA store operations. Never invoked by core parsing.
use std::os::windows::process::CommandExt;
use std::{
    fs::{self, File, OpenOptions},
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS},
    Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    },
    System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_SZ,
    },
};
const SETTINGS: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
const BYPASS:&str="<local>;discord.com;*.discord.com;discordapp.com;*.discordapp.com;github.com;*.github.com;*.openai.com;*.chatgpt.com";
#[derive(Clone, PartialEq, Eq, Debug)]
struct Value {
    kind: u32,
    bytes: Vec<u8>,
}
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
fn text(value: &str) -> Value {
    Value {
        kind: REG_SZ,
        bytes: wide(value).iter().flat_map(|b| b.to_le_bytes()).collect(),
    }
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
impl Key {
    fn open(path: &str) -> io::Result<Self> {
        let path = wide(path);
        let mut key = std::ptr::null_mut();
        let code = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                &mut key,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(Self(key))
    }
    fn read(&self, name: &str) -> io::Result<Option<Value>> {
        let name = wide(name);
        let mut kind = 0;
        let mut size = 0;
        let code = unsafe {
            RegQueryValueExW(
                self.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if code == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if code != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        if size > 1024 * 1024 {
            return Err(io::Error::other("proxy registry value exceeds 1 MiB"));
        }
        let mut bytes = vec![0; size as usize];
        let code = unsafe {
            RegQueryValueExW(
                self.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                bytes.as_mut_ptr(),
                &mut size,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        bytes.truncate(size as usize);
        Ok(Some(Value { kind, bytes }))
    }
    fn write(&self, name: &str, value: Option<&Value>) -> io::Result<()> {
        let name = wide(name);
        let code = unsafe {
            match value {
                Some(value) => RegSetValueExW(
                    self.0,
                    name.as_ptr(),
                    0,
                    value.kind,
                    value.bytes.as_ptr(),
                    value.bytes.len() as u32,
                ),
                None => RegDeleteValueW(self.0, name.as_ptr()),
            }
        };
        if code != ERROR_SUCCESS && !(value.is_none() && code == ERROR_FILE_NOT_FOUND) {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(())
    }
}
fn notify() {
    unsafe {
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        );
        InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        );
    }
}
pub(crate) struct ProxyGuard {
    path: String,
    journal: PathBuf,
    lock: Option<File>,
    before: Vec<(&'static str, Option<Value>)>,
    after: Vec<(&'static str, Value)>,
    active: bool,
    refresh: bool,
}
impl ProxyGuard {
    pub(crate) fn recover() -> io::Result<()> {
        let directory = std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("APPDATA"))
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::other("Windows application-data directory unavailable"))?
            .join("G-Earth-Rust");
        fs::create_dir_all(&directory)?;
        let lock_path = directory.join("system-proxy.lock");
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)?;
        lock.try_lock().map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "close the G-Earth Rust instance that controls the proxy first",
            )
        })?;
        Self::recover_at(SETTINGS, &lock_path.with_extension("state"), true)
    }
    pub(crate) fn activate(address: SocketAddr) -> io::Result<Self> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(io::Error::other(
                "system proxy must point to a bound loopback listener",
            ));
        }
        let directory = std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("APPDATA"))
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::other("Windows application-data directory unavailable"))?
            .join("G-Earth-Rust");
        fs::create_dir_all(&directory)?;
        Self::activate_at(
            SETTINGS,
            &directory.join("system-proxy.lock"),
            &address.to_string(),
            true,
        )
    }
    fn activate_at(path: &str, lock_path: &Path, server: &str, refresh: bool) -> io::Result<Self> {
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(lock_path)?;
        lock.try_lock().map_err(|_| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "another G-Earth Rust instance controls the system proxy",
            )
        })?;
        let journal = lock_path.with_extension("state");
        Self::recover_at(path, &journal, refresh)?;
        let key = Key::open(path)?;
        let before = ["ProxyServer", "ProxyOverride", "ProxyEnable"]
            .into_iter()
            .map(|name| key.read(name).map(|value| (name, value)))
            .collect::<io::Result<Vec<_>>>()?;
        let after = vec![
            ("ProxyServer", text(server)),
            ("ProxyOverride", text(BYPASS)),
            (
                "ProxyEnable",
                Value {
                    kind: REG_DWORD,
                    bytes: 1u32.to_le_bytes().to_vec(),
                },
            ),
        ];
        write_journal(&journal, path, &before, &after)?;
        let guard = Self {
            path: path.into(),
            journal,
            lock: Some(lock),
            before,
            after,
            active: true,
            refresh,
        };
        for (name, value) in &guard.after {
            key.write(name, Some(value))?;
        }
        if refresh {
            notify();
        }
        Ok(guard)
    }
    fn recover_at(path: &str, journal: &Path, refresh: bool) -> io::Result<()> {
        let (before, after) = match read_journal(journal, path)? {
            Some(values) => values,
            None => return Ok(()),
        };
        let key = Key::open(path)?;
        if key.read("ProxyServer")? == Some(after[0].1.clone()) {
            for ((name, original), (_, owned)) in before.iter().zip(&after) {
                if key.read(name)? == Some(owned.clone()) {
                    key.write(name, original.as_ref())?;
                }
            }
            if refresh {
                notify();
            }
        }
        remove_journal(journal)
    }
    pub(crate) fn restore(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        let key = Key::open(&self.path)?;
        // Preserve a proxy that another application or the user installed afterwards.
        if key.read("ProxyServer")? == Some(self.after[0].1.clone()) {
            for ((name, before), (_, owned)) in self.before.iter().zip(&self.after) {
                if key.read(name)? == Some(owned.clone()) {
                    key.write(name, before.as_ref())?;
                }
            }
            if self.refresh {
                notify();
            }
        }
        remove_journal(&self.journal)?;
        self.active = false;
        self.lock.take();
        Ok(())
    }
}
impl Drop for ProxyGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
type Before = Vec<(&'static str, Option<Value>)>;
type After = Vec<(&'static str, Value)>;
const VALUE_NAMES: [&str; 3] = ["ProxyServer", "ProxyOverride", "ProxyEnable"];
fn remove_journal(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}
fn write_journal(journal: &Path, path: &str, before: &Before, after: &After) -> io::Result<()> {
    use io::Write;
    let mut bytes = b"GEARTH-PROXY-1\0".to_vec();
    let mut field = |value: &[u8]| {
        bytes.extend((value.len() as u32).to_le_bytes());
        bytes.extend(value);
    };
    field(path.as_bytes());
    for (_, value) in before {
        match value {
            Some(value) => {
                field(&value.kind.to_le_bytes());
                field(&value.bytes);
            }
            None => {
                field(&[]);
                field(&[]);
            }
        }
    }
    for (_, value) in after {
        field(&value.kind.to_le_bytes());
        field(&value.bytes);
    }
    let temporary = journal.with_extension("pending");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, journal)
}
fn read_journal(journal: &Path, path: &str) -> io::Result<Option<(Before, After)>> {
    use io::Read;
    let file = match File::open(journal) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::new();
    file.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    let mut tail = bytes
        .strip_prefix(b"GEARTH-PROXY-1\0")
        .filter(|_| bytes.len() <= 4 * 1024 * 1024)
        .ok_or_else(|| io::Error::other("invalid saved proxy state"))?;
    fn field<'a>(tail: &mut &'a [u8]) -> io::Result<&'a [u8]> {
        let count = tail
            .get(..4)
            .ok_or_else(|| io::Error::other("truncated saved proxy state"))?;
        let size = u32::from_le_bytes(count.try_into().unwrap()) as usize;
        *tail = &tail[4..];
        let (value, rest) = tail
            .split_at_checked(size)
            .ok_or_else(|| io::Error::other("truncated saved proxy value"))?;
        *tail = rest;
        Ok(value)
    }
    if field(&mut tail)? != path.as_bytes() {
        return Err(io::Error::other(
            "saved proxy state belongs to a different registry key",
        ));
    }
    fn value(tail: &mut &[u8]) -> io::Result<Option<Value>> {
        let kind = field(tail)?;
        let bytes = field(tail)?.to_vec();
        if kind.is_empty() && bytes.is_empty() {
            return Ok(None);
        }
        let kind = u32::from_le_bytes(kind.try_into().map_err(io::Error::other)?);
        Ok(Some(Value { kind, bytes }))
    }
    let mut before = Vec::new();
    for name in VALUE_NAMES {
        before.push((name, value(&mut tail)?));
    }
    let mut after = Vec::new();
    for name in VALUE_NAMES {
        after.push((
            name,
            value(&mut tail)?.ok_or_else(|| io::Error::other("invalid saved owned proxy value"))?,
        ));
    }
    if !tail.is_empty() {
        return Err(io::Error::other("unexpected saved proxy data"));
    }
    Ok(Some((before, after)))
}
fn certutil() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32/certutil.exe")
}
pub(crate) fn thumbprint(der: &[u8]) -> io::Result<String> {
    use sha1::{Digest, Sha1};
    if der.is_empty() || der.len() > 65536 {
        return Err(io::Error::other("invalid public certificate size"));
    }
    Ok(Sha1::digest(der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
fn command() -> Command {
    let mut command = Command::new(certutil());
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000);
    command
}
pub(crate) fn certificate_trusted(der: &[u8]) -> io::Result<bool> {
    let hash = thumbprint(der)?;
    if command()
        .args(["-user", "-verifystore", "Root", &hash])
        .status()?
        .success()
    {
        return Ok(true);
    }
    Ok(command()
        .args(["-verifystore", "Root", &hash])
        .status()?
        .success())
}
pub(crate) fn install_certificate(path: &Path) -> io::Result<()> {
    let path = path.canonicalize()?;
    if !path.is_file() || fs::metadata(&path)?.len() > 65536 {
        return Err(io::Error::other("invalid public certificate file"));
    }
    let status = command()
        .args(["-user", "-addstore", "Root"])
        .arg(path)
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "certificate installation failed with exit code {:?}",
            status.code()
        )));
    }
    Ok(())
}
pub(crate) fn remove_certificate(der: &[u8]) -> io::Result<()> {
    let status = command()
        .args(["-user", "-delstore", "Root", &thumbprint(der)?])
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "certificate removal failed with exit code {:?}",
            status.code()
        )));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Registry::{
        RegCreateKeyExW, RegDeleteTreeW, REG_OPTION_NON_VOLATILE,
    };
    struct Fixture {
        path: String,
        directory: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let id = format!(
                "{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let path = format!("Software\\G-Earth-Rust\\Tests\\{id}");
            let mut key = std::ptr::null_mut();
            let code = unsafe {
                RegCreateKeyExW(
                    HKEY_CURRENT_USER,
                    wide(&path).as_ptr(),
                    0,
                    std::ptr::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_QUERY_VALUE | KEY_SET_VALUE,
                    std::ptr::null(),
                    &mut key,
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(code, ERROR_SUCCESS);
            drop(Key(key));
            let directory = std::env::temp_dir().join(format!("gearth-proxy-test-{id}"));
            fs::create_dir(&directory).unwrap();
            Self { path, directory }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            assert!(self.path.starts_with("Software\\G-Earth-Rust\\Tests\\"));
            unsafe {
                RegDeleteTreeW(HKEY_CURRENT_USER, wide(&self.path).as_ptr());
            }
            let _ = fs::remove_file(self.directory.join("lock"));
            let _ = fs::remove_dir(&self.directory);
        }
    }
    #[test]
    fn restores_exact_proxy_values_and_absence_in_an_isolated_registry_key() {
        let fixture = Fixture::new();
        let key = Key::open(&fixture.path).unwrap();
        let original = text("previous.example:8123");
        key.write("ProxyServer", Some(&original)).unwrap();
        key.write(
            "ProxyEnable",
            Some(&Value {
                kind: REG_DWORD,
                bytes: 0u32.to_le_bytes().to_vec(),
            }),
        )
        .unwrap();
        let before = [
            key.read("ProxyServer").unwrap(),
            key.read("ProxyOverride").unwrap(),
            key.read("ProxyEnable").unwrap(),
        ];
        let mut guard = ProxyGuard::activate_at(
            &fixture.path,
            &fixture.directory.join("lock"),
            "127.0.0.1:9090",
            false,
        )
        .unwrap();
        assert_eq!(
            key.read("ProxyServer").unwrap(),
            Some(text("127.0.0.1:9090"))
        );
        guard.restore().unwrap();
        assert_eq!(
            before,
            [
                key.read("ProxyServer").unwrap(),
                key.read("ProxyOverride").unwrap(),
                key.read("ProxyEnable").unwrap()
            ]
        );
    }
    #[test]
    fn preserves_a_later_proxy_owner_and_rejects_a_second_guard() {
        let fixture = Fixture::new();
        let key = Key::open(&fixture.path).unwrap();
        let guard = ProxyGuard::activate_at(
            &fixture.path,
            &fixture.directory.join("lock"),
            "127.0.0.1:9090",
            false,
        )
        .unwrap();
        assert!(ProxyGuard::activate_at(
            &fixture.path,
            &fixture.directory.join("lock"),
            "127.0.0.1:9091",
            false
        )
        .is_err());
        key.write("ProxyServer", Some(&text("other.example:9999")))
            .unwrap();
        drop(guard);
        assert_eq!(
            key.read("ProxyServer").unwrap(),
            Some(text("other.example:9999"))
        );
    }
    #[test]
    fn recovers_an_abandoned_owner_before_starting_a_new_guard() {
        let fixture = Fixture::new();
        let key = Key::open(&fixture.path).unwrap();
        let original = text("before-crash.example:1234");
        key.write("ProxyServer", Some(&original)).unwrap();
        let mut guard = ProxyGuard::activate_at(
            &fixture.path,
            &fixture.directory.join("lock"),
            "127.0.0.1:9090",
            false,
        )
        .unwrap();
        guard.active = false;
        drop(guard);
        assert!(fixture
            .directory
            .join("lock")
            .with_extension("state")
            .is_file());
        let mut next = ProxyGuard::activate_at(
            &fixture.path,
            &fixture.directory.join("lock"),
            "127.0.0.1:9091",
            false,
        )
        .unwrap();
        next.restore().unwrap();
        assert_eq!(key.read("ProxyServer").unwrap(), Some(original));
        assert!(!fixture
            .directory
            .join("lock")
            .with_extension("state")
            .exists());
    }
    #[test]
    fn recovery_preserves_later_user_changes() {
        let fixture = Fixture::new();
        let key = Key::open(&fixture.path).unwrap();
        let mut guard = ProxyGuard::activate_at(
            &fixture.path,
            &fixture.directory.join("lock"),
            "127.0.0.1:9090",
            false,
        )
        .unwrap();
        guard.active = false;
        drop(guard);
        let changed = text("user.example:1234");
        key.write("ProxyServer", Some(&changed)).unwrap();
        ProxyGuard::recover_at(
            &fixture.path,
            &fixture.directory.join("lock").with_extension("state"),
            false,
        )
        .unwrap();
        assert_eq!(key.read("ProxyServer").unwrap(), Some(changed));
    }
}
