//! Read-only native process access, isolated from the safe protocol core.
use std::{io, sync::atomic::AtomicBool};
mod file_dialog;
mod hotkeys;
mod ip_mapping;
#[cfg(any(target_os = "linux", test))]
mod linux;
#[cfg(any(target_os = "macos", test))]
mod macos;
mod macos_flash_prep;
mod macos_hosts;
mod port_checker;
mod process_tree;
mod tray;
#[cfg(any(target_os = "macos", target_os = "linux", test))]
mod unix_web_settings;
pub use file_dialog::{choose_file, open_folder, FileKind};
pub use hotkeys::GlobalHotkeys;
pub use ip_mapping::{system_ip_mapper, IpMapper};
pub use macos_flash_prep::{
    check_macos_flash_client, prepare_macos_flash_client, MacosFlashPrepStatus,
};
pub use macos_hosts::write_macos_hosts_privileged;
pub use port_checker::process_using_port;
pub use process_tree::ProcessTree;
pub use tray::{SystemTray, TrayEvent};
#[derive(Clone, Debug)]
pub struct ClientProcess {
    pub pid: u32,
    pub executable: String,
}
pub const MAX_TABLES: usize = 8192;
#[derive(Default)]
pub struct ScanResult {
    pub states: Vec<[u8; 256]>,
    pub bytes_read: usize,
    pub complete: bool,
    /// Address to resume an incomplete scan; None when the scan reached its end.
    pub next_address: Option<usize>,
}
/// Returns `true` when the current process has administrator/root privileges
/// (beta-29 `AdminValidator.isAdmin()` parity).
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        use std::mem::size_of;
        use windows_sys::Win32::{
            Foundation::{CloseHandle, HANDLE},
            Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        };
        let mut token: HANDLE = std::ptr::null_mut();
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened == 0 || token.is_null() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            )
        };
        unsafe {
            CloseHandle(token);
        }
        ok != 0 && elevation.TokenIsElevated != 0
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        true
    }
}

pub fn tcp_owner(
    local: std::net::SocketAddr,
    remote: std::net::SocketAddr,
) -> io::Result<Option<u32>> {
    #[cfg(windows)]
    {
        windows::tcp_owner(local, remote)
    }
    #[cfg(target_os = "linux")]
    {
        linux::tcp_owner(local, remote)
    }
    #[cfg(target_os = "macos")]
    {
        macos::tcp_owner(local, remote)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (local, remote);
        Ok(None)
    }
}
pub fn find_tables(bytes: &[u8], address: usize) -> Vec<[u8; 256]> {
    find_tables_with_offsets(bytes, address)
        .into_iter()
        .map(|(_, state)| state)
        .collect()
}
#[cfg_attr(not(windows), allow(dead_code))]
fn find_tables_with_offsets(bytes: &[u8], address: usize) -> Vec<(usize, [u8; 256])> {
    let mut result = Vec::new();
    let mut seen_states = std::collections::HashSet::new();
    let first = (4 - address % 4) % 4;
    for offset in (first..bytes.len().saturating_sub(1023)).step_by(4) {
        // Reject most windows before inspecting all 256 words.
        if bytes[offset + 1..offset + 4] != [0, 0, 0] || bytes[offset + 5..offset + 8] != [0, 0, 0]
        {
            continue;
        }
        let mut state = [0; 256];
        let mut seen = [false; 256];
        let mut valid = true;
        for (i, word) in bytes[offset..offset + 1024]
            .as_chunks::<4>()
            .0
            .iter()
            .enumerate()
        {
            let value = u32::from_le_bytes(*word);
            if value > 255 || seen[value as usize] {
                valid = false;
                break;
            }
            seen[value as usize] = true;
            state[i] = value as u8;
        }
        if valid && seen_states.insert(state) {
            result.push((offset, state));
            if result.len() == MAX_TABLES {
                break;
            }
        }
    }
    result
}
#[cfg(windows)]
mod web_settings;
#[cfg(windows)]
mod windows;
pub struct SystemProxyGuard {
    #[cfg(windows)]
    inner: web_settings::ProxyGuard,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    inner: unix_web_settings::ProxyGuard,
}
pub fn recover_system_proxy() -> io::Result<()> {
    #[cfg(windows)]
    {
        web_settings::ProxyGuard::recover()
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        unix_web_settings::ProxyGuard::recover()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "automatic system proxy restoration is unavailable on this platform",
        ))
    }
}
impl SystemProxyGuard {
    pub fn activate(address: std::net::SocketAddr) -> io::Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self {
                inner: web_settings::ProxyGuard::activate(address)?,
            })
        }
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            Ok(Self {
                inner: unix_web_settings::ProxyGuard::activate(address)?,
            })
        }
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            let _ = address;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "automatic system proxy configuration is unavailable on this platform",
            ))
        }
    }
    pub fn restore(&mut self) -> io::Result<()> {
        #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
        {
            self.inner.restore()
        }
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            Ok(())
        }
    }
}
pub fn certificate_trusted(der: &[u8]) -> io::Result<bool> {
    #[cfg(windows)]
    {
        web_settings::certificate_trusted(der)
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        unix_web_settings::certificate_trusted(der)
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = der;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "import the public proxy CA through the operating-system certificate manager",
        ))
    }
}
pub fn install_root_certificate(path: &std::path::Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        web_settings::install_certificate(path)
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        unix_web_settings::install_certificate(path)
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "automatic CA installation is unavailable on this platform",
        ))
    }
}
pub fn remove_root_certificate(der: &[u8]) -> io::Result<()> {
    #[cfg(windows)]
    {
        web_settings::remove_certificate(der)
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        unix_web_settings::remove_certificate(der)
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = der;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "automatic CA removal is unavailable on this platform",
        ))
    }
}
pub fn habbo_processes() -> io::Result<Vec<ClientProcess>> {
    #[cfg(windows)]
    {
        windows::processes()
    }
    #[cfg(target_os = "linux")]
    {
        linux::processes_from(std::path::Path::new("/proc"))
    }
    #[cfg(target_os = "macos")]
    {
        macos::processes()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "automatic client process discovery is unavailable on this platform",
        ))
    }
}
pub fn scan_habbo(pid: u32, cancel: &AtomicBool) -> io::Result<ScanResult> {
    scan_habbo_from(pid, 0, cancel)
}
/// Resume a bounded read-only scan at an address previously returned by the scanner.
pub fn scan_habbo_from(pid: u32, address: usize, cancel: &AtomicBool) -> io::Result<ScanResult> {
    scan_habbo_from_with_limit(pid, address, cancel, MAX_TABLES)
}
/// Resume a scan, limiting unique RC4 tables returned on this page.
pub fn scan_habbo_from_with_limit(
    pid: u32,
    address: usize,
    cancel: &AtomicBool,
    max_tables: usize,
) -> io::Result<ScanResult> {
    if !(1..=MAX_TABLES).contains(&max_tables) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Flash scan table limit",
        ));
    }
    #[cfg(windows)]
    {
        let known = habbo_processes()?;
        if !known.iter().any(|p| p.pid == pid) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "select a running Habbo or Flash player process",
            ));
        }
        windows::scan_limited(pid, cancel, Some((address, usize::MAX)), max_tables)
    }
    #[cfg(target_os = "linux")]
    {
        let root = std::path::Path::new("/proc");
        let known = linux::processes_from(root)?;
        if !known.iter().any(|process| process.pid == pid) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "select a running Habbo or Flash player process",
            ));
        }
        linux::scan_from(root, pid, address, cancel, max_tables)
    }
    #[cfg(target_os = "macos")]
    {
        let known = habbo_processes()?;
        if !known.iter().any(|process| process.pid == pid) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "select a running Habbo or Flash player process",
            ));
        }
        macos::scan_from(pid, address, cancel, max_tables)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = (pid, address, cancel, max_tables);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "automatic Flash memory scanning is unavailable on this platform",
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_scan_table_limits_before_process_lookup() {
        let cancel = AtomicBool::new(false);
        for limit in [0, MAX_TABLES + 1] {
            assert_eq!(
                scan_habbo_from_with_limit(0, 0, &cancel, limit)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
    #[test]
    fn retains_linear_permutations_once_in_discovery_order() {
        let identity: Vec<u8> = (0u32..256).flat_map(u32::to_le_bytes).collect();
        let reverse: Vec<u8> = (0u32..256).rev().flat_map(u32::to_le_bytes).collect();
        let mut memory = identity.clone();
        memory.extend_from_slice(&[255; 16]);
        memory.extend_from_slice(&reverse);
        memory.extend_from_slice(&[255; 16]);
        memory.extend_from_slice(&identity);
        let tables = find_tables(&memory, 0);
        assert_eq!(tables.len(), 2);
        assert_eq!(tables[0], std::array::from_fn(|i| i as u8));
        assert_eq!(tables[1], std::array::from_fn(|i| 255 - i as u8));
    }

    #[test]
    fn finds_aligned_word_permutations_and_rejects_duplicates() {
        let mut words: Vec<u32> = (0..256).collect();
        for i in 0..256 {
            let j = (i * 73 + words[i] as usize + 19) % 256;
            words.swap(i, j);
        }
        let mut bytes = vec![9; 12];
        for w in &words {
            bytes.extend(w.to_le_bytes());
        }
        let tables = find_tables(&bytes, 0);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0][0], words[0] as u8);
        bytes[16..20].copy_from_slice(&words[0].to_le_bytes());
        assert!(find_tables(&bytes, 0).is_empty());
    }
}
