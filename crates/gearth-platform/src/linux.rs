//! Read-only Linux process discovery, modeled on beta-29's /proc client lookup.
use crate::ClientProcess;
use std::{fs, io, path::Path};

fn matches_client(command: &[u8]) -> bool {
    let text = String::from_utf8_lossy(command).to_ascii_lowercase();
    ["--ppapi-flash-args", "plugin-container", "habbo"]
        .iter()
        .any(|name| text.contains(name))
}

pub(super) fn processes_from(root: &Path) -> io::Result<Vec<ClientProcess>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(command) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        if !matches_client(&command) {
            continue;
        }
        let executable = command.split(|b| *b == 0).next().unwrap_or_default();
        let path = String::from_utf8_lossy(executable);
        let executable = path.rsplit('/').next().unwrap_or(&path).to_owned();
        result.push(ClientProcess { pid, executable });
    }
    result.sort_unstable_by_key(|process| process.pid);
    Ok(result)
}

#[cfg(target_os = "linux")]
use std::net::SocketAddr;
use std::net::{Ipv4Addr, SocketAddrV4};

fn parse_proc_v4(value: &str) -> Option<SocketAddrV4> {
    let (address, port) = value.split_once(':')?;
    if address.len() != 8 || port.len() != 4 {
        return None;
    }
    let address = u32::from_str_radix(address, 16).ok()?;
    let port = u16::from_str_radix(port, 16).ok()?;
    Some(SocketAddrV4::new(
        Ipv4Addr::from(address.to_ne_bytes()),
        port,
    ))
}
fn matching_socket_inodes(table: &str, local: SocketAddrV4, remote: SocketAddrV4) -> Vec<u64> {
    table
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() <= 9
                || parse_proc_v4(fields[1])? != local
                || parse_proc_v4(fields[2])? != remote
            {
                return None;
            }
            let inode = fields[9].parse::<u64>().ok()?;
            (inode != 0).then_some(inode)
        })
        .collect()
}
#[cfg(target_os = "linux")]
fn socket_link_inode(path: &Path) -> io::Result<Option<u64>> {
    let target = fs::read_link(path)?;
    Ok(target
        .to_str()
        .and_then(|text| text.strip_prefix("socket:["))
        .and_then(|text| text.strip_suffix(']'))
        .and_then(|text| text.parse().ok()))
}
#[cfg(target_os = "linux")]
fn tcp_owner_from(
    root: &Path,
    local: SocketAddr,
    remote: SocketAddr,
    candidates: &[u32],
) -> io::Result<Option<u32>> {
    let (SocketAddr::V4(local), SocketAddr::V4(remote)) = (local, remote) else {
        return Ok(None);
    };
    let table = fs::read_to_string(root.join("net/tcp"))?;
    let inodes = matching_socket_inodes(&table, local, remote);
    if inodes.is_empty() {
        return Ok(None);
    }
    let mut owner = None;
    let mut inaccessible = false;
    for pid in candidates {
        let entries = match fs::read_dir(root.join(pid.to_string()).join("fd")) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                inaccessible = true;
                continue;
            }
            Err(_) => continue,
        };
        let mut matches = false;
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    inaccessible = true;
                    continue;
                }
                Err(_) => continue,
            };
            match socket_link_inode(&entry.path()) {
                Ok(Some(inode)) if inodes.contains(&inode) => {
                    matches = true;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    inaccessible = true
                }
                _ => {}
            }
        }
        if matches {
            if owner.is_some_and(|previous| previous != *pid) {
                return Ok(None);
            }
            owner = Some(*pid);
        }
    }
    if inaccessible {
        Ok(None)
    } else {
        Ok(owner)
    }
}
#[cfg(target_os = "linux")]
pub(super) fn tcp_owner(local: SocketAddr, remote: SocketAddr) -> io::Result<Option<u32>> {
    let root = Path::new("/proc");
    let candidates: Vec<_> = processes_from(root)?
        .into_iter()
        .map(|process| process.pid)
        .collect();
    tcp_owner_from(root, local, remote, &candidates)
}

use crate::{find_tables_with_offsets, ScanResult};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

fn memory_ranges(maps: &str) -> Vec<(usize, usize)> {
    maps.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let address = parts.next()?;
            let permissions = parts.next()?;
            let offset = parts.next()?;
            let device = parts.next()?;
            let inode = parts.next()?;
            let name = parts.next();
            if permissions != "rw-p"
                || offset != "00000000"
                || device != "00:00"
                || inode != "0"
                || name.is_some_and(|name| name != "[heap]" && !name.starts_with("[anon:"))
            {
                return None;
            }
            let (start, end) = address.split_once('-')?;
            let start = usize::from_str_radix(start, 16).ok()?;
            let end = usize::from_str_radix(end, 16).ok()?;
            (start < end).then_some((start, end))
        })
        .collect()
}

fn scan_memory(
    file: &mut File,
    ranges: &[(usize, usize)],
    address: usize,
    cancel: &AtomicBool,
    max_tables: usize,
    max_bytes: usize,
    deadline: Instant,
) -> io::Result<ScanResult> {
    if cancel.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "memory discovery cancelled",
        ));
    }
    let mut result = ScanResult::default();
    for &(start, end) in ranges {
        if end <= address {
            continue;
        }
        let mut at = start.max(address);
        while at < end {
            if cancel.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "memory discovery cancelled",
                ));
            }
            if result.bytes_read >= max_bytes || Instant::now() > deadline {
                result.next_address = Some(at);
                return Ok(result);
            }
            let size = (end - at).min(65536 + 1020);
            let mut bytes = vec![0u8; size];
            let read = match file
                .seek(SeekFrom::Start(at as u64))
                .and_then(|_| file.read(&mut bytes))
            {
                Ok(read) => read,
                // Mappings can disappear after /proc/<pid>/maps was read.
                Err(error) if error.raw_os_error() == Some(5) => {
                    at = at.saturating_add(65536);
                    continue;
                }
                Err(error) => return Err(error),
            };
            result.bytes_read += read;
            bytes.truncate(read);
            for (offset, state) in find_tables_with_offsets(&bytes, at) {
                if !result.states.contains(&state) {
                    result.states.push(state);
                    if result.states.len() == max_tables {
                        result.next_address = at
                            .checked_add(offset)
                            .and_then(|value| value.checked_add(4));
                        return Ok(result);
                    }
                }
            }
            // Preserve overlap after a short read as well as after a full chunk.
            let advance = if read >= 1024 {
                (read - 1020).min(65536)
            } else if read > 0 {
                read
            } else {
                65536
            };
            at = at.saturating_add(advance);
        }
    }
    result.complete = true;
    Ok(result)
}

#[cfg(target_os = "linux")]
pub(super) fn scan_from(
    root: &Path,
    pid: u32,
    address: usize,
    cancel: &AtomicBool,
    max_tables: usize,
) -> io::Result<ScanResult> {
    if cancel.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "memory discovery cancelled",
        ));
    }
    let directory = root.join(pid.to_string());
    let maps = fs::read_to_string(directory.join("maps"))?;
    let mut file = File::open(directory.join("mem"))?;
    scan_memory(
        &mut file,
        &memory_ranges(&maps),
        address,
        cancel,
        max_tables,
        1024 * 1024 * 1024,
        Instant::now() + Duration::from_secs(5),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn socket_table_matches_endpoints_and_ignores_invalid_rows() {
        let local = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 3000);
        let remote = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 4000);
        let a = u32::from_ne_bytes(local.ip().octets());
        let table = format!("header\n0: {a:08X}:0BB8 {a:08X}:0FA0 01 0:0 0:0 0 1000 0 12345\n1: {a:08X}:0BB8 {a:08X}:0FA0 01 0:0 0:0 0 1000 0 0\nmalformed\n");
        assert_eq!(matching_socket_inodes(&table, local, remote), [12345]);
        assert!(matching_socket_inodes(&table, remote, local).is_empty());
        assert!(parse_proc_v4("bad:0001").is_none());
        assert!(parse_proc_v4("0100007F:10000").is_none());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn refuses_a_socket_shared_by_multiple_candidate_processes() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!(
            "gearth-sockets-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("net")).unwrap();
        for pid in [7, 12] {
            fs::create_dir(root.join(pid.to_string())).unwrap();
            fs::create_dir(root.join(pid.to_string()).join("fd")).unwrap();
        }
        let local = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3000);
        let remote = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4000);
        let address = u32::from_ne_bytes(local.ip().octets());
        fs::write(
            root.join("net/tcp"),
            format!("0: {address:08X}:0BB8 {address:08X}:0FA0 01 0:0 0:0 0 1000 0 12345\n"),
        )
        .unwrap();
        for pid in [7, 12] {
            symlink("socket:[12345]", root.join(pid.to_string()).join("fd/3")).unwrap();
        }
        assert_eq!(
            tcp_owner_from(&root, local.into(), remote.into(), &[7, 12]).unwrap(),
            None
        );
        fs::remove_file(root.join("12/fd/3")).unwrap();
        assert_eq!(
            tcp_owner_from(&root, local.into(), remote.into(), &[7, 12]).unwrap(),
            Some(7)
        );
        fs::remove_file(root.join("7/fd/3")).unwrap();
        fs::remove_file(root.join("net/tcp")).unwrap();
        for pid in [7, 12] {
            fs::remove_dir(root.join(pid.to_string()).join("fd")).unwrap();
            fs::remove_dir(root.join(pid.to_string())).unwrap();
        }
        fs::remove_dir(root.join("net")).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn identifies_a_controlled_live_socket_owner() {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let owner = tcp_owner_from(
            Path::new("/proc"),
            client.local_addr().unwrap(),
            client.peer_addr().unwrap(),
            &[std::process::id()],
        )
        .unwrap();
        assert_eq!(owner, Some(std::process::id()));
    }

    #[test]
    fn parses_private_anonymous_maps_and_rejects_invalid_ranges() {
        let maps = "1000-2000 rw-p 00000000 00:00 0\n2000-3000 rw-p 00000000 00:00 0 [heap]\n3000-4000 r--p 00000000 00:00 0\n4000-5000 rw-s 00000000 00:00 0\n5000-6000 rw-p 00000000 08:01 3 /mapped\n7000-6000 rw-p 00000000 00:00 0\ninvalid\n";
        assert_eq!(memory_ranges(maps), [(0x1000, 0x2000), (0x2000, 0x3000)]);
    }
    #[test]
    fn memory_scan_resumes_and_honors_cancellation() {
        let path = std::env::temp_dir().join(format!(
            "gearth-proc-memory-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut bytes = vec![0u8; 200_000];
        let make_table = |seed: usize| {
            let mut values: Vec<u32> = (0..256).collect();
            for i in 0..256 {
                let j = (i * 73 + values[i] as usize + seed) % 256;
                values.swap(i, j);
            }
            values
        };
        let first = make_table(19);
        let second = make_table(37);
        for (position, table) in [(65024, &first), (150000, &second)] {
            for (i, value) in table.iter().enumerate() {
                bytes[position + i * 4..position + i * 4 + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        fs::write(&path, &bytes).unwrap();
        let mut file = File::open(&path).unwrap();
        let cancel = AtomicBool::new(false);
        let range = [(0, bytes.len())];
        let deadline = Instant::now() + Duration::from_secs(5);
        let limited = scan_memory(
            &mut file,
            &range,
            0,
            &cancel,
            crate::MAX_TABLES,
            1,
            deadline,
        )
        .unwrap();
        assert_eq!(limited.next_address, Some(65536));
        assert!(limited
            .states
            .iter()
            .any(|state| state.iter().copied().eq(first.iter().map(|v| *v as u8))));
        let page = scan_memory(&mut file, &range, 0, &cancel, 1, usize::MAX, deadline).unwrap();
        assert_eq!(page.states.len(), 1);
        assert_eq!(
            page.states[0].as_slice(),
            first.iter().map(|v| *v as u8).collect::<Vec<_>>()
        );
        let next = page.next_address.unwrap();
        assert!(next > 0 && next < 65536);
        let page = scan_memory(&mut file, &range, next, &cancel, 1, usize::MAX, deadline).unwrap();
        assert_eq!(page.states.len(), 1);
        assert_eq!(
            page.states[0].as_slice(),
            second.iter().map(|v| *v as u8).collect::<Vec<_>>()
        );
        cancel.store(true, Ordering::Release);
        assert_eq!(
            scan_memory(&mut file, &[], 0, &cancel, 1, 1, deadline)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::Interrupted
        );
        drop(file);
        fs::remove_file(path).unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn scans_a_controlled_live_process_memory_region() {
        let mut values: Vec<u32> = (0..256).collect();
        for i in 0..256 {
            let j = (i * 73 + values[i] as usize + 19) % 256;
            values.swap(i, j);
        }
        let start = values.as_ptr() as usize;
        let end = start + values.len() * 4;
        let mut memory = File::open("/proc/self/mem").unwrap();
        let result = scan_memory(
            &mut memory,
            &[(start, end)],
            start,
            &AtomicBool::new(false),
            1,
            usize::MAX,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert!(result
            .states
            .iter()
            .any(|state| state.iter().copied().eq(values.iter().map(|v| *v as u8))));
        std::hint::black_box(values);
    }

    #[test]
    fn client_command_matching_handles_nul_arguments_and_ignores_other_processes() {
        assert!(matches_client(b"/opt/Habbo\0--hotel=com\0"));
        assert!(matches_client(b"/usr/bin/chromium\0--ppapi-flash-args\0"));
        assert!(matches_client(b"/usr/bin/plugin-container\0"));
        assert!(!matches_client(b"/usr/bin/firefox\0--profile\0default\0"));
        assert!(!matches_client(b""));
    }
    #[test]
    fn process_enumeration_skips_disappeared_and_unrelated_entries() {
        let root = std::env::temp_dir().join(format!(
            "gearth-proc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        for name in ["12", "7", "33", "not-a-pid"] {
            fs::create_dir(root.join(name)).unwrap();
        }
        fs::write(root.join("12/cmdline"), b"/opt/Habbo\0--hotel=com\0").unwrap();
        fs::write(root.join("7/cmdline"), b"/usr/bin/plugin-container\0").unwrap();
        fs::write(root.join("not-a-pid/cmdline"), b"Habbo\0").unwrap();
        let processes = processes_from(&root).unwrap();
        assert_eq!(processes.iter().map(|p| p.pid).collect::<Vec<_>>(), [7, 12]);
        assert_eq!(processes[1].executable, "Habbo");
        for name in ["12", "7", "not-a-pid"] {
            fs::remove_file(root.join(name).join("cmdline")).unwrap();
        }
        for name in ["12", "7", "33", "not-a-pid"] {
            fs::remove_dir(root.join(name)).unwrap();
        }
        fs::remove_dir(root).unwrap();
    }
}
