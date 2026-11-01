use super::*;
use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::{
            Debug::ReadProcessMemory,
            ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
        },
        Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE,
            PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS,
            PAGE_READWRITE, PAGE_WRITECOPY,
        },
        Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
    },
};
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
pub(super) fn processes() -> io::Result<Vec<ClientProcess>> {
    // SAFETY: Owned snapshot, initialized structure and checked API results; no borrowed native pointers escape.
    unsafe {
        let raw = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let snapshot = Handle(raw);
        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut result = Vec::new();
        let mut next = Process32FirstW(snapshot.0, &mut entry);
        while next != 0 {
            let n = entry
                .szExeFile
                .iter()
                .position(|v| *v == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..n]);
            let lower = name.to_ascii_lowercase();
            if lower == "habbo.exe" || lower.starts_with("flashplayer") && lower.ends_with(".exe") {
                result.push(ClientProcess {
                    pid: entry.th32ProcessID,
                    executable: name,
                });
            }
            next = Process32NextW(snapshot.0, &mut entry);
        }
        Ok(result)
    }
}
pub(super) fn scan(
    pid: u32,
    cancel: &AtomicBool,
    range: Option<(usize, usize)>,
) -> io::Result<ScanResult> {
    // SAFETY: Read-only process handle. Every read targets a live, sized Rust allocation;
    // remote addresses are passed to Windows and never dereferenced in Rust.
    unsafe {
        let raw = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let process = Handle(raw);
        let mut result = ScanResult::default();
        let mut address = range.map_or(0, |r| r.0);
        let end = range.map_or(usize::MAX, |r| r.1);
        let deadline = Instant::now() + Duration::from_secs(5);
        while address < end {
            if cancel.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "memory discovery cancelled",
                ));
            }
            if result.bytes_read >= 1024 * 1024 * 1024
                || Instant::now() > deadline
                || result.states.len() >= MAX_TABLES
            {
                return Ok(result);
            }
            let mut info: MEMORY_BASIC_INFORMATION = zeroed();
            if VirtualQueryEx(
                process.0,
                address as *const c_void,
                &mut info,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                result.complete = true;
                return Ok(result);
            }
            let base = info.BaseAddress as usize;
            let Some(next) = base.checked_add(info.RegionSize) else {
                break;
            };
            if next <= address {
                break;
            }
            let writable = info.Protect
                & (PAGE_READWRITE
                    | PAGE_WRITECOPY
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_EXECUTE_WRITECOPY)
                != 0;
            if info.State == MEM_COMMIT
                && info.Type == MEM_PRIVATE
                && writable
                && info.Protect & (PAGE_GUARD | PAGE_NOACCESS) == 0
            {
                let limit = next.min(end);
                let mut at = address.max(base);
                while at < limit {
                    if cancel.load(Ordering::Acquire) {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "memory discovery cancelled",
                        ));
                    }
                    if Instant::now() > deadline || result.bytes_read >= 1024 * 1024 * 1024 {
                        return Ok(result);
                    }
                    let size = (limit - at).min(65536 + 1020);
                    let mut bytes = vec![0u8; size];
                    let mut read = 0;
                    ReadProcessMemory(
                        process.0,
                        at as *const c_void,
                        bytes.as_mut_ptr().cast(),
                        size,
                        &mut read,
                    );
                    result.bytes_read += read;
                    bytes.truncate(read);
                    for state in find_tables(&bytes, at) {
                        if !result.states.contains(&state) {
                            result.states.push(state);
                            if result.states.len() == MAX_TABLES {
                                return Ok(result);
                            }
                        }
                    }
                    at = at.saturating_add(65536);
                }
            }
            address = next;
        }
        result.complete = true;
        Ok(result)
    }
}
pub(super) fn tcp_owner(local:std::net::SocketAddr,remote:std::net::SocketAddr)->io::Result<Option<u32>> {
    use windows_sys::Win32::{NetworkManagement::IpHelper::{GetExtendedTcpTable,MIB_TCPROW_OWNER_PID,MIB_TCPTABLE_OWNER_PID,TCP_TABLE_OWNER_PID_ALL},Networking::WinSock::AF_INET};
    if !local.is_ipv4()||!local.ip().is_loopback()||!remote.is_ipv4()||!remote.ip().is_loopback(){return Ok(None);}
    // SAFETY: Windows writes into an aligned, bounded allocation. Row counts and
    // offsets are checked against the returned buffer before unaligned copies.
    unsafe {
        let mut size=0u32;let status=GetExtendedTcpTable(std::ptr::null_mut(),&mut size,0,u32::from(AF_INET),TCP_TABLE_OWNER_PID_ALL,0);
        if status!=0&&status!=122{return Err(io::Error::from_raw_os_error(status as i32));}
        for _ in 0..3 {
            if !(4..=16*1024*1024).contains(&size){return Err(io::Error::other("invalid TCP owner table size"));}
            let mut buffer=vec![0u64;(size as usize).div_ceil(size_of::<u64>())];let capacity=buffer.len()*size_of::<u64>();
            let status=GetExtendedTcpTable(buffer.as_mut_ptr().cast(),&mut size,0,u32::from(AF_INET),TCP_TABLE_OWNER_PID_ALL,0);
            if status==122{continue;}if status!=0{return Err(io::Error::from_raw_os_error(status as i32));}
            if size as usize>capacity{return Err(io::Error::other("TCP owner table exceeds allocation"));}
            let base=buffer.as_ptr().cast::<u8>();let count=base.cast::<u32>().read_unaligned() as usize;let offset=std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID,table);
            let bytes=count.checked_mul(size_of::<MIB_TCPROW_OWNER_PID>()).and_then(|n|n.checked_add(offset)).ok_or_else(||io::Error::other("TCP owner table length overflow"))?;
            if bytes>size as usize{return Err(io::Error::other("truncated TCP owner table"));}
            for i in 0..count {let row=base.add(offset+i*size_of::<MIB_TCPROW_OWNER_PID>()).cast::<MIB_TCPROW_OWNER_PID>().read_unaligned();
                if std::net::IpAddr::V4(std::net::Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()))==local.ip()&&u16::from_be(row.dwLocalPort as u16)==local.port()&&std::net::IpAddr::V4(std::net::Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()))==remote.ip()&&u16::from_be(row.dwRemotePort as u16)==remote.port(){return Ok(Some(row.dwOwningPid));}
            }return Ok(None);
        }Err(io::Error::other("TCP owner table kept changing"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads_only_requested_memory_in_a_controlled_process() {
        let mut words: Vec<u32> = (0..256).collect();
        for i in 0..256 {
            let j = (i * 73 + words[i] as usize + 19) % 256;
            words.swap(i, j);
        }
        let start = words.as_ptr() as usize;
        let result = scan(
            std::process::id(),
            &AtomicBool::new(false),
            Some((start, start + 1024)),
        )
        .unwrap();
        assert!(result.complete);
        assert_eq!(result.bytes_read, 1024);
        assert!(result
            .states
            .iter()
            .any(|s| s[0] == words[0] as u8 && s[1] == words[1] as u8));
        std::hint::black_box(words);
    }
    #[test]
    fn cancellation_is_checked_before_memory_is_read() {
        assert_eq!(
            scan(std::process::id(), &AtomicBool::new(true), None)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::Interrupted
        );
    }
}
