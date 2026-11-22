//! Read-only macOS client process enumeration.

fn client_name(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    match name.to_ascii_lowercase().as_str() {
        "habbo" | "flash player" | "adobe flash player" | "flashplayer" | "plugin-container" => {
            Some(name)
        }
        _ => None,
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::client_name;
    use crate::ClientProcess;
    use std::{ffi::CStr, io, mem, ptr};

    // PROC_ALL_PIDS from macOS <sys/proc_info.h>.
    const PROC_ALL_PIDS: u32 = 1;
    const MAX_PIDS: usize = 1_000_000;

    fn pids() -> io::Result<Vec<libc::pid_t>> {
        // SAFETY: A null buffer with size zero asks libproc for the required size.
        let size = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, ptr::null_mut(), 0) };
        if size <= 0 {
            return Err(io::Error::last_os_error());
        }
        let mut capacity = (size as usize / mem::size_of::<libc::pid_t>())
            .saturating_add(256)
            .min(MAX_PIDS);
        loop {
            let mut pids = vec![0 as libc::pid_t; capacity];
            let bytes = capacity * mem::size_of::<libc::pid_t>();
            // SAFETY: The vector owns `bytes` writable bytes for the duration of the call.
            let written = unsafe {
                libc::proc_listpids(PROC_ALL_PIDS, 0, pids.as_mut_ptr().cast(), bytes as i32)
            };
            if written <= 0 {
                return Err(io::Error::last_os_error());
            }
            if written as usize >= bytes {
                if capacity == MAX_PIDS {
                    return Err(io::Error::other("macOS process list exceeds limit"));
                }
                capacity = capacity.saturating_mul(2).min(MAX_PIDS);
                continue;
            }
            pids.truncate(written as usize / mem::size_of::<libc::pid_t>());
            pids.retain(|pid| *pid > 0);
            return Ok(pids);
        }
    }

    fn executable_path(pid: libc::pid_t) -> Option<String> {
        let mut buffer = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: libproc writes at most the supplied buffer length; the buffer is initialized.
        let size =
            unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
        if size <= 0 {
            return None;
        }
        let bytes = CStr::from_bytes_until_nul(&buffer).ok()?.to_bytes();
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    pub(crate) fn processes() -> io::Result<Vec<ClientProcess>> {
        let mut result = Vec::new();
        for pid in pids()? {
            let Some(path) = executable_path(pid) else {
                continue;
            };
            if let Some(name) = client_name(&path) {
                result.push(ClientProcess {
                    pid: pid as u32,
                    executable: name.to_owned(),
                });
            }
        }
        result.sort_unstable_by_key(|process| process.pid);
        result.dedup_by_key(|process| process.pid);
        Ok(result)
    }

    #[cfg(test)]
    #[test]
    fn libproc_can_enumerate_and_resolve_own_process() {
        let pid = std::process::id() as libc::pid_t;
        assert!(pids().unwrap().contains(&pid));
        assert!(executable_path(pid).is_some());
    }
}

#[cfg(target_os = "macos")]
pub(super) use native::processes;

#[cfg(target_os = "macos")]
mod memory {
    use crate::{find_tables_with_offsets, ScanResult};
    use mach2::{
        kern_return::{KERN_INVALID_ADDRESS, KERN_SUCCESS},
        mach_port::mach_port_deallocate,
        port::{mach_port_t, MACH_PORT_NULL},
        traps::{mach_task_self, task_for_pid},
        vm::{mach_vm_read_overwrite, mach_vm_region},
        vm_prot::{VM_PROT_READ, VM_PROT_WRITE},
        vm_region::{vm_region_basic_info_64, vm_region_info_t, VM_REGION_BASIC_INFO_64},
    };
    use std::{
        collections::HashSet,
        io,
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };

    struct TaskPort {
        raw: mach_port_t,
        owned: bool,
    }

    impl TaskPort {
        fn open(pid: u32) -> io::Result<Self> {
            // SAFETY: mach_task_self returns the current process's task port.
            let current = unsafe { mach_task_self() };
            if pid == std::process::id() {
                return Ok(Self {
                    raw: current,
                    owned: false,
                });
            }
            let pid = i32::try_from(pid)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid process ID"))?;
            let mut raw = MACH_PORT_NULL;
            // SAFETY: `raw` is a valid output pointer; the returned right is released in Drop.
            let status = unsafe { task_for_pid(current, pid, &mut raw) };
            if status != KERN_SUCCESS || raw == MACH_PORT_NULL {
                if raw != MACH_PORT_NULL {
                    // SAFETY: Release any right returned along with an unsuccessful status.
                    unsafe { mach_port_deallocate(current, raw) };
                }
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("macOS denied read access to process {pid} (Mach status {status})"),
                ));
            }
            Ok(Self { raw, owned: true })
        }
    }

    impl Drop for TaskPort {
        fn drop(&mut self) {
            if self.owned {
                // SAFETY: This task port right was returned by task_for_pid and is owned here.
                unsafe {
                    mach_port_deallocate(mach_task_self(), self.raw);
                }
            }
        }
    }

    fn next_region(task: mach_port_t, address: usize) -> io::Result<Option<(usize, usize, bool)>> {
        let mut base = address as u64;
        let mut size = 0u64;
        let mut info = vm_region_basic_info_64::default();
        let mut count = vm_region_basic_info_64::count();
        let mut object = MACH_PORT_NULL;
        // SAFETY: All output pointers refer to initialized local variables of the required types.
        let status = unsafe {
            mach_vm_region(
                task,
                &mut base,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                (&mut info as *mut vm_region_basic_info_64).cast::<i32>() as vm_region_info_t,
                &mut count,
                &mut object,
            )
        };
        if object != MACH_PORT_NULL {
            // SAFETY: mach_vm_region returned an owned object-name port right.
            unsafe {
                mach_port_deallocate(mach_task_self(), object);
            }
        }
        if status == KERN_INVALID_ADDRESS {
            return Ok(None);
        }
        if status != KERN_SUCCESS {
            return Err(io::Error::other(format!(
                "macOS memory-region query failed (Mach status {status})"
            )));
        }
        let start =
            usize::try_from(base).map_err(|_| io::Error::other("memory address overflow"))?;
        let length =
            usize::try_from(size).map_err(|_| io::Error::other("memory region overflow"))?;
        let end = start
            .checked_add(length)
            .filter(|end| *end > address)
            .ok_or_else(|| io::Error::other("macOS memory-region query did not advance"))?;
        let protection = info.protection;
        Ok(Some((
            start,
            end,
            protection & (VM_PROT_READ | VM_PROT_WRITE) == (VM_PROT_READ | VM_PROT_WRITE),
        )))
    }

    fn scan_with_limits(
        pid: u32,
        start: usize,
        end: usize,
        cancel: &AtomicBool,
        max_tables: usize,
        max_bytes: usize,
        max_time: Duration,
    ) -> io::Result<ScanResult> {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "memory discovery cancelled",
            ));
        }
        let task = TaskPort::open(pid)?;
        let deadline = Instant::now() + max_time;
        let mut result = ScanResult::default();
        let mut seen = HashSet::new();
        let mut address = start;
        while address < end {
            if cancel.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "memory discovery cancelled",
                ));
            }
            if result.bytes_read >= max_bytes || Instant::now() > deadline {
                result.next_address = Some(address);
                return Ok(result);
            }
            let Some((base, next, readable_writable)) = next_region(task.raw, address)? else {
                result.complete = true;
                return Ok(result);
            };
            if readable_writable {
                let limit = next.min(end);
                let mut at = address.max(base);
                while at < limit {
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
                    let size = (limit - at).min(65536 + 1020);
                    let mut bytes = vec![0u8; size];
                    let mut read = 0u64;
                    // SAFETY: Remote addresses are never dereferenced in Rust; output points to `size` allocated bytes.
                    let status = unsafe {
                        mach_vm_read_overwrite(
                            task.raw,
                            at as u64,
                            size as u64,
                            bytes.as_mut_ptr() as u64,
                            &mut read,
                        )
                    };
                    let read = if status == KERN_SUCCESS {
                        (read as usize).min(size)
                    } else {
                        0
                    };
                    result.bytes_read += read;
                    bytes.truncate(read);
                    for (offset, state) in find_tables_with_offsets(&bytes, at) {
                        if seen.insert(state) {
                            result.states.push(state);
                            if result.states.len() == max_tables {
                                result.next_address =
                                    at.checked_add(offset).and_then(|v| v.checked_add(4));
                                return Ok(result);
                            }
                        }
                    }
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
            address = next;
        }
        result.complete = true;
        Ok(result)
    }

    pub(crate) fn scan_from(
        pid: u32,
        address: usize,
        cancel: &AtomicBool,
        max_tables: usize,
    ) -> io::Result<ScanResult> {
        scan_with_limits(
            pid,
            address,
            usize::MAX,
            cancel,
            max_tables,
            1024 * 1024 * 1024,
            Duration::from_secs(5),
        )
    }

    #[cfg(test)]
    #[test]
    fn reads_a_controlled_self_process_rc4_table() {
        let table: Vec<u32> = (0..=255).collect();
        let start = table.as_ptr() as usize;
        let end = start + table.len() * std::mem::size_of::<u32>();
        let cancel = AtomicBool::new(false);
        let result = scan_with_limits(
            std::process::id(),
            start,
            end,
            &cancel,
            1,
            65536,
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(result.states.len(), 1);
        assert_eq!(result.states[0], std::array::from_fn(|index| index as u8));
        assert_eq!(result.next_address, Some(start + 4));
        std::hint::black_box(table);
        cancel.store(true, Ordering::Release);
        assert_eq!(
            scan_with_limits(
                std::process::id(),
                start,
                end,
                &cancel,
                1,
                65536,
                Duration::from_secs(5)
            )
            .err()
            .unwrap()
            .kind(),
            io::ErrorKind::Interrupted
        );
    }

    #[cfg(test)]
    #[test]
    fn resumes_a_controlled_self_process_scan_after_the_byte_budget() {
        let mut words = vec![0xfeed_u32; 18_000];
        let table_index = (65536 + 1024) / std::mem::size_of::<u32>();
        for index in 0..256 {
            words[table_index + index] = index as u32;
        }
        let start = words.as_ptr() as usize;
        let end = start + words.len() * std::mem::size_of::<u32>();
        let cancel = AtomicBool::new(false);
        let first = scan_with_limits(
            std::process::id(),
            start,
            end,
            &cancel,
            1,
            65536,
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(first.states.is_empty());
        assert_eq!(first.next_address, Some(start + 65536));
        let second = scan_with_limits(
            std::process::id(),
            first.next_address.unwrap(),
            end,
            &cancel,
            1,
            65536,
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(second.states.len(), 1);
        assert_eq!(second.states[0], std::array::from_fn(|index| index as u8));
        std::hint::black_box(words);
    }
}

#[cfg(target_os = "macos")]
pub(super) use memory::scan_from;

#[cfg(test)]
#[test]
fn macos_client_names_use_executable_basename() {
    assert_eq!(
        client_name("/Applications/Habbo.app/Contents/MacOS/Habbo"),
        Some("Habbo")
    );
    assert_eq!(
        client_name("/Applications/Flash Player.app/Contents/MacOS/Flash Player"),
        Some("Flash Player")
    );
    assert_eq!(client_name("/tmp/not-habbo"), None);
    assert_eq!(client_name("/tmp/Habbo Helper"), None);
}
