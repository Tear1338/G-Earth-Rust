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

#[cfg(target_os = "macos")]
mod sockets {
    use libproc::net_info::SocketFDInfo;
    use std::{
        io, mem,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    };

    const PROC_PIDFDSOCKETINFO: i32 = 3;
    const PROX_FDTYPE_SOCKET: u32 = 2;
    const SOCKINFO_TCP: i32 = 2;
    const TCP_ESTABLISHED: i32 = 4;
    const MAX_FDS: usize = 131_072;

    fn file_descriptors(pid: i32) -> io::Result<Vec<libc::proc_fdinfo>> {
        // SAFETY: A null buffer and zero size query the required allocation size.
        let size =
            unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        if size <= 0 {
            return Err(io::Error::last_os_error());
        }
        let mut capacity = (size as usize / mem::size_of::<libc::proc_fdinfo>())
            .saturating_add(32)
            .min(MAX_FDS);
        loop {
            let mut fds: Vec<_> = (0..capacity)
                .map(|_| libc::proc_fdinfo {
                    proc_fd: 0,
                    proc_fdtype: 0,
                })
                .collect();
            let bytes = capacity * mem::size_of::<libc::proc_fdinfo>();
            // SAFETY: The vector holds `bytes` initialized writable bytes for the call.
            let written = unsafe {
                libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDLISTFDS,
                    0,
                    fds.as_mut_ptr().cast(),
                    bytes as i32,
                )
            };
            if written <= 0 {
                return Err(io::Error::last_os_error());
            }
            if written as usize >= bytes {
                if capacity == MAX_FDS {
                    return Err(io::Error::other("macOS file descriptor list exceeds limit"));
                }
                capacity = capacity.saturating_mul(2).min(MAX_FDS);
                continue;
            }
            fds.truncate(written as usize / mem::size_of::<libc::proc_fdinfo>());
            return Ok(fds);
        }
    }

    fn endpoint(ip: IpAddr, port: u16) -> SocketAddr {
        SocketAddr::new(ip.to_canonical(), port)
    }

    fn socket_endpoints(info: &SocketFDInfo) -> Option<(SocketAddr, SocketAddr)> {
        if info.psi.soi_kind != SOCKINFO_TCP
            || info.psi.soi_type != libc::SOCK_STREAM
            || info.psi.soi_protocol != libc::IPPROTO_TCP
        {
            return None;
        }
        // SAFETY: soi_kind identifies the active TCP member of the union.
        let tcp = unsafe { info.psi.soi_proto.pri_tcp };
        if tcp.tcpsi_state != TCP_ESTABLISHED {
            return None;
        }
        let socket = tcp.tcpsi_ini;
        let local_port = u16::from_be(socket.insi_lport as u16);
        let remote_port = u16::from_be(socket.insi_fport as u16);
        let (local, remote) = match info.psi.soi_family {
            libc::AF_INET => {
                // SAFETY: AF_INET identifies the IPv4 members of both address unions.
                let (a, b) = unsafe {
                    (
                        socket.insi_laddr.ina_46.i46a_addr4.s_addr,
                        socket.insi_faddr.ina_46.i46a_addr4.s_addr,
                    )
                };
                (
                    IpAddr::V4(Ipv4Addr::from(a.to_ne_bytes())),
                    IpAddr::V4(Ipv4Addr::from(b.to_ne_bytes())),
                )
            }
            libc::AF_INET6 => {
                // SAFETY: AF_INET6 identifies the IPv6 members of both address unions.
                let (a, b) = unsafe {
                    (
                        socket.insi_laddr.ina_6.s6_addr,
                        socket.insi_faddr.ina_6.s6_addr,
                    )
                };
                (IpAddr::V6(Ipv6Addr::from(a)), IpAddr::V6(Ipv6Addr::from(b)))
            }
            _ => return None,
        };
        Some((endpoint(local, local_port), endpoint(remote, remote_port)))
    }

    fn inspect_pid(pid: u32, local: SocketAddr, remote: SocketAddr) -> io::Result<bool> {
        let pid = i32::try_from(pid)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid process ID"))?;
        for fd in file_descriptors(pid)? {
            if fd.proc_fdtype != PROX_FDTYPE_SOCKET {
                continue;
            }
            let mut info = SocketFDInfo::default();
            let size = mem::size_of::<SocketFDInfo>();
            // SAFETY: libproc writes into a properly aligned, initialized SocketFDInfo allocation.
            let written = unsafe {
                libc::proc_pidfdinfo(
                    pid,
                    fd.proc_fd,
                    PROC_PIDFDSOCKETINFO,
                    (&mut info as *mut SocketFDInfo).cast(),
                    size as i32,
                )
            };
            if written as usize != size {
                return Err(io::Error::other("cannot inspect macOS socket descriptor"));
            }
            if socket_endpoints(&info) == Some((local, remote)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn owner_from_pids(local: SocketAddr, remote: SocketAddr, pids: &[u32]) -> Option<u32> {
        if matches!(local, SocketAddr::V6(v) if v.scope_id() != 0)
            || matches!(remote, SocketAddr::V6(v) if v.scope_id() != 0)
        {
            return None;
        }
        let local = endpoint(local.ip(), local.port());
        let remote = endpoint(remote.ip(), remote.port());
        let mut owner = None;
        for &pid in pids {
            match inspect_pid(pid, local, remote) {
                Ok(true) if owner.is_some_and(|previous| previous != pid) => return None,
                Ok(true) => owner = Some(pid),
                Ok(false) => {}
                Err(_) => return None,
            }
        }
        owner
    }

    pub(crate) fn tcp_owner(local: SocketAddr, remote: SocketAddr) -> io::Result<Option<u32>> {
        let pids: Vec<_> = super::processes()?
            .into_iter()
            .map(|process| process.pid)
            .collect();
        Ok(owner_from_pids(local, remote, &pids))
    }

    #[cfg(test)]
    #[test]
    fn identifies_a_controlled_loopback_socket_owner() {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let local = client.local_addr().unwrap();
        let remote = client.peer_addr().unwrap();
        assert_eq!(
            owner_from_pids(local, remote, &[std::process::id()]),
            Some(std::process::id())
        );
        let wrong = SocketAddr::new(remote.ip(), remote.port().wrapping_add(1));
        assert_eq!(owner_from_pids(local, wrong, &[std::process::id()]), None);
        assert_eq!(
            owner_from_pids(local, remote, &[std::process::id(), u32::MAX]),
            None
        );
        eprintln!("macOS IPv4 loopback ownership verified");
    }

    #[cfg(test)]
    #[test]
    fn identifies_ipv6_loopback_when_available() {
        use std::net::{TcpListener, TcpStream};
        let Ok(listener) = TcpListener::bind("[::1]:0") else {
            eprintln!("IPv6 loopback unavailable; owner fixture skipped");
            return;
        };
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let local = client.local_addr().unwrap();
        let remote = client.peer_addr().unwrap();
        assert_eq!(
            owner_from_pids(local, remote, &[std::process::id()]),
            Some(std::process::id())
        );
        eprintln!("macOS IPv6 loopback ownership verified");
        let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            local.port(),
            0,
            1,
        ));
        assert_eq!(owner_from_pids(scoped, remote, &[std::process::id()]), None);
    }

    #[cfg(test)]
    #[test]
    fn identifies_ipv4_mapped_client_when_available() {
        use std::net::{SocketAddrV6, TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = SocketAddrV6::new(
            Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            listener.local_addr().unwrap().port(),
            0,
            0,
        );
        let Ok(client) = TcpStream::connect(address) else {
            eprintln!("macOS IPv4-mapped client unavailable; owner fixture skipped");
            return;
        };
        let (_server, _) = listener.accept().unwrap();
        assert_eq!(
            owner_from_pids(
                client.local_addr().unwrap(),
                client.peer_addr().unwrap(),
                &[std::process::id()]
            ),
            Some(std::process::id())
        );
        eprintln!("macOS IPv4-mapped client ownership verified");
    }
}

#[cfg(target_os = "macos")]
pub(super) use sockets::tcp_owner;

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
