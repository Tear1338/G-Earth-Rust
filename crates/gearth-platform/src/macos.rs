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
