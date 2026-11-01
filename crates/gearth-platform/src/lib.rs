//! Read-only native process access, isolated from the safe protocol core.
use std::{io, sync::atomic::AtomicBool};
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
}
pub fn tcp_owner(local:std::net::SocketAddr,remote:std::net::SocketAddr)->io::Result<Option<u32>> {
    #[cfg(windows)] {windows::tcp_owner(local,remote)}
    #[cfg(not(windows))] {let _=(local,remote);Ok(None)}
}
pub fn find_tables(bytes: &[u8], address: usize) -> Vec<[u8; 256]> {
    let mut result = Vec::new();
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
        // OS lookup tables can also be permutations (often a repeated identity table).
        // RC4 states are shuffled; reject strongly linear tables before the candidate cap.
        if valid {
            let mut deltas = [0u16; 256];
            for pair in state.windows(2) {
                deltas[pair[1].wrapping_sub(pair[0]) as usize] += 1;
            }
            if deltas.iter().any(|count| *count > 32) {
                valid = false;
            }
        }
        if valid && !result.contains(&state) {
            result.push(state);
            if result.len() == MAX_TABLES {
                break;
            }
        }
    }
    result
}
#[cfg(windows)]
mod windows;
pub fn habbo_processes() -> io::Result<Vec<ClientProcess>> {
    #[cfg(windows)]
    {
        windows::processes()
    }
    #[cfg(not(windows))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "automatic Flash memory discovery currently requires Windows",
        ))
    }
}
pub fn scan_habbo(pid: u32, cancel: &AtomicBool) -> io::Result<ScanResult> {
    #[cfg(windows)]
    {
        let known = habbo_processes()?;
        if !known.iter().any(|p| p.pid == pid) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "select a running Habbo or Flash player process",
            ));
        }
        windows::scan(pid, cancel, None)
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, cancel);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "automatic Flash memory discovery currently requires Windows",
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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
