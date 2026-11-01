//! Read-only native process access, isolated from the safe protocol core.
use std::{io,sync::atomic::AtomicBool};
#[derive(Clone,Debug)]
pub struct ClientProcess {pub pid:u32,pub executable:String}
#[derive(Default)]
pub struct ScanResult {pub states:Vec<[u8;256]>,pub bytes_read:usize,pub complete:bool}
pub fn find_tables(bytes:&[u8],address:usize)->Vec<[u8;256]> {
    let mut result=Vec::new();let first=(4-address%4)%4;
    for offset in (first..bytes.len().saturating_sub(1023)).step_by(4) {
        // Reject most windows before inspecting all 256 words.
        if bytes[offset+1..offset+4]!=[0,0,0]||bytes[offset+5..offset+8]!=[0,0,0]{continue;}
        let mut state=[0;256];let mut seen=[false;256];let mut valid=true;
        for (i,word) in bytes[offset..offset+1024].as_chunks::<4>().0.iter().enumerate(){let value=u32::from_le_bytes(*word);if value>255||seen[value as usize]{valid=false;break;}seen[value as usize]=true;state[i]=value as u8;}
        if valid&&!result.contains(&state){result.push(state);if result.len()==64{break;}}
    }
    result
}
#[cfg(windows)] mod windows;
pub fn habbo_processes()->io::Result<Vec<ClientProcess>> {
    #[cfg(windows)] {windows::processes()}
    #[cfg(not(windows))] {Err(io::Error::new(io::ErrorKind::Unsupported,"automatic Flash memory discovery currently requires Windows"))}
}
pub fn scan_habbo(pid:u32,cancel:&AtomicBool)->io::Result<ScanResult> {
    #[cfg(windows)] {
        let known=habbo_processes()?;if !known.iter().any(|p|p.pid==pid){return Err(io::Error::new(io::ErrorKind::InvalidInput,"select a running Habbo or Flash player process"));}
        windows::scan(pid,cancel,None)
    }
    #[cfg(not(windows))] {let _=(pid,cancel);Err(io::Error::new(io::ErrorKind::Unsupported,"automatic Flash memory discovery currently requires Windows"))}
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn finds_aligned_word_permutations_and_rejects_duplicates(){
        let words:Vec<u32>=(0..256).map(|i|255-i).collect();let mut bytes=vec![9;12];for w in &words{bytes.extend(w.to_le_bytes());}
        let tables=find_tables(&bytes,0);assert_eq!(tables.len(),1);assert_eq!(tables[0][0],255);
        bytes[16..20].copy_from_slice(&255u32.to_le_bytes());assert!(find_tables(&bytes,0).is_empty());
    }
}
