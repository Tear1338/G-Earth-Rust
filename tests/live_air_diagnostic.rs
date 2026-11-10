//! Opt-in, read-only diagnostics against an already running official AIR client.
//! The test prints only aggregate scan statistics, never process memory or cipher states.
#![cfg(windows)]

use std::sync::atomic::AtomicBool;

#[test]
#[ignore = "requires an existing official client and its established socket"]
fn official_air_process_and_socket_read_only_diagnostic() {
    let pid: u32 = std::env::var("GEARTH_LIVE_PID").unwrap().parse().unwrap();
    let local = std::env::var("GEARTH_LIVE_LOCAL").unwrap().parse().unwrap();
    let remote = std::env::var("GEARTH_LIVE_REMOTE")
        .unwrap()
        .parse()
        .unwrap();
    let processes = gearth_platform::habbo_processes().unwrap();
    assert!(processes.iter().any(|process| process.pid == pid));
    assert_eq!(
        gearth_platform::tcp_owner(local, remote).unwrap(),
        Some(pid)
    );
    let scan = gearth_platform::scan_habbo(pid, &AtomicBool::new(false)).unwrap();
    println!(
        "Read-only scan: {} bytes, complete={}, {} shuffled table candidates",
        scan.bytes_read,
        scan.complete,
        scan.states.len()
    );
    assert!(scan.bytes_read > 0, "the selected client could not be read");
}
