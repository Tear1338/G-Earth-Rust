use gearth_rust::attachment::HostsRedirect;
use std::{fs, net::Ipv4Addr};
fn fixture() -> (std::path::PathBuf, String) {
    let path = std::env::temp_dir().join(format!(
        "gearth-hosts-{}-{}.txt",
        std::process::id(),
        getrandom_u64()
    ));
    let original = "# user configuration\r\n127.0.0.1 localhost\r\n".to_owned();
    fs::write(&path, &original).unwrap();
    (path, original)
}
fn getrandom_u64() -> u64 {
    let mut b = [0; 8];
    getrandom::fill(&mut b).unwrap();
    u64::from_ne_bytes(b)
}
#[test]
fn restores_only_its_own_entry_and_preserves_later_edits() {
    let (path, original) = fixture();
    let mut guard =
        HostsRedirect::install(&path, "game-test.habbo.com", Ipv4Addr::new(127, 0, 0, 2)).unwrap();
    let mut content = fs::read_to_string(&path).unwrap();
    assert!(content.contains("127.0.0.2 game-test.habbo.com"));
    content.push_str("10.0.0.1 added.example\r\n");
    fs::write(&path, content).unwrap();
    guard.restore().unwrap();
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        original + "10.0.0.1 added.example\r\n"
    );
    drop(guard);
    fs::remove_file(path).unwrap();
}
#[test]
fn rejects_conflicts_injection_and_unowned_entries_without_changing_them() {
    let (path, _) = fixture();
    for host in ["localhost", "bad\n127.0.0.1 evil.example", "-invalid.test"] {
        let before = fs::read(&path).unwrap();
        assert!(HostsRedirect::install(&path, host, Ipv4Addr::LOCALHOST).is_err());
        assert_eq!(before, fs::read(&path).unwrap());
    }
    let guard = HostsRedirect::install(&path, "one.example", Ipv4Addr::LOCALHOST).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(HostsRedirect::install(&path, "two.example", Ipv4Addr::LOCALHOST).is_err());
    assert_eq!(before, fs::read(&path).unwrap());
    drop(guard);
    fs::remove_file(path).unwrap();
}
#[test]
fn explicit_stale_recovery_preserves_other_applications_redirects() {
    let (path, original) = fixture();
    let guard = HostsRedirect::install(&path, "stale.example", Ipv4Addr::LOCALHOST).unwrap();
    std::mem::forget(guard);
    let mut text = fs::read_to_string(&path).unwrap();
    text.push_str("127.0.0.3 original.example # G-Earth\r\n");
    fs::write(&path, text).unwrap();
    HostsRedirect::recover_stale(&path).unwrap();
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        original + "127.0.0.3 original.example # G-Earth\r\n"
    );
    fs::remove_file(path).unwrap();
}
