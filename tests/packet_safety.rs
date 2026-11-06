use gearth_rust::{packet::Direction, packet_safety::PacketSafety};

#[test]
fn observed_headers_are_scoped_by_revision_and_direction() {
    let mut safety = PacketSafety::default();
    assert!(safety.is_safe(None, Direction::ToServer, 42));
    assert!(!safety.is_safe(Some(""), Direction::ToServer, 42));
    assert!(!safety.observe("", Direction::ToServer, 42));
    assert!(!safety.may_send(Some("v1"), Direction::ToServer, 42, false));
    assert!(safety.may_send(Some("v1"), Direction::ToServer, 42, true));
    assert!(safety.observe("v1", Direction::ToServer, 42));
    assert!(safety.may_send(Some("v1"), Direction::ToServer, 42, false));
    assert!(!safety.is_safe(Some("v1"), Direction::ToClient, 42));
    assert!(!safety.is_safe(Some("v2"), Direction::ToServer, 42));
    assert!(safety.observe("v1", Direction::ToClient, 42));
    assert!(safety.is_safe(Some("v1"), Direction::ToClient, 42));
}

#[test]
fn invalid_or_excess_revisions_do_not_erase_existing_observations() {
    let mut safety = PacketSafety::default();
    for n in 0..64 {
        assert!(safety.observe(&format!("v{n}"), Direction::ToClient, n));
    }
    assert!(!safety.observe("v64", Direction::ToServer, 1));
    assert!(!safety.observe(&"x".repeat(1025), Direction::ToServer, 1));
    assert!(safety.is_safe(Some("v0"), Direction::ToClient, 0));
    assert!(safety.observe("v0", Direction::ToServer, 1));
}
