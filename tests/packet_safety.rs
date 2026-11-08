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

#[test]
fn metadata_ids_are_safe_by_revision_and_direction_even_before_observation() {
    use gearth_rust::packet_info::{PacketInfo, PacketInfoManager};
    let database = PacketInfoManager::new(
        "source",
        vec![PacketInfo {
            header: 77,
            name: Some("Known".into()),
            hash: None,
            structure: None,
            direction: Direction::ToServer,
            source: "fixture".into(),
        }],
    );
    let mut safety = PacketSafety::default();
    assert!(safety.register_metadata("v1", &database));
    assert!(safety.is_safe(Some("v1"), Direction::ToServer, 77));
    assert!(!safety.is_safe(Some("v1"), Direction::ToClient, 77));
    assert!(!safety.is_safe(Some("v2"), Direction::ToServer, 77));
    assert!(safety.register_metadata("", &database));
    assert!(safety.is_safe(Some(""), Direction::ToServer, 77));
    assert!(!safety.register_metadata(&"x".repeat(1025), &database));
    assert!(safety.is_safe(Some("v1"), Direction::ToServer, 77));
}
