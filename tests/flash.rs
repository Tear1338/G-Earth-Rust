use gearth_rust::{
    crypto::Rc4,
    flash::{recover_state, FlashSession},
    packet::{Direction, Packet},
};
use std::sync::atomic::AtomicBool;
#[test]
fn recovers_both_states_without_exposing_or_guessing_the_key() {
    let fresh = Rc4::new(b"actual-client-key").unwrap();
    let mut outgoing = fresh.clone();
    let mut p = Packet::new(77);
    p.put_i32(42).unwrap();
    let mut bytes = p.bytes().to_vec();
    outgoing.apply(&mut bytes);
    let found = recover_state(
        &[fresh.state().0, outgoing.state().0],
        &bytes,
        Direction::ToServer,
        &AtomicBool::new(false),
    )
    .unwrap()
    .unwrap();
    assert_eq!(found.state(), fresh.state());
    let incoming = recover_state(
        &[fresh.state().0],
        &bytes,
        Direction::ToClient,
        &AtomicBool::new(false),
    )
    .unwrap()
    .unwrap();
    assert_eq!(incoming.state(), fresh.state());
    assert!(recover_state(
        &[Rc4::new(b"wrong-key").unwrap().state().0],
        &bytes,
        Direction::ToClient,
        &AtomicBool::new(false)
    )
    .unwrap()
    .is_none());
    assert!(recover_state(
        &[outgoing.state().0],
        &bytes[..bytes.len() - 1],
        Direction::ToServer,
        &AtomicBool::new(false)
    )
    .unwrap()
    .is_none());
}
#[test]
fn fragmented_handshake_and_coalesced_encrypted_tail_preserve_stream_counters() {
    let mut session = FlashSession::default();
    let cancel = AtomicBool::new(false);
    let mut hello = Packet::new(1);
    hello
        .put_string("TEST-2026")
        .unwrap()
        .put_string("FLASH")
        .unwrap();
    for b in hello.bytes() {
        session.feed(Direction::ToServer, &[*b]).unwrap();
    }
    assert_eq!(session.take_identity().unwrap().version, "TEST-2026");
    assert!(session.take_identity().is_none());
    let outgoing = Rc4::new(b"outgoing").unwrap();
    let incoming = Rc4::new(b"outgoing").unwrap();
    let mut secret = Packet::new(2);
    secret
        .put_string(&"a".repeat(600))
        .unwrap()
        .put_bool(true)
        .unwrap();
    let mut message = Packet::new(91);
    message.put_i32(77).unwrap();
    let mut enc = message.bytes().to_vec();
    incoming.clone().apply(&mut enc);
    let mut coalesced = secret.bytes().to_vec();
    coalesced.extend_from_slice(&enc);
    let initial = session.feed(Direction::ToClient, &coalesced).unwrap();
    assert_eq!(initial.len(), 1);
    assert!(!initial[0].encrypted);
    assert_eq!(
        session.encode(Direction::ToClient, &secret, false).unwrap(),
        secret.bytes()
    );
    assert!(session.encrypted(Direction::ToServer));
    assert!(session.encrypted(Direction::ToClient));
    let mut sent = outgoing.clone();
    let mut enc = message.bytes().to_vec();
    sent.apply(&mut enc);
    for b in &enc {
        assert!(session.feed(Direction::ToServer, &[*b]).unwrap().is_empty());
    }
    assert!(session
        .recover_with(&[incoming.state().0, sent.state().0], &cancel)
        .unwrap());
    for direction in [Direction::ToClient, Direction::ToServer] {
        let packets = session.feed(direction, &[]).unwrap();
        assert_eq!(packets.len(), 1);
        assert!(packets[0].encrypted);
        assert_eq!(packets[0].packet.bytes(), message.bytes());
    }
    // Dropping a captured outgoing packet must not advance the independently encrypted output.
    let mut injected = Packet::new(92);
    injected.put_i32(13).unwrap();
    let mut wire = session
        .encode(Direction::ToServer, &injected, true)
        .unwrap();
    outgoing.clone().apply(&mut wire);
    assert_eq!(wire, injected.bytes());
}

#[test]
fn ambiguous_reverse_snapshot_never_silently_corrupts_a_packet() {
    let mut cipher = Rc4::new(b"outgoing").unwrap();
    let mut p = Packet::new(91);
    p.put_i32(77).unwrap();
    let mut wire = p.bytes().to_vec();
    cipher.apply(&mut wire);
    assert!(recover_state(
        &[cipher.state().0],
        &wire,
        Direction::ToServer,
        &AtomicBool::new(false)
    )
    .unwrap()
    .is_none());
}

#[test]
fn flash_identity_accepts_java_hello_variants_and_ignores_truncated_fields() {
    for version in ["TEST-2026", ""] {
        let mut session = FlashSession::default();
        let mut invalid = Packet::new(1);
        invalid.put_u16(5).unwrap().put_u8(b'a').unwrap();
        session.feed(Direction::ToServer, invalid.bytes()).unwrap();
        assert!(session.take_identity().is_none());
        let mut hello = Packet::new(1);
        hello
            .put_string(version)
            .unwrap()
            .put_string("FLASH")
            .unwrap()
            .put_u8(42)
            .unwrap();
        session.feed(Direction::ToServer, hello.bytes()).unwrap();
        let identity = session.take_identity().unwrap();
        assert_eq!(
            (identity.version.as_str(), identity.identifier.as_str()),
            (version, "FLASH")
        );
        assert!(session.take_identity().is_none());
    }
}

#[test]
#[ignore = "requires the pinned Java Flash identification oracle"]
fn identification_compares_with_java_and_handles_fragmentation() {
    let java =
        std::fs::read_to_string(std::env::var("GEARTH_FLASH_IDENTITY_ORACLE").unwrap()).unwrap();
    let expected: std::collections::BTreeMap<_, _> = java
        .lines()
        .map(|line| line.split_once('=').unwrap())
        .collect();
    let mut hello = Packet::new(1);
    hello
        .put_string("TEST-2026")
        .unwrap()
        .put_string("FLASH")
        .unwrap();
    for split in 1..hello.bytes().len() {
        let mut session = FlashSession::default();
        session
            .feed(Direction::ToServer, &hello.bytes()[..split])
            .unwrap();
        assert!(session.take_identity().is_none(), "split {split}");
        session
            .feed(Direction::ToServer, &hello.bytes()[split..])
            .unwrap();
        let identity = session.take_identity().unwrap();
        assert_eq!(
            (identity.version.as_str(), identity.identifier.as_str()),
            ("TEST-2026", "FLASH")
        );
        let java = expected[format!("split_{split}").as_str()];
        assert_eq!(
            java,
            if split <= 6 {
                "ok,false,none"
            } else {
                "ArrayIndexOutOfBoundsException,true,none"
            },
            "split {split}"
        );
    }
    for case in 0..3 {
        let mut packet = Packet::new(1);
        packet
            .put_string(if case == 2 { "" } else { "TEST-2026" })
            .unwrap()
            .put_string("FLASH")
            .unwrap();
        if case == 1 {
            packet.put_u8(42).unwrap();
        }
        let mut session = FlashSession::default();
        for fragment in packet.bytes().chunks(2) {
            session.feed(Direction::ToServer, fragment).unwrap();
        }
        let identity = session.take_identity();
        let key = format!("identity_{case}");
        let identity = identity.unwrap();
        assert_eq!(
            format!("{},{}", identity.version, identity.identifier),
            expected[key.as_str()]
        );
        assert!(session.take_identity().is_none());
    }
}
