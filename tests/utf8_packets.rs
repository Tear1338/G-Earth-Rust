use gearth_rust::packet::{Packet, PacketFormat};

#[test]
fn reads_and_writes_short_and_long_utf8_with_byte_lengths() {
    let mut packet = Packet::new(6);
    packet
        .put_utf8("café 🐱")
        .unwrap()
        .put_utf8_long("水🪶")
        .unwrap();
    assert_eq!(
        &packet.bytes()[6..8],
        &("café 🐱".len() as u16).to_be_bytes()
    );
    packet.reset();
    assert_eq!(packet.read_utf8().unwrap(), "café 🐱");
    assert_eq!(packet.read_utf8_long().unwrap(), "水🪶");
    assert_eq!(packet.remaining(), 0);
}

#[test]
fn rejects_invalid_or_truncated_utf8_without_consuming_data() {
    for body in [&[0, 2, 0xc3, 0x28][..], &[0, 3, b'x'][..]] {
        let mut packet = Packet::new(1);
        packet.append(body).unwrap();
        let start = packet.cursor();
        assert!(packet.read_utf8().is_err());
        assert_eq!(packet.cursor(), start);
    }
    let mut long = Packet::new(1);
    long.append(&[0, 0, 0, 2, 0xc3, 0x28]).unwrap();
    assert!(long.read_utf8_long().is_err());
    assert_eq!(long.cursor(), 6);
}

#[test]
fn utf8_edits_are_transactional_and_enforce_wire_limits() {
    let mut packet = Packet::new(7);
    packet.put_utf8("cat").unwrap().put_i32(42).unwrap();
    packet.set_cursor(7).unwrap();
    let before = packet.clone();
    assert!(packet.replace_utf8(6, &"x".repeat(65_536)).is_err());
    assert!(packet.put_utf8(&"x".repeat(65_536)).is_err());
    assert_eq!(packet, before);
    packet.replace_utf8(6, "雪🐱").unwrap();
    assert_eq!(packet.cursor(), 7);
    packet.reset();
    assert_eq!(packet.read_utf8().unwrap(), "雪🐱");
    assert_eq!(packet.read_i32().unwrap(), 42);
    let mut wedgie = Packet::new_with_format(PacketFormat::WedgieOutgoing, 1).unwrap();
    assert!(wedgie.put_utf8("hello").is_err());
    assert!(wedgie.read_utf8().is_err());
}

#[test]
fn short_utf8_limit_counts_encoded_bytes_not_characters() {
    let text = format!("{}x", "é".repeat(32_767));
    assert_eq!(text.len(), 65_535);
    let mut packet = Packet::new(8);
    packet.put_utf8(&text).unwrap();
    packet.reset();
    assert_eq!(packet.read_utf8().unwrap(), text);
    let before = packet.clone();
    assert!(packet.put_utf8(&format!("{text}x")).is_err());
    assert_eq!(packet, before);
}

#[test]
fn raw_short_fields_round_trip_custom_encodings_without_cursor_loss() {
    let original = [0, 65, 0, 233, 0x6c, 0x34];
    let replacement = [0, 90, 0x73, 0x2b];
    let mut packet = Packet::new(9);
    packet
        .put_short_bytes(&original)
        .unwrap()
        .put_i32(42)
        .unwrap();
    packet.reset();
    assert_eq!(packet.read_short_bytes().unwrap(), original);
    assert_eq!(packet.read_i32().unwrap(), 42);
    packet.replace_short_bytes(6, &replacement).unwrap();
    packet.reset();
    assert_eq!(packet.read_short_bytes().unwrap(), replacement);
    assert_eq!(packet.read_i32().unwrap(), 42);

    let mut truncated = Packet::new(1);
    truncated.append(&[0, 4, 1]).unwrap();
    assert!(truncated.read_short_bytes().is_err());
    assert_eq!(truncated.cursor(), 6);
    let before = truncated.clone();
    assert!(truncated.replace_short_bytes(6, &replacement).is_err());
    assert_eq!(truncated, before);
}
