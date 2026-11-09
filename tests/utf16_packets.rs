use gearth_rust::packet::{JavaStringEncoding, Packet, PacketField, PacketFormat, Utf16Encoding};

#[test]
fn utf16be_short_and_long_roundtrip_and_offset_reads_preserve_cursor() {
    let mut packet = Packet::new(23);
    packet
        .put_utf16be("Aé水🐱")
        .unwrap()
        .put_utf16be_long("雪🪶")
        .unwrap();
    let second = 6 + 2 + "Aé水🐱".encode_utf16().count() * 2;
    packet.set_cursor(7).unwrap();
    assert_eq!(packet.read_utf16be_at(6, false).unwrap(), "Aé水🐱");
    assert_eq!(packet.read_utf16be_long_at(second, false).unwrap(), "雪🪶");
    assert_eq!(packet.cursor(), 7);
    packet.reset();
    assert_eq!(packet.read_utf16be(false).unwrap(), "Aé水🐱");
    assert_eq!(packet.read_utf16be_long(false).unwrap(), "雪🪶");
    assert_eq!(packet.remaining(), 0);
}

#[test]
fn utf16be_strict_errors_preserve_cursor_and_java_lossy_consumes_bad_pairs() {
    let mut packet = Packet::new(23);
    packet
        .put_short_bytes(&[0xd8, 0, 0, 0x41])
        .unwrap()
        .put_long_bytes(&[0, 0x41, 0])
        .unwrap();
    assert!(packet.read_utf16be(false).is_err());
    assert_eq!(packet.cursor(), 6);
    assert_eq!(packet.read_utf16be(true).unwrap(), "�");
    let second = packet.cursor();
    assert!(packet.read_utf16be_long(false).is_err());
    assert_eq!(packet.cursor(), second);
    assert_eq!(packet.read_utf16be_long(true).unwrap(), "A�");
    let mut truncated = Packet::new(23);
    truncated.append(&[0, 4, 0]).unwrap();
    assert!(truncated.read_utf16be(true).is_err());
    assert_eq!(truncated.cursor(), 6);
}

#[test]
fn utf16be_replacement_and_short_length_limits_are_transactional() {
    let mut packet = Packet::new(23);
    packet.put_utf16be("cat").unwrap().put_i32(42).unwrap();
    packet.set_cursor(7).unwrap();
    let before = packet.clone();
    assert!(packet.replace_utf16be(6, &"🐱".repeat(16384)).is_err());
    assert_eq!(packet, before);
    packet.replace_utf16be(6, "雪🐱").unwrap();
    assert_eq!(packet.cursor(), 7);
    assert_eq!(packet.read_utf16be_at(6, false).unwrap(), "雪🐱");
    let mut limit = Packet::new(23);
    limit.put_utf16be(&"a".repeat(32767)).unwrap();
    assert!(limit.put_utf16be(&"a".repeat(32768)).is_err());
    let mut wedgie = Packet::new_with_format(PacketFormat::WedgieOutgoing, 1).unwrap();
    assert!(wedgie.put_utf16be("a").is_err());
    assert!(wedgie.read_utf16be(true).is_err());
}

#[test]
fn utf16_bom_selects_byte_order_and_empty_encoding_has_no_bom() {
    let mut packet = Packet::new(24);
    packet
        .put_utf16("", Utf16Encoding::WithBom)
        .unwrap()
        .put_utf16("🐱", Utf16Encoding::WithBom)
        .unwrap();
    assert_eq!(&packet.bytes()[6..8], &[0, 0]);
    assert_eq!(
        packet.read_utf16(Utf16Encoding::WithBom, false).unwrap(),
        ""
    );
    assert_eq!(
        packet.read_utf16(Utf16Encoding::WithBom, false).unwrap(),
        "🐱"
    );
    let mut input = Packet::new(24);
    input.put_short_bytes(&[0xff, 0xfe, 0x41, 0x00]).unwrap();
    assert_eq!(
        input
            .read_utf16_at(6, Utf16Encoding::WithBom, false)
            .unwrap(),
        "A"
    );
    assert_eq!(
        input
            .read_utf16_at(6, Utf16Encoding::LittleEndian, false)
            .unwrap(),
        "\u{feff}A"
    );
    input
        .replace_utf16(6, "雪", Utf16Encoding::LittleEndian)
        .unwrap();
    assert_eq!(
        input
            .read_utf16(Utf16Encoding::LittleEndian, false)
            .unwrap(),
        "雪"
    );
    let mut limit = Packet::new(24);
    limit
        .put_utf16(&"a".repeat(32766), Utf16Encoding::WithBom)
        .unwrap();
    assert!(Packet::new(24)
        .put_utf16(&"a".repeat(32767), Utf16Encoding::WithBom)
        .is_err());
}

#[test]
fn java_unpaired_surrogate_units_encode_with_charset_specific_replacement() {
    let units = [0xd800, 0xd800, 0xdc00, b'A' as u16];
    let mut packet = Packet::new(25);
    packet
        .append_fields(&[PacketField::StringUnits(&units, JavaStringEncoding::Utf8)])
        .unwrap();
    assert_eq!(
        packet.read_short_bytes_at(6).unwrap(),
        &[b'?', 0xf0, 0x90, 0x80, 0x80, b'A']
    );
    packet.reset();
    assert_eq!(packet.read_utf8().unwrap(), "?𐀀A");
    let mut packet = Packet::new(25);
    packet
        .put_java_units_long(&units, JavaStringEncoding::Utf16(Utf16Encoding::WithBom))
        .unwrap();
    assert_eq!(
        packet
            .read_utf16_long(Utf16Encoding::WithBom, false)
            .unwrap(),
        "�𐀀A"
    );
    let mut packet = Packet::new(25);
    packet.put_string("cat").unwrap();
    packet
        .replace_java_units(6, &units, JavaStringEncoding::Latin1)
        .unwrap();
    assert_eq!(packet.read_string().unwrap(), "??A");
    let before = packet.clone();
    assert!(packet
        .put_java_units(&vec![b'a' as u16; 65536], JavaStringEncoding::Utf8)
        .is_err());
    assert_eq!(packet, before);
    let mut wedgie = Packet::new_with_format(PacketFormat::WedgieOutgoing, 1).unwrap();
    assert!(wedgie
        .put_java_units(&units, JavaStringEncoding::Utf8)
        .is_err());
}
