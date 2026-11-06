use gearth_rust::{
    expression, extension,
    packet::{Direction, Message, Packet, PacketFormat},
};
#[test]
fn both_wedgie_formats_read_write_and_serialize() {
    for format in [PacketFormat::WedgieIncoming, PacketFormat::WedgieOutgoing] {
        let mut p = Packet::new_with_format(format, 123).unwrap();
        p.put_i32(-256)
            .unwrap()
            .put_string("é")
            .unwrap()
            .put_bool(true)
            .unwrap()
            .put_u16(1000)
            .unwrap();
        assert_eq!(p.header(), 123);
        assert_eq!(p.read_i32().unwrap(), -256);
        assert_eq!(p.read_string().unwrap(), "é");
        assert!(p.read_bool().unwrap());
        assert_eq!(p.read_u16().unwrap(), 1000);
        let decoded = Packet::from_stringified_with_format(&p.stringify(), format).unwrap();
        assert_eq!(decoded.bytes(), p.bytes());
        assert!(p.put_f64(1.0).is_err());
        assert!(p.put_i64(1).is_err());
    }
}

#[test]
fn invalid_unsigned_fields_leave_cursor_at_the_start() {
    for value in [-1, 65_536] {
        let mut packet = Packet::new_with_format(PacketFormat::WedgieIncoming, 1).unwrap();
        packet.put_i32(value).unwrap();
        let start = packet.cursor();
        assert!(packet.read_u16().is_err());
        assert_eq!(packet.cursor(), start);
        assert_eq!(packet.read_i32().unwrap(), value);
    }
    for bytes in [&[0x20, 0x40][..], &[0x40][..]] {
        let mut packet = Packet::new_with_format(PacketFormat::WedgieOutgoing, 1).unwrap();
        packet.append(bytes).unwrap();
        let start = packet.cursor();
        assert!(packet.read_u16().is_err());
        assert_eq!(packet.cursor(), start);
        assert_eq!(packet.read_bytes(bytes.len()).unwrap(), bytes);
    }
}

#[test]
fn header_edits_reject_out_of_range_shockwave_values_without_mutation() {
    for format in [PacketFormat::WedgieIncoming, PacketFormat::WedgieOutgoing] {
        let mut packet = Packet::new_with_format(format, 5).unwrap();
        let before = packet.clone();
        assert!(packet.set_header(4096).is_err());
        assert!(packet.set_header(u16::MAX).is_err());
        assert_eq!(packet, before);
        packet.set_header(4095).unwrap();
        assert_eq!(packet.header(), 4095);
        assert!(packet.edited);
    }
    let mut packet = Packet::new(0);
    packet.set_header(u16::MAX).unwrap();
    assert_eq!(packet.header(), u16::MAX);
}
#[test]
fn extension_codec_carries_wedgie_format_after_inner_data() {
    let p = Packet::new_with_format(PacketFormat::WedgieOutgoing, 123).unwrap();
    let message = Message {
        packet: p,
        direction: Direction::ToServer,
        index: 42,
        blocked: false,
    };
    match extension::decode(extension::manipulated(&message).unwrap()).unwrap() {
        extension::Incoming::Manipulated(m) => {
            assert_eq!(m.packet.format(), PacketFormat::WedgieOutgoing)
        }
        _ => panic!(),
    };
    match extension::decode(extension::send(Direction::ToServer, &message.packet).unwrap()).unwrap()
    {
        extension::Incoming::Send { packet, .. } => {
            assert_eq!(packet.format(), PacketFormat::WedgieOutgoing)
        }
        _ => panic!(),
    };
}
#[test]
fn expressions_are_format_aware() {
    let p = expression::parse_with_format(
        "{h:123}{i:-256}{s:\"é\"}{b:true}",
        PacketFormat::WedgieIncoming,
        None,
    )
    .unwrap();
    let raw = expression::to_lossless_expression(&p);
    assert_eq!(
        expression::parse_with_format(&raw, PacketFormat::WedgieIncoming, None)
            .unwrap()
            .bytes(),
        p.bytes()
    );
}
#[test]
fn lossless_raw_space_at_end_is_not_trimmed() {
    let p = expression::parse("{h:123}{hex:20}").unwrap();
    assert_eq!(
        expression::parse(&expression::wire_display(p.bytes()))
            .unwrap()
            .body(),
        &[32]
    );
}
