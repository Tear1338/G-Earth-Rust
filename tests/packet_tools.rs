use gearth_rust::{
    expression,
    packet::{Direction, Packet, PacketFormat},
    packet_info::{PacketInfo, PacketInfoManager},
    packet_tools,
};

#[test]
fn roundtrips_all_client_packet_formats() {
    let info = PacketInfoManager::default();
    for (format, direction) in [
        (PacketFormat::EvaWire, Direction::ToServer),
        (PacketFormat::WedgieIncoming, Direction::ToClient),
        (PacketFormat::WedgieOutgoing, Direction::ToServer),
    ] {
        let mut packet = Packet::new_with_format(format, 42).unwrap();
        packet.append(&[0, 1, 42, 255]).unwrap();
        let source = expression::to_lossless_expression(&packet);
        let hex = packet_tools::expression_to_hex(&source, format, direction, &info).unwrap();
        assert_eq!(expression::parse_hex(&hex).unwrap(), packet.bytes());
        let result = packet_tools::hex_to_expression(&hex, format).unwrap();
        assert_eq!(
            expression::parse_with_format(&result, format, None)
                .unwrap()
                .bytes(),
            packet.bytes()
        );
    }
}

#[test]
fn named_headers_follow_direction_and_invalid_packets_are_rejected() {
    let info = PacketInfoManager::new(
        "test",
        vec![PacketInfo {
            header: 42,
            hash: None,
            name: Some("Example".into()),
            structure: None,
            direction: Direction::ToServer,
            source: "fixture".into(),
        }],
    );
    assert_eq!(
        packet_tools::expression_to_hex(
            "{out:Example}{i:1}",
            PacketFormat::EvaWire,
            Direction::ToServer,
            &info
        )
        .unwrap(),
        "00 00 00 06 00 2A 00 00 00 01"
    );
    assert!(packet_tools::expression_to_hex(
        "{out:Example}",
        PacketFormat::EvaWire,
        Direction::ToClient,
        &info
    )
    .is_err());
    assert!(packet_tools::hex_to_expression("00 00 00 02 00", PacketFormat::EvaWire).is_err());
    assert!(packet_tools::hex_to_expression("3F 40", PacketFormat::WedgieIncoming).is_err());
}

#[test]
fn indexed_header_lookup_preserves_direction_and_duplicate_order() {
    let entry = |direction, name: &str| PacketInfo {
        header: 42,
        direction,
        name: Some(name.into()),
        hash: None,
        structure: None,
        source: "fixture".into(),
    };
    let info = PacketInfoManager::new(
        "test",
        vec![
            entry(Direction::ToClient, "first"),
            entry(Direction::ToServer, "other"),
            entry(Direction::ToClient, "second"),
        ],
    );
    assert_eq!(
        info.by_header(Direction::ToClient, 42)
            .map(|entry| entry.name.as_deref().unwrap())
            .collect::<Vec<_>>(),
        vec!["first", "second"]
    );
    assert_eq!(info.by_header(Direction::ToServer, 42).count(), 1);
    assert_eq!(info.by_header(Direction::ToClient, 43).count(), 0);
    assert_eq!(
        PacketInfoManager::default()
            .by_header(Direction::ToClient, 42)
            .count(),
        0
    );
}

#[test]
fn numeric_tools_roundtrip_signed_and_unsigned_boundaries() {
    for value in [i32::MIN, -65536, -1, 0, 1, 123456, i32::MAX] {
        let encoded = packet_tools::encode_i32(&value.to_string()).unwrap();
        assert_eq!(packet_tools::decode_i32(&encoded).unwrap(), value);
    }
    for value in [0u16, 1, 255, 256, 32768, u16::MAX] {
        let encoded = packet_tools::encode_u16(&value.to_string()).unwrap();
        assert_eq!(packet_tools::decode_u16(&encoded).unwrap(), value);
    }
    assert_eq!(packet_tools::decode_i32("{i:-2}").unwrap(), -2);
    assert_eq!(packet_tools::decode_u16("{u:65535}").unwrap(), 65535);
    assert_eq!(packet_tools::decode_i32("[0][0][0]*").unwrap(), 42);
    assert!(packet_tools::encode_i32("2147483648").is_err());
    assert!(packet_tools::encode_u16("-1").is_err());
    assert!(packet_tools::encode_u16("65536").is_err());
    assert!(packet_tools::decode_i32("[0][1]").is_err());
    assert!(packet_tools::decode_u16("[256]").is_err());
    assert!(packet_tools::decode_u16(&"x".repeat(4097)).is_err());
}

#[test]
fn preview_limits_output_without_modifying_the_packet() {
    let mut packet = Packet::new(42);
    packet.append(&[1; 2048]).unwrap();
    let before = packet.bytes().to_vec();
    let preview = packet_tools::hex_preview(&packet, 8);
    assert!(preview.starts_with("00 00 08 02 00 2A 01 01"));
    assert!(preview.ends_with("(2046 bytes omitted)"));
    assert_eq!(packet.bytes(), before);
    assert_eq!(
        packet_tools::hex_preview(&Packet::new(1), 6),
        "00 00 00 02 00 01"
    );
}

#[test]
fn legacy_packet_conversions_preserve_exact_bytes_for_all_formats() {
    let info = PacketInfoManager::default();
    for (format, direction) in [
        (PacketFormat::EvaWire, Direction::ToServer),
        (PacketFormat::WedgieIncoming, Direction::ToClient),
        (PacketFormat::WedgieOutgoing, Direction::ToServer),
    ] {
        let mut original = Packet::new_with_format(format, 42).unwrap();
        original.append(&(0..=255).collect::<Vec<_>>()).unwrap();
        let expression = expression::to_lossless_expression(&original);
        let wire = packet_tools::expression_to_wire(&expression, format, direction, &info).unwrap();
        let (recovered, _) =
            packet_tools::wire_to_expression(&wire, format, direction, &info, false).unwrap();
        let packet =
            expression::parse_with_format(&recovered, format, Some((direction, &info))).unwrap();
        assert_eq!(packet.bytes(), original.bytes());
        if format != PacketFormat::EvaWire {
            assert_eq!(recovered, wire);
        }
    }
}

#[test]
fn packet_conversion_uses_known_structure_when_exact() {
    let info = PacketInfoManager::new(
        "test",
        vec![PacketInfo {
            header: 42,
            direction: Direction::ToServer,
            name: Some("Example".into()),
            hash: None,
            structure: Some("is".into()),
            source: "fixture".into(),
        }],
    );
    let source = "{out:Example}{i:7}{s:\"hello\"}";
    let wire =
        packet_tools::expression_to_wire(source, PacketFormat::EvaWire, Direction::ToServer, &info)
            .unwrap();
    let (result, structured) = packet_tools::wire_to_expression(
        &wire,
        PacketFormat::EvaWire,
        Direction::ToServer,
        &info,
        false,
    )
    .unwrap();
    assert!(structured);
    assert!(result.contains("Example"));
    assert_eq!(
        packet_tools::expression_to_wire(
            &result,
            PacketFormat::EvaWire,
            Direction::ToServer,
            &info
        )
        .unwrap(),
        wire
    );
}
