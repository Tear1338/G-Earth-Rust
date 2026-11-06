use gearth_rust::{
    injection::{parse_packets, InjectionHistory},
    packet::{Direction, PacketFormat},
    packet_info::PacketInfoManager,
};

#[test]
fn parses_multiple_packets_and_multiline_quoted_fields() {
    let info = PacketInfoManager::default();
    let mut packets = parse_packets(
        "{h:1}{s:\"a\n{b}\\\"c\"}\r\n{h:2}{i:4}\n",
        PacketFormat::EvaWire,
        Direction::ToServer,
        &info,
    )
    .unwrap();
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].header(), 1);
    assert_eq!(packets[0].read_string().unwrap(), "a\n{b}\"c");
    assert_eq!(packets[1].header(), 2);
    assert_eq!(packets[1].read_i32().unwrap(), 4);
}

#[test]
fn batch_validates_all_packets_and_bounds_input() {
    let info = PacketInfoManager::default();
    let parse =
        |input: &str| parse_packets(input, PacketFormat::EvaWire, Direction::ToServer, &info);
    assert!(parse("{h:1}\n{h:bad}")
        .unwrap_err()
        .to_string()
        .contains("packet 2"));
    assert!(parse("{h:1}\n\n{h:2}").is_err());
    assert!(parse("").is_err());
    assert!(parse(&"{h:1}\n".repeat(257)).is_err());
    assert!(parse_packets(
        "{h:1}\n{h:2}",
        PacketFormat::WedgieOutgoing,
        Direction::ToServer,
        &info
    )
    .is_ok());
}

#[test]
fn batch_reports_partial_enqueue_and_stops_in_order() {
    let info = PacketInfoManager::default();
    let packets = parse_packets(
        "{h:1}\n{h:2}\n{h:3}",
        PacketFormat::EvaWire,
        Direction::ToServer,
        &info,
    )
    .unwrap();
    let mut attempted = Vec::new();
    let result = gearth_rust::injection::enqueue_packets(packets, |packet| {
        attempted.push(packet.header());
        if packet.header() == 2 {
            Err("queue full")
        } else {
            Ok(())
        }
    });
    assert_eq!(result, Err((1, "queue full")));
    assert_eq!(attempted, vec![1, 2]);
}

#[test]
fn named_packets_are_validated_for_the_actual_destination() {
    use gearth_rust::packet_info::PacketInfo;
    let info = PacketInfoManager::new(
        "v",
        vec![PacketInfo {
            header: 42,
            direction: Direction::ToServer,
            name: Some("Example".into()),
            hash: None,
            structure: None,
            source: "fixture".into(),
        }],
    );
    let packets = parse_packets(
        "{out:Example}\n{h:2}",
        PacketFormat::EvaWire,
        Direction::ToServer,
        &info,
    )
    .unwrap();
    assert_eq!(
        packets.iter().map(|p| p.header()).collect::<Vec<_>>(),
        vec![42, 2]
    );
    assert!(parse_packets(
        "{out:Example}\n{h:2}",
        PacketFormat::EvaWire,
        Direction::ToClient,
        &info
    )
    .is_err());
    let validate = |text| {
        gearth_rust::injection::valid_destinations(
            text,
            PacketFormat::EvaWire,
            PacketFormat::EvaWire,
            &info,
        )
    };
    assert_eq!(validate("{out:Example}\n{h:2}"), (true, false));
    assert_eq!(validate("{h:2}"), (true, true));
    assert_eq!(validate("{h:bad}"), (false, false));
    assert_eq!(validate(""), (false, false));
}

#[test]
fn safety_checks_all_packets_and_keeps_revision_and_direction_separate() {
    use gearth_rust::packet_safety::PacketSafety;
    let info = PacketInfoManager::default();
    let packets = parse_packets(
        "{h:1}\n{h:2}",
        PacketFormat::EvaWire,
        Direction::ToServer,
        &info,
    )
    .unwrap();
    let mut safety = PacketSafety::default();
    safety.observe("v1", Direction::ToServer, 1);
    assert_eq!(
        gearth_rust::injection::first_unsafe_packet(
            &packets,
            Direction::ToServer,
            Some("v1"),
            &safety,
            false
        ),
        Some(2)
    );
    assert_eq!(
        gearth_rust::injection::first_unsafe_packet(
            &packets,
            Direction::ToServer,
            Some("v1"),
            &safety,
            true
        ),
        None
    );
    safety.observe("v1", Direction::ToServer, 2);
    assert_eq!(
        gearth_rust::injection::first_unsafe_packet(
            &packets,
            Direction::ToServer,
            Some("v1"),
            &safety,
            false
        ),
        None
    );
    assert_eq!(
        gearth_rust::injection::first_unsafe_packet(
            &packets,
            Direction::ToClient,
            Some("v1"),
            &safety,
            false
        ),
        Some(1)
    );
    assert_eq!(
        gearth_rust::injection::first_unsafe_packet(
            &packets,
            Direction::ToServer,
            Some("v2"),
            &safety,
            false
        ),
        Some(1)
    );
}

#[test]
fn history_roundtrips_is_bounded_deduplicated_and_validates_input() {
    let mut history = InjectionHistory::default();
    assert!(history.record("{h:1}", Direction::ToServer));
    assert!(history.record("{h:1}", Direction::ToClient));
    assert!(history.record("{h:1}", Direction::ToClient));
    assert_eq!(history.entries().len(), 1);
    assert_eq!(history.entries()[0].direction, Direction::ToServer.name());
    for n in 0..80 {
        assert!(history.record(&format!("{{h:{n}}}"), Direction::ToClient));
    }
    assert_eq!(history.entries().len(), 69);
    assert!(!history.record(&"x".repeat(8193), Direction::ToClient));
    let mut restored = InjectionHistory::from_json(&history.to_json());
    assert_eq!(restored.entries(), history.entries());
    assert!(InjectionHistory::from_json("invalid").entries().is_empty());
    assert!(
        InjectionHistory::from_json(r#"[{"expression":"x","direction":"NO"}]"#)
            .entries()
            .is_empty()
    );
    restored.clear();
    assert!(restored.entries().is_empty());
}

#[test]
fn injection_history_survives_settings_save_and_reload() {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).unwrap();
    let name = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let path = std::env::temp_dir().join(format!("gearth-injection-{name}.json"));
    let mut history = InjectionHistory::default();
    assert!(history.record("{h:42}{s:\"hello\"}", Direction::ToClient));
    let mut settings = gearth_rust::settings::Settings::default();
    settings
        .values
        .insert("injection_history".into(), history.to_json());
    settings.save(&path).unwrap();
    let restored = gearth_rust::settings::Settings::read(&path).unwrap();
    assert_eq!(
        InjectionHistory::from_json(restored.get("injection_history")).entries(),
        history.entries()
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn immediate_history_save_preserves_other_settings_and_invalid_files() {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).unwrap();
    let name = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let path = std::env::temp_dir().join(format!("gearth-history-save-{name}.json"));
    let mut settings = gearth_rust::settings::Settings::default();
    settings
        .values
        .insert("remote".into(), "example:1234".into());
    settings
        .extra
        .insert("future".into(), serde_json::json!({"keep": true}));
    settings.save(&path).unwrap();
    let mut history = InjectionHistory::default();
    history.record("{h:1}", Direction::ToServer);
    history.save_to_settings(&path).unwrap();
    let saved = gearth_rust::settings::Settings::read(&path).unwrap();
    assert_eq!(saved.get("remote"), "example:1234");
    assert_eq!(saved.extra["future"]["keep"], true);
    assert_eq!(
        InjectionHistory::from_json(saved.get("injection_history")).entries(),
        history.entries()
    );
    std::fs::write(&path, "{broken").unwrap();
    assert!(history.save_to_settings(&path).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "{broken");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn history_caps_escaped_settings_size_and_preserves_newest() {
    let mut history = InjectionHistory::default();
    for index in 0..69 {
        let value = format!("{index}{}", "\0".repeat(8000));
        assert!(history.record(&value, Direction::ToServer));
    }
    let serialized = serde_json::to_string(&history.to_json()).unwrap();
    assert!(serialized.len() <= 512 * 1024);
    assert!(history
        .entries()
        .front()
        .unwrap()
        .expression
        .starts_with("68"));
    let restored = InjectionHistory::from_json(&history.to_json());
    assert_eq!(restored.entries(), history.entries());
}
