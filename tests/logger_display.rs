use gearth_rust::logger_display::{hex_dump, represent, PacketRepresentation};

#[test]
fn selected_direction_capture_can_match_java_or_keep_hidden_packets() {
    use gearth_rust::{
        logger_display::{capture_direction, displayed_directions},
        packet::Direction,
    };
    for incoming in [false, true] {
        for outgoing in [false, true] {
            assert!(capture_direction(
                Direction::ToClient,
                incoming,
                outgoing,
                false
            ));
            assert!(capture_direction(
                Direction::ToServer,
                incoming,
                outgoing,
                false
            ));
            assert_eq!(
                capture_direction(Direction::ToClient, incoming, outgoing, true),
                incoming
            );
            assert_eq!(
                capture_direction(Direction::ToServer, incoming, outgoing, true),
                outgoing
            );
            assert_eq!(
                displayed_directions(incoming, outgoing, false),
                (incoming, outgoing)
            );
            assert_eq!(displayed_directions(incoming, outgoing, true), (true, true));
        }
    }
}

#[test]
fn java_large_packet_thresholds_are_strict_and_exclude_frame_prefix() {
    use gearth_rust::logger_display::skip_large_eva_representations as skip;
    assert!(!skip(1004, true));
    assert!(skip(1005, true));
    assert!(!skip(4004, false));
    assert!(skip(4005, false));
    assert!(!skip(0, true));
}

#[test]
fn capture_export_preserves_existing_file_on_failed_write() {
    use std::io::Write;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).unwrap();
    let suffix = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let directory = std::env::temp_dir().join(format!("gearth-capture-test-{suffix}"));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("capture.txt");
    std::fs::write(&path, "old capture").unwrap();
    let error = gearth_rust::logger_display::write_atomic(&path, |file| {
        file.write_all(b"partial capture")?;
        Err(std::io::Error::other("simulated write failure"))
    });
    assert!(error.is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "old capture");
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
    gearth_rust::logger_display::write_atomic(&path, |file| file.write_all(b"complete capture"))
        .unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "complete capture");
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn hex_dump_aligns_bytes_offsets_and_marks_truncation() {
    let bytes = [0, b'A', b' ', b'\t', b'\n', b'\r', 255];
    let dump = hex_dump(&bytes, usize::MAX);
    assert_eq!(dump, format!("00000000  00 41 20 09 0a 0d ff{}|\u{25a1}A\u{2423}\u{2192}\u{00b6}\u{00a4}\u{25a1}|\n00000007", " ".repeat(30)));
    assert_eq!(hex_dump(&[], 100), "empty");
    assert!(hex_dump(&bytes, 2).ends_with("00000002\n[5 bytes not shown]"));
}

#[test]
#[ignore = "requires the pinned Java hexdump oracle"]
fn hex_dump_matches_original_java() {
    use std::process::Command;
    let cp = std::env::var("GEARTH_HEXDUMP_CLASSPATH").unwrap();
    for length in [0, 1, 7, 8, 9, 15, 16, 17, 32, 256] {
        let bytes: Vec<_> = (0..length).map(|n| n as u8).collect();
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let actual = Command::new("java")
            .args(["-cp", &cp, "JavaHexdumpOracle", &hex])
            .output()
            .unwrap();
        assert!(
            actual.status.success(),
            "{}",
            String::from_utf8_lossy(&actual.stderr)
        );
        assert_eq!(
            hex_dump(&bytes, usize::MAX).as_bytes(),
            actual.stdout,
            "length {length}"
        );
    }
}

#[test]
fn displays_legacy_and_hex_without_losing_control_bytes() {
    let bytes = [0, b'A', b'[', b']', b'{', b'}', 127, 160, 255];
    assert_eq!(
        represent(&bytes, PacketRepresentation::NoBytes, bytes.len()),
        ""
    );
    assert_eq!(
        represent(&bytes, PacketRepresentation::Legacy, bytes.len()),
        "[0]A[91][93][123][125][127]\u{a0}ÿ"
    );
    assert_eq!(
        represent(&bytes, PacketRepresentation::RawHex, bytes.len()),
        "00415b5d7b7d7fa0ff"
    );
}

#[test]
fn long_packets_are_bounded_and_options_restore_from_settings() {
    let bytes = [0, 1, 2, 3];
    assert_eq!(represent(&bytes, PacketRepresentation::RawHex, 2), "0001…");
    assert_eq!(represent(&bytes, PacketRepresentation::Legacy, 0), "…");
    for mode in [
        PacketRepresentation::Expression,
        PacketRepresentation::NoBytes,
        PacketRepresentation::Legacy,
        PacketRepresentation::RawHex,
        PacketRepresentation::HexDump,
    ] {
        assert_eq!(PacketRepresentation::from_setting(mode.name()), mode);
    }
    assert_eq!(
        PacketRepresentation::from_setting("unknown"),
        PacketRepresentation::Expression
    );
    assert_eq!(
        represent(&bytes, PacketRepresentation::HexDump, 2),
        hex_dump(&bytes, 2)
    );
}
