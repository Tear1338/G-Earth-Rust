use gearth_rust::packet::{Packet, PacketFormat};

fn cases() -> Vec<(&'static str, PacketFormat, Vec<u8>, &'static str)> {
    use PacketFormat::{WedgieIncoming as Incoming, WedgieOutgoing as Outgoing};
    vec![
        ("in_empty", Incoming, vec![2], "ok::3"),
        ("in_missing", Incoming, vec![], "ok::0"),
        ("in_unterminated", Incoming, vec![b'A', 255], "ok::0"),
        ("in_latin1", Incoming, vec![255, 2, b'Z'], "ok:c3bf:4"),
        ("out_empty", Outgoing, vec![64, 64], "ok::4"),
        ("out_short_prefix", Outgoing, vec![64], "error:2"),
        ("out_short_body", Outgoing, vec![64, 66, b'A'], "error:4"),
        ("out_latin1", Outgoing, vec![64, 65, 255], "ok:c3bf:5"),
        ("out_invalid_prefix", Outgoing, vec![63, 64], "error:4"),
    ]
}

fn observe(format: PacketFormat, body: &[u8]) -> String {
    let mut frame = vec![64, 64];
    frame.extend_from_slice(body);
    let mut packet = Packet::from_bytes_with_format(format, frame).unwrap();
    match packet.read_wedgie_string_java() {
        Ok(value) => format!(
            "ok:{}:{}",
            value
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            packet.cursor()
        ),
        Err(_) => format!("error:{}", packet.cursor()),
    }
}

#[test]
fn java_compatible_wedgie_strings_cover_boundaries() {
    for (name, format, body, expected) in cases() {
        assert_eq!(observe(format, &body), expected, "{name}");
    }
    let mut safe =
        Packet::from_bytes_with_format(PacketFormat::WedgieIncoming, vec![64, 64, b'A']).unwrap();
    assert!(safe.read_string().is_err());
    assert_eq!(safe.cursor(), 2);
    let mut eva = Packet::new(1);
    assert!(eva.read_wedgie_string_java().is_err());
    assert_eq!(eva.cursor(), 6);
}

#[test]
#[ignore = "requires compiled JavaWedgieStringOracle and beta-29 Java API"]
fn wedgie_string_boundaries_match_released_java() {
    let cp = std::env::var("GEARTH_JAVA_WEDGIE_CLASSPATH").unwrap();
    let output = std::process::Command::new("java")
        .args(["-cp", &cp, "JavaWedgieStringOracle"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    for (name, format, body, _) in cases() {
        let java = text
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap();
        let java = if let Some(error) = java.strip_prefix("error:") {
            format!("error:{}", error.rsplit_once(':').unwrap().1)
        } else {
            java.to_owned()
        };
        assert_eq!(observe(format, &body), java, "{name}");
    }
}
