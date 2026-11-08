use gearth_rust::{
    expression,
    packet::{Direction, Packet},
    packet_info::{PacketInfo, PacketInfoManager},
    structure_prediction,
};
use std::collections::BTreeMap;

#[test]
#[ignore = "requires the actual beta-29 Java predictor"]
fn predictions_match_the_released_java_api() {
    let input =
        std::fs::read_to_string(std::env::var("GEARTH_PREDICTION_ORACLE").unwrap()).unwrap();
    let observed: BTreeMap<_, _> = input
        .lines()
        .map(|line| line.split_once('=').unwrap())
        .collect();
    let samples = [
        "",
        "0000002a000568656c6c6f01",
        "ffffffff",
        "00000100",
        "61626364",
        "0000",
        "0100ffff",
        "0002c2a9",
        "0000000000bc614e",
        "000568656c6c6f00000000",
        "000000010000000000000001",
        "0020ff0001020304",
    ];
    let mut named = Packet::new(42);
    named.put_i32(7).unwrap().put_string("hello").unwrap();
    let entry = |direction, name: &str, structure: Option<&str>| PacketInfo {
        header: 42,
        hash: Some("hash".into()),
        name: Some(name.into()),
        structure: structure.map(str::to_owned),
        direction,
        source: "test".into(),
    };
    for known in [true, false] {
        let mut entries = vec![entry(Direction::ToClient, "Earlier", None)];
        if known {
            entries.push(entry(Direction::ToClient, "Known", Some("is")));
        }
        entries.push(entry(Direction::ToServer, "Wrong", Some("b")));
        let manager = PacketInfoManager::new("test", entries);
        let (actual, used_structure) = structure_prediction::expression_with_metadata(
            &named,
            Direction::ToClient,
            &manager,
            false,
        )
        .unwrap();
        let key = if known {
            "named_known"
        } else {
            "named_predicted"
        };
        assert_eq!(
            actual.as_bytes(),
            expression::parse_hex(observed[key]).unwrap()
        );
        assert_eq!(used_structure, known);
    }
    for unity in [false, true] {
        for (index, sample) in samples.iter().enumerate() {
            let mut packet = Packet::new(1);
            packet
                .append(&expression::parse_hex(sample).unwrap())
                .unwrap();
            let key = format!("{}_{index}", if unity { "unity" } else { "classic" });
            assert_eq!(
                structure_prediction::predict(&packet, unity).unwrap(),
                observed[key.as_str()],
                "{key}"
            );
            let expression_key = format!("expression_{key}");
            let expected = expression::parse_hex(observed[expression_key.as_str()]).unwrap();
            assert_eq!(
                structure_prediction::predicted_expression(&packet, unity)
                    .unwrap()
                    .as_bytes(),
                expected,
                "{expression_key}"
            );
        }
    }
    let mut nested = Packet::new(1);
    nested
        .put_i32(2)
        .unwrap()
        .put_string("a")
        .unwrap()
        .put_i32(7)
        .unwrap()
        .put_string("b\\\"")
        .unwrap()
        .put_i32(-1)
        .unwrap();
    assert_eq!(
        structure_prediction::expression_from_structure(&nested, "i(si)", None)
            .unwrap()
            .as_bytes(),
        expression::parse_hex(observed["nested"]).unwrap()
    );
    nested.set_cursor(7).unwrap();
    for structure in ["i(si)", "i(s)", "i(si)b", "", "i("] {
        let key = format!(
            "match_{}",
            structure
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert_eq!(
            format!("{},{}", nested.structure_equals(structure), nested.cursor()),
            observed[key.as_str()],
            "{structure}"
        );
    }
    let empty = Packet::new(1);
    assert_eq!(
        format!("{},{}", empty.structure_equals(""), empty.cursor()),
        observed["match_empty"]
    );
    let mut numeric = Packet::new(1);
    numeric
        .put_f32(0.1)
        .unwrap()
        .put_f64(-2.5)
        .unwrap()
        .put_u16(8)
        .unwrap();
    assert_eq!(
        structure_prediction::expression_from_structure(&numeric, "fdu", None)
            .unwrap()
            .as_bytes(),
        expression::parse_hex(observed["numeric"]).unwrap()
    );
    let mut floats = Packet::new(1);
    floats
        .put_f32(0.0001)
        .unwrap()
        .put_f32(10_000_000.0)
        .unwrap()
        .put_f64(0.0000001)
        .unwrap();
    assert_eq!(
        structure_prediction::expression_from_structure(&floats, "ffd", None)
            .unwrap()
            .as_bytes(),
        expression::parse_hex(observed["floats"]).unwrap()
    );
}
