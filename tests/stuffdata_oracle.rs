use gearth_rust::{
    expression,
    packet::Packet,
    parsers::stuffdata::{HighScoreEntry, StuffData, StuffValue},
};
use std::collections::BTreeMap;

#[test]
#[ignore = "requires the actual beta-29 Java API oracle"]
fn all_stuff_data_wire_formats_match_original_java() {
    let path = std::env::var("GEARTH_STUFF_ORACLE").expect("Java oracle path required");
    let text = std::fs::read_to_string(path).unwrap();
    let observed: BTreeMap<_, _> = text
        .lines()
        .map(|line| {
            let (key, value) = line.split_once('=').unwrap();
            (key, expression::parse_hex(value).unwrap())
        })
        .collect();
    let values = [
        ("legacy", StuffValue::Legacy("1".into())),
        (
            "map",
            StuffValue::Map(BTreeMap::from([("state".into(), "2".into())])),
        ),
        ("strings", StuffValue::Strings(vec!["a".into()])),
        (
            "vote",
            StuffValue::Vote {
                state: "x".into(),
                result: 3,
            },
        ),
        ("empty", StuffValue::Empty),
        ("integers", StuffValue::Integers(vec![1, -2])),
        (
            "highscore",
            StuffValue::HighScore {
                state: "x".into(),
                score_type: 1,
                clear_type: 2,
                entries: vec![HighScoreEntry {
                    score: 7,
                    users: vec!["Alice".into()],
                }],
            },
        ),
        (
            "crackable",
            StuffValue::Crackable {
                state: "z".into(),
                hits: 4,
                target: 5,
            },
        ),
    ];
    for (name, value) in values {
        let serial = if matches!(value, StuffValue::HighScore { .. }) {
            None
        } else {
            Some((13, 20))
        };
        let expected = StuffData {
            flags: 256,
            serial,
            value,
        };
        let mut packet = Packet::new(1);
        expected.append(&mut packet).unwrap();
        assert_eq!(packet.bytes(), observed[name], "{name}");
        let mut from_java = Packet::from_bytes(observed[name].clone()).unwrap();
        assert_eq!(StuffData::read(&mut from_java).unwrap(), expected, "{name}");
    }
}
