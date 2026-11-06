use gearth_rust::{expression, packet::Packet};
use std::collections::BTreeMap;

#[test]
#[ignore = "requires the beta-29 Java API mutation oracle"]
fn mutations_match_original_java_packets_and_cursor() {
    let input = std::fs::read_to_string(std::env::var("GEARTH_MUTATION_ORACLE").unwrap()).unwrap();
    let expected: BTreeMap<_, _> = input
        .lines()
        .map(|line| line.split_once('=').unwrap())
        .collect();
    let check = |name: &str, packet: &Packet| {
        let (hex, cursor) = expected[name].split_once(',').unwrap();
        assert_eq!(
            packet.bytes(),
            expression::parse_hex(hex).unwrap(),
            "{name}"
        );
        assert_eq!(packet.cursor(), cursor.parse::<usize>().unwrap(), "{name}");
    };
    let mut fixed = Packet::new(1);
    fixed
        .put_i32(123)
        .unwrap()
        .put_bool(false)
        .unwrap()
        .put_u16(7)
        .unwrap()
        .put_i64(8)
        .unwrap()
        .put_f32(1.5)
        .unwrap()
        .put_f64(2.5)
        .unwrap();
    fixed.set_cursor(10).unwrap();
    fixed
        .replace_i32(6, -77)
        .unwrap()
        .replace_bool(10, true)
        .unwrap()
        .replace_u16(11, 65000)
        .unwrap()
        .replace_i64(13, -9999999999)
        .unwrap()
        .replace_f32(21, -3.25)
        .unwrap()
        .replace_f64(25, 0.125)
        .unwrap();
    check("fixed", &fixed);
    for (name, original, replacement) in [
        ("growth", "cat", "caterpillar"),
        ("shrink", "elephant", "x"),
    ] {
        let mut packet = Packet::new(2);
        packet
            .put_string(original)
            .unwrap()
            .put_i32(42)
            .unwrap()
            .put_string("end")
            .unwrap();
        packet.set_cursor(7).unwrap();
        packet.replace_string(6, replacement).unwrap();
        check(name, &packet);
    }
    let mut strings = Packet::new(3);
    strings
        .put_string("cat")
        .unwrap()
        .put_i32(123)
        .unwrap()
        .put_string("cat")
        .unwrap()
        .put_string("dog")
        .unwrap()
        .put_string("cat")
        .unwrap();
    strings.set_cursor(8).unwrap();
    assert_eq!(
        strings.replace_strings("cat", "longer", Some(2)).unwrap(),
        2
    );
    check("strings", &strings);
    let mut integers = Packet::new(4);
    integers
        .put_u8(42)
        .unwrap()
        .put_i32(123456)
        .unwrap()
        .put_i32(123456)
        .unwrap()
        .put_u8(10)
        .unwrap();
    integers.set_cursor(7).unwrap();
    assert_eq!(integers.replace_all_i32(123456, -7).unwrap(), 2);
    check("integers", &integers);
    for limit in [1, 2, -1] {
        let mut packet = Packet::new(9);
        packet
            .put_string("cat cat")
            .unwrap()
            .put_string("catdog")
            .unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_literal(
                "cat",
                "hello",
                if limit == -1 {
                    None
                } else {
                    Some(limit as usize)
                },
            )
            .unwrap();
        check(&format!("substring_{limit}"), &packet);
    }
    let mut empty_growth = Packet::new(5);
    empty_growth
        .put_string("")
        .unwrap()
        .put_string("a")
        .unwrap();
    empty_growth.set_cursor(7).unwrap();
    empty_growth.replace_string(6, "x").unwrap();
    let (java_hex, _) = expected["empty_growth_original"].split_once(',').unwrap();
    assert_ne!(
        empty_growth.bytes(),
        expression::parse_hex(java_hex).unwrap()
    );
    empty_growth.reset();
    assert_eq!(empty_growth.read_string().unwrap(), "x");
    assert_eq!(empty_growth.read_string().unwrap(), "a");
    let mut utf8 = Packet::new(6);
    utf8.put_utf8("café 🐱")
        .unwrap()
        .put_utf8_long("水🪶")
        .unwrap();
    check("utf8", &utf8);
    let mut utf8_replacement = Packet::new(7);
    utf8_replacement
        .put_utf8("cat")
        .unwrap()
        .put_i32(42)
        .unwrap();
    utf8_replacement.set_cursor(7).unwrap();
    utf8_replacement.replace_utf8(6, "雪🐱").unwrap();
    check("utf8_replacement", &utf8_replacement);
    let mut utf16 = Packet::new(8);
    let encode_utf16 =
        |text: &str| -> Vec<u8> { text.encode_utf16().flat_map(u16::to_be_bytes).collect() };
    utf16
        .put_short_bytes(&encode_utf16("Aé水"))
        .unwrap()
        .put_i32(42)
        .unwrap();
    check("utf16", &utf16);
    utf16.set_cursor(7).unwrap();
    utf16.replace_short_bytes(6, &encode_utf16("Z猫")).unwrap();
    check("utf16_replacement", &utf16);
    let mut utf16_long = Packet::new(9);
    let encoded = encode_utf16("水🐱");
    utf16_long
        .put_long_bytes(&encoded)
        .unwrap()
        .put_i32(123)
        .unwrap();
    check("utf16_long", &utf16_long);
    utf16_long.reset();
    assert_eq!(utf16_long.read_long_bytes().unwrap(), encoded);
    assert_eq!(utf16_long.read_i32().unwrap(), 123);
    let values = ["", "a", "abc", "é"];
    let old_values = ["a", "abc", "é"];
    let limits = [Some(0), Some(1), Some(2), None];
    for (old_index, old) in old_values.iter().enumerate() {
        for (new_index, new) in values.iter().enumerate() {
            for (limit_index, limit) in limits.iter().enumerate() {
                let mut sample = Packet::new(5);
                sample
                    .put_string("")
                    .unwrap()
                    .put_string("a")
                    .unwrap()
                    .put_i32(1)
                    .unwrap()
                    .put_string("abc")
                    .unwrap()
                    .put_string("é")
                    .unwrap()
                    .put_string("a")
                    .unwrap()
                    .put_string("")
                    .unwrap();
                sample.set_cursor(7).unwrap();
                sample.replace_strings(old, new, *limit).unwrap();
                check(
                    &format!("strings_{old_index}_{new_index}_{limit_index}"),
                    &sample,
                );
            }
        }
    }
}
