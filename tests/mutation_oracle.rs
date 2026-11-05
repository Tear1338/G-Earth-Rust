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
}
