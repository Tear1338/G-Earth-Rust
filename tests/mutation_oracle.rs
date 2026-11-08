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
    let cases = [
        "eda080", "eda041", "eda0", "eda0ff", "edbf80", "ed9f80", "f0808080", "e08080", "f4908080",
        "e282", "e28241", "c080", "80",
    ];
    for (i, value) in cases.iter().enumerate() {
        let mut p = Packet::new(18);
        p.put_short_bytes(&expression::parse_hex(value).unwrap())
            .unwrap();
        let java = expression::parse_hex(expected[format!("utf8_case_{i}").as_str()]).unwrap();
        assert_eq!(p.read_utf8_lossy_at(6).unwrap().as_bytes(), java, "{value}");
        assert_eq!(p.read_utf8_lossy().unwrap().as_bytes(), java, "{value}");
    }
    for first in 0u8..=255 {
        for second in 0u8..=255 {
            let mut p = Packet::new(18);
            p.put_short_bytes(&[first, second]).unwrap();
            let key = format!(
                "utf8_pair_{}",
                usize::from(first) * 256 + usize::from(second)
            );
            let java = expression::parse_hex(expected[key.as_str()]).unwrap();
            assert_eq!(
                p.read_utf8_lossy().unwrap().as_bytes(),
                java,
                "{first:02x}{second:02x}"
            );
        }
    }
    for length in [0, 1, 255, 256, 32767, 65535] {
        let pattern = [0x61, 0xed, 0xa0, 0x80, 0xc3, 0xa9, 0xff];
        let bytes: Vec<_> = (0..length).map(|i| pattern[i % pattern.len()]).collect();
        let mut p = Packet::new(18);
        p.put_short_bytes(&bytes).unwrap();
        let key = format!("utf8_length_{length}");
        let java = expression::parse_hex(expected[key.as_str()]).unwrap();
        assert_eq!(
            p.read_utf8_lossy_at(6).unwrap().as_bytes(),
            java,
            "length {length}"
        );
        assert_eq!(p.cursor(), 6);
        assert_eq!(
            p.read_utf8_lossy().unwrap().as_bytes(),
            java,
            "length {length}"
        );
    }
    let mut state = 0x1234_5678u32;
    for case_index in 0..20_000 {
        let mut bytes = vec![0; 3 + case_index % 10];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        let mut p = Packet::new(18);
        p.put_short_bytes(&bytes).unwrap();
        let key = format!("utf8_mixed_{case_index}");
        let java = expression::parse_hex(expected[key.as_str()]).unwrap();
        assert_eq!(
            p.read_utf8_lossy().unwrap().as_bytes(),
            java,
            "case {case_index}, bytes {bytes:02x?}"
        );
    }
    let tails = [0x00, 0x7f, 0x80, 0x9f, 0xa0, 0xbf, 0xc0, 0xff];
    let mut boundary_index = 0;
    for lead in [0xe0, 0xed, 0xf0, 0xf4] {
        for second in 0u8..=255 {
            for third in tails {
                let fourths: &[u8] = if lead < 0xf0 { &[0] } else { &tails };
                for fourth in fourths {
                    let mut bytes = vec![lead, second, third];
                    if lead >= 0xf0 {
                        bytes.push(*fourth);
                    }
                    let mut p = Packet::new(18);
                    p.put_short_bytes(&bytes).unwrap();
                    let key = format!("utf8_boundary_{boundary_index}");
                    let java = expression::parse_hex(expected[key.as_str()]).unwrap();
                    assert_eq!(
                        p.read_utf8_lossy().unwrap().as_bytes(),
                        java,
                        "boundary {boundary_index}, bytes {bytes:02x?}"
                    );
                    boundary_index += 1;
                }
            }
        }
    }
    let mut malformed = Packet::new(16);
    malformed
        .put_short_bytes(&[0xe2, 0x82, 0x41])
        .unwrap()
        .put_long_bytes(&[0xff, 0x61])
        .unwrap();
    malformed.set_cursor(7).unwrap();
    let parts: Vec<_> = expected["utf8_malformed"].split(',').collect();
    assert_eq!(
        malformed.read_utf8_lossy_at(6).unwrap().as_bytes(),
        expression::parse_hex(parts[0]).unwrap()
    );
    assert_eq!(
        malformed.read_utf8_long_lossy_at(11).unwrap().as_bytes(),
        expression::parse_hex(parts[1]).unwrap()
    );
    assert_eq!(malformed.cursor(), parts[2].parse::<usize>().unwrap());
    malformed.set_cursor(6).unwrap();
    assert_eq!(
        malformed.read_utf8_lossy().unwrap().as_bytes(),
        expression::parse_hex(parts[0]).unwrap()
    );
    assert_eq!(
        malformed.read_utf8_long_lossy().unwrap().as_bytes(),
        expression::parse_hex(parts[1]).unwrap()
    );
    let mut utf = Packet::new(15);
    utf.put_utf8("Café 🐱")
        .unwrap()
        .put_utf8_long("éclair")
        .unwrap();
    utf.set_cursor(7).unwrap();
    let parts: Vec<_> = expected["utf8_offsets"].split(',').collect();
    assert_eq!(
        utf.read_utf8_at(6).unwrap().as_bytes(),
        expression::parse_hex(parts[0]).unwrap()
    );
    assert_eq!(
        utf.read_utf8_long_at(18).unwrap().as_bytes(),
        expression::parse_hex(parts[1]).unwrap()
    );
    assert_eq!(utf.cursor(), parts[2].parse::<usize>().unwrap());
    let mut bytes = Packet::new(14);
    for n in [i8::MIN, -1, 0, i8::MAX] {
        bytes.put_i8(n).unwrap();
    }
    bytes.set_cursor(7).unwrap();
    bytes.replace_i8(7, -42).unwrap();
    assert_eq!(
        format!(
            "{},{},{},{},{}",
            bytes.read_i8_at(6).unwrap(),
            bytes.read_i8_at(7).unwrap(),
            bytes.read_i8_at(8).unwrap(),
            bytes.read_i8_at(9).unwrap(),
            bytes.cursor()
        ),
        expected["signed_bytes"]
    );
    check("signed_byte_packet", &bytes);
    let mut shorts = Packet::new(13);
    for n in [i16::MIN, -1, 0, i16::MAX] {
        shorts.put_i16(n).unwrap();
    }
    shorts.set_cursor(8).unwrap();
    shorts.replace_i16(8, -1234).unwrap();
    assert_eq!(
        format!(
            "{},{},{},{},{}",
            shorts.read_i16_at(6).unwrap(),
            shorts.read_i16_at(8).unwrap(),
            shorts.read_i16_at(10).unwrap(),
            shorts.read_i16_at(12).unwrap(),
            shorts.cursor()
        ),
        expected["signed_shorts"]
    );
    check("signed_short_bytes", &shorts);
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
    let mut raw_bytes = Packet::new(10);
    raw_bytes.append(&[0, 1, 2, 3, 4, 5]).unwrap();
    raw_bytes.set_cursor(8).unwrap();
    raw_bytes.replace_bytes(7, &[0xff, 0x80, 42]).unwrap();
    check("fixed_bytes", &raw_bytes);
    let mut random = Packet::new(77);
    random
        .put_u8(0xff)
        .unwrap()
        .put_u16(65000)
        .unwrap()
        .put_i32(-123456)
        .unwrap()
        .put_i64(-9000000000)
        .unwrap()
        .put_f32(-3.25)
        .unwrap()
        .put_f64(0.125)
        .unwrap()
        .put_string("cafe")
        .unwrap()
        .put_long_string("long")
        .unwrap();
    random.set_cursor(8).unwrap();
    let result = format!(
        "{},{},{},{},{},{},{},{},{},{},{}",
        random.read_u8_at(6).unwrap(),
        random.read_bool_at(6).unwrap(),
        random.read_u16_at(7).unwrap(),
        random.read_i32_at(9).unwrap(),
        random.read_i64_at(13).unwrap(),
        random.read_f32_at(21).unwrap(),
        random.read_f64_at(25).unwrap(),
        random.read_string_at(33).unwrap(),
        random.read_long_string_at(39).unwrap(),
        random.read_i32_at(0).unwrap(),
        random.cursor()
    );
    assert_eq!(result, expected["random_reads"]);
    let mut skipped = Packet::new(11);
    skipped
        .put_i32(42)
        .unwrap()
        .put_string("hello")
        .unwrap()
        .put_u8(4)
        .unwrap()
        .put_bool(true)
        .unwrap()
        .put_u16(1234)
        .unwrap()
        .put_i64(123456789)
        .unwrap()
        .put_f64(2.5)
        .unwrap();
    skipped.skip_structure("i s?bBul d").unwrap();
    assert_eq!(
        format!(
            "{},{}",
            skipped.cursor(),
            u8::from(skipped.remaining() == 0)
        ),
        expected["skip_full"]
    );
    let mut partial = Packet::new(12);
    partial.put_i32(42).unwrap();
    assert!(partial.skip_structure("ib").is_err());
    // Java increments its cursor before the failed byte read; Rust keeps its
    // cursor inside the packet, after the successfully skipped integer.
    assert_eq!(expected["skip_partial"], "11,2");
    assert_eq!(partial.cursor(), 10);
    assert_eq!(partial.remaining(), 0);
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
