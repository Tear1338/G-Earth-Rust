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
    use gearth_rust::packet::PacketField;
    let mut objects = Packet::new(19);
    objects
        .append_fields(&[
            PacketField::Byte(-42),
            PacketField::Short(-1234),
            PacketField::Integer(-123456),
            PacketField::Long(-9000000000),
            PacketField::Float(-3.25),
            PacketField::Double(0.125),
            PacketField::Boolean(true),
            PacketField::String("Café"),
        ])
        .unwrap();
    objects.set_cursor(7).unwrap();
    check("append_objects", &objects);
    let mut latin1_java = Packet::new(20);
    latin1_java
        .put_string_java("Aé雪🐱B")
        .unwrap()
        .put_long_string_java("水🪶é")
        .unwrap()
        .put_i32(42)
        .unwrap();
    latin1_java.set_cursor(7).unwrap();
    check("latin1_java", &latin1_java);
    latin1_java.replace_string_java(6, "🐱雪é").unwrap();
    check("latin1_java_replaced", &latin1_java);
    let mut chunk = String::new();
    let mut chunk_index = 0;
    let mut count = 0;
    for codepoint in 0..=0x10ffff {
        if let Some(character) = char::from_u32(codepoint) {
            chunk.push(character);
            count += 1;
            if count % 4096 == 0 {
                let mut sample = Packet::new(21);
                sample.put_string_java(&chunk).unwrap();
                check(&format!("latin1_scalar_{chunk_index}"), &sample);
                chunk.clear();
                chunk_index += 1;
            }
        }
    }
    if !chunk.is_empty() {
        let mut sample = Packet::new(21);
        sample.put_string_java(&chunk).unwrap();
        check(&format!("latin1_scalar_{chunk_index}"), &sample);
    }
    let mut limit = Packet::new(22);
    limit.put_string_java(&"🐱".repeat(65535)).unwrap();
    check("latin1_limit_65535", &limit);
    assert!(Packet::new(22)
        .put_string_java(&"🐱".repeat(65536))
        .is_err());
    let java_overflow =
        expression::parse_hex(expected["latin1_limit_65536"].split_once(',').unwrap().0).unwrap();
    assert_eq!(java_overflow.len(), 65544);
    assert_eq!(&java_overflow[6..8], &[0, 0]);
    let malformed = [
        "d8000041",
        "d800d800dc00",
        "dc00",
        "d800",
        "d80000",
        "004100",
        "dc00dc00",
        "d800dc00",
        "feff0041",
        "fffe0041",
    ];
    for (i, hex) in malformed.iter().enumerate() {
        let mut sample = Packet::new(23);
        sample
            .put_short_bytes(&expression::parse_hex(hex).unwrap())
            .unwrap();
        let java = expression::parse_hex(expected[format!("utf16_case_{i}").as_str()]).unwrap();
        assert_eq!(
            sample.read_utf16be_at(6, true).unwrap().as_bytes(),
            java,
            "{hex}"
        );
        assert_eq!(sample.cursor(), 6);
        assert_eq!(sample.read_utf16be(true).unwrap().as_bytes(), java, "{hex}");
    }
    for unit in 0u16..=u16::MAX {
        let mut sample = Packet::new(23);
        sample.put_short_bytes(&unit.to_be_bytes()).unwrap();
        let java = expression::parse_hex(expected[format!("utf16_unit_{unit}").as_str()]).unwrap();
        assert_eq!(
            sample.read_utf16be(true).unwrap().as_bytes(),
            java,
            "unit {unit:04x}"
        );
    }
    for i in 0..10000 {
        let (hex, java) = expected[format!("utf16_random_{i}").as_str()]
            .split_once(',')
            .unwrap();
        let mut sample = Packet::new(23);
        sample
            .put_short_bytes(&expression::parse_hex(hex).unwrap())
            .unwrap();
        assert_eq!(
            sample.read_utf16be(true).unwrap().as_bytes(),
            expression::parse_hex(java).unwrap(),
            "random {i} {hex}"
        );
    }
    use gearth_rust::packet::Utf16Encoding;
    for (i, value) in ["", "A", "🐱", "\u{feff}A"].iter().enumerate() {
        for (encoding, key) in [
            (Utf16Encoding::LittleEndian, "utf16le_encoded"),
            (Utf16Encoding::WithBom, "utf16bom_encoded"),
        ] {
            let mut sample = Packet::new(24);
            sample
                .put_utf16(value, encoding)
                .unwrap()
                .put_utf16_long(value, encoding)
                .unwrap();
            check(&format!("{key}_{i}"), &sample);
            assert_eq!(sample.read_utf16(encoding, false).unwrap(), *value);
            assert_eq!(sample.read_utf16_long(encoding, false).unwrap(), *value);
        }
    }
    for i in 0..10009 {
        let parts: Vec<_> = expected[format!("utf16variant_{i}").as_str()]
            .split(',')
            .collect();
        let mut sample = Packet::new(24);
        sample
            .put_short_bytes(&expression::parse_hex(parts[0]).unwrap())
            .unwrap();
        for (encoding, expected_hex) in [
            (Utf16Encoding::LittleEndian, parts[1]),
            (Utf16Encoding::WithBom, parts[2]),
        ] {
            assert_eq!(
                sample.read_utf16_at(6, encoding, true).unwrap().as_bytes(),
                expression::parse_hex(expected_hex).unwrap(),
                "variant {i} {:?}",
                encoding
            );
        }
    }
    use gearth_rust::packet::JavaStringEncoding;
    for i in 0..4103 {
        let fields: Vec<_> = expected[format!("java_units_{i}").as_str()]
            .split(',')
            .collect();
        let input = expression::parse_hex(fields[0]).unwrap();
        let units: Vec<_> = input
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_be_bytes(*b))
            .collect();
        let encodings = [
            JavaStringEncoding::Latin1,
            JavaStringEncoding::Utf8,
            JavaStringEncoding::Utf16(Utf16Encoding::BigEndian),
            JavaStringEncoding::Utf16(Utf16Encoding::LittleEndian),
            JavaStringEncoding::Utf16(Utf16Encoding::WithBom),
        ];
        for (index, encoding) in encodings.iter().enumerate() {
            let mut sample = Packet::new(25);
            sample.put_java_units(&units, *encoding).unwrap();
            assert_eq!(
                sample.read_short_bytes_at(6).unwrap(),
                expression::parse_hex(fields[index + 1]).unwrap(),
                "units {i}, {encoding:?}"
            );
        }
    }
    let mut utf8_boundary = Packet::new(25);
    utf8_boundary.put_utf8(&"a".repeat(65535)).unwrap();
    check("utf8_limit_65535", &utf8_boundary);
    assert!(Packet::new(25).put_utf8(&"a".repeat(65536)).is_err());
    let java_overflow =
        expression::parse_hex(expected["utf8_limit_65536"].split_once(',').unwrap().0).unwrap();
    assert_eq!(&java_overflow[6..8], &[0, 0]);
    let mut multi = Packet::new(25);
    multi.put_utf8(&"€".repeat(21845)).unwrap();
    check("utf8_limit_multibyte", &multi);
    assert!(Packet::new(25).put_utf8(&"€".repeat(21846)).is_err());
    let units = [b'A' as u16, 0xd800, b'B' as u16, 0xdc00, 0xd800, 0xdc00];
    for (i, encoding) in [
        Utf16Encoding::BigEndian,
        Utf16Encoding::LittleEndian,
        Utf16Encoding::WithBom,
    ]
    .iter()
    .enumerate()
    {
        let mut replacement = Packet::new(26);
        replacement
            .put_utf16("cat", *encoding)
            .unwrap()
            .put_i32(42)
            .unwrap();
        replacement.set_cursor(7).unwrap();
        replacement
            .replace_java_units(6, &units, JavaStringEncoding::Utf16(*encoding))
            .unwrap();
        check(&format!("utf16_units_replace_{i}"), &replacement);
        let mut long = Packet::new(26);
        long.put_java_units_long(
            &vec![b'a' as u16; 32768],
            JavaStringEncoding::Utf16(*encoding),
        )
        .unwrap();
        check(&format!("utf16_units_long_{i}"), &long);
        for length in [32766, 32767, 32768] {
            let mut short = Packet::new(26);
            let input = vec![b'a' as u16; length];
            let java_key = format!("utf16_short_{i}_{length}");
            if length * 2 + usize::from(*encoding == Utf16Encoding::WithBom) * 2 <= 65535 {
                short
                    .put_java_units(&input, JavaStringEncoding::Utf16(*encoding))
                    .unwrap();
                check(&java_key, &short);
            } else {
                assert!(short
                    .put_java_units(&input, JavaStringEncoding::Utf16(*encoding))
                    .is_err());
                let java =
                    expression::parse_hex(expected[java_key.as_str()].split_once(',').unwrap().0)
                        .unwrap();
                assert_eq!(
                    u16::from_be_bytes([java[6], java[7]]) as usize,
                    (java.len() - 8) % 65536
                );
            }
        }
    }
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
    let templates = [
        "x$0y", "\\$", "\\\\", "$00", "$01", "$1", "$", "\\", "$$", "a\\qb",
    ];
    for (i, template) in templates.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet
            .put_string("cat cat")
            .unwrap()
            .put_string("catdog")
            .unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_template_{i}");
        match packet.replace_substrings_java_literal("cat", template, Some(1)) {
            Ok(count) => {
                assert_eq!(count, 1);
                check(&key, &packet);
            }
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let groups = [
        ("(cat) cat", "(cat)", "[$1]", Some(1)),
        ("(cat) cat", "(cat)", "$0/$1/$01/$10", None),
        ("(cat) cat", "(cat)", "\\$\\\\", Some(1)),
        ("(cat) cat", "(cat)", "$2", Some(1)),
        ("cat cat", "(cat)", "$2", Some(1)),
        ("(a) aaaa", "(a)", "x", None),
        ("(é) é", "(é)", "[$1]", Some(1)),
        ("(cat) cat", "(cat)", "$", Some(0)),
    ];
    for (i, (value, pattern, replacement, limit)) in groups.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_group_{i}");
        match packet.replace_substrings_java_group(pattern, replacement, *limit) {
            Ok(_) => check(&key, &packet),
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let multi_groups = [
        ("a(b)c abc", "a(b)c", "[$0:$1]", None),
        ("a(b)c", "a(b)c", "$2", Some(1)),
        ("a(b)c abc", "a(b)c", "$2", Some(1)),
        ("(ab)(cd) abcd", "(ab)(cd)", "$2-$1-$0-$12", Some(1)),
        ("x(a)y(b)z xaybz", "x(a)y(b)z", "$01/$02/$00", None),
        ("x(a)y(b)z", "x(a)y(b)z", "\\$", Some(1)),
        ("ordinary text", "a(b)c", "$2", Some(1)),
        ("a(b)c abc", "a(b)c", "$", Some(0)),
    ];
    for (i, (value, pattern, replacement, limit)) in multi_groups.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_multi_{i}");
        match packet.replace_substrings_java_groups(pattern, replacement, *limit) {
            Ok(_) => check(&key, &packet),
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let nested_groups = [
        ("(a\\.b) a.b", "(a\\.b)", "<$1>", Some(1)),
        ("((ab)c) abc", "((ab)c)", "$1/$2/$0", None),
        ("a()b ab", "a()b", "<$1>", Some(1)),
        ("(a()) a", "(a())", "$1/$2", Some(1)),
        ("a(\\()b a(b", "a(\\()b", "[$1]", Some(1)),
        ("((ab)c)", "((ab)c)", "$3", Some(1)),
    ];
    for (i, (value, pattern, replacement, limit)) in nested_groups.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_nested_{i}");
        match packet.replace_substrings_java_groups(pattern, replacement, *limit) {
            Ok(_) => check(&key, &packet),
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let zero_groups = [
        ("()", "()", "x", Some(1)),
        ("é()a", "()", "-", Some(1)),
        ("(())", "(())", "$1/$2", Some(1)),
        ("()", "()", "$2", Some(1)),
        ("abc", "()", "$2", Some(1)),
        ("()", "()", "$", Some(0)),
    ];
    for (i, (value, pattern, replacement, limit)) in zero_groups.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_zero_{i}");
        match packet.replace_substrings_java_groups(pattern, replacement, *limit) {
            Ok(_) => check(&key, &packet),
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let quoted_groups = [
        ("(\\Q(a+b)\\E) (a+b)", "(\\Q(a+b)\\E)", "[$1]", Some(1)),
        ("(\\Qx.y\\E) x.y", "(\\Qx.y\\E)", "$0:$1", Some(1)),
        ("(cat)\\Qx catx", "(cat)\\Qx", "<$1>", Some(1)),
        ("(\\Q\\E) x", "(\\Q\\E)", "-", Some(1)),
        ("(\\Q(a+b)\\E)", "(\\Q(a+b)\\E)", "$2", Some(1)),
    ];
    for (i, (value, pattern, replacement, limit)) in quoted_groups.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_quoted_{i}");
        match packet.replace_substrings_java_groups(pattern, replacement, *limit) {
            Ok(_) => check(&key, &packet),
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let named_groups = [
        ("(?<pet>cat) cat", "(?<pet>cat)", "${pet}-$1-$0", Some(1)),
        (
            "(?<all>x(?<inner>y)) xy",
            "(?<all>x(?<inner>y))",
            "${inner}/${all}/$2",
            Some(1),
        ),
        ("(?<empty>)", "(?<empty>)", "[${empty}]", Some(1)),
        ("(?<pet>cat) cat", "(?<pet>cat)", "${missing}", Some(1)),
        ("(?<pet>cat)", "(?<pet>cat)", "${missing}", Some(1)),
        ("(?<pet>cat) cat", "(?<pet>cat)", "${pet}0", Some(1)),
    ];
    for (i, (value, pattern, replacement, limit)) in named_groups.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_named_{i}");
        match packet.replace_substrings_java_groups(pattern, replacement, *limit) {
            Ok(_) => check(&key, &packet),
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let dot_groups = [
        ("(c.t) cat cot c.t", "(c.t)", "[$1]", Some(1)),
        ("x(.)y xay xéy x\ny", "x(.)y", "$1:$0", Some(1)),
        ("(?<g>.) a\rb\nc\u{85}d", "(?<g>.)", "${g}", Some(1)),
        ("x(.)y x\ny", "x(.)y", "$9", Some(1)),
        ("(c.t) cat", "(c.t)", "$2", Some(1)),
    ];
    for (i, (value, pattern, replacement, limit)) in dot_groups.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_dot_{i}");
        match packet.replace_substrings_java_groups(pattern, replacement, *limit) {
            Ok(_) => check(&key, &packet),
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let dot_patterns = ["(.)", "(a.)", "a(.)b", "(.)(.)", "(?<one>.)(?<two>.)"];
    let dot_alphabet = ['a', 'b', '.', '\n', '\r', '\u{85}', 'é', '(', ')'];
    for i in 0..120 {
        let pattern = dot_patterns[i % dot_patterns.len()];
        let mut value = format!("{pattern} ");
        for j in 0..24 {
            value.push(dot_alphabet[(i * 7 + j * 5) % dot_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_dot_corpus_{i}"), &packet);
    }
    let class_groups = [
        ("([abc]) a b c d", "([abc])", "<$1>", Some(1)),
        ("x([a-c])y xay xby xdy", "x([a-c])y", "$1:$0", Some(1)),
        ("([^a]) a é\n", "([^a])", "[$1]", Some(1)),
        ("([é-ÿ]) é ç z", "([é-ÿ])", "[$1]", Some(1)),
        ("([\\-\\]]) - ] a", "([\\-\\]])", "<$1>", Some(1)),
        ("([a-c]) abc", "([a-c])", "$2", Some(1)),
        ("x([a])y xby", "x([a])y", "$9", Some(1)),
    ];
    for (i, (value, pattern, replacement, limit)) in class_groups.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_class_{i}");
        match packet.replace_substrings_java_groups(pattern, replacement, *limit) {
            Ok(_) => check(&key, &packet),
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let class_patterns = ["([abc])", "x([a-c])y", "([^a])", "([é-ÿ])", "([\\-\\]])"];
    let class_alphabet = [
        'a', 'b', 'c', 'd', 'x', 'y', 'é', 'ÿ', '-', ']', '\n', '\u{85}',
    ];
    for i in 0..120 {
        let pattern = class_patterns[i % class_patterns.len()];
        let mut value = format!("{pattern} ");
        for j in 0..28 {
            value.push(class_alphabet[(i * 7 + j * 5) % class_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_class_corpus_{i}"), &packet);
    }
    let predefined_patterns = ["(\\d)", "(\\D)", "(\\w)", "(\\W)", "(\\s)", "(\\S)"];
    let predefined_alphabet = [
        'a', 'Z', '0', '9', '_', 'é', 'ÿ', ' ', '\t', '\n', '\r', '\u{b}', '\u{c}', '\u{85}',
    ];
    for i in 0..120 {
        let pattern = predefined_patterns[i % predefined_patterns.len()];
        let mut value = format!("{pattern} ");
        for j in 0..28 {
            value.push(predefined_alphabet[(i * 7 + j * 5) % predefined_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_predefined_{i}"), &packet);
    }
    let union_groups = [
        ("([\\dA-F]) a 2 B é", "([\\dA-F])", "<$1>", Some(1)),
        ("([^\\w]) a é 9 _", "([^\\w])", "[$1]", Some(1)),
        ("([\\s\\d]) a 2 \n", "([\\s\\d])", "<$1>", Some(1)),
        ("([\\D]) a 2 é", "([\\D])", "[$1]", Some(1)),
        ("([a-\\d]) a 2", "([a-\\d])", "x", Some(1)),
        ("([\\d-a]) a 2", "([\\d-a])", "x", Some(1)),
    ];
    for (i, (value, pattern, replacement, limit)) in union_groups.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_union_{i}");
        match packet.replace_substrings_java_groups(pattern, replacement, *limit) {
            Ok(_) => check(&key, &packet),
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let union_patterns = [
        "([\\dA-F])",
        "([^\\w])",
        "([\\s\\d])",
        "([\\D])",
        "([\\d-a])",
    ];
    let union_alphabet = [
        'a', 'b', 'F', '9', '0', '_', 'é', '-', ' ', '\n', '\u{b}', '\u{85}',
    ];
    for i in 0..120 {
        let pattern = union_patterns[i % union_patterns.len()];
        let mut value = format!("{pattern} ");
        for j in 0..28 {
            value.push(union_alphabet[(i * 7 + j * 5) % union_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_union_corpus_{i}"), &packet);
    }
    let control_patterns = [
        "(\\n)",
        "([\\t\\x41])",
        "([\\u00e9])",
        "(\\a)",
        "(\\e)",
        "(\\f)",
        "([\\x30-\\x39])",
    ];
    let control_alphabet = [
        'a', 'A', '0', '9', 'é', 'ÿ', ' ', '\t', '\n', '\r', '\u{7}', '\u{1b}', '\u{c}',
    ];
    for i in 0..140 {
        let pattern = control_patterns[i % control_patterns.len()];
        let mut value = format!("{pattern} ");
        for j in 0..28 {
            value.push(control_alphabet[(i * 7 + j * 5) % control_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_control_corpus_{i}"), &packet);
    }
    let optional_groups = [
        ("(a?) a ab", "(a?)", "[$1]", Some(1)),
        ("(a??) a ab", "(a??)", "[$1]", Some(1)),
        ("x(a?)b xb xab", "x(a?)b", "$1/$0", Some(1)),
        ("x(a??)b xb xab", "x(a??)b", "$1/$0", Some(1)),
        ("x(.?)b xéb x\nb", "x(.?)b", "[$1]", Some(1)),
        ("(\\d?) 1 2", "(\\d?)", "<$1>", Some(1)),
        ("(a?)", "(a?)", "$2", Some(1)),
    ];
    for (i, (value, pattern, replacement, limit)) in optional_groups.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_optional_{i}");
        match packet.replace_substrings_java_groups(pattern, replacement, *limit) {
            Ok(_) => check(&key, &packet),
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let optional_patterns = [
        "(a?)", "(a??)", "x(a?)b", "x(a??)b", "x(.?)b", "(\\d?)", "([a-c]?)",
    ];
    let optional_alphabet = ['a', 'b', 'c', 'x', '1', 'é', '-', ' ', '\n', '\r', '\u{85}'];
    for i in 0..140 {
        let pattern = optional_patterns[i % optional_patterns.len()];
        let mut value = format!("{pattern} ");
        for j in 0..24 {
            value.push(optional_alphabet[(i * 7 + j * 5) % optional_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_optional_corpus_{i}"), &packet);
    }
    let backtrack_patterns = [
        "(a?ab)",
        "(a??ab)",
        "((a?)(b?))",
        "x(a?b??)c",
        "(?<both>a?b?)",
    ];
    let backtrack_alphabet = ['a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u{85}'];
    for i in 0..160 {
        let pattern = backtrack_patterns[i % backtrack_patterns.len()];
        let mut value = format!("{pattern} ab aab ");
        for j in 0..24 {
            value.push(backtrack_alphabet[(i * 7 + j * 5) % backtrack_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_backtrack_{i}"), &packet);
    }
    let optional_captures = [
        ("(a)? a b", "(a)?", "[$1]", Some(1)),
        ("(a)?? a b", "(a)??", "[$1]", Some(1)),
        ("x(ab)?c xc xabc", "x(ab)?c", "$1/$0", Some(1)),
        ("x(ab)??c xc xabc", "x(ab)??c", "$1/$0", Some(1)),
        ("x((a)b)?c xc xabc", "x((a)b)?c", "$1/$2/$0", Some(1)),
        ("()? x", "()?", "[$1]", Some(1)),
        ("(a)?", "(a)?", "$2", Some(1)),
    ];
    for (i, (value, pattern, replacement, limit)) in optional_captures.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_optional_capture_{i}");
        match packet.replace_substrings_java_groups(pattern, replacement, *limit) {
            Ok(_) => check(&key, &packet),
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let optional_capture_patterns = [
        "(a)?",
        "(a)??",
        "x(ab)?c",
        "x(ab)??ab",
        "x((a)b)?c",
        "(a)?(b)?",
        "()?",
    ];
    let optional_capture_alphabet = ['a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u{85}'];
    for i in 0..140 {
        let pattern = optional_capture_patterns[i % optional_capture_patterns.len()];
        let mut value = format!("{pattern} xc xabc xab ");
        for j in 0..24 {
            value
                .push(optional_capture_alphabet[(i * 7 + j * 5) % optional_capture_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_optional_capture_corpus_{i}"), &packet);
    }
    let overlapping_patterns = [
        "((a?)b)?",
        "((a)?)?",
        "x((a?)b)??c",
        "((a?)(b?))?",
        "(?<all>(?<one>a?)b?)?",
    ];
    let overlapping_alphabet = ['a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u{85}'];
    for i in 0..160 {
        let pattern = overlapping_patterns[i % overlapping_patterns.len()];
        let mut value = format!("{pattern} xc xabc xab ");
        for j in 0..24 {
            value.push(overlapping_alphabet[(i * 7 + j * 5) % overlapping_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$2/$0", Some(1))
            .unwrap();
        check(&format!("substring_overlapping_{i}"), &packet);
    }
    let repeat_groups = [
        ("(a*) aaa b", "(a*)", "[$1]", Some(1)),
        ("(a*?) aaa b", "(a*?)", "[$1]", Some(1)),
        ("(a+) aaa b", "(a+)", "[$1]", Some(1)),
        ("(a+?) aaa b", "(a+?)", "[$1]", Some(1)),
        ("x(a*)ab xaab xab", "x(a*)ab", "$1/$0", Some(1)),
        ("x(a*?)ab xaab xab", "x(a*?)ab", "$1/$0", Some(1)),
        ("(\\d*) 123 a", "(\\d*)", "<$1>", Some(1)),
        ("(.+) a\nb", "(.+)", "[$1]", Some(1)),
    ];
    for (i, (value, pattern, replacement, limit)) in repeat_groups.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_repeat_{i}");
        match packet.replace_substrings_java_groups(pattern, replacement, *limit) {
            Ok(_) => check(&key, &packet),
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let repeat_patterns = [
        "(a*)",
        "(a+?)",
        "x(a*)ab",
        "((a*)b)?",
        "x(\\d+)b",
        "((a*)b?)",
        "([ab]+)(a*)",
        "((a*)b*)",
    ];
    let repeat_alphabet = ['a', 'b', 'c', 'x', '0', '1', 'é', ' ', '\n', '\u{85}'];
    for i in 0..160 {
        let pattern = repeat_patterns[i % repeat_patterns.len()];
        let mut value = format!("{pattern} aaaa ab aaab xab xaab x123b ");
        for j in 0..24 {
            value.push(repeat_alphabet[(i * 7 + j * 3) % repeat_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_repeat_corpus_{i}"), &packet);
    }
    let bounded_groups = [
        ("(a{2}) a aaa", "(a{2})", "[$1]", Some(1)),
        ("(a{0}) a", "(a{0})", "[$1]", Some(1)),
        ("(a{1,3}) a aaaa", "(a{1,3})", "[$1]", Some(1)),
        ("(a{1,3}?) a aaaa", "(a{1,3}?)", "[$1]", Some(1)),
        ("x(a{2,}?)b xaab xaaab", "x(a{2,}?)b", "$1/$0", Some(1)),
        ("([a-c]{2,3}) abcd", "([a-c]{2,3})", "[$1]", Some(1)),
        ("(a{2,1}) aa", "(a{2,1})", "x", Some(1)),
        ("(a{2147483648}) aa", "(a{2147483648})", "x", Some(1)),
    ];
    for (i, (value, pattern, replacement, limit)) in bounded_groups.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_bounded_{i}");
        match packet.replace_substrings_java_groups(pattern, replacement, *limit) {
            Ok(_) => check(&key, &packet),
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let bounded_patterns = [
        "(a{0})",
        "(a{2})",
        "(a{1,3})",
        "(a{1,3}?)",
        "x(a{2,}?)b",
        "([a-c]{2,3})",
        "((a{1,2})b)?",
        "x(\\d{1,2})b",
    ];
    let bounded_alphabet = ['a', 'b', 'c', 'x', '0', '1', 'é', ' ', '\n', '\u{85}'];
    for i in 0..160 {
        let pattern = bounded_patterns[i % bounded_patterns.len()];
        let mut value = format!("{pattern} aaaa ab aaab xab xaab x123b ");
        for j in 0..24 {
            value.push(bounded_alphabet[(i * 7 + j * 3) % bounded_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_bounded_corpus_{i}"), &packet);
    }
    let repeated_capture_groups = [
        (0, "(ab)* abab x", "(ab)*", "[$1]"),
        (1, "(ab)+? ababab", "(ab)+?", "[$1]"),
        (5, "(ab){2,3} abababab", "(ab){2,3}", "<$1>"),
    ];
    for (index, value, pattern, replacement) in repeated_capture_groups {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, replacement, Some(1))
            .unwrap();
        check(&format!("substring_repeated_capture_{index}"), &packet);
    }
    let simple_repeat_group_patterns = [
        "(ab)*",
        "(ab)+?",
        "x(ab)*ab",
        "x([ab]){1,3}b",
        "(?<v>ab)+?",
        "(ab){0,2}",
    ];
    let simple_repeat_group_alphabet = ['a', 'b', 'c', 'x', '0', 'é', ' ', '\n', '\u{85}'];
    for i in 0..150 {
        let pattern = simple_repeat_group_patterns[i % simple_repeat_group_patterns.len()];
        let mut value = format!("{pattern} abab ababab xabab xab ");
        for j in 0..20 {
            value.push(
                simple_repeat_group_alphabet[(i * 7 + j * 3) % simple_repeat_group_alphabet.len()],
            );
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_simple_repeat_group_{i}"), &packet);
    }
    assert_eq!(expected["repeated_capture_retention"], "b,a");

    let fixed_nested_patterns = [
        "((a)b)*",
        "(x(?<inner>y))+",
        "((a)(b)){1,3}",
        "x((a)b)*c",
        "(((ab)))+",
    ];
    let fixed_nested_alphabet = ['a', 'b', 'c', 'x', 'y', 'é', ' ', '\n', '\u{85}'];
    for i in 0..150 {
        let pattern = fixed_nested_patterns[i % fixed_nested_patterns.len()];
        let mut value = format!("{pattern} abab xyxy xabc ");
        for j in 0..20 {
            value.push(fixed_nested_alphabet[(i * 7 + j * 3) % fixed_nested_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$2/$0", Some(1))
            .unwrap();
        check(&format!("substring_fixed_nested_repeat_{i}"), &packet);
    }
    for (index, value, pattern, replacement) in [
        (2, "((a)?b)* abb ab", "((a)?b)*", "$1/$2"),
        (3, "x((a)?b)+c xabbc", "x((a)?b)+c", "$1/$2/$0"),
    ] {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, replacement, Some(1))
            .unwrap();
        check(&format!("substring_repeated_capture_{index}"), &packet);
    }
    let retention_patterns = [
        "((a)?b)*",
        "((a)??b)*",
        "x((a)?b)+c",
        "((a)?b)*?",
        "((a)?b)+?",
        "((a)?b)*b",
        "((?<inner>a)?b)*ab",
        "((a)?b)+ab",
    ];
    let retention_alphabet = ['a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u{85}'];
    for i in 0..200 {
        let pattern = retention_patterns[i % retention_patterns.len()];
        let mut value = format!("{pattern} abb abbb xabbc bbb ab ");
        for j in 0..20 {
            value.push(retention_alphabet[(i * 7 + j * 3) % retention_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$2/$0", Some(1))
            .unwrap();
        check(&format!("substring_retention_corpus_{i}"), &packet);
    }
    let multi_retention_patterns = [
        "((a)?(b)?c)*",
        "((a)??(b)?c)*",
        "x((a)?(b)??c)+d",
        "((?<left>a)?(?<right>b)?c)*c",
        "((a)?x(b)?c)+?",
    ];
    let multi_retention_alphabet = ['a', 'b', 'c', 'd', 'x', 'é', ' ', '\n', '\u{85}'];
    for i in 0..200 {
        let pattern = multi_retention_patterns[i % multi_retention_patterns.len()];
        let mut value = format!("{pattern} ac bc c abc xacbcd ");
        for j in 0..20 {
            value.push(multi_retention_alphabet[(i * 7 + j * 3) % multi_retention_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$2/$3/$0", Some(1))
            .unwrap();
        check(&format!("substring_multi_retention_{i}"), &packet);
    }
    let nullable_patterns = [
        "((a)?(b)?)*",
        "((a)?(b)?)*?",
        "((a)??(b)?)+",
        "x((a)?(b)?)*b",
        "((?<left>a)?(?<right>b)?)+?",
        "x((a)?(b)??)+b",
    ];
    let nullable_alphabet = ['a', 'b', 'x', 'é', ' ', '\n', '\r', '\u{85}'];
    for i in 0..180 {
        let pattern = nullable_patterns[i % nullable_patterns.len()];
        let mut value = format!("{pattern} ab aa bb xab xb ");
        for j in 0..16 {
            value.push(nullable_alphabet[(i * 7 + j * 3) % nullable_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$2/$3/$0", Some(1))
            .unwrap();
        check(&format!("substring_nullable_repeat_{i}"), &packet);
    }
    let bounded_nested = [
        ("((a)?b){2} abb ab", "((a)?b){2}", "$1/$2/$0"),
        ("((a)?b){1,3} abbb", "((a)?b){1,3}", "$1/$2/$0"),
        ("((a)?b){1,3}? abbb", "((a)?b){1,3}?", "$1/$2/$0"),
        ("((a)?b){2,} abb ab", "((a)?b){2,}", "$1/$2/$0"),
        ("((a)?(b)?){2,4} ab", "((a)?(b)?){2,4}", "$1/$2/$3/$0"),
        ("((a)?(b)?){2,4}? ab", "((a)?(b)?){2,4}?", "$1/$2/$3/$0"),
        ("((a)?b){0} ab", "((a)?b){0}", "$1/$2/$0"),
    ];
    for (i, (value, pattern, replacement)) in bounded_nested.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, replacement, Some(1))
            .unwrap();
        check(&format!("substring_bounded_nested_{i}"), &packet);
    }
    let bounded_nested_patterns = [
        "((a)?b){2}",
        "((a)?b){1,3}",
        "((a)?b){1,3}?",
        "((a)?b){2,}",
        "((a)?(b)?){2,4}",
        "((a)?(b)?){2,4}?",
        "((a)?b){0}",
    ];
    let bounded_nested_alphabet = ['a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u{85}'];
    for i in 0..140 {
        let pattern = bounded_nested_patterns[i % bounded_nested_patterns.len()];
        let mut value = format!("{pattern} abb abbb ab bb a ");
        for j in 0..16 {
            value.push(bounded_nested_alphabet[(i * 7 + j * 3) % bounded_nested_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$2/$0", Some(1))
            .unwrap();
        check(&format!("substring_bounded_nested_corpus_{i}"), &packet);
    }
    let inner_repeat_patterns = [
        "((a*)?b)*",
        "((a+)?b)*",
        "((a{1,3})?b){2,3}",
        "((a+?)?b)*?",
        "x((a*)?b)+c",
        "(a*)*",
    ];
    let inner_repeat_alphabet = ['a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u{85}'];
    for i in 0..180 {
        let pattern = inner_repeat_patterns[i % inner_repeat_patterns.len()];
        let mut value = format!("{pattern} abb aaab b xabbc ");
        for j in 0..16 {
            value.push(inner_repeat_alphabet[(i * 7 + j * 3) % inner_repeat_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(
                pattern,
                if pattern == "(a*)*" {
                    "$1/$0"
                } else {
                    "$1/$2/$0"
                },
                Some(1),
            )
            .unwrap();
        check(&format!("substring_inner_repeat_{i}"), &packet);
    }
    let optional_atom_patterns = [
        "(a?)*",
        "(a??)*",
        "([ab]?)+",
        "(a?b?)*",
        "x(a?b?){2,3}c",
        "((a)?b?)*",
    ];
    let optional_atom_alphabet = ['a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u{85}'];
    for i in 0..180 {
        let pattern = optional_atom_patterns[i % optional_atom_patterns.len()];
        let mut value = format!("{pattern} ab aa bb xabc ");
        for j in 0..16 {
            value.push(optional_atom_alphabet[(i * 7 + j * 3) % optional_atom_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_optional_atom_repeat_{i}"), &packet);
    }
    let required_inner_patterns = [
        "((a?)b)*",
        "((a??)b)*",
        "((a?)?b)*",
        "((a?)(b?)c)*",
        "(x(a?)y(b?)z)+",
        "((a*)b)*",
        "((a+?)b){1,3}",
    ];
    let required_inner_alphabet = ['a', 'b', 'c', 'x', 'y', 'z', 'é', ' ', '\n', '\u{85}'];
    for i in 0..210 {
        let pattern = required_inner_patterns[i % required_inner_patterns.len()];
        let mut value = format!("{pattern} ab bb abc xyz ");
        for j in 0..16 {
            value.push(required_inner_alphabet[(i * 7 + j * 3) % required_inner_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$2/$0", Some(1))
            .unwrap();
        check(&format!("substring_required_inner_{i}"), &packet);
    }
    let deep_patterns = [
        "(((a)?)b)*",
        "((((a)?)?)b)*",
        "x(((a)?)b)+c",
        "(((a)?)b){2,3}?",
        "(((a*)?)b)*",
        "(((a)?)(b)?c)*",
    ];
    let deep_alphabet = ['a', 'b', 'c', 'x', 'é', ' ', '\n', '\r', '\u{85}'];
    for i in 0..180 {
        let pattern = deep_patterns[i % deep_patterns.len()];
        let mut value = format!("{pattern} abb abbb xabbc bb ");
        for j in 0..16 {
            value.push(deep_alphabet[(i * 7 + j * 3) % deep_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$2/$3/$0", Some(1))
            .unwrap();
        check(&format!("substring_deep_capture_{i}"), &packet);
    }
    let maximum_depth_pattern = format!("{}a?{}*", "(".repeat(99), ")".repeat(99));
    let mut maximum_depth = Packet::new(9);
    maximum_depth
        .put_string(&format!("{maximum_depth_pattern} a"))
        .unwrap();
    maximum_depth.set_cursor(7).unwrap();
    maximum_depth
        .replace_substrings_java_groups(&maximum_depth_pattern, "$99", Some(1))
        .unwrap();
    check("substring_maximum_depth", &maximum_depth);
    let anchors = [
        ("a ^(a)", "^(a)"),
        ("a \\A(a)", "\\A(a)"),
        ("(a)$a\n", "(a)$"),
        ("(a)$a\r\n", "(a)$"),
        ("(a)\\Za\u{85}", "(a)\\Z"),
        ("(a)\\za", "(a)\\z"),
        ("x($)", "x($)"),
        ("(^) value", "(^)"),
        ("(\\z) value", "(\\z)"),
        ("(a)$a\r", "(a)$"),
    ];
    for (i, (value, pattern)) in anchors.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_anchor_{i}"), &packet);
    }
    let anchor_patterns = [
        "^(a)", "\\A(a)", "(a)$", "(a)\\z", "(a)\\Z", "(.)$", "(^)", "(\\z)",
    ];
    let anchor_suffixes = ["", "\n", "\r\n", "\r", "\u{85}", "b"];
    for i in 0..144 {
        let pattern = anchor_patterns[i % anchor_patterns.len()];
        let value = format!(
            "a {pattern} a{}",
            anchor_suffixes[(i / anchor_patterns.len()) % anchor_suffixes.len()]
        );
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_anchor_corpus_{i}"), &packet);
    }
    let word_boundary_patterns = [
        "(\\b)",
        "(\\B)",
        "\\b(a)",
        "\\B(a)",
        "(a)\\b",
        "(\\b)(a)",
        "\\b(\\w+)\\b",
    ];
    let word_boundary_alphabet = ['a', 'b', '0', '_', 'é', 'ÿ', '!', ' ', '\n', '\u{85}'];
    for i in 0..175 {
        let pattern = word_boundary_patterns[i % word_boundary_patterns.len()];
        let mut value = format!("{pattern} éa _a 9é ! ");
        for j in 0..16 {
            value.push(word_boundary_alphabet[(i * 7 + j * 3) % word_boundary_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_word_boundary_{i}"), &packet);
    }
    let insensitive_patterns = [
        "(?i)(cat)",
        "(?i)([a-c]+)",
        "(?i)([^a])",
        "(?i)(é)",
        "(?i)(\\x41)",
        "(?i)(\\QAb\\E)",
        "(?i)((a)?b)*",
    ];
    let insensitive_alphabet = ['a', 'A', 'b', 'B', 'C', 'é', 'É', '_', ' ', '\n', '\u{85}'];
    for i in 0..175 {
        let pattern = insensitive_patterns[i % insensitive_patterns.len()];
        let mut value = format!("{pattern} CAT cat ABC abc É é AB ab ");
        for j in 0..16 {
            value.push(insensitive_alphabet[(i * 7 + j * 3) % insensitive_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java_groups(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_insensitive_{i}"), &packet);
    }
    let no_capture = [
        ("cat cat", "cat", "[$0]", Some(1)),
        ("cat cat", "cat", "$1", Some(1)),
        ("cat cat", "dog", "$1", Some(1)),
        ("abc", "", "x", Some(1)),
        ("éa", "", "-", Some(1)),
        ("abc", "", "$0", Some(1)),
        ("abc", "", "$1", Some(1)),
        ("(?i)cat CAT cat", "(?i)cat", "[$0]", Some(1)),
        (".abc.", ".", "[$0]", Some(1)),
        ("abc", "", "$", Some(0)),
    ];
    for (i, (value, pattern, replacement, limit)) in no_capture.iter().enumerate() {
        let mut packet = Packet::new(9);
        packet.put_string(value).unwrap();
        packet.set_cursor(7).unwrap();
        let before = packet.clone();
        let key = format!("substring_no_capture_{i}");
        match packet.replace_substrings_java_groups(pattern, replacement, *limit) {
            Ok(_) => check(&key, &packet),
            Err(_) => {
                assert_eq!(expected[key.as_str()], "error");
                assert_eq!(packet, before);
            }
        }
    }
    let dotall_patterns = [
        "(?s)(.)",
        "(?s)(.+)",
        "(?s).",
        "(?is)(a.b)",
        "(?si)([a-c].)",
        "(?i)(?s)(a.)",
        "(?s)((a)?.)*",
    ];
    let dotall_alphabet = ['a', 'A', 'b', 'B', 'é', ' ', '\n', '\r', '\u{85}'];
    for i in 0..175 {
        let pattern = dotall_patterns[i % dotall_patterns.len()];
        let mut value = format!("{pattern} a\nb A\rB ");
        for j in 0..16 {
            value.push(dotall_alphabet[(i * 7 + j * 3) % dotall_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(
                pattern,
                if pattern == "(?s)." { "$0" } else { "$1/$0" },
                Some(1),
            )
            .unwrap();
        check(&format!("substring_dotall_{i}"), &packet);
    }
    let multiline_patterns = [
        "(?m)^(a)",
        "(?m)(a)$",
        "(?m)\\A(a)",
        "(?m)(a)\\Z",
        "(?m)(a)\\z",
        "(?im)^(a)",
        "(?ms)(.)$",
        "(?m)(^)",
    ];
    let multiline_alphabet = ['a', 'A', 'b', 'é', ' ', '\n', '\r', '\u{85}'];
    for i in 0..200 {
        let pattern = multiline_patterns[i % multiline_patterns.len()];
        let mut value = format!("{pattern} a\r\na\nA\r\u{85}a ");
        for j in 0..16 {
            value.push(multiline_alphabet[(i * 7 + j * 3) % multiline_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_multiline_{i}"), &packet);
    }
    let unicode_patterns = [
        "(?iu)(é)",
        "(?iu)([é])",
        "(?iu)([^é])",
        "(?ui)([À-Ö]+)",
        "(?i)(?u)([ø-þ]+)",
        "(?iu)([a-z]+)",
        "(?u)(é)",
    ];
    let unicode_alphabet = [
        'é', 'É', 'à', 'À', 'ß', 'ÿ', '×', 'Ø', 'ø', 'Ð', 'ð', 'a', 'A',
    ];
    for i in 0..210 {
        let pattern = unicode_patterns[i % unicode_patterns.len()];
        let mut value = format!("{pattern} éÉàÀ Øø Ðð ");
        for j in 0..16 {
            value.push(unicode_alphabet[(i * 7 + j * 3) % unicode_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_unicode_case_{i}"), &packet);
    }
    let unicode_class_patterns = [
        "(?U)(\\w+)",
        "(?U)(\\W+)",
        "(?U)(\\s+)",
        "(?U)(\\S+)",
        "(?U)(\\d+)",
        "(?U)([\\w]+)",
        "(?U)([^\\w]+)",
        "(?U)(\\b)",
        "(?U)(\\B)",
        "(?iU)(é)",
    ];
    let unicode_class_alphabet = [
        'é', 'É', 'µ', 'ª', 'º', '×', '9', ' ', '\u{85}', '\u{a0}', 'a', '_',
    ];
    for i in 0..200 {
        let pattern = unicode_class_patterns[i % unicode_class_patterns.len()];
        let mut value = format!("{pattern} éÉ µªº 9_ ");
        for j in 0..16 {
            value.push(unicode_class_alphabet[(i * 7 + j * 3) % unicode_class_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_unicode_class_{i}"), &packet);
    }
    let noncapturing_patterns = [
        "(?:ab)",
        "(?:a(b)c)",
        "(a(?:b)c)",
        "(?:(a)(b))",
        "(?:(?:a)b)(c)",
        "(?:[a-c]+)(a)",
        "(?i)(?:É(a))",
        "(?:(a)?b)(c)",
        "(?:)(a)",
    ];
    for i in 0..180 {
        let pattern = noncapturing_patterns[i % noncapturing_patterns.len()];
        let value = format!("{pattern} abc abbc Éa eA aac {}", "abc".repeat(i % 5));
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(
                pattern,
                if pattern == "(?:ab)" { "$0" } else { "$1/$0" },
                Some(1),
            )
            .unwrap();
        check(&format!("substring_noncapturing_{i}"), &packet);
    }
    let noncapturing_repeat_patterns = [
        "(?:ab)*",
        "(?:ab)+",
        "(?:ab){1,3}",
        "(?:ab)*?b",
        "a(?:bc)+d",
        "(?:[a-c]d){0,2}",
        "(?i)(?:Ab)+",
    ];
    for i in 0..140 {
        let pattern = noncapturing_repeat_patterns[i % noncapturing_repeat_patterns.len()];
        let value = format!("{pattern} abab abcd abbd AbAB a {}", "ab".repeat(i % 5));
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, "[$0]", Some(1))
            .unwrap();
        check(&format!("substring_noncapturing_repeat_{i}"), &packet);
    }
    let noncapturing_optional_patterns = [
        "(?:ab)?c",
        "(?:ab)??c",
        "(?:ab)?(?:cd)?",
        "a(?:[a-c]d)?b",
        "(?i)(?:Ab)?b",
        "(?:)?a",
        "(?:(?:a)?b)?c",
    ];
    for i in 0..140 {
        let pattern = noncapturing_optional_patterns[i % noncapturing_optional_patterns.len()];
        let value = format!("{pattern} abc ac abcd c AbB adab {}", "ab".repeat(i % 5));
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, "[$0]", Some(1))
            .unwrap();
        check(&format!("substring_noncapturing_optional_{i}"), &packet);
    }
    let optional_capture_patterns = [
        "(?:(a))?b",
        "(?:(a))??b",
        "(a)(?:b)?(c)",
        "(a(?:b)?c)",
        "(?:(a)(b))?(c)",
        "(?:(a)?b)?(c)",
        "(?:()a)?(b)",
        "(?<x>a)(?:b)?",
    ];
    for i in 0..200 {
        let pattern = optional_capture_patterns[i % optional_capture_patterns.len()];
        let value = format!("{pattern} ab abc ac bc aabb abb {}", "abc".repeat(i % 5));
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(
                pattern,
                if matches!(i % 8, 2 | 4 | 5 | 6) {
                    "$1/$2/$0"
                } else {
                    "$1/$0"
                },
                Some(1),
            )
            .unwrap();
        check(&format!("substring_noncapture_with_capture_{i}"), &packet);
    }
    let fixed_repeat_capture_patterns = [
        "(?:(a)(b))+",
        "(?:(a)(b)){1,3}",
        "(?:(a(b)))+",
        "(?:(?<x>a)b)+",
        "(?:(a)(b))+ab",
    ];
    for i in 0..200 {
        let pattern = fixed_repeat_capture_patterns[i % fixed_repeat_capture_patterns.len()];
        let value = format!("{pattern} abab ab aab abc bb {}", "ab".repeat(i % 5));
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(
                pattern,
                if i % 5 != 3 { "$1/$2/$0" } else { "$1/$0" },
                Some(1),
            )
            .unwrap();
        check(&format!("substring_fixed_repeat_capture_{i}"), &packet);
    }
    let scoped_flag_patterns = [
        "(?i:(a))b",
        "(?i)(?-i:(a))B",
        "(a(?i:b)c)",
        "(?i:(a)(?-i:b)c)d",
        "(?s:(.))",
        "(?m:^(a))",
        "(?iu:(é))",
        "(?iU:(é))",
        "(?iU)(?-U:(é))",
        "(?iU)(?-u:(é))",
        "(?U:(\\w+))",
        "(?U)(?-U:(\\w+))",
        "(?i-i:(a))",
        "(?i-:(a))",
        "(?i:(ab))+",
        "(?i:(ab))?",
        "(?i:(?<x>a))b",
        "(?i:(?-i:(a))b)c",
        "(?i:(a))(?-i:b)",
        "(?iU-u:(é))",
    ];
    let scoped_flag_alphabet = [
        'a', 'A', 'b', 'B', 'c', 'C', 'é', 'É', '\n', '\r', '\u{85}', ' ',
    ];
    for i in 0..400 {
        let pattern = scoped_flag_patterns[i % scoped_flag_patterns.len()];
        let mut value = format!("{pattern} aAbBcC éÉ\nAb\r ");
        for j in 0..14 {
            value.push(scoped_flag_alphabet[(i * 7 + j * 3) % scoped_flag_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_scoped_flags_{i}"), &packet);
    }
    let embedded_flag_patterns = [
        "(a(?i)b)c",
        "(?i)(a(?-i)b)c",
        "(?i)(?-i)(a)",
        "(a)(?i)b",
        "(?iu)(é(?-u)é)",
        "(?s)(.(?-s).)",
        "(a(?i)b(?-i)c)d",
        "((?i)a)b",
        "(?i)((?-i)a)b",
        "(?i)(?-i)(?i)(a)b",
        "(?U)(?i)(é(?-U)é)",
        "(?i)(a(?-i)b(?i)c)",
        "(?i)(a)(?-i)b",
        "(a)(?s).",
        "(?m)(a)(?-m)$",
    ];
    let embedded_flag_alphabet = [
        'a', 'A', 'b', 'B', 'c', 'C', 'é', 'É', '\n', '\r', '\u{85}', ' ',
    ];
    for i in 0..300 {
        let pattern = embedded_flag_patterns[i % embedded_flag_patterns.len()];
        let mut value = format!("{pattern} aAbBcC éÉ\nAb\r ");
        for j in 0..14 {
            value.push(embedded_flag_alphabet[(i * 7 + j * 3) % embedded_flag_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_embedded_flags_{i}"), &packet);
    }
    let unix_line_patterns = [
        "(?d)(.)",
        "(?dm)^(a)",
        "(?dm)(a)$",
        "(?d)(a)\\Z",
        "(?ds)(.)",
        "(?d)(?-d:(.))",
        "(?d)(a)(?-d)$",
        "(?d:(.))",
        "(?dm)(^)(.)",
        "(?d)(a)$",
        "(?d)(a)\\z",
        "(?dm)(?-d:^(a))",
    ];
    let unix_line_alphabet = ['a', 'A', '\n', '\r', '\u{85}', ' ', 'b'];
    for i in 0..240 {
        let pattern = unix_line_patterns[i % unix_line_patterns.len()];
        let mut value = format!("{pattern} a\ra\na\r\na\u{85}a ");
        for j in 0..14 {
            value.push(unix_line_alphabet[(i * 7 + j * 3) % unix_line_alphabet.len()]);
        }
        value.push(match i % 3 {
            0 => '\n',
            1 => '\r',
            _ => '\u{85}',
        });
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_unix_lines_{i}"), &packet);
    }
    let comment_patterns = [
        "(?x)(a b)",
        "(?x)(a #comment\n b)",
        "(?x)([a b])",
        "(?x)([a#comment\nb])",
        "(?x)(a\\ b)",
        "(?x)(a\\#b)",
        "(?x)(\\Q a#b \\E)",
        "(?x)(?-x:(a b))",
        "(?x)((?-x) a b)",
        "(?x:(a b)) c",
        "(?x)(a){1 , 2 }",
        "(?x)(\\x 4 1)",
        "(?xd)(a)# c\r\nb",
        "(?x)(a#c\u{85}b)",
        "(?x)([a\\ b])",
        "(?x)(a)(? -x) b",
        "(?x i:(a b))",
        "(?x)(a\u{b}b)",
        "(?x)(?:a #comment\n (b))",
    ];
    let comment_alphabet = ['a', 'A', 'b', 'B', '#', ' ', '\n', '\r', '\u{85}'];
    for i in 0..380 {
        let pattern = comment_patterns[i % comment_patterns.len()];
        let mut value = format!("{pattern} ab a b a#b  a#b  Aab ");
        for j in 0..14 {
            value.push(comment_alphabet[(i * 7 + j * 3) % comment_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, "$1/$0", Some(1))
            .unwrap();
        check(&format!("substring_comments_mode_{i}"), &packet);
    }
    let alternation_patterns = [
        "a|ab",
        "ab|a",
        "a|",
        "|b",
        "(?i)a|B",
        "a+|b*",
        "(?:ab)|bc",
        "\\w+|x",
        "a?|b",
        "(?x)a #comment\n | b",
        "(?s).|a",
        "^a|b$",
        "(?:ab)+|cd",
        "a|(?:bc){2}|d",
        "a|(?i)b|c",
        "a||b",
    ];
    let alternation_alphabet = ['a', 'A', 'b', 'B', 'c', 'x', ' ', '\n', '\r', '\u{85}'];
    for i in 0..240 {
        let pattern = alternation_patterns[i % alternation_patterns.len()];
        let mut value = format!("{pattern} ab abc ba aB\n ");
        for j in 0..14 {
            value.push(alternation_alphabet[(i * 7 + j * 3) % alternation_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, "[$0]", Some(1))
            .unwrap();
        check(&format!("substring_alternation_{i}"), &packet);
    }
    let capture_alternation_patterns = [
        "(a)|b",
        "a|(b)",
        "((ab))|c",
        "(a?)|b",
        "(?<x>a)|b",
        "(a+)|b",
        "(ab)|c",
        "a|(b)|(c)",
        "(?:ab)|(a)",
        "(?i)(a)|B",
    ];
    let capture_alternation_alphabet = ['a', 'A', 'b', 'B', 'c', ' ', '\n'];
    for i in 0..200 {
        let pattern = capture_alternation_patterns[i % capture_alternation_patterns.len()];
        let mut value = format!("{pattern} ab abc ba aB ");
        for j in 0..14 {
            value.push(
                capture_alternation_alphabet[(i * 7 + j * 3) % capture_alternation_alphabet.len()],
            );
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(
                pattern,
                if matches!(i % 10, 2 | 7) {
                    "$1/$2/$0"
                } else if i % 10 == 4 {
                    "${x}/$0"
                } else {
                    "$1/$0"
                },
                Some(1),
            )
            .unwrap();
        check(&format!("substring_capture_alternation_{i}"), &packet);
    }
    let lazy_capture_patterns = [
        "(?:(a)b)*?b",
        "(?:(a)(b))*?c",
        "(?:(a)b)+?b",
        "(?:(?<x>a)b){0,3}?b",
        "(?:(a(b)))*?c",
        "x(?:(a)b)*?b",
        "(?i)(?:(a)b)*?B",
        "(?:(a)b){1,2}?a",
        "(?:(()a)b)*?b",
    ];
    let lazy_capture_alphabet = ['a', 'A', 'b', 'B', 'c', 'x', ' '];
    for i in 0..240 {
        let pattern = lazy_capture_patterns[i % lazy_capture_patterns.len()];
        let mut value = format!("{pattern} abab abc abbc xabab aabbb ");
        for j in 0..14 {
            value
                .push(lazy_capture_alphabet[(i * 5 + j * 3 + j * j) % lazy_capture_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        let replacement = if matches!(i % 9, 1 | 4 | 8) {
            "$1/$2/$0"
        } else if i % 9 == 3 {
            "${x}/$0"
        } else {
            "$1/$0"
        };
        packet
            .replace_substrings_java(pattern, replacement, Some(1))
            .unwrap();
        check(&format!("substring_lazy_capture_repeat_{i}"), &packet);
    }
    let greedy_capture_patterns = [
        "(?:(.)(.))+ab",
        "(?:(.)(.))*ab",
        "(?:(.)(.)){0,3}ab",
        "(?:(a)b)*b",
        "(?:(?<x>.)b)*b",
        "(?:(a)(.)){1,3}ab",
        "(?i)(?:(.)(.))*AB",
        "x(?:(.)(.))*ab",
    ];
    let greedy_capture_alphabet = ['a', 'A', 'b', 'B', 'c', 'd', 'e', 'f', 'x', ' '];
    for i in 0..240 {
        let pattern = greedy_capture_patterns[i % greedy_capture_patterns.len()];
        let mut value = format!("{pattern} cdefab abab aabb xab ");
        for j in 0..14 {
            value.push(
                greedy_capture_alphabet[(i * 3 + j * 7 + j * j) % greedy_capture_alphabet.len()],
            );
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        let replacement = if i % 8 == 3 {
            "$1/$0"
        } else if i % 8 == 4 {
            "${x}/$0"
        } else {
            "$1/$2/$0"
        };
        packet
            .replace_substrings_java(pattern, replacement, Some(1))
            .unwrap();
        check(&format!("substring_greedy_capture_repeat_{i}"), &packet);
    }
    let branch_rollback_patterns = [
        "(a)c|b",
        "(a)b|b",
        "(a)?c|b",
        "((a)b)c|b",
        "(a)(b)c|b",
        "(?<x>a)c|b",
        "(a+)b|c",
        "a|(b)c",
        "([ab]+)a|b",
        "(a)(?:b)?c|b",
    ];
    let branch_rollback_alphabet = ['a', 'A', 'b', 'B', 'c', ' ', '\n'];
    for i in 0..250 {
        let pattern = branch_rollback_patterns[i % branch_rollback_patterns.len()];
        let mut value = format!("{pattern} ab abc aaab bc cab ");
        for j in 0..14 {
            value.push(
                branch_rollback_alphabet[(i * 5 + j * 3 + j * j) % branch_rollback_alphabet.len()],
            );
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        let replacement = if matches!(i % 10, 3 | 4) {
            "$1/$2/$0"
        } else if i % 10 == 5 {
            "${x}/$0"
        } else {
            "$1/$0"
        };
        packet
            .replace_substrings_java(pattern, replacement, Some(1))
            .unwrap();
        check(&format!("substring_branch_capture_rollback_{i}"), &packet);
    }
    let nested_alternation_patterns = [
        "(?:a|b)c",
        "a(?:b|c)d",
        "(?:a|ab)b",
        "a*(?:a|b)",
        "(?:a|b)?c",
        "a(?:b|(?:c|d)e)f",
        "(?i:a|b)c",
        "(?:a||b)c",
        "(?:|a)b",
        "(?:a?|bc)d",
        "(?:a|b)|c",
    ];
    let nested_alternation_alphabet = ['a', 'A', 'b', 'B', 'c', 'd', 'e', 'f', ' ', '\n'];
    for i in 0..240 {
        let pattern = nested_alternation_patterns[i % nested_alternation_patterns.len()];
        let mut value = format!("{pattern} abc abd aab aaab acd acef ab ");
        for j in 0..14 {
            value.push(
                nested_alternation_alphabet
                    [(i * 3 + j * 7 + j * j) % nested_alternation_alphabet.len()],
            );
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, "[$0]", Some(1))
            .unwrap();
        check(&format!("substring_nested_alternation_{i}"), &packet);
    }
    let nested_capture_patterns = [
        "(a|b)c",
        "(a|(b))c",
        "((a)|(b))c",
        "(?:(a)|b)c",
        "(a|b)(c)",
        "(a|b)?c",
        "a*(a|b)b",
        "(?<x>a|b)c",
        "(a|(?:b|c))d",
        "(?:()|a)b",
        "(?:a|(b?))c",
        "(a|b)|(c)",
        "(?:(a)|b)?",
    ];
    let nested_capture_alphabet = ['a', 'A', 'b', 'B', 'c', 'd', ' ', '\n'];
    for i in 0..240 {
        let pattern = nested_capture_patterns[i % nested_capture_patterns.len()];
        let mut value = format!("{pattern} ac bc abc aaab abd cd ");
        for j in 0..14 {
            value.push(
                nested_capture_alphabet[(i * 3 + j * 7 + j * j) % nested_capture_alphabet.len()],
            );
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        let replacement = match i % 13 {
            2 => "$1/$2/$3/$0",
            1 | 4 | 11 => "$1/$2/$0",
            7 => "${x}/$0",
            _ => "$1/$0",
        };
        packet
            .replace_substrings_java(pattern, replacement, Some(1))
            .unwrap();
        check(
            &format!("substring_nested_capture_alternation_{i}"),
            &packet,
        );
    }
    let repeated_alternation_patterns = [
        "(?:a|b)+",
        "(?:a|b)*c",
        "(?:a|ab)+b",
        "(?:a||b)*c",
        "(a|b)*c",
        "(a|ab)+b",
        "(?:(a)|b)+c",
        "(?:a|(b))*c",
        "(?:(a)|(b))*?c",
        "(a|b){1,3}?c",
        "(?:a|b){0,2}",
        "(?:|a)*b",
        "(a|b){0}c",
        "(?:a|bc){2}d",
    ];
    let repeated_alternation_alphabet = ['a', 'A', 'b', 'B', 'c', 'd', ' ', '\n'];
    for i in 0..280 {
        let pattern = repeated_alternation_patterns[i % repeated_alternation_patterns.len()];
        let mut value = format!("{pattern} ac bc abc aaab abd babc ");
        for j in 0..14 {
            value.push(
                repeated_alternation_alphabet
                    [(i * 3 + j * 7 + j * j) % repeated_alternation_alphabet.len()],
            );
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        let replacement = match i % 14 {
            8 => "$1/$2/$0",
            4 | 5 | 6 | 7 | 9 | 12 => "$1/$0",
            _ => "[$0]",
        };
        packet
            .replace_substrings_java(pattern, replacement, Some(1))
            .unwrap();
        check(&format!("substring_repeated_alternation_{i}"), &packet);
    }
    let nullable_alternation_cases = [
        ("(?:|a){2,4}a", "[$0]"),
        ("(a|){2,4}a", "$1/$0"),
        ("(?:|a)+a", "[$0]"),
        ("(a|)+?a", "$1/$0"),
        ("(?:a|){0,2}a", "[$0]"),
        ("(?:|a){2}b", "[$0]"),
    ];
    for i in 0..120 {
        let (pattern, replacement) =
            nullable_alternation_cases[i % nullable_alternation_cases.len()];
        let value = format!("{pattern} aaab aab ab b a {}", "ab".repeat(i % 5));
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, replacement, Some(1))
            .unwrap();
        check(&format!("substring_nullable_alternation_{i}"), &packet);
    }
    let multiple_repeat_cases = [
        ("(?:a|b)+(?:c|d)+", "[$0]"),
        ("(a|b)+(c|d)+", "$1/$2/$0"),
        ("((?:a|b)+)c", "$1/$0"),
        ("((?:a|b){1,3})c", "$1/$0"),
        ("(?<x>(?:a|b)+)(c|d)+", "${x}/$2/$0"),
        ("(?:a|b)*?(?:c|d)+", "[$0]"),
        ("(?:a|)*(?:b|c)+", "[$0]"),
        ("(?:a|b){2}(?:c|d){1,2}", "[$0]"),
        ("(?:(a)|b)+(c|d)+", "$1/$2/$0"),
        ("(a|b)*?(c|d)+?d", "$1/$2/$0"),
    ];
    let multiple_repeat_alphabet = ['a', 'A', 'b', 'B', 'c', 'd', ' ', '\n'];
    for i in 0..250 {
        let (pattern, replacement) = multiple_repeat_cases[i % multiple_repeat_cases.len()];
        let mut value = format!("{pattern} abcd abc aacc bbd acd ");
        for j in 0..14 {
            value.push(
                multiple_repeat_alphabet[(i * 3 + j * 7 + j * j) % multiple_repeat_alphabet.len()],
            );
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, replacement, Some(1))
            .unwrap();
        check(&format!("substring_multiple_repeat_{i}"), &packet);
    }
    let nested_repeat_cases = [
        ("(?:(?:a|b)+|c)+d", "[$0]"),
        ("((?:a|b)+|c)+d", "$1/$0"),
        ("(?:(a|b)+|c)+d", "$1/$0"),
        ("(?:(?:a|b)*|c)+d", "[$0]"),
        ("(?:(a|)|c)+?d", "$1/$0"),
        ("(?:(?:a|b){1,2}|c){2,3}d", "[$0]"),
        ("(?:(?:a|b)+|c)*?(?:d|e)+", "[$0]"),
        ("(?<x>(?:a|b)+|c)+d", "${x}/$0"),
        ("(?:(a|b)*|(c))+d", "$1/$2/$0"),
        ("(?:(?:a|){0,2}|b){1,3}c", "[$0]"),
    ];
    let nested_repeat_alphabet = ['a', 'A', 'b', 'c', 'd', 'e', ' ', '\n'];
    for i in 0..200 {
        let (pattern, replacement) = nested_repeat_cases[i % nested_repeat_cases.len()];
        let mut value = format!("{pattern} abcd abcd aaac babd ");
        for j in 0..12 {
            value.push(
                nested_repeat_alphabet[(i * 3 + j * 7 + j * j) % nested_repeat_alphabet.len()],
            );
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, replacement, Some(1))
            .unwrap();
        check(&format!("substring_nested_repeat_{i}"), &packet);
    }
    let plain_multiple_cases = [
        ("(?:a)+(?:b)+", "[$0]"),
        ("(a)+(b)+", "$1/$2/$0"),
        ("([ab])+b([cd])+d", "$1/$2/$0"),
        ("(a){1,3}(b){0,2}", "$1/$2/$0"),
        ("((?:a)+)b", "$1/$0"),
        ("(a)+(b)+?b", "$1/$2/$0"),
        ("(?:a)*?(?:b)+", "[$0]"),
        ("(a)+(b)+|(c)", "$1/$2/$3/$0"),
        ("((a)+)(b)+", "$1/$2/$3/$0"),
        ("(?<x>a)+(?<y>b)+", "${x}/${y}/$0"),
    ];
    let plain_multiple_alphabet = ['a', 'A', 'b', 'c', 'd', ' ', '\n'];
    for i in 0..250 {
        let (pattern, replacement) = plain_multiple_cases[i % plain_multiple_cases.len()];
        let mut value = format!("{pattern} aaabb ab ababccdd aabb ");
        for j in 0..12 {
            value.push(
                plain_multiple_alphabet[(i * 5 + j * 3 + j * j) % plain_multiple_alphabet.len()],
            );
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, replacement, Some(1))
            .unwrap();
        check(&format!("substring_plain_multiple_{i}"), &packet);
    }
    let variable_repeat_cases = [
        ("(?:a*)+(?:b)+", "[$0]"),
        ("(?:a*)+", "[$0]"),
        ("(?:a?)+(?:b)+", "[$0]"),
        ("(?:ab*){1,3}(?:c)+", "[$0]"),
        ("(?:a*)+?(?:b)+", "[$0]"),
        ("(?:a?){2,4}(?:b)+", "[$0]"),
        ("(?:[ab]*)+(?:c)+", "[$0]"),
        ("((?:a*)+)b", "$1/$0"),
        ("(?:a+)+(?:b*)c", "[$0]"),
        ("(?:a?)*?(?:b){1,2}", "[$0]"),
        ("(?:ab?){1,3}?(?:c)+", "[$0]"),
    ];
    let variable_repeat_alphabet = ['a', 'A', 'b', 'c', ' ', '\n'];
    for i in 0..250 {
        let (pattern, replacement) = variable_repeat_cases[i % variable_repeat_cases.len()];
        let mut value = format!("{pattern} aaabb ab abc aaac bbc ");
        for j in 0..12 {
            value.push(
                variable_repeat_alphabet[(i * 5 + j * 3 + j * j) % variable_repeat_alphabet.len()],
            );
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, replacement, Some(1))
            .unwrap_or_else(|e| panic!("{pattern}: {e:?}"));
        check(&format!("substring_variable_repeat_{i}"), &packet);
    }
    let group_curly_cases = [
        ("(a*)+(?:b)+", "$1/$0"),
        ("((a*)+)(b)+", "$1/$2/$3/$0"),
        ("([ab]*)+(?:c)+", "$1/$0"),
        ("(a?)+(b)+", "$1/$2/$0"),
        ("(a+)+(b)+", "$1/$2/$0"),
        ("(?<x>a*)+(b)+", "${x}/$2/$0"),
        ("([ab]*)*?(?:c)+", "$1/$0"),
        ("([ab]*)+(?:b)+", "$1/$0"),
        ("([ab]*)+?(?:b)+", "$1/$0"),
        ("(?<x>[ab]*)+(?:b)+", "${x}/$0"),
    ];
    let group_curly_alphabet = ['a', 'A', 'b', 'c', 'd', ' ', '\n'];
    for i in 0..250 {
        let (pattern, replacement) = group_curly_cases[i % group_curly_cases.len()];
        let mut value = format!("{pattern} abababc cdefab aabb abc ");
        for j in 0..12 {
            value.push(group_curly_alphabet[(i * 5 + j * 3 + j * j) % group_curly_alphabet.len()]);
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, replacement, Some(1))
            .unwrap_or_else(|e| panic!("{pattern}: {e:?}"));
        check(&format!("substring_group_curly_{i}"), &packet);
    }
    let sticky_capture_cases = [
        ("(?:(a)b)+(?:c)+", "$1/$0"),
        ("(?:(.)(.))+(?:ab)+", "$1/$2/$0"),
        ("(?:(a)b)*?(?:c)+", "$1/$0"),
        ("(?:(?<x>a)b)+(?:c)+", "${x}/$0"),
        ("(?:([ab])b)+(?:c)+", "$1/$0"),
        ("(?:(a)b){0,3}(?:c)+", "$1/$0"),
        ("((a)b)+(c)+", "$1/$2/$3/$0"),
        ("(?:(a)b)+?b(?:c)+", "$1/$0"),
        ("(?:(a)b)*(?:c)+", "$1/$0"),
        ("(?:(a)b)+(?:c)*", "$1/$0"),
        ("(?:(a)b)+(?:(c)d)+e", "$1/$2/$0"),
        ("(?:(a)b)+(?:c)+|d", "$1/$0"),
        ("((?:(a)b)+)", "$1/$2/$0"),
        ("(?<x>(?:(a)b)+)", "${x}/$2/$0"),
    ];
    let sticky_capture_alphabet = ['a', 'A', 'b', 'c', 'd', ' ', '\n'];
    for i in 0..250 {
        let (pattern, replacement) = sticky_capture_cases[i % sticky_capture_cases.len()];
        let mut value = format!("{pattern} abababc cdefab aabb abc ");
        for j in 0..12 {
            value.push(
                sticky_capture_alphabet[(i * 5 + j * 3 + j * j) % sticky_capture_alphabet.len()],
            );
        }
        let mut packet = Packet::new(9);
        packet.put_string(&value).unwrap();
        packet.set_cursor(7).unwrap();
        packet
            .replace_substrings_java(pattern, replacement, Some(1))
            .unwrap_or_else(|e| panic!("{pattern}: {e:?}"));
        check(&format!("substring_sticky_capture_{i}"), &packet);
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
    let mut utf16_typed = Packet::new(8);
    utf16_typed
        .put_utf16be("Aé水")
        .unwrap()
        .put_i32(42)
        .unwrap();
    check("utf16", &utf16_typed);
    utf16_typed.set_cursor(7).unwrap();
    utf16_typed.replace_utf16be(6, "Z猫").unwrap();
    check("utf16_replacement", &utf16_typed);
    let mut utf16_typed_long = Packet::new(9);
    utf16_typed_long
        .put_utf16be_long("水🐱")
        .unwrap()
        .put_i32(123)
        .unwrap();
    check("utf16_long", &utf16_typed_long);
    assert_eq!(utf16_typed_long.read_utf16be_long(false).unwrap(), "水🐱");
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
