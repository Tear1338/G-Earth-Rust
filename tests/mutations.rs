use gearth_rust::packet::{Packet, PacketFormat};

#[test]
fn utf8_offset_reads_are_strict_and_do_not_move_the_cursor() {
    let mut packet = Packet::new(15);
    packet
        .put_utf8("Café 🐱")
        .unwrap()
        .put_utf8_long("éclair")
        .unwrap();
    packet.set_cursor(7).unwrap();
    assert_eq!(packet.read_utf8_at(6).unwrap(), "Café 🐱");
    assert_eq!(packet.read_utf8_long_at(18).unwrap(), "éclair");
    assert_eq!(packet.read_short_bytes_at(6).unwrap(), "Café 🐱".as_bytes());
    assert_eq!(packet.read_long_bytes_at(18).unwrap(), "éclair".as_bytes());
    assert!(packet.read_utf8_at(usize::MAX).is_err());
    assert_eq!(packet.cursor(), 7);
    let mut invalid = Packet::new(16);
    invalid.put_short_bytes(&[0xff]).unwrap();
    assert!(invalid.read_utf8_at(6).is_err());
    assert_eq!(invalid.cursor(), 6);
    let mut truncated = Packet::new(17);
    truncated.append(&[0, 0, 0, 3, b'x']).unwrap();
    assert!(truncated.read_utf8_long_at(6).is_err());
    assert_eq!(truncated.cursor(), 6);
    let wedgie = Packet::new_with_format(PacketFormat::WedgieOutgoing, 1).unwrap();
    assert!(wedgie.read_utf8_at(0).is_err());
    assert!(wedgie.read_utf8_long_at(0).is_err());
}

#[test]
fn lossy_utf8_reads_replace_invalid_bytes_and_validate_lengths() {
    let mut packet = Packet::new(16);
    packet
        .put_short_bytes(&[0xe2, 0x82, b'A'])
        .unwrap()
        .put_long_bytes(&[0xff, b'a'])
        .unwrap();
    packet.set_cursor(7).unwrap();
    assert_eq!(packet.read_utf8_lossy_at(6).unwrap(), "�A");
    assert_eq!(packet.read_utf8_long_lossy_at(11).unwrap(), "�a");
    assert_eq!(packet.cursor(), 7);
    packet.set_cursor(6).unwrap();
    assert_eq!(packet.read_utf8_lossy().unwrap(), "�A");
    assert_eq!(packet.read_utf8_long_lossy().unwrap(), "�a");
    let end = packet.cursor();
    assert!(packet.read_utf8_lossy().is_err());
    assert_eq!(packet.cursor(), end);
    assert!(packet.read_utf8_long_lossy_at(usize::MAX).is_err());
}

#[test]
fn malformed_utf8_surrogate_is_one_replacement_like_java() {
    let mut packet = Packet::new(18);
    packet.put_short_bytes(&[0xed, 0xa0, 0x80, b'A']).unwrap();
    assert_eq!(packet.read_utf8_lossy_at(6).unwrap(), "�A");
    assert_eq!(packet.read_utf8_lossy().unwrap(), "�A");
}

#[test]
fn signed_bytes_roundtrip_and_preserve_cursor_on_errors() {
    let mut packet = Packet::new(14);
    for value in [i8::MIN, -1, 0, i8::MAX] {
        packet.put_i8(value).unwrap();
    }
    assert_eq!(packet.read_i8().unwrap(), i8::MIN);
    assert_eq!(packet.read_i8_at(7).unwrap(), -1);
    assert_eq!(packet.cursor(), 7);
    packet.replace_i8(7, -42).unwrap();
    assert_eq!(packet.read_i8().unwrap(), -42);
    assert_eq!(packet.read_i8().unwrap(), 0);
    assert_eq!(packet.read_i8().unwrap(), i8::MAX);
    let end = packet.cursor();
    assert!(packet.read_i8().is_err());
    assert_eq!(packet.cursor(), end);
    let before = packet.bytes().to_vec();
    assert!(packet.replace_i8(0, -1).is_err());
    assert_eq!(packet.bytes(), before);
}

#[test]
fn signed_shorts_roundtrip_and_reject_invalid_operations() {
    let mut packet = Packet::new(13);
    for value in [i16::MIN, -1, 0, i16::MAX] {
        packet.put_i16(value).unwrap();
    }
    assert_eq!(packet.read_i16().unwrap(), i16::MIN);
    let cursor = packet.cursor();
    assert_eq!(packet.read_i16_at(8).unwrap(), -1);
    assert_eq!(packet.cursor(), cursor);
    packet.replace_i16(8, -1234).unwrap();
    assert_eq!(packet.read_i16().unwrap(), -1234);
    assert_eq!(packet.read_i16().unwrap(), 0);
    assert_eq!(packet.read_i16().unwrap(), i16::MAX);
    let end = packet.cursor();
    assert!(packet.read_i16().is_err());
    assert_eq!(packet.cursor(), end);
    let before = packet.bytes().to_vec();
    assert!(packet.replace_i16(0, 2).is_err());
    assert_eq!(packet.bytes(), before);
    let mut wedgie = Packet::new_with_format(PacketFormat::WedgieOutgoing, 1).unwrap();
    assert!(wedgie.put_i16(-1).is_err());
    assert!(wedgie.read_i16().is_err());
    assert!(wedgie.read_i16_at(0).is_err());
}

#[test]
fn skip_structure_advances_fields_and_preserves_completed_reads_on_error() {
    let mut packet = Packet::new(11);
    packet
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
    let before = packet.bytes().to_vec();
    packet.skip_structure("i s?bBul d").unwrap();
    assert_eq!(packet.remaining(), 0);
    assert_eq!(packet.bytes(), before);
    let mut partial = Packet::new(12);
    partial.put_i32(42).unwrap();
    assert!(partial.skip_structure("ib").is_err());
    assert_eq!(partial.cursor(), 10);
    let mut truncated = Packet::new(13);
    truncated.append(&[0, 3, b'x']).unwrap();
    assert!(truncated.skip_structure("s").is_err());
    assert_eq!(truncated.cursor(), 6);
    let mut wedgie = Packet::new_with_format(PacketFormat::WedgieOutgoing, 1).unwrap();
    assert!(wedgie.skip_structure("i").is_err());
}

#[test]
fn absolute_reads_preserve_cursor_and_validate_bounds() {
    let mut packet = Packet::new(77);
    packet
        .put_i32(42)
        .unwrap()
        .put_string("hi")
        .unwrap()
        .put_long_string("world")
        .unwrap();
    packet.set_cursor(8).unwrap();
    assert_eq!(packet.read_i32_at(6).unwrap(), 42);
    assert_eq!(packet.read_string_at(10).unwrap(), "hi");
    assert_eq!(packet.read_long_string_at(14).unwrap(), "world");
    assert_eq!(packet.read_u16_at(4).unwrap(), 77);
    assert!(packet.read_i64_at(packet.bytes().len() - 1).is_err());
    assert!(packet.read_bytes_at(usize::MAX, 2).is_err());
    assert!(packet.read_string_at(packet.bytes().len() - 1).is_err());
    assert_eq!(packet.cursor(), 8);
    let mut invalid = Packet::new(1);
    invalid.put_i32(-1).unwrap();
    assert!(invalid.read_long_string_at(6).is_err());
    let wedgie = Packet::new_with_format(PacketFormat::WedgieOutgoing, 1).unwrap();
    assert!(wedgie.read_i32_at(wedgie.bytes().len()).is_err());
}

#[test]
fn replacing_raw_bytes_keeps_length_and_cursor_and_rejects_partial_writes() {
    let mut packet = Packet::new(10);
    packet.append(&[0, 1, 2, 3, 4, 5]).unwrap();
    packet.set_cursor(8).unwrap();
    let length = packet.bytes().len();
    packet.replace_bytes(7, &[0xff, 0x80, 42]).unwrap();
    assert_eq!(packet.body(), &[0, 0xff, 0x80, 42, 4, 5]);
    assert_eq!(packet.cursor(), 8);
    assert_eq!(packet.bytes().len(), length);
    let before = packet.clone();
    assert!(packet.replace_bytes(5, &[1]).is_err());
    assert!(packet.replace_bytes(usize::MAX, &[1]).is_err());
    assert!(packet.replace_bytes(length - 1, &[1, 2]).is_err());
    assert_eq!(packet, before);
}

#[test]
fn typed_edits_keep_cursor_and_reject_invalid_fields_without_mutation() {
    let mut packet = Packet::new(7);
    packet.put_string("old").unwrap().put_i32(9).unwrap();
    packet.set_cursor(7).unwrap();
    let before = packet.clone();
    assert!(packet.replace_i32(usize::MAX, 10).is_err());
    assert!(packet.replace_string(6, "snowman ☃").is_err());
    assert!(packet
        .replace_strings("old", &"x".repeat(65_536), None)
        .is_err());
    assert!(packet.replace_string(9, "bad").is_err());
    assert_eq!(packet, before);
    packet.replace_string(6, "new value").unwrap();
    assert_eq!(packet.cursor(), 7);
    packet.reset();
    assert_eq!(packet.read_string().unwrap(), "new value");
    assert_eq!(packet.read_i32().unwrap(), 9);
}

#[test]
fn shrinking_string_clamps_cursor_and_bulk_replacements_are_bounded() {
    let mut packet = Packet::new(1);
    packet.put_string("long value").unwrap();
    packet.set_cursor(packet.bytes().len()).unwrap();
    packet.replace_string(6, "x").unwrap();
    assert_eq!(packet.cursor(), packet.bytes().len());
    packet.reset();
    assert_eq!(packet.read_string().unwrap(), "x");
    packet.put_string("x").unwrap().put_string("x").unwrap();
    assert_eq!(packet.replace_strings("x", "hello", Some(1)).unwrap(), 1);
    assert_eq!(packet.replace_strings("x", "", None).unwrap(), 2);
    packet.reset();
    assert_eq!(packet.read_string().unwrap(), "hello");
    assert_eq!(packet.read_string().unwrap(), "");
    assert_eq!(packet.read_string().unwrap(), "");
}

#[test]
fn typed_mutations_do_not_guess_wedgie_encodings() {
    let mut packet = Packet::new_with_format(PacketFormat::WedgieOutgoing, 5).unwrap();
    packet.put_string("hello").unwrap();
    let before = packet.clone();
    assert!(packet.replace_string(2, "world").is_err());
    assert!(packet.replace_all_i32(0, 1).is_err());
    assert_eq!(packet, before);
}

#[test]
fn zero_replacements_do_not_edit_or_validate_replacement_text() {
    let mut packet = Packet::new(2);
    packet.put_string("hello").unwrap();
    packet.edited = false;
    assert_eq!(packet.replace_strings("hello", "☃", Some(0)).unwrap(), 0);
    assert!(!packet.edited);
}

#[test]
fn growing_empty_string_does_not_corrupt_the_following_field() {
    let mut packet = Packet::new(5);
    packet.put_string("").unwrap().put_string("a").unwrap();
    let mut direct = packet.clone();
    direct.replace_string(6, "x").unwrap();
    direct.reset();
    assert_eq!(direct.read_string().unwrap(), "x");
    assert_eq!(direct.read_string().unwrap(), "a");
    assert_eq!(packet.replace_strings("", "x", Some(1)).unwrap(), 1);
    packet.reset();
    assert_eq!(packet.read_string().unwrap(), "x");
    assert_eq!(packet.read_string().unwrap(), "a");
}

#[test]
fn substring_replacement_scans_from_the_end_and_is_transactional() {
    let mut packet = Packet::new(9);
    packet
        .put_string("cat cat")
        .unwrap()
        .put_string("catdog")
        .unwrap();
    let mut first = packet.clone();
    assert_eq!(
        first
            .replace_substrings_literal("cat", "x", Some(1))
            .unwrap(),
        1
    );
    first.reset();
    assert_eq!(first.read_string().unwrap(), "cat cat");
    assert_eq!(first.read_string().unwrap(), "xdog");
    // Java's backward scan skips the preceding adjacent field here.
    assert_eq!(
        packet
            .replace_substrings_literal("cat", "hello", None)
            .unwrap(),
        1
    );
    packet.reset();
    assert_eq!(packet.read_string().unwrap(), "cat cat");
    assert_eq!(packet.read_string().unwrap(), "hellodog");
    let before = packet.clone();
    assert!(packet.replace_substrings_literal(".", "x", None).is_err());
    assert!(packet.replace_substrings_literal("x", "$1", None).is_err());
    assert_eq!(packet, before);
    let mut large = Packet::new(3);
    large.put_string(&"a".repeat(40_000)).unwrap();
    let before = large.clone();
    assert!(large.replace_substrings_literal("a", "aaa", None).is_err());
    assert_eq!(large, before);
}

#[test]
fn java_literal_substring_templates_handle_group_zero_and_escapes() {
    let mut packet = Packet::new(9);
    packet
        .put_string("cat cat")
        .unwrap()
        .put_string("catdog")
        .unwrap();
    assert_eq!(
        packet
            .replace_substrings_java_literal("cat", "[$0]\\$", Some(1))
            .unwrap(),
        1
    );
    packet.reset();
    assert_eq!(packet.read_string().unwrap(), "cat cat");
    assert_eq!(packet.read_string().unwrap(), "[cat]$dog");
    let before = packet.clone();
    assert!(packet
        .replace_substrings_java_literal("cat", "$1", None)
        .is_err());
    assert_eq!(packet, before);
    assert_eq!(
        packet
            .replace_substrings_java_literal("missing", "$1", None)
            .unwrap(),
        0
    );
    assert_eq!(packet, before);
    assert_eq!(
        packet
            .replace_substrings_java_literal("cat", "$1", Some(0))
            .unwrap(),
        0
    );
    assert_eq!(packet, before);
    assert!(packet
        .replace_substrings_java_literal("c.t", "$0", None)
        .is_err());
}

#[test]
fn java_literal_capture_group_requires_raw_pattern_and_is_transactional() {
    let mut packet = Packet::new(9);
    packet.put_string("cat (cat) cat").unwrap();
    let original = packet.clone();
    assert!(packet
        .replace_substrings_java_group("(cat)", "$2", None)
        .is_err());
    assert_eq!(packet, original);
    assert!(packet
        .replace_substrings_java_group("(c.t)", "$1", None)
        .is_err());
    assert_eq!(packet, original);
    assert_eq!(
        packet
            .replace_substrings_java_group("(dog)", "$2", None)
            .unwrap(),
        0
    );
    assert_eq!(packet, original);
    assert_eq!(
        packet
            .replace_substrings_java_group("(cat)", "[$1]", None)
            .unwrap(),
        1
    );
    packet.reset();
    assert_eq!(packet.read_string().unwrap(), "[cat] ([cat]) [cat]");
    let mut large = Packet::new(9);
    large
        .put_string(&format!("(a){}", "a".repeat(40_000)))
        .unwrap();
    let before = large.clone();
    assert!(large
        .replace_substrings_java_group("(a)", "aaa", None)
        .is_err());
    assert_eq!(large, before);
}

#[test]
fn java_literal_groups_keep_no_match_and_reject_unsupported_patterns_transactionally() {
    let mut no_match = Packet::new(9);
    no_match.put_string("a(b)c").unwrap();
    assert_eq!(
        no_match
            .replace_substrings_java_groups("a(b)c", "$9", None)
            .unwrap(),
        1
    );
    no_match.reset();
    assert_eq!(no_match.read_string().unwrap(), "a(b)c");
    let mut packet = Packet::new(9);
    packet.put_string("(a)(b) ab").unwrap();
    let before = packet.clone();
    for pattern in ["(a.*)", "(\\p)", "(a", "a)", "abc"] {
        assert!(packet
            .replace_substrings_java_groups(pattern, "$1", None)
            .is_err());
        assert_eq!(packet, before);
    }
    assert!(packet
        .replace_substrings_java_groups("(a)(b)", "$3", None)
        .is_err());
    assert_eq!(packet, before);
    assert_eq!(
        packet
            .replace_substrings_java_groups("(a)(b)", "$2$1", None)
            .unwrap(),
        1
    );
    packet.reset();
    assert_eq!(packet.read_string().unwrap(), "(a)(b) ba");
}

#[test]
fn java_zero_width_group_respects_size_bounds_and_preserves_packet_on_error() {
    let mut packet = Packet::new(9);
    packet
        .put_string(&format!("(){}", "é".repeat(40_000)))
        .unwrap();
    let before = packet.clone();
    assert!(packet
        .replace_substrings_java_groups("()", "x", None)
        .is_err());
    assert_eq!(packet, before);
}

#[test]
fn java_named_group_rejects_invalid_names_and_references_transactionally() {
    let mut packet = Packet::new(9);
    packet.put_string("(?<pet>cat) cat").unwrap();
    let before = packet.clone();
    for pattern in ["(?<1pet>cat)", "(?<x>a)(?<x>b)", "(?<=cat)"] {
        assert!(packet
            .replace_substrings_java_groups(pattern, "x", None)
            .is_err());
        assert_eq!(packet, before);
    }
    for replacement in ["${missing}", "${pet", "${}"] {
        assert!(packet
            .replace_substrings_java_groups("(?<pet>cat)", replacement, None)
            .is_err());
        assert_eq!(packet, before);
    }
    assert_eq!(
        packet
            .replace_substrings_java_groups("(?<pet>cat)", "${pet}!", None)
            .unwrap(),
        1
    );
    packet.reset();
    assert_eq!(packet.read_string().unwrap(), "(?<pet>cat!) cat!");
}

#[test]
fn java_dot_group_captures_each_match_and_bounds_expansion() {
    let mut packet = Packet::new(9);
    packet.put_string("(c.t) cat cét c\nt").unwrap();
    assert_eq!(
        packet
            .replace_substrings_java_groups("(c.t)", "[$1]", None)
            .unwrap(),
        1
    );
    packet.reset();
    assert_eq!(packet.read_string().unwrap(), "([c.t]) [cat] [cét] c\nt");
    let mut large = Packet::new(9);
    large
        .put_string(&format!("(.){}", "a".repeat(40_000)))
        .unwrap();
    let before = large.clone();
    assert!(large
        .replace_substrings_java_groups("(.)", "[$1]", None)
        .is_err());
    assert_eq!(large, before);
}

#[test]
fn java_character_classes_reject_unsupported_forms_transactionally() {
    let mut packet = Packet::new(9);
    packet.put_string("([abc]) abc").unwrap();
    let before = packet.clone();
    for pattern in ["([a&&b])", "([z-a])", "([])", "([a", "([\\p])"] {
        assert!(packet
            .replace_substrings_java_groups(pattern, "x", None)
            .is_err());
        assert_eq!(packet, before);
    }
    assert_eq!(
        packet
            .replace_substrings_java_groups("([abc])", "[$1]", None)
            .unwrap(),
        1
    );
    packet.reset();
    assert_eq!(packet.read_string().unwrap(), "([[a][b][c]]) [a][b][c]");
}

#[test]
fn java_control_escapes_reject_invalid_values_without_mutation() {
    let mut packet = Packet::new(9);
    packet.put_string("(\\x41) A").unwrap();
    let before = packet.clone();
    for pattern in ["(\\x4)", "(\\u1000)", "([\\xG1])"] {
        assert!(packet
            .replace_substrings_java_groups(pattern, "x", None)
            .is_err());
        assert_eq!(packet, before);
    }
    assert_eq!(
        packet
            .replace_substrings_java_groups("(\\x41)", "[$1]", None)
            .unwrap(),
        1
    );
    packet.reset();
    assert_eq!(packet.read_string().unwrap(), "(\\x41) [A]");
}

#[test]
fn java_optional_regex_quantifier_is_bounded_and_rejects_unsupported_forms() {
    let mut packet = Packet::new(9);
    packet.put_string("(a?) a").unwrap();
    let before = packet.clone();
    for pattern in ["(a?b?)", "(a)?", "(a?+)"] {
        assert!(packet
            .replace_substrings_java_groups(pattern, "x", None)
            .is_err());
        assert_eq!(packet, before);
    }
    let mut large = Packet::new(9);
    large
        .put_string(&format!("(a?){}", "a".repeat(40_000)))
        .unwrap();
    let original = large.clone();
    assert!(large
        .replace_substrings_java_groups("(a?)", "[$1]", None)
        .is_err());
    assert_eq!(large, original);
}

#[test]
fn append_typed_fields_preserves_prior_fields_on_error() {
    use gearth_rust::packet::{PacketField, PacketFormat};
    let mut packet = Packet::new(7);
    assert!(packet
        .append_fields(&[PacketField::Integer(42), PacketField::String("☃")])
        .is_err());
    assert_eq!(packet.read_i32().unwrap(), 42);
    assert_eq!(packet.remaining(), 0);
    let mut wedgie = Packet::new_with_format(PacketFormat::WedgieOutgoing, 7).unwrap();
    let original = wedgie.clone();
    assert!(wedgie.append_fields(&[PacketField::Integer(1)]).is_err());
    assert_eq!(wedgie, original);
}

#[test]
fn java_latin1_replacement_is_explicit_and_short_length_counts_scalars() {
    use gearth_rust::packet::{PacketField, PacketFormat};
    let mut packet = Packet::new(1);
    assert!(packet.put_string("雪").is_err());
    packet
        .append_fields(&[PacketField::StringJava("é雪🐱")])
        .unwrap();
    assert_eq!(packet.read_string().unwrap(), "é??");
    let mut limit = Packet::new(1);
    limit.put_string_java(&"🐱".repeat(65535)).unwrap();
    assert!(limit.put_string_java(&"🐱".repeat(65536)).is_err());
    let mut wedgie = Packet::new_with_format(PacketFormat::WedgieOutgoing, 1).unwrap();
    assert!(wedgie.put_string_java("雪").is_err());
}
