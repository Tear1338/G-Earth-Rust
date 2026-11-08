use gearth_rust::packet::{Packet, PacketFormat};

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
