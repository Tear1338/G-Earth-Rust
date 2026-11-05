use gearth_rust::{packet::Direction, schedule_file};

#[test]
fn imports_original_schedule_rows_and_preserves_pause_and_offsets() {
    let input = "0\tfalse\t500+0\tTOSERVER\t{h:42}{s:\"bonjour\"}\r\n1\ttrue\t1000+125\tTOCLIENT\t[0][0][0][2][0][5]";
    let schedules = schedule_file::parse(input).unwrap();
    assert_eq!(schedules.len(), 2);
    assert_eq!(schedules[0].direction, Direction::ToServer);
    assert!(!schedules[0].paused);
    assert_eq!(schedules[0].repeat, 0);
    assert_eq!(schedules[1].direction, Direction::ToClient);
    assert!(schedules[1].paused);
    assert_eq!(schedules[1].offset_ms, Some(125));
    let serialized = schedule_file::format(&schedules).unwrap();
    assert_eq!(serialized, input.replace("\r\n", "\n"));
    assert_eq!(schedule_file::parse(&serialized).unwrap(), schedules);
}

#[test]
fn rejects_malformed_files_and_lossy_exports() {
    let valid = "0\tfalse\t500+100\tTOSERVER\t{h:42}";
    for input in [
        "0\tfalse\t0+0\tTOSERVER\t{h:42}",
        "0\tfalse\t500+500\tTOSERVER\t{h:42}",
        "0\tfalse\t500+0\tUNKNOWN\t{h:42}",
        "0\tfalse\t500+0\tTOSERVER\t",
        "0\tfalse\t500+0\tTOSERVER\t{h:42}\textra",
        "0\tmaybe\t500+0\tTOSERVER\t{h:42}",
    ] {
        assert!(schedule_file::parse(input).is_err(), "{input}");
    }
    assert!(schedule_file::parse(&format!("{valid}\ninvalid")).is_err());
    let mut items = schedule_file::parse(valid).unwrap();
    items[0].repeat = 4;
    assert!(schedule_file::format(&items).is_err());
    items[0].repeat = 0;
    items[0].offset_ms = None;
    assert!(schedule_file::format(&items).is_err());
}
