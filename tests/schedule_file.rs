use gearth_rust::{
    expression,
    packet::{Direction, Packet, PacketFormat},
    schedule_file,
    scheduler::Scheduler,
};
use std::time::{Duration, Instant, UNIX_EPOCH};

fn active_fixture() -> Scheduler {
    let now = Instant::now();
    let wall = UNIX_EPOCH + Duration::from_secs(100);
    let mut scheduler = Scheduler::default();
    for (format, direction) in [
        (PacketFormat::EvaWire, Direction::ToServer),
        (PacketFormat::WedgieIncoming, Direction::ToClient),
        (PacketFormat::WedgieOutgoing, Direction::ToServer),
    ] {
        let mut packet = Packet::new_with_format(format, 42).unwrap();
        packet.append(&(0..=255).collect::<Vec<u8>>()).unwrap();
        scheduler
            .add_aligned(packet, direction, 1000, 125, None, (now, wall))
            .unwrap();
    }
    scheduler.jobs[1].paused = true;
    scheduler
}

#[test]
fn active_export_roundtrips_packets_timing_and_pause_without_templates() {
    let scheduler = active_fixture();
    let exported = schedule_file::format_active(&scheduler.jobs).unwrap();
    let templates = schedule_file::parse(&exported).unwrap();
    for (job, template) in scheduler.jobs.iter().zip(&templates) {
        let packet =
            expression::parse_with_format(&template.expression, job.packet.format(), None).unwrap();
        assert_eq!(packet.bytes(), job.packet.bytes());
        assert_eq!(template.direction, job.direction);
        assert_eq!(template.paused, job.paused);
        assert_eq!(template.offset_ms, Some(125));
        assert_eq!(template.interval_ms, 1000);
        assert_eq!(template.repeat, 0);
    }
}

#[test]
fn active_export_preserves_the_original_named_expression() {
    let mut scheduler = active_fixture();
    scheduler.jobs[0].source_expression = Some("{out:Example}{i:7}".into());
    let exported = schedule_file::format_active(&scheduler.jobs).unwrap();
    let restored = schedule_file::parse(&exported).unwrap();
    assert_eq!(restored[0].expression, "{out:Example}{i:7}");
    assert_eq!(restored[0].direction, Direction::ToServer);
}

#[test]
fn active_export_refuses_timing_that_original_format_cannot_represent() {
    let mut scheduler = active_fixture();
    scheduler.jobs[0].remaining = Some(1);
    assert!(schedule_file::format_active(&scheduler.jobs).is_err());
    scheduler.jobs[0].remaining = None;
    scheduler.jobs[0].alignment_offset_ms = None;
    assert!(schedule_file::format_active(&scheduler.jobs).is_err());
    scheduler.jobs[0].alignment_offset_ms = Some(0);
    scheduler.jobs[0].interval = Duration::from_micros(1500);
    assert!(schedule_file::format_active(&scheduler.jobs).is_err());
}

#[test]
fn schedule_file_atomic_export_replaces_complete_file() {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).unwrap();
    let name = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let directory = std::env::temp_dir().join(format!("gearth-schedule-test-{name}"));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("example.sched");
    std::fs::write(&path, "previous").unwrap();
    schedule_file::write_atomic(&path, "new content").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "new content");
    assert!(schedule_file::write_atomic(
        &path,
        &"x".repeat(schedule_file::MAX_SCHEDULE_FILE_BYTES + 1)
    )
    .is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "new content");
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
#[ignore = "requires the original Java API and compiled JavaSchedulePacketOracle"]
fn active_export_packets_are_understood_by_original_java() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let scheduler = active_fixture();
    let exported = schedule_file::format_active(&scheduler.jobs).unwrap();
    let templates = schedule_file::parse(&exported).unwrap();
    let mut child = Command::new("java")
        .args([
            "-cp",
            &std::env::var("GEARTH_SCHEDULE_PACKET_CLASSPATH").unwrap(),
            "JavaSchedulePacketOracle",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        for template in templates {
            writeln!(stdin, "{}", template.expression).unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let actual = String::from_utf8(output.stdout).unwrap();
    let expected = scheduler
        .jobs
        .iter()
        .map(|job| {
            job.packet
                .bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    assert_eq!(actual.lines().collect::<Vec<_>>(), expected);
}

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
fn interval_equal_to_offset_roundtrips_without_a_reachable_phase() {
    let input = "0\tfalse\t500+500\tTOSERVER\t{h:42}";
    let schedules = schedule_file::parse(input).unwrap();
    assert_eq!(schedules[0].offset_ms, Some(500));
    assert_eq!(schedule_file::format(&schedules).unwrap(), input);

    let now = Instant::now();
    let wall = UNIX_EPOCH + Duration::from_millis(125);
    let packet = Packet::new_with_format(PacketFormat::EvaWire, 42).unwrap();
    let mut scheduler = Scheduler::default();
    scheduler
        .add_aligned(
            packet.clone(),
            Direction::ToServer,
            500,
            500,
            None,
            (now, wall),
        )
        .unwrap();
    scheduler
        .add_aligned(packet, Direction::ToServer, 500, 0, None, (now, wall))
        .unwrap();
    let due = now + Duration::from_millis(375);
    assert_eq!(scheduler.jobs[0].next, due);
    assert_eq!(scheduler.jobs[1].next, due);
    assert!(scheduler.tick(due - Duration::from_millis(1)).is_empty());
    let sent = scheduler.tick(due);
    assert_eq!(sent.len(), 1);
    assert_eq!(scheduler.jobs[0].alignment_offset_ms, Some(500));
    assert_eq!(scheduler.jobs[1].next, due + Duration::from_millis(500));
    scheduler.jobs.remove(1);
    assert_eq!(scheduler.next_wake_in(due), None);
    scheduler.set_paused(0, true, due).unwrap();
    scheduler
        .set_paused(0, false, due + Duration::from_secs(2))
        .unwrap();
    assert!(scheduler
        .tick_with_wall_clock(due + Duration::from_secs(3), wall + Duration::from_secs(10))
        .is_empty());
    assert_eq!(scheduler.jobs.len(), 1);
    let saved = schedule_file::format_active(&scheduler.jobs).unwrap();
    let restored = schedule_file::parse(&saved).unwrap();
    assert_eq!(restored[0].offset_ms, Some(500));
    assert_eq!(restored[0].interval_ms, 500);
    assert!(scheduler
        .add_aligned(
            Packet::new_with_format(PacketFormat::EvaWire, 42).unwrap(),
            Direction::ToServer,
            500,
            501,
            None,
            (now, wall)
        )
        .is_err());
}

#[test]
fn java_maximum_interval_and_equal_offset_survive_settings_and_schedule_files() {
    use gearth_rust::settings::Settings;

    let input = "0\tfalse\t2147483647+2147483647\tTOSERVER\t{h:42}";
    let schedules = schedule_file::parse(input).unwrap();
    assert_eq!(schedule_file::format(&schedules).unwrap(), input);
    let settings = Settings {
        schedules,
        ..Settings::default()
    };
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).unwrap();
    let name = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let directory = std::env::temp_dir().join(format!("gearth-settings-test-{name}"));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("settings.json");
    settings.save(&path).unwrap();
    let restored = Settings::read(&path).unwrap();
    assert_eq!(restored.schedules, settings.schedules);

    let now = Instant::now();
    let mut scheduler = Scheduler::default();
    scheduler
        .add_aligned(
            Packet::new(42),
            Direction::ToServer,
            2_147_483_647,
            2_147_483_647,
            None,
            (now, UNIX_EPOCH),
        )
        .unwrap();
    assert!(scheduler.tick(now).is_empty());
    assert_eq!(scheduler.next_wake_in(now), None);
    assert_eq!(scheduler.jobs[0].alignment_offset_ms, Some(2_147_483_647));
    assert!(schedule_file::parse("0\tfalse\t2147483648+0\tTOSERVER\t{h:42}").is_err());
    let mut invalid = settings.to_json();
    invalid["schedules"][0]["offset_ms"] = serde_json::json!(2_147_483_648u64);
    std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
    assert!(Settings::read(&path).is_err());
    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn rejects_malformed_files_and_lossy_exports() {
    let valid = "0\tfalse\t500+100\tTOSERVER\t{h:42}";
    for input in [
        "0\tfalse\t0+0\tTOSERVER\t{h:42}",
        "0\tfalse\t500+501\tTOSERVER\t{h:42}",
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

#[test]
#[ignore = "requires the original Java scheduler oracle"]
fn schedule_file_matches_original_java_serializer() {
    let path = std::env::var("GEARTH_SCHEDULE_ORACLE").unwrap();
    let input = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
    let input = input.trim_end_matches('\n');
    let schedules = schedule_file::parse(input).unwrap();
    assert_eq!(schedules.len(), 2);
    assert_eq!(schedule_file::format(&schedules).unwrap(), input);
}

#[test]
#[ignore = "requires JavaSchedulerCatchupOracle"]
fn aligned_catchup_matches_java_scheduler_time_window() {
    let cp = std::env::var("GEARTH_SCHEDULER_CATCHUP_CLASSPATH").unwrap();
    let output = std::process::Command::new("java")
        .args(["-cp", &cp, "JavaSchedulerCatchupOracle"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for line in String::from_utf8(output.stdout).unwrap().lines() {
        let (input, expected) = line.split_once('=').unwrap();
        let values: Vec<u64> = input.split(',').map(|part| part.parse().unwrap()).collect();
        let (end, changed, interval, offset) = (values[0], values[1], values[2], values[3]);
        let start = end - changed + 1;
        let now = Instant::now();
        let mut scheduler = Scheduler::default();
        scheduler
            .add_aligned(
                Packet::new(42),
                Direction::ToServer,
                interval,
                offset,
                None,
                (now, UNIX_EPOCH + Duration::from_millis(start)),
            )
            .unwrap();
        let end_at = now + Duration::from_millis(changed - 1);
        let mut count = 0;
        loop {
            let batch = scheduler.tick(end_at).len();
            count += batch;
            if batch == 0 {
                break;
            }
            assert!(count <= 10000, "unexpected unbounded catch-up");
        }
        assert_eq!(count, expected.parse::<usize>().unwrap(), "{input}");
    }
}
