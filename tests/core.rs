use gearth_rust::{
    crypto::Rc4, encoding::*, expression, extension, packet::*, rules::*, scheduler::Scheduler,
};
use std::time::{Duration, Instant};

#[test]
fn scheduler_initial_draft_matches_original_java_sample() {
    let draft = gearth_rust::scheduler::ScheduleDraft::default();
    assert_eq!(draft.direction, Direction::ToClient);
    assert_eq!(
        draft.expression,
        "{in:Chat}{i:-1}{s:\"Frank loves G-Earth\"}{i:0}{i:33}{i:0}{i:0}"
    );
}

#[test]
fn scheduler_resolves_source_against_current_client_and_metadata_at_each_send() {
    use gearth_rust::packet_info::{PacketInfo, PacketInfoManager};
    let catalog = |header| {
        PacketInfoManager::new(
            "fixture",
            vec![PacketInfo {
                header,
                direction: Direction::ToServer,
                name: Some("Example".into()),
                hash: None,
                structure: None,
                source: "test".into(),
            }],
        )
    };
    let first = catalog(42);
    let second = catalog(77);
    let source = "{out:Example}{i:7}";
    let initial = expression::parse_with_format(
        source,
        PacketFormat::EvaWire,
        Some((Direction::ToServer, &first)),
    )
    .unwrap();
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_secs(100);
    let mut scheduler = Scheduler::default();
    scheduler
        .add_configured(
            initial,
            Direction::ToServer,
            500,
            Some(0),
            Some(3),
            (now, wall),
        )
        .unwrap();
    scheduler.jobs[0].source_expression = Some(source.into());
    let mut sent = Vec::new();
    scheduler
        .dispatch_jobs_filtered_with_wall_clock(now, wall, |job| {
            let packet = job
                .resolve_packet(PacketFormat::EvaWire, &first)
                .map_err(|_| "unresolved")?;
            sent.push((packet.header(), packet.format()));
            Ok::<_, &str>(true)
        })
        .unwrap();
    let next = now + Duration::from_millis(500);
    let next_wall = wall + Duration::from_millis(500);
    scheduler
        .dispatch_jobs_filtered_with_wall_clock(next, next_wall, |job| {
            let packet = job
                .resolve_packet(PacketFormat::WedgieOutgoing, &second)
                .map_err(|_| "unresolved")?;
            sent.push((packet.header(), packet.format()));
            Ok::<_, &str>(true)
        })
        .unwrap();
    assert_eq!(
        sent,
        [
            (42, PacketFormat::EvaWire),
            (77, PacketFormat::WedgieOutgoing)
        ]
    );
    let third = now + Duration::from_secs(1);
    let third_wall = wall + Duration::from_secs(1);
    assert_eq!(
        scheduler.dispatch_jobs_filtered_with_wall_clock(third, third_wall, |job| {
            job.resolve_packet(PacketFormat::EvaWire, &PacketInfoManager::default())
                .map_err(|_| "unresolved")?;
            Ok::<_, &str>(true)
        }),
        Err("unresolved")
    );
    assert_eq!(scheduler.jobs[0].remaining, Some(1));
    scheduler
        .dispatch_jobs_filtered_with_wall_clock(third, third_wall, |job| {
            let packet = job
                .resolve_packet(PacketFormat::EvaWire, &second)
                .map_err(|_| "unresolved")?;
            sent.push((packet.header(), packet.format()));
            Ok::<_, &str>(true)
        })
        .unwrap();
    assert_eq!(sent[2], (77, PacketFormat::EvaWire));
    assert!(scheduler.jobs.is_empty());
}

#[test]
fn scheduler_skips_disallowed_occurrence_without_starving_other_jobs() {
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_secs(100);
    let mut scheduler = Scheduler::default();
    scheduler
        .add_configured(
            Packet::new(1),
            Direction::ToServer,
            500,
            None,
            Some(2),
            (now, wall),
        )
        .unwrap();
    scheduler
        .add_configured(
            Packet::new(2),
            Direction::ToClient,
            500,
            None,
            Some(1),
            (now, wall),
        )
        .unwrap();
    let mut sent = Vec::new();
    scheduler
        .dispatch_filtered_with_wall_clock(now, wall, |_, packet| {
            if packet.header() == 1 {
                return Ok::<_, ()>(false);
            }
            sent.push(packet.header());
            Ok(true)
        })
        .unwrap();
    assert_eq!(sent, vec![2]);
    assert_eq!(scheduler.jobs.len(), 1);
    assert_eq!(scheduler.jobs[0].remaining, Some(2));
    assert_eq!(scheduler.jobs[0].next, now + Duration::from_millis(500));
    scheduler
        .dispatch_filtered_with_wall_clock(
            now + Duration::from_millis(500),
            wall + Duration::from_millis(500),
            |_, packet| {
                sent.push(packet.header());
                Ok::<_, ()>(true)
            },
        )
        .unwrap();
    assert_eq!(sent, vec![2, 1]);
    assert_eq!(scheduler.jobs[0].remaining, Some(1));
}

#[test]
fn java_bytebuffer_wire_vector() {
    let p = expression::parse("{h:123}{i:42}{s:\"hello\"}{b:true}").unwrap();
    assert_eq!(
        p.bytes(),
        &[0, 0, 0, 14, 0, 123, 0, 0, 0, 42, 0, 5, 104, 101, 108, 108, 111, 1]
    );
}
#[test]
fn primitives_and_latin1() {
    let mut p = Packet::new(65535);
    p.put_u8(255)
        .unwrap()
        .put_bool(true)
        .unwrap()
        .put_u16(65535)
        .unwrap()
        .put_i32(i32::MIN)
        .unwrap()
        .put_i64(i64::MAX)
        .unwrap()
        .put_f32(1.25)
        .unwrap()
        .put_f64(-2.5)
        .unwrap()
        .put_string("éÿ\0")
        .unwrap()
        .put_long_string("x\ty")
        .unwrap();
    assert_eq!(p.header(), 65535);
    assert_eq!(p.read_u8().unwrap(), 255);
    assert!(p.read_bool().unwrap());
    assert_eq!(p.read_u16().unwrap(), 65535);
    assert_eq!(p.read_i32().unwrap(), i32::MIN);
    assert_eq!(p.read_i64().unwrap(), i64::MAX);
    assert_eq!(p.read_f32().unwrap(), 1.25);
    assert_eq!(p.read_f64().unwrap(), -2.5);
    assert_eq!(p.read_string().unwrap(), "éÿ\0");
    assert_eq!(p.read_long_string().unwrap(), "x\ty");
    assert_eq!(p.remaining(), 0);
}
#[test]
fn failed_string_read_is_transactional() {
    let mut p = Packet::new(1);
    p.append(&[0, 4, b'x']).unwrap();
    assert!(p.read_string().is_err());
    assert_eq!(p.cursor(), 6);
}
#[test]
fn malformed_packets_rejected() {
    for data in [
        vec![],
        vec![0; 5],
        vec![0, 0, 0, 1, 0, 0],
        vec![255, 255, 255, 255, 0, 0],
    ] {
        assert!(Packet::from_bytes(data).is_err());
    }
}
#[test]
fn string_write_rejects_unrepresentable_without_mutating() {
    let mut p = Packet::new(1);
    assert!(p.put_string("🦀").is_err());
    assert_eq!(p.bytes().len(), 6);
}
#[test]
fn split_at_every_offset() {
    let p = expression::parse("{h:4000}{i:-42}{s:\"hello\"}").unwrap();
    for offset in 0..p.bytes().len() {
        let mut d = FrameDecoder::default();
        d.push(&p.bytes()[..offset]).unwrap();
        assert!(d.next_packet().unwrap().is_none());
        d.push(&p.bytes()[offset..]).unwrap();
        assert_eq!(d.next_packet().unwrap().unwrap().bytes(), p.bytes());
        assert!(d.next_packet().unwrap().is_none());
    }
}
#[test]
fn coalesced_frames() {
    let p = Packet::new(7);
    let mut d = FrameDecoder::default();
    d.push(&[p.bytes(), p.bytes(), p.bytes()].concat()).unwrap();
    for _ in 0..3 {
        assert_eq!(d.next_packet().unwrap().unwrap().header(), 7);
    }
    assert!(d.next_packet().unwrap().is_none());
}
#[test]
fn invalid_frame_prefix() {
    for prefix in [[0, 0, 0, 0], [255, 255, 255, 255]] {
        let mut d = FrameDecoder::default();
        d.push(&prefix).unwrap();
        assert!(d.next_packet().is_err());
    }
}
#[test]
fn hmessage_serialization_binary_tabs() {
    let mut p = Packet::new(255);
    p.append(&(0u8..=255).collect::<Vec<_>>()).unwrap();
    let m = Message {
        packet: p,
        direction: Direction::ToClient,
        index: 123,
        blocked: true,
    };
    let decoded = Message::parse(&m.stringify()).unwrap();
    assert_eq!(decoded.packet.bytes(), m.packet.bytes());
    assert_eq!(decoded.direction, m.direction);
    assert!(decoded.blocked);
    assert_eq!(decoded.index, 123);
}
#[test]
fn replace_resizes_and_fixes_length() {
    let mut p = expression::parse("{h:1}{s:\"ab\"}").unwrap();
    p.replace(6, 4, &[0, 1, b'x']).unwrap();
    assert_eq!(p.read_string().unwrap(), "x");
    assert!(Packet::from_bytes(p.bytes().to_vec()).is_ok());
    assert!(p.replace(0, 4, &[]).is_err());
}
#[test]
fn expression_quoted_braces_and_escapes() {
    let mut p = expression::parse("{h:9}{s:\"a}b\\\"c\\\\d\\n\"}").unwrap();
    assert_eq!(p.read_string().unwrap(), "a}b\"c\\d\n");
}
#[test]
fn lossless_expression_binary_roundtrip() {
    let mut p = Packet::new(50000);
    p.append(&(0u8..=255).collect::<Vec<_>>()).unwrap();
    assert_eq!(
        expression::parse(&expression::to_lossless_expression(&p))
            .unwrap()
            .bytes(),
        p.bytes()
    );
}
#[test]
fn invalid_expressions_rejected() {
    for s in [
        "",
        "{i:1}",
        "{h:-32769}",
        "{h:65536}",
        "{h:1}{s:\"unterminated}",
        "{h:1}{hex:0}",
        "{h:1}{x:1}",
        "{h:1}[256]",
    ] {
        assert!(expression::parse(s).is_err(), "{s}");
    }
}
#[test]
fn rc4_known_answer() {
    let mut bytes = b"Plaintext".to_vec();
    Rc4::new(b"Key").unwrap().apply(&mut bytes);
    assert_eq!(expression::hex(&bytes), "BB F3 16 E8 D9 40 AF 0A D3");
}
#[test]
fn rc4_streaming_rewind_and_restore() {
    let mut r = Rc4::new(b"test").unwrap();
    let before = r.state();
    let mut a = [0; 1024];
    r.apply(&mut a[..123]);
    r.apply(&mut a[123..]);
    r.rewind(1024);
    assert_eq!(r.state(), before);
    let mut b = [0; 1024];
    r.apply(&mut b);
    assert_eq!(a, b);
    let (s, x, y) = r.state();
    assert!(Rc4::from_state(s, x, y).is_ok());
    assert!(Rc4::from_state([0; 256], 0, 0).is_err());
    assert!(Rc4::new(b"").is_err());
}
#[test]
fn vl64_boundaries() {
    for n in [
        i32::MIN,
        -1000000,
        -256,
        -4,
        -1,
        0,
        1,
        3,
        4,
        63,
        64,
        256,
        1000000,
        i32::MAX,
    ] {
        let encoded = encode_vl64(n);
        assert_eq!(decode_vl64(&encoded).unwrap(), (n, encoded.len()));
    }
    assert_eq!(encode_vl64(0), b"H");
    assert_eq!(encode_vl64(1), b"I");
    assert!(decode_vl64(&[]).is_err());
}
#[test]
fn b64_known_values_and_limits() {
    assert_eq!(encode_b64(123, 2).unwrap(), b"A{");
    assert_eq!(decode_b64(b"A{").unwrap(), 123);
    assert!(encode_b64(4096, 2).is_err());
    assert!(decode_b64(b"!").is_err());
}
#[test]
fn extension_info_roundtrip() {
    let info = extension::ExtensionInfo {
        title: "test".into(),
        author: "me".into(),
        version: "1".into(),
        description: "é".into(),
        on_click: true,
        file: None,
        cookie: String::new(),
        can_leave: true,
        can_delete: false,
    };
    match extension::decode(extension::info_response(&info).unwrap()).unwrap() {
        extension::Incoming::Info(decoded) => assert_eq!(decoded, info),
        _ => panic!(),
    }
}
#[test]
fn extension_send_and_intercept_vectors() {
    let p = Packet::new(123);
    let mut encoded = extension::send(Direction::ToClient, &p).unwrap();
    assert_eq!(encoded.read_u8().unwrap(), 0);
    assert_eq!(encoded.read_i32().unwrap(), 6);
    match extension::decode(extension::send(Direction::ToServer, &p).unwrap()).unwrap() {
        extension::Incoming::Send { direction, packet } => {
            assert_eq!(direction, Direction::ToServer);
            assert_eq!(packet.bytes(), p.bytes());
        }
        _ => panic!(),
    };
    let message = Message {
        packet: p,
        direction: Direction::ToServer,
        index: 7,
        blocked: false,
    };
    match extension::decode(extension::manipulated(&message).unwrap()).unwrap() {
        extension::Incoming::Manipulated(m) => assert_eq!(m.stringify(), message.stringify()),
        _ => panic!(),
    }
}
#[test]
fn extension_rejects_unsupported_format() {
    let mut p = extension::send(Direction::ToServer, &Packet::new(1)).unwrap();
    let n = p.bytes().len();
    p.replace(n - 4, 4, &99i32.to_be_bytes()).unwrap();
    assert!(extension::decode(p).is_err());
}
#[test]
fn rules_direction_and_replacement() {
    let replacement = Packet::new(2);
    let rules = Rules {
        entries: vec![
            Rule {
                enabled: true,
                direction: Direction::ToServer,
                header: 1,
                action: Action::Replace(replacement),
            },
            Rule {
                enabled: true,
                direction: Direction::ToServer,
                header: 2,
                action: Action::Block,
            },
        ],
    };
    let mut m = Message {
        packet: Packet::new(1),
        direction: Direction::ToClient,
        index: 0,
        blocked: false,
    };
    rules.apply(&mut m);
    assert_eq!(m.packet.header(), 1);
    assert!(!m.blocked);
    m.direction = Direction::ToServer;
    rules.apply(&mut m);
    assert_eq!(m.packet.header(), 2);
    assert!(m.packet.edited);
    assert!(m.blocked);
}
#[test]
fn aligned_scheduler_replays_missed_slots_in_bounded_retryable_batches() {
    use gearth_rust::scheduler::MAX_CATCHUP_PER_DISPATCH;
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_millis(10_000);
    let mut scheduler = Scheduler::default();
    scheduler
        .add_aligned(Packet::new(1), Direction::ToServer, 1, 0, None, (now, wall))
        .unwrap();
    let late = now + Duration::from_millis(300);
    let late_wall = wall + Duration::from_millis(300);
    let mut accepted = 0;
    let result = scheduler.dispatch_with_wall_clock(late, late_wall, |_, _| {
        if accepted == 2 {
            return Err("full");
        }
        accepted += 1;
        Ok(())
    });
    assert_eq!(result, Err("full"));
    assert_eq!(accepted, 2);
    assert_eq!(scheduler.next_wake_in(late), Some(Duration::from_millis(1)));
    assert_eq!(scheduler.tick(late).len(), MAX_CATCHUP_PER_DISPATCH);
    assert_eq!(scheduler.tick(late).len(), MAX_CATCHUP_PER_DISPATCH);
    assert_eq!(scheduler.tick(late).len(), 43);
    assert!(scheduler.tick(late).is_empty());
    assert_eq!(scheduler.jobs[0].next, now + Duration::from_millis(301));

    let mut finite = Scheduler::default();
    finite
        .add_aligned(
            Packet::new(2),
            Direction::ToClient,
            100,
            0,
            Some(3),
            (now, wall),
        )
        .unwrap();
    assert_eq!(finite.tick(now + Duration::from_secs(2)).len(), 3);
    assert!(finite.jobs.is_empty());
}

#[test]
fn scheduler_no_catchup_bursts_and_repeat() {
    let now = Instant::now();
    let mut s = Scheduler::default();
    s.add(
        Packet::new(1),
        Direction::ToServer,
        Duration::from_secs(1),
        Some(2),
        now,
    )
    .unwrap();
    assert_eq!(s.tick(now).len(), 1);
    assert!(s.tick(now).is_empty());
    assert_eq!(s.tick(now + Duration::from_secs(100)).len(), 1);
    assert!(s.jobs.is_empty());
    assert!(s
        .add(
            Packet::new(1),
            Direction::ToServer,
            Duration::ZERO,
            None,
            now
        )
        .is_err());
}

#[test]
fn scheduler_wakeup_tracks_the_earliest_active_deadline() {
    let now = Instant::now();
    let mut scheduler = Scheduler::default();
    assert_eq!(scheduler.next_wake_in(now), None);
    scheduler
        .add(
            Packet::new(1),
            Direction::ToServer,
            Duration::from_millis(10),
            None,
            now,
        )
        .unwrap();
    scheduler
        .add(
            Packet::new(2),
            Direction::ToClient,
            Duration::from_millis(80),
            None,
            now,
        )
        .unwrap();
    assert_eq!(scheduler.next_wake_in(now), Some(Duration::from_millis(1)));
    assert_eq!(scheduler.tick(now).len(), 2);
    assert_eq!(scheduler.next_wake_in(now), Some(Duration::from_millis(10)));
    assert_eq!(
        scheduler.next_wake_in(now + Duration::from_millis(4)),
        Some(Duration::from_millis(6))
    );
    scheduler
        .set_paused(0, true, now + Duration::from_millis(4))
        .unwrap();
    assert_eq!(
        scheduler.next_wake_in(now + Duration::from_millis(4)),
        Some(Duration::from_millis(76))
    );
    scheduler
        .set_paused(1, true, now + Duration::from_millis(4))
        .unwrap();
    assert_eq!(
        scheduler.next_wake_in(now + Duration::from_millis(100)),
        None
    );
    scheduler
        .set_paused(0, false, now + Duration::from_millis(100))
        .unwrap();
    assert_eq!(
        scheduler.next_wake_in(now + Duration::from_millis(100)),
        Some(Duration::from_millis(10))
    );
    assert_eq!(
        scheduler.next_wake_in(now + Duration::from_millis(200)),
        Some(Duration::from_millis(1))
    );
}

#[test]
fn scheduler_batch_failure_is_atomic_and_preserves_existing_jobs() {
    use gearth_rust::scheduler::ScheduleSpec;
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_secs(1234);
    let mut scheduler = Scheduler::default();
    scheduler
        .add(
            Packet::new(1),
            Direction::ToServer,
            Duration::from_secs(1),
            None,
            now,
        )
        .unwrap();
    let spec = |header, interval_ms| ScheduleSpec {
        packet: Packet::new(header),
        source_expression: Some(format!("{{h:{header}}}")),
        direction: Direction::ToClient,
        interval_ms,
        offset_ms: None,
        repeat: Some(2),
    };
    assert!(scheduler
        .add_batch_configured(
            vec![(spec(2, 100), false), (spec(3, 0), false)],
            (now, wall)
        )
        .is_err());
    assert_eq!(scheduler.jobs.len(), 1);
    assert_eq!(scheduler.jobs[0].id, 0);
    scheduler
        .add_batch_configured(
            vec![(spec(2, 100), true), (spec(3, 100), false)],
            (now, wall),
        )
        .unwrap();
    assert_eq!(
        scheduler.jobs.iter().map(|job| job.id).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert!(scheduler.jobs[1].paused);
    assert_eq!(
        scheduler.jobs[1].source_expression.as_deref(),
        Some("{h:2}")
    );
    assert!(!scheduler.jobs[2].paused);
    assert_eq!(scheduler.tick(now).len(), 2);
}

#[test]
fn scheduler_replacement_is_atomic_and_does_not_reuse_ids() {
    use gearth_rust::scheduler::ScheduleSpec;
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_secs(100);
    let mut scheduler = Scheduler::default();
    scheduler
        .add(
            Packet::new(1),
            Direction::ToServer,
            Duration::from_secs(1),
            None,
            now,
        )
        .unwrap();
    let spec = |header, interval_ms| ScheduleSpec {
        packet: Packet::new(header),
        source_expression: Some(format!("{{h:{header}}}")),
        direction: Direction::ToClient,
        interval_ms,
        offset_ms: Some(0),
        repeat: None,
    };
    assert!(scheduler
        .replace_batch_configured(vec![(spec(2, 500), false), (spec(3, 0), true)], (now, wall))
        .is_err());
    assert_eq!(scheduler.jobs.len(), 1);
    assert_eq!(scheduler.jobs[0].id, 0);
    assert_eq!(scheduler.jobs[0].packet.header(), 1);
    scheduler
        .replace_batch_configured(vec![(spec(2, 500), true)], (now, wall))
        .unwrap();
    assert_eq!(scheduler.jobs.len(), 1);
    assert_eq!(scheduler.jobs[0].id, 1);
    assert!(scheduler.jobs[0].paused);
    assert!(scheduler.tick(now).is_empty());
    scheduler
        .replace_batch_configured(vec![], (now, wall))
        .unwrap();
    assert!(scheduler.jobs.is_empty());
    scheduler
        .replace_batch_configured(vec![(spec(3, 500), false)], (now, wall))
        .unwrap();
    assert_eq!(scheduler.jobs[0].id, 2);
}

#[test]
fn aligned_scheduler_resumes_at_the_current_boundary_without_replaying_missed_sends() {
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_millis(10_000);
    for (resume_ms, expected_wait) in [(300, 0), (350, 50)] {
        let mut scheduler = Scheduler::default();
        scheduler
            .add_aligned(
                Packet::new(1),
                Direction::ToServer,
                100,
                0,
                None,
                (now, wall),
            )
            .unwrap();
        scheduler.set_paused(0, true, now).unwrap();
        let resumed = now + Duration::from_millis(resume_ms);
        scheduler.set_paused(0, false, resumed).unwrap();
        assert_eq!(
            scheduler.jobs[0].next,
            resumed + Duration::from_millis(expected_wait)
        );
        let due = resumed + Duration::from_millis(expected_wait);
        assert_eq!(scheduler.tick(due).len(), 1);
        assert!(scheduler.tick(due).is_empty());
        assert_eq!(scheduler.jobs[0].next, due + Duration::from_millis(100));
    }
}

#[test]
fn scheduler_can_pause_and_repeat_until_removed() {
    let now = Instant::now();
    let mut scheduler = Scheduler::default();
    scheduler
        .add(
            Packet::new(2),
            Direction::ToClient,
            Duration::from_secs(1),
            None,
            now,
        )
        .unwrap();
    assert_eq!(scheduler.tick(now).len(), 1);
    scheduler.set_paused(0, true, now).unwrap();
    assert!(scheduler.tick(now + Duration::from_secs(50)).is_empty());
    scheduler
        .set_paused(0, false, now + Duration::from_secs(50))
        .unwrap();
    assert!(scheduler.tick(now + Duration::from_secs(50)).is_empty());
    assert_eq!(scheduler.tick(now + Duration::from_secs(51)).len(), 1);
    assert_eq!(scheduler.tick(now + Duration::from_secs(100)).len(), 1);
    assert_eq!(scheduler.jobs.len(), 1);
}

#[test]
fn scheduler_preserves_clock_alignment_when_late_or_resumed() {
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_millis(1234);
    let mut scheduler = Scheduler::default();
    scheduler
        .add_aligned(
            Packet::new(2),
            Direction::ToServer,
            500,
            100,
            None,
            (now, wall),
        )
        .unwrap();
    assert!(scheduler.tick(now + Duration::from_millis(365)).is_empty());
    assert_eq!(scheduler.tick(now + Duration::from_millis(475)).len(), 1);
    assert!(scheduler.tick(now + Duration::from_millis(865)).is_empty());
    assert_eq!(scheduler.tick(now + Duration::from_millis(866)).len(), 1);
    scheduler
        .set_paused(0, true, now + Duration::from_millis(900))
        .unwrap();
    scheduler
        .set_paused(0, false, now + Duration::from_millis(2000))
        .unwrap();
    assert!(scheduler.tick(now + Duration::from_millis(2365)).is_empty());
    assert_eq!(scheduler.tick(now + Duration::from_millis(2366)).len(), 1);
    assert!(scheduler
        .add_aligned(
            Packet::new(2),
            Direction::ToServer,
            500,
            501,
            None,
            (now, wall)
        )
        .is_err());
    assert_eq!(scheduler.jobs.len(), 1);
}

#[test]
fn scheduler_replays_forward_clock_jumps_and_realigns_backward() {
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_millis(1234);
    let mut scheduler = Scheduler::default();
    scheduler
        .add_aligned(
            Packet::new(2),
            Direction::ToServer,
            500,
            100,
            None,
            (now, wall),
        )
        .unwrap();

    assert!(scheduler
        .tick_with_wall_clock(
            now + Duration::from_millis(200),
            wall + Duration::from_millis(200)
        )
        .is_empty());
    let forward = std::time::UNIX_EPOCH + Duration::from_millis(2384);
    assert_eq!(
        scheduler
            .tick_with_wall_clock(now + Duration::from_millis(250), forward)
            .len(),
        2
    );
    assert!(scheduler
        .tick_with_wall_clock(now + Duration::from_millis(250), forward)
        .is_empty());
    assert!(scheduler
        .tick_with_wall_clock(
            now + Duration::from_millis(465),
            forward + Duration::from_millis(215)
        )
        .is_empty());
    assert_eq!(
        scheduler
            .tick_with_wall_clock(
                now + Duration::from_millis(466),
                forward + Duration::from_millis(216)
            )
            .len(),
        1
    );

    let backward = std::time::UNIX_EPOCH + Duration::from_millis(1534);
    assert!(scheduler
        .tick_with_wall_clock(now + Duration::from_millis(600), backward)
        .is_empty());
    assert!(scheduler
        .tick_with_wall_clock(
            now + Duration::from_millis(665),
            backward + Duration::from_millis(65)
        )
        .is_empty());
    assert_eq!(
        scheduler
            .tick_with_wall_clock(
                now + Duration::from_millis(666),
                backward + Duration::from_millis(66)
            )
            .len(),
        1
    );
    assert!(scheduler
        .tick_with_wall_clock(
            now + Duration::from_millis(666),
            backward + Duration::from_millis(66)
        )
        .is_empty());
}

#[test]
fn scheduler_detects_small_forward_and_backward_wall_clock_jumps() {
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_millis(10_000);
    let mut scheduler = Scheduler::default();
    scheduler
        .add_aligned(
            Packet::new(1),
            Direction::ToServer,
            10,
            0,
            None,
            (now, wall),
        )
        .unwrap();
    assert_eq!(scheduler.tick_with_wall_clock(now, wall).len(), 1);
    // At monotonic +6 ms, wall time jumps four milliseconds and reaches a slot.
    let at = now + Duration::from_millis(6);
    let forward = wall + Duration::from_millis(10);
    assert_eq!(scheduler.tick_with_wall_clock(at, forward).len(), 1);
    assert!(scheduler.tick_with_wall_clock(at, forward).is_empty());
    // A five-millisecond backward jump must rebase to the next new wall slot.
    let backward_at = at + Duration::from_millis(1);
    let backward = wall + Duration::from_millis(6);
    assert!(scheduler
        .tick_with_wall_clock(backward_at, backward)
        .is_empty());
    assert!(scheduler
        .tick_with_wall_clock(
            backward_at + Duration::from_millis(3),
            backward + Duration::from_millis(3)
        )
        .is_empty());
    assert_eq!(
        scheduler
            .tick_with_wall_clock(
                backward_at + Duration::from_millis(4),
                backward + Duration::from_millis(4)
            )
            .len(),
        1
    );
}

#[test]
fn scheduler_preserves_pending_sends_across_backward_clock_jump() {
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_millis(10_000);
    let mut scheduler = Scheduler::default();
    scheduler
        .add_aligned(
            Packet::new(1),
            Direction::ToServer,
            100,
            0,
            None,
            (now, wall),
        )
        .unwrap();
    let at = now + Duration::from_millis(500);
    let mut sent = 0;
    let error =
        scheduler.dispatch_with_wall_clock(at, wall + Duration::from_millis(500), |_, _| {
            if sent == 2 {
                return Err("full");
            }
            sent += 1;
            Ok(())
        });
    assert_eq!(error, Err("full"));
    assert_eq!(sent, 2);
    let backwards = wall - Duration::from_millis(200);
    scheduler
        .dispatch_with_wall_clock(at + Duration::from_millis(1), backwards, |_, _| {
            sent += 1;
            Ok::<(), &str>(())
        })
        .unwrap();
    assert_eq!(sent, 6);
    assert!(scheduler
        .tick_with_wall_clock(at + Duration::from_millis(1), backwards)
        .is_empty());
    assert_eq!(
        scheduler
            .tick_with_wall_clock(
                at + Duration::from_millis(101),
                backwards + Duration::from_millis(100)
            )
            .len(),
        1
    );
}

#[test]
fn scheduler_retains_huge_forward_clock_jump_without_instant_underflow() {
    use gearth_rust::scheduler::MAX_CATCHUP_PER_DISPATCH;
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_secs(10_000);
    let mut scheduler = Scheduler::default();
    scheduler
        .add_aligned(
            Packet::new(1),
            Direction::ToServer,
            1000,
            0,
            None,
            (now, wall),
        )
        .unwrap();
    assert_eq!(scheduler.tick_with_wall_clock(now, wall).len(), 1);
    let jumped = wall
        .checked_add(Duration::from_secs(50_000_000_000))
        .unwrap();
    assert_eq!(
        scheduler
            .tick_with_wall_clock(now + Duration::from_millis(1), jumped)
            .len(),
        MAX_CATCHUP_PER_DISPATCH
    );
    assert_eq!(
        scheduler.next_wake_in(now + Duration::from_millis(1)),
        Some(Duration::from_millis(1))
    );
    assert_eq!(
        scheduler
            .tick_with_wall_clock(now + Duration::from_millis(1), jumped)
            .len(),
        MAX_CATCHUP_PER_DISPATCH
    );
}

#[test]
fn scheduler_retries_a_forward_clock_jump_after_queue_rejection() {
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_millis(1234);
    let mut scheduler = Scheduler::default();
    scheduler
        .add_aligned(
            Packet::new(2),
            Direction::ToServer,
            500,
            100,
            None,
            (now, wall),
        )
        .unwrap();
    let at = now + Duration::from_millis(250);
    let jumped = std::time::UNIX_EPOCH + Duration::from_millis(2384);
    let mut sent = 0;
    let result = scheduler.dispatch_with_wall_clock(at, jumped, |_, _| {
        if sent == 1 {
            return Err("queue full");
        }
        sent += 1;
        Ok(())
    });
    assert_eq!(result, Err("queue full"));
    assert_eq!(sent, 1);
    scheduler
        .dispatch_with_wall_clock(at, jumped, |_, _| {
            sent += 1;
            Ok::<(), &str>(())
        })
        .unwrap();
    assert_eq!(sent, 2);
    assert!(scheduler.tick_with_wall_clock(at, jumped).is_empty());
    assert_eq!(
        scheduler
            .tick_with_wall_clock(
                at + Duration::from_millis(216),
                jumped + Duration::from_millis(216)
            )
            .len(),
        1
    );
}

#[test]
fn scheduler_keeps_relative_jobs_and_paused_jobs_safe_after_clock_changes() {
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_millis(1234);
    let mut scheduler = Scheduler::default();
    scheduler
        .add(
            Packet::new(1),
            Direction::ToServer,
            Duration::from_millis(500),
            None,
            now,
        )
        .unwrap();
    scheduler
        .add_aligned(
            Packet::new(2),
            Direction::ToClient,
            500,
            100,
            None,
            (now, wall),
        )
        .unwrap();
    scheduler.set_paused(1, true, now).unwrap();
    assert_eq!(scheduler.tick_with_wall_clock(now, wall).len(), 1);
    let changed = std::time::UNIX_EPOCH + Duration::from_millis(2000);
    assert!(scheduler
        .tick_with_wall_clock(now + Duration::from_millis(250), changed)
        .is_empty());
    assert_eq!(
        scheduler
            .tick_with_wall_clock(
                now + Duration::from_millis(500),
                changed + Duration::from_millis(250)
            )
            .len(),
        1
    );
    assert!(scheduler.jobs[1].paused);
    scheduler
        .set_paused(1, false, now + Duration::from_millis(500))
        .unwrap();
    assert!(scheduler
        .tick_with_wall_clock(
            now + Duration::from_millis(500),
            changed + Duration::from_millis(250)
        )
        .is_empty());
    assert_eq!(
        scheduler
            .tick_with_wall_clock(
                now + Duration::from_millis(850),
                changed + Duration::from_millis(600)
            )
            .len(),
        1
    );
}

#[test]
fn scheduler_edit_targets_stable_identity_and_preserves_pause_on_failure() {
    use gearth_rust::scheduler::ScheduleSpec;
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_millis(1234);
    let mut scheduler = Scheduler::default();
    scheduler
        .add(
            Packet::new(1),
            Direction::ToClient,
            Duration::from_secs(1),
            None,
            now,
        )
        .unwrap();
    scheduler
        .add(
            Packet::new(2),
            Direction::ToServer,
            Duration::from_secs(1),
            None,
            now,
        )
        .unwrap();
    let id = scheduler.jobs[1].id;
    scheduler.set_paused(1, true, now).unwrap();
    scheduler.jobs.remove(0);
    let spec = |offset_ms| ScheduleSpec {
        packet: Packet::new(7),
        source_expression: Some("{h:7}".into()),
        direction: Direction::ToClient,
        interval_ms: 500,
        offset_ms,
        repeat: Some(3),
    };
    assert!(scheduler
        .update_configured(id, spec(Some(501)), (now, wall))
        .is_err());
    assert_eq!(scheduler.jobs[0].packet.header(), 2);
    assert!(scheduler.jobs[0].paused);
    scheduler
        .update_configured(id, spec(Some(100)), (now, wall))
        .unwrap();
    assert_eq!(scheduler.jobs[0].id, id);
    assert_eq!(scheduler.jobs[0].packet.header(), 7);
    assert_eq!(
        scheduler.jobs[0].source_expression.as_deref(),
        Some("{h:7}")
    );
    assert_eq!(scheduler.jobs[0].remaining, Some(3));
    assert!(scheduler.jobs[0].paused);
    assert!(scheduler
        .update_configured(id + 100, spec(None), (now, wall))
        .is_err());
    assert_eq!(scheduler.jobs[0].packet.header(), 7);
    scheduler.set_paused(0, false, now).unwrap();
    scheduler
        .update_configured(id, spec(None), (now, wall))
        .unwrap();
    assert!(scheduler.tick(now).is_empty());
    assert_eq!(scheduler.tick(now + Duration::from_millis(500)).len(), 1);
    scheduler.jobs.clear();
    scheduler
        .add(
            Packet::new(8),
            Direction::ToServer,
            Duration::from_secs(1),
            None,
            now,
        )
        .unwrap();
    assert_ne!(scheduler.jobs[0].id, id);
    assert!(scheduler
        .update_configured(id, spec(None), (now, wall))
        .is_err());
}

#[test]
fn scheduler_keeps_unsent_jobs_when_injection_queue_rejects_a_packet() {
    let now = Instant::now();
    let wall = std::time::UNIX_EPOCH + Duration::from_millis(1234);
    let mut scheduler = Scheduler::default();
    for (header, repeat) in [(1, 1), (2, 2), (3, 1)] {
        scheduler
            .add(
                Packet::new(header),
                Direction::ToServer,
                Duration::from_secs(1),
                Some(repeat),
                now,
            )
            .unwrap();
    }
    let mut accepted = Vec::new();
    let result = scheduler.dispatch_with_wall_clock(now, wall, |_, packet| {
        if packet.header() == 2 {
            return Err("queue full");
        }
        accepted.push(packet.header());
        Ok(())
    });
    assert_eq!(result, Err("queue full"));
    assert_eq!(accepted, [1]);
    assert_eq!(scheduler.jobs.len(), 2);
    assert_eq!(scheduler.jobs[0].packet.header(), 2);
    assert_eq!(scheduler.jobs[0].remaining, Some(2));
    assert_eq!(scheduler.jobs[1].packet.header(), 3);
    scheduler
        .dispatch_with_wall_clock(now, wall, |_, packet| {
            accepted.push(packet.header());
            Ok::<(), &str>(())
        })
        .unwrap();
    assert_eq!(accepted, [1, 2, 3]);
    assert_eq!(scheduler.jobs.len(), 1);
    assert_eq!(scheduler.jobs[0].remaining, Some(1));
    assert!(scheduler.tick(now).is_empty());
    assert_eq!(scheduler.tick(now + Duration::from_secs(1)).len(), 1);
}
