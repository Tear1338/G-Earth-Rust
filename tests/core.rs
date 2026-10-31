use gearth_rust::{
    crypto::Rc4, encoding::*, expression, extension, packet::*, rules::*, scheduler::Scheduler,
};
use std::time::{Duration, Instant};

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
        "{h:1}garbage",
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
    p.replace(n - 4, 4, &1i32.to_be_bytes()).unwrap();
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
