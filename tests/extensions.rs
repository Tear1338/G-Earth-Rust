use gearth_rust::{
    extension::{self, ExtensionInfo},
    extension_host::{ConnectionDetails, ExtensionHost, HostEvent},
    packet::{read_frame, write_frame, Direction, Message, Packet},
    packet_info::{PacketInfo, PacketInfoManager},
};
use std::{
    net::TcpStream,
    thread,
    time::{Duration, Instant},
};
fn info() -> ExtensionInfo {
    ExtensionInfo {
        title: "fixture".into(),
        author: "test".into(),
        version: "1".into(),
        description: "fixture".into(),
        on_click: true,
        file: None,
        cookie: String::new(),
        can_leave: true,
        can_delete: true,
    }
}
fn details() -> ConnectionDetails {
    ConnectionDetails {
        host: "test.example".into(),
        port: 30000,
        version: "TEST".into(),
        identifier: "test".into(),
        client_type: "FLASH".into(),
        packets: PacketInfoManager::new(
            "TEST",
            vec![PacketInfo {
                header: 77,
                name: Some("TestOutgoing".into()),
                hash: None,
                structure: Some("i".into()),
                direction: Direction::ToServer,
                source: "test".into(),
            }],
        ),
    }
}
fn connect(
    host: &ExtensionHost,
    events: &std::sync::mpsc::Receiver<HostEvent>,
) -> (TcpStream, u64) {
    let mut stream = TcpStream::connect(host.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 2);
    write_frame(&mut stream, &extension::info_response(&info()).unwrap()).unwrap();
    let id = match events.recv_timeout(Duration::from_secs(3)).unwrap() {
        HostEvent::Pending { id, .. } => id,
        e => panic!("{e:?}"),
    };
    host.approve(id).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 7);
    (stream, id)
}
#[test]
fn requires_approval_and_supports_flags_click_injection_and_interception() {
    let (host, events) =
        ExtensionHost::start("127.0.0.1:0".parse().unwrap(), vec!["-test".into()]).unwrap();
    host.start_connection(details()).unwrap();
    let (mut stream, id) = connect(&host, &events);
    let mut start = read_frame(&mut stream).unwrap();
    assert_eq!(start.header(), 5);
    assert_eq!(start.read_string().unwrap(), "test.example");
    assert_eq!(start.read_i32().unwrap(), 30000);
    let version = start.read_string().unwrap();
    start.read_string().unwrap();
    start.read_string().unwrap();
    assert_eq!(
        PacketInfoManager::read_from(version, &mut start)
            .unwrap()
            .by_name(Direction::ToServer, "TestOutgoing")
            .unwrap()
            .header,
        77
    );
    write_frame(&mut stream, &Packet::new(3)).unwrap();
    let mut flags = read_frame(&mut stream).unwrap();
    assert_eq!(flags.header(), 4);
    assert_eq!(flags.read_i32().unwrap(), 1);
    assert_eq!(flags.read_string().unwrap(), "-test");
    host.click(id).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 1);
    write_frame(
        &mut stream,
        &extension::send(Direction::ToServer, &Packet::new(91)).unwrap(),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let injections = host.take_injections();
        if !injections.is_empty() {
            assert_eq!(injections[0].1.header(), 91);
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    let reply = thread::spawn(move || {
        let mut p = read_frame(&mut stream).unwrap();
        assert_eq!(p.header(), 3);
        let mut message = Message::parse(&p.read_long_string().unwrap()).unwrap();
        message.packet.set_header(88).unwrap();
        message.blocked = true;
        write_frame(&mut stream, &extension::manipulated(&message).unwrap()).unwrap();
        stream
    });
    let mut m = Message {
        packet: Packet::new(77),
        direction: Direction::ToServer,
        index: 42,
        blocked: false,
    };
    host.intercept(&mut m).unwrap();
    assert_eq!(m.packet.header(), 88);
    assert!(m.blocked);
    drop(reply.join().unwrap());
    host.stop();
}

#[test]
fn reconnect_does_not_replay_injections_from_a_previous_session() {
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    host.start_connection(details()).unwrap();
    let (mut stream, _) = connect(&host, &events);
    assert_eq!(read_frame(&mut stream).unwrap().header(), 5);

    // The flags response is a protocol barrier: the preceding injection has
    // been processed and queued before the connection is ended.
    write_frame(
        &mut stream,
        &extension::send(Direction::ToServer, &Packet::new(91)).unwrap(),
    )
    .unwrap();
    write_frame(&mut stream, &Packet::new(3)).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 4);
    host.end_connection();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 6);

    // An extension may continue sending while no game session is active.
    write_frame(
        &mut stream,
        &extension::send(Direction::ToServer, &Packet::new(92)).unwrap(),
    )
    .unwrap();
    write_frame(&mut stream, &Packet::new(3)).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 4);
    host.start_connection(details()).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 5);
    assert!(host.take_injections().is_empty());

    write_frame(
        &mut stream,
        &extension::send(Direction::ToServer, &Packet::new(93)).unwrap(),
    )
    .unwrap();
    write_frame(&mut stream, &Packet::new(3)).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 4);
    let packets = host.take_injections();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].1.header(), 93);
    drop(stream);
    host.stop();
}

#[test]
fn a_full_injection_queue_reports_the_dropped_packet_and_keeps_the_extension_connected() {
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    host.start_connection(details()).unwrap();
    let (mut stream, id) = connect(&host, &events);
    assert_eq!(read_frame(&mut stream).unwrap().header(), 5);
    for header in 0..=384 {
        write_frame(
            &mut stream,
            &extension::send(Direction::ToServer, &Packet::new(header)).unwrap(),
        )
        .unwrap();
    }
    // This response confirms that all 385 requests were handled in order.
    write_frame(&mut stream, &Packet::new(3)).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 4);
    assert!(events.try_iter().any(|event| matches!(event, HostEvent::Console { id: source, text } if source == id && text.contains("Packet 384 not sent") && text.contains("queue full"))));
    let mut headers = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while headers.len() < 384 {
        headers.extend(
            host.take_injections()
                .into_iter()
                .map(|(_, packet)| packet.header()),
        );
        assert!(Instant::now() < deadline, "deferred packets did not drain");
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(headers, (0..384).collect::<Vec<_>>());
    assert!(host.take_injections().is_empty());
    write_frame(
        &mut stream,
        &extension::send(Direction::ToServer, &Packet::new(300)).unwrap(),
    )
    .unwrap();
    write_frame(&mut stream, &Packet::new(3)).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 4);
    assert_eq!(host.take_injections()[0].1.header(), 300);
    drop(stream);
    host.stop();
}

#[test]
fn temporary_transport_backpressure_preserves_order_and_disconnect_clears_pending() {
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    host.start_connection(details()).unwrap();
    let (mut stream, _) = connect(&host, &events);
    assert_eq!(read_frame(&mut stream).unwrap().header(), 5);
    for header in [41, 42, 43] {
        write_frame(
            &mut stream,
            &extension::send(Direction::ToClient, &Packet::new(header)).unwrap(),
        )
        .unwrap();
    }
    write_frame(&mut stream, &Packet::new(3)).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 4);
    let mut accepted = Vec::new();
    let mut retained_address = None;
    assert_eq!(
        host.forward_injections(|_, packet| {
            if packet.header() == 42 {
                retained_address = Some(packet.bytes().as_ptr() as usize);
                return Err((std::io::Error::from(std::io::ErrorKind::WouldBlock), packet));
            }
            accepted.push(packet.header());
            Ok(())
        })
        .unwrap(),
        1
    );
    assert_eq!(accepted, [41]);
    assert_eq!(
        host.forward_injections(|_, packet| {
            if packet.header() == 42 {
                assert_eq!(Some(packet.bytes().as_ptr() as usize), retained_address);
            }
            accepted.push(packet.header());
            Ok(())
        })
        .unwrap(),
        2
    );
    assert_eq!(accepted, [41, 42, 43]);
    write_frame(
        &mut stream,
        &extension::send(Direction::ToClient, &Packet::new(44)).unwrap(),
    )
    .unwrap();
    write_frame(&mut stream, &Packet::new(3)).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 4);
    assert!(host
        .forward_injections(|_, packet| Err((std::io::Error::other("transport failed"), packet)))
        .is_err());
    assert_eq!(
        host.forward_injections(|_, packet| Err((
            std::io::Error::from(std::io::ErrorKind::WouldBlock),
            packet
        )))
        .unwrap(),
        0
    );
    host.end_connection();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 6);
    host.start_connection(details()).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 5);
    assert!(host.take_injections().is_empty());
    drop(stream);
    host.stop();
}

#[test]
fn deferred_extension_packets_do_not_block_interception_or_leak_across_reconnects() {
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    host.start_connection(details()).unwrap();
    let (mut stream, _) = connect(&host, &events);
    assert_eq!(read_frame(&mut stream).unwrap().header(), 5);
    for header in 0..257 {
        write_frame(
            &mut stream,
            &extension::send(Direction::ToServer, &Packet::new(header)).unwrap(),
        )
        .unwrap();
    }
    write_frame(&mut stream, &Packet::new(3)).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 4);
    let reply = thread::spawn(move || {
        let mut request = read_frame(&mut stream).unwrap();
        assert_eq!(request.header(), 3);
        let mut message = Message::parse(&request.read_long_string().unwrap()).unwrap();
        message.packet.set_header(88).unwrap();
        write_frame(&mut stream, &extension::manipulated(&message).unwrap()).unwrap();
        stream
    });
    let mut message = Message {
        packet: Packet::new(77),
        direction: Direction::ToServer,
        index: 10,
        blocked: false,
    };
    host.intercept(&mut message).unwrap();
    assert_eq!(message.packet.header(), 88);
    let mut stream = reply.join().unwrap();
    host.end_connection();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 6);
    host.start_connection(details()).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 5);
    write_frame(
        &mut stream,
        &extension::send(Direction::ToServer, &Packet::new(999)).unwrap(),
    )
    .unwrap();
    write_frame(&mut stream, &Packet::new(3)).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 4);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut headers = Vec::new();
    while headers.is_empty() {
        headers.extend(
            host.take_injections()
                .into_iter()
                .map(|(_, packet)| packet.header()),
        );
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(headers, [999]);
    assert!(host.take_injections().is_empty());
    drop(stream);
    host.stop();
}

#[test]
fn packet_safety_blocks_unseen_extension_packets_without_disconnecting() {
    use gearth_rust::packet_safety::PacketSafety;
    use std::sync::{Arc, Mutex};
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    let safety = Arc::new(Mutex::new(PacketSafety::default()));
    host.set_packet_safety(safety.clone()).unwrap();
    host.start_connection(details()).unwrap();
    let (mut stream, id) = connect(&host, &events);
    assert_eq!(read_frame(&mut stream).unwrap().header(), 5);
    write_frame(
        &mut stream,
        &extension::send(Direction::ToServer, &Packet::new(91)).unwrap(),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if events.try_iter().any(|event| matches!(event, HostEvent::Console {id: source, text} if source == id && text.contains("91 not sent"))) { break; }
        assert!(Instant::now() < deadline, "missing blocked-packet event");
        thread::sleep(Duration::from_millis(5));
    }
    assert!(host.take_injections().is_empty());
    safety
        .lock()
        .unwrap()
        .observe("TEST", Direction::ToServer, 92);
    write_frame(
        &mut stream,
        &extension::send(Direction::ToServer, &Packet::new(92)).unwrap(),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let packets = host.take_injections();
        if !packets.is_empty() {
            assert_eq!(packets[0].1.header(), 92);
            break;
        }
        assert!(Instant::now() < deadline, "observed packet was not queued");
        thread::sleep(Duration::from_millis(5));
    }
    safety.lock().unwrap().set_developer_mode(true);
    write_frame(
        &mut stream,
        &extension::send(Direction::ToClient, &Packet::new(93)).unwrap(),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let packets = host.take_injections();
        if !packets.is_empty() {
            assert_eq!(packets[0].1.header(), 93);
            break;
        }
        assert!(Instant::now() < deadline, "developer packet was not queued");
        thread::sleep(Duration::from_millis(5));
    }
    drop(stream);
    host.stop();
}

#[test]
fn packet_to_string_uses_known_structure_and_falls_back_to_prediction() {
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    host.start_connection(details()).unwrap();
    let (mut stream, _) = connect(&host, &events);
    assert_eq!(read_frame(&mut stream).unwrap().header(), 5);
    for (header, expected) in [(77, "{out:TestOutgoing}{i:42}"), (90, "{h:90}{i:42}")] {
        let mut target = Packet::new(header);
        target.put_i32(42).unwrap();
        let mut request = Packet::new(20);
        request.put_long_string(&target.stringify()).unwrap();
        write_frame(&mut stream, &request).unwrap();
        let mut response = read_frame(&mut stream).unwrap();
        assert_eq!(response.header(), 20);
        let _ = response.read_long_string().unwrap();
        assert_eq!(response.read_utf8_long().unwrap(), expected);
    }
    host.stop();
}
#[test]
fn launch_token_is_bound_to_filename_and_one_use() {
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    let token = host.register_launch("fixture.jar").unwrap();
    let mut metadata = info();
    metadata.file = Some("fixture.jar".into());
    metadata.cookie = token.clone();
    let mut stream = TcpStream::connect(host.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    read_frame(&mut stream).unwrap();
    write_frame(&mut stream, &extension::info_response(&metadata).unwrap()).unwrap();
    assert_eq!(read_frame(&mut stream).unwrap().header(), 7);
    assert!(matches!(
        events.recv_timeout(Duration::from_secs(2)).unwrap(),
        HostEvent::Connected { .. }
    ));
    let mut replay = TcpStream::connect(host.address).unwrap();
    replay
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    read_frame(&mut replay).unwrap();
    write_frame(&mut replay, &extension::info_response(&metadata).unwrap()).unwrap();
    assert!(read_frame(&mut replay).is_err());
    host.stop();
}
#[test]
fn unresponsive_extension_has_bounded_timeout() {
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    let (_stream, _) = connect(&host, &events);
    let start = Instant::now();
    let result = host.intercept(&mut Message {
        packet: Packet::new(77),
        direction: Direction::ToServer,
        index: 1,
        blocked: false,
    });
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(2));
    host.stop();
}
#[test]
fn identifier_database_roundtrip_and_duplicate_directions() {
    let text = "TOSERVER\t77\tSameName\thash1\ti\ttest\nTOCLIENT\t78\tSameName\thash2\ts\ttest\n";
    let db = PacketInfoManager::from_tsv("TEST", text).unwrap();
    assert_eq!(
        db.by_name(Direction::ToClient, "SameName").unwrap().header,
        78
    );
    let mut packet = Packet::new(0);
    db.append_to(&mut packet).unwrap();
    let decoded = PacketInfoManager::read_from("TEST", &mut packet).unwrap();
    assert_eq!(decoded.entries(), db.entries());
}
#[test]
fn language_is_in_host_info_and_updates_existing_extensions() {
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    host.set_language("fr").unwrap();
    let mut stream = TcpStream::connect(host.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    read_frame(&mut stream).unwrap();
    write_frame(&mut stream, &extension::info_response(&info()).unwrap()).unwrap();
    let id = match events.recv_timeout(Duration::from_secs(2)).unwrap() {
        HostEvent::Pending { id, .. } => id,
        e => panic!("{e:?}"),
    };
    host.approve(id).unwrap();
    let mut init = read_frame(&mut stream).unwrap();
    assert_eq!(init.header(), 7);
    assert!(!init.read_bool().unwrap());
    init.read_string().unwrap();
    init.read_string().unwrap();
    assert_eq!(init.read_i32().unwrap(), 1);
    assert_eq!(init.read_string().unwrap(), "language");
    assert_eq!(init.read_string().unwrap(), "fr");
    host.set_language("de").unwrap();
    let mut update = read_frame(&mut stream).unwrap();
    assert_eq!(update.header(), 10);
    update.read_string().unwrap();
    update.read_string().unwrap();
    assert_eq!(update.read_i32().unwrap(), 1);
    assert_eq!(update.read_string().unwrap(), "language");
    assert_eq!(update.read_string().unwrap(), "de");
    host.stop();
}
