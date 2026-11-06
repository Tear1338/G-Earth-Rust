use gearth_rust::{
    packet::{read_frame, write_frame, Direction, Packet},
    relay::{Config, Event, Relay},
    rules::{Action, Rule, Rules},
    scheduler::Scheduler,
};
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    thread,
    time::{Duration, Instant, SystemTime},
};
fn wait_for(events: &std::sync::mpsc::Receiver<Event>, predicate: impl Fn(&Event) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(e) = events.recv_timeout(Duration::from_millis(50)) {
            if predicate(&e) {
                return;
            }
        }
    }
    panic!("timed out waiting for relay event");
}
#[test]
fn duplex_injection_rules_and_stop() {
    let remote = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut relay, events) = Relay::start(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        remote: remote.local_addr().unwrap().to_string(),
    })
    .unwrap();
    let mut client = TcpStream::connect(relay.address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (mut server, _) = remote.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    wait_for(&events, |e| matches!(e, Event::Connected(_)));
    let mut p = Packet::new(100);
    p.put_i32(42).unwrap();
    write_frame(&mut client, &p).unwrap();
    assert_eq!(read_frame(&mut server).unwrap().bytes(), p.bytes());
    let reply = Packet::new(101);
    write_frame(&mut server, &reply).unwrap();
    assert_eq!(read_frame(&mut client).unwrap().header(), 101);
    relay.inject(Direction::ToClient, Packet::new(200)).unwrap();
    assert_eq!(read_frame(&mut client).unwrap().header(), 200);
    relay.inject(Direction::ToServer, Packet::new(201)).unwrap();
    assert_eq!(read_frame(&mut server).unwrap().header(), 201);
    relay
        .set_rules(Rules {
            entries: vec![
                Rule {
                    enabled: true,
                    direction: Direction::ToServer,
                    header: 300,
                    action: Action::Block,
                },
                Rule {
                    enabled: true,
                    direction: Direction::ToServer,
                    header: 301,
                    action: Action::Replace(Packet::new(302)),
                },
            ],
        })
        .unwrap();
    write_frame(&mut client, &Packet::new(300)).unwrap();
    write_frame(&mut client, &Packet::new(301)).unwrap();
    assert_eq!(read_frame(&mut server).unwrap().header(), 302);
    wait_for(
        &events,
        |e| matches!(e,Event::Packet(m) if m.blocked&&m.packet.header()==300),
    );
    let start = Instant::now();
    relay.stop();
    assert!(start.elapsed() < Duration::from_secs(3));
    assert!(!relay.connected());
    assert!(relay.inject(Direction::ToServer, Packet::new(1)).is_err());
}

#[test]
fn tracks_only_original_traffic_before_rules_not_injections() {
    use gearth_rust::{
        extension_host::ConnectionDetails, packet_info::PacketInfoManager,
        packet_safety::PacketSafety, relay::RelayOptions,
    };
    use std::sync::{Arc, Mutex};
    let safety = Arc::new(Mutex::new(PacketSafety::default()));
    let remote = TcpListener::bind("127.0.0.1:0").unwrap();
    let options = RelayOptions {
        packet_safety: Some(safety.clone()),
        connection: Some(ConnectionDetails {
            host: "fixture".into(),
            port: 1,
            version: "fixture-v1".into(),
            identifier: "fixture".into(),
            client_type: "FLASH".into(),
            packets: PacketInfoManager::default(),
        }),
        ..Default::default()
    };
    let (mut relay, events) = Relay::start_with_options(
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            remote: remote.local_addr().unwrap().to_string(),
        },
        options,
    )
    .unwrap();
    let mut client = TcpStream::connect(relay.address).unwrap();
    let (mut server, _) = remote.accept().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    wait_for(&events, |event| matches!(event, Event::Connected(_)));
    relay
        .set_rules(Rules {
            entries: vec![Rule {
                enabled: true,
                direction: Direction::ToServer,
                header: 77,
                action: Action::Replace(Packet::new(78)),
            }],
        })
        .unwrap();
    write_frame(&mut client, &Packet::new(77)).unwrap();
    assert_eq!(read_frame(&mut server).unwrap().header(), 78);
    relay.inject(Direction::ToClient, Packet::new(99)).unwrap();
    assert_eq!(read_frame(&mut client).unwrap().header(), 99);
    let observed = safety.lock().unwrap();
    assert!(observed.is_safe(Some("fixture-v1"), Direction::ToServer, 77));
    assert!(!observed.is_safe(Some("fixture-v1"), Direction::ToServer, 78));
    assert!(!observed.is_safe(Some("fixture-v1"), Direction::ToClient, 99));
    drop(observed);
    relay.stop();
}
#[test]
fn truncated_frame_closes_both_sockets() {
    let remote = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut relay, events) = Relay::start(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        remote: remote.local_addr().unwrap().to_string(),
    })
    .unwrap();
    let mut client = TcpStream::connect(relay.address).unwrap();
    let (mut server, _) = remote.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    wait_for(&events, |e| matches!(e, Event::Connected(_)));
    client.write_all(&[0, 0, 0, 20, 0, 1, 1]).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut b = [0; 1];
    assert_eq!(server.read(&mut b).unwrap(), 0);
    wait_for(&events, |e| matches!(e, Event::Disconnected));
    relay.stop();
}
#[test]
fn reconnect_after_client_disconnect() {
    let remote = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut relay, events) = Relay::start(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        remote: remote.local_addr().unwrap().to_string(),
    })
    .unwrap();
    for _ in 0..2 {
        let mut client = TcpStream::connect(relay.address).unwrap();
        let (mut server, _) = remote.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        wait_for(&events, |e| matches!(e, Event::Connected(_)));
        write_frame(&mut client, &Packet::new(22)).unwrap();
        assert_eq!(read_frame(&mut server).unwrap().header(), 22);
        client.shutdown(Shutdown::Both).unwrap();
        wait_for(&events, |e| matches!(e, Event::Disconnected));
    }
    relay.stop();
}

#[test]
fn scheduled_send_survives_disconnection_and_retries_after_reconnect() {
    let remote = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut relay, events) = Relay::start(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        remote: remote.local_addr().unwrap().to_string(),
    })
    .unwrap();
    let client = TcpStream::connect(relay.address).unwrap();
    let (mut server, _) = remote.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    wait_for(&events, |e| matches!(e, Event::Connected(_)));
    let now = Instant::now();
    let wall = SystemTime::now();
    let mut scheduler = Scheduler::default();
    scheduler
        .add(
            Packet::new(555),
            Direction::ToServer,
            Duration::from_millis(10),
            Some(2),
            now,
        )
        .unwrap();
    scheduler
        .dispatch_with_wall_clock(now, wall, |direction, packet| {
            relay.inject(direction, packet.clone())
        })
        .unwrap();
    assert_eq!(read_frame(&mut server).unwrap().header(), 555);
    client.shutdown(Shutdown::Both).unwrap();
    wait_for(&events, |e| matches!(e, Event::Disconnected));
    let later = now + Duration::from_secs(1);
    assert!(scheduler
        .dispatch_with_wall_clock(later, wall + Duration::from_secs(1), |direction, packet| {
            relay.inject(direction, packet.clone())
        })
        .is_err());
    assert_eq!(scheduler.jobs[0].remaining, Some(1));
    let _client = TcpStream::connect(relay.address).unwrap();
    let (mut server, _) = remote.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    wait_for(&events, |e| matches!(e, Event::Connected(_)));
    scheduler
        .dispatch_with_wall_clock(later, wall + Duration::from_secs(1), |direction, packet| {
            relay.inject(direction, packet.clone())
        })
        .unwrap();
    assert_eq!(read_frame(&mut server).unwrap().header(), 555);
    assert!(scheduler.jobs.is_empty());
    relay.stop();
}
#[test]
fn logging_backpressure_does_not_stall_relay() {
    let remote = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mut relay, events) = Relay::start(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        remote: remote.local_addr().unwrap().to_string(),
    })
    .unwrap();
    let mut client = TcpStream::connect(relay.address).unwrap();
    let (mut server, _) = remote.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    wait_for(&events, |e| matches!(e, Event::Connected(_)));
    let writer = thread::spawn(move || {
        for _ in 0..3000 {
            write_frame(&mut client, &Packet::new(33)).unwrap();
        }
        client
    });
    for _ in 0..3000 {
        assert_eq!(read_frame(&mut server).unwrap().header(), 33);
    }
    drop(writer.join().unwrap());
    relay.stop();
}
#[test]
fn rejects_non_loopback_binding() {
    assert!(Relay::start(Config {
        listen: "0.0.0.0:0".parse().unwrap(),
        remote: "127.0.0.1:1".into()
    })
    .is_err());
}
