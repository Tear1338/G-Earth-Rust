use gearth_rust::{
    extension_host::{ConnectionDetails, ExtensionHost, HostEvent},
    packet::{read_frame, write_frame, Direction, Packet},
    packet_info::{PacketInfo, PacketInfoManager},
    relay::{Config, Relay, RelayOptions},
};
use std::{
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
#[ignore = "requires the actual beta-29 Java API and compiled JavaExtensionFixture"]
fn actual_java_extension_connects_resolves_names_injects_blocks_and_edits() {
    let classpath =
        std::env::var("GEARTH_EXTENSION_CLASSPATH").expect("Java fixture classpath required");
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    let token = host.register_launch("fixture.jar").unwrap();
    let _process = Process(
        Command::new("java")
            .args([
                "-cp",
                &classpath,
                "JavaExtensionFixture",
                "-p",
                &host.address.port().to_string(),
                "-f",
                "fixture.jar",
                "-c",
                &token,
            ])
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if matches!(
            events.recv_timeout(Duration::from_millis(100)),
            Ok(HostEvent::Connected { .. })
        ) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Java extension did not authenticate"
        );
    }
    let packets = PacketInfoManager::new(
        "TEST",
        vec![
            PacketInfo {
                header: 77,
                name: Some("TestOutgoing".into()),
                hash: None,
                structure: Some("i".into()),
                direction: Direction::ToServer,
                source: "fixture".into(),
            },
            PacketInfo {
                header: 91,
                name: Some("TestInjection".into()),
                hash: None,
                structure: Some("i".into()),
                direction: Direction::ToServer,
                source: "fixture".into(),
            },
        ],
    );
    let remote = TcpListener::bind("127.0.0.1:0").unwrap();
    let options = RelayOptions {
        extensions: Some(host.clone()),
        connection: Some(ConnectionDetails {
            host: "test.example".into(),
            port: 30000,
            version: "TEST".into(),
            identifier: "fixture".into(),
            client_type: "FLASH".into(),
            packets,
        }),
        ..Default::default()
    };
    let (mut relay, _) = Relay::start_with_options(
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            remote: remote.local_addr().unwrap().to_string(),
        },
        options,
    )
    .unwrap();
    let mut client = TcpStream::connect(relay.address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (mut server, _) = remote.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut injected = read_frame(&mut server).unwrap();
    assert_eq!(injected.header(), 91);
    assert_eq!(injected.read_i32().unwrap(), 17);
    for (value, expected) in [(5, 6), (8, 9)] {
        if value == 8 {
            let mut blocked = Packet::new(77);
            blocked.put_i32(13).unwrap();
            write_frame(&mut client, &blocked).unwrap();
        }
        let mut p = Packet::new(77);
        p.put_i32(value).unwrap();
        write_frame(&mut client, &p).unwrap();
        let mut received = read_frame(&mut server).unwrap();
        assert_eq!(received.header(), 77);
        assert_eq!(received.read_i32().unwrap(), expected);
    }
    let mut incoming = Packet::new(78);
    incoming.put_i32(5).unwrap();
    write_frame(&mut server, &incoming).unwrap();
    assert_eq!(read_frame(&mut client).unwrap().read_i32().unwrap(), 7);
    relay.stop();
    host.stop();
    thread::sleep(Duration::from_millis(10));
}
