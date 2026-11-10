//! Controlled startup check for the user's released G-Presets extension.
use gearth_rust::{
    extension_host::{ConnectionDetails, ExtensionHost, HostEvent},
    packet::{read_frame, write_frame, Direction, Message, Packet},
    packet_info::{PacketInfo, PacketInfoManager},
    parsers::{
        entity::{HDirection, HPoint},
        furniture::{HFloorItem, HInventoryItem, HProductType, HWallItem},
        stuffdata::{StuffData, StuffValue},
    },
    relay::{Config, Event, Relay, RelayOptions},
};
use std::{
    fs,
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        if self.0.parent() == Some(std::env::temp_dir().as_path())
            && self
                .0
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("gearth-gpresets-"))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
#[ignore = "requires pinned G-Presets, JavaFX and a virtual display"]
fn released_gpresets_authenticates_to_the_rust_host() {
    let jar = PathBuf::from(std::env::var_os("GEARTH_GPRESETS_JAR").expect("pinned G-Presets JAR"));
    let modules = std::env::var_os("GEARTH_JAVAFX_MODULES").expect("JavaFX module directory");
    let mut random = [0; 16];
    getrandom::fill(&mut random).unwrap();
    let suffix = random
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let directory = Directory(std::env::temp_dir().join(format!("gearth-gpresets-{suffix}")));
    fs::create_dir(&directory.0).unwrap();
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    let filename = "GPresets-1.6.5.jar";
    let token = host.register_launch(filename).unwrap();
    let stdout = fs::File::create(directory.0.join("stdout.log")).unwrap();
    let stderr = fs::File::create(directory.0.join("stderr.log")).unwrap();
    // G-Presets loads public furnidata after connection. Keep its HTTPS traffic
    // on loopback, where an unserved listener prevents external requests.
    let offline_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = offline_proxy.local_addr().unwrap().port();
    let mut process = Process(
        Command::new("java")
            .current_dir(&directory.0)
            .arg(format!("-Duser.home={}", directory.0.display()))
            .arg("-Dhttps.proxyHost=127.0.0.1")
            .arg(format!("-Dhttps.proxyPort={proxy_port}"))
            .arg("--module-path")
            .arg(modules)
            .arg("--add-modules=javafx.controls,javafx.fxml,javafx.web,javafx.swing")
            .arg("-jar")
            .arg(jar)
            .args([
                "--debug",
                "-p",
                &host.address.port().to_string(),
                "-f",
                filename,
                "-c",
                &token,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut connected = false;
    while Instant::now() < deadline {
        if let Ok(HostEvent::Connected { info, .. }) =
            events.recv_timeout(Duration::from_millis(100))
        {
            if info.title == "G-Presets" {
                connected = true;
                break;
            }
        }
        if process.0.try_wait().unwrap().is_some() {
            break;
        }
    }
    if !connected {
        let log = fs::read_to_string(directory.0.join("stderr.log"))
            .unwrap_or_default()
            .replace(&token, "[token]");
        panic!(
            "G-Presets did not authenticate: {}",
            log.chars().take(8000).collect::<String>()
        );
    }
    // Exercise both IPC directions without connecting to a real hotel.
    for (index, direction) in [Direction::ToServer, Direction::ToClient]
        .into_iter()
        .enumerate()
    {
        let mut packet = Packet::new(77);
        packet.put_i32(123).unwrap();
        let mut message = Message {
            packet,
            direction,
            index: index as i32,
            blocked: false,
        };
        host.intercept(&mut message)
            .expect("G-Presets must return the intercepted fixture packet");
        assert_eq!(message.packet.header(), 77);
        assert_eq!(message.packet.read_i32().unwrap(), 123);
        assert!(!message.blocked);
    }
    // Use loopback peers so the published extension receives real connection,
    // interception and disconnection IPC without joining a hotel.
    let remote = TcpListener::bind("127.0.0.1:0").unwrap();
    let details = ConnectionDetails {
        host: "game-us.habbo.com".into(),
        port: 30000,
        version: "FIXTURE".into(),
        identifier: "fixture".into(),
        client_type: "FLASH".into(),
        packets: PacketInfoManager::new(
            "FIXTURE",
            [(78, "FurniList"), (79, "Objects"), (80, "Items")]
                .into_iter()
                .map(|(header, name)| PacketInfo {
                    header,
                    hash: None,
                    name: Some(name.into()),
                    structure: None,
                    direction: Direction::ToClient,
                    source: "fixture".into(),
                })
                .collect(),
        ),
    };
    let (mut relay, relay_events) = Relay::start_with_options(
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            remote: remote.local_addr().unwrap().to_string(),
        },
        RelayOptions {
            extensions: Some(host.clone()),
            connection: Some(details),
            ..Default::default()
        },
    )
    .unwrap();
    for session in 0..2 {
        let mut client = TcpStream::connect(relay.address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let (mut server, _) = remote.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        for direction in [Direction::ToServer, Direction::ToClient] {
            let mut packet = Packet::new(77);
            packet.put_i32(123 + session).unwrap();
            let received = match direction {
                Direction::ToServer => {
                    write_frame(&mut client, &packet).unwrap();
                    read_frame(&mut server)
                }
                Direction::ToClient => {
                    write_frame(&mut server, &packet).unwrap();
                    read_frame(&mut client)
                }
            };
            let received = received.unwrap_or_else(|error| {
                std::thread::sleep(Duration::from_millis(100));
                let relay_log: Vec<_> = relay_events.try_iter().collect();
                let host_log: Vec<_> = events.try_iter().collect();
                let stderr = fs::read_to_string(directory.0.join("stderr.log"))
                    .unwrap_or_default().replace(&token, "[token]");
                let stdout = fs::read_to_string(directory.0.join("stdout.log"))
                    .unwrap_or_default().replace(&token, "[token]");
                panic!("session {session} {direction:?}: {error}; relay={relay_log:?}; host={host_log:?}; stderr={}; stdout={}",
                    stderr.chars().take(8000).collect::<String>(), stdout.chars().take(8000).collect::<String>());
            });
            assert_eq!(received.bytes(), packet.bytes());
        }
        // Exercise a named packet that the released extension actually parses.
        let item = HInventoryItem {
            placement_id: 1200 + session,
            product_type: HProductType::FloorItem,
            id: 1400 + session,
            type_id: 1500,
            special_type: 1,
            stuff: StuffData {
                flags: 0,
                serial: None,
                value: StuffValue::Legacy("0".into()),
            },
            recyclable: true,
            tradeable: true,
            groupable: true,
            sellable: true,
            seconds_to_expiration: -1,
            rent_period_started: false,
            room_id: 0,
            floor_details: Some(("".into(), 0)),
        };
        let mut inventory = Packet::new(78);
        inventory
            .put_i32(1)
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_i32(1)
            .unwrap();
        item.append(&mut inventory).unwrap();
        write_frame(&mut server, &inventory).unwrap();
        assert_eq!(read_frame(&mut client).unwrap().bytes(), inventory.bytes());
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let log = fs::read_to_string(directory.0.join("app.log")).unwrap_or_default();
            if log.matches("Inventory loaded: found 1 items.").count() > session as usize {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "G-Presets did not parse inventory in session {session}: {}",
                log.replace(&token, "[token]")
                    .chars()
                    .take(8000)
                    .collect::<String>()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let floor = HFloorItem {
            id: 1600 + session,
            type_id: 1500,
            tile: HPoint::new(2, 3),
            facing: HDirection::North,
            size_z: "1.0".into(),
            extra: 0,
            stuff: StuffData {
                flags: 0,
                serial: None,
                value: StuffValue::Legacy("0".into()),
            },
            seconds_to_expiration: -1,
            usage_policy: 0,
            owner_id: 42,
            owner_name: Some("Fixture".into()),
            static_class: None,
        };
        let wall = HWallItem {
            id: 1700 + session,
            type_id: 1800,
            location: ":w=1,2 l=3,4 r".into(),
            state: "0".into(),
            seconds_to_expiration: -1,
            usage_policy: 0,
            owner_id: 42,
            owner_name: Some("Fixture".into()),
        };
        for packet in [
            HFloorItem::construct(&[floor], 79).unwrap(),
            HWallItem::construct(&[wall], 80).unwrap(),
        ] {
            write_frame(&mut server, &packet).unwrap();
            assert_eq!(read_frame(&mut client).unwrap().bytes(), packet.bytes());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let log = fs::read_to_string(directory.0.join("app.log")).unwrap_or_default();
            if ["Parsed floor items", "Parsed wall items"]
                .iter()
                .all(|event| log.matches(event).count() > session as usize)
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "G-Presets did not parse room items in session {session}: {}",
                log.replace(&token, "[token]")
                    .chars()
                    .take(8000)
                    .collect::<String>()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(client);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if matches!(
                relay_events.recv_timeout(Duration::from_millis(100)),
                Ok(Event::Disconnected)
            ) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "relay did not disconnect after session {session}"
            );
        }
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "G-Presets exited during session {session}"
        );
    }
    relay.stop();
    host.stop();
}
