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
fn released_gpresets_original_launcher_authenticates() {
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
    // G-Presets can migrate legacy presets from beside its own JAR.
    // Give each test a private copy so that migration cannot inspect user files.
    let isolated_jar = directory.0.join("GPresets-1.6.5.jar");
    fs::copy(&jar, &isolated_jar).unwrap();
    let jar = isolated_jar;
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    let filename = "GPresets-1.6.5.jar";
    let token = host.register_launch(filename).unwrap();
    let offline_proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let stderr = fs::File::create(directory.0.join("stderr.log")).unwrap();
    let mut process = Process(
        Command::new("java")
            .current_dir(&directory.0)
            .arg(format!("-Duser.home={}", directory.0.display()))
            .arg(format!(
                "-Dgpresets.dataDir={}",
                directory.0.join("data").display()
            ))
            .arg("-Dhttps.proxyHost=127.0.0.1")
            .arg(format!(
                "-Dhttps.proxyPort={}",
                offline_proxy.local_addr().unwrap().port()
            ))
            .arg("--module-path")
            .arg(modules)
            .arg("--add-modules=javafx.controls,javafx.fxml,javafx.web,javafx.swing")
            .arg("-jar")
            .arg(jar)
            .args([
                "-p",
                &host.address.port().to_string(),
                "-f",
                filename,
                "-c",
                &token,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
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
    if connected {
        assert!(
            directory.0.join("data").is_dir(),
            "G-Presets must use the isolated data directory"
        );
    }
    if !connected {
        let log = fs::read_to_string(directory.0.join("stderr.log"))
            .unwrap_or_default()
            .replace(&token, "[token]");
        panic!(
            "original G-Presets launcher did not authenticate: {}",
            log.chars().take(8000).collect::<String>()
        );
    }
    host.stop();
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
    // G-Presets can migrate legacy presets from beside its own JAR.
    // Give each test a private copy so that migration cannot inspect user files.
    let isolated_jar = directory.0.join("GPresets-1.6.5.jar");
    fs::copy(&jar, &isolated_jar).unwrap();
    let jar = isolated_jar;
    let observer_source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/GPresetsObserver.java");
    let status = Command::new("javac")
        .args(["-encoding", "UTF-8", "--module-path"])
        .arg(&modules)
        .args([
            "--add-modules",
            "javafx.controls,javafx.fxml,javafx.web,javafx.swing",
            "-cp",
        ])
        .arg(&jar)
        .arg("-d")
        .arg(&directory.0)
        .arg(observer_source)
        .status()
        .expect("compile G-Presets observer");
    assert!(status.success(), "G-Presets observer compilation failed");
    let classpath = std::env::join_paths([directory.0.as_path(), jar.as_path()]).unwrap();
    let state_path = directory.0.join("inventory-state.txt");
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
            .arg(format!(
                "-Dgpresets.dataDir={}",
                directory.0.join("data").display()
            ))
            .arg("-Dhttps.proxyHost=127.0.0.1")
            .arg(format!("-Dhttps.proxyPort={proxy_port}"))
            .arg(format!("-Dgearth.fixture.state={}", state_path.display()))
            .arg("--module-path")
            .arg(modules)
            .arg("--add-modules=javafx.controls,javafx.fxml,javafx.web,javafx.swing")
            .arg("-cp")
            .arg(classpath)
            .arg("GPresetsObserver")
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
    if connected {
        assert!(
            directory.0.join("data").is_dir(),
            "G-Presets must use the isolated data directory"
        );
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
            [
                (78, "FurniList"),
                (79, "Objects"),
                (80, "Items"),
                (81, "FurniListAddOrUpdate"),
                (82, "FurniListRemove"),
                (83, "FloorHeightMap"),
                (84, "HeightMap"),
                (85, "RoomEntryInfo"),
                (86, "ObjectAdd"),
                (87, "ObjectRemove"),
                (88, "ItemAdd"),
                (89, "ItemRemove"),
                (90, "ObjectUpdate"),
                (91, "ItemUpdate"),
                (93, "Whisper"),
                (95, "WiredAllVariablesDiffs"),
            ]
            .into_iter()
            .map(|(header, name)| PacketInfo {
                header,
                hash: None,
                name: Some(name.into()),
                structure: None,
                direction: Direction::ToClient,
                source: "fixture".into(),
            })
            .chain(std::iter::once(PacketInfo {
                header: 96,
                hash: None,
                name: Some("WiredGetAllVariablesDiffs".into()),
                structure: None,
                direction: Direction::ToServer,
                source: "fixture".into(),
            }))
            .chain(std::iter::once(PacketInfo {
                header: 94,
                hash: None,
                name: Some("RequestFurniInventory".into()),
                structure: None,
                direction: Direction::ToServer,
                source: "fixture".into(),
            }))
            .chain(std::iter::once(PacketInfo {
                header: 92,
                hash: None,
                name: Some("Chat".into()),
                structure: None,
                direction: Direction::ToServer,
                source: "fixture".into(),
            }))
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
        let wait_state = |expected: &str| {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let state = fs::read_to_string(&state_path).unwrap_or_default();
                if state == expected {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "G-Presets inventory expected {expected:?}, observed {state:?}"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        };
        wait_state(&(1200 + session).to_string());
        let mut added = item.clone();
        added.placement_id = 2200 + session;
        added.id = 2400 + session;
        let mut update = Packet::new(81);
        update.put_i32(1).unwrap();
        added.append(&mut update).unwrap();
        write_frame(&mut server, &update).unwrap();
        assert_eq!(read_frame(&mut client).unwrap().bytes(), update.bytes());
        wait_state(&format!("{},{}", 1200 + session, 2200 + session));
        let mut remove = Packet::new(82);
        remove.put_i32(1200 + session).unwrap();
        write_frame(&mut server, &remove).unwrap();
        assert_eq!(read_frame(&mut client).unwrap().bytes(), remove.bytes());
        wait_state(&(2200 + session).to_string());
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
            HFloorItem::construct(std::slice::from_ref(&floor), 79).unwrap(),
            HWallItem::construct(std::slice::from_ref(&wall), 80).unwrap(),
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
        let mut floorplan = Packet::new(83);
        floorplan
            .put_u8(0)
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_string("0000\r0000\r0000\r0000")
            .unwrap();
        let mut heightmap = Packet::new(84);
        heightmap.put_i32(4).unwrap().put_i32(16).unwrap();
        for _ in 0..16 {
            heightmap.put_u16(0).unwrap();
        }
        let mut room = Packet::new(85);
        room.put_i32(12345).unwrap();
        for packet in [floorplan, heightmap] {
            write_frame(&mut server, &packet).unwrap();
            assert_eq!(read_frame(&mut client).unwrap().bytes(), packet.bytes());
        }
        // G-Presets can block RoomEntryInfo when it just requested room state.
        write_frame(&mut server, &room).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        match read_frame(&mut client) {
            Ok(received) => assert_eq!(received.bytes(), room.bytes()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => panic!("room entry forwarding failed: {error}"),
        }
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let wait_room = |filename: &str, expected: &str| {
            let path = directory.0.join(filename);
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let state = fs::read_to_string(&path).unwrap_or_default();
                if state == expected {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "G-Presets {filename} expected {expected:?}, observed {state:?}"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        };
        wait_room("floor-state.txt", &(1600 + session).to_string());
        wait_room("wall-state.txt", &(1700 + session).to_string());
        let mut extra_floor = floor.clone();
        extra_floor.id = 2600 + session;
        let mut extra_wall = wall.clone();
        extra_wall.id = 2700 + session;
        let mut floor_add = Packet::new(86);
        extra_floor.append(&mut floor_add).unwrap();
        floor_add.put_string("Fixture").unwrap();
        let mut wall_add = Packet::new(88);
        extra_wall.append(&mut wall_add).unwrap();
        wall_add.put_string("Fixture").unwrap();
        for packet in [floor_add, wall_add] {
            write_frame(&mut server, &packet).unwrap();
            assert_eq!(read_frame(&mut client).unwrap().bytes(), packet.bytes());
        }
        wait_room(
            "floor-state.txt",
            &format!("{},{}", 1600 + session, 2600 + session),
        );
        wait_room(
            "wall-state.txt",
            &format!("{},{}", 1700 + session, 2700 + session),
        );
        extra_floor.tile = HPoint::new(3, 1);
        extra_wall.state = "1".into();
        let mut floor_update = Packet::new(90);
        extra_floor.append(&mut floor_update).unwrap();
        let mut wall_update = Packet::new(91);
        extra_wall.append(&mut wall_update).unwrap();
        for packet in [floor_update, wall_update] {
            write_frame(&mut server, &packet).unwrap();
            assert_eq!(read_frame(&mut client).unwrap().bytes(), packet.bytes());
        }
        wait_room(
            "floor-details.txt",
            &format!("{}:2:3,{}:3:1", 1600 + session, 2600 + session),
        );
        wait_room(
            "wall-details.txt",
            &format!("{}:0,{}:1", 1700 + session, 2700 + session),
        );
        let mut floor_remove = Packet::new(87);
        floor_remove
            .put_string(&(1600 + session).to_string())
            .unwrap();
        let mut wall_remove = Packet::new(89);
        wall_remove
            .put_string(&(1700 + session).to_string())
            .unwrap();
        for packet in [floor_remove, wall_remove] {
            write_frame(&mut server, &packet).unwrap();
            assert_eq!(read_frame(&mut client).unwrap().bytes(), packet.bytes());
        }
        wait_room("floor-state.txt", &(2600 + session).to_string());
        wait_room("wall-state.txt", &(2700 + session).to_string());
        // The real extension recognizes :ep and blocks it before the server.
        let mut command = Packet::new(92);
        command.put_string(":ep").unwrap();
        write_frame(&mut client, &command).unwrap();
        let mut marker = Packet::new(77);
        marker.put_i32(9000 + session).unwrap();
        write_frame(&mut client, &marker).unwrap();
        loop {
            let packet = read_frame(&mut server).unwrap();
            assert_ne!(
                packet.header(),
                92,
                "G-Presets command reached the simulated server"
            );
            if packet.header() == 77 {
                assert_eq!(packet.bytes(), marker.bytes());
                break;
            }
        }
        let mut feedback = read_frame(&mut client).unwrap();
        assert_eq!(feedback.header(), 93);
        assert_eq!(feedback.read_i32().unwrap(), -1);
        assert_eq!(
            feedback.read_string().unwrap(),
            "Error: no room detected or furnidata not available"
        );
        // Ask the real extension to request inventory and observe its injection.
        fs::write(directory.0.join("request-inventory.trigger"), "").unwrap();
        loop {
            let packet = read_frame(&mut server).unwrap();
            if packet.header() == 94 {
                break;
            }
        }
        let mut refreshed = item.clone();
        refreshed.placement_id = 3200 + session;
        refreshed.id = 3400 + session;
        let mut inventory_reply = Packet::new(78);
        inventory_reply
            .put_i32(1)
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_i32(1)
            .unwrap();
        refreshed.append(&mut inventory_reply).unwrap();
        write_frame(&mut server, &inventory_reply).unwrap();
        let mut marker = Packet::new(77);
        marker.put_i32(10000 + session).unwrap();
        write_frame(&mut server, &marker).unwrap();
        let forwarded = read_frame(&mut client).unwrap();
        assert_eq!(
            forwarded.bytes(),
            marker.bytes(),
            "virtual inventory response should be blocked"
        );
        wait_state(&(3200 + session).to_string());
        // Exercise exact and crossed boundaries with the real extension.
        for (case, count) in [599, 600, 601, 1201].into_iter().enumerate() {
            let base = 50_000 + session * 10_000 + case as i32 * 2_000;
            let items: Vec<_> = (0..count)
                .map(|offset| {
                    let mut entry = item.clone();
                    entry.placement_id = base + offset;
                    entry.id = base + offset;
                    entry
                })
                .collect();
            let pages = HInventoryItem::construct_pages(&items, 78).unwrap();
            assert_eq!(pages.len(), (count as usize).div_ceil(600));
            for page in pages {
                write_frame(&mut server, &page).unwrap();
                assert_eq!(read_frame(&mut client).unwrap().bytes(), page.bytes());
            }
            let expected = (0..count)
                .map(|offset| (base + offset).to_string())
                .collect::<Vec<_>>()
                .join(",");
            wait_state(&expected);
        }
        // Virtual multi-page responses are hidden from the client until completion.
        fs::write(directory.0.join("request-inventory.trigger"), "").unwrap();
        while read_frame(&mut server).unwrap().header() != 94 {}
        let base = 90_000 + session * 2_000;
        let virtual_items: Vec<_> = (0..601)
            .map(|offset| {
                let mut entry = item.clone();
                entry.placement_id = base + offset;
                entry.id = base + offset;
                entry
            })
            .collect();
        for page in HInventoryItem::construct_pages(&virtual_items, 78).unwrap() {
            write_frame(&mut server, &page).unwrap();
        }
        let mut after_virtual = Packet::new(77);
        after_virtual.put_i32(20000 + session).unwrap();
        write_frame(&mut server, &after_virtual).unwrap();
        assert_eq!(
            read_frame(&mut client).unwrap().bytes(),
            after_virtual.bytes()
        );
        let expected = (0..601)
            .map(|offset| (base + offset).to_string())
            .collect::<Vec<_>>()
            .join(",");
        wait_state(&expected);
        // Use synthetic furnidata, isolated from real Habbo assets, to exercise an export.
        let ready = directory.0.join("fixture-furnidata.ready");
        let _ = fs::remove_file(&ready);
        fs::write(directory.0.join("fixture-furnidata.trigger"), "").unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(
                Instant::now() < deadline,
                "fixture furnidata was not installed"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut export_command = Packet::new(92);
        export_command.put_string(":ep all").unwrap();
        write_frame(&mut client, &export_command).unwrap();
        let mut marker = Packet::new(77);
        marker.put_i32(30000 + session).unwrap();
        write_frame(&mut client, &marker).unwrap();
        loop {
            let packet = read_frame(&mut server).unwrap();
            assert_ne!(
                packet.header(),
                92,
                "export command reached the simulated server"
            );
            if packet.header() == 77 {
                assert_eq!(packet.bytes(), marker.bytes());
                break;
            }
        }
        let mut prompt = read_frame(&mut client).unwrap();
        assert_eq!(prompt.header(), 93);
        assert_eq!(prompt.read_i32().unwrap(), -1);
        assert_eq!(
            prompt.read_string().unwrap(),
            "Enter the name of the preset"
        );
        let preset_name = format!("fixture_{session}");
        let mut name_packet = Packet::new(92);
        name_packet.put_string(&preset_name).unwrap();
        write_frame(&mut client, &name_packet).unwrap();
        let mut marker = Packet::new(77);
        marker.put_i32(40000 + session).unwrap();
        write_frame(&mut client, &marker).unwrap();
        let mut saw_marker = false;
        let mut saw_request = false;
        while !saw_marker || !saw_request {
            let packet = read_frame(&mut server).unwrap();
            assert_ne!(
                packet.header(),
                92,
                "preset name reached the simulated server"
            );
            if packet.header() == 77 {
                assert_eq!(packet.bytes(), marker.bytes());
                saw_marker = true;
            }
            if packet.header() == 96 {
                saw_request = true;
            }
        }
        let mut variables = Packet::new(95);
        variables
            .put_i32(0)
            .unwrap()
            .put_bool(true)
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_i32(0)
            .unwrap();
        write_frame(&mut server, &variables).unwrap();
        assert_eq!(read_frame(&mut client).unwrap().bytes(), variables.bytes());
        let preset_path = directory
            .0
            .join("data")
            .join("presets")
            .join(format!("{preset_name}.json"));
        let deadline = Instant::now() + Duration::from_secs(20);
        while !preset_path.exists() {
            let log = fs::read_to_string(directory.0.join("app.log")).unwrap_or_default();
            assert!(
                Instant::now() < deadline,
                "preset not exported: {}; stderr: {}",
                log.replace(&token, "[token]"),
                fs::read_to_string(directory.0.join("stderr.log"))
                    .unwrap_or_default()
                    .replace(&token, "[token]")
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let preset = fs::read_to_string(&preset_path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&preset).unwrap();
        let furni = json["furni"].as_array().expect("preset furni array");
        assert!(
            furni.iter().any(|entry| {
                entry["id"] == 1
                    && entry["className"] == "fixture_floor"
                    && entry["location"]["x"] == 3
                    && entry["location"]["y"] == 1
            }),
            "export did not include the moved simulated item: {json}"
        );
        // Reload the actual exported file through the extension's own parser.
        let loaded = directory.0.join("loaded-preset.txt");
        let _ = fs::remove_file(&loaded);
        let pending = directory.0.join("load-preset.pending");
        fs::write(&pending, &preset_name).unwrap();
        fs::rename(&pending, directory.0.join("load-preset.trigger")).unwrap();
        wait_room("loaded-preset.txt", "fixture_floor:1:3:1:0");
        assert_eq!(
            fs::read_to_string(directory.0.join("import-status.txt")).unwrap(),
            "false:NONE"
        );
        // With no catalog, the real importer must reject :ip without server traffic.
        let mut import_command = Packet::new(92);
        import_command.put_string(":ip").unwrap();
        write_frame(&mut client, &import_command).unwrap();
        let mut marker = Packet::new(77);
        marker.put_i32(50000 + session).unwrap();
        write_frame(&mut client, &marker).unwrap();
        let forwarded = read_frame(&mut server).unwrap();
        assert_eq!(
            forwarded.bytes(),
            marker.bytes(),
            "import refusal must not send a placement packet"
        );
        // The successful export may also inject feedback; read until the import refusal.
        let mut refusal_seen = false;
        for _ in 0..8 {
            let mut feedback = read_frame(&mut client).unwrap();
            if feedback.header() == 93 {
                feedback.read_i32().unwrap();
                if feedback.read_string().unwrap() == "ERROR: extension not fully initialized yet" {
                    refusal_seen = true;
                    break;
                }
            }
        }
        assert!(
            refusal_seen,
            "G-Presets did not report missing import prerequisites"
        );
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
