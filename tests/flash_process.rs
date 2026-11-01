#![cfg(windows)]
use gearth_rust::{
    crypto::Rc4,
    packet::{read_frame, write_frame, Direction, Packet},
    relay::{Config, Event, Relay, RelayOptions},
    rules::{Action, Rule, Rules},
};
use std::os::windows::process::CommandExt;
use std::{
    io::{BufRead, Read, Write},
    net::TcpListener,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
struct Fixture(Child, std::path::PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_file(self.1.join("Habbo.exe"));
        let _ = std::fs::remove_dir(&self.1);
    }
}
fn receive(stream: &mut std::net::TcpStream, cipher: &mut Rc4) -> Packet {
    let mut h = [0; 4];
    stream.read_exact(&mut h).unwrap();
    cipher.apply(&mut h);
    let n = u32::from_be_bytes(h) as usize;
    assert!((2..=65536).contains(&n));
    let mut body = vec![0; n];
    stream.read_exact(&mut body).unwrap();
    cipher.apply(&mut body);
    let mut bytes = h.to_vec();
    bytes.extend(body);
    Packet::from_bytes(bytes).unwrap()
}
#[test]
fn discovers_real_child_memory_and_relays_negotiated_encryption_with_rules_and_injections() {
    let dir = std::env::temp_dir().join(format!("gearth-flash-process-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::copy(
        env!("CARGO_BIN_EXE_gearth-flash-fixture"),
        dir.join("Habbo.exe"),
    )
    .unwrap();
    let child = Command::new(dir.join("Habbo.exe"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(0x08000000)
        .spawn()
        .unwrap();
    let mut fixture = Fixture(child, dir);
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = server.local_addr().unwrap();
    let (mut relay, events) = Relay::start_with_options(
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            remote: remote.to_string(),
        },
        RelayOptions {
            flash_process: Some(0),
            ..Default::default()
        },
    )
    .unwrap();
    let mut replacement = Packet::new(78);
    replacement.put_i32(42).unwrap();
    relay
        .set_rules(Rules {
            entries: vec![
                Rule {
                    enabled: true,
                    direction: Direction::ToServer,
                    header: 77,
                    action: Action::Block,
                },
                Rule {
                    enabled: true,
                    direction: Direction::ToServer,
                    header: 78,
                    action: Action::Replace(replacement),
                },
            ],
        })
        .unwrap();
    writeln!(fixture.0.stdin.take().unwrap(), "{}", relay.address).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(25)))
            .unwrap();
        let hello = read_frame(&mut stream).unwrap();
        assert_eq!(hello.header(), 1);
        let mut secret = Packet::new(2);
        secret
            .put_string(&"a".repeat(600))
            .unwrap()
            .put_bool(true)
            .unwrap();
        write_frame(&mut stream, &secret).unwrap();
        let mut cipher = Rc4::new(b"flash-fixture-shared-secret").unwrap();
        let mut outgoing = cipher.clone();
        for (header, value) in [(78, 42), (79, 99)] {
            let mut p = receive(&mut stream, &mut outgoing);
            assert_eq!(p.header(), header);
            assert_eq!(p.read_i32().unwrap(), value);
        }
        let mut p = Packet::new(88);
        p.put_i32(17).unwrap();
        let mut bytes = p.bytes().to_vec();
        cipher.apply(&mut bytes);
        stream.write_all(&bytes).unwrap();
        let p = receive(&mut stream, &mut outgoing);
        assert_eq!(p.header(), 90);
    });
    let mut stdout = std::io::BufReader::new(fixture.0.stdout.take().unwrap());
    let mut ready = String::new();
    stdout.read_line(&mut ready).unwrap();
    assert!(ready.contains("FLASH_FIXTURE_READY"));
    let scan =
        gearth_platform::scan_habbo(fixture.0.id(), &std::sync::atomic::AtomicBool::new(false))
            .unwrap();
    let fresh = Rc4::new(b"flash-fixture-shared-secret").unwrap().state().0;
    assert!(
        scan.states.contains(&fresh),
        "native scan missed live table: {} candidates, {} bytes, complete={}",
        scan.states.len(),
        scan.bytes_read,
        scan.complete
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut out = false;
    let mut incoming = false;
    let mut owner = false;
    while Instant::now() < deadline {
        match events.recv_timeout(Duration::from_millis(100)) {
            Ok(Event::Status(s)) if s == format!("Flash client process: {}", fixture.0.id()) => {
                owner = true
            }
            Ok(Event::Packet(m))
                if m.direction == Direction::ToServer && m.packet.header() == 78 && !out =>
            {
                let mut p = Packet::new(79);
                p.put_i32(99).unwrap();
                relay.inject(Direction::ToServer, p).unwrap();
                out = true;
            }
            Ok(Event::Packet(m))
                if m.direction == Direction::ToClient && m.packet.header() == 88 && !incoming =>
            {
                let mut p = Packet::new(89);
                p.put_i32(33).unwrap();
                relay.inject(Direction::ToClient, p).unwrap();
                incoming = true;
            }
            Ok(Event::Error(e)) => panic!("{e}"),
            _ => {}
        }
        if let Some(status) = fixture.0.try_wait().unwrap() {
            let mut output = String::new();
            stdout.read_to_string(&mut output).unwrap();
            let mut stderr = String::new();
            fixture
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            assert!(status.success(), "fixture failed: {stderr}");
            assert!(output.contains("FLASH_FIXTURE_OK"));
            assert!(out && incoming && owner);
            server.join().unwrap();
            relay.stop();
            return;
        }
    }
    panic!("native Flash fixture timed out");
}
