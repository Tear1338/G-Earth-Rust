//! Packet construction, RC4/framing/rule pipeline, and loopback relay benchmarks.
use gearth_rust::{
    crypto::Rc4,
    expression,
    packet::{read_frame, write_frame, Direction, FrameDecoder, Message, Packet},
    relay::{Config, Relay},
    rules::{Action, Rule, Rules},
};
use std::{
    hint::black_box,
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

fn sample_construct(iterations: usize) -> (u128, u64) {
    let start = Instant::now();
    let mut checksum = 0u64;
    for i in 0..iterations {
        let mut p = Packet::new(123);
        p.put_i32(i as i32)
            .unwrap()
            .put_string("hello")
            .unwrap()
            .put_bool(true)
            .unwrap();
        let bytes = black_box(p.bytes());
        checksum = checksum.wrapping_add(bytes[9] as u64 + bytes.len() as u64);
        black_box(&p);
    }
    (start.elapsed().as_nanos(), checksum)
}

fn sample_rc4_frame_rules(iterations: usize) -> (u128, u64) {
    let mut encrypt = Rc4::new(b"gearth-benchmark-rc4-key-0123456").unwrap();
    let mut decrypt = Rc4::new(b"gearth-benchmark-rc4-key-0123456").unwrap();
    let mut decoder = FrameDecoder::default();
    let rules = Rules {
        entries: vec![
            Rule {
                enabled: true,
                direction: Direction::ToServer,
                header: 999,
                action: Action::Block,
            },
            Rule {
                enabled: true,
                direction: Direction::ToServer,
                header: 124,
                action: Action::Replace(Packet::new(124)),
            },
        ],
    };
    let mut base = Packet::new(123);
    base.put_i32(42)
        .unwrap()
        .put_string("room-chat-benchmark-payload")
        .unwrap()
        .put_bool(true)
        .unwrap();
    let template = base.bytes().to_vec();

    let start = Instant::now();
    let mut checksum = 0u64;
    let mut wire = template.clone();
    for i in 0..iterations {
        wire.copy_from_slice(&template);
        encrypt.apply(&mut wire);
        decrypt.apply(&mut wire);
        decoder.push(&wire).unwrap();
        while let Some(packet) = decoder.next_packet().unwrap() {
            let mut message = Message {
                packet,
                direction: Direction::ToServer,
                index: i as i32,
                blocked: false,
            };
            rules.apply(&mut message);
            let expr = expression::to_lossless_expression(&message.packet);
            checksum = checksum.wrapping_add(expr.len() as u64);
            black_box(&expr);
        }
    }
    (start.elapsed().as_nanos(), checksum)
}

fn sample_loopback_relay(iterations: usize) -> Option<(u128, u64)> {
    let remote = TcpListener::bind("127.0.0.1:0").ok()?;
    let remote_addr = remote.local_addr().ok()?;
    let (mut relay, _events) = Relay::start(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        remote: remote_addr.to_string(),
    })
    .ok()?;
    relay
        .set_rules(Rules {
            entries: vec![Rule {
                enabled: true,
                direction: Direction::ToServer,
                header: 999,
                action: Action::Block,
            }],
        })
        .ok()?;

    let server_thread = thread::spawn(move || -> u64 {
        let (mut server, _) = remote.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut checksum = 0u64;
        for _ in 0..iterations {
            let packet = read_frame(&mut server).unwrap();
            checksum = checksum.wrapping_add(packet.header() as u64 + packet.bytes().len() as u64);
            write_frame(&mut server, &packet).unwrap();
        }
        checksum
    });

    let mut client = TcpStream::connect(relay.address).ok()?;
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
    let mut packet = Packet::new(123);
    packet
        .put_i32(7)
        .unwrap()
        .put_string("loopback-e2e")
        .unwrap();

    let start = Instant::now();
    let mut client_checksum = 0u64;
    for _ in 0..iterations {
        write_frame(&mut client, &packet).unwrap();
        let echoed = read_frame(&mut client).unwrap();
        client_checksum =
            client_checksum.wrapping_add(echoed.header() as u64 + echoed.bytes().len() as u64);
    }
    let elapsed = start.elapsed().as_nanos();
    drop(client);
    let server_checksum = server_thread.join().ok()?;
    relay.stop();
    Some((elapsed, client_checksum.wrapping_add(server_checksum)))
}

fn main() {
    let iterations = 250_000;
    for _ in 0..5 {
        black_box(sample_construct(iterations));
    }
    println!("runtime,workload,iterations,nanoseconds,checksum");
    for _ in 0..5 {
        let (elapsed, checksum) = sample_construct(iterations);
        println!("rust,construct_packet,{iterations},{elapsed},{checksum}");
    }

    let pipeline_iterations = 50_000;
    black_box(sample_rc4_frame_rules(5_000));
    for _ in 0..5 {
        let (elapsed, checksum) = sample_rc4_frame_rules(pipeline_iterations);
        println!("rust,rc4_frame_rules,{pipeline_iterations},{elapsed},{checksum}");
    }

    let relay_iterations = 2_000;
    if sample_loopback_relay(200).is_some() {
        for _ in 0..3 {
            if let Some((elapsed, checksum)) = sample_loopback_relay(relay_iterations) {
                println!("rust,loopback_relay_e2e,{relay_iterations},{elapsed},{checksum}");
            }
        }
    }
}
