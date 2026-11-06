use gearth_rust::{
    expression,
    extension_host::ConnectionDetails,
    packet::Direction,
    packet_info::PacketInfoManager,
    packet_safety::PacketSafety,
    relay::{Config, Event, Relay, RelayOptions},
};
use std::env;
use std::io::{self, BufRead};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("encode") if args.len() == 2 => {
            println!("{}", expression::hex(expression::parse(&args[1])?.bytes()));
        }
        Some("decode") if args.len() == 2 => {
            let p = gearth_rust::packet::Packet::from_bytes(expression::parse_hex(&args[1])?)?;
            println!("{}", expression::to_lossless_expression(&p));
        }
        Some("relay") if args.len() >= 3 => {
            let mut revision: Option<String> = None;
            let mut developer_mode = false;
            let mut options = args[3..].iter();
            while let Some(option) = options.next() {
                match option.as_str() {
                    "--revision" if revision.is_none() => {
                        let value = options.next().ok_or("--revision requires a value")?;
                        if value.is_empty() || value.len() > 1024 {
                            return Err("revision must contain between 1 and 1024 bytes".into());
                        }
                        revision = Some(value.clone());
                    }
                    "--developer" if !developer_mode => developer_mode = true,
                    _ => return Err(format!("unknown or repeated relay option: {option}").into()),
                }
            }
            let safety = Arc::new(Mutex::new(PacketSafety::default()));
            let details = revision.as_ref().map(|version| ConnectionDetails {
                host: args[2].clone(),
                port: 0,
                version: version.clone(),
                identifier: String::new(),
                client_type: String::new(),
                packets: PacketInfoManager::default(),
            });
            let (mut relay, events) = Relay::start_with_options(
                Config {
                    listen: args[1].parse()?,
                    remote: args[2].clone(),
                },
                RelayOptions {
                    connection: details,
                    packet_safety: Some(Arc::clone(&safety)),
                    ..RelayOptions::default()
                },
            )?;
            println!("Listening at {}. Explicit plaintext EVA_WIRE only. Commands: server EXPR | client EXPR | quit",relay.address);
            let (tx, rx) = mpsc::sync_channel(16);
            std::thread::spawn(move || {
                for line in io::stdin().lock().lines() {
                    match line {
                        Ok(s) => {
                            if tx.send(s).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
            loop {
                for event in events.try_iter().take(256) {
                    match event {
                        Event::Packet(m) => println!(
                            "{} #{} {} {}",
                            m.direction.name(),
                            m.index,
                            if m.blocked { "BLOCKED" } else { "" },
                            expression::to_lossless_expression(&m.packet)
                        ),
                        other => println!("{other:?}"),
                    }
                }
                match rx.recv_timeout(Duration::from_millis(20)) {
                    Ok(line) if line == "quit" => break,
                    Ok(line) => {
                        if let Some((side, expr)) = line.split_once(' ') {
                            let direction = match side {
                                "server" => Direction::ToServer,
                                "client" => Direction::ToClient,
                                _ => {
                                    eprintln!("expected server or client");
                                    continue;
                                }
                            };
                            match expression::parse(expr) {
                                Ok(p) => {
                                    let allowed = safety.lock().is_ok_and(|registry| {
                                        registry.may_send(
                                            revision.as_deref(),
                                            direction,
                                            p.header(),
                                            developer_mode,
                                        )
                                    });
                                    if !allowed {
                                        eprintln!("packet ID {} has not been observed for this revision and direction", p.header());
                                        continue;
                                    }
                                    if let Err(e) = relay.inject(direction, p) {
                                        eprintln!("{e}")
                                    }
                                }
                                Err(e) => eprintln!("{e}"),
                            }
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
            relay.stop();
        }
        _ => {
            println!("G-Earth Rust {} - work in progress\nCommands:\n  encode '{{h:123}}{{i:42}}{{s:\"hello\"}}'\n  decode '00 00 00 02 00 7B'\n  relay 127.0.0.1:1234 remote.example:30000 [--revision VERSION] [--developer]\nDesktop: cargo run --release --features desktop --bin gearth-desktop\nSee docs/PARITY.md before using this as a G-Earth replacement.",env!("CARGO_PKG_VERSION"));
        }
    }
    Ok(())
}
