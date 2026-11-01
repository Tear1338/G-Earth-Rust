use gearth_rust::{
    crypto::Rc4,
    packet::{Direction, Packet},
    relay::{Config, Relay, RelayOptions},
    rules::{Action, Rule, Rules},
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    time::Duration,
};
fn write_encrypted(stream: &mut TcpStream, cipher: &mut Rc4, packet: &Packet) {
    let mut bytes = packet.bytes().to_vec();
    cipher.apply(&mut bytes);
    stream.write_all(&bytes).unwrap();
}
fn read_encrypted(stream: &mut TcpStream, cipher: &mut Rc4) -> Packet {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    cipher.apply(&mut prefix);
    let n = u32::from_be_bytes(prefix) as usize;
    assert!((2..=10000).contains(&n));
    let mut body = vec![0; n];
    stream.read_exact(&mut body).unwrap();
    cipher.apply(&mut body);
    Packet::from_bytes([prefix.to_vec(), body].concat()).unwrap()
}
#[test]
fn rc4_counters_remain_independent_after_blocking_and_injection() {
    let remote = TcpListener::bind("127.0.0.1:0").unwrap();
    let out = Rc4::new(b"outgoing").unwrap();
    let incoming = Rc4::new(b"incoming").unwrap();
    let (mut relay, _) = Relay::start_with_options(
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            remote: remote.local_addr().unwrap().to_string(),
        },
        RelayOptions {
            outgoing_rc4: Some(out.clone()),
            incoming_rc4: Some(incoming.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    relay
        .set_rules(Rules {
            entries: vec![Rule {
                enabled: true,
                direction: Direction::ToServer,
                header: 77,
                action: Action::Block,
            }],
        })
        .unwrap();
    let mut client = TcpStream::connect(relay.address).unwrap();
    let (mut server, _) = remote.accept().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (mut client_encrypt, mut server_decrypt) = (out.clone(), out);
    let (mut server_encrypt, mut client_decrypt) = (incoming.clone(), incoming);
    write_encrypted(&mut client, &mut client_encrypt, &Packet::new(77));
    write_encrypted(&mut client, &mut client_encrypt, &Packet::new(78));
    assert_eq!(
        read_encrypted(&mut server, &mut server_decrypt).header(),
        78
    );
    relay.inject(Direction::ToServer, Packet::new(90)).unwrap();
    assert_eq!(
        read_encrypted(&mut server, &mut server_decrypt).header(),
        90
    );
    write_encrypted(&mut client, &mut client_encrypt, &Packet::new(79));
    assert_eq!(
        read_encrypted(&mut server, &mut server_decrypt).header(),
        79
    );
    write_encrypted(&mut server, &mut server_encrypt, &Packet::new(80));
    assert_eq!(
        read_encrypted(&mut client, &mut client_decrypt).header(),
        80
    );
    relay.inject(Direction::ToClient, Packet::new(91)).unwrap();
    assert_eq!(
        read_encrypted(&mut client, &mut client_decrypt).header(),
        91
    );
    write_encrypted(&mut server, &mut server_encrypt, &Packet::new(81));
    assert_eq!(
        read_encrypted(&mut client, &mut client_decrypt).header(),
        81
    );
    relay.stop();
}
