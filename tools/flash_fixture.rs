//! Controlled integration client. This binary only connects to a supplied loopback endpoint.
use gearth_rust::{
    crypto::Rc4,
    packet::{read_frame, write_frame, Packet},
};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};
fn read_encrypted(stream: &mut TcpStream, cipher: &mut Rc4) -> io::Result<Packet> {
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    cipher.apply(&mut header);
    let n = u32::from_be_bytes(header) as usize;
    if !(2..=65536).contains(&n) {
        return Err(io::Error::other("invalid fixture frame"));
    }
    let mut body = vec![0; n];
    stream.read_exact(&mut body)?;
    cipher.apply(&mut body);
    let mut bytes = header.to_vec();
    bytes.extend(body);
    Packet::from_bytes(bytes).map_err(io::Error::other)
}
fn main() -> io::Result<()> {
    let mut address = String::new();
    io::stdin().read_line(&mut address)?;
    let address: SocketAddr = address.trim().parse().map_err(io::Error::other)?;
    if !address.ip().is_loopback() {
        return Err(io::Error::other("fixture requires loopback"));
    }
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(25)))?;
    let mut outgoing = Rc4::new(b"flash-fixture-shared-secret").unwrap();
    let mut incoming = outgoing.clone();
    // Simulate AIR's 256 u32 RC4 tables in this controlled process's heap.
    let mut outgoing_words = outgoing.state().0.map(u32::from).to_vec();
    let incoming_words = incoming.state().0.map(u32::from).to_vec();
    println!("FLASH_FIXTURE_READY");
    io::stdout().flush()?;
    let mut hello = Packet::new(1);
    hello
        .put_string("FLASH-TEST")
        .unwrap()
        .put_string("fixture")
        .unwrap();
    write_frame(&mut stream, &hello)?;
    let mut secret = read_frame(&mut stream)?;
    assert_eq!(secret.header(), 2);
    secret.read_string().unwrap();
    assert!(secret.read_bool().unwrap());
    let mut wire = Vec::new();
    for (header, value) in [(77, 13), (78, 41)] {
        let mut p = Packet::new(header);
        p.put_i32(value).unwrap();
        wire.extend_from_slice(p.bytes());
    }
    outgoing.apply(&mut wire);
    outgoing_words.copy_from_slice(&outgoing.state().0.map(u32::from));
    std::hint::black_box((&outgoing_words, &incoming_words));
    stream.write_all(&wire)?;
    for (header, value) in [(88, 17), (89, 33)] {
        let mut p = read_encrypted(&mut stream, &mut incoming)?;
        assert_eq!(p.header(), header);
        assert_eq!(p.read_i32().unwrap(), value);
    }
    let mut ack = Packet::new(90);
    ack.put_bool(true).unwrap();
    let mut wire = ack.bytes().to_vec();
    outgoing.apply(&mut wire);
    stream.write_all(&wire)?;
    std::hint::black_box((&outgoing_words, &incoming_words));
    println!("FLASH_FIXTURE_OK");
    Ok(())
}
