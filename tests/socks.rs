use gearth_rust::socks::SocksConfig;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};
#[test]
fn domain_is_resolved_by_proxy_and_authenticates() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut greeting = [0; 3];
        s.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, 1, 2]);
        s.write_all(&[5, 2]).unwrap();
        let mut auth = [0; 9];
        s.read_exact(&mut auth).unwrap();
        assert_eq!(&auth, b"\x01\x03bob\x03pwd");
        s.write_all(&[1, 0]).unwrap();
        let mut request = [0; 5];
        s.read_exact(&mut request).unwrap();
        assert_eq!(&request[..4], &[5, 1, 0, 3]);
        let mut target = vec![0; request[4] as usize + 2];
        s.read_exact(&mut target).unwrap();
        assert_eq!(&target[..target.len() - 2], b"not-resolved-locally.invalid");
        s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1]).unwrap();
        s.write_all(b"ok").unwrap();
    });
    let mut stream = SocksConfig {
        proxy: address.to_string(),
        credentials: Some(("bob".into(), "pwd".into())),
    }
    .connect("not-resolved-locally.invalid:30000")
    .unwrap();
    let mut result = [0; 2];
    stream.read_exact(&mut result).unwrap();
    assert_eq!(&result, b"ok");
    proxy.join().unwrap();
}
#[test]
fn rejects_wrong_authentication_method() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut greeting = [0; 3];
        s.read_exact(&mut greeting).unwrap();
        s.write_all(&[5, 255]).unwrap();
    });
    assert!(SocksConfig {
        proxy: address.to_string(),
        credentials: None
    }
    .connect("127.0.0.1:30000")
    .is_err());
    proxy.join().unwrap();
}
