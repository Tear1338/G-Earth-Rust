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

#[test]
fn ipv4_and_ipv6_targets_use_binary_addresses_and_accept_fragmented_replies() {
    use std::net::{Ipv4Addr, Ipv6Addr};
    for (target, kind, expected, reply) in [
        (
            "192.0.2.3:30000",
            1,
            Ipv4Addr::new(192, 0, 2, 3).octets().to_vec(),
            vec![5, 0, 0, 3, 3, b'f', b'o', b'o', 1, 2],
        ),
        (
            "[2001:db8::1234]:30000",
            4,
            "2001:db8::1234"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
            vec![
                5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2,
            ],
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5]).unwrap();
            stream.write_all(&[0]).unwrap();
            let mut request = vec![0; 4 + expected.len() + 2];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, kind]);
            assert_eq!(&request[4..4 + expected.len()], expected);
            assert_eq!(&request[4 + expected.len()..], &30000u16.to_be_bytes());
            for byte in reply {
                stream.write_all(&[byte]).unwrap();
            }
            stream.write_all(b"ok").unwrap();
        });
        let mut stream = SocksConfig {
            proxy: address.to_string(),
            credentials: None,
        }
        .connect(target)
        .unwrap();
        let mut result = [0; 2];
        stream.read_exact(&mut result).unwrap();
        assert_eq!(&result, b"ok");
        proxy.join().unwrap();
    }
}

#[test]
fn malformed_targets_fail_before_connecting_to_proxy() {
    let proxy = SocksConfig {
        proxy: "127.0.0.1:0".into(),
        credentials: None,
    };
    for target in [
        ":30000",
        "[example.com]:30000",
        "[::1:30000",
        "::1:30000",
        "example.com:invalid",
        "example.com",
        "[127.0.0.1]:30000",
    ] {
        let error = proxy.connect(target).unwrap_err();
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "{target}: {error}"
        );
    }
}
