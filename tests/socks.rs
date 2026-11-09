use gearth_rust::socks::SocksConfig;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

#[tokio::test]
async fn async_socks_authenticates_and_sends_hostname_to_proxy() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 2]);
        stream.write_all(&[5, 2]).await.unwrap();
        let mut auth = [0; 5];
        stream.read_exact(&mut auth).await.unwrap();
        assert_eq!(&auth, &[1, 1, b'u', 1, b'p']);
        stream.write_all(&[1, 0]).await.unwrap();
        let mut prefix = [0; 5];
        stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix[..4], &[5, 1, 0, 3]);
        let mut host = vec![0; usize::from(prefix[4])];
        stream.read_exact(&mut host).await.unwrap();
        assert_eq!(host, b"unresolvable.invalid");
        let mut port = [0; 2];
        stream.read_exact(&mut port).await.unwrap();
        assert_eq!(u16::from_be_bytes(port), 443);
        for byte in [5, 0, 0, 1, 127, 0, 0, 1, 0, 1] {
            stream.write_all(&[byte]).await.unwrap();
        }
        stream.write_all(b"ok").await.unwrap();
    });
    let config = SocksConfig {
        proxy: proxy_address.to_string(),
        credentials: Some(("u".into(), "p".into())),
    };
    let mut stream = config
        .connect_async("unresolvable.invalid:443")
        .await
        .unwrap();
    let mut result = [0; 2];
    stream.read_exact(&mut result).await.unwrap();
    assert_eq!(&result, b"ok");
    server.await.unwrap();
}

#[tokio::test]
async fn async_socks_cancellation_closes_stalled_handshake() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = SocksConfig {
        proxy: listener.local_addr().unwrap().to_string(),
        credentials: None,
    };
    let worker = tokio::spawn(async move { config.connect_async("example.invalid:443").await });
    let (mut peer, _) = listener.accept().await.unwrap();
    let mut greeting = [0; 3];
    peer.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, 0]);
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), peer.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn async_socks_encodes_ip_targets_and_propagates_proxy_rejection() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for (target, expected) in [
        ("192.0.2.3:443", vec![1, 192, 0, 2, 3]),
        (
            "[2001:db8::1]:443",
            [
                vec![4],
                "2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
                    .to_vec(),
            ]
            .concat(),
        ),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = SocksConfig {
            proxy: listener.local_addr().unwrap().to_string(),
            credentials: None,
        };
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = vec![0; 3 + expected.len() + 2];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..3], &[5, 1, 0]);
            assert_eq!(&request[3..3 + expected.len()], expected);
            assert_eq!(&request[3 + expected.len()..], &443u16.to_be_bytes());
            stream.write_all(&[5, 5, 0, 1]).await.unwrap();
        });
        assert_eq!(
            config.connect_async(target).await.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionRefused
        );
        server.await.unwrap();
    }
    let config = SocksConfig {
        proxy: "127.0.0.1:0".into(),
        credentials: None,
    };
    for target in [":443", "[example.com]:443", "::1:443", "example.com:nope"] {
        assert_eq!(
            config.connect_async(target).await.unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
}

#[tokio::test]
async fn async_socks_rejects_authentication_downgrade_and_bad_credentials() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for downgrade in [true, false] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = SocksConfig {
            proxy: listener.local_addr().unwrap().to_string(),
            credentials: Some(("u".into(), "p".into())),
        };
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            if downgrade {
                stream.write_all(&[5, 0]).await.unwrap();
            } else {
                stream.write_all(&[5, 2]).await.unwrap();
                let mut auth = [0; 5];
                stream.read_exact(&mut auth).await.unwrap();
                stream.write_all(&[1, 1]).await.unwrap();
            }
        });
        assert_eq!(
            config
                .connect_async("example.invalid:443")
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        server.await.unwrap();
    }
}
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
