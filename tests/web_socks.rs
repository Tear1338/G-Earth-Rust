#![cfg(feature = "web")]
use gearth_rust::{
    socks::SocksConfig,
    web_ca::ProxyIdentity,
    web_proxy::{WebOptions, WebProxy},
};
use hudsucker::{
    certificate_authority::CertificateAuthority,
    futures::{SinkExt, StreamExt},
    rustls::{self, crypto::aws_lc_rs, pki_types::CertificateDer},
    tokio_tungstenite::{
        accept_async, client_async, client_async_tls_with_config, tungstenite::Message, Connector,
    },
};
use std::{io, path::PathBuf, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gearth-web-socks-{:032x}",
            u128::from_ne_bytes(random)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        for name in ["proxy", "upstream"] {
            for file in ["gearth-proxy-cert.pem", "gearth-proxy-key.pem"] {
                let _ = std::fs::remove_file(self.0.join(name).join(file));
            }
            let _ = std::fs::remove_dir(self.0.join(name));
        }
        let _ = std::fs::remove_dir(&self.0);
    }
}

async fn socks_proxy(
    destination: std::net::SocketAddr,
    expected_host: &'static str,
    count: usize,
    reject: bool,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut workers = Vec::new();
        for _ in 0..count {
            let (mut stream, _) = listener.accept().await.unwrap();
            workers.push(tokio::spawn(async move {
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 2]);
                stream.write_all(&[5, 2]).await.unwrap();
                let mut auth = [0; 5];
                stream.read_exact(&mut auth).await.unwrap();
                assert_eq!(auth, [1, 1, b'u', 1, b'p']);
                stream.write_all(&[1, 0]).await.unwrap();
                let mut header = [0; 4];
                stream.read_exact(&mut header).await.unwrap();
                assert_eq!(&header[..3], &[5, 1, 0]);
                let host = match header[3] {
                    1 => {
                        let mut bytes = [0; 4];
                        stream.read_exact(&mut bytes).await.unwrap();
                        std::net::Ipv4Addr::from(bytes).to_string()
                    }
                    3 => {
                        let mut len = [0];
                        stream.read_exact(&mut len).await.unwrap();
                        let mut bytes = vec![0; len[0] as usize];
                        stream.read_exact(&mut bytes).await.unwrap();
                        String::from_utf8(bytes).unwrap()
                    }
                    other => panic!("unexpected address type {other}"),
                };
                assert_eq!(host, expected_host);
                let mut port = [0; 2];
                stream.read_exact(&mut port).await.unwrap();
                assert_eq!(u16::from_be_bytes(port), destination.port());
                if reject {
                    stream.write_all(&[5, 5, 0, 1]).await.unwrap();
                    return;
                }
                let mut target = tokio::net::TcpStream::connect(destination).await.unwrap();
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
            }));
        }
        for worker in workers {
            worker.await.unwrap();
        }
    });
    (address, task)
}

fn options(directory: &Directory, proxy: std::net::SocketAddr) -> WebOptions {
    let mut options = WebOptions::new("127.0.0.1:0".parse().unwrap(), directory.0.join("proxy"));
    options.fetch_packet_info = false;
    options.upstream_socks = Some(SocksConfig {
        proxy: proxy.to_string(),
        credentials: Some(("u".into(), "p".into())),
    });
    options
}

async fn tunnel(proxy: std::net::SocketAddr, target: &str) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
        assert!(response.len() < 8192);
    }
    assert!(response.starts_with(b"HTTP/1.1 200"));
    stream
}

#[tokio::test]
async fn http_websocket_and_raw_connect_use_authenticated_socks() {
    let directory = Directory::new();
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = upstream.local_addr().unwrap();
    let (proxy_addr, socks) = socks_proxy(target_addr, "fixture.invalid", 3, false).await;
    let (mut proxy, _) = WebProxy::start(options(&directory, proxy_addr)).unwrap();
    let server = tokio::spawn(async move {
        let (mut http, _) = upstream.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            http.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
            assert!(request.len() < 8192);
        }
        assert!(request.starts_with(b"GET /fixture HTTP/1.1\r\n"));
        http.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        drop(http);
        let (stream, _) = upstream.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "hello"
        );
        socket.send(Message::Text("reply".into())).await.unwrap();
        drop(socket);
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"PING");
        stream.write_all(b"PONG").await.unwrap();
    });
    let target = format!("fixture.invalid:{}", target_addr.port());
    let mut http = tokio::net::TcpStream::connect(proxy.address).await.unwrap();
    http.write_all(
        format!(
            "GET http://{target}/fixture HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), http.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.ends_with(b"ok"));
    let stream = tunnel(proxy.address, &target).await;
    let (mut ws, _) = client_async(format!("ws://{target}/game"), stream)
        .await
        .unwrap();
    ws.send(Message::Text("hello".into())).await.unwrap();
    assert_eq!(
        ws.next().await.unwrap().unwrap().into_text().unwrap(),
        "reply"
    );
    drop(ws);
    let mut raw = tunnel(proxy.address, &target).await;
    raw.write_all(b"PING").await.unwrap();
    let mut response = [0; 4];
    raw.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"PONG");
    drop(raw);
    server.await.unwrap();
    proxy.stop();
    tokio::time::timeout(Duration::from_secs(5), socks)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn https_and_wss_use_socks_and_check_both_tls_legs() {
    let directory = Directory::new();
    let identity = ProxyIdentity::ensure(&directory.0.join("upstream")).unwrap();
    let authority = identity.authority().unwrap();
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = upstream.local_addr().unwrap();
    let target = format!("fixture.invalid:{}", target_addr.port());
    let server_config = authority.gen_server_config(&target.parse().unwrap()).await;
    let (proxy_addr, socks) = socks_proxy(target_addr, "fixture.invalid", 2, false).await;
    let mut opts = options(&directory, proxy_addr);
    opts.extra_roots.push(identity.certificate_der);
    let (mut proxy, _) = WebProxy::start(opts).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(server_config.clone())
            .accept(stream)
            .await
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            tls.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
            assert!(request.len() < 8192);
        }
        assert!(request.starts_with(b"GET /fixture HTTP/1.1\r\n"));
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        tls.shutdown().await.unwrap();
        let (stream, _) = upstream.accept().await.unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(server_config)
            .accept(stream)
            .await
            .unwrap();
        let mut ws = accept_async(tls).await.unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap().into_text().unwrap(),
            "hello"
        );
        ws.send(Message::Text("secure".into())).await.unwrap();
    });
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(proxy.certificate_der.clone()))
        .unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let stream = tunnel(proxy.address, &target).await;
    let mut https = tokio_rustls::TlsConnector::from(Arc::new(tls.clone()))
        .connect(
            rustls::pki_types::ServerName::try_from("fixture.invalid")
                .unwrap()
                .to_owned(),
            stream,
        )
        .await
        .unwrap();
    https
        .write_all(
            format!("GET /fixture HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), https.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.ends_with(b"ok"));
    let stream = tunnel(proxy.address, &target).await;
    let (mut ws, _) = client_async_tls_with_config(
        format!("wss://{target}/game"),
        stream,
        None,
        Some(Connector::Rustls(Arc::new(tls))),
    )
    .await
    .unwrap();
    ws.send(Message::Text("hello".into())).await.unwrap();
    assert_eq!(
        ws.next().await.unwrap().unwrap().into_text().unwrap(),
        "secure"
    );
    drop(ws);
    server.await.unwrap();
    proxy.stop();
    tokio::time::timeout(Duration::from_secs(5), socks)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn https_over_socks_rejects_untrusted_upstream_certificate() {
    let directory = Directory::new();
    let identity = ProxyIdentity::ensure(&directory.0.join("upstream")).unwrap();
    let authority = identity.authority().unwrap();
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = upstream.local_addr().unwrap();
    let target = format!("fixture.invalid:{}", target_addr.port());
    let server_config = authority.gen_server_config(&target.parse().unwrap()).await;
    let (proxy_addr, socks) = socks_proxy(target_addr, "fixture.invalid", 1, false).await;
    // Do not add the upstream test CA to the proxy's trusted roots.
    let (mut proxy, _) = WebProxy::start(options(&directory, proxy_addr)).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.unwrap();
        if let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(server_config)
            .accept(stream)
            .await
        {
            let mut byte = [0];
            assert_eq!(tls.read(&mut byte).await.unwrap_or(0), 0);
        }
    });
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(proxy.certificate_der.clone()))
        .unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let stream = tunnel(proxy.address, &target).await;
    let mut client = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(
            rustls::pki_types::ServerName::try_from("fixture.invalid")
                .unwrap()
                .to_owned(),
            stream,
        )
        .await
        .unwrap();
    client
        .write_all(
            format!("GET /fixture HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 502"));
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    proxy.stop();
    socks.await.unwrap();
}

#[tokio::test]
async fn rejected_socks_never_falls_back_to_direct_http_websocket_or_raw() {
    let directory = Directory::new();
    let forbidden = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = forbidden.local_addr().unwrap();
    let (proxy_addr, socks) = socks_proxy(target_addr, "127.0.0.1", 3, true).await;
    let (mut proxy, _) = WebProxy::start(options(&directory, proxy_addr)).unwrap();
    let target = target_addr.to_string();
    let mut http = tokio::net::TcpStream::connect(proxy.address).await.unwrap();
    http.write_all(
        format!("GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), http.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 502"));
    let stream = tunnel(proxy.address, &target).await;
    let (mut ws, _) = client_async(format!("ws://{target}/game"), stream)
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap();
    drop(ws);
    let mut raw = tunnel(proxy.address, &target).await;
    raw.write_all(b"PING").await.unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), raw.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), forbidden.accept())
            .await
            .is_err(),
        "unexpected direct connection"
    );
    proxy.stop();
    socks.await.unwrap();
}

#[test]
fn socks_rejects_city_helper_until_it_is_routed() {
    let directory = Directory::new();
    let mut opts = WebOptions::new("127.0.0.1:0".parse().unwrap(), directory.0.join("proxy"));
    opts.upstream_socks = Some(SocksConfig {
        proxy: "127.0.0.1:9".into(),
        credentials: None,
    });
    opts.allow_city_helper = true;
    assert_eq!(
        WebProxy::start(opts).err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
}
