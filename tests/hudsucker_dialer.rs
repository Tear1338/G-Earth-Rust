#![cfg(feature = "web")]
use gearth_rust::web_ca::ProxyIdentity;
use hudsucker::{
    certificate_authority::CertificateAuthority,
    futures::{SinkExt, StreamExt},
    rustls::{self, crypto::aws_lc_rs, pki_types::CertificateDer},
    tokio_tungstenite::{
        accept_async, client_async, client_async_tls_with_config, tungstenite::Message, Connector,
    },
    Proxy, UpstreamDialer,
};
use std::{io, path::PathBuf, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gearth-dialer-{:032x}",
            u128::from_ne_bytes(random)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

#[tokio::test]
async fn custom_dialer_preserves_websocket_tls_hostname_and_certificate_validation() {
    let directory = Directory::new();
    let identity = ProxyIdentity::ensure(&directory.0.join("ca")).unwrap();
    let authority = identity.authority().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(identity.certificate_der))
        .unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let target = "fixture.invalid:3456";
    let server_config = authority.gen_server_config(&target.parse().unwrap()).await;
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let (called_tx, mut called_rx) = tokio::sync::mpsc::unbounded_channel();
    let dialer: UpstreamDialer = Arc::new(move |uri| {
        let called = called_tx.clone();
        Box::pin(async move {
            called.send(uri).unwrap();
            tokio::net::TcpStream::connect(upstream_address).await
        })
    });
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(authority)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_websocket_connector(Connector::Rustls(Arc::new(tls.clone())))
        .with_upstream_dialer(dialer)
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        })
        .build()
        .unwrap();
    let proxy_task = tokio::spawn(proxy.start());
    let server = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(server_config)
            .accept(stream)
            .await
            .unwrap();
        let mut socket = accept_async(tls).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "secure"
        );
        socket.send(Message::Text("reply".into())).await.unwrap();
    });
    let stream = tunnel(proxy_address, target).await;
    let (mut client, _) = client_async_tls_with_config(
        format!("wss://{target}/game"),
        stream,
        None,
        Some(Connector::Rustls(Arc::new(tls))),
    )
    .await
    .unwrap();
    client.send(Message::Text("secure".into())).await.unwrap();
    assert_eq!(
        client.next().await.unwrap().unwrap().into_text().unwrap(),
        "reply"
    );
    let called = called_rx.recv().await.unwrap();
    assert_eq!(called.scheme_str(), Some("wss"));
    assert_eq!(called.host(), Some("fixture.invalid"));
    server.await.unwrap();
    drop(client);
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), proxy_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn custom_dialer_rejects_websocket_tls_certificate_for_wrong_hostname() {
    let directory = Directory::new();
    let identity = ProxyIdentity::ensure(&directory.0.join("ca")).unwrap();
    let authority = identity.authority().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(identity.certificate_der))
        .unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_config = authority
        .gen_server_config(&"wrong.invalid:3456".parse().unwrap())
        .await;
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let dialer: UpstreamDialer =
        Arc::new(move |_| Box::pin(tokio::net::TcpStream::connect(upstream_address)));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(authority)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_websocket_connector(Connector::Rustls(Arc::new(tls.clone())))
        .with_upstream_dialer(dialer)
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        })
        .build()
        .unwrap();
    let proxy_task = tokio::spawn(proxy.start());
    let server = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.unwrap();
        if let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(server_config)
            .accept(stream)
            .await
        {
            let mut data = [0; 1];
            assert_eq!(tls.read(&mut data).await.unwrap_or(0), 0);
        }
    });
    let target = "fixture.invalid:3456";
    let stream = tunnel(proxy_address, target).await;
    let (mut client, _) = client_async_tls_with_config(
        format!("wss://{target}/game"),
        stream,
        None,
        Some(Connector::Rustls(Arc::new(tls))),
    )
    .await
    .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), client.next())
        .await
        .unwrap();
    assert!(!matches!(
        result,
        Some(Ok(Message::Text(_) | Message::Binary(_)))
    ));
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    drop(client);
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), proxy_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
impl Drop for Directory {
    fn drop(&mut self) {
        for file in ["gearth-proxy-cert.pem", "gearth-proxy-key.pem"] {
            let _ = std::fs::remove_file(self.0.join("ca").join(file));
        }
        let _ = std::fs::remove_dir(self.0.join("ca"));
        let _ = std::fs::remove_dir(&self.0);
    }
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
async fn custom_dialer_routes_websocket_and_never_falls_back_on_failure() {
    let directory = Directory::new();
    let identity = ProxyIdentity::ensure(&directory.0.join("ca")).unwrap();
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let (called_tx, mut called_rx) = tokio::sync::mpsc::unbounded_channel();
    let dialer: UpstreamDialer = Arc::new(move |uri| {
        let called = called_tx.clone();
        Box::pin(async move {
            called.send(uri.clone()).unwrap();
            if uri.host() == Some("fixture.invalid") {
                tokio::net::TcpStream::connect(upstream_address).await
            } else {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "fixture rejects direct dial",
                ))
            }
        })
    });
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(identity.authority().unwrap())
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_upstream_dialer(dialer)
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        })
        .build()
        .unwrap();
    let proxy_task = tokio::spawn(proxy.start());
    let server = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        assert_eq!(
            socket.next().await.unwrap().unwrap().into_text().unwrap(),
            "hello"
        );
        socket.send(Message::Text("reply".into())).await.unwrap();
        drop(socket);
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = [0; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"PING");
        stream.write_all(b"PONG").await.unwrap();
    });
    let target = "fixture.invalid:3456";
    let stream = tunnel(proxy_address, target).await;
    let (mut client, _) = client_async(format!("ws://{target}/game"), stream)
        .await
        .unwrap();
    client.send(Message::Text("hello".into())).await.unwrap();
    assert_eq!(
        client.next().await.unwrap().unwrap().into_text().unwrap(),
        "reply"
    );
    assert_eq!(
        called_rx.recv().await.unwrap().host(),
        Some("fixture.invalid")
    );
    drop(client);
    let mut raw = tunnel(proxy_address, target).await;
    raw.write_all(b"PING").await.unwrap();
    let mut reply = [0; 4];
    raw.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"PONG");
    assert_eq!(
        called_rx.recv().await.unwrap().host(),
        Some("fixture.invalid")
    );
    server.await.unwrap();
    drop(raw);

    for websocket in [true, false] {
        let forbidden = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = forbidden.local_addr().unwrap().to_string();
        let mut stream = tunnel(proxy_address, &target).await;
        if websocket {
            let (mut client, _) = client_async(format!("ws://{target}/game"), stream)
                .await
                .unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(2), client.next()).await;
        } else {
            stream.write_all(b"PING").await.unwrap();
            let mut response = [0];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), stream.read(&mut response))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
        let called = tokio::time::timeout(Duration::from_secs(2), called_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(called.host(), Some("127.0.0.1"));
        assert!(
            tokio::time::timeout(Duration::from_millis(250), forbidden.accept())
                .await
                .is_err(),
            "unexpected direct connection"
        );
    }
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), proxy_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
