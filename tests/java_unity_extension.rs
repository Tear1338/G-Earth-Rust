#![cfg(feature = "web")]
use gearth_rust::{
    extension_host::{ExtensionHost, HostEvent},
    packet::{Direction, Packet},
    packet_info::{PacketInfo, PacketInfoManager},
    unity_server::{UnityOptions, UnityServer},
};
use hudsucker::{
    futures::{SinkExt, StreamExt},
    rustls::{self, crypto::aws_lc_rs, pki_types::CertificateDer},
    tokio_tungstenite::{
        client_async_tls_with_config, tungstenite::Message, Connector, MaybeTlsStream,
        WebSocketStream,
    },
};
use std::{
    path::PathBuf,
    process::{Child, Command},
    time::{Duration, Instant},
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        for file in ["ca/gearth-proxy-cert.pem", "ca/gearth-proxy-key.pem"] {
            let _ = std::fs::remove_file(self.0.join(file));
        }
        let _ = std::fs::remove_dir(self.0.join("ca"));
        let _ = std::fs::remove_dir(&self.0);
    }
}
type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
async fn send(socket: &mut Socket, direction: u8, packet: &Packet) {
    let mut bytes = vec![direction];
    bytes.extend(packet.bytes());
    socket.send(Message::Binary(bytes.into())).await.unwrap();
}
async fn receive(socket: &mut Socket) -> (u8, Packet) {
    let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let bytes = message.into_data();
    (bytes[0], Packet::from_bytes(bytes[1..].to_vec()).unwrap())
}
#[test]
#[ignore = "requires the actual beta-29 Java API and compiled JavaExtensionFixture"]
fn actual_beta29_java_extension_resolves_injects_and_intercepts_unity_packets() {
    let classpath =
        std::env::var("GEARTH_EXTENSION_CLASSPATH").expect("Java fixture classpath is required");
    let (host, host_events) =
        ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    let token = host.register_launch("fixture.jar").unwrap();
    let _process = Process(
        Command::new("java")
            .args([
                "-cp",
                &classpath,
                "JavaExtensionFixture",
                "-p",
                &host.address.port().to_string(),
                "-f",
                "fixture.jar",
                "-c",
                &token,
            ])
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !matches!(
        host_events.recv_timeout(Duration::from_millis(100)),
        Ok(HostEvent::Connected { .. })
    ) {
        assert!(
            Instant::now() < deadline,
            "Java extension did not authenticate"
        );
    }
    let mut random = [0; 16];
    getrandom::fill(&mut random).unwrap();
    let directory = Directory(
        std::env::temp_dir().join(format!(
            "gearth-java-unity-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )),
    );
    std::fs::create_dir(&directory.0).unwrap();
    let mut options = UnityOptions::new("127.0.0.1:0".parse().unwrap(), directory.0.join("ca"));
    options.extensions = Some(host.clone());
    options.packet_info = PacketInfoManager::new(
        "",
        vec![
            PacketInfo {
                header: 77,
                name: Some("TestOutgoing".into()),
                hash: None,
                structure: Some("i".into()),
                direction: Direction::ToServer,
                source: "fixture".into(),
            },
            PacketInfo {
                header: 91,
                name: Some("TestInjection".into()),
                hash: None,
                structure: Some("i".into()),
                direction: Direction::ToServer,
                source: "fixture".into(),
            },
        ],
    );
    let (mut server, _) = UnityServer::start(options).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(server.certificate_der.clone()))
        .unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let stream = tokio::net::TcpStream::connect(server.address)
            .await
            .unwrap();
        let (mut client, _) = client_async_tls_with_config(
            server.websocket_url(),
            stream,
            None,
            Some(Connector::Rustls(std::sync::Arc::new(tls))),
        )
        .await
        .unwrap();
        client
            .send(Message::Binary(b"TEST-UNITY-JAVA".to_vec().into()))
            .await
            .unwrap();
        let mut hello = Packet::new(4000);
        hello
            .put_string("ignored")
            .unwrap()
            .put_string("UNITY-FIXTURE")
            .unwrap();
        send(&mut client, 1, &hello).await;
        assert_eq!(receive(&mut client).await.1.header(), 4000);
        let (direction, mut injected) = receive(&mut client).await;
        assert_eq!((direction, injected.header()), (1, 91));
        assert_eq!(injected.read_i32().unwrap(), 17);
        for (value, expected) in [(5, Some(6)), (13, None), (8, Some(9))] {
            let mut packet = Packet::new(77);
            packet.put_i32(value).unwrap();
            send(&mut client, 1, &packet).await;
            if let Some(expected) = expected {
                let (direction, mut packet) = receive(&mut client).await;
                assert_eq!((direction, packet.header()), (1, 77));
                assert_eq!(packet.read_i32().unwrap(), expected);
            }
        }
        let mut packet = Packet::new(78);
        packet.put_i32(5).unwrap();
        send(&mut client, 0, &packet).await;
        let (direction, mut packet) = receive(&mut client).await;
        assert_eq!((direction, packet.header()), (0, 78));
        assert_eq!(packet.read_i32().unwrap(), 7);
        client.close(None).await.unwrap();
    });
    server.stop();
    host.stop();
}
