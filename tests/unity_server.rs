#![cfg(feature = "web")]
use gearth_rust::{
    packet::{Direction, Packet},
    relay::Event,
    rules::{Action, Rule, Rules},
    unity_server::{UnityOptions, UnityServer},
};
use hudsucker::{
    futures::{SinkExt, StreamExt},
    rustls::{self, crypto::aws_lc_rs, pki_types::CertificateDer},
    tokio_tungstenite::{
        client_async_tls_with_config,
        tungstenite::{Error, Message},
        Connector, MaybeTlsStream, WebSocketStream,
    },
};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).unwrap();
        let name = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let path = std::env::temp_dir().join(format!("gearth-unity-test-{name}"));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        for name in ["gearth-proxy-cert.pem", "gearth-proxy-key.pem"] {
            let _ = std::fs::remove_file(self.0.join("ca").join(name));
        }
        let _ = std::fs::remove_dir(self.0.join("ca"));
        let _ = std::fs::remove_dir(&self.0);
    }
}
async fn connect(server: &UnityServer, url: Option<&str>) -> Result<Socket, Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(server.certificate_der.clone()))
        .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let stream = tokio::net::TcpStream::connect(server.address)
        .await
        .unwrap();
    client_async_tls_with_config(
        url.unwrap_or(&server.websocket_url()),
        stream,
        None,
        Some(Connector::Rustls(std::sync::Arc::new(config))),
    )
    .await
    .map(|(socket, _)| socket)
}
fn packet(header: u16, value: i32) -> Packet {
    let mut packet = Packet::new(header);
    packet.put_i32(value).unwrap();
    packet.edited = false;
    packet
}
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
async fn hello(socket: &mut Socket) {
    hello_revision(socket, "TEST-UNITY-1").await;
}
async fn hello_revision(socket: &mut Socket, revision: &str) {
    socket
        .send(Message::Binary(revision.as_bytes().to_vec().into()))
        .await
        .unwrap();
    let mut hello = Packet::new(4000);
    hello
        .put_string("ignored")
        .unwrap()
        .put_string("UNITY-FIXTURE")
        .unwrap();
    hello.edited = false;
    send(socket, 1, &hello).await;
    assert_eq!(receive(socket).await, (1, hello));
}

#[test]
fn client_permissions_are_rewritten_and_restored_through_unity() {
    use gearth_rust::admin_service::AdminService;
    use std::sync::{Arc, Mutex};
    let directory = Directory::new();
    let service = Arc::new(Mutex::new(AdminService::default()));
    service.lock().unwrap().set_enabled(true);
    let mut options = UnityOptions::new("127.0.0.1:0".parse().unwrap(), directory.0.join("ca"));
    options.admin_service = Some(service.clone());
    let (mut server, _) = UnityServer::start(options).unwrap();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let mut client = connect(&server, None).await.unwrap();
        hello(&mut client).await;
        let mut original = Packet::new(88);
        original.append(&[0, 0, 0, 1, 0, 0, 0, 2, 0]).unwrap();
        send(&mut client, 0, &original).await;
        assert_eq!(
            receive(&mut client).await.1.body(),
            &[0, 0, 0, 7, 0, 0, 0, 7, 1]
        );
        let restore = service.lock().unwrap().set_enabled(false).unwrap();
        server.inject(Direction::ToClient, restore).unwrap();
        assert_eq!(receive(&mut client).await.1.bytes(), original.bytes());
        client.close(None).await.unwrap();
    });
    server.stop();
}
#[test]
fn tls_communicator_authenticates_and_routes_mutations_injections_and_fragmented_packets() {
    let directory = Directory::new();
    let safety = std::sync::Arc::new(std::sync::Mutex::new(
        gearth_rust::packet_safety::PacketSafety::default(),
    ));
    let mut options = UnityOptions::new("127.0.0.1:0".parse().unwrap(), directory.0.join("ca"));
    options.packet_safety = Some(safety.clone());
    options.packet_info = gearth_rust::packet_info::PacketInfoManager::new(
        "fixture",
        vec![gearth_rust::packet_info::PacketInfo {
            header: 444,
            name: Some("Known".into()),
            hash: None,
            structure: None,
            direction: Direction::ToServer,
            source: "fixture".into(),
        }],
    );

    let (mut server, events) = UnityServer::start(options).unwrap();
    server
        .set_rules(Rules {
            entries: vec![
                Rule {
                    enabled: true,
                    direction: Direction::ToServer,
                    header: 77,
                    action: Action::Block,
                },
                Rule {
                    enabled: true,
                    direction: Direction::ToServer,
                    header: 78,
                    action: Action::Replace(packet(78, 42)),
                },
            ],
        })
        .unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let mut client = connect(&server, None).await.unwrap();
        hello(&mut client).await;
        assert!(server.connected());
        send(&mut client, 1, &packet(77, 13)).await;
        send(&mut client, 1, &packet(78, 41)).await;
        let (direction, mut edited) = receive(&mut client).await;
        assert_eq!(direction, 1);
        assert_eq!(edited.header(), 78);
        assert_eq!(edited.read_i32().unwrap(), 42);
        server.inject(Direction::ToServer, packet(79, 99)).unwrap();
        assert_eq!(receive(&mut client).await, (1, packet(79, 99)));
        send(&mut client, 0, &packet(88, 17)).await;
        assert_eq!(receive(&mut client).await, (0, packet(88, 17)));
        server.inject(Direction::ToClient, packet(89, 33)).unwrap();
        assert_eq!(receive(&mut client).await, (0, packet(89, 33)));
        let fragmented = packet(90, 100);
        for chunk in fragmented.bytes().chunks(3) {
            let mut bytes = vec![1];
            bytes.extend(chunk);
            client.send(Message::Binary(bytes.into())).await.unwrap();
        }
        assert_eq!(receive(&mut client).await, (1, fragmented));
        let mut bytes = vec![1];
        bytes.extend(packet(92, 1).bytes());
        bytes.extend(packet(93, 2).bytes());
        client.send(Message::Binary(bytes.into())).await.unwrap();
        assert_eq!(receive(&mut client).await, (1, packet(92, 1)));
        assert_eq!(receive(&mut client).await, (1, packet(93, 2)));
        client.close(None).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while server.connected() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let mut reconnected = connect(&server, None).await.unwrap();
        hello(&mut reconnected).await;
        let start = Instant::now();
        server.stop();
        assert!(start.elapsed() < Duration::from_secs(2));
    });
    let events = events.try_iter().collect::<Vec<_>>();
    assert!(events
        .iter()
        .any(|e| matches!(e,Event::Packet(m) if m.packet.header()==77&&m.blocked)));
    assert!(events.iter().any(|e|matches!(e,Event::Identified {version,identifier} if version=="TEST-UNITY-1"&&identifier=="UNITY-FIXTURE")));
    let observed = safety.lock().unwrap();
    let revision = Some("TEST-UNITY-1");
    assert!(observed.is_safe(revision, Direction::ToServer, 444));
    assert!(!observed.is_safe(revision, Direction::ToClient, 444));
    assert!(observed.is_safe(revision, Direction::ToServer, 77));
    assert!(observed.is_safe(revision, Direction::ToServer, 78));
    assert!(observed.is_safe(revision, Direction::ToClient, 88));
    assert!(!observed.is_safe(revision, Direction::ToServer, 79));
    assert!(!observed.is_safe(revision, Direction::ToClient, 89));
}
#[test]
fn unity_static_metadata_is_registered_separately_for_each_revision() {
    use gearth_rust::{
        packet_info::{PacketInfo, PacketInfoManager},
        packet_safety::PacketSafety,
    };
    use std::sync::{Arc, Mutex};
    let directory = Directory::new();
    let safety = Arc::new(Mutex::new(PacketSafety::default()));
    let mut options = UnityOptions::new("127.0.0.1:0".parse().unwrap(), directory.0.join("ca"));
    options.packet_safety = Some(safety.clone());
    options.packet_info = PacketInfoManager::new(
        "",
        vec![PacketInfo {
            header: 444,
            name: Some("Known".into()),
            hash: None,
            structure: None,
            direction: Direction::ToServer,
            source: "fixture".into(),
        }],
    );
    let (mut server, _) = UnityServer::start(options).unwrap();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for revision in ["REV-A", "REV-B"] {
            let mut client = connect(&server, None).await.unwrap();
            hello_revision(&mut client, revision).await;
            assert!(safety
                .lock()
                .unwrap()
                .is_safe(Some(revision), Direction::ToServer, 444));
            assert!(!safety
                .lock()
                .unwrap()
                .is_safe(Some(revision), Direction::ToClient, 444));
            client.close(None).await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while server.connected() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        }
    });
    assert!(!safety
        .lock()
        .unwrap()
        .is_safe(Some("OTHER"), Direction::ToServer, 444));
    server.stop();
}

#[test]
fn refuses_missing_token_and_a_second_concurrent_browser() {
    let directory = Directory::new();
    let (mut server, _) = UnityServer::start(UnityOptions::new(
        "127.0.0.1:0".parse().unwrap(),
        directory.0.join("ca"),
    ))
    .unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async{assert!(matches!(connect(&server,Some(&format!("wss://localhost:{}/",server.address.port()))).await,Err(Error::Http(response)) if response.status()==403));let mut first=connect(&server,None).await.unwrap();hello(&mut first).await;let mut second=connect(&server,None).await.unwrap();assert!(tokio::time::timeout(Duration::from_secs(5),second.next()).await.unwrap().is_none_or(|message|message.is_err()||message.unwrap().is_close()));send(&mut first,1,&packet(99,1)).await;assert_eq!(receive(&mut first).await,(1,packet(99,1)));first.close(None).await.unwrap();});
    server.stop();
}
