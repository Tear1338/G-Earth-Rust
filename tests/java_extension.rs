use gearth_rust::{
    extension_host::{ConnectionDetails, ExtensionHost, HostEvent},
    packet::{read_frame, write_frame, Direction, Packet},
    packet_info::{PacketInfo, PacketInfoManager},
    relay::{Config, Relay, RelayOptions},
};
use std::{
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
#[ignore = "requires the actual beta-29 Java API and compiled JavaExtensionFixture"]
fn actual_java_extension_connects_resolves_names_injects_blocks_and_edits() {
    let classpath =
        std::env::var("GEARTH_EXTENSION_CLASSPATH").expect("Java fixture classpath required");
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
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
    loop {
        if matches!(
            events.recv_timeout(Duration::from_millis(100)),
            Ok(HostEvent::Connected { .. })
        ) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Java extension did not authenticate"
        );
    }
    let packets = PacketInfoManager::new(
        "TEST",
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
    let remote = TcpListener::bind("127.0.0.1:0").unwrap();
    let options = RelayOptions {
        extensions: Some(host.clone()),
        connection: Some(ConnectionDetails {
            host: "test.example".into(),
            port: 30000,
            version: "TEST".into(),
            identifier: "fixture".into(),
            client_type: "FLASH".into(),
            packets,
        }),
        ..Default::default()
    };
    let (mut relay, _) = Relay::start_with_options(
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            remote: remote.local_addr().unwrap().to_string(),
        },
        options,
    )
    .unwrap();
    let mut client = TcpStream::connect(relay.address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (mut server, _) = remote.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut injected = read_frame(&mut server).unwrap();
    assert_eq!(injected.header(), 91);
    assert_eq!(injected.read_i32().unwrap(), 17);
    for (value, expected) in [(5, 6), (8, 9)] {
        if value == 8 {
            let mut blocked = Packet::new(77);
            blocked.put_i32(13).unwrap();
            write_frame(&mut client, &blocked).unwrap();
        }
        let mut p = Packet::new(77);
        p.put_i32(value).unwrap();
        write_frame(&mut client, &p).unwrap();
        let mut received = read_frame(&mut server).unwrap();
        assert_eq!(received.header(), 77);
        assert_eq!(received.read_i32().unwrap(), expected);
    }
    let mut incoming = Packet::new(78);
    incoming.put_i32(5).unwrap();
    write_frame(&mut server, &incoming).unwrap();
    assert_eq!(read_frame(&mut client).unwrap().read_i32().unwrap(), 7);
    relay.stop();
    host.stop();
    thread::sleep(Duration::from_millis(10));
}
#[cfg(feature="web")]
#[test]
#[ignore="requires the actual beta-29 Java API and compiled JavaExtensionFixture"]
fn actual_java_extension_intercepts_a_nitro_websocket_connection(){
    use gearth_rust::web_proxy::{WebOptions,WebProxy,NITRO_REVISION};
    use hudsucker::{futures::{SinkExt,StreamExt},tokio_tungstenite::{accept_async,client_async,tungstenite::Message}};
    let classpath=std::env::var("GEARTH_EXTENSION_CLASSPATH").expect("Java fixture classpath required");let (host,events)=ExtensionHost::start("127.0.0.1:0".parse().unwrap(),Vec::new()).unwrap();let token=host.register_launch("fixture.jar").unwrap();let _process=Process(Command::new("java").args(["-cp",&classpath,"JavaExtensionFixture","-p",&host.address.port().to_string(),"-f","fixture.jar","-c",&token]).spawn().unwrap());
    let deadline=Instant::now()+Duration::from_secs(10);while !matches!(events.recv_timeout(Duration::from_millis(100)),Ok(HostEvent::Connected{..})){assert!(Instant::now()<deadline,"Java extension did not authenticate");}
    let mut random=[0;8];getrandom::fill(&mut random).unwrap();let directory=std::env::temp_dir().join(format!("gearth-java-nitro-{}",u64::from_ne_bytes(random)));let mut options=WebOptions::new("127.0.0.1:0".parse().unwrap(),directory.join("ca"));options.extensions=Some(host.clone());options.packet_info=PacketInfoManager::new(NITRO_REVISION,vec![PacketInfo {header:77,name:Some("TestOutgoing".into()),hash:None,structure:Some("i".into()),direction:Direction::ToServer,source:"fixture".into()},PacketInfo {header:91,name:Some("TestInjection".into()),hash:None,structure:Some("i".into()),direction:Direction::ToServer,source:"fixture".into()}]);let (mut proxy,_)=WebProxy::start(options).unwrap();
    let runtime=tokio::runtime::Runtime::new().unwrap();runtime.block_on(async{
        use tokio::io::{AsyncReadExt,AsyncWriteExt};let server=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=server.local_addr().unwrap();let (ready,wait)=tokio::sync::oneshot::channel();
        let upstream=tokio::spawn(async move{let (stream,_)=server.accept().await.unwrap();let mut socket=accept_async(stream).await.unwrap();for (header,value) in [(4000,0),(91,17)]{let message=socket.next().await.unwrap().unwrap();let mut packet=Packet::from_bytes(message.into_data().to_vec()).unwrap();assert_eq!(packet.header(),header);assert_eq!(packet.read_i32().unwrap(),value);}ready.send(()).unwrap();for expected in [6,9]{let message=socket.next().await.unwrap().unwrap();let mut packet=Packet::from_bytes(message.into_data().to_vec()).unwrap();assert_eq!(packet.header(),77);assert_eq!(packet.read_i32().unwrap(),expected);}let mut packet=Packet::new(78);packet.put_i32(5).unwrap();socket.send(Message::Binary(packet.bytes().to_vec().into())).await.unwrap();let _=socket.next().await;});
        let mut tunnel=tokio::net::TcpStream::connect(proxy.address).await.unwrap();tunnel.write_all(format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()).await.unwrap();let mut response=Vec::new();tokio::time::timeout(Duration::from_secs(5),async{while !response.ends_with(b"\r\n\r\n"){assert!(response.len()<8192);let mut byte=[0];tunnel.read_exact(&mut byte).await.unwrap();response.push(byte[0]);}}).await.unwrap();assert!(response.starts_with(b"HTTP/1.1 200"));let (mut client,_)=client_async(format!("ws://{address}/game"),tunnel).await.unwrap();let mut hello=Packet::new(4000);hello.put_i32(0).unwrap();client.send(Message::Binary(hello.bytes().to_vec().into())).await.unwrap();tokio::time::timeout(Duration::from_secs(5),wait).await.unwrap().unwrap();
        for value in [5,13,8]{let mut packet=Packet::new(77);packet.put_i32(value).unwrap();client.send(Message::Binary(packet.bytes().to_vec().into())).await.unwrap();}let reply=tokio::time::timeout(Duration::from_secs(5),client.next()).await.unwrap().unwrap().unwrap();let mut packet=Packet::from_bytes(reply.into_data().to_vec()).unwrap();assert_eq!(packet.header(),78);assert_eq!(packet.read_i32().unwrap(),7);client.close(None).await.unwrap();upstream.await.unwrap();
    });proxy.stop();host.stop();drop(proxy);assert!(directory.starts_with(std::env::temp_dir()));let _=std::fs::remove_file(directory.join("ca/gearth-proxy-key.pem"));let _=std::fs::remove_file(directory.join("ca/gearth-proxy-cert.pem"));let _=std::fs::remove_dir(directory.join("ca"));let _=std::fs::remove_dir(directory);
}
