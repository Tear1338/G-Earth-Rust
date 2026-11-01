#![cfg(feature="web")]
use gearth_rust::{packet::{Direction,Packet},relay::Event,rules::{Rules,Rule,Action},web_proxy::{WebOptions,WebProxy},web_ca::ProxyIdentity};
use hudsucker::{futures::{SinkExt,StreamExt},hyper::header::SEC_WEBSOCKET_KEY,tokio_tungstenite::{accept_async,client_async,tungstenite::{client::IntoClientRequest,Message as WsMessage}}};
use std::{io::{Read,Write},net::{TcpListener,TcpStream},path::PathBuf,time::{Duration,Instant}};
struct Directory(PathBuf);
async fn connect_tunnel(proxy:std::net::SocketAddr,remote:&str)->tokio::net::TcpStream{
    use tokio::io::{AsyncReadExt,AsyncWriteExt};
    let mut stream=tokio::net::TcpStream::connect(proxy).await.unwrap();stream.write_all(format!("CONNECT {remote} HTTP/1.1\r\nHost: {remote}\r\n\r\n").as_bytes()).await.unwrap();let mut response=Vec::new();tokio::time::timeout(Duration::from_secs(5),async{while !response.ends_with(b"\r\n\r\n"){assert!(response.len()<8192);let mut byte=[0];stream.read_exact(&mut byte).await.unwrap();response.push(byte[0]);}}).await.unwrap();assert!(String::from_utf8(response).unwrap().starts_with("HTTP/1.1 200"));stream
}
impl Directory{fn new()->Self{let mut bytes=[0;8];getrandom::fill(&mut bytes).unwrap();let path=std::env::temp_dir().join(format!("gearth-web-test-{}",u64::from_ne_bytes(bytes)));std::fs::create_dir(&path).unwrap();Self(path)}}
impl Drop for Directory{fn drop(&mut self){if let (Ok(path),Ok(temp))=(self.0.canonicalize(),std::env::temp_dir().canonicalize()){if path.starts_with(temp)&&path.file_name().is_some_and(|n|n.to_string_lossy().starts_with("gearth-web-test-")){let _=std::fs::remove_dir_all(path);}}}}
fn packet(header:u16,value:i32)->Packet{let mut p=Packet::new(header);p.put_i32(value).unwrap();p}
#[test] fn configured_hotel_bypasses_hubbe_prelude_and_then_processes_packets(){
    use gearth_rust::nitro::{Hotel,HotelKind,Hotels};
    let directory=Directory::new();let runtime=tokio::runtime::Runtime::new().unwrap();runtime.block_on(async{
        let server=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=server.local_addr().unwrap();let url=format!("ws://{address}/game");let mut options=WebOptions::new("127.0.0.1:0".parse().unwrap(),directory.0.join("ca"));options.hotels=Hotels {entries:vec![Hotel {name:"controlled Hubbe fixture".into(),websocket_urls:vec![format!("{url}*")],kind:HotelKind::HubbeSt}]};let (mut proxy,events)=WebProxy::start(options).unwrap();
        proxy.set_rules(Rules {entries:vec![Rule {enabled:true,direction:Direction::ToServer,header:77,action:Action::Block}]}).unwrap();
        let upstream=tokio::spawn(async move{let (stream,_)=server.accept().await.unwrap();let mut socket=accept_async(stream).await.unwrap();assert_eq!(socket.next().await.unwrap().unwrap().into_data().as_ref(),b"non-packet prelude");let bytes=socket.next().await.unwrap().unwrap().into_data();assert_eq!(Packet::from_bytes(bytes.to_vec()).unwrap().header(),78);socket.send(WsMessage::Binary(packet(88,1).bytes().to_vec().into())).await.unwrap();let _=socket.next().await;});
        let stream=connect_tunnel(proxy.address,&address.to_string()).await;let (mut client,_)=client_async(format!("{url}?session=fixture"),stream).await.unwrap();for bytes in [b"non-packet prelude".to_vec(),packet(77,0).bytes().to_vec(),packet(78,0).bytes().to_vec()]{client.send(WsMessage::Binary(bytes.into())).await.unwrap();}
        let message=tokio::time::timeout(Duration::from_secs(5),client.next()).await.unwrap().unwrap().unwrap();assert_eq!(Packet::from_bytes(message.into_data().to_vec()).unwrap().header(),88);client.close(None).await.unwrap();upstream.await.unwrap();assert!(events.try_iter().any(|e|matches!(e,Event::Packet(m) if m.packet.header()==77&&m.blocked)));proxy.stop();
    });
}
#[test] fn validates_both_tls_legs_and_routes_nitro_over_wss_without_changing_system_trust(){
    use hudsucker::{certificate_authority::CertificateAuthority,rustls::{self,crypto::aws_lc_rs,pki_types::CertificateDer},tokio_tungstenite::{client_async_tls_with_config,Connector}};
    let directory=Directory::new();let upstream_identity=ProxyIdentity::ensure(&directory.0.join("upstream-ca")).unwrap();let authority=upstream_identity.authority().unwrap();let mut options=WebOptions::new("127.0.0.1:0".parse().unwrap(),directory.0.join("proxy-ca"));options.extra_roots.push(upstream_identity.certificate_der.clone());let (mut proxy,_)=WebProxy::start(options).unwrap();
    let mut roots=rustls::RootCertStore::empty();roots.add(CertificateDer::from(proxy.certificate_der.clone())).unwrap();let client_tls=rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(aws_lc_rs::default_provider())).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
    let runtime=tokio::runtime::Runtime::new().unwrap();runtime.block_on(async{
        let server=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let port=server.local_addr().unwrap().port();let address=format!("localhost:{port}");let tls=authority.gen_server_config(&address.parse().unwrap()).await;
        let server=tokio::spawn(async move{let (stream,_)=server.accept().await.unwrap();let stream=tokio_rustls::TlsAcceptor::from(tls).accept(stream).await.unwrap();let mut socket=accept_async(stream).await.unwrap();let message=socket.next().await.unwrap().unwrap();assert_eq!(Packet::from_bytes(message.into_data().to_vec()).unwrap().header(),4000);socket.send(WsMessage::Binary(packet(88,17).bytes().to_vec().into())).await.unwrap();let _=socket.next().await;});
        let stream=connect_tunnel(proxy.address,&address).await;let (mut client,_)=client_async_tls_with_config(format!("wss://{address}/game"),stream,None,Some(Connector::Rustls(std::sync::Arc::new(client_tls)))).await.unwrap();
        client.send(WsMessage::Binary(packet(4000,0).bytes().to_vec().into())).await.unwrap();let message=tokio::time::timeout(Duration::from_secs(5),client.next()).await.unwrap().unwrap().unwrap();assert_eq!(Packet::from_bytes(message.into_data().to_vec()).unwrap().header(),88);client.close(None).await.unwrap();server.await.unwrap();
    });proxy.stop();
}
#[test] fn identity_is_private_persistent_and_never_requires_global_trust(){let dir=Directory::new();let path=dir.0.join("ca");let first=ProxyIdentity::ensure(&path).unwrap();let second=ProxyIdentity::ensure(&path).unwrap();assert_eq!(first.certificate_der,second.certificate_der);assert!(first.authority().is_ok());assert_eq!(std::fs::read_dir(path).unwrap().count(),2);}
#[test] fn forwards_plain_http_and_stops_without_external_network(){
    let dir=Directory::new();let server=TcpListener::bind("127.0.0.1:0").unwrap();let remote=server.local_addr().unwrap();let worker=std::thread::spawn(move||{let (mut stream,_)=server.accept().unwrap();stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();let mut bytes=Vec::new();while !bytes.ends_with(b"\r\n\r\n"){assert!(bytes.len()<8192);let mut byte=[0];stream.read_exact(&mut byte).unwrap();bytes.push(byte[0]);}stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello").unwrap();});
    let (mut proxy,_)=WebProxy::start(WebOptions::new("127.0.0.1:0".parse().unwrap(),dir.0.join("ca"))).unwrap();let mut client=TcpStream::connect(proxy.address).unwrap();client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();write!(client,"GET http://{remote}/test HTTP/1.1\r\nHost: {remote}\r\nConnection: close\r\n\r\n").unwrap();let mut response=String::new();client.read_to_string(&mut response).unwrap();assert!(response.starts_with("HTTP/1.1 200"));assert!(response.ends_with("hello"));worker.join().unwrap();let start=Instant::now();proxy.stop();assert!(start.elapsed()<Duration::from_secs(2));
}
#[test] fn nitro_websocket_supports_block_replace_and_bidirectional_injection(){
    let dir=Directory::new();let (mut proxy,events)=WebProxy::start(WebOptions::new("127.0.0.1:0".parse().unwrap(),dir.0.join("ca"))).unwrap();proxy.set_rules(Rules {entries:vec![Rule {enabled:true,direction:Direction::ToServer,header:77,action:Action::Block},Rule {enabled:true,direction:Direction::ToServer,header:78,action:Action::Replace(packet(78,42))}]}).unwrap();
    let mut blocked_seen=false;let rt=tokio::runtime::Runtime::new().unwrap();rt.block_on(async{
        let server=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let remote=server.local_addr().unwrap();let upstream=tokio::spawn(async move{let (stream,_)=server.accept().await.unwrap();let mut socket=accept_async(stream).await.unwrap();for (header,value) in [(4000,0),(78,42),(79,99)]{let message=socket.next().await.unwrap().unwrap();let mut p=Packet::from_bytes(message.into_data().to_vec()).unwrap();assert_eq!(p.header(),header);assert_eq!(p.read_i32().unwrap(),value);}
            socket.send(WsMessage::Binary(packet(88,17).bytes().to_vec().into())).await.unwrap();let message=socket.next().await.unwrap().unwrap();let p=Packet::from_bytes(message.into_data().to_vec()).unwrap();assert_eq!(p.header(),90);
        });
        // The HTTP upgrade request uses the absolute upstream URI through the proxy.
        let mut stream=tokio::net::TcpStream::connect(proxy.address).await.unwrap();
        use tokio::io::{AsyncReadExt,AsyncWriteExt};
        stream.write_all(format!("CONNECT {remote} HTTP/1.1\r\nHost: {remote}\r\n\r\n").as_bytes()).await.unwrap();
        let mut response=Vec::new();tokio::time::timeout(Duration::from_secs(5),async{while !response.ends_with(b"\r\n\r\n"){assert!(response.len()<8192);let mut byte=[0];stream.read_exact(&mut byte).await.unwrap();response.push(byte[0]);}}).await.unwrap();assert!(String::from_utf8(response).unwrap().starts_with("HTTP/1.1 200"));
        let request=format!("ws://{remote}/game").into_client_request().unwrap();assert!(request.headers().contains_key(SEC_WEBSOCKET_KEY));
        let (mut client,_)=client_async(request,stream).await.unwrap();client.send(WsMessage::Binary(packet(4000,0).bytes().to_vec().into())).await.unwrap();client.send(WsMessage::Binary(packet(77,13).bytes().to_vec().into())).await.unwrap();client.send(WsMessage::Binary(packet(78,41).bytes().to_vec().into())).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5),async{let mut forwarded=false;loop{for event in events.try_iter(){if let Event::Packet(m)=event{blocked_seen|=m.packet.header()==77&&m.blocked;forwarded|=m.packet.header()==78;}}if proxy.connected()&&forwarded{break;}tokio::time::sleep(Duration::from_millis(5)).await;}}).await.unwrap();proxy.inject(Direction::ToServer,packet(79,99)).unwrap();
        let message=tokio::time::timeout(Duration::from_secs(5),client.next()).await.unwrap().unwrap().unwrap();let mut p=Packet::from_bytes(message.into_data().to_vec()).unwrap();assert_eq!(p.header(),88);assert_eq!(p.read_i32().unwrap(),17);
        proxy.inject(Direction::ToClient,packet(89,33)).unwrap();let message=tokio::time::timeout(Duration::from_secs(5),client.next()).await.unwrap().unwrap().unwrap();let mut p=Packet::from_bytes(message.into_data().to_vec()).unwrap();assert_eq!(p.header(),89);assert_eq!(p.read_i32().unwrap(),33);client.send(WsMessage::Binary(packet(90,1).bytes().to_vec().into())).await.unwrap();upstream.await.unwrap();
    });
    assert!(blocked_seen);proxy.stop();
}
