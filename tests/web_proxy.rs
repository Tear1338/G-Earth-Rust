#![cfg(feature="web")]
use gearth_rust::{packet::{Direction,Packet},relay::Event,rules::{Rules,Rule,Action},web_proxy::{WebOptions,WebProxy},web_ca::ProxyIdentity};
use hudsucker::{futures::{SinkExt,StreamExt},hyper::header::SEC_WEBSOCKET_KEY,tokio_tungstenite::{accept_async,client_async,tungstenite::{client::IntoClientRequest,Message as WsMessage}}};
use std::{io::{Read,Write},net::{TcpListener,TcpStream},path::PathBuf,time::{Duration,Instant}};
struct Directory(PathBuf);
impl Directory{fn new()->Self{let mut bytes=[0;8];getrandom::fill(&mut bytes).unwrap();let path=std::env::temp_dir().join(format!("gearth-web-test-{}",u64::from_ne_bytes(bytes)));std::fs::create_dir(&path).unwrap();Self(path)}}
impl Drop for Directory{fn drop(&mut self){if let (Ok(path),Ok(temp))=(self.0.canonicalize(),std::env::temp_dir().canonicalize()){if path.starts_with(temp)&&path.file_name().is_some_and(|n|n.to_string_lossy().starts_with("gearth-web-test-")){let _=std::fs::remove_dir_all(path);}}}}
fn packet(header:u16,value:i32)->Packet{let mut p=Packet::new(header);p.put_i32(value).unwrap();p}
#[test] fn identity_is_private_persistent_and_never_requires_global_trust(){let dir=Directory::new();let path=dir.0.join("ca");let first=ProxyIdentity::ensure(&path).unwrap();let second=ProxyIdentity::ensure(&path).unwrap();assert_eq!(first.certificate_der,second.certificate_der);assert!(first.authority().is_ok());assert_eq!(std::fs::read_dir(path).unwrap().count(),2);}
#[test] fn forwards_plain_http_and_stops_without_external_network(){
    let dir=Directory::new();let server=TcpListener::bind("127.0.0.1:0").unwrap();let remote=server.local_addr().unwrap();let worker=std::thread::spawn(move||{let (mut stream,_)=server.accept().unwrap();stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();let mut bytes=[0;4096];stream.read(&mut bytes).unwrap();stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello").unwrap();});
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
