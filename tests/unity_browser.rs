#![cfg(feature="web")]
use gearth_rust::{packet::{Direction,Packet},relay::Event,rules::{Action,Rule,Rules},unity_assets::{framework,UnityAssets},unity_server::{UnityOptions,UnityServer},unity_wasm};
use std::{path::PathBuf,process::{Child,Command},time::{Duration,Instant}};
struct Process(Child);impl Drop for Process{fn drop(&mut self){let _=self.0.kill();let _=self.0.wait();}}
struct Directory(PathBuf);impl Drop for Directory {fn drop(&mut self){for file in ["client.wasm","framework.js","ca/gearth-proxy-cert.pem","ca/gearth-proxy-key.pem"]{let _=std::fs::remove_file(self.0.join(file));}let _=std::fs::remove_dir(self.0.join("ca"));let _=std::fs::remove_dir(&self.0);}}
fn packet(header:u16,value:i32)->Packet{let mut packet=Packet::new(header);packet.put_i32(value).unwrap();packet}
#[test]
#[ignore="requires Node with its native WebSocket implementation; run in web CI"]
fn real_browser_hooks_roundtrip_through_rust_without_touching_the_system_proxy(){
    let mut random=[0;16];getrandom::fill(&mut random).unwrap();let path=std::env::temp_dir().join(format!("gearth-unity-browser-{}",random.iter().map(|b|format!("{b:02x}")).collect::<String>()));std::fs::create_dir(&path).unwrap();let directory=Directory(path);let (mut server,events)=UnityServer::start(UnityOptions::new("127.0.0.1:0".parse().unwrap(),directory.0.join("ca"))).unwrap();server.set_rules(Rules {entries:vec![Rule {enabled:true,direction:Direction::ToServer,header:77,action:Action::Block},Rule {enabled:true,direction:Direction::ToServer,header:78,action:Action::Replace(packet(78,42))}]}).unwrap();
    let wasm=wat::parse_str(include_str!("fixtures/unity_hooks.wat")).unwrap();std::fs::write(directory.0.join("client.wasm"),unity_wasm::patch(&wasm).unwrap().bytes).unwrap();let assets=UnityAssets {websocket_port:server.address.port(),token:server.token().into(),cache_directory:directory.0.join("unused")};std::fs::write(directory.0.join("framework.js"),framework("TEST-UNITY-1",&assets,include_str!("fixtures/unity_framework.js")).unwrap()).unwrap();
    let node=std::env::var_os("GEARTH_NODE").unwrap_or_else(||"node".into());let mut process=Process(Command::new(node).arg("tests/unity_browser_runtime.mjs").arg(&directory.0).env("NODE_EXTRA_CA_CERTS",&server.certificate_path).spawn().unwrap());let deadline=Instant::now()+Duration::from_secs(25);let mut injected=false;let mut blocked=false;
    loop {for event in events.try_iter(){if let Event::Packet(message)=event {blocked|=message.packet.header()==77&&message.blocked;if message.packet.header()==90&&!injected{server.inject(Direction::ToServer,packet(79,99)).unwrap();server.inject(Direction::ToClient,packet(89,33)).unwrap();injected=true;}}}if let Some(status)=process.0.try_wait().unwrap(){assert!(status.success(),"browser fixture exited with {status}");break;}assert!(Instant::now()<deadline,"browser fixture timed out");std::thread::sleep(Duration::from_millis(5));}
    assert!(blocked&&injected);server.stop();
}
