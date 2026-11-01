//! One lifecycle for Unity's browser asset proxy and TLS communicator.
use crate::{packet::{Direction,Packet},relay::Event,rules::Rules,unity_assets::UnityAssets,unity_server::{UnityOptions,UnityServer},web_proxy::{WebOptions,WebProxy}};
use std::{io,path::PathBuf,sync::{Arc,atomic::{AtomicBool,Ordering},mpsc::{self,Receiver}},thread::{self,JoinHandle},time::Duration};
pub struct UnityConnection {http:WebProxy,communicator:UnityServer,forward_stop:Arc<AtomicBool>,forwarder:Option<JoinHandle<()>>,pub address:std::net::SocketAddr}
impl UnityConnection {
    pub fn start(mut http:WebOptions,communicator:UnityOptions,cache_directory:PathBuf)->io::Result<(Self,Receiver<Event>)> {
        if http.identity_directory!=communicator.identity_directory{return Err(io::Error::other("Unity proxy and communicator must use the same public certificate"));}let (server,unity_events)=UnityServer::start(communicator)?;http.unity=Some(UnityAssets {websocket_port:server.address.port(),token:server.token().into(),cache_directory});http.detect_nitro=false;http.hotels=crate::nitro::Hotels::default();http.websocket_urls.clear();http.extensions=None;http.allow_city_helper=false;
        let (proxy,http_events)=WebProxy::start(http)?;let address=proxy.address;let (sender,events)=mpsc::sync_channel(2048);let forward_stop=Arc::new(AtomicBool::new(false));let stopping=forward_stop.clone();let forwarder=thread::spawn(move||{while !stopping.load(Ordering::Acquire){for event in unity_events.try_iter().take(512).chain(http_events.try_iter().take(128)){let _=sender.try_send(event);}thread::park_timeout(Duration::from_millis(10));}});
        Ok((Self {http:proxy,communicator:server,forward_stop,forwarder:Some(forwarder),address},events))
    }
    pub fn connected(&self)->bool{self.communicator.connected()}
    pub fn inject(&self,direction:Direction,packet:Packet)->io::Result<()>{self.communicator.inject(direction,packet)}
    pub fn set_rules(&self,rules:Rules)->io::Result<()>{self.communicator.set_rules(rules)}
    pub fn stop(&mut self){self.communicator.stop();self.http.stop();self.forward_stop.store(true,Ordering::Release);if let Some(forwarder)=self.forwarder.take(){forwarder.thread().unpark();let _=forwarder.join();}}
}
impl Drop for UnityConnection {fn drop(&mut self){self.stop();}}
