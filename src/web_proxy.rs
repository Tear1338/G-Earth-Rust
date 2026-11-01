//! HTTP/TLS proxy and Nitro WebSocket packet pipeline. No OS proxy/trust changes.
use crate::{nitro::{Hotels,Modifier,Decoded},extension_host::{ConnectionDetails,ExtensionHost},packet::{Direction,FrameDecoder,Message,Packet,PacketFormat},packet_info::PacketInfoManager,relay::Event,rules::Rules,web_ca::ProxyIdentity};
use hudsucker::{futures::{Sink,SinkExt,Stream,StreamExt},hyper::{Request,Response,Uri,StatusCode},rustls::{self,crypto::aws_lc_rs,pki_types::CertificateDer},tokio_tungstenite::{Connector,tungstenite::{Message as WsMessage,Error as WsError}},Body,HttpContext,HttpHandler,RequestOrResponse,Proxy,WebSocketContext,WebSocketHandler};
use std::{collections::HashMap,io,net::{SocketAddr,TcpListener},path::PathBuf,sync::{Arc,Mutex,atomic::{AtomicBool,AtomicI32,AtomicUsize,Ordering},mpsc::{self,Receiver,SyncSender}},thread::{self,JoinHandle},time::Duration};
use tokio::sync::{mpsc as asynchronous,oneshot,watch,Notify};
pub const NITRO_REVISION:&str="PRODUCTION-201611291003-338511768";
const MAX_QUEUED:usize=32*1024*1024;
#[derive(Clone)]
pub struct WebOptions {pub listen:SocketAddr,pub identity_directory:PathBuf,pub packet_info:PacketInfoManager,pub extensions:Option<Arc<ExtensionHost>>,pub extra_roots:Vec<Vec<u8>>,pub websocket_urls:Vec<String>,pub hotels:Hotels}
impl WebOptions {pub fn new(listen:SocketAddr,identity_directory:PathBuf)->Self{Self {listen,identity_directory,packet_info:PacketInfoManager::default(),extensions:None,extra_roots:Vec::new(),websocket_urls:Vec::new(),hotels:Hotels::beta29()}}}
#[derive(Clone,PartialEq,Eq,Hash)]
struct PeerKey {client:SocketAddr,uri:String}
struct Peer {key:PeerKey,modifier:tokio::sync::Mutex<Modifier>,active:AtomicBool,ready:AtomicBool,closed:AtomicBool,notify:Notify,queued:AtomicUsize,finished:AtomicUsize,senders:[asynchronous::Sender<Packet>;2],receivers:Mutex<[Option<asynchronous::Receiver<Packet>>;2]>,stop:watch::Sender<bool>}
impl Peer {
    fn new(key:PeerKey,modifier:Modifier)->Self{let (out,out_rx)=asynchronous::channel(128);let (incoming,in_rx)=asynchronous::channel(128);let (stop,_)=watch::channel(false);Self {key,modifier:tokio::sync::Mutex::new(modifier),active:AtomicBool::new(false),ready:AtomicBool::new(false),closed:AtomicBool::new(false),notify:Notify::new(),queued:AtomicUsize::new(0),finished:AtomicUsize::new(0),senders:[out,incoming],receivers:Mutex::new([Some(out_rx),Some(in_rx)]),stop}}
    fn enqueue(&self,direction:Direction,packet:Packet)->io::Result<()> {
        if !self.active.load(Ordering::Acquire)||self.closed.load(Ordering::Acquire){return Err(io::Error::new(io::ErrorKind::NotConnected,"no active Nitro client"));}
        if packet.format()!=PacketFormat::EvaWire{return Err(io::Error::other("Nitro injection requires EVA_WIRE"));}
        let bytes=packet.bytes().len();self.queued.try_update(Ordering::AcqRel,Ordering::Acquire,|n|n.checked_add(bytes).filter(|n|*n<=MAX_QUEUED)).map_err(|_|io::Error::new(io::ErrorKind::WouldBlock,"Nitro injection byte budget exceeded"))?;
        if self.senders[side(direction)].try_send(packet).is_err(){self.queued.fetch_sub(bytes,Ordering::AcqRel);return Err(io::Error::new(io::ErrorKind::WouldBlock,"Nitro injection queue unavailable"));}Ok(())
    }
}
fn side(direction:Direction)->usize{if direction==Direction::ToServer{0}else{1}}
struct Shared {options:WebOptions,hartico_key:Mutex<Option<[u8;24]>>,peers:Mutex<HashMap<PeerKey,Arc<Peer>>>,active:Mutex<Option<Arc<Peer>>>,rules:Mutex<Rules>,pipeline:Mutex<()>,events:SyncSender<Event>,index:AtomicI32,stop:AtomicBool}
impl Shared {
    fn peer(&self,key:PeerKey)->io::Result<Arc<Peer>>{let mut peers=self.peers.lock().map_err(|_|io::Error::other("web peer lock poisoned"))?;if let Some(peer)=peers.get(&key){return Ok(peer.clone());}if peers.len()>=128{return Err(io::Error::other("too many pending WebSocket connections"));}let kind=self.options.hotels.find(&key.uri).map(|h|h.kind.clone()).unwrap_or(crate::nitro::HotelKind::Plain);let modifier=if kind==crate::nitro::HotelKind::Hartico{Modifier::Hartico(crate::nitro_assets::Hartico::new(self.hartico_key.lock().map_err(|_|io::Error::other("Hartico asset lock poisoned"))?.ok_or_else(||io::Error::other("Hartico logo key is unavailable; reload the hotel assets before connecting"))?))}else{Modifier::new(&kind)?};let peer=Arc::new(Peer::new(key.clone(),modifier));peers.insert(key,peer.clone());Ok(peer)}
    fn close(&self,peer:&Peer){if peer.closed.swap(true,Ordering::AcqRel){return;}peer.stop.send_replace(true);peer.notify.notify_waiters();if let Ok(mut active)=self.active.lock(){if active.as_ref().is_some_and(|p|p.key==peer.key){*active=None;if let Some(host)=&self.options.extensions{host.end_connection();}let _=self.events.try_send(Event::Disconnected);}}}
    fn finish(&self,peer:&Peer){self.close(peer);if peer.finished.fetch_add(1,Ordering::AcqRel)==1{if let Ok(mut peers)=self.peers.lock(){peers.remove(&peer.key);}}}
    fn close_all(&self){let peers=self.peers.lock().map(|p|p.values().cloned().collect::<Vec<_>>()).unwrap_or_default();for peer in peers{self.close(&peer);}}
    fn active(&self)->Option<Arc<Peer>>{self.active.lock().ok()?.clone().filter(|p|p.ready.load(Ordering::Acquire)&&!p.closed.load(Ordering::Acquire))}
    async fn activate(self:&Arc<Self>,peer:&Arc<Peer>,uri:&Uri)->io::Result<()> {
        {let mut active=self.active.lock().map_err(|_|io::Error::other("web active lock poisoned"))?;if peer.closed.load(Ordering::Acquire)||self.stop.load(Ordering::Acquire){return Err(io::Error::new(io::ErrorKind::Interrupted,"Nitro connection already closed"));}if active.as_ref().is_some_and(|p|p.key!=peer.key){return Err(io::Error::other("another Nitro client is already active"));}*active=Some(peer.clone());peer.active.store(true,Ordering::Release);}
        let mut database=self.options.packet_info.clone();
        if database.entries().is_empty()&&self.options.extensions.is_some(){
            let _=self.events.try_send(Event::Status("Loading Nitro packet identifiers...".into()));
            match tokio::task::spawn_blocking(||PacketInfoManager::fetch_sulek(NITRO_REVISION,false)).await{
                Ok(Ok(info))=>{let _=self.events.try_send(Event::PacketIdentifiers(info.clone()));database=info;},
                Ok(Err(e))=>{let _=self.events.try_send(Event::Status(format!("Nitro connected without packet names: {e}")));},
                Err(e)=>return Err(io::Error::other(e.to_string())),
            }
        }
        if peer.closed.load(Ordering::Acquire)||self.stop.load(Ordering::Acquire){return Err(io::Error::new(io::ErrorKind::Interrupted,"Nitro connection stopped"));}
        if let Some(host)=&self.options.extensions{host.start_connection(ConnectionDetails {host:uri.host().unwrap_or("").into(),port:uri.port_u16().unwrap_or(if matches!(uri.scheme_str(),Some("https"|"wss")){443}else{80}),version:NITRO_REVISION.into(),identifier:"HTML5".into(),client_type:"NITRO".into(),packets:database})?;}
        peer.ready.store(true,Ordering::Release);peer.notify.notify_waiters();let _=self.events.try_send(Event::Connected(format!("Nitro {}",uri.host().unwrap_or(""))));Ok(())
    }
    async fn packet(self:&Arc<Self>,direction:Direction,packet:Packet,injected:bool)->io::Result<Option<Packet>> {
        let state=self.clone();tokio::task::spawn_blocking(move||{
            let _serial=state.pipeline.lock().map_err(|_|io::Error::other("Nitro pipeline lock poisoned"))?;
            let mut message=Message {packet,direction,index:state.index.fetch_add(1,Ordering::Relaxed),blocked:false};
            if !injected{state.rules.lock().map_err(|_|io::Error::other("Nitro rule lock poisoned"))?.apply(&mut message);if let Some(host)=&state.options.extensions{host.intercept(&mut message)?;}}
            let output=if message.blocked{None}else{Some(message.packet.clone())};let _=state.events.try_send(Event::Packet(message));Ok(output)
        }).await.map_err(|e|io::Error::other(e.to_string()))?
    }
}
#[derive(Clone)] struct Handler(Arc<Shared>,bool);
impl HttpHandler for Handler {
    async fn handle_request(&mut self,_ctx:&HttpContext,mut request:Request<Body>)->RequestOrResponse {
        self.1=request.uri().host()==Some("images.hartico.tv")&&request.uri().path()=="/cosmos/img/logos/logo.png";
        if self.1 {for name in ["if-none-match","if-modified-since","accept-encoding"]{request.headers_mut().remove(name);}}
        request.into()
    }
    async fn handle_response(&mut self,_ctx:&HttpContext,response:Response<Body>)->Response<Body> {
        if !self.1||response.status()!=StatusCode::OK{return response;}
        use http_body_util::BodyExt;
        let (parts,mut body)=response.into_parts();let mut bytes=Vec::new();let result:io::Result<()>=async {while let Some(frame)=body.frame().await {let frame=frame.map_err(io::Error::other)?;if let Ok(data)=frame.into_data(){if bytes.len()+data.len()>16*1024*1024{return Err(io::Error::other("Hartico logo response exceeds 16 MiB"));}bytes.extend_from_slice(&data);}}Ok(())}.await;
        if let Err(e)=result {let _=self.0.events.try_send(Event::Error(e.to_string()));return Response::builder().status(StatusCode::BAD_GATEWAY).body(Body::from("Hotel asset could not be read")).unwrap();}
        match crate::nitro_assets::hartico_key(&bytes){Ok(key)=>{if let Ok(mut target)=self.0.hartico_key.lock(){*target=Some(key);}},Err(e)=>{let _=self.0.events.try_send(Event::Error(format!("Hartico key extraction failed: {e}")));}}
        Response::from_parts(parts,Body::from(bytes))
    }

    async fn should_intercept_connect(&mut self,_ctx:&HttpContext,_request:&Request<Body>)->bool{!self.0.stop.load(Ordering::Acquire)}
}
impl WebSocketHandler for Handler {
    async fn handle_websocket(self,ctx:WebSocketContext,mut stream:impl Stream<Item=Result<WsMessage,WsError>>+Unpin+Send+'static,mut sink:impl Sink<WsMessage,Error=WsError>+Unpin+Send+'static){
        let (direction,key,uri)=match ctx {WebSocketContext::ClientToServer {src,dst,..}=>(Direction::ToServer,PeerKey {client:src,uri:dst.to_string()},dst),WebSocketContext::ServerToClient {src,dst,..}=>(Direction::ToClient,PeerKey {client:dst,uri:src.to_string()},src)};
        let peer=match self.0.peer(key){Ok(p)=>p,Err(e)=>{let _=self.0.events.try_send(Event::Error(e.to_string()));let _=sink.close().await;return;}};
        let receiver=peer.receivers.lock().ok().and_then(|mut r|r[side(direction)].take());let Some(mut injections)=receiver else{self.0.close(&peer);return;};let mut stopping=peer.stop.subscribe();let mut tick=tokio::time::interval(Duration::from_millis(20));let mut decoder=FrameDecoder::default();let mut decided=false;
        let result:io::Result<()> = async {
            loop {
                if self.0.stop.load(Ordering::Acquire)||peer.closed.load(Ordering::Acquire){break;}
                tokio::select! {
                    _=stopping.changed()=>break,
                    _=tick.tick(), if direction==Direction::ToServer&&peer.ready.load(Ordering::Acquire)=>{
                        if direction==Direction::ToServer&&peer.ready.load(Ordering::Acquire){if let Some(host)=&self.0.options.extensions{for (direction,packet) in host.take_injections(){peer.enqueue(direction,packet)?;}}}
                    },
                    packet=injections.recv()=>{let Some(packet)=packet else{break;};peer.queued.fetch_sub(packet.bytes().len(),Ordering::AcqRel);let mut modifier=peer.modifier.lock().await;if let Some(packet)=self.0.packet(direction,packet,true).await?{let bytes=modifier.encode(direction,packet.bytes().to_vec())?;sink.send(WsMessage::Binary(bytes.into())).await.map_err(io::Error::other)?;}},
                    message=stream.next()=>{
                        let Some(message)=message else{break;};let message=message.map_err(io::Error::other)?;
                        if let WsMessage::Binary(bytes)=message {
                            if direction==Direction::ToServer&&!decided {
                                decided=true;let url=uri.to_string();let configured=self.0.options.hotels.find(&url).is_some()||self.0.options.websocket_urls.iter().any(|u|{let url=url.split('?').next().unwrap_or(&url);match u.strip_suffix('*'){Some(prefix)=>url.starts_with(prefix),None=>u==url}});
                                let hello=Packet::from_bytes(bytes.to_vec()).is_ok_and(|p|p.header()==4000);
                                if configured||hello{self.0.activate(&peer,&uri).await?;}
                            }
                            if peer.active.load(Ordering::Acquire){
                                while !peer.ready.load(Ordering::Acquire)&&!peer.closed.load(Ordering::Acquire){let notified=peer.notify.notified();if peer.ready.load(Ordering::Acquire)||peer.closed.load(Ordering::Acquire){break;}notified.await;}
                                if peer.closed.load(Ordering::Acquire){break;}
                                let mut modifier=peer.modifier.lock().await;
                                match modifier.decode(direction,bytes.to_vec())? {
                                    Decoded::Bypass(bytes)=>sink.send(WsMessage::Binary(bytes.into())).await.map_err(io::Error::other)?,
                                    Decoded::PacketBytes(bytes)=>for chunk in bytes.chunks(65536){decoder.push(chunk).map_err(io::Error::other)?;while let Some(packet)=decoder.next_packet().map_err(io::Error::other)?{if let Some(packet)=self.0.packet(direction,packet,false).await?{let bytes=modifier.encode(direction,packet.bytes().to_vec())?;sink.send(WsMessage::Binary(bytes.into())).await.map_err(io::Error::other)?;}}},
                                }
                            }else{sink.send(WsMessage::Binary(bytes)).await.map_err(io::Error::other)?;}
                        }else{let close=message.is_close();sink.send(message).await.map_err(io::Error::other)?;if close{break;}}
                    },
                }
            }Ok(())
        }.await;
        if let Err(e)=result{if !self.0.stop.load(Ordering::Acquire)&&!peer.closed.load(Ordering::Acquire){let _=self.0.events.try_send(Event::Error(e.to_string()));}}self.0.finish(&peer);let _=sink.close().await;
    }
}
pub struct WebProxy {state:Arc<Shared>,stop:Option<oneshot::Sender<()>>,worker:Option<JoinHandle<()>>,pub address:SocketAddr,pub certificate_path:PathBuf,pub certificate_der:Vec<u8>}
impl WebProxy {
    pub fn start(options:WebOptions)->io::Result<(Self,Receiver<Event>)>{
        if !options.listen.ip().is_loopback(){return Err(io::Error::other("HTTP proxy must bind loopback"));}
        let identity=ProxyIdentity::ensure(&options.identity_directory)?;let ca=identity.authority()?;let listener=TcpListener::bind(options.listen)?;let address=listener.local_addr()?;listener.set_nonblocking(true)?;
        let (events,receiver)=mpsc::sync_channel(2048);let state=Arc::new(Shared {options,hartico_key:Mutex::new(None),peers:Mutex::new(HashMap::new()),active:Mutex::new(None),rules:Mutex::new(Rules::default()),pipeline:Mutex::new(()),events,index:AtomicI32::new(0),stop:AtomicBool::new(false)});
        let actor=state.clone();let (stop,shutdown)=oneshot::channel();let (ready,started)=mpsc::sync_channel(1);
        let worker=thread::spawn(move||{let result=(||->io::Result<()>{let runtime=tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;runtime.block_on(async{
            let provider=aws_lc_rs::default_provider();let _=provider.clone().install_default();let mut roots=rustls::RootCertStore::empty();roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());for der in &actor.options.extra_roots{roots.add(CertificateDer::from(der.clone())).map_err(io::Error::other)?;}
            let tls=rustls::ClientConfig::builder_with_provider(Arc::new(provider)).with_safe_default_protocol_versions().map_err(io::Error::other)?.with_root_certificates(roots).with_no_client_auth();
            let connector=hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls.clone()).https_or_http().enable_http1().build();let listener=tokio::net::TcpListener::from_std(listener)?;
            let proxy=Proxy::builder().with_listener(listener).with_ca(ca).with_http_connector(connector).with_websocket_connector(Connector::Rustls(Arc::new(tls))).with_http_handler(Handler(actor.clone(),false)).with_websocket_handler(Handler(actor.clone(),false)).build().map_err(io::Error::other)?;
            let _=ready.send(());let _=actor.events.try_send(Event::Listening(address));tokio::select!{result=proxy.start()=>result.map_err(io::Error::other),_=shutdown=>Ok(())}
        })})();if let Err(e)=result{let _=actor.events.try_send(Event::Error(e.to_string()));}actor.close_all();});
        let mut proxy=Self {state,stop:Some(stop),worker:Some(worker),address,certificate_path:identity.certificate_path,certificate_der:identity.certificate_der};
        if started.recv_timeout(Duration::from_secs(5)).is_err(){proxy.stop();return Err(io::Error::other("HTTP proxy initialization failed; check TLS configuration"));}Ok((proxy,receiver))
    }
    pub fn connected(&self)->bool{self.state.active().is_some()}
    pub fn inject(&self,direction:Direction,packet:Packet)->io::Result<()>{self.state.active().ok_or_else(||io::Error::new(io::ErrorKind::NotConnected,"no Nitro client connected"))?.enqueue(direction,packet)}
    pub fn set_rules(&self,rules:Rules)->io::Result<()>{*self.state.rules.lock().map_err(|_|io::Error::other("Nitro rule lock poisoned"))?=rules;Ok(())}
    pub fn stop(&mut self){self.state.stop.store(true,Ordering::Release);self.state.close_all();if let Some(stop)=self.stop.take(){let _=stop.send(());}if let Some(worker)=self.worker.take(){let _=worker.join();}}
}
impl Drop for WebProxy{fn drop(&mut self){self.stop();}}
