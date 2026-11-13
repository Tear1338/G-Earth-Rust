//! Authenticated loopback TLS communicator for the patched Unity WebGL client.
use crate::{
    extension_host::{ConnectionDetails, ExtensionHost},
    packet::{Direction, FrameDecoder, Message, Packet, PacketFormat, MAX_FRAME},
    packet_info::PacketInfoManager,
    relay::Event,
    rules::Rules,
    web_ca::ProxyIdentity,
};
use hudsucker::{
    certificate_authority::CertificateAuthority,
    futures::{SinkExt, StreamExt},
    tokio_tungstenite::{
        accept_hdr_async_with_config,
        tungstenite::{
            handshake::server::{ErrorResponse, Request, Response},
            protocol::WebSocketConfig,
            Message as WsMessage,
        },
    },
};
use std::{
    io,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::{
    sync::{mpsc as asynchronous, oneshot, watch, Semaphore},
    task::JoinSet,
};
const MAX_QUEUED: usize = 32 * 1024 * 1024;
type InjectionReceiver = asynchronous::Receiver<(Direction, Packet)>;
#[derive(Clone)]
pub struct UnityOptions {
    pub listen: SocketAddr,
    pub identity_directory: PathBuf,
    pub packet_info: PacketInfoManager,
    pub packet_safety: Option<Arc<Mutex<crate::packet_safety::PacketSafety>>>,
    pub admin_service: Option<Arc<Mutex<crate::admin_service::AdminService>>>,
    pub extensions: Option<Arc<ExtensionHost>>,
}
impl UnityOptions {
    pub fn new(listen: SocketAddr, identity_directory: PathBuf) -> Self {
        Self {
            listen,
            identity_directory,
            packet_info: PacketInfoManager::default(),
            packet_safety: None,
            admin_service: None,
            extensions: None,
        }
    }
}
struct Peer {
    ready: AtomicBool,
    closed: AtomicBool,
    extension_session: Mutex<Option<u64>>,
    schedule_metadata: Mutex<Option<(String, Arc<PacketInfoManager>)>>,
    queued: AtomicUsize,
    sender: asynchronous::Sender<(Direction, Packet)>,
    stop: watch::Sender<bool>,
}
impl Peer {
    fn enqueue(&self, direction: Direction, packet: Packet) -> io::Result<()> {
        self.enqueue_retaining(direction, packet)
            .map_err(|(error, _)| error)
    }
    fn enqueue_retaining(
        &self,
        direction: Direction,
        packet: Packet,
    ) -> Result<(), (io::Error, Packet)> {
        if !self.ready.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            return Err((
                io::Error::new(io::ErrorKind::NotConnected, "no active Unity client"),
                packet,
            ));
        }
        if packet.format() != PacketFormat::EvaWire {
            return Err((
                io::Error::other("Unity injection requires EVA_WIRE"),
                packet,
            ));
        }
        let bytes = packet.bytes().len();
        if self
            .queued
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count
                    .checked_add(bytes)
                    .filter(|count| *count <= MAX_QUEUED)
            })
            .is_err()
        {
            return Err((
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Unity injection byte budget exceeded",
                ),
                packet,
            ));
        }
        if let Err(error) = self.sender.try_send((direction, packet)) {
            self.queued.fetch_sub(bytes, Ordering::AcqRel);
            return Err(match error {
                asynchronous::error::TrySendError::Full((_, packet)) => (
                    io::Error::new(io::ErrorKind::WouldBlock, "Unity injection queue full"),
                    packet,
                ),
                asynchronous::error::TrySendError::Closed((_, packet)) => (
                    io::Error::new(io::ErrorKind::NotConnected, "Unity injection queue closed"),
                    packet,
                ),
            });
        }
        Ok(())
    }
}
/// Metadata bound to the exact initialized Unity peer.
pub struct UnityScheduleContext {
    peer: Arc<Peer>,
    pub version: String,
    pub packets: Arc<PacketInfoManager>,
}
struct State {
    options: UnityOptions,
    active: Mutex<Option<Arc<Peer>>>,
    rules: Mutex<Rules>,
    events: SyncSender<Event>,
    index: [AtomicI32; 2],
    stop: AtomicBool,
}
impl State {
    fn peer(&self) -> Option<Arc<Peer>> {
        self.active.lock().ok()?.clone().filter(|peer| {
            peer.ready.load(Ordering::Acquire) && !peer.closed.load(Ordering::Acquire)
        })
    }
    fn claim(&self) -> io::Result<(Arc<Peer>, InjectionReceiver)> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| io::Error::other("Unity active lock poisoned"))?;
        if self.stop.load(Ordering::Acquire) || active.is_some() {
            return Err(io::Error::other("Unity already has an attached browser"));
        }
        let (sender, receiver) = asynchronous::channel(128);
        let (stop, _) = watch::channel(false);
        let peer = Arc::new(Peer {
            ready: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            extension_session: Mutex::new(None),
            schedule_metadata: Mutex::new(None),
            queued: AtomicUsize::new(0),
            sender,
            stop,
        });
        *active = Some(peer.clone());
        Ok((peer, receiver))
    }
    fn finish(&self, peer: &Arc<Peer>) {
        peer.closed.store(true, Ordering::Release);
        peer.stop.send_replace(true);
        if let Ok(mut active) = self.active.lock() {
            if active
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, peer))
            {
                *active = None;
                if peer.ready.load(Ordering::Acquire) {
                    if let Some(host) = &self.options.extensions {
                        if let Ok(mut session) = peer.extension_session.lock() {
                            if let Some(epoch) = session.take() {
                                host.end_owned_connection(epoch);
                            }
                        }
                    }
                    let _ = self.events.try_send(Event::Disconnected);
                }
            }
        }
    }
    fn close(&self) {
        let peer = self.active.lock().ok().and_then(|active| active.clone());
        if let Some(peer) = peer {
            self.finish(&peer);
        }
    }
    fn initialize(&self, peer: &Arc<Peer>, revision: String, identifier: String) -> io::Result<()> {
        let active = self
            .active
            .lock()
            .map_err(|_| io::Error::other("Unity active lock poisoned"))?;
        if self.stop.load(Ordering::Acquire)
            || peer.closed.load(Ordering::Acquire)
            || !active
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, peer))
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Unity connection stopped",
            ));
        }
        let mut packets = self.options.packet_info.clone();
        packets.version = revision.clone();
        if let Some(safety) = &self.options.packet_safety {
            if let Ok(mut safety) = safety.lock() {
                safety.register_metadata(&revision, &packets);
            }
        }
        if let Some(host) = &self.options.extensions {
            let mut session = peer
                .extension_session
                .lock()
                .map_err(|_| io::Error::other("Unity extension session lock poisoned"))?;
            *session = Some(host.start_owned_connection(ConnectionDetails {
                host: String::new(),
                port: 0,
                version: revision.clone(),
                identifier: identifier.clone(),
                client_type: "UNITY".into(),
                packets: packets.clone(),
            })?);
        }
        self.index[0].store(0, Ordering::Release);
        self.index[1].store(0, Ordering::Release);
        if let Some(service) = &self.options.admin_service {
            if let Ok(mut service) = service.lock() {
                service.on_connect();
            }
        }
        *peer
            .schedule_metadata
            .lock()
            .map_err(|_| io::Error::other("Unity metadata lock poisoned"))? =
            Some((revision.clone(), Arc::new(packets.clone())));
        peer.ready.store(true, Ordering::Release);
        let _ = self.events.try_send(Event::PacketIdentifiers(packets));
        let _ = self.events.try_send(Event::Identified {
            version: revision,
            identifier,
        });
        let _ = self.events.try_send(Event::Connected("Unity WebGL".into()));
        Ok(())
    }
    async fn packet(
        self: &Arc<Self>,
        direction: Direction,
        packet: Packet,
        injected: bool,
        revision: Option<String>,
    ) -> io::Result<Option<Packet>> {
        let state = self.clone();
        tokio::task::spawn_blocking(move || {
            if state.stop.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Unity proxy stopped",
                ));
            }
            let side = if direction == Direction::ToServer {
                1
            } else {
                0
            };
            let mut message = Message {
                packet,
                direction,
                index: state.index[side].fetch_add(1, Ordering::Relaxed),
                blocked: false,
            };
            if !injected {
                if let (Some(safety), Some(revision)) =
                    (&state.options.packet_safety, revision.as_deref())
                {
                    if let Ok(mut safety) = safety.lock() {
                        safety.observe(revision, direction, message.packet.header());
                    }
                }
                if let Some(service) = &state.options.admin_service {
                    if let Ok(mut service) = service.lock() {
                        service.on_message(&mut message);
                    }
                }
                state
                    .rules
                    .lock()
                    .map_err(|_| io::Error::other("Unity rule lock poisoned"))?
                    .apply(&mut message);
                if let Some(host) = &state.options.extensions {
                    host.intercept(&mut message)?;
                }
            }
            let output = if message.blocked {
                None
            } else {
                Some(message.packet.clone())
            };
            let _ = state.events.try_send(Event::Packet(message));
            Ok(output)
        })
        .await
        .map_err(io::Error::other)?
    }
}
fn direction(byte: u8) -> io::Result<Direction> {
    match byte {
        0 => Ok(Direction::ToClient),
        1 => Ok(Direction::ToServer),
        _ => Err(io::Error::other("invalid Unity direction byte")),
    }
}
fn wire(direction: Direction, packet: &Packet) -> WsMessage {
    let mut bytes = Vec::with_capacity(packet.bytes().len() + 1);
    bytes.push(if direction == Direction::ToClient {
        0
    } else {
        1
    });
    bytes.extend(packet.bytes());
    WsMessage::Binary(bytes.into())
}
fn revision(bytes: &[u8]) -> io::Result<String> {
    if bytes.is_empty()
        || bytes.len() > 200
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(byte))
    {
        return Err(io::Error::other("invalid Unity revision"));
    }
    Ok(String::from_utf8(bytes.to_vec()).unwrap())
}
async fn session(
    state: Arc<State>,
    mut socket: hudsucker::tokio_tungstenite::WebSocketStream<
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    >,
) -> io::Result<()> {
    let (peer, mut injections) = state.claim()?;
    let mut stopped = peer.stop.subscribe();
    let mut revision_name = None;
    let mut decoders = [FrameDecoder::default(), FrameDecoder::default()];
    let mut prehello_bytes = 0;
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    let handshake = tokio::time::sleep(Duration::from_secs(15));
    tokio::pin!(handshake);
    let result:io::Result<()>=async {loop {if state.stop.load(Ordering::Acquire)||peer.closed.load(Ordering::Acquire){break;}tokio::select! {
        _=stopped.changed()=>break,
        _=&mut handshake,if !peer.ready.load(Ordering::Acquire)=>return Err(io::Error::new(io::ErrorKind::TimedOut,"Unity revision/hello timed out")),
        _=tick.tick(),if peer.ready.load(Ordering::Acquire)=>{if let Some(host)=&state.options.extensions {let epoch=peer.extension_session.lock().map_err(|_|io::Error::other("Unity extension session lock poisoned"))?.ok_or_else(||io::Error::other("Unity extension session missing"))?;host.forward_owned_injections(epoch,|direction,packet|peer.enqueue_retaining(direction,packet))?;}},
        injection=injections.recv()=>{let Some((direction,packet))=injection else{break;};peer.queued.fetch_sub(packet.bytes().len(),Ordering::AcqRel);if let Some(packet)=state.packet(direction,packet,true,None).await?{tokio::time::timeout(Duration::from_secs(5),socket.send(wire(direction,&packet))).await.map_err(io::Error::other)?.map_err(io::Error::other)?;}},
        message=socket.next()=>{let Some(message)=message else{break;};match message.map_err(io::Error::other)? {
            WsMessage::Binary(bytes)=>{if revision_name.is_none(){revision_name=Some(revision(&bytes)?);continue;}let (&prefix,payload)=bytes.split_first().ok_or_else(||io::Error::other("empty Unity frame"))?;let direction=direction(prefix)?;
                if !peer.ready.load(Ordering::Acquire){prehello_bytes+=payload.len();if direction!=Direction::ToServer||prehello_bytes>65536{return Err(io::Error::other("Unity requires an outgoing hello after its revision"));}}
                let decoder=&mut decoders[prefix as usize];for chunk in payload.chunks(65536){decoder.push(chunk).map_err(io::Error::other)?;while let Some(packet)=decoder.next_packet().map_err(io::Error::other)? {
                    if !peer.ready.load(Ordering::Acquire){if packet.header()!=4000{return Err(io::Error::other("Unity first outgoing packet must be hello 4000"));}let mut hello=packet.clone();hello.read_string().map_err(io::Error::other)?;let identifier=hello.read_string().map_err(io::Error::other)?;let actor=state.clone();let current=peer.clone();let revision=revision_name.clone().unwrap();tokio::task::spawn_blocking(move||actor.initialize(&current,revision,identifier)).await.map_err(io::Error::other)??;}
                    if let Some(packet)=state.packet(direction,packet,false,revision_name.clone()).await?{tokio::time::timeout(Duration::from_secs(5),socket.send(wire(direction,&packet))).await.map_err(io::Error::other)?.map_err(io::Error::other)?;}
                }}
            },
            WsMessage::Ping(_)=>socket.flush().await.map_err(io::Error::other)?,WsMessage::Pong(_)=>{},WsMessage::Close(_)=>break,_=>return Err(io::Error::other("Unity communicator requires binary messages")),
        }},
    }}Ok(())}.await;
    state.finish(&peer);
    let _ = tokio::time::timeout(Duration::from_millis(200), socket.close(None)).await;
    result
}
pub struct UnityServer {
    state: Arc<State>,
    worker: Option<JoinHandle<()>>,
    stop: Option<oneshot::Sender<()>>,
    pub address: SocketAddr,
    pub certificate_path: PathBuf,
    pub certificate_der: Vec<u8>,
    token: String,
}
impl UnityServer {
    pub fn start(options: UnityOptions) -> io::Result<(Self, Receiver<Event>)> {
        if !options.listen.ip().is_loopback() {
            return Err(io::Error::other("Unity communicator must bind loopback"));
        }
        let identity = ProxyIdentity::ensure(&options.identity_directory)?;
        let authority = identity.authority()?;
        let listener = TcpListener::bind(options.listen)?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let mut token_bytes = [0; 32];
        getrandom::fill(&mut token_bytes).map_err(|e| io::Error::other(e.to_string()))?;
        let token = token_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let (events, receiver) = mpsc::sync_channel(2048);
        let state = Arc::new(State {
            options,
            active: Mutex::new(None),
            rules: Mutex::new(Rules::default()),
            events,
            index: [AtomicI32::new(0), AtomicI32::new(0)],
            stop: AtomicBool::new(false),
        });
        let actor = state.clone();
        let (stop, mut shutdown) = oneshot::channel();
        let (ready, started) = mpsc::sync_channel(1);
        let secret = token.clone();
        let worker = thread::spawn(move || {
            let result = (|| -> io::Result<()> {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()?;
                let result=runtime.block_on(async {
            let config=authority.gen_server_config(&"localhost".parse().unwrap()).await;let acceptor=tokio_rustls::TlsAcceptor::from(config);let listener=tokio::net::TcpListener::from_std(listener)?;let permits=Arc::new(Semaphore::new(8));let mut tasks=JoinSet::new();let _=ready.send(());let _=actor.events.try_send(Event::Listening(address));
            loop {tokio::select! {_=&mut shutdown=>break,Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},connection=listener.accept()=>{let (stream,_)=connection?;let Ok(permit)=permits.clone().try_acquire_owned()else{continue;};let tls=acceptor.clone();let secret=secret.clone();let state=actor.clone();tasks.spawn(async move {let _permit=permit;let result:io::Result<()>=async {
                let tls=tokio::time::timeout(Duration::from_secs(5),tls.accept(stream)).await.map_err(io::Error::other)?.map_err(io::Error::other)?;let expected=format!("/?token={secret}");#[allow(clippy::result_large_err)] let callback=move|request:&Request,response:Response|->Result<Response,ErrorResponse>{let supplied=request.uri().path_and_query().map(|value|value.as_str()).unwrap_or("");let same=supplied.len()==expected.len()&&supplied.bytes().zip(expected.bytes()).fold(0u8,|difference,(a,b)|difference|(a^b))==0;if !same {return Err(Response::builder().status(403).body(Some("Unity communicator authentication required".into())).unwrap());}Ok(response)};
                let config=WebSocketConfig::default().max_message_size(Some(MAX_FRAME+65536)).max_frame_size(Some(MAX_FRAME+65536)).max_write_buffer_size(MAX_QUEUED);
                let socket=tokio::time::timeout(Duration::from_secs(5),accept_hdr_async_with_config(tls,callback,Some(config))).await.map_err(io::Error::other)?.map_err(io::Error::other)?;session(state.clone(),socket).await
            }.await;if let Err(error)=result {if !state.stop.load(Ordering::Acquire){let _=state.events.try_send(Event::Error(error.to_string()));}}});}}}actor.close();tasks.abort_all();while tasks.join_next().await.is_some(){}Ok(())
        });
                runtime.shutdown_timeout(Duration::from_secs(1));
                result
            })();
            if let Err(error) = result {
                let _ = actor.events.try_send(Event::Error(error.to_string()));
            }
            actor.close();
        });
        let mut server = Self {
            state,
            worker: Some(worker),
            stop: Some(stop),
            address,
            certificate_path: identity.certificate_path,
            certificate_der: identity.certificate_der,
            token,
        };
        if started.recv_timeout(Duration::from_secs(5)).is_err() {
            server.stop();
            return Err(io::Error::other("Unity TLS communicator failed to start"));
        }
        Ok((server, receiver))
    }
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn websocket_url(&self) -> String {
        format!(
            "wss://localhost:{}/?token={}",
            self.address.port(),
            self.token
        )
    }
    pub fn connected(&self) -> bool {
        self.state.peer().is_some()
    }
    /// Read the metadata of the ready peer without relying on desktop event delivery.
    pub fn schedule_context(&self) -> Option<UnityScheduleContext> {
        let peer = self.state.peer()?;
        let (version, packets) = peer.schedule_metadata.lock().ok()?.as_ref()?.clone();
        Some(UnityScheduleContext {
            peer,
            version,
            packets,
        })
    }
    /// Do not send a packet resolved for a peer that has since disconnected.
    pub fn inject_for_session(
        &self,
        context: &UnityScheduleContext,
        direction: Direction,
        packet: Packet,
    ) -> io::Result<()> {
        let active = self
            .state
            .active
            .lock()
            .map_err(|_| io::Error::other("Unity active lock poisoned"))?;
        let peer = active
            .as_ref()
            .filter(|peer| Arc::ptr_eq(peer, &context.peer))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "Unity session changed"))?;
        let metadata = peer
            .schedule_metadata
            .lock()
            .map_err(|_| io::Error::other("Unity metadata lock poisoned"))?;
        if !metadata
            .as_ref()
            .is_some_and(|(_, packets)| Arc::ptr_eq(packets, &context.packets))
        {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Unity metadata changed",
            ));
        }
        peer.enqueue(direction, packet)
    }
    /// Apply an explicit catalog download only to the matching ready revision.
    pub fn update_schedule_metadata(&self, packets: PacketInfoManager) -> bool {
        let Ok(active) = self.state.active.lock() else {
            return false;
        };
        let Some(peer) = active.as_ref().filter(|peer| {
            peer.ready.load(Ordering::Acquire) && !peer.closed.load(Ordering::Acquire)
        }) else {
            return false;
        };
        let Ok(mut metadata) = peer.schedule_metadata.lock() else {
            return false;
        };
        let Some((version, _)) = metadata.as_ref() else {
            return false;
        };
        if version.is_empty() || *version != packets.version {
            return false;
        }
        *metadata = Some((version.clone(), Arc::new(packets)));
        true
    }
    pub fn inject(&self, direction: Direction, packet: Packet) -> io::Result<()> {
        self.state
            .peer()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no Unity client"))?
            .enqueue(direction, packet)
    }
    pub fn set_rules(&self, rules: Rules) -> io::Result<()> {
        *self
            .state
            .rules
            .lock()
            .map_err(|_| io::Error::other("Unity rule lock poisoned"))? = rules;
        Ok(())
    }
    pub fn stop(&mut self) {
        self.state.stop.store(true, Ordering::Release);
        self.state.close();
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl Drop for UnityServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod injection_queue_tests {
    use super::*;
    #[test]
    fn full_and_closed_queues_return_the_original_packet_and_restore_budget() {
        let (sender, mut receiver) = asynchronous::channel(1);
        let (stop, _) = watch::channel(false);
        let peer = Peer {
            ready: AtomicBool::new(true),
            closed: AtomicBool::new(false),
            extension_session: Mutex::new(None),
            schedule_metadata: Mutex::new(None),
            queued: AtomicUsize::new(0),
            sender,
            stop,
        };
        peer.enqueue(Direction::ToClient, Packet::new(1)).unwrap();
        let queued_bytes = peer.queued.load(Ordering::Acquire);
        let packet = Packet::new(2);
        let address = packet.bytes().as_ptr();
        let (error, packet) = peer
            .enqueue_retaining(Direction::ToClient, packet)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(packet.bytes().as_ptr(), address);
        assert_eq!(peer.queued.load(Ordering::Acquire), queued_bytes);
        let (_, first) = receiver.try_recv().unwrap();
        peer.queued.fetch_sub(first.bytes().len(), Ordering::AcqRel);
        peer.enqueue_retaining(Direction::ToClient, packet).unwrap();
        let (_, packet) = receiver.try_recv().unwrap();
        peer.queued
            .fetch_sub(packet.bytes().len(), Ordering::AcqRel);
        drop(receiver);
        let (error, packet) = peer
            .enqueue_retaining(Direction::ToClient, packet)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert_eq!(packet.bytes().as_ptr(), address);
        assert_eq!(peer.queued.load(Ordering::Acquire), 0);
    }
}
