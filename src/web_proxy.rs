//! HTTP/TLS proxy and Nitro WebSocket packet pipeline. No OS proxy/trust changes.
use crate::{
    extension_host::{ConnectionDetails, ExtensionHost},
    nitro::{Decoded, Hotels, Modifier},
    packet::{Direction, FrameDecoder, Message, Packet, PacketFormat},
    packet_info::PacketInfoManager,
    relay::Event,
    rules::Rules,
    web_ca::ProxyIdentity,
};
use hudsucker::{
    futures::{Sink, SinkExt, Stream, StreamExt},
    hyper::{Request, Response, StatusCode, Uri},
    rustls::{self, crypto::aws_lc_rs, pki_types::CertificateDer},
    tokio_tungstenite::{
        tungstenite::{Error as WsError, Message as WsMessage},
        Connector,
    },
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext, WebSocketHandler,
};
use std::{
    collections::HashMap,
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
use tokio::sync::{mpsc as asynchronous, oneshot, watch, Notify};
pub const NITRO_REVISION: &str = "PRODUCTION-201611291003-338511768";
const MAX_QUEUED: usize = 32 * 1024 * 1024;
#[derive(Clone)]
pub struct WebOptions {
    pub unity: Option<crate::unity_assets::UnityAssets>,
    pub detect_nitro: bool,
    pub listen: SocketAddr,
    pub identity_directory: PathBuf,
    pub packet_info: PacketInfoManager,
    pub packet_safety: Option<Arc<Mutex<crate::packet_safety::PacketSafety>>>,
    pub admin_service: Option<Arc<Mutex<crate::admin_service::AdminService>>>,
    pub extensions: Option<Arc<ExtensionHost>>,
    pub extra_roots: Vec<Vec<u8>>,
    pub websocket_urls: Vec<String>,
    pub hotels: Hotels,
    pub allow_city_helper: bool,
    pub city_keys: Option<crate::nitro_city::CityKeys>,
}
impl WebOptions {
    pub fn new(listen: SocketAddr, identity_directory: PathBuf) -> Self {
        Self {
            listen,
            identity_directory,
            unity: None,
            detect_nitro: true,
            packet_info: PacketInfoManager::default(),
            packet_safety: None,
            admin_service: None,
            extensions: None,
            extra_roots: Vec::new(),
            websocket_urls: Vec::new(),
            hotels: Hotels::beta29(),
            allow_city_helper: false,
            city_keys: None,
        }
    }
}
#[derive(Clone, PartialEq, Eq, Hash)]
struct PeerKey {
    client: SocketAddr,
    uri: String,
}
struct Peer {
    key: PeerKey,
    modifier: tokio::sync::Mutex<Modifier>,
    active: AtomicBool,
    ready: AtomicBool,
    closed: AtomicBool,
    extension_session: Mutex<Option<u64>>,
    notify: Notify,
    queued: AtomicUsize,
    finished: AtomicUsize,
    senders: [asynchronous::Sender<Packet>; 2],
    receivers: Mutex<[Option<asynchronous::Receiver<Packet>>; 2]>,
    stop: watch::Sender<bool>,
}
impl Peer {
    fn new(key: PeerKey, modifier: Modifier) -> Self {
        let (out, out_rx) = asynchronous::channel(128);
        let (incoming, in_rx) = asynchronous::channel(128);
        let (stop, _) = watch::channel(false);
        Self {
            key,
            modifier: tokio::sync::Mutex::new(modifier),
            active: AtomicBool::new(false),
            ready: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            extension_session: Mutex::new(None),
            notify: Notify::new(),
            queued: AtomicUsize::new(0),
            finished: AtomicUsize::new(0),
            senders: [out, incoming],
            receivers: Mutex::new([Some(out_rx), Some(in_rx)]),
            stop,
        }
    }
    fn enqueue(&self, direction: Direction, packet: Packet) -> io::Result<()> {
        self.enqueue_retaining(direction, packet)
            .map_err(|(error, _)| error)
    }
    fn enqueue_retaining(
        &self,
        direction: Direction,
        packet: Packet,
    ) -> Result<(), (io::Error, Packet)> {
        if !self.active.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            return Err((
                io::Error::new(io::ErrorKind::NotConnected, "no active Nitro client"),
                packet,
            ));
        }
        if packet.format() != PacketFormat::EvaWire {
            return Err((
                io::Error::other("Nitro injection requires EVA_WIRE"),
                packet,
            ));
        }
        let bytes = packet.bytes().len();
        if self
            .queued
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(bytes).filter(|n| *n <= MAX_QUEUED)
            })
            .is_err()
        {
            return Err((
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Nitro injection byte budget exceeded",
                ),
                packet,
            ));
        }
        if let Err(error) = self.senders[side(direction)].try_send(packet) {
            self.queued.fetch_sub(bytes, Ordering::AcqRel);
            return Err(match error {
                asynchronous::error::TrySendError::Full(packet) => (
                    io::Error::new(io::ErrorKind::WouldBlock, "Nitro injection queue full"),
                    packet,
                ),
                asynchronous::error::TrySendError::Closed(packet) => (
                    io::Error::new(io::ErrorKind::NotConnected, "Nitro injection queue closed"),
                    packet,
                ),
            });
        }
        Ok(())
    }
}
fn side(direction: Direction) -> usize {
    if direction == Direction::ToServer {
        0
    } else {
        1
    }
}
struct Shared {
    options: WebOptions,
    hartico_key: Mutex<Option<[u8; 24]>>,
    city_keys: Mutex<Option<crate::nitro_city::CityKeys>>,
    peers: Mutex<HashMap<PeerKey, Arc<Peer>>>,
    active: Mutex<Option<Arc<Peer>>>,
    rules: Mutex<Rules>,
    pipeline: Mutex<()>,
    events: SyncSender<Event>,
    index: AtomicI32,
    stop: AtomicBool,
}
impl Shared {
    fn peer(&self, key: PeerKey) -> io::Result<Arc<Peer>> {
        let mut peers = self
            .peers
            .lock()
            .map_err(|_| io::Error::other("web peer lock poisoned"))?;
        if let Some(peer) = peers.get(&key) {
            return Ok(peer.clone());
        }
        if peers.len() >= 128 {
            return Err(io::Error::other("too many pending WebSocket connections"));
        }
        let kind = self
            .options
            .hotels
            .find(&key.uri)
            .map(|h| h.kind.clone())
            .unwrap_or(crate::nitro::HotelKind::Plain);
        let modifier = if kind == crate::nitro::HotelKind::Hartico {
            Modifier::Hartico(crate::nitro_assets::Hartico::new(self.hartico_key.lock().map_err(|_|io::Error::other("Hartico asset lock poisoned"))?.ok_or_else(||io::Error::other("Hartico logo key is unavailable; reload the hotel assets before connecting"))?))
        } else if kind == crate::nitro::HotelKind::HabboCity {
            Modifier::HabboCity(Box::new(crate::nitro_city::HabboCity::new(self.city_keys.lock().map_err(|_|io::Error::other("HabboCity key lock poisoned"))?.clone().ok_or_else(||io::Error::other("HabboCity keys are unavailable; import keys or opt in to Nitro Helper, then reload the hotel"))?)))
        } else {
            Modifier::new(&kind)?
        };
        let peer = Arc::new(Peer::new(key.clone(), modifier));
        peers.insert(key, peer.clone());
        Ok(peer)
    }
    fn close(&self, peer: &Peer) {
        if peer.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        peer.stop.send_replace(true);
        peer.notify.notify_waiters();
        if let Ok(mut active) = self.active.lock() {
            if active.as_ref().is_some_and(|p| p.key == peer.key) {
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
    fn finish(&self, peer: &Peer) {
        self.close(peer);
        if peer.finished.fetch_add(1, Ordering::AcqRel) == 1 {
            if let Ok(mut peers) = self.peers.lock() {
                peers.remove(&peer.key);
            }
        }
    }
    fn close_all(&self) {
        let peers = self
            .peers
            .lock()
            .map(|p| p.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for peer in peers {
            self.close(&peer);
        }
    }
    fn active(&self) -> Option<Arc<Peer>> {
        self.active
            .lock()
            .ok()?
            .clone()
            .filter(|p| p.ready.load(Ordering::Acquire) && !p.closed.load(Ordering::Acquire))
    }
    async fn activate(self: &Arc<Self>, peer: &Arc<Peer>, uri: &Uri) -> io::Result<()> {
        {
            let mut active = self
                .active
                .lock()
                .map_err(|_| io::Error::other("web active lock poisoned"))?;
            if peer.closed.load(Ordering::Acquire) || self.stop.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Nitro connection already closed",
                ));
            }
            if active.as_ref().is_some_and(|p| p.key != peer.key) {
                return Err(io::Error::other("another Nitro client is already active"));
            }
            *active = Some(peer.clone());
            peer.active.store(true, Ordering::Release);
        }
        let mut database = self.options.packet_info.clone();
        if !database.entries().is_empty() && database.version != NITRO_REVISION {
            let _ = self.events.try_send(Event::Status(format!(
                "Ignoring Nitro packet identifiers for revision {:?}; expected {:?}",
                database.version, NITRO_REVISION
            )));
            database = PacketInfoManager::new(NITRO_REVISION, Vec::new());
            let _ = self
                .events
                .try_send(Event::PacketIdentifiers(database.clone()));
        }
        if database.entries().is_empty() && self.options.extensions.is_some() {
            let _ = self
                .events
                .try_send(Event::Status("Loading Nitro packet identifiers...".into()));
            match tokio::task::spawn_blocking(|| {
                PacketInfoManager::fetch_sulek(NITRO_REVISION, false)
            })
            .await
            {
                Ok(Ok(info)) => {
                    let _ = self.events.try_send(Event::PacketIdentifiers(info.clone()));
                    database = info;
                }
                Ok(Err(e)) => {
                    let _ = self.events.try_send(Event::Status(format!(
                        "Nitro connected without packet names: {e}"
                    )));
                }
                Err(e) => return Err(io::Error::other(e.to_string())),
            }
        }
        // Serialize extension initialization with close(), so stopping during a
        // packet-name lookup cannot leave extensions attached to a closed game.
        let _connection = self
            .active
            .lock()
            .map_err(|_| io::Error::other("web active lock poisoned"))?;
        if peer.closed.load(Ordering::Acquire) || self.stop.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Nitro connection stopped",
            ));
        }
        if let Some(safety) = &self.options.packet_safety {
            if let Ok(mut safety) = safety.lock() {
                safety.register_metadata(NITRO_REVISION, &database);
            }
        }
        if let Some(host) = &self.options.extensions {
            let mut session = peer
                .extension_session
                .lock()
                .map_err(|_| io::Error::other("Nitro extension session lock poisoned"))?;
            *session = Some(host.start_owned_connection(ConnectionDetails {
                host: uri.host().unwrap_or("").into(),
                port: uri.port_u16().unwrap_or(
                    if matches!(uri.scheme_str(), Some("https" | "wss")) {
                        443
                    } else {
                        80
                    },
                ),
                version: NITRO_REVISION.into(),
                identifier: "HTML5".into(),
                client_type: "NITRO".into(),
                packets: database,
            })?);
        }
        if let Some(service) = &self.options.admin_service {
            if let Ok(mut service) = service.lock() {
                service.on_connect();
            }
        }
        peer.ready.store(true, Ordering::Release);
        peer.notify.notify_waiters();
        let _ = self.events.try_send(Event::Connected(format!(
            "Nitro {}",
            uri.host().unwrap_or("")
        )));
        Ok(())
    }
    async fn packet(
        self: &Arc<Self>,
        direction: Direction,
        packet: Packet,
        injected: bool,
    ) -> io::Result<Option<Packet>> {
        let state = self.clone();
        tokio::task::spawn_blocking(move || {
            let _serial = state
                .pipeline
                .lock()
                .map_err(|_| io::Error::other("Nitro pipeline lock poisoned"))?;
            let mut message = Message {
                packet,
                direction,
                index: state.index.fetch_add(1, Ordering::Relaxed),
                blocked: false,
            };
            if !injected {
                if let Some(safety) = &state.options.packet_safety {
                    if let Ok(mut safety) = safety.lock() {
                        safety.observe(NITRO_REVISION, direction, message.packet.header());
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
                    .map_err(|_| io::Error::other("Nitro rule lock poisoned"))?
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
        .map_err(|e| io::Error::other(e.to_string()))?
    }
}
#[derive(Clone)]
struct Handler(Arc<Shared>, u8, Option<crate::unity_assets::UnityAsset>);
impl Handler {
    async fn handle_asset_request(&mut self, mut request: Request<Body>) -> RequestOrResponse {
        self.1 = if request.uri().host() == Some("images.hartico.tv")
            && request.uri().path() == "/cosmos/img/logos/logo.png"
        {
            1
        } else if request.uri().host() == Some("cdn.habbocity.fr")
            && request.uri().path() == "/crypto/file/city_crypto_bg.wasm"
        {
            2
        } else {
            0
        };
        self.2 = self.0.options.unity.as_ref().and_then(|_| {
            crate::unity_assets::UnityAsset::from_url(
                request.uri().host().unwrap_or(""),
                request.uri().path(),
            )
        });
        if self.2.is_some() {
            self.1 = 3;
        }
        if self.1 != 0 {
            for name in [
                "if-none-match",
                "if-modified-since",
                "accept-encoding",
                "cache-control",
                "age",
                "etag",
                "last-modified",
                "date",
                "expires",
            ] {
                request.headers_mut().remove(name);
            }
            request
                .headers_mut()
                .insert("accept-encoding", "identity".parse().unwrap());
        }
        request.into()
    }
    async fn handle_asset_response(&mut self, response: Response<Body>) -> Response<Body> {
        if self.1 == 0 || response.status() != StatusCode::OK {
            return response;
        }
        use http_body_util::BodyExt;
        let (mut parts, mut body) = response.into_parts();
        if self.1 == 3 {
            for name in [
                "age",
                "cache-control",
                "etag",
                "if-none-match",
                "if-modified-since",
                "last-modified",
                "date",
                "expires",
            ] {
                parts.headers.remove(name);
            }
            parts
                .headers
                .insert("cache-control", "no-store".parse().unwrap());
            parts
                .headers
                .insert("x-modified-by", "G-Earth-Rust".parse().unwrap());
            if self
                .2
                .as_ref()
                .is_some_and(|asset| asset.kind == crate::unity_assets::AssetKind::Data)
            {
                return Response::from_parts(parts, body);
            }
        }
        let maximum = if self.1 == 3 {
            crate::unity_wasm::MAX_WASM
        } else {
            16 * 1024 * 1024
        };
        let mut bytes = Vec::new();
        let download_timeout = if self.1 == 3 {
            Duration::from_secs(180)
        } else {
            Duration::from_secs(20)
        };
        let result = tokio::time::timeout(download_timeout, async {
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(io::Error::other)?;
                if let Ok(data) = frame.into_data() {
                    if bytes.len() + data.len() > maximum {
                        return Err(io::Error::other("Browser asset exceeds its size limit"));
                    }
                    bytes.extend_from_slice(&data);
                }
            }
            Ok::<(), io::Error>(())
        })
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Browser asset download timed out",
            ))
        });
        if let Err(e) = result {
            let _ = self.0.events.try_send(Event::Error(e.to_string()));
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Hotel asset could not be read"))
                .unwrap();
        }
        if self.1 == 3 {
            let asset = self.2.clone().unwrap();
            let settings = self.0.options.unity.clone().unwrap();
            let result = tokio::task::spawn_blocking(move || {
                crate::unity_assets::modify(&asset, &bytes, &settings)
            })
            .await
            .map_err(io::Error::other)
            .and_then(|result| result);
            return match result {
                Ok(bytes) => {
                    parts.headers.remove("transfer-encoding");
                    parts.headers.remove("content-md5");
                    parts.headers.remove("digest");
                    parts
                        .headers
                        .insert("content-length", bytes.len().to_string().parse().unwrap());
                    Response::from_parts(parts, Body::from(bytes))
                }
                Err(error) => {
                    let _ = self
                        .0
                        .events
                        .try_send(Event::Error(format!("Unity asset patch failed: {error}")));
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from(
                            "Unity asset patch failed; see G-Earth Rust status",
                        ))
                        .unwrap()
                }
            };
        }
        if self.1 == 1 {
            match crate::nitro_assets::hartico_key(&bytes) {
                Ok(key) => {
                    if let Ok(mut target) = self.0.hartico_key.lock() {
                        *target = Some(key);
                    }
                }
                Err(e) => {
                    let _ = self
                        .0
                        .events
                        .try_send(Event::Error(format!("Hartico key extraction failed: {e}")));
                }
            }
        }
        if self.1 == 2 {
            if self.0.options.allow_city_helper {
                let wasm = bytes.clone();
                match tokio::task::spawn_blocking(move || crate::nitro_city::fetch_keys(&wasm))
                    .await
                {
                    Ok(Ok(keys)) => {
                        if let Ok(mut target) = self.0.city_keys.lock() {
                            *target = Some(keys);
                        }
                    }
                    Ok(Err(e)) => {
                        let _ = self
                            .0
                            .events
                            .try_send(Event::Error(format!("Nitro Helper failed: {e}")));
                    }
                    Err(e) => {
                        let _ = self.0.events.try_send(Event::Error(e.to_string()));
                    }
                }
            } else if self.0.city_keys.lock().is_ok_and(|keys| keys.is_none()) {
                let _=self.0.events.try_send(Event::Status("HabboCity requires imported key data or an explicit Nitro Helper opt-in before reloading".into()));
            }
        }
        Response::from_parts(parts, Body::from(bytes))
    }
}
impl HttpHandler for Handler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        request: Request<Body>,
    ) -> RequestOrResponse {
        self.handle_asset_request(request).await
    }
    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        response: Response<Body>,
    ) -> Response<Body> {
        self.handle_asset_response(response).await
    }
    async fn should_intercept_connect(
        &mut self,
        _ctx: &HttpContext,
        _request: &Request<Body>,
    ) -> bool {
        !self.0.stop.load(Ordering::Acquire)
    }
}
impl WebSocketHandler for Handler {
    async fn handle_websocket(
        self,
        ctx: WebSocketContext,
        mut stream: impl Stream<Item = Result<WsMessage, WsError>> + Unpin + Send + 'static,
        mut sink: impl Sink<WsMessage, Error = WsError> + Unpin + Send + 'static,
    ) {
        let (direction, key, uri) = match ctx {
            WebSocketContext::ClientToServer { src, dst, .. } => (
                Direction::ToServer,
                PeerKey {
                    client: src,
                    uri: dst.to_string(),
                },
                dst,
            ),
            WebSocketContext::ServerToClient { src, dst, .. } => (
                Direction::ToClient,
                PeerKey {
                    client: dst,
                    uri: src.to_string(),
                },
                src,
            ),
        };
        let peer = match self.0.peer(key) {
            Ok(p) => p,
            Err(e) => {
                let _ = self.0.events.try_send(Event::Error(e.to_string()));
                let _ = sink.close().await;
                return;
            }
        };
        let receiver = peer
            .receivers
            .lock()
            .ok()
            .and_then(|mut r| r[side(direction)].take());
        let Some(mut injections) = receiver else {
            self.0.close(&peer);
            return;
        };
        let mut stopping = peer.stop.subscribe();
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        let mut decoder = FrameDecoder::default();
        let mut decided = false;
        let result:io::Result<()> = async {
            loop {
                if self.0.stop.load(Ordering::Acquire)||peer.closed.load(Ordering::Acquire){break;}
                tokio::select! {
                    _=stopping.changed()=>break,
                    _=tick.tick(), if direction==Direction::ToServer&&peer.ready.load(Ordering::Acquire)=>{
                        if let Some(host)=&self.0.options.extensions{let epoch=peer.extension_session.lock().map_err(|_|io::Error::other("Nitro extension session lock poisoned"))?.ok_or_else(||io::Error::other("Nitro extension session missing"))?;host.forward_owned_injections(epoch,|direction,packet|peer.enqueue_retaining(direction,packet))?;}
                    },
                    packet=injections.recv()=>{let Some(packet)=packet else{break;};peer.queued.fetch_sub(packet.bytes().len(),Ordering::AcqRel);let mut modifier=peer.modifier.lock().await;if let Some(packet)=self.0.packet(direction,packet,true).await?{let bytes=modifier.encode(direction,packet.bytes().to_vec())?;sink.send(WsMessage::Binary(bytes.into())).await.map_err(io::Error::other)?;}},
                    message=stream.next()=>{
                        let Some(message)=message else{break;};let message=message.map_err(io::Error::other)?;
                        if let WsMessage::Binary(bytes)=message {
                            if direction==Direction::ToServer&&!decided {
                                decided=true;let url=uri.to_string();let configured=self.0.options.hotels.find(&url).is_some()||self.0.options.websocket_urls.iter().any(|u|{let url=url.split('?').next().unwrap_or(&url);match u.strip_suffix('*'){Some(prefix)=>url.starts_with(prefix),None=>u==url}});
                                let hello=Packet::from_bytes(bytes.to_vec()).is_ok_and(|p|p.header()==4000);
                                if self.0.options.detect_nitro&&(configured||hello){self.0.activate(&peer,&uri).await?;}
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
        if let Err(e) = result {
            if !self.0.stop.load(Ordering::Acquire) && !peer.closed.load(Ordering::Acquire) {
                let _ = self.0.events.try_send(Event::Error(e.to_string()));
            }
        }
        self.0.finish(&peer);
        let _ = sink.close().await;
    }
}
pub struct WebProxy {
    state: Arc<Shared>,
    stop: Option<oneshot::Sender<()>>,
    worker: Option<JoinHandle<()>>,
    pub address: SocketAddr,
    pub certificate_path: PathBuf,
    pub certificate_der: Vec<u8>,
}
impl WebProxy {
    pub fn start(options: WebOptions) -> io::Result<(Self, Receiver<Event>)> {
        if !options.listen.ip().is_loopback() {
            return Err(io::Error::other("HTTP proxy must bind loopback"));
        }
        let identity = ProxyIdentity::ensure(&options.identity_directory)?;
        let ca = identity.authority()?;
        let listener = TcpListener::bind(options.listen)?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let (events, receiver) = mpsc::sync_channel(2048);
        let state = Arc::new(Shared {
            city_keys: Mutex::new(options.city_keys.clone()),
            options,
            hartico_key: Mutex::new(None),
            peers: Mutex::new(HashMap::new()),
            active: Mutex::new(None),
            rules: Mutex::new(Rules::default()),
            pipeline: Mutex::new(()),
            events,
            index: AtomicI32::new(0),
            stop: AtomicBool::new(false),
        });
        let actor = state.clone();
        let (stop, shutdown) = oneshot::channel();
        let (ready, started) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let result = (|| -> io::Result<()> {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()?;
                let result=runtime.block_on(async{
            let provider=aws_lc_rs::default_provider();let _=provider.clone().install_default();let mut roots=rustls::RootCertStore::empty();roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());for der in &actor.options.extra_roots{roots.add(CertificateDer::from(der.clone())).map_err(io::Error::other)?;}
            let tls=rustls::ClientConfig::builder_with_provider(Arc::new(provider)).with_safe_default_protocol_versions().map_err(io::Error::other)?.with_root_certificates(roots).with_no_client_auth();
            let connector=hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls.clone()).https_or_http().enable_http1().build();let listener=tokio::net::TcpListener::from_std(listener)?;
            let proxy=Proxy::builder().with_listener(listener).with_ca(ca).with_http_connector(connector).with_websocket_connector(Connector::Rustls(Arc::new(tls))).with_http_handler(Handler(actor.clone(),0,None)).with_websocket_handler(Handler(actor.clone(),0,None)).build().map_err(io::Error::other)?;
            let _=ready.send(());let _=actor.events.try_send(Event::Listening(address));tokio::select!{result=proxy.start()=>result.map_err(io::Error::other),_=shutdown=>Ok(())}
        });
                runtime.shutdown_timeout(Duration::from_secs(1));
                result
            })();
            if let Err(e) = result {
                let _ = actor.events.try_send(Event::Error(e.to_string()));
            }
            actor.close_all();
        });
        let mut proxy = Self {
            state,
            stop: Some(stop),
            worker: Some(worker),
            address,
            certificate_path: identity.certificate_path,
            certificate_der: identity.certificate_der,
        };
        if started.recv_timeout(Duration::from_secs(5)).is_err() {
            proxy.stop();
            return Err(io::Error::other(
                "HTTP proxy initialization failed; check TLS configuration",
            ));
        }
        Ok((proxy, receiver))
    }
    pub fn connected(&self) -> bool {
        self.state.active().is_some()
    }
    pub fn inject(&self, direction: Direction, packet: Packet) -> io::Result<()> {
        self.state
            .active()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "no Nitro client connected")
            })?
            .enqueue(direction, packet)
    }
    pub fn set_rules(&self, rules: Rules) -> io::Result<()> {
        *self
            .state
            .rules
            .lock()
            .map_err(|_| io::Error::other("Nitro rule lock poisoned"))? = rules;
        Ok(())
    }
    pub fn stop(&mut self) {
        self.state.stop.store(true, Ordering::Release);
        self.state.close_all();
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl Drop for WebProxy {
    fn drop(&mut self) {
        self.stop();
    }
}
#[cfg(test)]
mod unity_http_tests {
    use super::*;
    use crate::unity_assets::UnityAssets;
    use std::io::{Read, Write};
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
    #[test]
    fn proxy_asset_handler_preserves_gzip_and_updates_headers_without_changing_system_settings() {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let directory = Directory(std::env::temp_dir().join(format!(
                "gearth-unity-http-{}",
                random
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )));
        std::fs::create_dir(&directory.0).unwrap();
        let mut options = WebOptions::new("127.0.0.1:0".parse().unwrap(), directory.0.join("ca"));
        options.unity = Some(UnityAssets {
            websocket_port: 12345,
            token: "a".repeat(64),
            cache_directory: directory.0.join("unused"),
        });
        options.detect_nitro = false;
        let (mut proxy, _) = WebProxy::start(options).unwrap();
        let mut handler = Handler(proxy.state.clone(), 0, None);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async{
            use http_body_util::BodyExt;
            let url="https://images.habbo.com/habbo-webgl-clients/TEST-1/WebGL/habbo2020-global-prod/StreamingAssets/Version.txt";let request=Request::builder().uri(url).header("if-none-match","old-tag").header("accept-encoding","gzip, br").body(Body::empty()).unwrap();let RequestOrResponse::Request(request)=handler.handle_asset_request(request).await else{panic!("asset request was not forwarded")};assert!(!request.headers().contains_key("if-none-match"));assert_eq!(request.headers()["accept-encoding"],"identity");
            let mut encoder=flate2::write::GzEncoder::new(Vec::new(),flate2::Compression::fast());encoder.write_all(b"fixture-version").unwrap();let bytes=encoder.finish().unwrap();let response=Response::builder().header("etag","old-tag").header("last-modified","old-date").header("content-encoding","gzip").header("content-length",bytes.len()).body(Body::from(bytes)).unwrap();let response=handler.handle_asset_response(response).await;assert_eq!(response.status(),StatusCode::OK);assert_eq!(response.headers()["cache-control"],"no-store");assert_eq!(response.headers()["x-modified-by"],"G-Earth-Rust");assert_eq!(response.headers()["content-encoding"],"gzip");assert!(!response.headers().contains_key("etag"));assert!(!response.headers().contains_key("last-modified"));let length=response.headers()["content-length"].to_str().unwrap().parse::<usize>().unwrap();let bytes=response.into_body().collect().await.unwrap().to_bytes();assert_eq!(bytes.len(),length);let mut text=String::new();flate2::read::GzDecoder::new(bytes.as_ref()).read_to_string(&mut text).unwrap();assert_eq!(text,"fixture-version - G-Earth Rust");
            let data_url=url.replace("StreamingAssets/Version.txt","Build/habbo2020-global-prod.data.gz");let request=Request::builder().uri(data_url).body(Body::empty()).unwrap();let _=handler.handle_asset_request(request).await;let response=Response::builder().header("etag","data-tag").body(Body::from("original-data")).unwrap();let response=handler.handle_asset_response(response).await;assert!(!response.headers().contains_key("etag"));assert_eq!(response.into_body().collect().await.unwrap().to_bytes(),"original-data");
            let request=Request::builder().uri(url).body(Body::empty()).unwrap();let _=handler.handle_asset_request(request).await;let response=Response::builder().status(404).header("etag","error-tag").body(Body::from("not found")).unwrap();let response=handler.handle_asset_response(response).await;assert_eq!(response.status(),StatusCode::NOT_FOUND);assert_eq!(response.headers()["etag"],"error-tag");
        });
        proxy.stop();
    }
}

#[cfg(test)]
mod injection_queue_tests {
    use super::*;
    #[test]
    fn full_and_closed_queues_return_the_original_packet_and_restore_budget() {
        let peer = Peer::new(
            PeerKey {
                client: "127.0.0.1:1234".parse().unwrap(),
                uri: "ws://fixture".into(),
            },
            Modifier::new(&crate::nitro::HotelKind::Plain).unwrap(),
        );
        peer.active.store(true, Ordering::Release);
        let mut receiver = peer.receivers.lock().unwrap()[side(Direction::ToClient)]
            .take()
            .unwrap();
        for header in 0..128 {
            peer.enqueue(Direction::ToClient, Packet::new(header))
                .unwrap();
        }
        let queued_bytes = peer.queued.load(Ordering::Acquire);
        let packet = Packet::new(500);
        let address = packet.bytes().as_ptr();
        let (error, packet) = peer
            .enqueue_retaining(Direction::ToClient, packet)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(packet.bytes().as_ptr(), address);
        assert_eq!(peer.queued.load(Ordering::Acquire), queued_bytes);
        let first = receiver.try_recv().unwrap();
        peer.queued.fetch_sub(first.bytes().len(), Ordering::AcqRel);
        peer.enqueue_retaining(Direction::ToClient, packet).unwrap();
        while let Ok(packet) = receiver.try_recv() {
            peer.queued
                .fetch_sub(packet.bytes().len(), Ordering::AcqRel);
        }
        drop(receiver);
        let (error, _) = peer
            .enqueue_retaining(Direction::ToClient, Packet::new(501))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert_eq!(peer.queued.load(Ordering::Acquire), 0);
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use crate::{
        extension::{self, ExtensionInfo},
        extension_host::HostEvent,
        packet::{read_frame, write_frame},
    };
    use std::net::TcpStream;

    #[test]
    fn nitro_discards_metadata_from_another_revision_without_extension_host() {
        use crate::{packet_info::PacketInfo, packet_safety::PacketSafety};
        for original in ["OLD", ""] {
            let safety = Arc::new(Mutex::new(PacketSafety::default()));
            let mut options = WebOptions::new("127.0.0.1:0".parse().unwrap(), PathBuf::new());
            options.packet_safety = Some(safety.clone());
            options.packet_info = PacketInfoManager::new(
                original,
                vec![PacketInfo {
                    header: 777,
                    name: Some("OldPacket".into()),
                    hash: None,
                    structure: None,
                    direction: Direction::ToServer,
                    source: "fixture".into(),
                }],
            );
            let (events, receiver) = mpsc::sync_channel(16);
            let state = Arc::new(Shared {
                options,
                hartico_key: Mutex::new(None),
                city_keys: Mutex::new(None),
                peers: Mutex::new(HashMap::new()),
                active: Mutex::new(None),
                rules: Mutex::new(Rules::default()),
                pipeline: Mutex::new(()),
                events,
                index: AtomicI32::new(0),
                stop: AtomicBool::new(false),
            });
            let peer = Arc::new(Peer::new(
                PeerKey {
                    client: "127.0.0.1:1234".parse().unwrap(),
                    uri: "ws://fixture".into(),
                },
                Modifier::new(&crate::nitro::HotelKind::Plain).unwrap(),
            ));
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(state.activate(&peer, &"ws://fixture".parse().unwrap()))
                .unwrap();
            assert!(peer.ready.load(Ordering::Acquire));
            assert!(!safety.lock().unwrap().is_safe(
                Some(NITRO_REVISION),
                Direction::ToServer,
                777
            ));
            assert!(receiver.try_iter().any(|event| matches!(event, Event::PacketIdentifiers(db) if db.version == NITRO_REVISION && db.entries().is_empty())));
            state.close(&peer);
        }
    }

    #[test]
    fn closing_an_uninitialized_peer_does_not_disconnect_extensions() {
        let (host, host_events) =
            ExtensionHost::start("127.0.0.1:0".parse().unwrap(), vec![]).unwrap();
        let epoch = host
            .start_owned_connection(ConnectionDetails {
                host: "fixture".into(),
                port: 1,
                version: "test".into(),
                identifier: "test".into(),
                client_type: "FLASH".into(),
                packets: PacketInfoManager::default(),
            })
            .unwrap();
        let mut stream = TcpStream::connect(host.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        assert_eq!(read_frame(&mut stream).unwrap().header(), 2);
        let info = ExtensionInfo {
            title: "fixture".into(),
            author: "test".into(),
            version: "1".into(),
            description: String::new(),
            on_click: false,
            file: None,
            cookie: String::new(),
            can_leave: true,
            can_delete: true,
        };
        write_frame(&mut stream, &extension::info_response(&info).unwrap()).unwrap();
        let HostEvent::Pending { id, .. } =
            host_events.recv_timeout(Duration::from_secs(3)).unwrap()
        else {
            panic!("extension not pending")
        };
        host.approve(id).unwrap();
        assert_eq!(read_frame(&mut stream).unwrap().header(), 7);
        assert_eq!(read_frame(&mut stream).unwrap().header(), 5);

        let mut options = WebOptions::new("127.0.0.1:0".parse().unwrap(), PathBuf::new());
        options.extensions = Some(host.clone());
        let (events, receiver) = mpsc::sync_channel(8);
        let state = Shared {
            options,
            hartico_key: Mutex::new(None),
            city_keys: Mutex::new(None),
            peers: Mutex::new(HashMap::new()),
            active: Mutex::new(None),
            rules: Mutex::new(Rules::default()),
            pipeline: Mutex::new(()),
            events,
            index: AtomicI32::new(0),
            stop: AtomicBool::new(false),
        };
        let peer = Arc::new(Peer::new(
            PeerKey {
                client: "127.0.0.1:1234".parse().unwrap(),
                uri: "ws://fixture".into(),
            },
            Modifier::new(&crate::nitro::HotelKind::Plain).unwrap(),
        ));
        *state.active.lock().unwrap() = Some(peer.clone());
        state.close(&peer);
        assert!(receiver.try_recv().is_err());
        write_frame(&mut stream, &Packet::new(3)).unwrap();
        assert_eq!(read_frame(&mut stream).unwrap().header(), 4);

        let ready_peer = Arc::new(Peer::new(
            PeerKey {
                client: "127.0.0.1:1235".parse().unwrap(),
                uri: "ws://fixture".into(),
            },
            Modifier::new(&crate::nitro::HotelKind::Plain).unwrap(),
        ));
        ready_peer.ready.store(true, Ordering::Release);
        *ready_peer.extension_session.lock().unwrap() = Some(epoch);
        *state.active.lock().unwrap() = Some(ready_peer.clone());
        state.close(&ready_peer);
        assert!(matches!(receiver.try_recv(), Ok(Event::Disconnected)));
        assert_eq!(read_frame(&mut stream).unwrap().header(), 6);
        drop(stream);
        host.stop();
    }
}
