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
const MAX_NITRO_LOOKUPS: usize = 4;
static ACTIVE_NITRO_LOOKUPS: AtomicUsize = AtomicUsize::new(0);
struct NitroLookupSlot;
impl NitroLookupSlot {
    fn reserve() -> io::Result<Self> {
        let mut count = ACTIVE_NITRO_LOOKUPS.load(Ordering::Acquire);
        loop {
            if count >= MAX_NITRO_LOOKUPS {
                return Err(io::Error::other(
                    "too many Nitro metadata lookups still in progress",
                ));
            }
            match ACTIVE_NITRO_LOOKUPS.compare_exchange_weak(
                count,
                count + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self),
                Err(actual) => count = actual,
            }
        }
    }
}
impl Drop for NitroLookupSlot {
    fn drop(&mut self) {
        ACTIVE_NITRO_LOOKUPS.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone)]
pub struct WebOptions {
    pub unity: Option<crate::unity_assets::UnityAssets>,
    pub detect_nitro: bool,
    pub listen: SocketAddr,
    pub identity_directory: PathBuf,
    pub packet_info: PacketInfoManager,
    /// Route upstream traffic, packet-info fetching and the opted-in City helper through SOCKS5.
    pub upstream_socks: Option<crate::socks::SocksConfig>,
    /// Fetch missing Nitro identifiers from the upstream provider.
    pub fetch_packet_info: bool,
    #[cfg(test)]
    nitro_lookup: Option<Arc<dyn Fn() -> io::Result<PacketInfoManager> + Send + Sync>>,
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
            upstream_socks: None,
            fetch_packet_info: true,
            #[cfg(test)]
            nitro_lookup: None,
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
        let mut publish_database = false;
        if !database.entries().is_empty() && database.version != NITRO_REVISION {
            let _ = self.events.try_send(Event::Status(format!(
                "Ignoring Nitro packet identifiers for revision {:?}; expected {:?}",
                database.version, NITRO_REVISION
            )));
            database = PacketInfoManager::new(NITRO_REVISION, Vec::new());
            publish_database = true;
        }
        if database.entries().is_empty() && self.options.fetch_packet_info {
            let _ = self
                .events
                .try_send(Event::Status("Loading Nitro packet identifiers...".into()));
            let result = match NitroLookupSlot::reserve() {
                Ok(slot) => {
                    #[cfg(test)]
                    let lookup = self.options.nitro_lookup.clone();
                    let socks = self.options.upstream_socks.clone();
                    let worker = tokio::task::spawn_blocking(move || {
                        let _slot = slot;
                        #[cfg(test)]
                        if let Some(lookup) = lookup {
                            return lookup();
                        }
                        if let Some(socks) = socks {
                            return crate::web_socks::fetch_nitro(socks);
                        }
                        PacketInfoManager::fetch_sulek(NITRO_REVISION, false)
                    });
                    let mut closed = peer.stop.subscribe();
                    if peer.closed.load(Ordering::Acquire) || self.stop.load(Ordering::Acquire) {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "Nitro connection stopped",
                        ));
                    }
                    tokio::select! {
                        result = worker => result.map_err(|e| io::Error::other(e.to_string()))?,
                        _ = closed.changed() => return Err(io::Error::new(io::ErrorKind::Interrupted, "Nitro connection stopped")),
                    }
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(info) => {
                    database = info;
                    publish_database = true;
                }
                Err(e) => {
                    let _ = self.events.try_send(Event::Status(format!(
                        "Nitro connected without packet names: {e}"
                    )));
                }
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
        if publish_database {
            let _ = self
                .events
                .try_send(Event::PacketIdentifiers(database.clone()));
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
                let socks = self.0.options.upstream_socks.clone();
                match tokio::task::spawn_blocking(move || {
                    if let Some(socks) = socks {
                        crate::web_socks::fetch_city(socks, &wasm)
                    } else {
                        crate::nitro_city::fetch_keys(&wasm)
                    }
                })
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
            let connector=hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls.clone()).https_or_http().enable_http1().wrap_connector(crate::web_socks::OutboundConnector::new(actor.options.upstream_socks.clone()));let listener=tokio::net::TcpListener::from_std(listener)?;
            let mut builder=Proxy::builder().with_listener(listener).with_ca(ca).with_http_connector(connector).with_websocket_connector(Connector::Rustls(Arc::new(tls))).with_http_handler(Handler(actor.clone(),0,None)).with_websocket_handler(Handler(actor.clone(),0,None));
            if let Some(socks)=actor.options.upstream_socks.clone(){builder=builder.with_upstream_dialer(crate::web_socks::dialer(socks));}
            let proxy=builder.build().map_err(io::Error::other)?;
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

    static NITRO_LOOKUP_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn city_helper_never_uploads_without_session_opt_in_with_socks() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut options = WebOptions::new("127.0.0.1:0".parse().unwrap(), PathBuf::new());
        options.upstream_socks = Some(crate::socks::SocksConfig {
            proxy: listener.local_addr().unwrap().to_string(),
            credentials: None,
        });
        assert!(!options.allow_city_helper);
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
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let mut handler = Handler(state, 2, None);
            let response = Response::builder()
                .status(200)
                .body(Body::from(b"\0asm\x01\0\0\0".to_vec()))
                .unwrap();
            assert_eq!(
                handler.handle_asset_response(response).await.status(),
                StatusCode::OK
            );
        });
        assert!(receiver.try_iter().any(|event| matches!(event, Event::Status(text) if text.contains("explicit Nitro Helper opt-in"))));
        assert_eq!(
            listener.accept().err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn nitro_fetches_metadata_without_extension_host_and_handles_failure() {
        let _test_lock = NITRO_LOOKUP_TEST_LOCK.lock().unwrap();
        use crate::{packet_info::PacketInfo, packet_safety::PacketSafety};
        for succeed in [true, false] {
            let safety = Arc::new(Mutex::new(PacketSafety::default()));
            let mut options = WebOptions::new("127.0.0.1:0".parse().unwrap(), PathBuf::new());
            options.packet_safety = Some(safety.clone());
            options.nitro_lookup = Some(Arc::new(move || {
                if !succeed {
                    return Err(io::Error::other("fixture offline"));
                }
                Ok(PacketInfoManager::new(
                    NITRO_REVISION,
                    vec![PacketInfo {
                        header: 900,
                        name: Some("Known".into()),
                        hash: None,
                        structure: None,
                        direction: Direction::ToServer,
                        source: "fixture".into(),
                    }],
                ))
            }));
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
            assert_eq!(
                safety
                    .lock()
                    .unwrap()
                    .is_safe(Some(NITRO_REVISION), Direction::ToServer, 900),
                succeed
            );
            let events: Vec<_> = receiver.try_iter().collect();
            if succeed {
                assert!(events.iter().any(
                    |event| matches!(event, Event::PacketIdentifiers(db) if db.entries().len() == 1)
                ));
            } else {
                assert!(events.iter().any(
                    |event| matches!(event, Event::Status(text) if text.contains("fixture offline"))
                ));
            }
            state.close(&peer);
        }
    }

    #[test]
    fn closing_nitro_peer_cancels_wait_for_stalled_metadata_without_starting_session() {
        let _test_lock = NITRO_LOOKUP_TEST_LOCK.lock().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let (host, _) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
        let epoch = host
            .start_owned_connection(ConnectionDetails {
                host: "old".into(),
                port: 1,
                version: "OLD".into(),
                identifier: String::new(),
                client_type: "FLASH".into(),
                packets: PacketInfoManager::default(),
            })
            .unwrap();
        let mut options = WebOptions::new("127.0.0.1:0".parse().unwrap(), PathBuf::new());
        options.extensions = Some(host.clone());
        options.nitro_lookup = Some(Arc::new(move || {
            started_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            finished_tx.send(()).unwrap();
            Ok(PacketInfoManager::default())
        }));
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
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let task_state = state.clone();
            let task_peer = peer.clone();
            let task = tokio::spawn(async move {
                task_state
                    .activate(&task_peer, &"ws://fixture".parse().unwrap())
                    .await
            });
            started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            state.close(&peer);
            let result = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
            assert!(!peer.ready.load(Ordering::Acquire));
            release_tx.send(()).unwrap();
            finished_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        });
        assert!(!receiver
            .try_iter()
            .any(|event| matches!(event, Event::Connected(_) | Event::PacketIdentifiers(_))));
        assert!(host.end_owned_connection(epoch));
        host.stop();
    }

    #[test]
    fn nitro_proxy_stop_returns_while_metadata_provider_is_stalled() {
        let _test_lock = NITRO_LOOKUP_TEST_LOCK.lock().unwrap();
        use hudsucker::tokio_tungstenite::{
            accept_async, client_async, tungstenite::Message as WsMessage,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let directory = Directory(std::env::temp_dir().join(format!(
            "gearth-nitro-stop-{:032x}",
            u128::from_ne_bytes(random)
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let mut options = WebOptions::new("127.0.0.1:0".parse().unwrap(), directory.0.join("ca"));
        options.nitro_lookup = Some(Arc::new(move || {
            started_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            finished_tx.send(()).unwrap();
            Ok(PacketInfoManager::default())
        }));
        let (mut proxy, _) = WebProxy::start(options).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let remote = listener.local_addr().unwrap();
            let upstream = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = accept_async(stream).await.unwrap();
                let _ = socket.next().await;
            });
            let mut stream = tokio::net::TcpStream::connect(proxy.address).await.unwrap();
            stream
                .write_all(
                    format!("CONNECT {remote} HTTP/1.1\r\nHost: {remote}\r\n\r\n").as_bytes(),
                )
                .await
                .unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(5), async {
                while !response.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await.unwrap();
                    response.push(byte[0]);
                    assert!(response.len() < 8192);
                }
            })
            .await
            .unwrap();
            assert!(String::from_utf8(response)
                .unwrap()
                .starts_with("HTTP/1.1 200"));
            let (mut client, _) = client_async(format!("ws://{remote}/game"), stream)
                .await
                .unwrap();
            let mut hello = Packet::new(4000);
            hello.put_i32(0).unwrap();
            client
                .send(WsMessage::Binary(hello.bytes().to_vec().into()))
                .await
                .unwrap();
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let start = std::time::Instant::now();
            proxy.stop();
            assert!(start.elapsed() < Duration::from_secs(3));
            assert!(!proxy.connected());
            release_tx.send(()).unwrap();
            finished_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            drop(client);
            tokio::time::timeout(Duration::from_secs(5), upstream)
                .await
                .unwrap()
                .unwrap();
        });
    }

    #[test]
    fn cancelled_nitro_lookup_cannot_replace_new_extension_metadata() {
        use crate::packet_info::PacketInfo;
        let _test_lock = NITRO_LOOKUP_TEST_LOCK.lock().unwrap();
        let (host, host_events) =
            ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
        let mut extension_peer = TcpStream::connect(host.address).unwrap();
        extension_peer
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        assert_eq!(read_frame(&mut extension_peer).unwrap().header(), 2);
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
        write_frame(
            &mut extension_peer,
            &extension::info_response(&info).unwrap(),
        )
        .unwrap();
        let id = match host_events.recv_timeout(Duration::from_secs(3)).unwrap() {
            HostEvent::Pending { id, .. } => id,
            event => panic!("{event:?}"),
        };
        host.approve(id).unwrap();
        assert_eq!(read_frame(&mut extension_peer).unwrap().header(), 7);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let calls = AtomicUsize::new(0);
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let cache = std::env::temp_dir().join(format!(
            "gearth-nitro-race-{:032x}.bin",
            u128::from_ne_bytes(random)
        ));
        let worker_cache = cache.clone();
        let mut options = WebOptions::new("127.0.0.1:0".parse().unwrap(), PathBuf::new());
        options.extensions = Some(host.clone());
        options.nitro_lookup = Some(Arc::new(move || {
            let index = calls.fetch_add(1, Ordering::AcqRel);
            let result = PacketInfoManager::load_or_refresh(
                &worker_cache,
                NITRO_REVISION,
                std::time::SystemTime::now() + Duration::from_secs(301),
                || {
                    if index == 0 {
                        started_tx.send(()).unwrap();
                        release_rx.lock().unwrap().recv().unwrap();
                    }
                    let header = if index == 0 { 901 } else { 902 };
                    Ok(PacketInfoManager::new(
                        NITRO_REVISION,
                        vec![PacketInfo {
                            header,
                            name: Some("Known".into()),
                            hash: None,
                            structure: None,
                            direction: Direction::ToServer,
                            source: "fixture".into(),
                        }],
                    ))
                },
            );
            if index == 0 {
                finished_tx.send(()).unwrap();
            }
            result
        }));
        let (events, receiver) = mpsc::sync_channel(32);
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
        let peer = |port| {
            Arc::new(Peer::new(
                PeerKey {
                    client: format!("127.0.0.1:{port}").parse().unwrap(),
                    uri: "ws://fixture".into(),
                },
                Modifier::new(&crate::nitro::HotelKind::Plain).unwrap(),
            ))
        };
        let old = peer(1234);
        let new = peer(1235);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let old_state = state.clone(); let old_peer = old.clone();
            let task = tokio::spawn(async move { old_state.activate(&old_peer, &"ws://fixture".parse().unwrap()).await });
            started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            state.close(&old);
            assert_eq!(tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap().unwrap_err().kind(), io::ErrorKind::Interrupted);
            state.activate(&new, &"ws://fixture".parse().unwrap()).await.unwrap();
            let mut start = read_frame(&mut extension_peer).unwrap();
            assert_eq!(start.header(), 5);
            start.read_string().unwrap(); start.read_i32().unwrap();
            let version = start.read_string().unwrap(); start.read_string().unwrap(); start.read_string().unwrap();
            let metadata = PacketInfoManager::read_from(version, &mut start).unwrap();
            assert_eq!(metadata.entries()[0].header, 902);
            release_tx.send(()).unwrap();
            finished_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            assert_eq!(PacketInfoManager::load_cache(&cache, NITRO_REVISION).unwrap().entries()[0].header, 902);
            write_frame(&mut extension_peer, &Packet::new(3)).unwrap();
            assert_eq!(read_frame(&mut extension_peer).unwrap().header(), 4);
            let events: Vec<_> = receiver.try_iter().collect();
            assert_eq!(events.iter().filter(|event| matches!(event, Event::Connected(_))).count(), 1);
            assert!(events.iter().any(|event| matches!(event, Event::PacketIdentifiers(db) if db.entries().first().is_some_and(|entry| entry.header == 902))));
            assert!(!events.iter().any(|event| matches!(event, Event::PacketIdentifiers(db) if db.entries().first().is_some_and(|entry| entry.header == 901))));
            state.close(&new);
            assert_eq!(read_frame(&mut extension_peer).unwrap().header(), 6);
        });
        drop(extension_peer);
        host.stop();
        std::fs::remove_file(cache).unwrap();
    }

    #[test]
    fn nitro_metadata_https_success_failure_and_cancel_use_local_trusted_server() {
        use crate::{packet_info::download_json, packet_safety::PacketSafety};
        use hudsucker::{
            certificate_authority::CertificateAuthority,
            rustls::{self, crypto::aws_lc_rs, pki_types::CertificateDer},
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _test_lock = NITRO_LOOKUP_TEST_LOCK.lock().unwrap();
        struct Directory(PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                for file in [
                    "ca/gearth-proxy-cert.pem",
                    "ca/gearth-proxy-key.pem",
                    "cache_success.bin",
                    "cache_failure.bin",
                    "cache_stall.bin",
                    "race.bin",
                    "SHOCKWAVE-LATEST.bin",
                    "SHOCKWAVE-OLD.bin",
                    "SHOCKWAVE-EMPTY.bin",
                ] {
                    let _ = std::fs::remove_file(self.0.join(file));
                }
                let _ = std::fs::remove_dir(self.0.join("ca"));
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).unwrap();
        let directory = Directory(std::env::temp_dir().join(format!(
            "gearth-nitro-https-{:032x}",
            u128::from_ne_bytes(random)
        )));
        std::fs::create_dir(&directory.0).unwrap();
        let identity = ProxyIdentity::ensure(&directory.0.join("ca")).unwrap();
        let authority = identity.authority().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(identity.certificate_der))
            .unwrap();
        let tls =
            rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        let agent = ureq::AgentBuilder::new()
            .tls_config(Arc::new(tls))
            .try_proxy_from_env(false)
            .timeout(Duration::from_secs(5))
            .build();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            for mode in ["success", "failure", "malformed", "truncated", "oversized", "stall", "cache_success", "cache_failure", "cache_stall"] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = format!("localhost:{}", listener.local_addr().unwrap().port());
                let server_config = authority.gen_server_config(&address.parse().unwrap()).await;
                let (request_tx, request_rx) = mpsc::channel();
                let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
                let server = tokio::spawn(async move {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut tls = tokio_rustls::TlsAcceptor::from(server_config).accept(stream).await.unwrap();
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        let mut byte = [0]; tls.read_exact(&mut byte).await.unwrap(); request.push(byte[0]); assert!(request.len() < 8192);
                    }
                    assert!(request.starts_with(b"GET /fixture HTTP/1.1\r\n"));
                    request_tx.send(()).unwrap();
                    if matches!(mode, "stall" | "cache_stall") { release_rx.await.unwrap(); }
                    let body = match mode {
                        "failure" | "cache_failure" => "offline".to_string(),
                        "malformed" | "truncated" => "{".to_string(),
                        "oversized" => "x".repeat(8 * 1024 * 1024 + 1),
                        _ => r#"{"messages":{"incoming":[],"outgoing":[{"id":900,"name":"KnownComposer"}]}}"#.to_string(),
                    };
                    let status = if matches!(mode, "failure" | "cache_failure") { "503 Service Unavailable" } else { "200 OK" };
                    let length = if mode == "truncated" { body.len() + 100 } else { body.len() };
                    let headers = format!("HTTP/1.1 {status}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n");
                    let _ = tls.write_all(headers.as_bytes()).await;
                    let _ = tls.write_all(body.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
                let url = format!("https://{address}/fixture");
                let agent = agent.clone();
                let cache = mode.starts_with("cache_").then(|| directory.0.join(format!("{mode}.bin")));
                if let Some(path) = &cache {
                    let old = PacketInfoManager::from_json(NITRO_REVISION, br#"{"messages":{"incoming":[],"outgoing":[{"id":899,"name":"OldComposer"}]}}"#).unwrap();
                    old.save_cache(path).unwrap();
                }
                let cache_for_worker = cache.clone();
                let (done_tx, done_rx) = mpsc::channel();
                let mut options = WebOptions::new("127.0.0.1:0".parse().unwrap(), PathBuf::new());
                let extension_fixture = if !matches!(mode, "success" | "stall" | "cache_success" | "cache_failure" | "cache_stall") {
                    let (host, host_events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
                    let mut peer = TcpStream::connect(host.address).unwrap();
                    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    assert_eq!(read_frame(&mut peer).unwrap().header(), 2);
                    let info = ExtensionInfo { title: "fixture".into(), author: "test".into(), version: "1".into(), description: String::new(), on_click: false, file: None, cookie: String::new(), can_leave: true, can_delete: true };
                    write_frame(&mut peer, &extension::info_response(&info).unwrap()).unwrap();
                    let id = match host_events.recv_timeout(Duration::from_secs(3)).unwrap() { HostEvent::Pending { id, .. } => id, event => panic!("{event:?}") };
                    host.approve(id).unwrap();
                    assert_eq!(read_frame(&mut peer).unwrap().header(), 7);
                    options.extensions = Some(host.clone());
                    Some((host, peer))
                } else { None };
                let safety = Arc::new(Mutex::new(PacketSafety::default()));
                options.packet_safety = Some(safety.clone());
                options.nitro_lookup = Some(Arc::new(move || {
                    let fetch = || download_json(&agent, &url).and_then(|bytes| PacketInfoManager::from_json(NITRO_REVISION, &bytes).map_err(io::Error::other));
                    let result = if let Some(path) = &cache_for_worker {
                        PacketInfoManager::load_or_refresh(path, NITRO_REVISION, std::time::SystemTime::now() + Duration::from_secs(301), fetch)
                    } else { fetch() };
                    let _ = done_tx.send(result.as_ref().err().map(ToString::to_string));
                    result
                }));
                let (events, receiver) = mpsc::sync_channel(16);
                let state = Arc::new(Shared { options, hartico_key: Mutex::new(None), city_keys: Mutex::new(None), peers: Mutex::new(HashMap::new()), active: Mutex::new(None), rules: Mutex::new(Rules::default()), pipeline: Mutex::new(()), events, index: AtomicI32::new(0), stop: AtomicBool::new(false) });
                let peer = Arc::new(Peer::new(PeerKey { client: "127.0.0.1:1234".parse().unwrap(), uri: "ws://fixture".into() }, Modifier::new(&crate::nitro::HotelKind::Plain).unwrap()));
                let worker_state = state.clone(); let worker_peer = peer.clone();
                let task = tokio::spawn(async move { worker_state.activate(&worker_peer, &"ws://fixture".parse().unwrap()).await });
                request_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                if matches!(mode, "stall" | "cache_stall") {
                    state.close(&peer);
                    assert_eq!(tokio::time::timeout(Duration::from_secs(2), task).await.unwrap().unwrap().unwrap_err().kind(), io::ErrorKind::Interrupted);
                    release_tx.send(()).unwrap();
                } else {
                    tokio::time::timeout(Duration::from_secs(15), task).await.unwrap().unwrap().unwrap();
                    assert!(peer.ready.load(Ordering::Acquire));
                    assert_eq!(safety.lock().unwrap().is_safe(Some(NITRO_REVISION), Direction::ToServer, 900), matches!(mode, "success" | "cache_success"));
                    assert_eq!(safety.lock().unwrap().is_safe(Some(NITRO_REVISION), Direction::ToServer, 899), mode == "cache_failure");
                    if let Some((_, mut extension_peer)) = extension_fixture {
                        let mut start = read_frame(&mut extension_peer).unwrap();
                        assert_eq!(start.header(), 5);
                        start.read_string().unwrap(); start.read_i32().unwrap();
                        let version = start.read_string().unwrap(); start.read_string().unwrap(); start.read_string().unwrap();
                        assert!(PacketInfoManager::read_from(version, &mut start).unwrap().entries().is_empty());
                        let packet = Packet::new(77);
                        let pipeline = state.clone();
                        let forward = tokio::spawn(async move { pipeline.packet(Direction::ToServer, packet, false).await });
                        let mut intercepted = read_frame(&mut extension_peer).unwrap();
                        assert_eq!(intercepted.header(), 3);
                        let message = Message::parse(&intercepted.read_long_string().unwrap()).unwrap();
                        write_frame(&mut extension_peer, &extension::manipulated(&message).unwrap()).unwrap();
                        assert_eq!(forward.await.unwrap().unwrap().unwrap().header(), 77);
                        state.close(&peer);
                        assert_eq!(read_frame(&mut extension_peer).unwrap().header(), 6);
                    }
                }
                let error = done_rx.recv_timeout(Duration::from_secs(15)).unwrap();
                match mode {
                    "success" | "stall" | "cache_success" | "cache_failure" | "cache_stall" => assert!(error.is_none(), "{error:?}"),
                    "failure" => assert!(error.unwrap().contains("503")),
                    "oversized" => assert!(error.unwrap().contains("8 MiB")),
                    "malformed" | "truncated" => assert!(error.is_some(), "{mode} unexpectedly succeeded"),
                    _ => unreachable!(),
                }
                tokio::time::timeout(Duration::from_secs(15), server).await.unwrap().unwrap();
                if matches!(mode, "stall" | "cache_stall") { assert!(!receiver.try_iter().any(|event| matches!(event, Event::PacketIdentifiers(_) | Event::Connected(_)))); }
                if let Some(path) = cache {
                    let cached = PacketInfoManager::load_cache(&path, NITRO_REVISION).unwrap();
                    assert_eq!(cached.entries()[0].header, if mode == "cache_failure" { 899 } else { 900 });
                }
                state.close(&peer);
            }
            // Exercise the actual Origins discovery and metadata sequence over
            // the same locally trusted HTTPS transport, with an isolated cache.
            for mode in ["latest", "fallback", "empty"] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = format!("localhost:{}", listener.local_addr().unwrap().port());
                let server_config = authority.gen_server_config(&address.parse().unwrap()).await;
                let expected = match mode { "latest" => "LATEST", "empty" => "EMPTY", _ => "OLD" };
                let server = tokio::spawn(async move {
                    for index in 0..2 {
                        let (stream, _) = listener.accept().await.unwrap();
                        let mut tls = tokio_rustls::TlsAcceptor::from(server_config.clone()).accept(stream).await.unwrap();
                        let mut request = Vec::new();
                        while !request.ends_with(b"\r\n\r\n") {
                            let mut byte = [0]; tls.read_exact(&mut byte).await.unwrap(); request.push(byte[0]); assert!(request.len() < 8192);
                        }
                        let expected_path = if index == 0 { "/releases?variant=shockwave-windows".to_owned() } else { format!("/releases/shockwave-windows/{expected}/messages") };
                        assert!(request.starts_with(format!("GET {expected_path} HTTP/1.1\r\n").as_bytes()));
                        let status = if index == 0 && mode == "fallback" { "503 Service Unavailable" } else { "200 OK" };
                        let body = if index == 0 { format!(r#"[{{"version":"{expected}"}}]"#) } else if mode == "empty" { r#"{"messages":{"incoming":[],"outgoing":[]}}"#.to_owned() } else { r#"{"messages":{"incoming":[],"outgoing":[{"id":900,"name":"KnownComposer"}]}}"#.to_owned() };
                        let headers = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                        tls.write_all(headers.as_bytes()).await.unwrap(); tls.write_all(body.as_bytes()).await.unwrap(); tls.shutdown().await.unwrap();
                    }
                });
                let agent = agent.clone();
                let base_url = format!("https://{address}");
                let cache_dir = directory.0.clone();
                let database = tokio::task::spawn_blocking(move || PacketInfoManager::fetch_sulek_using("OLD", true, &agent, &base_url, &cache_dir)).await.unwrap().unwrap();
                assert_eq!(database.version, if mode == "empty" { "OLD" } else { expected });
                assert_eq!(database.entries().len(), usize::from(mode != "empty"));
                let saved = PacketInfoManager::load_cache(&directory.0.join(format!("SHOCKWAVE-{expected}.bin")), expected).unwrap();
                assert_eq!(saved.entries().len(), database.entries().len());
                tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
            }
            // Keep the first HTTPS response pending while a replacement session
            // receives a second response and writes the same cache file.
            let cache = directory.0.join("race.bin");
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = format!("localhost:{}", listener.local_addr().unwrap().port());
            let server_config = authority.gen_server_config(&address.parse().unwrap()).await;
            let (started_tx, started_rx) = mpsc::channel();
            let (release_tx, release_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let mut release_rx = Some(release_rx);
                let mut tasks = Vec::new();
                for index in 0..2 {
                    let (stream, _) = listener.accept().await.unwrap();
                    let config = server_config.clone();
                    let started = started_tx.clone();
                    let release = if index == 0 { release_rx.take() } else { None };
                    tasks.push(tokio::spawn(async move {
                        let mut tls = tokio_rustls::TlsAcceptor::from(config).accept(stream).await.unwrap();
                        let mut request = Vec::new();
                        while !request.ends_with(b"\r\n\r\n") {
                            let mut byte = [0];
                            tls.read_exact(&mut byte).await.unwrap();
                            request.push(byte[0]);
                            assert!(request.len() < 8192);
                        }
                        started.send(index).unwrap();
                        if let Some(release) = release { release.await.unwrap(); }
                        let id = if index == 0 { 901 } else { 902 };
                        let body = format!(r#"{{"messages":{{"incoming":[],"outgoing":[{{"id":{id},"name":"KnownComposer"}}]}}}}"#);
                        let headers = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                        tls.write_all(headers.as_bytes()).await.unwrap();
                        tls.write_all(body.as_bytes()).await.unwrap();
                        tls.shutdown().await.unwrap();
                    }));
                }
                for task in tasks { task.await.unwrap(); }
            });
            let (host, host_events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
            let mut extension_peer = TcpStream::connect(host.address).unwrap();
            extension_peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            assert_eq!(read_frame(&mut extension_peer).unwrap().header(), 2);
            let info = ExtensionInfo { title: "fixture".into(), author: "test".into(), version: "1".into(), description: String::new(), on_click: false, file: None, cookie: String::new(), can_leave: true, can_delete: true };
            write_frame(&mut extension_peer, &extension::info_response(&info).unwrap()).unwrap();
            let id = match host_events.recv_timeout(Duration::from_secs(3)).unwrap() { HostEvent::Pending { id, .. } => id, event => panic!("{event:?}") };
            host.approve(id).unwrap();
            assert_eq!(read_frame(&mut extension_peer).unwrap().header(), 7);
            let mut options = WebOptions::new("127.0.0.1:0".parse().unwrap(), PathBuf::new());
            options.extensions = Some(host.clone());
            let url = format!("https://{address}/fixture");
            let worker_cache = cache.clone();
            let (finished_tx, finished_rx) = mpsc::channel();
            let agent = agent.clone();
            options.nitro_lookup = Some(Arc::new(move || {
                let result = PacketInfoManager::load_or_refresh(&worker_cache, NITRO_REVISION, std::time::SystemTime::now() + Duration::from_secs(301), || {
                    download_json(&agent, &url).and_then(|bytes| PacketInfoManager::from_json(NITRO_REVISION, &bytes).map_err(io::Error::other))
                });
                finished_tx.send(result.as_ref().map(|db| db.entries()[0].header).unwrap_or(0)).unwrap();
                result
            }));
            let (events, receiver) = mpsc::sync_channel(32);
            let state = Arc::new(Shared { options, hartico_key: Mutex::new(None), city_keys: Mutex::new(None), peers: Mutex::new(HashMap::new()), active: Mutex::new(None), rules: Mutex::new(Rules::default()), pipeline: Mutex::new(()), events, index: AtomicI32::new(0), stop: AtomicBool::new(false) });
            let peer = |port| Arc::new(Peer::new(PeerKey { client: format!("127.0.0.1:{port}").parse().unwrap(), uri: "ws://fixture".into() }, Modifier::new(&crate::nitro::HotelKind::Plain).unwrap()));
            let old = peer(1234); let new = peer(1235);
            let old_state = state.clone(); let old_peer = old.clone();
            let old_task = tokio::spawn(async move { old_state.activate(&old_peer, &"ws://fixture".parse().unwrap()).await });
            assert_eq!(started_rx.recv_timeout(Duration::from_secs(3)).unwrap(), 0);
            state.close(&old);
            assert_eq!(tokio::time::timeout(Duration::from_secs(2), old_task).await.unwrap().unwrap().unwrap_err().kind(), io::ErrorKind::Interrupted);
            state.activate(&new, &"ws://fixture".parse().unwrap()).await.unwrap();
            assert_eq!(started_rx.recv_timeout(Duration::from_secs(3)).unwrap(), 1);
            assert_eq!(finished_rx.recv_timeout(Duration::from_secs(3)).unwrap(), 902);
            let mut start = read_frame(&mut extension_peer).unwrap();
            assert_eq!(start.header(), 5);
            start.read_string().unwrap(); start.read_i32().unwrap();
            let version = start.read_string().unwrap(); start.read_string().unwrap(); start.read_string().unwrap();
            assert_eq!(PacketInfoManager::read_from(version, &mut start).unwrap().entries()[0].header, 902);
            release_tx.send(()).unwrap();
            assert_eq!(finished_rx.recv_timeout(Duration::from_secs(3)).unwrap(), 901);
            assert_eq!(PacketInfoManager::load_cache(&cache, NITRO_REVISION).unwrap().entries()[0].header, 902);
            assert!(!receiver.try_iter().any(|event| matches!(event, Event::PacketIdentifiers(db) if db.entries().first().is_some_and(|entry| entry.header == 901))));
            state.close(&new);
            assert_eq!(read_frame(&mut extension_peer).unwrap().header(), 6);
            host.stop();
            tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
        });
        let test_directory = directory.0.clone();
        drop(directory);
        assert!(
            !test_directory.exists(),
            "HTTPS fixture left temporary files"
        );
    }

    #[test]
    fn nitro_discards_metadata_from_another_revision_without_extension_host() {
        use crate::{packet_info::PacketInfo, packet_safety::PacketSafety};
        for original in ["OLD", ""] {
            let safety = Arc::new(Mutex::new(PacketSafety::default()));
            let mut options = WebOptions::new("127.0.0.1:0".parse().unwrap(), PathBuf::new());
            options.packet_safety = Some(safety.clone());
            options.fetch_packet_info = false;
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
