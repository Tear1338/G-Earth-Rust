//! Cancellable nonblocking relay for EVA_WIRE, negotiated Flash and Origins.
use crate::packet::{Direction, FrameDecoder, Message, Packet};
use crate::rules::Rules;
use crate::{
    crypto::Rc4,
    extension_host::{ConnectionDetails, ExtensionHost},
    socks::SocksConfig,
};
use crate::{packet::PacketFormat, shockwave::ShockwaveTransport};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc::{self, Receiver, SyncSender},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;
const MAX_METADATA_LOOKUPS: usize = 4;
static ACTIVE_METADATA_LOOKUPS: AtomicUsize = AtomicUsize::new(0);

// The HTTP client cannot interrupt a request already in flight. Bound detached
// lookups and let the relay stop without waiting for their network timeout.
fn cancellable_metadata_lookup<T: Send + 'static>(
    stop: &AtomicBool,
    closed: &AtomicBool,
    mut peer_closed: impl FnMut() -> bool,
    lookup: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    if stop.load(Ordering::Acquire) || closed.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "metadata lookup cancelled",
        ));
    }
    let mut count = ACTIVE_METADATA_LOOKUPS.load(Ordering::Acquire);
    loop {
        if count >= MAX_METADATA_LOOKUPS {
            return Err(io::Error::other(
                "too many metadata lookups still in progress",
            ));
        }
        match ACTIVE_METADATA_LOOKUPS.compare_exchange_weak(
            count,
            count + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(actual) => count = actual,
        }
    }
    struct LookupSlot;
    impl Drop for LookupSlot {
        fn drop(&mut self) {
            ACTIVE_METADATA_LOOKUPS.fetch_sub(1, Ordering::AcqRel);
        }
    }
    let slot = LookupSlot;
    let (tx, rx) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("relay-metadata".into())
        .spawn(move || {
            let _slot = slot;
            let _ = tx.send(lookup());
        })?;
    loop {
        if stop.load(Ordering::Acquire) || closed.load(Ordering::Acquire) || peer_closed() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "metadata lookup cancelled",
            ));
        }
        match rx.recv_timeout(Duration::from_millis(25)) {
            Ok(result) => {
                if stop.load(Ordering::Acquire) || closed.load(Ordering::Acquire) || peer_closed() {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "metadata lookup cancelled",
                    ));
                }
                return result;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("metadata lookup worker failed"))
            }
        }
    }
}

fn peer_has_closed(stream: &TcpStream) -> bool {
    match stream.peek(&mut [0u8; 1]) {
        Ok(0) => true,
        Ok(_) => false,
        Err(error) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::NotConnected
        ),
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Status(String),
    PacketIdentifiers(crate::packet_info::PacketInfoManager),
    Identified { version: String, identifier: String },
    Listening(SocketAddr),
    Connected(String),
    Disconnected,
    Packet(Message),
    Error(String),
}
pub struct Config {
    pub listen: SocketAddr,
    pub remote: String,
}
#[derive(Clone, Default)]
pub struct RelayOptions {
    pub flash_process: Option<u32>,
    pub shockwave: bool,
    pub extensions: Option<Arc<ExtensionHost>>,
    pub connection: Option<ConnectionDetails>,
    pub socks: Option<SocksConfig>,
    pub outgoing_rc4: Option<Rc4>,
    pub incoming_rc4: Option<Rc4>,
    /// Optional session-shared registry for tracking IDs from real traffic.
    pub packet_safety: Option<Arc<Mutex<crate::packet_safety::PacketSafety>>>,
    pub admin_service: Option<Arc<Mutex<crate::admin_service::AdminService>>>,
    /// Disable automatic Origins metadata retrieval for offline use.
    pub disable_origins_metadata: bool,
    #[cfg(test)]
    flash_lookup: Option<
        Arc<dyn Fn(String) -> io::Result<crate::packet_info::PacketInfoManager> + Send + Sync>,
    >,
    #[cfg(test)]
    origins_lookup: Option<
        Arc<dyn Fn(String) -> io::Result<crate::packet_info::PacketInfoManager> + Send + Sync>,
    >,
}
struct Session {
    injections: SyncSender<(Direction, Packet)>,
    closed: Arc<AtomicBool>,
    flash_automatic: bool,
    schedule_metadata: Mutex<Option<(String, Arc<crate::packet_info::PacketInfoManager>)>>,
}

/// A catalog snapshot bound to exactly one active TCP relay session.
pub struct TcpScheduleContext {
    session: Arc<Session>,
    pub version: String,
    pub packets: Arc<crate::packet_info::PacketInfoManager>,
}

pub type FlashScheduleContext = TcpScheduleContext;

pub enum FlashScheduleState {
    NotAutomatic,
    Pending,
    Ready(FlashScheduleContext),
}

pub struct Relay {
    stop: Arc<AtomicBool>,
    active: Arc<Mutex<Option<Arc<Session>>>>,
    worker: Option<JoinHandle<()>>,
    rules: Arc<Mutex<Rules>>,
    pub address: SocketAddr,
}
impl Relay {
    pub fn start(config: Config) -> io::Result<(Self, Receiver<Event>)> {
        Self::start_with_options(config, RelayOptions::default())
    }
    pub fn start_with_options(
        config: Config,
        options: RelayOptions,
    ) -> io::Result<(Self, Receiver<Event>)> {
        Self::start_inner(config, options, None)
    }
    pub(crate) fn start_raw(
        config: Config,
        options: RelayOptions,
        upstream: VecDeque<TcpStream>,
    ) -> io::Result<(Self, Receiver<Event>)> {
        Self::start_inner(config, options, Some(upstream))
    }
    fn start_inner(
        config: Config,
        options: RelayOptions,
        raw_upstream: Option<VecDeque<TcpStream>>,
    ) -> io::Result<(Self, Receiver<Event>)> {
        if options.flash_process.is_some()
            && (options.shockwave
                || options.outgoing_rc4.is_some()
                || options.incoming_rc4.is_some())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "automatic Flash discovery cannot be combined with Origins or explicit keys",
            ));
        }
        if options.shockwave && (options.outgoing_rc4.is_some() || options.incoming_rc4.is_some()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Origins negotiates its own crypto; remove explicit RC4 keys",
            ));
        }
        let raw = raw_upstream.is_some();
        if raw {
            if !config.listen.is_ipv4() || !config.listen.ip().is_unspecified() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Raw-IP listen address must be 0.0.0.0",
                ));
            }
            if options.socks.is_none()
                && raw_upstream
                    .as_ref()
                    .is_none_or(|upstream| upstream.is_empty())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "direct Raw-IP relay requires preconnected server sockets",
                ));
            }
        } else if !config.listen.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "listen address must be loopback",
            ));
        }
        let remote: Vec<SocketAddr> = if raw || options.socks.is_some() {
            Vec::new()
        } else {
            config.remote.to_socket_addrs()?.collect()
        };
        if !raw && remote.is_empty() && options.socks.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "remote has no addresses",
            ));
        }
        let listener = TcpListener::bind(config.listen)?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let (events, rx) = mpsc::sync_channel(2048);
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(Mutex::new(None));
        let rules = Arc::new(Mutex::new(Rules::default()));
        let (worker_stop, worker_active, worker_rules) =
            (stop.clone(), active.clone(), rules.clone());
        let worker = thread::spawn(move || {
            let mut raw_upstream = raw_upstream;
            let _ = events.try_send(Event::Listening(address));
            let mut index = 0i32;
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((client, _)) => {
                        let mut session_options = options.clone();
                        if session_options.flash_process == Some(0) {
                            if let Some(pid) = client.peer_addr().ok().and_then(|address| {
                                client.local_addr().ok().and_then(|remote| {
                                    gearth_platform::tcp_owner(address, remote).ok().flatten()
                                })
                            }) {
                                session_options.flash_process = Some(pid);
                                let _ = events.try_send(Event::Status(format!(
                                    "Flash client process: {pid}"
                                )));
                            }
                        }
                        let server = if let Some(socks) = &options.socks {
                            socks
                                .connect(&config.remote)
                                .map_err(|error| format!("SOCKS connection failed: {error}"))
                        } else if let Some(upstream) = &mut raw_upstream {
                            upstream.pop_front().ok_or_else(|| {
                                "preconnected Raw-IP server sockets exhausted".to_string()
                            })
                        } else {
                            let mut last_error = None;
                            let mut connected = None;
                            for addr in &remote {
                                if worker_stop.load(Ordering::Acquire) {
                                    break;
                                }
                                match TcpStream::connect_timeout(addr, Duration::from_secs(2)) {
                                    Ok(stream) => {
                                        connected = Some(stream);
                                        break;
                                    }
                                    Err(error) => last_error = Some(error),
                                }
                            }
                            connected.ok_or_else(|| match last_error {
                                Some(error) => format!("remote connection failed: {error}"),
                                None => "remote connection cancelled".to_string(),
                            })
                        };
                        let server = match server {
                            Ok(server) => server,
                            Err(error) => {
                                if !worker_stop.load(Ordering::Acquire) {
                                    let _ = events.try_send(Event::Error(error));
                                }
                                continue;
                            }
                        };
                        let (injections, commands) = mpsc::sync_channel(256);
                        if let Some(service) = &session_options.admin_service {
                            if let Ok(mut service) = service.lock() {
                                service.on_connect();
                            }
                        }
                        let closed = Arc::new(AtomicBool::new(false));
                        let session = Arc::new(Session {
                            injections,
                            closed: closed.clone(),
                            flash_automatic: session_options.flash_process.is_some(),
                            schedule_metadata: Mutex::new(None),
                        });
                        if let Ok(mut slot) = worker_active.lock() {
                            if worker_stop.load(Ordering::Acquire) {
                                break;
                            }
                            *slot = Some(session.clone());
                        } else {
                            break;
                        }
                        if session_options.shockwave {
                            if session_options.connection.is_none() {
                                let remote = server.peer_addr().ok();
                                session_options.connection = Some(ConnectionDetails {
                                    host: remote.map(|a| a.ip().to_string()).unwrap_or_default(),
                                    port: remote.map(|a| a.port()).unwrap_or_default(),
                                    version: "latest".into(),
                                    identifier: "SHOCKWAVE".into(),
                                    client_type: "SHOCKWAVE".into(),
                                    packets: crate::packet_info::PacketInfoManager::default(),
                                });
                            }
                            let details = session_options.connection.as_mut().unwrap();
                            if details.version.is_empty() {
                                details.version = "latest".into();
                            }
                            if details.identifier.is_empty() {
                                details.identifier = "SHOCKWAVE".into();
                            }
                            if !details.packets.entries().is_empty()
                                && details.packets.version != details.version
                            {
                                details.packets = crate::packet_info::PacketInfoManager::new(
                                    &details.version,
                                    Vec::new(),
                                );
                            }
                            if !session_options.disable_origins_metadata
                                && details.packets.entries().is_empty()
                            {
                                let setup = client
                                    .set_nonblocking(true)
                                    .and_then(|()| server.set_nonblocking(true));
                                let version = details.version.clone();
                                let socks = session_options.socks.clone();
                                #[cfg(test)]
                                let lookup = session_options.origins_lookup.clone();
                                let result = setup.and_then(|()| {
                                    cancellable_metadata_lookup(
                                        &worker_stop,
                                        &closed,
                                        || peer_has_closed(&client) || peer_has_closed(&server),
                                        move || {
                                            #[cfg(test)]
                                            if let Some(lookup) = lookup {
                                                return lookup(version);
                                            }
                                            crate::packet_info::PacketInfoManager::fetch_sulek_for_proxy(
                                                &version, true, socks,
                                            )
                                        },
                                    )
                                });
                                match result {
                                    Ok(database) => {
                                        details.version = database.version.clone();
                                        details.packets = database.clone();
                                        let _ = events.try_send(Event::Identified {
                                            version: details.version.clone(),
                                            identifier: details.identifier.clone(),
                                        });
                                        let _ = events.try_send(Event::PacketIdentifiers(database));
                                    }
                                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                                        closed.store(true, Ordering::Release);
                                        if let Ok(mut slot) = worker_active.lock() {
                                            *slot = None;
                                        }
                                        continue;
                                    }
                                    Err(error) => {
                                        let _ = events.try_send(Event::Status(format!(
                                            "Connected without packet names: {error}"
                                        )));
                                    }
                                }
                            }
                        }
                        if worker_stop.load(Ordering::Acquire) || closed.load(Ordering::Acquire) {
                            closed.store(true, Ordering::Release);
                            if let Ok(mut slot) = worker_active.lock() {
                                *slot = None;
                            }
                            continue;
                        }
                        if session_options.flash_process.is_none() {
                            if let (Some(safety), Some(details)) =
                                (&session_options.packet_safety, &session_options.connection)
                            {
                                if let Ok(mut safety) = safety.lock() {
                                    safety.register_metadata(&details.version, &details.packets);
                                }
                            }
                            let (version, packets) = session_options
                                .connection
                                .as_ref()
                                .map(|details| (details.version.clone(), details.packets.clone()))
                                .unwrap_or_default();
                            if let Ok(mut metadata) = session.schedule_metadata.lock() {
                                *metadata = Some((version, Arc::new(packets)));
                            }
                        }
                        let _ = events.try_send(Event::Connected(
                            server
                                .peer_addr()
                                .map(|v| v.to_string())
                                .unwrap_or_default(),
                        ));
                        let mut extension_session = None;
                        if let (Some(host), Some(details)) =
                            (&session_options.extensions, &session_options.connection)
                        {
                            if session_options.flash_process.is_none() {
                                match host.start_owned_connection(details.clone()) {
                                    Ok(epoch) => extension_session = Some(epoch),
                                    Err(e) => {
                                        let _ = events.try_send(Event::Error(e.to_string()));
                                    }
                                }
                            }
                        }
                        let result = run_session(
                            client,
                            server,
                            &worker_stop,
                            &closed,
                            &worker_rules,
                            &events,
                            commands,
                            &mut index,
                            &session_options,
                            &mut extension_session,
                            &session.schedule_metadata,
                        );
                        if let (Some(host), Some(epoch)) = (&options.extensions, extension_session)
                        {
                            host.end_owned_connection(epoch);
                        }
                        closed.store(true, Ordering::Release);
                        if let Ok(mut slot) = worker_active.lock() {
                            *slot = None;
                        }
                        let _ = events.try_send(Event::Disconnected);
                        // Report the cause last so a desktop processing both
                        // events keeps the actionable error in its status bar.
                        if let Err(e) = result {
                            let _ = events.try_send(Event::Error(e.to_string()));
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => {
                        let _ = events.try_send(Event::Error(e.to_string()));
                        break;
                    }
                }
            }
        });
        Ok((
            Self {
                stop,
                active,
                worker: Some(worker),
                rules,
                address,
            },
            rx,
        ))
    }
    pub fn set_rules(&self, rules: Rules) -> io::Result<()> {
        *self
            .rules
            .lock()
            .map_err(|_| io::Error::other("rules lock poisoned"))? = rules;
        Ok(())
    }
    pub fn connected(&self) -> bool {
        self.active
            .lock()
            .map(|s| {
                s.as_ref()
                    .is_some_and(|s| !s.closed.load(Ordering::Acquire))
            })
            .unwrap_or(false)
    }
    /// Read catalog metadata from the active session after it finishes initialization.
    pub fn schedule_context(&self) -> Option<TcpScheduleContext> {
        let active = self.active.lock().ok()?;
        let session = active
            .as_ref()
            .filter(|s| !s.closed.load(Ordering::Acquire))?;
        let metadata = session.schedule_metadata.lock().ok()?;
        let (version, packets) = metadata.as_ref()?;
        Some(TcpScheduleContext {
            session: session.clone(),
            version: version.clone(),
            packets: packets.clone(),
        })
    }
    /// Queue an injection only if the catalog and session are still current.
    pub fn inject_for_session(
        &self,
        context: &TcpScheduleContext,
        direction: Direction,
        packet: Packet,
    ) -> io::Result<()> {
        self.inject_for_flash_session(context, direction, packet)
    }
    /// Update the active catalog only if its nonempty revision matches.
    pub fn update_schedule_metadata(&self, packets: crate::packet_info::PacketInfoManager) -> bool {
        let Ok(active) = self.active.lock() else {
            return false;
        };
        let Some(session) = active
            .as_ref()
            .filter(|s| !s.closed.load(Ordering::Acquire))
        else {
            return false;
        };
        let Ok(mut metadata) = session.schedule_metadata.lock() else {
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
    /// Snapshot metadata only after this automatic Flash session has identified itself.
    pub fn flash_schedule_state(&self) -> FlashScheduleState {
        let Ok(active) = self.active.lock() else {
            return FlashScheduleState::Pending;
        };
        let Some(session) = active
            .as_ref()
            .filter(|s| !s.closed.load(Ordering::Acquire))
        else {
            return FlashScheduleState::Pending;
        };
        if !session.flash_automatic {
            return FlashScheduleState::NotAutomatic;
        }
        let Ok(metadata) = session.schedule_metadata.lock() else {
            return FlashScheduleState::Pending;
        };
        match metadata.as_ref() {
            Some((version, packets)) => FlashScheduleState::Ready(TcpScheduleContext {
                session: session.clone(),
                version: version.clone(),
                packets: packets.clone(),
            }),
            None => FlashScheduleState::Pending,
        }
    }
    /// Reject a schedule resolved for a session that was replaced in the meantime.
    pub fn inject_for_flash_session(
        &self,
        context: &FlashScheduleContext,
        direction: Direction,
        packet: Packet,
    ) -> io::Result<()> {
        let active = self
            .active
            .lock()
            .map_err(|_| io::Error::other("session lock poisoned"))?;
        let session = active
            .as_ref()
            .filter(|session| {
                Arc::ptr_eq(session, &context.session) && !session.closed.load(Ordering::Acquire)
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "TCP session changed"))?;
        let metadata = session
            .schedule_metadata
            .lock()
            .map_err(|_| io::Error::other("metadata lock poisoned"))?;
        if !metadata
            .as_ref()
            .is_some_and(|(_, packets)| Arc::ptr_eq(packets, &context.packets))
        {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "TCP metadata changed",
            ));
        }
        session
            .injections
            .try_send((direction, packet))
            .map_err(|e| match e {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "injection queue full")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::NotConnected, "session closed")
                }
            })
    }
    /// Apply an explicitly downloaded catalog only to the identified matching revision.
    pub fn update_flash_schedule_metadata(
        &self,
        packets: crate::packet_info::PacketInfoManager,
    ) -> bool {
        let Ok(active) = self.active.lock() else {
            return false;
        };
        let Some(session) = active
            .as_ref()
            .filter(|s| s.flash_automatic && !s.closed.load(Ordering::Acquire))
        else {
            return false;
        };
        let Ok(mut metadata) = session.schedule_metadata.lock() else {
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
    /// Queue an injection. Delivery errors are reported through Event::Error.
    pub fn inject(&self, direction: Direction, packet: Packet) -> io::Result<()> {
        let active = self
            .active
            .lock()
            .map_err(|_| io::Error::other("session lock poisoned"))?;
        let session = active
            .as_ref()
            .filter(|s| !s.closed.load(Ordering::Acquire))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no active client"))?;
        session
            .injections
            .try_send((direction, packet))
            .map_err(|e| match e {
                mpsc::TrySendError::Full(_) => {
                    io::Error::new(io::ErrorKind::WouldBlock, "injection queue full")
                }
                mpsc::TrySendError::Disconnected(_) => {
                    io::Error::new(io::ErrorKind::NotConnected, "session closed")
                }
            })
    }
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(active) = self.active.lock() {
            if let Some(s) = active.as_ref() {
                s.closed.store(true, Ordering::Release);
            }
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.stop();
    }
}
struct Pending {
    bytes: Vec<u8>,
    offset: usize,
}
#[derive(Default)]
struct Output {
    queue: VecDeque<Pending>,
    bytes: usize,
    cipher: Option<Rc4>,
}
impl Output {
    fn push(&mut self, packet: Packet) -> io::Result<()> {
        self.push_wire(packet.bytes().to_vec())
    }
    fn push_wire(&mut self, mut bytes: Vec<u8>) -> io::Result<()> {
        if self.bytes + bytes.len() > MAX_PENDING_BYTES {
            return Err(io::Error::other("peer output queue limit exceeded"));
        }
        self.bytes += bytes.len();
        if let Some(cipher) = &mut self.cipher {
            cipher.apply(&mut bytes);
        }
        self.queue.push_back(Pending { bytes, offset: 0 });
        Ok(())
    }
    fn flush(&mut self, stream: &mut impl Write) -> io::Result<bool> {
        let mut progress = false;
        for _ in 0..64 {
            let Some(frame) = self.queue.front_mut() else {
                break;
            };
            match stream.write(&frame.bytes[frame.offset..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "peer stopped accepting data",
                    ))
                }
                Ok(n) => {
                    frame.offset += n;
                    self.bytes -= n;
                    progress = true;
                    if frame.offset == frame.bytes.len() {
                        self.queue.pop_front();
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(progress)
    }
}
// A blocked peer must not indefinitely prevent stopping or accepting a new session.
fn drain_outputs(
    client: &mut TcpStream,
    server: &mut TcpStream,
    to_client: &mut Output,
    to_server: &mut Output,
    stop: &AtomicBool,
    closed: &AtomicBool,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !to_client.queue.is_empty() || !to_server.queue.is_empty() {
        if stop.load(Ordering::Acquire) || closed.load(Ordering::Acquire) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out flushing queued packets after disconnect",
            ));
        }
        let progress = to_server.flush(server)? | to_client.flush(client)?;
        if !progress {
            thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_session(
    mut client: TcpStream,
    mut server: TcpStream,
    stop: &AtomicBool,
    closed: &AtomicBool,
    rules: &Mutex<Rules>,
    events: &SyncSender<Event>,
    commands: Receiver<(Direction, Packet)>,
    index: &mut i32,
    options: &RelayOptions,
    extension_session: &mut Option<u64>,
    schedule_metadata: &Mutex<Option<(String, Arc<crate::packet_info::PacketInfoManager>)>>,
) -> io::Result<()> {
    client.set_nonblocking(true)?;
    server.set_nonblocking(true)?;
    client.set_nodelay(true)?;
    server.set_nodelay(true)?;
    let mut to_server = Output {
        cipher: options.outgoing_rc4.clone(),
        ..Default::default()
    };
    let mut to_client = Output {
        cipher: options.incoming_rc4.clone(),
        ..Default::default()
    };
    let mut decrypt_outgoing = options.outgoing_rc4.clone();
    let mut decrypt_incoming = options.incoming_rc4.clone();
    let mut from_client = FrameDecoder::default();
    let mut from_server = FrameDecoder::default();
    let mut buffer = [0u8; 8192];
    let mut shockwave = if options.shockwave {
        Some(ShockwaveTransport::new()?)
    } else {
        None
    };
    let mut flash = options
        .flash_process
        .map(|_| crate::flash::FlashSession::default());
    let mut safety_revision = options
        .connection
        .as_ref()
        .map(|details| details.version.clone())
        .unwrap_or_default();
    while !stop.load(Ordering::Acquire) && !closed.load(Ordering::Acquire) {
        let mut progress = false;
        let mut injected: Vec<_> = commands.try_iter().take(64).collect();
        if let (Some(host), Some(epoch)) = (&options.extensions, *extension_session) {
            injected.extend(host.take_owned_injections(epoch)?);
        }
        for (direction, packet) in injected {
            let message = Message {
                packet,
                direction,
                index: *index,
                blocked: false,
            };
            *index = index.wrapping_add(1);
            let expected = if options.shockwave {
                if direction == Direction::ToServer {
                    PacketFormat::WedgieOutgoing
                } else {
                    PacketFormat::WedgieIncoming
                }
            } else {
                PacketFormat::EvaWire
            };
            if message.packet.format() != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "injected packet format does not match active client",
                ));
            }
            if let Some(shock) = &mut shockwave {
                match direction {
                    Direction::ToServer => {
                        to_server.push_wire(shock.encode_to_server(&message.packet)?)?
                    }
                    Direction::ToClient => {
                        to_client.push_wire(shock.encode_to_client(&message.packet)?)?
                    }
                }
            } else if let Some(flash) = &mut flash {
                let encrypted = flash.encrypted(direction);
                let bytes = flash.encode(direction, &message.packet, encrypted)?;
                match direction {
                    Direction::ToServer => to_server.push_wire(bytes)?,
                    Direction::ToClient => to_client.push_wire(bytes)?,
                }
            } else {
                match direction {
                    Direction::ToServer => to_server.push(message.packet.clone())?,
                    Direction::ToClient => to_client.push(message.packet.clone())?,
                }
            }
            let _ = events.try_send(Event::Packet(message));
            progress = true;
        }
        for direction in [Direction::ToServer, Direction::ToClient] {
            let (input, decoder, output) = match direction {
                Direction::ToServer => (&mut client, &mut from_client, &mut to_server),
                Direction::ToClient => (&mut server, &mut from_server, &mut to_client),
            };
            let n = match input.read(&mut buffer) {
                Ok(0) => {
                    let pending_bytes = decoder.pending_bytes();
                    drain_outputs(
                        &mut client,
                        &mut server,
                        &mut to_client,
                        &mut to_server,
                        stop,
                        closed,
                    )?;
                    if flash.is_none() && shockwave.is_none() && pending_bytes != 0 {
                        let peer = if direction == Direction::ToServer {
                            "client"
                        } else {
                            "server"
                        };
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "{peer} closed with an incomplete packet ({} buffered bytes)",
                                pending_bytes
                            ),
                        ));
                    }
                    return Ok(());
                }
                Ok(n) => {
                    progress = true;
                    n
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    0
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    return Ok(())
                }
                Err(e) => return Err(e),
            };
            let decrypt = if direction == Direction::ToServer {
                &mut decrypt_outgoing
            } else {
                &mut decrypt_incoming
            };
            if let Some(cipher) = decrypt {
                cipher.apply(&mut buffer[..n]);
            }
            let packets: Vec<(Packet, bool)> = if let Some(flash) = &mut flash {
                flash
                    .feed(direction, &buffer[..n])?
                    .into_iter()
                    .map(|p| (p.packet, p.encrypted))
                    .collect()
            } else if let Some(shock) = &mut shockwave {
                let packets = if direction == Direction::ToServer {
                    shock.client_packets(&buffer[..n])?
                } else {
                    shock.server_packets(&buffer[..n])?
                };
                packets.into_iter().map(|p| (p, false)).collect()
            } else {
                decoder.push(&buffer[..n]).map_err(io::Error::other)?;
                let mut packets = Vec::new();
                while let Some(p) = decoder.next_packet().map_err(io::Error::other)? {
                    packets.push((p, false));
                }
                packets
            };
            if let Some(flash) = &mut flash {
                if let Some(identity) = flash.take_identity() {
                    safety_revision.clone_from(&identity.version);
                    let _ = events.try_send(Event::Identified {
                        version: identity.version.clone(),
                        identifier: identity.identifier.clone(),
                    });
                    if let Some(details) = &options.connection {
                        let mut details = details.clone();
                        details.version = identity.version;
                        details.identifier = identity.identifier;
                        if !details.packets.entries().is_empty()
                            && (details.version.is_empty()
                                || details.packets.version != details.version)
                        {
                            let _ = events.try_send(Event::Status(format!(
                                "Ignoring Flash packet identifiers for revision {:?}; detected {:?}",
                                details.packets.version, details.version
                            )));
                            details.packets = crate::packet_info::PacketInfoManager::new(
                                &details.version,
                                Vec::new(),
                            );
                            let _ =
                                events.try_send(Event::PacketIdentifiers(details.packets.clone()));
                        }
                        if details.packets.entries().is_empty() {
                            let _ = events.try_send(Event::Status(
                                "Loading packet identifiers for the detected Flash revision..."
                                    .into(),
                            ));
                            let version = details.version.clone();
                            let socks = options.socks.clone();
                            #[cfg(test)]
                            let lookup = options.flash_lookup.clone();
                            match cancellable_metadata_lookup(
                                stop,
                                closed,
                                || peer_has_closed(&client) || peer_has_closed(&server),
                                move || {
                                    #[cfg(test)]
                                    if let Some(lookup) = lookup {
                                        return lookup(version);
                                    }
                                    crate::packet_info::PacketInfoManager::fetch_sulek_for_proxy(
                                        &version, false, socks,
                                    )
                                },
                            ) {
                                Ok(database) => {
                                    let _ =
                                        events.try_send(Event::PacketIdentifiers(database.clone()));
                                    details.packets = database;
                                }
                                Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(()),
                                Err(e) => {
                                    let _ = events.try_send(Event::Status(format!(
                                        "Connected without packet names: {e}"
                                    )));
                                }
                            }
                            if stop.load(Ordering::Acquire) || closed.load(Ordering::Acquire) {
                                return Ok(());
                            }
                        }
                        if let Some(safety) = &options.packet_safety {
                            if let Ok(mut safety) = safety.lock() {
                                safety.register_metadata(&details.version, &details.packets);
                            }
                        }
                        if let Ok(mut metadata) = schedule_metadata.lock() {
                            *metadata =
                                Some((details.version.clone(), Arc::new(details.packets.clone())));
                        }
                        if let Some(host) = &options.extensions {
                            *extension_session = Some(host.start_owned_connection(details)?);
                        }
                    }
                }
            }
            for (packet, encrypted) in packets {
                progress = true;
                if let Some(safety) = &options.packet_safety {
                    if let Ok(mut safety) = safety.lock() {
                        safety.observe(&safety_revision, direction, packet.header());
                    }
                }
                let mut message = Message {
                    packet,
                    direction,
                    index: *index,
                    blocked: false,
                };
                *index = index.wrapping_add(1);
                if let Some(service) = &options.admin_service {
                    if let Ok(mut service) = service.lock() {
                        service.on_message(&mut message);
                    }
                }
                rules
                    .lock()
                    .map_err(|_| io::Error::other("rules lock poisoned"))?
                    .apply(&mut message);
                if let Some(host) = &options.extensions {
                    host.intercept(&mut message)?;
                }
                if !message.blocked {
                    if let Some(shock) = &mut shockwave {
                        let bytes = if direction == Direction::ToServer {
                            shock.encode_to_server(&message.packet)?
                        } else {
                            shock.encode_to_client(&message.packet)?
                        };
                        output.push_wire(bytes)?;
                    } else if let Some(flash) = &mut flash {
                        output.push_wire(flash.encode(direction, &message.packet, encrypted)?)?;
                    } else {
                        output.push(message.packet.clone())?;
                    }
                }
                let _ = events.try_send(Event::Packet(message));
            }
        }
        if let (Some(flash), Some(pid)) = (&mut flash, options.flash_process) {
            flash.discover(pid, stop)?;
        }
        progress |= to_server.flush(&mut server)?;
        progress |= to_client.flush(&mut client)?;
        if !progress {
            thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{read_frame, write_frame};
    use std::net::Shutdown;

    // These tests intentionally occupy the process-wide bounded lookup slots.
    static LOOKUP_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn wait_for(events: &Receiver<Event>, predicate: impl Fn(&Event) -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Ok(event) = events.recv_timeout(Duration::from_millis(50)) {
                if predicate(&event) {
                    return;
                }
            }
        }
        panic!("timed out waiting for Raw-IP relay event");
    }

    #[test]
    fn origins_metadata_initializes_without_host_and_handles_failure() {
        use crate::{
            packet_info::{PacketInfo, PacketInfoManager},
            packet_safety::PacketSafety,
        };
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        for succeeds in [true, false] {
            let remote = TcpListener::bind("127.0.0.1:0").unwrap();
            let safety = Arc::new(Mutex::new(PacketSafety::default()));
            let (requested_tx, requested_rx) = mpsc::channel();
            let lookup = Arc::new(move |version: String| {
                requested_tx.send(version).unwrap();
                if !succeeds {
                    return Err(io::Error::other("fixture offline"));
                }
                Ok(PacketInfoManager::new(
                    "ORIGINS-2",
                    vec![PacketInfo {
                        header: 900,
                        hash: None,
                        name: Some("Known".into()),
                        structure: None,
                        direction: Direction::ToServer,
                        source: "fixture".into(),
                    }],
                ))
            });
            let (mut relay, events) = Relay::start_with_options(
                Config {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    remote: remote.local_addr().unwrap().to_string(),
                },
                RelayOptions {
                    shockwave: true,
                    packet_safety: Some(safety.clone()),
                    origins_lookup: Some(lookup),
                    ..RelayOptions::default()
                },
            )
            .unwrap();
            let client = TcpStream::connect(relay.address).unwrap();
            let (_server, _) = remote.accept().unwrap();
            assert_eq!(
                requested_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
                "latest"
            );
            if succeeds {
                wait_for(
                    &events,
                    |event| matches!(event, Event::PacketIdentifiers(db) if db.version == "ORIGINS-2" && db.entries().len() == 1),
                );
            } else {
                wait_for(
                    &events,
                    |event| matches!(event, Event::Status(text) if text.contains("fixture offline")),
                );
            }
            wait_for(&events, |event| matches!(event, Event::Connected(_)));
            assert_eq!(
                safety
                    .lock()
                    .unwrap()
                    .is_safe(Some("ORIGINS-2"), Direction::ToServer, 900),
                succeeds
            );
            drop(client);
            wait_for(&events, |event| matches!(event, Event::Disconnected));
            relay.stop();
        }
    }

    #[test]
    fn origins_stop_cancels_stalled_metadata_wait() {
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        let remote = TcpListener::bind("127.0.0.1:0").unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let lookup = Arc::new(move |_: String| {
            started_tx.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            Ok(crate::packet_info::PacketInfoManager::default())
        });
        let (mut relay, _events) = Relay::start_with_options(
            Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                remote: remote.local_addr().unwrap().to_string(),
            },
            RelayOptions {
                shockwave: true,
                origins_lookup: Some(lookup),
                ..RelayOptions::default()
            },
        )
        .unwrap();
        let _client = TcpStream::connect(relay.address).unwrap();
        let (_server, _) = remote.accept().unwrap();
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let started = Instant::now();
        relay.stop();
        assert!(started.elapsed() < Duration::from_secs(2));
        release_tx.send(()).unwrap();
    }

    #[cfg(not(feature = "web"))]
    #[test]
    fn origins_socks_without_web_uses_proxy_for_metadata() {
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        let remote = TcpListener::bind("127.0.0.1:0").unwrap();
        let remote_address = remote.local_addr().unwrap();
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let proxy_worker = proxy.try_clone().unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut client, _) = proxy_worker.accept().unwrap();
            let mut greeting = [0; 3];
            client.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            client.write_all(&[5, 0]).unwrap();
            let mut request = [0; 10];
            client.read_exact(&mut request).unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 1]);
            assert_eq!(&request[8..], &remote_address.port().to_be_bytes());
            let upstream = TcpStream::connect(remote_address).unwrap();
            client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1]).unwrap();
            for _ in 0..2 {
                let (mut metadata, _) = proxy_worker.accept().unwrap();
                metadata
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut greeting = [0; 3];
                metadata.read_exact(&mut greeting).unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                metadata.write_all(&[5, 0]).unwrap();
                let mut header = [0; 5];
                metadata.read_exact(&mut header).unwrap();
                assert_eq!(&header[..4], &[5, 1, 0, 3]);
                let mut target = vec![0; usize::from(header[4]) + 2];
                metadata.read_exact(&mut target).unwrap();
                assert_eq!(&target[..target.len() - 2], b"api.sulek.dev");
                assert_eq!(&target[target.len() - 2..], &443u16.to_be_bytes());
                metadata.write_all(&[5, 5, 0, 1]).unwrap();
            }
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            drop((client, upstream));
        });
        let (mut relay, events) = Relay::start_with_options(
            Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                remote: remote_address.to_string(),
            },
            RelayOptions {
                shockwave: true,
                connection: Some(ConnectionDetails {
                    host: "fixture".into(),
                    port: 1,
                    version: format!(
                        "TEST-{}",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_nanos()
                    ),
                    identifier: "SHOCKWAVE".into(),
                    client_type: "SHOCKWAVE".into(),
                    packets: crate::packet_info::PacketInfoManager::default(),
                }),
                socks: Some(SocksConfig {
                    proxy: proxy_address.to_string(),
                    credentials: None,
                }),
                ..RelayOptions::default()
            },
        )
        .unwrap();
        let client = TcpStream::connect(relay.address).unwrap();
        let (_remote, _) = remote.accept().unwrap();
        wait_for(
            &events,
            |event| matches!(event, Event::Status(text) if text.contains("Connected without packet names")),
        );
        wait_for(&events, |event| matches!(event, Event::Connected(_)));
        proxy.set_nonblocking(true).unwrap();
        assert_eq!(
            proxy.accept().err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(client);
        wait_for(&events, |event| matches!(event, Event::Disconnected));
        release_tx.send(()).unwrap();
        server.join().unwrap();
        relay.stop();
    }

    #[test]
    fn origins_peer_close_during_lookup_preserves_previous_extension_session() {
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        for close_client in [true, false] {
            let (host, _) =
                ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
            let old_epoch = host
                .start_owned_connection(ConnectionDetails {
                    host: "fixture".into(),
                    port: 1,
                    version: "OLD".into(),
                    identifier: "OLD".into(),
                    client_type: "FLASH".into(),
                    packets: crate::packet_info::PacketInfoManager::default(),
                })
                .unwrap();
            let remote = TcpListener::bind("127.0.0.1:0").unwrap();
            let (started_tx, started_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let release_rx = Mutex::new(release_rx);
            let lookup = Arc::new(move |_: String| {
                started_tx.send(()).unwrap();
                release_rx.lock().unwrap().recv().unwrap();
                Ok(crate::packet_info::PacketInfoManager::default())
            });
            let (mut relay, events) = Relay::start_with_options(
                Config {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    remote: remote.local_addr().unwrap().to_string(),
                },
                RelayOptions {
                    shockwave: true,
                    extensions: Some(host.clone()),
                    origins_lookup: Some(lookup),
                    ..RelayOptions::default()
                },
            )
            .unwrap();
            let client = TcpStream::connect(relay.address).unwrap();
            let (server, _) = remote.accept().unwrap();
            started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            if close_client {
                client.shutdown(Shutdown::Both).unwrap();
            } else {
                server.shutdown(Shutdown::Both).unwrap();
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            while relay.connected() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(!relay.connected());
            release_tx.send(()).unwrap();
            assert!(!events
                .try_iter()
                .any(|event| matches!(event, Event::Connected(_) | Event::PacketIdentifiers(_))));
            assert!(host.end_owned_connection(old_epoch));
            relay.stop();
            host.stop();
        }
    }

    #[test]
    fn origins_extension_receives_discovered_metadata_before_connection() {
        use crate::{
            extension::{self, ExtensionInfo},
            extension_host::HostEvent,
            packet_info::{PacketInfo, PacketInfoManager},
        };
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        let (host, host_events) =
            ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
        let mut peer = TcpStream::connect(host.address).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        assert_eq!(read_frame(&mut peer).unwrap().header(), 2);
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
        write_frame(&mut peer, &extension::info_response(&info).unwrap()).unwrap();
        let id = match host_events.recv_timeout(Duration::from_secs(3)).unwrap() {
            HostEvent::Pending { id, .. } => id,
            event => panic!("{event:?}"),
        };
        host.approve(id).unwrap();
        assert_eq!(read_frame(&mut peer).unwrap().header(), 7);
        let remote = TcpListener::bind("127.0.0.1:0").unwrap();
        let lookup = Arc::new(|_: String| {
            Ok(PacketInfoManager::new(
                "ORIGINS-2",
                vec![PacketInfo {
                    header: 900,
                    hash: None,
                    name: Some("Known".into()),
                    structure: None,
                    direction: Direction::ToServer,
                    source: "fixture".into(),
                }],
            ))
        });
        let (mut relay, events) = Relay::start_with_options(
            Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                remote: remote.local_addr().unwrap().to_string(),
            },
            RelayOptions {
                shockwave: true,
                extensions: Some(host.clone()),
                origins_lookup: Some(lookup),
                ..RelayOptions::default()
            },
        )
        .unwrap();
        let client = TcpStream::connect(relay.address).unwrap();
        let (_server, _) = remote.accept().unwrap();
        let mut start = read_frame(&mut peer).unwrap();
        assert_eq!(start.header(), 5);
        start.read_string().unwrap();
        start.read_i32().unwrap();
        let version = start.read_string().unwrap();
        assert_eq!(version, "ORIGINS-2");
        assert_eq!(start.read_string().unwrap(), "SHOCKWAVE");
        assert_eq!(start.read_string().unwrap(), "SHOCKWAVE");
        let database = PacketInfoManager::read_from(version, &mut start).unwrap();
        assert_eq!(database.entries()[0].header, 900);
        drop(client);
        wait_for(&events, |event| matches!(event, Event::Disconnected));
        assert_eq!(read_frame(&mut peer).unwrap().header(), 6);
        relay.stop();
        host.stop();
    }

    #[test]
    fn origins_relay_encrypts_and_intercepts_after_metadata_and_reconnect() {
        exercise_origins_encrypted_extension(false);
    }

    #[test]
    #[ignore = "requires the beta-29 Java API and compiled JavaOriginsExtensionFixture"]
    fn origins_relay_interoperates_with_actual_java_extension() {
        exercise_origins_encrypted_extension(true);
    }

    fn exercise_origins_encrypted_extension(real_java: bool) {
        use crate::{
            encoding::{decode_b64, encode_b64},
            extension::{self, ExtensionInfo},
            extension_host::HostEvent,
            packet_info::{PacketInfo, PacketInfoManager},
            shockwave::{test_encrypt, BobbaCrypto, ChaChaKey},
        };
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
        fn intercept(peer: &mut TcpStream, direction: Direction, header: u16) {
            let mut frame = read_frame(peer).unwrap();
            assert_eq!(frame.header(), 3);
            let text = frame.read_long_string().unwrap();
            let format = PacketFormat::from_id(frame.read_i32().unwrap()).unwrap();
            let mut message = Message::parse_with_format(&text, format).unwrap();
            assert_eq!(message.direction, direction);
            assert_eq!(message.packet.header(), header);
            if header == 77 {
                if message.packet.read_i32().unwrap() == 13 {
                    message.blocked = true;
                } else {
                    let mut replacement = Packet::new_with_format(format, header).unwrap();
                    replacement.put_i32(43).unwrap();
                    message.packet = replacement;
                }
            } else if header == 78 {
                let mut replacement = Packet::new_with_format(format, header).unwrap();
                replacement.put_string("Hello").unwrap();
                message.packet = replacement;
            }
            write_frame(peer, &extension::manipulated(&message).unwrap()).unwrap();
        }
        fn read_encrypted(
            stream: &mut TcpStream,
            header: &mut ChaChaKey,
            data: &mut ChaChaKey,
        ) -> Vec<u8> {
            let mut wire_header = [0; 6];
            stream.read_exact(&mut wire_header).unwrap();
            let mut decoded = STANDARD_NO_PAD.decode(wire_header).unwrap();
            header.apply(&mut decoded);
            let length = decode_b64(&decoded[1..]).unwrap() as usize;
            let mut wire = vec![0; length];
            stream.read_exact(&mut wire).unwrap();
            let mut plain = STANDARD_NO_PAD.decode(wire).unwrap();
            data.apply(&mut plain);
            plain
        }
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        let (host, host_events) =
            ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
        struct Process(std::process::Child);
        impl Drop for Process {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let (_process, mut peer) = if real_java {
            let classpath = std::env::var("GEARTH_EXTENSION_CLASSPATH")
                .expect("Java fixture classpath required");
            let token = host.register_launch("origins-fixture.jar").unwrap();
            let child = Process(
                std::process::Command::new("java")
                    .args([
                        "-cp",
                        &classpath,
                        "JavaOriginsExtensionFixture",
                        "-p",
                        &host.address.port().to_string(),
                        "-f",
                        "origins-fixture.jar",
                        "-c",
                        &token,
                    ])
                    .spawn()
                    .unwrap(),
            );
            let deadline = Instant::now() + Duration::from_secs(10);
            while !matches!(
                host_events.recv_timeout(Duration::from_millis(100)),
                Ok(HostEvent::Connected { .. })
            ) {
                assert!(
                    Instant::now() < deadline,
                    "Java extension did not authenticate"
                );
            }
            (Some(child), None)
        } else {
            let mut peer = TcpStream::connect(host.address).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            assert_eq!(read_frame(&mut peer).unwrap().header(), 2);
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
            write_frame(&mut peer, &extension::info_response(&info).unwrap()).unwrap();
            let id = match host_events.recv_timeout(Duration::from_secs(3)).unwrap() {
                HostEvent::Pending { id, .. } => id,
                event => panic!("{event:?}"),
            };
            host.approve(id).unwrap();
            assert_eq!(read_frame(&mut peer).unwrap().header(), 7);
            (None, Some(peer))
        };
        let remote = TcpListener::bind("127.0.0.1:0").unwrap();
        let (called_tx, called_rx) = mpsc::channel();
        let lookup = Arc::new(move |version: String| {
            called_tx.send(version).unwrap();
            Ok(PacketInfoManager::new(
                "ORIGINS-2",
                vec![
                    PacketInfo {
                        header: 77,
                        hash: None,
                        name: Some("Known".into()),
                        structure: None,
                        direction: Direction::ToServer,
                        source: "fixture".into(),
                    },
                    PacketInfo {
                        header: 78,
                        hash: None,
                        name: Some("Incoming".into()),
                        structure: None,
                        direction: Direction::ToClient,
                        source: "fixture".into(),
                    },
                ],
            ))
        });
        let (mut relay, events) = Relay::start_with_options(
            Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                remote: remote.local_addr().unwrap().to_string(),
            },
            RelayOptions {
                shockwave: true,
                extensions: Some(host.clone()),
                origins_lookup: Some(lookup),
                ..RelayOptions::default()
            },
        )
        .unwrap();
        for _ in 0..2 {
            let mut client = TcpStream::connect(relay.address).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let (mut server, _) = remote.accept().unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            assert_eq!(
                called_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
                "latest"
            );
            if let Some(peer) = &mut peer {
                let mut start = read_frame(peer).unwrap();
                assert_eq!(start.header(), 5);
                start.read_string().unwrap();
                start.read_i32().unwrap();
                let version = start.read_string().unwrap();
                assert_eq!(version, "ORIGINS-2");
                start.read_string().unwrap();
                start.read_string().unwrap();
                assert_eq!(
                    PacketInfoManager::read_from(version, &mut start)
                        .unwrap()
                        .entries()[0]
                        .header,
                    77
                );
            }
            if real_java {
                let mut length = [0; 3];
                server.read_exact(&mut length).unwrap();
                let mut payload = vec![0; decode_b64(&length).unwrap() as usize];
                server.read_exact(&mut payload).unwrap();
                let mut injected =
                    Packet::from_bytes_with_format(PacketFormat::WedgieOutgoing, payload).unwrap();
                assert_eq!(injected.header(), 77);
                assert_eq!(injected.read_i32().unwrap(), 17);
            }
            let mut client_crypto = BobbaCrypto::with_private(12345).unwrap();
            let mut server_crypto = BobbaCrypto::with_private(67890).unwrap();
            let mut hello = Packet::new_with_format(PacketFormat::WedgieOutgoing, 202).unwrap();
            hello.put_string(&client_crypto.public_key()).unwrap();
            let mut wire = encode_b64(hello.bytes().len() as u32, 3).unwrap();
            wire.extend_from_slice(hello.bytes());
            client.write_all(&wire).unwrap();
            if let Some(peer) = &mut peer {
                intercept(peer, Direction::ToServer, 202);
            }
            let mut length = [0; 3];
            server.read_exact(&mut length).unwrap();
            let mut payload = vec![0; decode_b64(&length).unwrap() as usize];
            server.read_exact(&mut payload).unwrap();
            let mut packet =
                Packet::from_bytes_with_format(PacketFormat::WedgieOutgoing, payload).unwrap();
            server_crypto
                .set_peer(&packet.read_string().unwrap())
                .unwrap();
            let mut reply = Packet::new_with_format(PacketFormat::WedgieIncoming, 1).unwrap();
            reply.put_string(&server_crypto.public_key()).unwrap();
            let mut wire = reply.bytes().to_vec();
            wire.push(1);
            server.write_all(&wire).unwrap();
            if let Some(peer) = &mut peer {
                intercept(peer, Direction::ToClient, 1);
            }
            let mut response = Vec::new();
            loop {
                let mut byte = [0];
                client.read_exact(&mut byte).unwrap();
                if byte[0] == 1 {
                    break;
                }
                response.push(byte[0]);
            }
            let mut packet =
                Packet::from_bytes_with_format(PacketFormat::WedgieIncoming, response).unwrap();
            client_crypto
                .set_peer(&packet.read_string().unwrap())
                .unwrap();
            let mut blocked = Packet::new_with_format(PacketFormat::WedgieOutgoing, 77).unwrap();
            blocked.put_i32(13).unwrap();
            let keys = client_crypto.keys_mut().unwrap();
            client
                .write_all(
                    &test_encrypt(blocked.bytes(), &mut keys.c2s_header, &mut keys.c2s_data)
                        .unwrap(),
                )
                .unwrap();
            if let Some(peer) = &mut peer {
                intercept(peer, Direction::ToServer, 77);
            }
            let mut outgoing = Packet::new_with_format(PacketFormat::WedgieOutgoing, 77).unwrap();
            outgoing.put_i32(42).unwrap();
            let keys = client_crypto.keys_mut().unwrap();
            client
                .write_all(
                    &test_encrypt(outgoing.bytes(), &mut keys.c2s_header, &mut keys.c2s_data)
                        .unwrap(),
                )
                .unwrap();
            if let Some(peer) = &mut peer {
                intercept(peer, Direction::ToServer, 77);
            }
            let keys = server_crypto.keys_mut().unwrap();
            let mut replaced = Packet::new_with_format(PacketFormat::WedgieOutgoing, 77).unwrap();
            replaced.put_i32(43).unwrap();
            assert_eq!(
                read_encrypted(&mut server, &mut keys.c2s_header, &mut keys.c2s_data),
                replaced.bytes()
            );
            if real_java {
                let injected =
                    read_encrypted(&mut server, &mut keys.c2s_header, &mut keys.c2s_data);
                let mut packet =
                    Packet::from_bytes_with_format(PacketFormat::WedgieOutgoing, injected).unwrap();
                assert_eq!(packet.header(), 77);
                assert_eq!(packet.read_i32().unwrap(), 18);
            }
            let mut incoming = Packet::new_with_format(PacketFormat::WedgieIncoming, 78).unwrap();
            incoming.put_string("hello").unwrap();
            let mut plain = incoming.bytes().to_vec();
            plain.push(1);
            let keys = server_crypto.keys_mut().unwrap();
            server
                .write_all(&test_encrypt(&plain, &mut keys.s2c_header, &mut keys.s2c_data).unwrap())
                .unwrap();
            if let Some(peer) = &mut peer {
                intercept(peer, Direction::ToClient, 78);
            }
            let keys = client_crypto.keys_mut().unwrap();
            let mut replaced_incoming =
                Packet::new_with_format(PacketFormat::WedgieIncoming, 78).unwrap();
            replaced_incoming.put_string("Hello").unwrap();
            let mut expected = replaced_incoming.bytes().to_vec();
            expected.push(1);
            assert_eq!(
                read_encrypted(&mut client, &mut keys.s2c_header, &mut keys.s2c_data),
                expected
            );
            if real_java {
                let mut injected =
                    read_encrypted(&mut client, &mut keys.s2c_header, &mut keys.s2c_data);
                assert_eq!(injected.pop(), Some(1));
                let mut packet =
                    Packet::from_bytes_with_format(PacketFormat::WedgieIncoming, injected).unwrap();
                assert_eq!(packet.header(), 78);
                assert_eq!(packet.read_string().unwrap(), "extra");
            }
            drop(client);
            wait_for(&events, |event| matches!(event, Event::Disconnected));
            if let Some(peer) = &mut peer {
                assert_eq!(read_frame(peer).unwrap().header(), 6);
            }
        }
        relay.stop();
        host.stop();
    }

    #[test]
    fn origins_matching_metadata_and_offline_mode_skip_lookup() {
        use crate::{
            packet_info::{PacketInfo, PacketInfoManager},
            packet_safety::PacketSafety,
        };
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        for preloaded in [true, false] {
            let remote = TcpListener::bind("127.0.0.1:0").unwrap();
            let safety = Arc::new(Mutex::new(PacketSafety::default()));
            let packets = if preloaded {
                PacketInfoManager::new(
                    "REV",
                    vec![PacketInfo {
                        header: 900,
                        hash: None,
                        name: Some("Known".into()),
                        structure: None,
                        direction: Direction::ToServer,
                        source: "fixture".into(),
                    }],
                )
            } else {
                PacketInfoManager::new("REV", Vec::new())
            };
            let details = ConnectionDetails {
                host: "fixture".into(),
                port: 1,
                version: "REV".into(),
                identifier: "SHOCKWAVE".into(),
                client_type: "SHOCKWAVE".into(),
                packets,
            };
            let called = Arc::new(AtomicBool::new(false));
            let called_by_lookup = called.clone();
            let lookup = Arc::new(move |_: String| -> io::Result<PacketInfoManager> {
                called_by_lookup.store(true, Ordering::Release);
                Err(io::Error::other("unexpected lookup"))
            });
            let (mut relay, events) = Relay::start_with_options(
                Config {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    remote: remote.local_addr().unwrap().to_string(),
                },
                RelayOptions {
                    shockwave: true,
                    disable_origins_metadata: !preloaded,
                    connection: Some(details),
                    origins_lookup: Some(lookup),
                    packet_safety: Some(safety.clone()),
                    ..RelayOptions::default()
                },
            )
            .unwrap();
            let client = TcpStream::connect(relay.address).unwrap();
            let (_server, _) = remote.accept().unwrap();
            wait_for(&events, |event| matches!(event, Event::Connected(_)));
            assert!(!called.load(Ordering::Acquire));
            assert_eq!(
                safety
                    .lock()
                    .unwrap()
                    .is_safe(Some("REV"), Direction::ToServer, 900),
                preloaded
            );
            drop(client);
            wait_for(&events, |event| matches!(event, Event::Disconnected));
            relay.stop();
        }
    }

    #[test]
    fn origins_does_not_trust_metadata_from_another_version() {
        use crate::{
            packet_info::{PacketInfo, PacketInfoManager},
            packet_safety::PacketSafety,
        };
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        let remote = TcpListener::bind("127.0.0.1:0").unwrap();
        let safety = Arc::new(Mutex::new(PacketSafety::default()));
        let stale = PacketInfoManager::new(
            "OLD",
            vec![PacketInfo {
                header: 777,
                hash: None,
                name: Some("Stale".into()),
                structure: None,
                direction: Direction::ToServer,
                source: "fixture".into(),
            }],
        );
        let details = ConnectionDetails {
            host: "fixture".into(),
            port: 1,
            version: "NEW".into(),
            identifier: "SHOCKWAVE".into(),
            client_type: "SHOCKWAVE".into(),
            packets: stale,
        };
        let lookup = Arc::new(|version: String| {
            assert_eq!(version, "NEW");
            Err(io::Error::other("fixture offline"))
        });
        let (mut relay, events) = Relay::start_with_options(
            Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                remote: remote.local_addr().unwrap().to_string(),
            },
            RelayOptions {
                shockwave: true,
                connection: Some(details),
                packet_safety: Some(safety.clone()),
                origins_lookup: Some(lookup),
                ..RelayOptions::default()
            },
        )
        .unwrap();
        let client = TcpStream::connect(relay.address).unwrap();
        let (_server, _) = remote.accept().unwrap();
        wait_for(
            &events,
            |event| matches!(event, Event::Status(text) if text.contains("fixture offline")),
        );
        wait_for(&events, |event| matches!(event, Event::Connected(_)));
        assert!(!safety
            .lock()
            .unwrap()
            .is_safe(Some("NEW"), Direction::ToServer, 777));
        drop(client);
        wait_for(&events, |event| matches!(event, Event::Disconnected));
        relay.stop();
    }
    #[test]
    fn flash_metadata_lookup_returns_results_and_can_be_cancelled() {
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        let stop = AtomicBool::new(false);
        let closed = AtomicBool::new(false);
        assert_eq!(
            cancellable_metadata_lookup(&stop, &closed, || false, || Ok(42)).unwrap(),
            42
        );
        assert_eq!(
            cancellable_metadata_lookup::<()>(
                &stop,
                &closed,
                || false,
                || Err(io::Error::other("offline"))
            )
            .unwrap_err()
            .to_string(),
            "offline"
        );
        for cancel_stop in [true, false] {
            let stop = Arc::new(AtomicBool::new(false));
            let closed = Arc::new(AtomicBool::new(false));
            let (started_tx, started_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let stop_worker = stop.clone();
            let closed_worker = closed.clone();
            let waiter = thread::spawn(move || {
                cancellable_metadata_lookup(
                    &stop_worker,
                    &closed_worker,
                    || false,
                    move || {
                        started_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok(99)
                    },
                )
            });
            started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            let now = Instant::now();
            if cancel_stop {
                stop.store(true, Ordering::Release);
            } else {
                closed.store(true, Ordering::Release);
            }
            let error = waiter.join().unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(now.elapsed() < Duration::from_secs(2));
            release_tx.send(()).unwrap();
        }
    }

    #[test]
    fn relay_stop_does_not_wait_for_stalled_flash_metadata_lookup() {
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        use crate::packet_info::PacketInfoManager;
        let (host, _) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
        let remote = TcpListener::bind("127.0.0.1:0").unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let lookup = Arc::new(move |version: String| {
            started_tx.send(version).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
            Ok(PacketInfoManager::default())
        });
        let (mut relay, _) = Relay::start_with_options(
            Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                remote: remote.local_addr().unwrap().to_string(),
            },
            RelayOptions {
                flash_process: Some(1),
                extensions: Some(host.clone()),
                flash_lookup: Some(lookup),
                connection: Some(ConnectionDetails {
                    host: "fixture".into(),
                    port: 1,
                    version: String::new(),
                    identifier: String::new(),
                    client_type: "FLASH".into(),
                    packets: PacketInfoManager::default(),
                }),
                ..RelayOptions::default()
            },
        )
        .unwrap();
        let mut client = TcpStream::connect(relay.address).unwrap();
        let (_server, _) = remote.accept().unwrap();
        let mut hello = Packet::new(1);
        hello
            .put_string("TEST-2026")
            .unwrap()
            .put_string("FLASH")
            .unwrap();
        write_frame(&mut client, &hello).unwrap();
        assert_eq!(
            started_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            "TEST-2026"
        );
        let start = Instant::now();
        relay.stop();
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(!relay.connected());
        release_tx.send(()).unwrap();
        host.stop();
    }

    #[test]
    fn disconnected_flash_peer_does_not_start_stale_extension_session_during_lookup() {
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        use crate::packet_info::PacketInfoManager;
        for close_client in [true, false] {
            let (host, _) =
                ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
            let details = ConnectionDetails {
                host: "fixture".into(),
                port: 1,
                version: "old".into(),
                identifier: String::new(),
                client_type: "FLASH".into(),
                packets: PacketInfoManager::default(),
            };
            let old_epoch = host.start_owned_connection(details.clone()).unwrap();
            let remote = TcpListener::bind("127.0.0.1:0").unwrap();
            let (started_tx, started_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let (finished_tx, finished_rx) = mpsc::channel();
            let release_rx = Mutex::new(release_rx);
            let lookup = Arc::new(move |_: String| {
                started_tx.send(()).unwrap();
                release_rx.lock().unwrap().recv().unwrap();
                finished_tx.send(()).unwrap();
                Ok(PacketInfoManager::default())
            });
            let (mut relay, events) = Relay::start_with_options(
                Config {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    remote: remote.local_addr().unwrap().to_string(),
                },
                RelayOptions {
                    flash_process: Some(1),
                    extensions: Some(host.clone()),
                    flash_lookup: Some(lookup),
                    connection: Some(details),
                    ..RelayOptions::default()
                },
            )
            .unwrap();
            let mut client = TcpStream::connect(relay.address).unwrap();
            let (server, _) = remote.accept().unwrap();
            let mut hello = Packet::new(1);
            hello
                .put_string("TEST-2026")
                .unwrap()
                .put_string("FLASH")
                .unwrap();
            write_frame(&mut client, &hello).unwrap();
            started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            if close_client {
                client.shutdown(Shutdown::Both).unwrap();
            } else {
                server.shutdown(Shutdown::Both).unwrap();
            }
            wait_for(&events, |event| matches!(event, Event::Disconnected));
            release_tx.send(()).unwrap();
            finished_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            assert!(
                host.end_owned_connection(old_epoch),
                "stale Flash session replaced the existing extension session"
            );
            relay.stop();
            host.stop();
        }
    }

    #[test]
    fn flash_reconnect_does_not_reuse_stale_or_unversioned_metadata() {
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        use crate::{
            extension::{self, ExtensionInfo},
            extension_host::HostEvent,
            packet_info::{PacketInfo, PacketInfoManager},
            packet_safety::PacketSafety,
        };
        for original_version in ["OLD", ""] {
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
            let entry = |header| PacketInfo {
                header,
                name: Some(format!("Packet{header}")),
                hash: None,
                structure: None,
                direction: Direction::ToServer,
                source: "fixture".into(),
            };
            let stale = PacketInfoManager::new(original_version, vec![entry(777)]);
            let safety = Arc::new(Mutex::new(PacketSafety::default()));
            let lookup = Arc::new(move |version: String| {
                let header = if version == "REV-1" {
                    801
                } else if version == "REV-2" {
                    802
                } else {
                    panic!("unexpected revision {version}")
                };
                Ok(PacketInfoManager::new(
                    version,
                    vec![PacketInfo {
                        header,
                        name: Some(format!("Packet{header}")),
                        hash: None,
                        structure: None,
                        direction: Direction::ToServer,
                        source: "fixture".into(),
                    }],
                ))
            });
            let remote = TcpListener::bind("127.0.0.1:0").unwrap();
            let details = ConnectionDetails {
                host: "fixture".into(),
                port: 1,
                version: original_version.into(),
                identifier: String::new(),
                client_type: "FLASH".into(),
                packets: stale,
            };
            let (mut relay, events) = Relay::start_with_options(
                Config {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    remote: remote.local_addr().unwrap().to_string(),
                },
                RelayOptions {
                    flash_process: Some(1),
                    extensions: Some(host.clone()),
                    packet_safety: Some(safety.clone()),
                    flash_lookup: Some(lookup),
                    connection: Some(details),
                    ..RelayOptions::default()
                },
            )
            .unwrap();
            for (version, expected_header, other_header) in
                [("REV-1", 801, 802), ("REV-2", 802, 801)]
            {
                let mut client = TcpStream::connect(relay.address).unwrap();
                let (mut server, _) = remote.accept().unwrap();
                server
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut hello = Packet::new(1);
                hello
                    .put_string(version)
                    .unwrap()
                    .put_string("FLASH")
                    .unwrap();
                write_frame(&mut client, &hello).unwrap();
                let mut start = read_frame(&mut extension_peer).unwrap();
                assert_eq!(start.header(), 5);
                start.read_string().unwrap();
                start.read_i32().unwrap();
                let actual_version = start.read_string().unwrap();
                assert_eq!(actual_version, version);
                start.read_string().unwrap();
                start.read_string().unwrap();
                let metadata = PacketInfoManager::read_from(actual_version, &mut start).unwrap();
                assert_eq!(metadata.entries().len(), 1);
                assert_eq!(metadata.entries()[0].header, expected_header);
                let mut intercepted = read_frame(&mut extension_peer).unwrap();
                assert_eq!(intercepted.header(), 3);
                let message = Message::parse(&intercepted.read_long_string().unwrap()).unwrap();
                write_frame(
                    &mut extension_peer,
                    &extension::manipulated(&message).unwrap(),
                )
                .unwrap();
                assert_eq!(read_frame(&mut server).unwrap().bytes(), hello.bytes());
                let guard = safety.lock().unwrap();
                assert!(guard.is_safe(Some(version), Direction::ToServer, expected_header));
                assert!(!guard.is_safe(Some(version), Direction::ToServer, other_header));
                assert!(!guard.is_safe(Some(version), Direction::ToServer, 777));
                drop(guard);
                drop(client);
                assert_eq!(read_frame(&mut extension_peer).unwrap().header(), 6);
                wait_for(&events, |event| matches!(event, Event::Disconnected));
            }
            relay.stop();
            drop(extension_peer);
            host.stop();
        }
    }

    #[test]
    fn flash_loads_packet_metadata_without_extension_host_and_handles_failure() {
        use crate::{
            packet_info::{PacketInfo, PacketInfoManager},
            packet_safety::PacketSafety,
        };
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        let safety = Arc::new(Mutex::new(PacketSafety::default()));
        let remote = TcpListener::bind("127.0.0.1:0").unwrap();
        let (requested_tx, requested_rx) = mpsc::channel();
        let lookup = Arc::new(move |version: String| {
            requested_tx.send(version.clone()).unwrap();
            if version == "FAIL" {
                return Err(io::Error::other("fixture offline"));
            }
            Ok(PacketInfoManager::new(
                version,
                vec![PacketInfo {
                    header: 900,
                    name: Some("Known".into()),
                    hash: None,
                    structure: None,
                    direction: Direction::ToServer,
                    source: "fixture".into(),
                }],
            ))
        });
        let details = ConnectionDetails {
            host: "fixture".into(),
            port: 1,
            version: String::new(),
            identifier: String::new(),
            client_type: "FLASH".into(),
            packets: PacketInfoManager::default(),
        };
        let (mut relay, events) = Relay::start_with_options(
            Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                remote: remote.local_addr().unwrap().to_string(),
            },
            RelayOptions {
                flash_process: Some(1),
                packet_safety: Some(safety.clone()),
                flash_lookup: Some(lookup),
                connection: Some(details),
                ..RelayOptions::default()
            },
        )
        .unwrap();
        for version in ["SUCCESS", "FAIL"] {
            let mut client = TcpStream::connect(relay.address).unwrap();
            let (mut server, _) = remote.accept().unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut hello = Packet::new(1);
            hello
                .put_string(version)
                .unwrap()
                .put_string("FLASH")
                .unwrap();
            write_frame(&mut client, &hello).unwrap();
            assert_eq!(
                requested_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
                version
            );
            assert_eq!(read_frame(&mut server).unwrap().bytes(), hello.bytes());
            if version == "SUCCESS" {
                wait_for(
                    &events,
                    |event| matches!(event, Event::PacketIdentifiers(db) if db.version == "SUCCESS" && db.entries().len() == 1),
                );
                assert!(safety
                    .lock()
                    .unwrap()
                    .is_safe(Some(version), Direction::ToServer, 900));
            } else {
                wait_for(
                    &events,
                    |event| matches!(event, Event::Status(text) if text.contains("fixture offline")),
                );
                assert!(!safety
                    .lock()
                    .unwrap()
                    .is_safe(Some(version), Direction::ToServer, 900));
            }
            drop(client);
            wait_for(&events, |event| matches!(event, Event::Disconnected));
        }
        relay.stop();
    }

    #[test]
    fn orderly_eof_flushes_already_queued_injections() {
        let client_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client_peer = TcpStream::connect(client_listener.local_addr().unwrap()).unwrap();
        let (client, _) = client_listener.accept().unwrap();
        let server_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = TcpStream::connect(server_listener.local_addr().unwrap()).unwrap();
        let (mut server_peer, _) = server_listener.accept().unwrap();
        server_peer
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        server_peer.shutdown(Shutdown::Write).unwrap();
        let (commands, receiver) = mpsc::sync_channel(128);
        for header in 1..=64 {
            commands
                .send((Direction::ToServer, Packet::new(header)))
                .unwrap();
        }
        let (events, _) = mpsc::sync_channel(256);
        let worker = thread::spawn(move || {
            run_session(
                client,
                server,
                &AtomicBool::new(false),
                &AtomicBool::new(false),
                &Mutex::new(Rules::default()),
                &events,
                receiver,
                &mut 0,
                &RelayOptions::default(),
                &mut None,
                &Mutex::new(None),
            )
        });
        for header in 1..=64 {
            assert_eq!(read_frame(&mut server_peer).unwrap().header(), header);
        }
        worker.join().unwrap().unwrap();
    }
    #[test]
    fn raw_relay_consumes_preconnected_sockets_without_direct_fallback() {
        let remote = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream = TcpStream::connect(remote.local_addr().unwrap()).unwrap();
        let (mut server, _) = remote.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let (mut relay, events) = Relay::start_raw(
            Config {
                listen: "0.0.0.0:0".parse().unwrap(),
                remote: remote.local_addr().unwrap().to_string(),
            },
            RelayOptions::default(),
            VecDeque::from([upstream]),
        )
        .unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], relay.address.port()));
        let mut client = TcpStream::connect(address).unwrap();
        wait_for(&events, |event| matches!(event, Event::Connected(_)));
        write_frame(&mut client, &Packet::new(711)).unwrap();
        assert_eq!(read_frame(&mut server).unwrap().header(), 711);
        client.shutdown(Shutdown::Both).unwrap();
        wait_for(&events, |event| matches!(event, Event::Disconnected));
        drop(server);

        remote.set_nonblocking(true).unwrap();
        let _second_client = TcpStream::connect(address).unwrap();
        wait_for(
            &events,
            |event| matches!(event, Event::Error(error) if error == "preconnected Raw-IP server sockets exhausted"),
        );
        assert!(matches!(
            remote.accept(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock
        ));
        relay.stop();
    }
    #[test]
    fn flash_schedule_metadata_is_bound_to_identified_session() {
        use crate::packet_info::{PacketInfo, PacketInfoManager};
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        let remote = TcpListener::bind("127.0.0.1:0").unwrap();
        let (requested_tx, requested_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let lookup = Arc::new(move |version: String| {
            requested_tx.send(version.clone()).unwrap();
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
            let header = if version == "REV-1" { 801 } else { 802 };
            Ok(PacketInfoManager::new(
                version,
                vec![PacketInfo {
                    header,
                    direction: Direction::ToServer,
                    name: Some("Example".into()),
                    hash: None,
                    structure: None,
                    source: "fixture".into(),
                }],
            ))
        });
        let (mut relay, events) = Relay::start_with_options(
            Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                remote: remote.local_addr().unwrap().to_string(),
            },
            RelayOptions {
                flash_process: Some(1),
                flash_lookup: Some(lookup),
                connection: Some(ConnectionDetails {
                    host: "fixture".into(),
                    port: 1,
                    version: "OLD".into(),
                    identifier: String::new(),
                    client_type: "FLASH".into(),
                    packets: PacketInfoManager::default(),
                }),
                ..RelayOptions::default()
            },
        )
        .unwrap();
        let mut previous = None;
        for (version, header) in [("REV-1", 801), ("REV-2", 802)] {
            let mut client = TcpStream::connect(relay.address).unwrap();
            let (mut server, _) = remote.accept().unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            wait_for(&events, |event| matches!(event, Event::Connected(_)));
            assert!(matches!(
                relay.flash_schedule_state(),
                FlashScheduleState::Pending
            ));
            if let Some(old) = &previous {
                assert_eq!(
                    relay
                        .inject_for_flash_session(old, Direction::ToServer, Packet::new(801))
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::NotConnected
                );
            }
            let mut hello = Packet::new(1);
            hello
                .put_string(version)
                .unwrap()
                .put_string("FLASH")
                .unwrap();
            write_frame(&mut client, &hello).unwrap();
            assert_eq!(
                requested_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
                version
            );
            assert!(matches!(
                relay.flash_schedule_state(),
                FlashScheduleState::Pending
            ));
            release_tx.send(()).unwrap();
            assert_eq!(read_frame(&mut server).unwrap().bytes(), hello.bytes());
            let deadline = Instant::now() + Duration::from_secs(3);
            let context = loop {
                if let FlashScheduleState::Ready(context) = relay.flash_schedule_state() {
                    break context;
                }
                assert!(Instant::now() < deadline);
                thread::yield_now();
            };
            assert_eq!(context.version, version);
            assert_eq!(context.packets.entries()[0].header, header);
            relay
                .inject_for_flash_session(&context, Direction::ToServer, Packet::new(header))
                .unwrap();
            assert_eq!(read_frame(&mut server).unwrap().header(), header);
            assert!(
                !relay.update_flash_schedule_metadata(PacketInfoManager::new("WRONG", Vec::new()))
            );
            let replacement = PacketInfoManager::new(
                version,
                vec![PacketInfo {
                    header: header + 10,
                    direction: Direction::ToServer,
                    name: Some("Example".into()),
                    hash: None,
                    structure: None,
                    source: "download".into(),
                }],
            );
            assert!(relay.update_flash_schedule_metadata(replacement));
            assert_eq!(
                relay
                    .inject_for_flash_session(&context, Direction::ToServer, Packet::new(header))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::NotConnected
            );
            let FlashScheduleState::Ready(replacement) = relay.flash_schedule_state() else {
                panic!("updated metadata missing")
            };
            assert_eq!(replacement.packets.entries()[0].header, header + 10);
            relay
                .inject_for_flash_session(
                    &replacement,
                    Direction::ToServer,
                    Packet::new(header + 10),
                )
                .unwrap();
            assert_eq!(read_frame(&mut server).unwrap().header(), header + 10);
            previous = Some(replacement);
            client.shutdown(std::net::Shutdown::Both).unwrap();
            wait_for(&events, |event| matches!(event, Event::Disconnected));
        }
        relay.stop();
    }
    #[test]
    fn origins_schedule_context_waits_for_lookup_and_rejects_previous_session() {
        use crate::packet_info::{PacketInfo, PacketInfoManager};
        let _test_lock = LOOKUP_TEST_LOCK.lock().unwrap();
        let remote = TcpListener::bind("127.0.0.1:0").unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let counter = AtomicUsize::new(0);
        let lookup = Arc::new(move |_: String| {
            let iteration = counter.fetch_add(1, Ordering::SeqCst);
            started_tx.send(()).unwrap();
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3))
                .unwrap();
            Ok(PacketInfoManager::new(
                format!("REV-{iteration}"),
                vec![PacketInfo {
                    header: 900 + iteration as u16,
                    direction: Direction::ToServer,
                    name: Some("Example".into()),
                    hash: None,
                    structure: None,
                    source: "fixture".into(),
                }],
            ))
        });
        let (mut relay, events) = Relay::start_with_options(
            Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                remote: remote.local_addr().unwrap().to_string(),
            },
            RelayOptions {
                shockwave: true,
                origins_lookup: Some(lookup),
                ..RelayOptions::default()
            },
        )
        .unwrap();
        let mut previous = None;
        for iteration in 0..2 {
            let client = TcpStream::connect(relay.address).unwrap();
            let (_server, _) = remote.accept().unwrap();
            started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            assert!(relay.connected());
            assert!(relay.schedule_context().is_none());
            if let Some(old) = &previous {
                assert_eq!(
                    relay
                        .inject_for_session(old, Direction::ToServer, Packet::new(1))
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::NotConnected
                );
            }
            release_tx.send(()).unwrap();
            wait_for(&events, |event| matches!(event, Event::Connected(_)));
            let context = relay.schedule_context().expect("ready Origins metadata");
            assert_eq!(context.version, format!("REV-{iteration}"));
            assert_eq!(context.packets.entries()[0].header, 900 + iteration as u16);
            previous = Some(context);
            client.shutdown(Shutdown::Both).unwrap();
            wait_for(&events, |event| matches!(event, Event::Disconnected));
        }
        relay.stop();
    }
    #[test]
    fn manual_tcp_schedule_context_keeps_configured_catalog_across_reconnect() {
        use crate::packet_info::{PacketInfo, PacketInfoManager};
        let remote = TcpListener::bind("127.0.0.1:0").unwrap();
        let catalog = PacketInfoManager::new(
            "MANUAL",
            vec![PacketInfo {
                header: 777,
                direction: Direction::ToServer,
                name: Some("Example".into()),
                hash: None,
                structure: None,
                source: "fixture".into(),
            }],
        );
        let (mut relay, events) = Relay::start_with_options(
            Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                remote: remote.local_addr().unwrap().to_string(),
            },
            RelayOptions {
                connection: Some(ConnectionDetails {
                    host: "fixture".into(),
                    port: 1,
                    version: "MANUAL".into(),
                    identifier: "fixture".into(),
                    client_type: "FLASH".into(),
                    packets: catalog,
                }),
                ..RelayOptions::default()
            },
        )
        .unwrap();
        let mut previous = None;
        for _ in 0..2 {
            let client = TcpStream::connect(relay.address).unwrap();
            let (mut server, _) = remote.accept().unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            wait_for(&events, |event| matches!(event, Event::Connected(_)));
            let context = relay.schedule_context().expect("manual catalog");
            assert_eq!(context.version, "MANUAL");
            assert_eq!(context.packets.entries()[0].header, 777);
            if let Some(old) = &previous {
                assert_eq!(
                    relay
                        .inject_for_session(old, Direction::ToServer, Packet::new(777))
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::NotConnected
                );
            }
            relay
                .inject_for_session(&context, Direction::ToServer, Packet::new(777))
                .unwrap();
            assert_eq!(read_frame(&mut server).unwrap().header(), 777);
            previous = Some(context);
            client.shutdown(Shutdown::Both).unwrap();
            wait_for(&events, |event| matches!(event, Event::Disconnected));
        }
        relay.stop();
    }
    #[test]
    fn origins_schedule_context_can_inject_before_crypto_handshake() {
        use crate::packet_info::{PacketInfo, PacketInfoManager};
        let remote = TcpListener::bind("127.0.0.1:0").unwrap();
        let catalog = PacketInfoManager::new(
            "ORIGINS",
            vec![PacketInfo {
                header: 777,
                direction: Direction::ToServer,
                name: Some("Example".into()),
                hash: None,
                structure: None,
                source: "fixture".into(),
            }],
        );
        let (mut relay, events) = Relay::start_with_options(
            Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                remote: remote.local_addr().unwrap().to_string(),
            },
            RelayOptions {
                shockwave: true,
                disable_origins_metadata: true,
                connection: Some(ConnectionDetails {
                    host: "fixture".into(),
                    port: 1,
                    version: "ORIGINS".into(),
                    identifier: "SHOCKWAVE".into(),
                    client_type: "SHOCKWAVE".into(),
                    packets: catalog,
                }),
                ..RelayOptions::default()
            },
        )
        .unwrap();
        let _client = TcpStream::connect(relay.address).unwrap();
        let (mut server, _) = remote.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        wait_for(&events, |event| matches!(event, Event::Connected(_)));
        let context = relay.schedule_context().expect("Origins metadata");
        let packet = Packet::new_with_format(PacketFormat::WedgieOutgoing, 777).unwrap();
        let mut expected = crate::encoding::encode_b64(packet.bytes().len() as u32, 3).unwrap();
        expected.extend_from_slice(packet.bytes());
        relay
            .inject_for_session(&context, Direction::ToServer, packet)
            .unwrap();
        let mut actual = vec![0; expected.len()];
        server.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected);
        relay.stop();
    }
    #[test]
    fn accepted_scheduled_enqueue_is_not_a_delivery_acknowledgement() {
        use crate::scheduler::Scheduler;
        use std::time::SystemTime;
        let (sender, receiver) = mpsc::sync_channel(1);
        let session = Arc::new(Session {
            injections: sender,
            closed: Arc::new(AtomicBool::new(false)),
            flash_automatic: false,
            schedule_metadata: Mutex::new(None),
        });
        let mut relay = Relay {
            stop: Arc::new(AtomicBool::new(false)),
            active: Arc::new(Mutex::new(Some(session))),
            worker: None,
            rules: Arc::new(Mutex::new(Rules::default())),
            address: "127.0.0.1:0".parse().unwrap(),
        };
        let now = Instant::now();
        let mut scheduler = Scheduler::default();
        scheduler
            .add(
                Packet::new(777),
                Direction::ToServer,
                Duration::from_secs(1),
                Some(1),
                now,
            )
            .unwrap();
        scheduler
            .dispatch_with_wall_clock(now, SystemTime::now(), |direction, packet| {
                relay.inject(direction, packet.clone())
            })
            .unwrap();
        assert!(
            scheduler.jobs.is_empty(),
            "accepted enqueue consumes the occurrence"
        );
        // No worker sends the packet; disconnect discards the accepted command.
        relay.stop();
        drop(receiver);
        assert!(
            scheduler.jobs.is_empty(),
            "disconnect cannot restore an already accepted occurrence"
        );
    }
    #[test]
    fn output_preserves_partial_frame_across_backpressure_and_reports_disconnect() {
        struct ScriptedWriter {
            bytes: Vec<u8>,
            calls: usize,
            fail: io::ErrorKind,
        }
        impl Write for ScriptedWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                if self.calls == 1 {
                    let count = bytes.len().min(3);
                    self.bytes.extend_from_slice(&bytes[..count]);
                    Ok(count)
                } else if self.calls == 2 {
                    Err(io::Error::from(self.fail))
                } else {
                    self.bytes.extend_from_slice(bytes);
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let wire = Packet::new(777).bytes().to_vec();
        let mut output = Output::default();
        output.push_wire(wire.clone()).unwrap();
        let mut blocked = ScriptedWriter {
            bytes: Vec::new(),
            calls: 0,
            fail: io::ErrorKind::WouldBlock,
        };
        assert!(output.flush(&mut blocked).unwrap());
        assert_eq!(output.bytes, wire.len() - 3);
        assert!(output.flush(&mut blocked).unwrap());
        assert_eq!(blocked.bytes, wire);
        assert_eq!(output.bytes, 0);
        assert!(output.queue.is_empty());

        output.push_wire(wire.clone()).unwrap();
        let mut disconnected = ScriptedWriter {
            bytes: Vec::new(),
            calls: 0,
            fail: io::ErrorKind::BrokenPipe,
        };
        assert_eq!(
            output.flush(&mut disconnected).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(disconnected.bytes, &wire[..3]);
        assert_eq!(output.bytes, wire.len() - 3);
        assert_eq!(output.queue.front().unwrap().offset, 3);
    }
}
