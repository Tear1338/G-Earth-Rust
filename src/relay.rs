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
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, SyncSender},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;
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
}
struct Session {
    injections: SyncSender<(Direction, Packet)>,
    closed: Arc<AtomicBool>,
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
        if !config.listen.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "listen address must be loopback",
            ));
        }
        let remote: Vec<SocketAddr> = if options.socks.is_some() {
            Vec::new()
        } else {
            config.remote.to_socket_addrs()?.collect()
        };
        if remote.is_empty() && options.socks.is_none() {
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
                            socks.connect(&config.remote).ok()
                        } else {
                            remote.iter().find_map(|addr| {
                                if worker_stop.load(Ordering::Acquire) {
                                    return None;
                                }
                                TcpStream::connect_timeout(addr, Duration::from_secs(2)).ok()
                            })
                        };
                        let Some(server) = server else {
                            let _ =
                                events.try_send(Event::Error("remote connection failed".into()));
                            continue;
                        };
                        let (injections, commands) = mpsc::sync_channel(256);
                        let closed = Arc::new(AtomicBool::new(false));
                        let session = Arc::new(Session {
                            injections,
                            closed: closed.clone(),
                        });
                        if let Ok(mut slot) = worker_active.lock() {
                            if worker_stop.load(Ordering::Acquire) {
                                break;
                            }
                            *slot = Some(session);
                        } else {
                            break;
                        }
                        let _ = events.try_send(Event::Connected(
                            server
                                .peer_addr()
                                .map(|v| v.to_string())
                                .unwrap_or_default(),
                        ));
                        if let (Some(host), Some(details)) =
                            (&options.extensions, &options.connection)
                        {
                            if options.flash_process.is_none() {
                                if let Err(e) = host.start_connection(details.clone()) {
                                    let _ = events.try_send(Event::Error(e.to_string()));
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
                        );
                        if let Some(host) = &options.extensions {
                            host.end_connection();
                        }
                        closed.store(true, Ordering::Release);
                        if let Err(e) = result {
                            let _ = events.try_send(Event::Error(e.to_string()));
                        }
                        if let Ok(mut slot) = worker_active.lock() {
                            *slot = None;
                        }
                        let _ = events.try_send(Event::Disconnected);
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
    fn flush(&mut self, stream: &mut TcpStream) -> io::Result<bool> {
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
    while !stop.load(Ordering::Acquire) && !closed.load(Ordering::Acquire) {
        let mut progress = false;
        let mut injected: Vec<_> = commands.try_iter().take(64).collect();
        if let Some(host) = &options.extensions {
            injected.extend(host.take_injections());
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
                Ok(0) => return Ok(()),
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
                    let _ = events.try_send(Event::Identified {
                        version: identity.version.clone(),
                        identifier: identity.identifier.clone(),
                    });
                    if let (Some(host), Some(details)) = (&options.extensions, &options.connection)
                    {
                        let mut details = details.clone();
                        details.version = identity.version;
                        details.identifier = identity.identifier;
                        if details.packets.entries().is_empty() {
                            let _ = events.try_send(Event::Status(
                                "Loading packet identifiers for the detected Flash revision..."
                                    .into(),
                            ));
                            match crate::packet_info::PacketInfoManager::fetch_sulek(
                                &details.version,
                                false,
                            ) {
                                Ok(database) => {
                                    let _ =
                                        events.try_send(Event::PacketIdentifiers(database.clone()));
                                    details.packets = database;
                                }
                                Err(e) => {
                                    let _ = events.try_send(Event::Status(format!(
                                        "Connected without packet names: {e}"
                                    )));
                                }
                            }
                            if stop.load(Ordering::Acquire) {
                                return Ok(());
                            }
                        }
                        host.start_connection(details)?;
                    }
                }
            }
            for (packet, encrypted) in packets {
                progress = true;
                let mut message = Message {
                    packet,
                    direction,
                    index: *index,
                    blocked: false,
                };
                *index = index.wrapping_add(1);
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
