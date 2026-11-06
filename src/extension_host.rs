//! Authenticated beta-29 extension host, with a nonblocking worker per extension.
use crate::{
    expression,
    extension::{self, ExtensionInfo, Incoming},
    packet::{Direction, FrameDecoder, Message, Packet},
    packet_info::PacketInfoManager,
};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct ConnectionDetails {
    pub host: String,
    pub port: u16,
    pub version: String,
    pub identifier: String,
    pub client_type: String,
    pub packets: PacketInfoManager,
}
impl ConnectionDetails {
    fn packet(&self) -> io::Result<Packet> {
        let mut p = Packet::new(5);
        p.put_string(&self.host)
            .and_then(|p| p.put_i32(i32::from(self.port)))
            .and_then(|p| p.put_string(&self.version))
            .and_then(|p| p.put_string(&self.identifier))
            .and_then(|p| p.put_string(&self.client_type))
            .map_err(io::Error::other)?;
        self.packets.append_to(&mut p).map_err(io::Error::other)?;
        Ok(p)
    }
}
#[derive(Clone, Debug)]
pub enum HostEvent {
    Pending { id: u64, info: ExtensionInfo },
    Connected { id: u64, info: ExtensionInfo },
    Disconnected(u64),
    Console { id: u64, text: String },
    Error { id: u64, text: String },
}
#[derive(Clone, Debug)]
pub struct ExtensionView {
    pub id: u64,
    pub info: ExtensionInfo,
    pub approved: bool,
}
struct Peer {
    id: u64,
    info: ExtensionInfo,
    approved: AtomicBool,
    closed: Arc<AtomicBool>,
    output: SyncSender<Packet>,
    responses: Mutex<Receiver<Message>>,
}
struct Shared {
    language: Mutex<String>,
    peers: Mutex<BTreeMap<u64, Arc<Peer>>>,
    tokens: Mutex<HashMap<String, (String, Instant)>>,
    connection: Mutex<Option<ConnectionDetails>>,
    packet_safety: Mutex<Option<Arc<Mutex<crate::packet_safety::PacketSafety>>>>,
    injections: SyncSender<(Direction, Packet)>,
    events: SyncSender<HostEvent>,
    stop: AtomicBool,
    next_id: AtomicU64,
    flags: Vec<String>,
}
pub struct ExtensionHost {
    shared: Arc<Shared>,
    injections: Mutex<Receiver<(Direction, Packet)>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    pub address: SocketAddr,
}
impl ExtensionHost {
    /// Use the same observed-ID and developer-mode state as the desktop.
    pub fn set_packet_safety(
        &self,
        safety: Arc<Mutex<crate::packet_safety::PacketSafety>>,
    ) -> io::Result<()> {
        *self
            .shared
            .packet_safety
            .lock()
            .map_err(|_| io::Error::other("packet safety lock poisoned"))? = Some(safety);
        Ok(())
    }

    pub fn start(
        address: SocketAddr,
        flags: Vec<String>,
    ) -> io::Result<(Arc<Self>, Receiver<HostEvent>)> {
        if !address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "extension host must bind loopback",
            ));
        }
        let listener = TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let (events, event_rx) = mpsc::sync_channel(1024);
        let (injections, injection_rx) = mpsc::sync_channel(256);
        let shared = Arc::new(Shared {
            language: Mutex::new("en".into()),
            peers: Mutex::new(BTreeMap::new()),
            tokens: Mutex::new(HashMap::new()),
            connection: Mutex::new(None),
            packet_safety: Mutex::new(None),
            injections,
            events,
            stop: AtomicBool::new(false),
            next_id: AtomicU64::new(1),
            flags,
        });
        let actor = shared.clone();
        let worker = thread::spawn(move || {
            let mut children = Vec::new();
            while !actor.stop.load(Ordering::Acquire) {
                children.retain(|j: &JoinHandle<()>| !j.is_finished());
                match listener.accept() {
                    Ok((stream, _)) => {
                        // Pending handshakes are bounded as well as authenticated peers.
                        if children.len() >= 32 {
                            drop(stream);
                            continue;
                        }
                        let state = actor.clone();
                        let id = state.next_id.fetch_add(1, Ordering::Relaxed);
                        children.push(thread::spawn(move || {
                            if let Err(e) = serve_peer(stream, id, &state) {
                                let _ = state.events.try_send(HostEvent::Error {
                                    id,
                                    text: e.to_string(),
                                });
                            }
                            if let Ok(mut peers) = state.peers.lock() {
                                if let Some(p) = peers.remove(&id) {
                                    p.closed.store(true, Ordering::Release);
                                }
                            }
                            let _ = state.events.try_send(HostEvent::Disconnected(id));
                        }));
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
            for child in children {
                let _ = child.join();
            }
        });
        Ok((
            Arc::new(Self {
                shared,
                injections: Mutex::new(injection_rx),
                worker: Mutex::new(Some(worker)),
                address,
            }),
            event_rx,
        ))
    }
    pub fn extensions(&self) -> Vec<ExtensionView> {
        self.shared
            .peers
            .lock()
            .map(|p| {
                p.values()
                    .map(|p| ExtensionView {
                        id: p.id,
                        info: p.info.clone(),
                        approved: p.approved.load(Ordering::Acquire),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn set_language(&self, language: &str) -> io::Result<()> {
        if !crate::i18n::LANGUAGES
            .iter()
            .any(|(code, _)| *code == language)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported language",
            ));
        }
        *self
            .shared
            .language
            .lock()
            .map_err(|_| io::Error::other("language lock poisoned"))? = language.into();
        self.broadcast(extension::update_host_info(language).map_err(io::Error::other)?);
        Ok(())
    }
    pub fn approve(&self, id: u64) -> io::Result<()> {
        let peer = self.peer(id)?;
        initialize(&self.shared, &peer)
    }
    pub fn disconnect(&self, id: u64) -> io::Result<()> {
        self.peer(id)?.closed.store(true, Ordering::Release);
        Ok(())
    }
    pub fn click(&self, id: u64) -> io::Result<()> {
        let p = self.peer(id)?;
        if !p.approved.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "extension not approved",
            ));
        }
        send(&p.output, Packet::new(1))
    }
    fn peer(&self, id: u64) -> io::Result<Arc<Peer>> {
        self.shared
            .peers
            .lock()
            .map_err(|_| io::Error::other("peer lock poisoned"))?
            .get(&id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "extension not found"))
    }
    pub fn start_connection(&self, details: ConnectionDetails) -> io::Result<()> {
        let packet = details.packet()?;
        *self
            .shared
            .connection
            .lock()
            .map_err(|_| io::Error::other("connection lock poisoned"))? = Some(details);
        self.broadcast(packet);
        Ok(())
    }
    pub fn end_connection(&self) {
        if let Ok(mut c) = self.shared.connection.lock() {
            *c = None;
            // Keep the connection lock until pending injections are discarded:
            // extension workers use the same lock while they enqueue, so an
            // old-session packet cannot race this drain into the next session.
            if let Ok(injections) = self.injections.lock() {
                while injections.try_recv().is_ok() {}
            }
        }
        self.broadcast(Packet::new(6));
    }
    fn broadcast(&self, packet: Packet) {
        if let Ok(peers) = self.shared.peers.lock() {
            for p in peers
                .values()
                .filter(|p| p.approved.load(Ordering::Acquire))
            {
                if send(&p.output, packet.clone()).is_err() {
                    p.closed.store(true, Ordering::Release);
                }
            }
        }
    }
    pub fn intercept(&self, message: &mut Message) -> io::Result<()> {
        let peers: Vec<_> = self
            .shared
            .peers
            .lock()
            .map_err(|_| io::Error::other("peer lock poisoned"))?
            .values()
            .filter(|p| p.approved.load(Ordering::Acquire) && !p.closed.load(Ordering::Acquire))
            .cloned()
            .collect();
        let deadline = Instant::now() + Duration::from_millis(500);
        for peer in peers {
            if self.shared.stop.load(Ordering::Acquire) || message.blocked {
                break;
            }
            let response = peer
                .responses
                .lock()
                .map_err(|_| io::Error::other("extension response lock poisoned"))?;
            // Discard old responses before a fresh transaction; indices are never trusted alone.
            while response.try_recv().is_ok() {}
            send(
                &peer.output,
                extension::intercept(message).map_err(io::Error::other)?,
            )?;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    peer.closed.store(true, Ordering::Release);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "extension interception timed out; session stopped",
                    ));
                }
                match response.recv_timeout(remaining.min(Duration::from_millis(20))) {
                    Ok(mut updated) => {
                        if updated.index != message.index
                            || updated.direction != message.direction
                            || updated.packet.format() != message.packet.format()
                        {
                            peer.closed.store(true, Ordering::Release);
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "extension response transaction or packet format mismatch",
                            ));
                        }
                        updated.packet.reset();
                        *message = updated;
                        break;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if self.shared.stop.load(Ordering::Acquire)
                            || peer.closed.load(Ordering::Acquire)
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "extension disconnected during interception",
                            ));
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "extension response channel closed",
                        ))
                    }
                }
            }
        }
        Ok(())
    }
    pub fn take_injections(&self) -> Vec<(Direction, Packet)> {
        self.injections
            .lock()
            .map(|r| r.try_iter().take(64).collect())
            .unwrap_or_default()
    }
    pub fn launch(&self, executable: &Path, path: &Path) -> io::Result<Child> {
        let path = path.canonicalize()?;
        if !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "extension must be a regular file",
            ));
        }
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::other("invalid extension filename"))?
            .to_owned();
        let token = self.register_launch(&filename)?;
        let mut command = Command::new(executable);
        match path
            .extension()
            .and_then(|s| s.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("jar") => {
                command.arg("-jar").arg(&path);
            }
            Some("py" | "js") => {
                command.arg(&path);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "choose a .jar, .py or .js extension",
                ))
            }
        }
        command
            .arg("-p")
            .arg(self.address.port().to_string())
            .arg("-f")
            .arg(&filename)
            .arg("-c")
            .arg(token);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        command.spawn()
    }
    pub fn register_launch(&self, filename: &str) -> io::Result<String> {
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
        let token = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let mut tokens = self
            .shared
            .tokens
            .lock()
            .map_err(|_| io::Error::other("token lock poisoned"))?;
        tokens.retain(|_, (_, expires)| *expires > Instant::now());
        tokens.insert(
            token.clone(),
            (
                filename.to_owned(),
                Instant::now() + Duration::from_secs(60),
            ),
        );
        Ok(token)
    }
    /// Launch an installed store command with the original file-bound IPC placeholders.
    pub fn launch_command(
        &self,
        words: &[String],
        directory: &Path,
        filename: &str,
        label: &str,
        java_runtime: &Path,
    ) -> io::Result<Child> {
        if words.is_empty()
            || words.len() > 128
            || words
                .iter()
                .any(|word| word.contains('\0') || word.len() > 16384)
            || filename.is_empty()
            || filename.len() > 256
            || !filename
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(io::Error::other("invalid installed extension command"));
        }
        let directory = directory.canonicalize()?;
        if !directory.is_dir() {
            return Err(io::Error::other(
                "extension working directory is unavailable",
            ));
        }
        let token = self.register_launch(filename)?;
        let command = words
            .iter()
            .map(|word| {
                word.replace("{port}", &self.address.port().to_string())
                    .replace("{filename}", filename)
                    .replace("{cookie}", &token)
            })
            .collect::<Vec<_>>();
        let program = if matches!(
            command[0].to_ascii_lowercase().as_str(),
            "java" | "java.exe" | "javaw" | "javaw.exe"
        ) && !java_runtime.as_os_str().is_empty()
        {
            java_runtime.to_path_buf()
        } else {
            let program = std::path::PathBuf::from(&command[0]);
            if !program.is_absolute() && (command[0].contains('/') || command[0].contains('\\')) {
                let path = directory.join(program).canonicalize()?;
                if !path.starts_with(&directory) {
                    return Err(io::Error::other(
                        "relative extension entry point escapes its installation",
                    ));
                }
                path
            } else {
                program
            }
        };
        let mut child = Command::new(program);
        child
            .args(&command[1..])
            .current_dir(directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            child.creation_flags(0x08000000);
        }
        let mut process = child.spawn()?;
        if let Some(output) = process.stdout.take() {
            self.capture_output(output, format!("{label} stdout"));
        }
        if let Some(output) = process.stderr.take() {
            self.capture_output(output, format!("{label} stderr"));
        }
        Ok(process)
    }
    fn capture_output(&self, mut output: impl Read + Send + 'static, label: String) {
        let state = self.shared.clone();
        thread::spawn(move || {
            let mut buffer = [0; 4096];
            loop {
                match output.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => {
                        for line in String::from_utf8_lossy(&buffer[..count]).lines() {
                            let _ = state.events.try_send(HostEvent::Console {
                                id: 0,
                                text: format!("{label}: {line}"),
                            });
                        }
                    }
                }
                if state.stop.load(Ordering::Acquire) {
                    break;
                }
            }
        });
    }
    pub fn stop(&self) {
        self.shared.stop.store(true, Ordering::Release);
        if let Ok(peers) = self.shared.peers.lock() {
            for p in peers.values() {
                p.closed.store(true, Ordering::Release);
            }
        }
        if let Ok(mut worker) = self.worker.lock() {
            if let Some(j) = worker.take() {
                let _ = j.join();
            }
        }
    }
}
impl Drop for ExtensionHost {
    fn drop(&mut self) {
        self.stop();
    }
}
fn send(sender: &SyncSender<Packet>, packet: Packet) -> io::Result<()> {
    sender.try_send(packet).map_err(|_| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "extension output queue unavailable",
        )
    })
}
fn initialize(shared: &Shared, peer: &Peer) -> io::Result<()> {
    if peer.approved.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    let connection = shared
        .connection
        .lock()
        .map_err(|_| io::Error::other("connection lock poisoned"))?
        .clone();
    let language = shared
        .language
        .lock()
        .map_err(|_| io::Error::other("language lock poisoned"))?
        .clone();
    send(
        &peer.output,
        extension::init_with_language(connection.is_some(), &language).map_err(io::Error::other)?,
    )?;
    if let Some(c) = connection {
        send(&peer.output, c.packet()?)?;
    }
    let _ = shared.events.try_send(HostEvent::Connected {
        id: peer.id,
        info: peer.info.clone(),
    });
    Ok(())
}
fn serve_peer(mut stream: TcpStream, id: u64, shared: &Arc<Shared>) -> io::Result<()> {
    stream.set_nonblocking(true)?;
    stream.set_nodelay(true)?;
    let (output, commands) = mpsc::sync_channel::<Packet>(64);
    let (responses, response_rx) = mpsc::sync_channel::<Message>(8);
    let closed = Arc::new(AtomicBool::new(false));
    let mut response_rx = Some(response_rx);
    let mut peer: Option<Arc<Peer>> = None;
    let mut pending = VecDeque::from([(extension::info_request(), 0usize)]);
    let mut pending_bytes = 6usize;
    let mut decoder = FrameDecoder::default();
    let mut buffer = [0u8; 8192];
    let handshake = Instant::now() + Duration::from_secs(30);
    while !shared.stop.load(Ordering::Acquire) && !closed.load(Ordering::Acquire) {
        if peer.is_none() && Instant::now() > handshake {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "extension handshake timed out",
            ));
        }
        let mut progress = false;
        for p in commands.try_iter().take(64) {
            pending_bytes += p.bytes().len();
            if pending_bytes > 32 * 1024 * 1024 {
                return Err(io::Error::other("extension output byte limit"));
            }
            pending.push_back((p, 0));
        }
        if let Some((p, offset)) = pending.front_mut() {
            match stream.write(&p.bytes()[*offset..]) {
                Ok(0) => break,
                Ok(n) => {
                    progress = true;
                    pending_bytes -= n;
                    *offset += n;
                    if *offset == p.bytes().len() {
                        pending.pop_front();
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                progress = true;
                decoder.push(&buffer[..n]).map_err(io::Error::other)?;
                while let Some(p) = decoder.next_packet().map_err(io::Error::other)? {
                    let incoming = extension::decode(p).map_err(io::Error::other)?;
                    if let Incoming::Info(info) = incoming {
                        if peer.is_some() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "duplicate extension info",
                            ));
                        }
                        let auto = if let Some(filename) = &info.file {
                            let claimed = shared
                                .tokens
                                .lock()
                                .map_err(|_| io::Error::other("token lock poisoned"))?
                                .remove(&info.cookie);
                            match claimed {
                                Some((expected, expires))
                                    if expected == *filename && expires > Instant::now() =>
                                {
                                    true
                                }
                                _ => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::PermissionDenied,
                                        "invalid or expired extension launch token",
                                    ))
                                }
                            }
                        } else {
                            false
                        };
                        let p = Arc::new(Peer {
                            id,
                            info: info.clone(),
                            approved: AtomicBool::new(false),
                            closed: closed.clone(),
                            output: output.clone(),
                            responses: Mutex::new(response_rx.take().unwrap()),
                        });
                        shared
                            .peers
                            .lock()
                            .map_err(|_| io::Error::other("peer lock poisoned"))?
                            .insert(id, p.clone());
                        if auto {
                            initialize(shared, &p)?;
                        } else {
                            let _ = shared.events.try_send(HostEvent::Pending { id, info });
                        }
                        peer = Some(p);
                        continue;
                    }
                    let p = peer
                        .as_ref()
                        .filter(|p| p.approved.load(Ordering::Acquire))
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "extension has not been approved",
                            )
                        })?;
                    match incoming {
                        Incoming::Manipulated(m) => {
                            responses
                                .try_send(m)
                                .map_err(|_| io::Error::other("unsolicited extension responses"))?;
                        }
                        Incoming::RequestFlags => send(
                            &output,
                            extension::flags(&shared.flags).map_err(io::Error::other)?,
                        )?,
                        Incoming::Send { direction, packet } => {
                            let connection = shared
                                .connection
                                .lock()
                                .map_err(|_| io::Error::other("connection lock poisoned"))?;
                            let revision = connection
                                .as_ref()
                                .map(|connection| connection.version.clone());
                            if let Some(revision) = revision {
                                let allowed = match shared.packet_safety.lock() {
                                    Ok(policy) => match policy.as_ref() {
                                        Some(safety) => safety.lock().is_ok_and(|safety| {
                                            safety.may_send_with_current_mode(
                                                Some(&revision),
                                                direction,
                                                packet.header(),
                                            )
                                        }),
                                        None => true,
                                    },
                                    Err(_) => false,
                                };
                                if !allowed {
                                    let _ = shared.events.try_send(HostEvent::Console {
                                        id: p.id,
                                        text: format!("Packet {} not sent: ID not observed for this hotel version and direction", packet.header()),
                                    });
                                    continue;
                                }
                                shared
                                    .injections
                                    .try_send((direction, packet))
                                    .map_err(|_| {
                                        io::Error::other("extension injection queue full")
                                    })?;
                            }
                            drop(connection);
                        }
                        Incoming::Console(text) => {
                            let _ = shared
                                .events
                                .try_send(HostEvent::Console { id: p.id, text });
                        }
                        Incoming::PacketToString { text, format } => {
                            let decoded = Packet::from_stringified_with_format(&text, format)
                                .map_err(io::Error::other)?;
                            let connection = shared
                                .connection
                                .lock()
                                .map_err(|_| io::Error::other("connection lock poisoned"))?
                                .clone();
                            let expression = if format == crate::packet::PacketFormat::EvaWire {
                                if decoded.bytes().len().saturating_sub(4) >= 3000 {
                                    String::new()
                                } else {
                                    let find = |direction| {
                                        connection.as_ref().and_then(|connection| {
                                            let mut entries = connection
                                                .packets
                                                .by_header(direction, decoded.header());
                                            let first = entries.next()?;
                                            if first.structure.is_some() {
                                                Some(first)
                                            } else {
                                                Some(
                                                    entries
                                                        .find(|entry| entry.structure.is_some())
                                                        .unwrap_or(first),
                                                )
                                            }
                                        })
                                    };
                                    let incoming = find(Direction::ToClient);
                                    let outgoing = find(Direction::ToServer);
                                    let selected = match (incoming, outgoing) {
                                        (Some(info), None) => Some(("in", info)),
                                        (None, Some(info)) => Some(("out", info)),
                                        _ => None,
                                    };
                                    let identifier = selected.and_then(|(direction, info)| {
                                        info.name
                                            .as_ref()
                                            .or(info.hash.as_ref())
                                            .map(|name| format!("{direction}:{name}"))
                                    });
                                    let unity = connection.as_ref().is_some_and(|c| {
                                        c.client_type.eq_ignore_ascii_case("UNITY")
                                    });
                                    let structure = selected
                                        .and_then(|(_, info)| info.structure.clone())
                                        .map(Ok)
                                        .unwrap_or_else(|| {
                                            crate::structure_prediction::predict(&decoded, unity)
                                        });
                                    structure
                                        .and_then(|s| {
                                            crate::structure_prediction::expression_from_structure(
                                                &decoded,
                                                &s,
                                                identifier.as_deref(),
                                            )
                                        })
                                        .unwrap_or_default()
                                }
                            } else {
                                expression::to_lossless_expression(&decoded)
                            };
                            let mut result = Packet::new(20);
                            result
                                .put_long_string(&expression::wire_display(decoded.bytes()))
                                .and_then(|p| p.put_long_bytes(expression.as_bytes()))
                                .map_err(io::Error::other)?;
                            send(&output, result)?;
                        }
                        Incoming::StringToPacket { text, format } => {
                            let connection = shared
                                .connection
                                .lock()
                                .map_err(|_| io::Error::other("connection lock poisoned"))?
                                .clone();
                            let direction = if text.starts_with("{in:") {
                                Direction::ToClient
                            } else {
                                Direction::ToServer
                            };
                            let context = connection.as_ref().map(|c| (direction, &c.packets));
                            let decoded = expression::parse_with_format(&text, format, context)
                                .map_err(io::Error::other)?;
                            let mut result = Packet::new(21);
                            result
                                .put_long_string(&decoded.stringify())
                                .map_err(io::Error::other)?;
                            send(&output, result)?;
                        }
                        Incoming::Info(_) => unreachable!(),
                    }
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
        if !progress {
            thread::sleep(Duration::from_millis(2));
        }
    }
    Ok(())
}
