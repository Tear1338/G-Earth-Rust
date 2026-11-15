//! Flash negotiation and bounded RC4 recovery from read-only client snapshots.
use crate::{
    crypto::Rc4,
    packet::{Direction, Packet, MAX_FRAME},
};
use std::{
    io,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};
const BOOTSTRAP_LIMIT: usize = 65536;
const MAX_DISCOVERY_WORKERS: usize = 4;
static ACTIVE_DISCOVERY_WORKERS: AtomicUsize = AtomicUsize::new(0);

struct DiscoveryTask {
    cancel: Arc<AtomicBool>,
    events: mpsc::Receiver<DiscoveryEvent>,
}
impl Drop for DiscoveryTask {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}
enum DiscoveryEvent {
    Scanned((usize, usize, bool)),
    Found(Vec<u8>, Box<Rc4>),
    Done(usize),
    Failed(io::Error),
}
struct DiscoverySlot;
impl Drop for DiscoverySlot {
    fn drop(&mut self) {
        ACTIVE_DISCOVERY_WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}
#[derive(Default)]
struct Side {
    buffer: Vec<u8>,
    encrypted: bool,
    reader: Option<Rc4>,
    writer: Option<Rc4>,
    waiting: Option<Instant>,
    last_scan: Option<Instant>,
}
impl Side {
    fn feed(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.buffer.len() + bytes.len()
            > if self.encrypted && self.reader.is_none() {
                BOOTSTRAP_LIMIT
            } else {
                MAX_FRAME + 65536
            }
        {
            return Err(io::Error::other("Flash buffer limit exceeded"));
        }
        let start = self.buffer.len();
        self.buffer.extend_from_slice(bytes);
        if let Some(cipher) = &mut self.reader {
            cipher.apply(&mut self.buffer[start..]);
        }
        Ok(())
    }
    fn next(&mut self) -> io::Result<Option<Packet>> {
        if self.encrypted && self.reader.is_none() || self.buffer.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_be_bytes(self.buffer[..4].try_into().unwrap()) as usize;
        if !(2..=MAX_FRAME).contains(&n) {
            return Err(io::Error::other("invalid Flash frame length"));
        }
        if self.buffer.len() < n + 4 {
            return Ok(None);
        }
        let p =
            Packet::from_bytes(self.buffer.drain(..n + 4).collect()).map_err(io::Error::other)?;
        Ok(Some(p))
    }
    fn negotiate(&mut self) {
        self.encrypted = true;
        self.waiting = Some(Instant::now());
    }
    fn install(&mut self, cipher: Rc4) {
        self.writer = Some(cipher.clone());
        let mut reader = cipher;
        reader.apply(&mut self.buffer);
        self.reader = Some(reader);
        self.waiting = None;
    }
}
pub struct DecodedPacket {
    pub packet: Packet,
    pub encrypted: bool,
}
#[derive(Clone, Debug)]
pub struct Identity {
    pub version: String,
    pub identifier: String,
}
#[derive(Default)]
pub struct FlashSession {
    outgoing: Side,
    incoming: Side,
    identity: Option<Identity>,
    reported: bool,
    incoming_count: usize,
    negotiated: bool,
    scan_stats: Option<(usize, usize, bool)>,
    discovery: [Option<DiscoveryTask>; 2],
}
impl FlashSession {
    pub fn feed(&mut self, direction: Direction, bytes: &[u8]) -> io::Result<Vec<DecodedPacket>> {
        let (packets, error) = self.feed_batch(direction, bytes)?;
        match error {
            Some(error) => Err(error),
            None => Ok(packets),
        }
    }
    /// Preserve decoded packets preceding a malformed frame in the same input.
    pub fn feed_batch(
        &mut self,
        direction: Direction,
        bytes: &[u8],
    ) -> io::Result<(Vec<DecodedPacket>, Option<io::Error>)> {
        self.side(direction).feed(bytes)?;
        let mut packets = Vec::new();
        loop {
            let side = self.side(direction);
            let encrypted = side.encrypted;
            let packet = match side.next() {
                Ok(Some(packet)) => packet,
                Ok(None) => return Ok((packets, None)),
                Err(error) => return Ok((packets, Some(error))),
            };
            self.observe(direction, &packet);
            packets.push(DecodedPacket { packet, encrypted });
        }
    }
    fn side(&mut self, direction: Direction) -> &mut Side {
        if direction == Direction::ToServer {
            &mut self.outgoing
        } else {
            &mut self.incoming
        }
    }
    fn observe(&mut self, direction: Direction, p: &Packet) {
        if direction == Direction::ToServer && self.identity.is_none() && p.bytes().len() < 104 {
            let mut hello = p.clone();
            if let (Ok(version), Ok(identifier)) = (hello.read_string(), hello.read_string()) {
                self.identity = Some(Identity {
                    version,
                    identifier,
                });
            }
        }
        if direction == Direction::ToClient {
            if !self.negotiated && self.identity.is_some() && self.incoming_count < 2 {
                let mut packet = p.clone();
                if packet.read_string().is_ok() {
                    let remaining = packet.remaining();
                    if p.bytes().len() > 504 && remaining == 1 {
                        let incoming = packet.read_bool().unwrap_or(false);
                        self.outgoing.negotiate();
                        if incoming {
                            self.incoming.negotiate();
                        }
                        self.negotiated = true;
                    } else if p.bytes().len() > 204 && remaining == 0 {
                        self.outgoing.negotiate();
                        self.negotiated = true;
                    }
                }
            }
            self.incoming_count += 1;
        }
    }
    pub fn take_identity(&mut self) -> Option<Identity> {
        if self.reported {
            return None;
        }
        let identity = self.identity.clone()?;
        self.reported = true;
        Some(identity)
    }
    pub fn encrypted(&mut self, direction: Direction) -> bool {
        self.side(direction).encrypted
    }
    /// Whether an injection can be encoded without waiting for the direction's key.
    pub fn ready_for_injection(&self, direction: Direction) -> bool {
        let side = if direction == Direction::ToServer {
            &self.outgoing
        } else {
            &self.incoming
        };
        if !side.encrypted {
            return true;
        }
        if side.writer.is_none() {
            return false;
        }
        if side.buffer.len() < 4 {
            return true;
        }
        let length = u32::from_be_bytes(side.buffer[..4].try_into().unwrap()) as usize;
        // Deliver complete buffered traffic, or report an invalid prefix, before
        // allowing an injection to overtake it on the same encrypted stream.
        (2..=MAX_FRAME).contains(&length) && side.buffer.len() < length + 4
    }
    pub fn encode(
        &mut self,
        direction: Direction,
        packet: &Packet,
        encrypted: bool,
    ) -> io::Result<Vec<u8>> {
        let mut bytes = packet.bytes().to_vec();
        if encrypted {
            let cipher = self.side(direction).writer.as_mut().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Flash key discovery is still pending",
                )
            })?;
            cipher.apply(&mut bytes);
        }
        Ok(bytes)
    }
    pub fn recover_with(&mut self, states: &[[u8; 256]], cancel: &AtomicBool) -> io::Result<bool> {
        for direction in [Direction::ToServer, Direction::ToClient] {
            let side = self.side(direction);
            if side.encrypted && side.reader.is_none() && side.buffer.len() >= 6 {
                if let Some(cipher) = recover_state(states, &side.buffer, direction, cancel)? {
                    side.install(cipher);
                }
            }
        }
        Ok([&self.outgoing, &self.incoming]
            .iter()
            .all(|s| !s.encrypted || s.reader.is_some()))
    }
    fn discovery_index(direction: Direction) -> usize {
        if direction == Direction::ToServer {
            0
        } else {
            1
        }
    }
    // Each direction has its own cancellable worker. A slow outgoing reversal
    // cannot prevent a later incoming key from being recovered.
    fn start_discovery<F>(&mut self, direction: Direction, scan: F) -> io::Result<bool>
    where
        F: FnOnce(&AtomicBool) -> io::Result<gearth_platform::ScanResult> + Send + 'static,
    {
        let index = Self::discovery_index(direction);
        if self.discovery[index].is_some() {
            return Ok(false);
        }
        let side = self.side(direction);
        if !side.encrypted || side.reader.is_some() || side.buffer.len() < 6 {
            return Ok(false);
        }
        let sample = side.buffer.clone();
        if ACTIVE_DISCOVERY_WORKERS
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_DISCOVERY_WORKERS).then_some(n + 1)
            })
            .is_err()
        {
            return Ok(false);
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let (sender, events) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("gearth-flash-discovery".into())
            .spawn(move || {
                let _slot = DiscoverySlot;
                let scan = match scan(&worker_cancel) {
                    Ok(scan) => scan,
                    Err(error) => {
                        let _ = sender.send(DiscoveryEvent::Failed(error));
                        return;
                    }
                };
                let _ = sender.send(DiscoveryEvent::Scanned((
                    scan.states.len(),
                    scan.bytes_read,
                    scan.complete,
                )));
                let length = sample.len();
                match recover_state_inner(&scan.states, &sample, direction, &worker_cancel, None) {
                    Ok(Some(cipher)) => {
                        let _ = sender.send(DiscoveryEvent::Found(sample, Box::new(cipher)));
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let _ = sender.send(DiscoveryEvent::Failed(error));
                        return;
                    }
                }
                let _ = sender.send(DiscoveryEvent::Done(length));
            });
        if let Err(error) = worker {
            ACTIVE_DISCOVERY_WORKERS.fetch_sub(1, Ordering::AcqRel);
            return Err(error);
        }
        self.discovery[index] = Some(DiscoveryTask { cancel, events });
        Ok(true)
    }
    fn poll_discovery(&mut self, direction: Direction, now: Instant) -> io::Result<()> {
        let index = Self::discovery_index(direction);
        while let Some(task) = &self.discovery[index] {
            let event = match task.events.try_recv() {
                Ok(event) => event,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.discovery[index] = None;
                    return Err(io::Error::other(
                        "Flash discovery worker stopped unexpectedly",
                    ));
                }
            };
            match event {
                DiscoveryEvent::Scanned(stats) => self.scan_stats = Some(stats),
                DiscoveryEvent::Found(sample, cipher) => {
                    let side = self.side(direction);
                    if side.encrypted && side.reader.is_none() && side.buffer.starts_with(&sample) {
                        side.install(*cipher);
                    }
                }
                DiscoveryEvent::Done(sampled_len) => {
                    self.discovery[index] = None;
                    let side = self.side(direction);
                    if side.reader.is_none() && side.buffer.len() > sampled_len {
                        side.waiting = Some(now);
                    }
                    break;
                }
                DiscoveryEvent::Failed(error) => {
                    self.discovery[index] = None;
                    return Err(error);
                }
            }
        }
        Ok(())
    }
    pub fn discover(&mut self, pid: u32, cancel: &AtomicBool) -> io::Result<()> {
        if cancel.load(Ordering::Acquire) {
            self.discovery = [None, None];
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "key discovery cancelled",
            ));
        }
        let now = Instant::now();
        for direction in [Direction::ToClient, Direction::ToServer] {
            self.poll_discovery(direction, now)?;
            let index = Self::discovery_index(direction);
            let running = self.discovery[index].is_some();
            let side = self.side(direction);
            if !running
                && side
                    .waiting
                    .is_some_and(|t| now.duration_since(t) > Duration::from_secs(15))
            {
                return Err(io::Error::new(io::ErrorKind::TimedOut,format!("Flash RC4 discovery timed out; scan {:?}; pending outgoing {} bytes, incoming {} bytes",self.scan_stats,if self.outgoing.reader.is_none(){self.outgoing.buffer.len()}else{0},if self.incoming.reader.is_none(){self.incoming.buffer.len()}else{0})));
            }
            if !running
                && side.encrypted
                && side.reader.is_none()
                && side.buffer.len() >= 6
                && side
                    .last_scan
                    .is_none_or(|t| now.duration_since(t) >= Duration::from_millis(100))
            {
                side.last_scan = Some(now);
                self.start_discovery(direction, move |cancel| {
                    let pid = if pid == 0 {
                        let processes = gearth_platform::habbo_processes()?;
                        if processes.len() != 1 { return Err(io::Error::other("Unable to identify the connecting client; select the Habbo process before attaching")); }
                        processes[0].pid
                    } else { pid };
                    gearth_platform::scan_habbo(pid, cancel)
                })?;
            }
        }
        Ok(())
    }
}
fn valid_frames(encrypted: &[u8], candidate: &Rc4) -> bool {
    let mut prefix = encrypted[..4].to_vec();
    let mut cipher = candidate.clone();
    cipher.apply(&mut prefix);
    let length = u32::from_be_bytes(prefix[..4].try_into().unwrap()) as usize;
    if !(2..=MAX_FRAME).contains(&length) || length + 4 > encrypted.len() {
        return false;
    }
    let mut decoded = encrypted.to_vec();
    candidate.clone().apply(&mut decoded);
    let mut at = 0;
    let mut count = 0;
    while at + 6 <= decoded.len() {
        let n = u32::from_be_bytes(decoded[at..at + 4].try_into().unwrap()) as usize;
        if !(2..=MAX_FRAME).contains(&n) || at + n + 4 > decoded.len() {
            break;
        }
        at += n + 4;
        count += 1;
    }
    at == decoded.len() && count > 0
}
pub fn recover_state(
    states: &[[u8; 256]],
    encrypted: &[u8],
    direction: Direction,
    cancel: &AtomicBool,
) -> io::Result<Option<Rc4>> {
    recover_state_inner(
        states,
        encrypted,
        direction,
        cancel,
        Some(Instant::now() + Duration::from_secs(5)),
    )
}
fn recover_state_inner(
    states: &[[u8; 256]],
    encrypted: &[u8],
    direction: Direction,
    cancel: &AtomicBool,
    deadline: Option<Instant>,
) -> io::Result<Option<Rc4>> {
    if cancel.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "key discovery cancelled",
        ));
    }
    if encrypted.len() < 6 || encrypted.len() > BOOTSTRAP_LIMIT {
        return Ok(None);
    }
    // Flash commonly retains the fresh shared-secret table for the opposite direction.
    // Prefer that exact table over reversing a snapshot with an unknown j counter.
    let mut fresh = None;
    for state in states.iter().take(gearth_platform::MAX_TABLES) {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "key discovery cancelled",
            ));
        }
        let candidate = Rc4::from_state(*state, 0, 0).map_err(io::Error::other)?;
        if valid_frames(encrypted, &candidate) {
            if fresh
                .as_ref()
                .is_some_and(|c: &Rc4| c.state() != candidate.state())
            {
                return Ok(None);
            }
            fresh = Some(candidate);
        }
    }
    if fresh.is_some() || direction == Direction::ToClient {
        return Ok(fresh);
    }
    let mut found = None;
    for state in states.iter().take(gearth_platform::MAX_TABLES) {
        for y in 0..256 {
            if cancel.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "key discovery cancelled",
                ));
            }
            if deadline.is_some_and(|deadline| Instant::now() > deadline) {
                return Ok(None);
            }
            let mut candidate = Rc4::from_state(*state, encrypted.len() as u8, y as u8)
                .map_err(io::Error::other)?;
            candidate.rewind(encrypted.len());
            let (_, x, y) = candidate.state();
            if x != 0 || y != 0 || !valid_frames(encrypted, &candidate) {
                continue;
            }
            // Different reverse states can reproduce frame lengths yet corrupt the final body byte.
            // Wait for additional evidence rather than silently selecting the first match.
            if found
                .as_ref()
                .is_some_and(|c: &Rc4| c.state() != candidate.state())
            {
                return Ok(None);
            }
            found = Some(candidate);
        }
    }
    Ok(found)
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use crate::packet::Packet;

    fn outgoing_fixture() -> (Rc4, Rc4, Vec<u8>) {
        let cancel = AtomicBool::new(false);
        for index in 0..16 {
            let fresh = Rc4::new(format!("target-key-{index}").as_bytes()).unwrap();
            let mut current = fresh.clone();
            let mut packet = Packet::new(77);
            for n in 0..32 {
                packet.put_i32(n * 1103).unwrap();
            }
            let mut wire = packet.bytes().to_vec();
            current.apply(&mut wire);
            if recover_state(&[current.state().0], &wire, Direction::ToServer, &cancel)
                .unwrap()
                .is_some()
            {
                return (fresh, current, wire);
            }
        }
        panic!("no unambiguous fixture");
    }

    #[test]
    fn background_discovery_reaches_late_candidate_while_buffer_grows() {
        let (fresh, mut current, first_wire) = outgoing_fixture();
        let mut tables: Vec<_> = (0..96)
            .map(|i| {
                Rc4::new(format!("unrelated-{i}").as_bytes())
                    .unwrap()
                    .state()
                    .0
            })
            .collect();
        tables.push(current.state().0);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut session = FlashSession::default();
        session.outgoing.encrypted = true;
        session.outgoing.waiting = Some(Instant::now());
        session.outgoing.feed(&first_wire).unwrap();
        assert!(session
            .start_discovery(Direction::ToServer, move |cancel| {
                started_tx.send(()).unwrap();
                while !cancel.load(Ordering::Acquire) {
                    if release_rx.recv_timeout(Duration::from_millis(5)).is_ok() {
                        return Ok(gearth_platform::ScanResult {
                            states: tables,
                            bytes_read: 100,
                            complete: true,
                        });
                    }
                }
                Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
            })
            .unwrap());
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        session.outgoing.waiting = Instant::now().checked_sub(Duration::from_secs(16));
        session.discover(1, &AtomicBool::new(false)).unwrap();
        assert!(
            session.discovery[0].is_some(),
            "an active search must not be cut off by the idle timeout"
        );
        let mut second = Packet::new(78);
        second.put_i32(42).unwrap();
        let mut second_wire = second.bytes().to_vec();
        current.apply(&mut second_wire);
        assert!(session
            .feed(Direction::ToServer, &second_wire)
            .unwrap()
            .is_empty());
        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while session.discovery[0].is_some() {
            session
                .poll_discovery(Direction::ToServer, Instant::now())
                .unwrap();
            assert!(Instant::now() < deadline, "discovery did not finish");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            session.outgoing.writer.as_ref().unwrap().state(),
            fresh.state()
        );
        let packets = session.feed(Direction::ToServer, &[]).unwrap();
        assert_eq!(
            packets
                .iter()
                .map(|packet| packet.packet.header())
                .collect::<Vec<_>>(),
            [77, 78]
        );
        assert!(packets.iter().all(|packet| packet.encrypted));
    }

    #[test]
    fn slow_outgoing_search_does_not_block_incoming_key() {
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let mut session = FlashSession::default();
        session.outgoing.encrypted = true;
        session.outgoing.buffer = vec![0; 6];
        assert!(session
            .start_discovery(Direction::ToServer, move |cancel| {
                started_tx.send(()).unwrap();
                while !cancel.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                done_tx.send(()).unwrap();
                Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
            })
            .unwrap());
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let incoming = Rc4::new(b"incoming-fixture-key").unwrap();
        let mut wire = Packet::new(81).bytes().to_vec();
        incoming.clone().apply(&mut wire);
        session.incoming.encrypted = true;
        session.incoming.feed(&wire).unwrap();
        assert!(session
            .start_discovery(Direction::ToClient, move |_| Ok(
                gearth_platform::ScanResult {
                    states: vec![incoming.state().0],
                    bytes_read: 1024,
                    complete: true,
                }
            ))
            .unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        while session.discovery[1].is_some() {
            session
                .poll_discovery(Direction::ToClient, Instant::now())
                .unwrap();
            assert!(Instant::now() < deadline, "incoming search stalled");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(session.discovery[0].is_some());
        assert_eq!(
            session.feed(Direction::ToClient, &[]).unwrap()[0]
                .packet
                .header(),
            81
        );
        drop(session);
        done_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    }

    #[test]
    fn dropping_session_cancels_background_discovery() {
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let mut session = FlashSession::default();
        session.outgoing.encrypted = true;
        session.outgoing.buffer = vec![0; 6];
        assert!(session
            .start_discovery(Direction::ToServer, move |cancel| {
                started_tx.send(()).unwrap();
                while !cancel.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                done_tx.send(()).unwrap();
                Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
            })
            .unwrap());
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        drop(session);
        done_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    }
}
