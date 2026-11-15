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
    Scanned((usize, usize, bool), mpsc::SyncSender<CiphertextSample>),
    Candidate(Vec<u8>, Box<RecoveryOutcome>),
    Done {
        sampled_len: usize,
        next_address: Option<usize>,
    },
    Failed(io::Error),
}
struct CiphertextSample {
    bytes: Vec<u8>,
    at_capacity: bool,
}
struct DiscoverySlot;
impl Drop for DiscoverySlot {
    fn drop(&mut self) {
        ACTIVE_DISCOVERY_WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}
// Fresh-table candidates have the same preference as the original single-page
// search. Ambiguity at the highest observed priority prevents installation.
#[derive(Default)]
struct CandidateAccumulator {
    priority: u8,
    ambiguous: bool,
    cipher: Option<Rc4>,
}
struct RecoveryOutcome {
    priority: u8,
    ambiguous: bool,
    cipher: Option<Rc4>,
}
impl CandidateAccumulator {
    fn merge(&mut self, outcome: RecoveryOutcome) {
        if outcome.priority == 0 || outcome.priority < self.priority {
            return;
        }
        if outcome.priority > self.priority {
            self.priority = outcome.priority;
            self.ambiguous = outcome.ambiguous;
            self.cipher = outcome.cipher;
            return;
        }
        if outcome.ambiguous || self.ambiguous {
            self.ambiguous = true;
            self.cipher = None;
        } else if let Some(candidate) = outcome.cipher {
            if self
                .cipher
                .as_ref()
                .is_some_and(|existing| existing.state() != candidate.state())
            {
                self.ambiguous = true;
                self.cipher = None;
            } else {
                self.cipher = Some(candidate);
            }
        }
    }
    fn take_unique(&mut self) -> Option<Rc4> {
        let previous = std::mem::take(self);
        if previous.ambiguous {
            None
        } else {
            previous.cipher
        }
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
    scan_address: usize,
    candidates: CandidateAccumulator,
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
    /// Remaining encrypted bootstrap space; zero pauses socket reads until recovery.
    pub fn input_capacity(&self, direction: Direction) -> usize {
        let side = if direction == Direction::ToServer {
            &self.outgoing
        } else {
            &self.incoming
        };
        if side.encrypted && side.reader.is_none() {
            BOOTSTRAP_LIMIT.saturating_sub(side.buffer.len())
        } else {
            usize::MAX
        }
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
                if scan.complete != scan.next_address.is_none() {
                    let _ = sender.send(DiscoveryEvent::Failed(io::Error::other(
                        "inconsistent Flash memory scan cursor",
                    )));
                    return;
                }
                let (sample_sender, sample_receiver) = mpsc::sync_channel(1);
                if sender
                    .send(DiscoveryEvent::Scanned(
                        (scan.states.len(), scan.bytes_read, scan.complete),
                        sample_sender,
                    ))
                    .is_err()
                {
                    return;
                }
                // Match Java's ordering: copy the encrypted buffer after the
                // process scan, while allowing relay I/O to continue meanwhile.
                let sample = loop {
                    if worker_cancel.load(Ordering::Acquire) {
                        return;
                    }
                    match sample_receiver.recv_timeout(Duration::from_millis(20)) {
                        Ok(sample) => break sample,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                };
                let length = sample.bytes.len();
                let next_address = scan.next_address;
                match recover_candidates(
                    &scan.states,
                    &sample.bytes,
                    direction,
                    &worker_cancel,
                    None,
                    sample.at_capacity,
                ) {
                    Ok(outcome) => {
                        let _ =
                            sender.send(DiscoveryEvent::Candidate(sample.bytes, Box::new(outcome)));
                    }
                    Err(error) => {
                        let _ = sender.send(DiscoveryEvent::Failed(error));
                        return;
                    }
                }
                let _ = sender.send(DiscoveryEvent::Done {
                    sampled_len: length,
                    next_address,
                });
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
                DiscoveryEvent::Scanned(stats, sample_sender) => {
                    self.scan_stats = Some(stats);
                    let side = self.side(direction);
                    let sample = if side.encrypted && side.reader.is_none() {
                        CiphertextSample {
                            bytes: side.buffer.clone(),
                            at_capacity: side.buffer.len() == BOOTSTRAP_LIMIT,
                        }
                    } else {
                        CiphertextSample {
                            bytes: Vec::new(),
                            at_capacity: false,
                        }
                    };
                    let _ = sample_sender.try_send(sample);
                }
                DiscoveryEvent::Candidate(sample, outcome) => {
                    let side = self.side(direction);
                    if side.encrypted && side.reader.is_none() && side.buffer.starts_with(&sample) {
                        side.candidates.merge(*outcome);
                    }
                }
                DiscoveryEvent::Done {
                    sampled_len,
                    next_address,
                } => {
                    self.discovery[index] = None;
                    let side = self.side(direction);
                    if let Some(next) = next_address {
                        if next <= side.scan_address {
                            return Err(io::Error::other("Flash memory scan did not advance"));
                        }
                        side.scan_address = next;
                        if side.reader.is_none() {
                            side.waiting = Some(now);
                        }
                    } else {
                        side.scan_address = 0;
                        if side.reader.is_none() {
                            if let Some(cipher) = side.candidates.take_unique() {
                                if valid_stream_prefix(&side.buffer, &cipher) {
                                    side.install(cipher);
                                } else {
                                    side.waiting = Some(now);
                                }
                            } else if side.buffer.len() > sampled_len {
                                side.waiting = Some(now);
                            }
                        }
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
                let address = side.scan_address;
                self.start_discovery(direction, move |cancel| {
                    let pid = if pid == 0 {
                        let processes = gearth_platform::habbo_processes()?;
                        if processes.len() != 1 { return Err(io::Error::other("Unable to identify the connecting client; select the Habbo process before attaching")); }
                        processes[0].pid
                    } else { pid };
                    gearth_platform::scan_habbo_from(pid, address, cancel)
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
// Validate newly buffered ciphertext too, while allowing an incomplete final
// frame. The original sample already supplied at least one complete frame.
fn valid_stream_prefix(encrypted: &[u8], candidate: &Rc4) -> bool {
    let mut decoded = encrypted.to_vec();
    candidate.clone().apply(&mut decoded);
    let mut at = 0;
    let mut complete = 0;
    while at < decoded.len() {
        if decoded.len() - at < 4 {
            return complete > 0;
        }
        let length = u32::from_be_bytes(decoded[at..at + 4].try_into().unwrap()) as usize;
        if !(2..=MAX_FRAME).contains(&length) {
            return false;
        }
        if decoded.len() - at < length + 4 {
            return complete > 0;
        }
        at += length + 4;
        complete += 1;
    }
    complete > 0
}
pub fn recover_state(
    states: &[[u8; 256]],
    encrypted: &[u8],
    direction: Direction,
    cancel: &AtomicBool,
) -> io::Result<Option<Rc4>> {
    let outcome = recover_candidates(
        states,
        encrypted,
        direction,
        cancel,
        Some(Instant::now() + Duration::from_secs(5)),
        false,
    )?;
    if outcome.ambiguous {
        Ok(None)
    } else {
        Ok(outcome.cipher)
    }
}
fn recover_candidates(
    states: &[[u8; 256]],
    encrypted: &[u8],
    direction: Direction,
    cancel: &AtomicBool,
    deadline: Option<Instant>,
    allow_partial_tail: bool,
) -> io::Result<RecoveryOutcome> {
    if cancel.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "key discovery cancelled",
        ));
    }
    if encrypted.len() < 6 || encrypted.len() > BOOTSTRAP_LIMIT {
        return Ok(RecoveryOutcome {
            priority: 0,
            ambiguous: false,
            cipher: None,
        });
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
        let matches = if allow_partial_tail {
            valid_stream_prefix(encrypted, &candidate)
        } else {
            valid_frames(encrypted, &candidate)
        };
        if matches {
            if fresh
                .as_ref()
                .is_some_and(|c: &Rc4| c.state() != candidate.state())
            {
                return Ok(RecoveryOutcome {
                    priority: 2,
                    ambiguous: true,
                    cipher: None,
                });
            }
            fresh = Some(candidate);
        }
    }
    if let Some(cipher) = fresh {
        return Ok(RecoveryOutcome {
            priority: 2,
            ambiguous: false,
            cipher: Some(cipher),
        });
    }
    if direction == Direction::ToClient {
        return Ok(RecoveryOutcome {
            priority: 0,
            ambiguous: false,
            cipher: None,
        });
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
                return Ok(RecoveryOutcome {
                    priority: 0,
                    ambiguous: false,
                    cipher: None,
                });
            }
            let mut candidate = Rc4::from_state(*state, encrypted.len() as u8, y as u8)
                .map_err(io::Error::other)?;
            candidate.rewind(encrypted.len());
            let (_, x, y) = candidate.state();
            if x != 0
                || y != 0
                || !(if allow_partial_tail {
                    valid_stream_prefix(encrypted, &candidate)
                } else {
                    valid_frames(encrypted, &candidate)
                })
            {
                continue;
            }
            // Different reverse states can reproduce frame lengths yet corrupt the final body byte.
            // Wait for additional evidence rather than silently selecting the first match.
            if found
                .as_ref()
                .is_some_and(|c: &Rc4| c.state() != candidate.state())
            {
                return Ok(RecoveryOutcome {
                    priority: 1,
                    ambiguous: true,
                    cipher: None,
                });
            }
            found = Some(candidate);
        }
    }
    Ok(RecoveryOutcome {
        priority: if found.is_some() { 1 } else { 0 },
        ambiguous: false,
        cipher: found,
    })
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
        let mut fixture = None;
        for index in 0..32 {
            let fresh = Rc4::new(format!("growing-fixture-{index}").as_bytes()).unwrap();
            let mut current = fresh.clone();
            let mut first = Packet::new(77);
            for n in 0..32 {
                first.put_i32(n * 1103).unwrap();
            }
            let mut second = Packet::new(78);
            second.put_i32(42).unwrap();
            let mut first_wire = first.bytes().to_vec();
            let mut second_wire = second.bytes().to_vec();
            current.apply(&mut first_wire);
            current.apply(&mut second_wire);
            let mut combined = first_wire.clone();
            combined.extend_from_slice(&second_wire);
            if recover_state(
                &[current.state().0],
                &combined,
                Direction::ToServer,
                &AtomicBool::new(false),
            )
            .unwrap()
            .is_some()
                && recover_state(
                    &[current.state().0],
                    &first_wire,
                    Direction::ToServer,
                    &AtomicBool::new(false),
                )
                .unwrap()
                .is_none()
            {
                fixture = Some((fresh, current, first_wire, second_wire));
                break;
            }
        }
        let (fresh, current, first_wire, second_wire) =
            fixture.expect("unambiguous growing fixture");
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
                            next_address: None,
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
    fn rejects_candidate_when_new_ciphertext_contradicts_it() {
        let (fresh, mut current, first_wire) = outgoing_fixture();
        let mut bad_tail = 1u32.to_be_bytes();
        current.apply(&mut bad_tail);
        let mut combined = first_wire.clone();
        combined.extend_from_slice(&bad_tail);
        assert!(!valid_stream_prefix(&combined, &fresh));
        let mut valid_tail = Packet::new(78).bytes().to_vec();
        let mut tail_cipher = fresh.clone();
        tail_cipher.apply(&mut first_wire.clone());
        tail_cipher.apply(&mut valid_tail);
        let mut partial = first_wire;
        partial.extend_from_slice(&valid_tail[..2]);
        assert!(valid_stream_prefix(&partial, &fresh));
    }

    #[test]
    fn candidates_remain_ambiguous_across_pages() {
        let first = Rc4::new(b"first-candidate").unwrap();
        let second = Rc4::new(b"second-candidate").unwrap();
        let outcome = |priority, cipher: Rc4| RecoveryOutcome {
            priority,
            ambiguous: false,
            cipher: Some(cipher),
        };
        let mut candidates = CandidateAccumulator::default();
        candidates.merge(outcome(1, first.clone()));
        candidates.merge(outcome(1, second.clone()));
        assert!(candidates.take_unique().is_none());
        candidates.merge(outcome(1, first.clone()));
        candidates.merge(outcome(1, first.clone()));
        assert_eq!(candidates.take_unique().unwrap().state(), first.state());
        candidates.merge(RecoveryOutcome {
            priority: 1,
            ambiguous: true,
            cipher: None,
        });
        candidates.merge(outcome(2, second.clone()));
        assert_eq!(candidates.take_unique().unwrap().state(), second.state());
        candidates.merge(outcome(2, first));
        candidates.merge(outcome(2, second));
        assert!(candidates.take_unique().is_none());
    }

    #[test]
    fn candidate_is_not_installed_until_memory_scan_completes() {
        let (fresh, _current, wire) = outgoing_fixture();
        let mut session = FlashSession::default();
        session.outgoing.encrypted = true;
        session.outgoing.waiting = Some(Instant::now());
        session.outgoing.feed(&wire).unwrap();
        let table = fresh.state().0;
        assert!(session
            .start_discovery(Direction::ToServer, move |_| Ok(
                gearth_platform::ScanResult {
                    states: vec![table],
                    bytes_read: 65536,
                    complete: false,
                    next_address: Some(65536),
                }
            ))
            .unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        while session.discovery[0].is_some() {
            session
                .poll_discovery(Direction::ToServer, Instant::now())
                .unwrap();
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            session.outgoing.reader.is_none(),
            "incomplete scan must not install a key"
        );
        assert!(session
            .start_discovery(Direction::ToServer, |_| Ok(gearth_platform::ScanResult {
                states: Vec::new(),
                bytes_read: 1024,
                complete: true,
                next_address: None,
            }))
            .unwrap());
        while session.discovery[0].is_some() {
            session
                .poll_discovery(Direction::ToServer, Instant::now())
                .unwrap();
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            session.outgoing.reader.as_ref().unwrap().state().1,
            wire.len() as u8
        );
        assert_eq!(
            session.feed(Direction::ToServer, &[]).unwrap()[0]
                .packet
                .header(),
            77
        );
    }

    #[test]
    fn incomplete_memory_page_advances_before_the_next_key_search() {
        let (fresh, _current, wire) = outgoing_fixture();
        let mut session = FlashSession::default();
        session.outgoing.encrypted = true;
        session.outgoing.waiting = Instant::now().checked_sub(Duration::from_secs(16));
        session.outgoing.feed(&wire).unwrap();
        assert!(session
            .start_discovery(Direction::ToServer, |_| Ok(gearth_platform::ScanResult {
                states: Vec::new(),
                bytes_read: 65536,
                complete: false,
                next_address: Some(65536),
            }))
            .unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        while session.discovery[0].is_some() {
            session
                .poll_discovery(Direction::ToServer, Instant::now())
                .unwrap();
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(session.outgoing.scan_address, 65536);
        assert!(session.outgoing.waiting.unwrap().elapsed() < Duration::from_secs(1));
        let table = fresh.state().0;
        assert!(session
            .start_discovery(Direction::ToServer, move |_| Ok(
                gearth_platform::ScanResult {
                    states: vec![table],
                    bytes_read: 1024,
                    complete: true,
                    next_address: None,
                }
            ))
            .unwrap());
        while session.discovery[0].is_some() {
            session
                .poll_discovery(Direction::ToServer, Instant::now())
                .unwrap();
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(session.outgoing.scan_address, 0);
        assert_eq!(
            session.feed(Direction::ToServer, &[]).unwrap()[0]
                .packet
                .header(),
            77
        );
    }

    #[test]
    fn full_bootstrap_pauses_reads_and_recovers_with_partial_tail() {
        let key = Rc4::new(b"backpressure-fixture-key").unwrap();
        let first = Packet::new(77);
        let mut second = Packet::new(78);
        second.append(&vec![42; BOOTSTRAP_LIMIT]).unwrap();
        let mut wire = first.bytes().to_vec();
        wire.extend_from_slice(second.bytes());
        key.clone().apply(&mut wire);
        let mut input = std::io::Cursor::new(wire);
        let mut session = FlashSession::default();
        session.incoming.encrypted = true;
        session.incoming.waiting = Some(Instant::now());
        let mut buffer = vec![0u8; 8192];
        let n = crate::relay::read_with_capacity(
            &mut input,
            &mut buffer,
            session.input_capacity(Direction::ToClient),
        )
        .unwrap()
        .unwrap();
        assert!(session
            .feed(Direction::ToClient, &buffer[..n])
            .unwrap()
            .is_empty());
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let table = key.state().0;
        assert!(session
            .start_discovery(Direction::ToClient, move |cancel| {
                started_tx.send(()).unwrap();
                while !cancel.load(Ordering::Acquire) {
                    if release_rx.recv_timeout(Duration::from_millis(5)).is_ok() {
                        return Ok(gearth_platform::ScanResult {
                            states: vec![table],
                            bytes_read: 1024,
                            complete: true,
                            next_address: None,
                        });
                    }
                }
                Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
            })
            .unwrap());
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        while session.input_capacity(Direction::ToClient) > 0 {
            let n = crate::relay::read_with_capacity(
                &mut input,
                &mut buffer,
                session.input_capacity(Direction::ToClient),
            )
            .unwrap()
            .unwrap();
            assert!(n > 0);
            assert!(session
                .feed(Direction::ToClient, &buffer[..n])
                .unwrap()
                .is_empty());
        }
        assert_eq!(input.position() as usize, BOOTSTRAP_LIMIT);
        assert!(crate::relay::read_with_capacity(
            &mut input,
            &mut buffer,
            session.input_capacity(Direction::ToClient)
        )
        .unwrap()
        .is_none());
        assert_eq!(input.position() as usize, BOOTSTRAP_LIMIT);
        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while session.discovery[1].is_some() {
            session
                .poll_discovery(Direction::ToClient, Instant::now())
                .unwrap();
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let packets = session.feed(Direction::ToClient, &[]).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].packet.header(), 77);
        let n = crate::relay::read_with_capacity(
            &mut input,
            &mut buffer,
            session.input_capacity(Direction::ToClient),
        )
        .unwrap()
        .unwrap();
        let packets = session.feed(Direction::ToClient, &buffer[..n]).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].packet.bytes(), second.bytes());
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
                    next_address: None,
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
