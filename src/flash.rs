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
const BOOTSTRAP_MAX: usize = MAX_FRAME + 4;
const MAX_DISCOVERY_WORKERS: usize = 4;
// Estimate reverse work per page; one table may still take a long time for a
// very large sample, and the sample can grow after this limit is selected.
const REVERSE_PAGE_BYTES: usize = 8 * BOOTSTRAP_LIMIT;
const REVERSE_PAGE_TABLES: usize = 8;
// Rewind and frame-validation RC4 steps per reverse worker invocation.
const REVERSE_SLICE_BYTES: usize = 1024 * 1024;
fn reverse_page_table_limit(buffer_len: usize) -> usize {
    (REVERSE_PAGE_BYTES / buffer_len.max(1)).clamp(1, REVERSE_PAGE_TABLES)
}
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
    Partial(Box<ReverseJob>),
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
    // Outgoing discovery checks every page for fresh states before the
    // expensive reverse-state pass.
    reverse_phase: bool,
    bootstrap_limit: Option<usize>,
    candidates: CandidateAccumulator,
    pending_reverse: Option<ReverseJob>,
}
impl Side {
    fn bootstrap_limit(&self) -> usize {
        self.bootstrap_limit.unwrap_or(BOOTSTRAP_LIMIT)
    }
    fn grow_bootstrap(&mut self) -> bool {
        let current = self.bootstrap_limit();
        let next = current.saturating_mul(2).min(BOOTSTRAP_MAX);
        if next == current {
            return false;
        }
        self.bootstrap_limit = Some(next);
        true
    }
    fn feed(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.buffer.len() + bytes.len()
            > if self.encrypted && self.reader.is_none() {
                self.bootstrap_limit()
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
        self.pending_reverse = None;
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
            side.bootstrap_limit().saturating_sub(side.buffer.len())
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
        let skip_reverse = side.candidates.priority == 2
            || (direction == Direction::ToServer && !side.reverse_phase);
        if ACTIVE_DISCOVERY_WORKERS
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_DISCOVERY_WORKERS).then_some(n + 1)
            })
            .is_err()
        {
            return Ok(false);
        }
        let pending_reverse = self.side(direction).pending_reverse.take();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let (sender, events) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("gearth-flash-discovery".into())
            .spawn(move || {
                let _slot = DiscoverySlot;
                if let Some(job) = pending_reverse {
                    job.run_slice(&sender, &worker_cancel);
                    return;
                }
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
                let partial_minimum = Some(if sample.at_capacity { 1 } else { 2 });
                // Prefer fresh states before scheduling reverse-only work.
                match recover_candidates(
                    &scan.states,
                    &sample.bytes,
                    direction,
                    &worker_cancel,
                    None,
                    partial_minimum,
                    true,
                ) {
                    Ok(outcome)
                        if outcome.priority == 0
                            && direction == Direction::ToServer
                            && !skip_reverse =>
                    {
                        ReverseJob {
                            states: scan.states,
                            sample: sample.bytes,
                            partial_minimum,
                            next_address,
                            search: ReverseSearch::default(),
                        }
                        .run_slice(&sender, &worker_cancel);
                    }
                    Ok(outcome) => {
                        if sender
                            .send(DiscoveryEvent::Candidate(sample.bytes, Box::new(outcome)))
                            .is_ok()
                        {
                            let _ = sender.send(DiscoveryEvent::Done {
                                sampled_len: length,
                                next_address,
                            });
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(DiscoveryEvent::Failed(error));
                    }
                }
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
                            at_capacity: side.buffer.len() == side.bootstrap_limit(),
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
                DiscoveryEvent::Partial(job) => {
                    self.discovery[index] = None;
                    let side = self.side(direction);
                    if side.reader.is_none() && side.buffer.starts_with(&job.sample) {
                        side.pending_reverse = Some(*job);
                        side.last_scan = None;
                        side.waiting = Some(now);
                    }
                    break;
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
                            if side.reverse_phase {
                                // Continue a bounded reverse page immediately;
                                // the normal idle retry delay applies to new scans.
                                side.last_scan = None;
                            }
                        }
                    } else {
                        side.scan_address = 0;
                        if side.reader.is_none() {
                            let no_fresh_candidate = side.candidates.priority == 0;
                            if let Some(cipher) = side.candidates.take_unique() {
                                if valid_stream_prefix(&side.buffer, &cipher) {
                                    side.install(cipher);
                                }
                            }
                            let start_reverse = direction == Direction::ToServer
                                && !side.reverse_phase
                                && no_fresh_candidate
                                && side.reader.is_none();
                            side.reverse_phase = start_reverse;
                            let grew = side.reader.is_none()
                                && side.buffer.len() == side.bootstrap_limit()
                                && side.grow_bootstrap();
                            if side.reader.is_none()
                                && (start_reverse || grew || side.buffer.len() > sampled_len)
                            {
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
            self.outgoing.pending_reverse = None;
            self.incoming.pending_reverse = None;
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
                let table_limit = if side.reverse_phase && side.candidates.priority != 2 {
                    reverse_page_table_limit(side.buffer.len())
                } else {
                    gearth_platform::MAX_TABLES
                };
                self.start_discovery(direction, move |cancel| {
                    let pid = if pid == 0 {
                        let processes = gearth_platform::habbo_processes()?;
                        if processes.len() != 1 { return Err(io::Error::other("Unable to identify the connecting client; select the Habbo process before attaching")); }
                        processes[0].pid
                    } else { pid };
                    gearth_platform::scan_habbo_from_with_limit(pid, address, cancel, table_limit)
                })?;
            }
        }
        Ok(())
    }
}
// Validate newly buffered ciphertext too, while allowing an incomplete final
// frame. The original sample already supplied at least one complete frame.
fn valid_stream_prefix(encrypted: &[u8], candidate: &Rc4) -> bool {
    valid_stream_prefix_with_minimum(encrypted, candidate, 1)
}
fn valid_stream_prefix_with_minimum(encrypted: &[u8], candidate: &Rc4, minimum: usize) -> bool {
    validate_frame_lengths(encrypted, candidate, minimum, Some(minimum))
}
// The same sample must be used for every slice. `at` points to the next
// frame; `body_remaining` advances the cipher between complete frames.
struct FrameValidator {
    cipher: Rc4,
    at: usize,
    complete: usize,
    complete_minimum: usize,
    partial_minimum: Option<usize>,
    body_remaining: usize,
    prefix: [u8; 4],
    prefix_done: usize,
}
impl FrameValidator {
    fn new(candidate: &Rc4, complete_minimum: usize, partial_minimum: Option<usize>) -> Self {
        Self {
            cipher: candidate.clone(),
            at: 0,
            complete: 0,
            complete_minimum,
            partial_minimum,
            body_remaining: 0,
            prefix: [0; 4],
            prefix_done: 0,
        }
    }
    fn step(&mut self, encrypted: &[u8], mut budget: usize) -> Option<bool> {
        self.step_limited(encrypted, &mut budget)
    }
    fn step_limited(&mut self, encrypted: &[u8], budget: &mut usize) -> Option<bool> {
        if encrypted.len() < 6 {
            return Some(false);
        }
        let mut scratch = [0u8; 4096];
        loop {
            if self.body_remaining != 0 {
                if *budget == 0 {
                    return None;
                }
                let count = self.body_remaining.min(*budget).min(scratch.len());
                self.cipher.apply(&mut scratch[..count]);
                self.body_remaining -= count;
                *budget -= count;
                continue;
            }
            let remaining = encrypted.len() - self.at;
            if remaining == 0 {
                return Some(self.complete >= self.complete_minimum);
            }
            if remaining < 4 {
                return Some(self.partial_minimum.is_some_and(|n| self.complete >= n));
            }
            if *budget == 0 {
                return None;
            }
            let count = (4 - self.prefix_done).min(*budget);
            let start = self.prefix_done;
            self.prefix[start..start + count]
                .copy_from_slice(&encrypted[self.at + start..self.at + start + count]);
            self.cipher.apply(&mut self.prefix[start..start + count]);
            self.prefix_done += count;
            *budget -= count;
            if self.prefix_done < 4 {
                continue;
            }
            let length = u32::from_be_bytes(self.prefix) as usize;
            self.prefix_done = 0;
            if !(2..=MAX_FRAME).contains(&length) {
                return Some(false);
            }
            if remaining < length + 4 {
                return Some(self.partial_minimum.is_some_and(|n| self.complete >= n));
            }
            self.at += length + 4;
            self.complete += 1;
            if encrypted.len() - self.at >= 4 {
                self.body_remaining = length;
            }
        }
    }
}
fn validate_frame_lengths(
    encrypted: &[u8],
    candidate: &Rc4,
    complete_minimum: usize,
    partial_minimum: Option<usize>,
) -> bool {
    let mut validator = FrameValidator::new(candidate, complete_minimum, partial_minimum);
    loop {
        if let Some(result) = validator.step(encrypted, 65536) {
            return result;
        }
    }
}
// A partial tail is accepted below capacity only after two complete frames.
fn candidate_matches(encrypted: &[u8], candidate: &Rc4, partial_minimum: Option<usize>) -> bool {
    validate_frame_lengths(encrypted, candidate, 1, partial_minimum)
}
fn rewind_cancellable(
    cipher: &mut Rc4,
    mut count: usize,
    cancel: &AtomicBool,
    deadline: Option<Instant>,
) -> io::Result<bool> {
    while count > 0 {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "key discovery cancelled",
            ));
        }
        if deadline.is_some_and(|deadline| Instant::now() > deadline) {
            return Ok(false);
        }
        let chunk = count.min(4096);
        cipher.rewind(chunk);
        count -= chunk;
    }
    Ok(true)
}
// Incremental reverse search. The caller must retain the same table snapshot and
// ciphertext until completion; partial candidates are deliberately not exposed.
#[derive(Default)]
struct ReverseSearch {
    table: usize,
    y: u16,
    current: Option<(Rc4, usize)>,
    validation: Option<(Rc4, FrameValidator)>,
    found: Option<Rc4>,
}
struct ReverseJob {
    states: Vec<[u8; 256]>,
    sample: Vec<u8>,
    partial_minimum: Option<usize>,
    next_address: Option<usize>,
    search: ReverseSearch,
}
impl ReverseJob {
    fn run_slice(mut self, sender: &mpsc::Sender<DiscoveryEvent>, cancel: &AtomicBool) {
        match self.search.step(
            &self.states,
            &self.sample,
            cancel,
            None,
            self.partial_minimum,
            REVERSE_SLICE_BYTES,
        ) {
            Ok(Some(outcome)) => {
                let sampled_len = self.sample.len();
                if sender
                    .send(DiscoveryEvent::Candidate(self.sample, Box::new(outcome)))
                    .is_ok()
                {
                    let _ = sender.send(DiscoveryEvent::Done {
                        sampled_len,
                        next_address: self.next_address,
                    });
                }
            }
            Ok(None) => {
                let _ = sender.send(DiscoveryEvent::Partial(Box::new(self)));
            }
            Err(error) => {
                let _ = sender.send(DiscoveryEvent::Failed(error));
            }
        }
    }
}
impl ReverseSearch {
    fn step(
        &mut self,
        states: &[[u8; 256]],
        encrypted: &[u8],
        cancel: &AtomicBool,
        deadline: Option<Instant>,
        partial_minimum: Option<usize>,
        mut budget: usize,
    ) -> io::Result<Option<RecoveryOutcome>> {
        while budget > 0 && self.table < states.len().min(gearth_platform::MAX_TABLES) {
            if cancel.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "key discovery cancelled",
                ));
            }
            if deadline.is_some_and(|limit| Instant::now() > limit) {
                return Ok(None);
            }
            if let Some((_, validator)) = &mut self.validation {
                let Some(matches) = validator.step_limited(encrypted, &mut budget) else {
                    return Ok(None);
                };
                let (candidate, _) = self
                    .validation
                    .take()
                    .expect("completed candidate validation");
                if matches {
                    if self
                        .found
                        .as_ref()
                        .is_some_and(|c| c.state() != candidate.state())
                    {
                        return Ok(Some(RecoveryOutcome {
                            priority: 1,
                            ambiguous: true,
                            cipher: None,
                        }));
                    }
                    self.found = Some(candidate);
                }
            } else {
                if self.current.is_none() {
                    let cipher =
                        Rc4::from_state(states[self.table], encrypted.len() as u8, self.y as u8)
                            .map_err(io::Error::other)?;
                    self.current = Some((cipher, encrypted.len()));
                }
                let (cipher, remaining) = self.current.as_mut().expect("initialized reverse state");
                let chunk = (*remaining).min(budget).min(4096);
                if !rewind_cancellable(cipher, chunk, cancel, deadline)? {
                    return Ok(None);
                }
                *remaining -= chunk;
                budget -= chunk;
                if *remaining != 0 {
                    continue;
                }
                let (candidate, _) = self.current.take().expect("completed reverse state");
                let (_, x, y) = candidate.state();
                if x == 0 && y == 0 {
                    let validator = FrameValidator::new(&candidate, 1, partial_minimum);
                    self.validation = Some((candidate, validator));
                    continue;
                }
            }
            self.y += 1;
            if self.y == 256 {
                self.y = 0;
                self.table += 1;
            }
        }
        if self.table == states.len().min(gearth_platform::MAX_TABLES) {
            let found = self.found.take();
            Ok(Some(RecoveryOutcome {
                priority: u8::from(found.is_some()),
                ambiguous: false,
                cipher: found,
            }))
        } else {
            Ok(None)
        }
    }
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
        None,
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
    partial_minimum: Option<usize>,
    fresh_known: bool,
) -> io::Result<RecoveryOutcome> {
    if cancel.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "key discovery cancelled",
        ));
    }
    if encrypted.len() < 6 || encrypted.len() > BOOTSTRAP_MAX {
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
        let matches = candidate_matches(encrypted, &candidate, partial_minimum);
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
    if direction == Direction::ToClient || fresh_known {
        return Ok(RecoveryOutcome {
            priority: 0,
            ambiguous: false,
            cipher: None,
        });
    }
    let mut search = ReverseSearch::default();
    loop {
        if let Some(outcome) =
            search.step(states, encrypted, cancel, deadline, partial_minimum, 65536)?
        {
            return Ok(outcome);
        }
        if deadline.is_some_and(|limit| Instant::now() > limit) {
            return Ok(RecoveryOutcome {
                priority: 0,
                ambiguous: false,
                cipher: None,
            });
        }
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use crate::packet::Packet;

    impl FlashSession {
        // Production intentionally refuses a new worker when all slots are
        // occupied. Independent parallel tests wait for a slot instead of
        // assuming the process-wide pool is idle.
        fn start_discovery_wait<F>(&mut self, direction: Direction, scan: F) -> io::Result<bool>
        where
            F: FnOnce(&AtomicBool) -> io::Result<gearth_platform::ScanResult> + Send + 'static,
        {
            let action = Arc::new(std::sync::Mutex::new(Some(scan)));
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                let pending = action.clone();
                if self.start_discovery(direction, move |cancel| {
                    let scan = pending
                        .lock()
                        .map_err(|_| io::Error::other("test scan lock poisoned"))?
                        .take()
                        .ok_or_else(|| io::Error::other("test scan already consumed"))?;
                    scan(cancel)
                })? {
                    return Ok(true);
                }
                let running = self.discovery[Self::discovery_index(direction)].is_some();
                let side = self.side(direction);
                if running
                    || !side.encrypted
                    || side.reader.is_some()
                    || side.buffer.len() < 6
                    || Instant::now() >= deadline
                {
                    return Ok(false);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    fn reference_frame_validation(
        encrypted: &[u8],
        cipher: &Rc4,
        partial: Option<usize>,
        complete_minimum: usize,
    ) -> bool {
        if encrypted.len() < 6 {
            return false;
        }
        let mut decoded = encrypted.to_vec();
        cipher.clone().apply(&mut decoded);
        let mut at = 0;
        let mut complete = 0;
        while at < decoded.len() {
            if decoded.len() - at < 4 {
                return partial.is_some_and(|minimum| complete >= minimum);
            }
            let length = u32::from_be_bytes(decoded[at..at + 4].try_into().unwrap()) as usize;
            if !(2..=MAX_FRAME).contains(&length) {
                return false;
            }
            if decoded.len() - at < length + 4 {
                return partial.is_some_and(|minimum| complete >= minimum);
            }
            at += length + 4;
            complete += 1;
        }
        complete >= complete_minimum
    }

    #[test]
    fn streamed_frame_validation_matches_full_decryption_reference() {
        for key_index in 0..8 {
            let cipher = Rc4::new(format!("validation-{key_index}").as_bytes()).unwrap();
            let mut plain = Vec::new();
            for payload in [2usize, 7, 31] {
                plain.extend_from_slice(&(payload as u32).to_be_bytes());
                plain.extend((0..payload).map(|value| (value + key_index) as u8));
            }
            for variant in 0..4 {
                let mut sample = plain.clone();
                match variant {
                    1 => sample.extend_from_slice(&1u32.to_be_bytes()),
                    2 => sample[..4].copy_from_slice(&1u32.to_be_bytes()),
                    3 => sample[6..10].copy_from_slice(&u32::MAX.to_be_bytes()),
                    _ => {}
                }
                let mut encrypted = sample.clone();
                cipher.clone().apply(&mut encrypted);
                for end in 0..=encrypted.len() {
                    let bytes = &encrypted[..end];
                    for minimum in [1, 2] {
                        assert_eq!(
                            valid_stream_prefix_with_minimum(bytes, &cipher, minimum),
                            reference_frame_validation(bytes, &cipher, Some(minimum), minimum),
                            "key={key_index} variant={variant} end={end} minimum={minimum}"
                        );
                        assert_eq!(candidate_matches(bytes, &cipher, Some(minimum)), reference_frame_validation(bytes, &cipher, Some(minimum), 1), "candidate key={key_index} variant={variant} end={end} minimum={minimum}");
                    }
                    assert_eq!(
                        candidate_matches(bytes, &cipher, None),
                        reference_frame_validation(bytes, &cipher, None, 1)
                    );
                }
            }
        }
    }

    #[test]
    fn sliced_frame_validation_matches_reference_at_all_boundaries() {
        let cipher = Rc4::new(b"frame-slice-fixture").unwrap();
        let mut plain = Vec::new();
        for length in [2usize, 7, 31] {
            plain.extend_from_slice(&(length as u32).to_be_bytes());
            plain.extend((0..length).map(|i| i as u8));
        }
        let mut wire = plain;
        cipher.clone().apply(&mut wire);
        for end in 0..=wire.len() {
            let bytes = &wire[..end];
            for partial in [None, Some(1), Some(2)] {
                let expected = reference_frame_validation(bytes, &cipher, partial, 1);
                for budget in [1, 3, 7] {
                    let mut validator = FrameValidator::new(&cipher, 1, partial);
                    let actual = loop {
                        if let Some(result) = validator.step(bytes, budget) {
                            break result;
                        }
                    };
                    assert_eq!(
                        actual, expected,
                        "end={end} partial={partial:?} budget={budget}"
                    );
                }
            }
        }
    }

    #[test]
    fn streamed_validation_advances_across_multiple_scratch_chunks() {
        let cipher = Rc4::new(b"large-validation").unwrap();
        let mut plain = 9000u32.to_be_bytes().to_vec();
        plain.extend(vec![42; 9000]);
        plain.extend_from_slice(Packet::new(7).bytes());
        let mut encrypted = plain;
        cipher.clone().apply(&mut encrypted);
        assert!(candidate_matches(&encrypted, &cipher, None));
        encrypted.pop();
        assert!(valid_stream_prefix(&encrypted, &cipher));
        assert!(!candidate_matches(&encrypted, &cipher, Some(2)));
    }

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

    fn finish_outgoing_discovery(session: &mut FlashSession) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while session.discovery[0].is_some() || session.outgoing.pending_reverse.is_some() {
            if session.discovery[0].is_none() {
                assert!(session
                    .start_discovery_wait(Direction::ToServer, |_| {
                        Err(io::Error::other("resumption must not rescan memory"))
                    })
                    .unwrap());
            }
            session
                .poll_discovery(Direction::ToServer, Instant::now())
                .unwrap();
            assert!(Instant::now() < deadline, "discovery did not finish");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn reverse_page_limit_scales_with_sample_and_remains_nonzero() {
        assert_eq!(reverse_page_table_limit(0), 8);
        assert_eq!(reverse_page_table_limit(BOOTSTRAP_LIMIT), 8);
        assert_eq!(reverse_page_table_limit(BOOTSTRAP_LIMIT * 2), 4);
        assert_eq!(reverse_page_table_limit(1024 * 1024), 1);
        assert_eq!(reverse_page_table_limit(BOOTSTRAP_MAX), 1);
    }

    #[test]
    fn fresh_pass_reaches_later_page_before_reverse_search() {
        let (fresh, current, wire) = outgoing_fixture();
        let mut session = FlashSession::default();
        session.outgoing.encrypted = true;
        session.outgoing.waiting = Some(Instant::now());
        session.outgoing.feed(&wire).unwrap();
        let first = current.state().0;
        assert!(session
            .start_discovery_wait(Direction::ToServer, move |_| Ok(
                gearth_platform::ScanResult {
                    states: vec![first],
                    bytes_read: 65536,
                    complete: false,
                    next_address: Some(65536),
                }
            ))
            .unwrap());
        finish_outgoing_discovery(&mut session);
        assert_eq!(session.outgoing.candidates.priority, 0);
        assert!(!session.outgoing.reverse_phase);
        let second = fresh.state().0;
        assert!(session
            .start_discovery_wait(Direction::ToServer, move |_| Ok(
                gearth_platform::ScanResult {
                    states: vec![second],
                    bytes_read: 1024,
                    complete: true,
                    next_address: None,
                }
            ))
            .unwrap());
        finish_outgoing_discovery(&mut session);
        assert_eq!(
            session.outgoing.writer.as_ref().unwrap().state(),
            fresh.state()
        );
    }

    #[test]
    fn reverse_pass_recovers_when_fresh_pass_finds_nothing() {
        let (fresh, current, wire) = outgoing_fixture();
        let mut session = FlashSession::default();
        session.outgoing.encrypted = true;
        session.outgoing.waiting = Some(Instant::now());
        session.outgoing.feed(&wire).unwrap();
        let table = current.state().0;
        assert!(session
            .start_discovery_wait(Direction::ToServer, move |_| Ok(
                gearth_platform::ScanResult {
                    states: vec![table],
                    bytes_read: 1024,
                    complete: true,
                    next_address: None,
                }
            ))
            .unwrap());
        finish_outgoing_discovery(&mut session);
        assert!(session.outgoing.reader.is_none());
        assert!(session.outgoing.reverse_phase);
        assert!(session
            .start_discovery_wait(Direction::ToServer, move |_| Ok(
                gearth_platform::ScanResult {
                    states: vec![table],
                    bytes_read: 1024,
                    complete: true,
                    next_address: None,
                }
            ))
            .unwrap());
        finish_outgoing_discovery(&mut session);
        assert_eq!(
            session.outgoing.writer.as_ref().unwrap().state(),
            fresh.state()
        );
        assert!(!session.outgoing.reverse_phase);
    }

    #[test]
    fn bounded_reverse_pages_preserve_candidates_and_resume_immediately() {
        let (fresh, current, wire) = outgoing_fixture();
        let mut session = FlashSession::default();
        session.outgoing.encrypted = true;
        session.outgoing.reverse_phase = true;
        session.outgoing.waiting = Some(Instant::now());
        session.outgoing.last_scan = Some(Instant::now());
        session.outgoing.feed(&wire).unwrap();
        let table = current.state().0;
        assert!(session
            .start_discovery_wait(Direction::ToServer, move |_| Ok(
                gearth_platform::ScanResult {
                    states: vec![table],
                    bytes_read: 1024,
                    complete: false,
                    next_address: Some(1024),
                }
            ))
            .unwrap());
        finish_outgoing_discovery(&mut session);
        assert_eq!(session.outgoing.candidates.priority, 1);
        assert_eq!(session.outgoing.scan_address, 1024);
        assert!(session.outgoing.last_scan.is_none());
        assert!(session
            .start_discovery_wait(Direction::ToServer, move |_| Ok(
                gearth_platform::ScanResult {
                    states: vec![table],
                    bytes_read: 1024,
                    complete: true,
                    next_address: None,
                }
            ))
            .unwrap());
        finish_outgoing_discovery(&mut session);
        assert_eq!(
            session.outgoing.writer.as_ref().unwrap().state(),
            fresh.state()
        );
    }

    #[test]
    fn full_outgoing_buffer_grows_when_reverse_pass_is_scheduled() {
        let mut session = FlashSession::default();
        session.outgoing.encrypted = true;
        session.outgoing.waiting = Some(Instant::now());
        session.outgoing.feed(&vec![0; BOOTSTRAP_LIMIT]).unwrap();
        assert!(session
            .start_discovery_wait(Direction::ToServer, |_| Ok(gearth_platform::ScanResult {
                states: Vec::new(),
                bytes_read: 1024,
                complete: true,
                next_address: None,
            }))
            .unwrap());
        finish_outgoing_discovery(&mut session);
        assert!(session.outgoing.reverse_phase);
        assert_eq!(session.outgoing.bootstrap_limit(), BOOTSTRAP_LIMIT * 2);
        assert!(session.input_capacity(Direction::ToServer) > 0);
    }

    #[test]
    fn ambiguous_fresh_pass_does_not_fall_back_to_reverse() {
        let (_, _, wire) = outgoing_fixture();
        let mut session = FlashSession::default();
        session.outgoing.encrypted = true;
        session.outgoing.waiting = Some(Instant::now());
        session.outgoing.feed(&wire).unwrap();
        session.outgoing.candidates.priority = 2;
        session.outgoing.candidates.ambiguous = true;
        assert!(session
            .start_discovery_wait(Direction::ToServer, |_| Ok(gearth_platform::ScanResult {
                states: Vec::new(),
                bytes_read: 1024,
                complete: true,
                next_address: None,
            }))
            .unwrap());
        finish_outgoing_discovery(&mut session);
        assert!(session.outgoing.reader.is_none());
        assert!(!session.outgoing.reverse_phase);
        assert_eq!(session.outgoing.candidates.priority, 0);
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
        session.outgoing.reverse_phase = true;
        session.outgoing.waiting = Some(Instant::now());
        session.outgoing.feed(&first_wire).unwrap();
        assert!(session
            .start_discovery_wait(Direction::ToServer, move |cancel| {
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
        let mut resumptions = 0;
        let mut third_wire = Packet::new(79).bytes().to_vec();
        current.clone().apply(&mut third_wire);
        while session.discovery[0].is_some() || session.outgoing.pending_reverse.is_some() {
            if session.discovery[0].is_none() {
                resumptions += 1;
                if resumptions == 1 {
                    assert!(session
                        .feed(Direction::ToServer, &third_wire)
                        .unwrap()
                        .is_empty());
                }
                assert!(session
                    .start_discovery_wait(Direction::ToServer, |_| {
                        Err(io::Error::other("resumption must not rescan memory"))
                    })
                    .unwrap());
            }
            session
                .poll_discovery(Direction::ToServer, Instant::now())
                .unwrap();
            assert!(Instant::now() < deadline, "discovery did not finish");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(resumptions > 0, "the fixture must cross a worker boundary");
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
            [77, 78, 79]
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
    fn known_fresh_candidate_skips_reverse_but_still_checks_fresh_tables() {
        let (fresh, current, wire) = outgoing_fixture();
        let cancel = AtomicBool::new(false);
        let normal = recover_candidates(
            &[current.state().0],
            &wire,
            Direction::ToServer,
            &cancel,
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(normal.priority, 1);
        assert!(!normal.ambiguous);
        let skipped = recover_candidates(
            &[current.state().0],
            &wire,
            Direction::ToServer,
            &cancel,
            None,
            None,
            true,
        )
        .unwrap();
        assert_eq!(skipped.priority, 0);
        let checked = recover_candidates(
            &[fresh.state().0],
            &wire,
            Direction::ToServer,
            &cancel,
            None,
            None,
            true,
        )
        .unwrap();
        assert_eq!(checked.priority, 2);
        assert_eq!(checked.cipher.unwrap().state(), fresh.state());
    }

    #[test]
    fn fresh_candidate_survives_a_later_reverse_only_page() {
        let (fresh, current, wire) = outgoing_fixture();
        let mut session = FlashSession::default();
        session.outgoing.encrypted = true;
        session.outgoing.waiting = Some(Instant::now());
        session.outgoing.feed(&wire).unwrap();
        let table = fresh.state().0;
        assert!(session
            .start_discovery_wait(Direction::ToServer, move |_| Ok(
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
        assert_eq!(session.outgoing.candidates.priority, 2);
        assert!(session.outgoing.reader.is_none());
        let table = current.state().0;
        assert!(session
            .start_discovery_wait(Direction::ToServer, move |_| Ok(
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
        assert_eq!(
            session.outgoing.writer.as_ref().unwrap().state(),
            fresh.state()
        );
    }

    #[test]
    fn stale_fresh_candidate_is_rejected_after_later_ciphertext() {
        let (fresh, mut current, wire) = outgoing_fixture();
        let mut session = FlashSession::default();
        session.outgoing.encrypted = true;
        session.outgoing.waiting = Some(Instant::now());
        session.outgoing.feed(&wire).unwrap();
        let table = fresh.state().0;
        assert!(session
            .start_discovery_wait(Direction::ToServer, move |_| Ok(
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
        assert_eq!(session.outgoing.candidates.priority, 2);
        let mut bad_tail = 1u32.to_be_bytes();
        current.apply(&mut bad_tail);
        session.outgoing.feed(&bad_tail).unwrap();
        assert!(session
            .start_discovery_wait(Direction::ToServer, |_| Ok(gearth_platform::ScanResult {
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
        assert!(session.outgoing.reader.is_none());
        assert_eq!(session.outgoing.scan_address, 0);
        assert_eq!(session.outgoing.candidates.priority, 0);
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
            .start_discovery_wait(Direction::ToServer, move |_| Ok(
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
            .start_discovery_wait(Direction::ToServer, |_| Ok(gearth_platform::ScanResult {
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
            .start_discovery_wait(Direction::ToServer, |_| Ok(gearth_platform::ScanResult {
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
            .start_discovery_wait(Direction::ToServer, move |_| Ok(
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
            .start_discovery_wait(Direction::ToClient, move |cancel| {
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
    fn recovery_handles_two_complete_frames_with_incomplete_tail() {
        let key = Rc4::new(b"fragmented-tail-key").unwrap();
        let first = Packet::new(77);
        let second = Packet::new(78);
        let mut third = Packet::new(79);
        third.append(&[7; 20]).unwrap();
        let mut wire = first.bytes().to_vec();
        wire.extend_from_slice(second.bytes());
        wire.extend_from_slice(third.bytes());
        key.clone().apply(&mut wire);
        let split = first.bytes().len() + second.bytes().len() + 5;
        assert!(
            recover_state(
                &[key.state().0],
                &wire[..split],
                Direction::ToClient,
                &AtomicBool::new(false)
            )
            .unwrap()
            .is_none(),
            "legacy direct recovery remains strict"
        );
        let one_frame_and_tail = first.bytes().len() + 5;
        assert!(!candidate_matches(
            &wire[..one_frame_and_tail],
            &key,
            Some(2)
        ));
        assert!(candidate_matches(
            &wire[..one_frame_and_tail],
            &key,
            Some(1)
        ));
        let mut session = FlashSession::default();
        session.incoming.encrypted = true;
        session.incoming.waiting = Some(Instant::now());
        assert!(session
            .feed(Direction::ToClient, &wire[..split])
            .unwrap()
            .is_empty());
        let table = key.state().0;
        assert!(session
            .start_discovery_wait(Direction::ToClient, move |_| Ok(
                gearth_platform::ScanResult {
                    states: vec![table],
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
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            session.incoming.reader.is_some(),
            "complete prefix should permit recovery without waiting for the tail"
        );
        let packets = session.feed(Direction::ToClient, &[]).unwrap();
        assert_eq!(
            packets
                .iter()
                .map(|p| p.packet.header())
                .collect::<Vec<_>>(),
            [77, 78]
        );
        let packets = session.feed(Direction::ToClient, &wire[split..]).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].packet.bytes(), third.bytes());
    }

    #[test]
    fn oversized_first_frame_grows_bootstrap_and_recovers() {
        let key = Rc4::new(b"large-first-frame-key").unwrap();
        let mut packet = Packet::new(90);
        packet.append(&vec![7; BOOTSTRAP_LIMIT + 4096]).unwrap();
        let mut wire = packet.bytes().to_vec();
        key.clone().apply(&mut wire);
        let mut input = std::io::Cursor::new(wire);
        let mut session = FlashSession::default();
        session.incoming.encrypted = true;
        session.incoming.waiting = Some(Instant::now());
        let mut buffer = vec![0u8; 8192];
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
        let table = key.state().0;
        assert!(session
            .start_discovery_wait(Direction::ToClient, move |_| Ok(
                gearth_platform::ScanResult {
                    states: vec![table],
                    bytes_read: 1024,
                    complete: true,
                    next_address: None,
                }
            ))
            .unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        while session.discovery[1].is_some() {
            session
                .poll_discovery(Direction::ToClient, Instant::now())
                .unwrap();
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(session.incoming.reader.is_none());
        assert_eq!(session.incoming.bootstrap_limit(), BOOTSTRAP_LIMIT * 2);
        while let Some(n) = crate::relay::read_with_capacity(
            &mut input,
            &mut buffer,
            session.input_capacity(Direction::ToClient),
        )
        .unwrap()
        {
            if n == 0 {
                break;
            }
            assert!(session
                .feed(Direction::ToClient, &buffer[..n])
                .unwrap()
                .is_empty());
        }
        let table = key.state().0;
        assert!(session
            .start_discovery_wait(Direction::ToClient, move |_| Ok(
                gearth_platform::ScanResult {
                    states: vec![table],
                    bytes_read: 1024,
                    complete: true,
                    next_address: None,
                }
            ))
            .unwrap());
        while session.discovery[1].is_some() {
            session
                .poll_discovery(Direction::ToClient, Instant::now())
                .unwrap();
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let packets = session.feed(Direction::ToClient, &[]).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].packet.bytes(), packet.bytes());
        session.incoming.bootstrap_limit = Some(BOOTSTRAP_MAX - 1);
        assert!(session.incoming.grow_bootstrap());
        assert_eq!(session.incoming.bootstrap_limit(), BOOTSTRAP_MAX);
        assert!(!session.incoming.grow_bootstrap());
    }

    #[test]
    fn reverse_search_resumes_inside_a_table_and_preserves_result() {
        let (fresh, current, wire) = outgoing_fixture();
        let tables = [current.state().0];
        let cancel = AtomicBool::new(false);
        let expected = recover_candidates(
            &tables,
            &wire,
            Direction::ToServer,
            &cancel,
            None,
            None,
            false,
        )
        .unwrap();
        let mut search = ReverseSearch::default();
        assert!(search
            .step(&tables, &wire, &cancel, None, None, 1)
            .unwrap()
            .is_none());
        assert_eq!(search.current.as_ref().unwrap().1, wire.len() - 1);
        cancel.store(true, Ordering::Release);
        assert_eq!(
            search
                .step(&tables, &wire, &cancel, None, None, 7)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::Interrupted
        );
        cancel.store(false, Ordering::Release);
        let result = loop {
            if let Some(outcome) = search.step(&tables, &wire, &cancel, None, None, 7).unwrap() {
                break outcome;
            }
        };
        assert_eq!(result.priority, expected.priority);
        assert_eq!(result.ambiguous, expected.ambiguous);
        assert_eq!(result.cipher.unwrap().state(), fresh.state());
    }

    #[test]
    fn reverse_search_slices_candidate_validation_and_honors_cancellation() {
        let (fresh, current, wire) = outgoing_fixture();
        let tables = [current.state().0];
        let cancel = AtomicBool::new(false);
        let mut search = ReverseSearch {
            y: 255,
            validation: Some((fresh.clone(), FrameValidator::new(&fresh, 1, None))),
            ..Default::default()
        };
        assert!(search
            .step(&tables, &wire, &cancel, None, None, 1)
            .unwrap()
            .is_none());
        assert_eq!(search.validation.as_ref().unwrap().1.prefix_done, 1);
        cancel.store(true, Ordering::Release);
        assert_eq!(
            search
                .step(&tables, &wire, &cancel, None, None, 1)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::Interrupted
        );
        cancel.store(false, Ordering::Release);
        let outcome = loop {
            if let Some(outcome) = search.step(&tables, &wire, &cancel, None, None, 1).unwrap() {
                break outcome;
            }
        };
        assert_eq!(outcome.cipher.unwrap().state(), fresh.state());
        assert!(!outcome.ambiguous);
    }

    #[test]
    fn reverse_search_keeps_ambiguity_across_slices() {
        let (_, current, wire) = outgoing_fixture();
        let tables = [current.state().0];
        let cancel = AtomicBool::new(false);
        let mut search = ReverseSearch {
            found: Some(Rc4::new(b"different-candidate").unwrap()),
            ..Default::default()
        };
        let mut slices = 0;
        let outcome = loop {
            slices += 1;
            if let Some(outcome) = search.step(&tables, &wire, &cancel, None, None, 7).unwrap() {
                break outcome;
            }
        };
        assert!(slices > 1);
        assert_eq!(outcome.priority, 1);
        assert!(outcome.ambiguous);
        assert!(outcome.cipher.is_none());
    }

    #[test]
    fn cancelling_discovery_discards_pending_reverse_job() {
        let (_, current, wire) = outgoing_fixture();
        let mut session = FlashSession::default();
        session.outgoing.pending_reverse = Some(ReverseJob {
            states: vec![current.state().0],
            sample: wire,
            partial_minimum: None,
            next_address: None,
            search: ReverseSearch::default(),
        });
        let error = session.discover(1, &AtomicBool::new(true)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(session.outgoing.pending_reverse.is_none());
    }

    #[test]
    fn reverse_search_checks_cancellation_before_work() {
        let mut cipher = Rc4::new(b"cancellable-key").unwrap();
        let original = cipher.state();
        let error = rewind_cancellable(&mut cipher, BOOTSTRAP_MAX, &AtomicBool::new(true), None)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(cipher.state(), original);
        let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        assert!(!rewind_cancellable(
            &mut cipher,
            BOOTSTRAP_MAX,
            &AtomicBool::new(false),
            Some(expired)
        )
        .unwrap());
        assert_eq!(cipher.state(), original);
    }

    #[test]
    fn slow_outgoing_search_does_not_block_incoming_key() {
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let mut session = FlashSession::default();
        session.outgoing.encrypted = true;
        session.outgoing.buffer = vec![0; 6];
        assert!(session
            .start_discovery_wait(Direction::ToServer, move |cancel| {
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
            .start_discovery_wait(Direction::ToClient, move |_| Ok(
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
            .start_discovery_wait(Direction::ToServer, move |cancel| {
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
