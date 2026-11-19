# Migration tasks

## Latest: Flash worker slices

- [x] Preserve reverse-search snapshot and state between workers, including cancellation, sample growth and ambiguity fixtures.
- [ ] Bound or measure fresh-state and candidate frame-validation work, investigate scheduling fairness, and rebuild release. Live client and extension behavior remains unverified.


## Latest: incremental Flash reverse search

- [x] Preserve the reverse search state across bounded rewind slices and test resume/cancellation.
- [ ] Persist the snapshot and search state across worker jobs, retain ambiguity and validate sample growth; bound frame validation and test fairness. Rebuild release and await user-run live tests.


## Latest: release and expanded regex fixtures

- [x] Build Windows desktop/web release at `b7c5f6cc42fc2e42f605fa40a152ac620008c620`; compare 3,400 short-input `\R` combinations against beta-29.
- [ ] Bound and resume work inside a Flash reverse table without losing candidates; live client and extension compatibility remains unverified.


## Latest: Java line-ending regex

- [x] Implement and compare `\R` on targeted and short-input beta-29 packet fixtures, including CRLF backtracking, direct and grouped repetition.
- [ ] Broaden regex parity coverage and investigate progress within one expensive Flash reverse table. Rebuild the current desktop/web release. Live clients and extensions remain unverified.


## Java previous-match anchor

- [x] Implement `\G` previous-match anchoring with zero-width and quantified behavior in selected beta-29 fixtures.
- [ ] Implement Java `\R` matcher-level variable-width backtracking, including direct and enclosing repetition.
- [ ] Repeat combined desktop/web release and await user-run real-client/extension evidence.
## Java Unicode regex escapes

- [x] Support four-digit Unicode escapes beyond Latin-1, Unicode case folding and paired surrogate range endpoints in selected Java oracle cases.
- [ ] Implement Java `\R` matcher-level backtracking and test direct and enclosing quantifiers.
- [ ] Repeat release and await user-run real-client and extension evidence.
## Java regex octal escapes

- [x] Implement Java octal regex escapes and verify digit limits against the beta-29 packet API.
- [x] Compare Java four-digit Unicode escapes outside Latin-1, including case folding and selected surrogate boundaries.
- [ ] Revisit `\R` matcher backtracking, repeat release and await user-run compatibility tests.
## Java regex control escapes

- [x] Support `\cX`, including COMMENTS-mode operand handling, with beta-29 and all-byte Java comparisons.
- [x] Compare Java regex octal escapes `\0...`, including digit limits, bracket ranges and malformed syntax.
- [ ] Revisit `\R` matcher backtracking, repeat release and await user-run compatibility tests.
## Flash test stability

- [x] Make parallel discovery fixtures wait safely for the global worker pool and run the CI-equivalent workspace/all-targets tests.
- [ ] Compare and implement Java `\R` matcher backtracking, including quantification and repeated enclosing groups.
- [ ] Repeat release and await user-run real-client/extension evidence.
## Unicode braced hex folding

- [x] Implement and compare external Unicode case-folded hex literals and ranges over all Latin-1 byte values.
- [x] Fix intermittent parallel Flash discovery test contention for the global worker cap, and run the CI-equivalent command.
- [ ] Revisit Java `\R` matcher backtracking and repeat release.
## Java braced hexadecimal escapes

- [x] Support Java `\x{...}` and bracket ranges over Latin-1, including nonmatching code points outside Latin-1 without Unicode case folding.
- [x] Implement and differentially test Unicode case folding from non-Latin-1 braced code points and ranges back into Latin-1.
- [ ] Return to matcher-level `\R` CRLF/backtracking semantics and repeat release.
## Java line-break investigation

- [ ] Implement `\R` with Java-compatible CRLF/backtracking semantics; naive alternation differs inside repeated groups.
- [x] Compare and implement Java braced hexadecimal escapes `\x{...}` over the Latin-1 packet domain; cross-domain Unicode folding remains tracked above.
## Java regex whitespace

- [x] Support Java horizontal and vertical whitespace classes and complements over Latin-1, with beta-29 oracle fixtures.
- [ ] Compare Java `\R` line-break matching, especially CRLF and quantification, and implement evidenced behavior.
- [ ] Continue investigating remaining regex constructs and the unreproduced rejected intersection branch.
- [ ] Repeat release and await user-run real-client and extension evidence.
## Session metadata events

- [x] Retain bounded identity and packet catalog events across TCP, Nitro and Unity saturation, with latest-update coalescing and session-boundary tests.
- [x] Audit existing Java class-intersection fixtures; retain the unreproduced rejected branch as an open investigation above.
- [ ] Repeat release and await user-run real-client and extension evidence.
## Bounded reverse scan

- [x] Limit tables per reverse scan page and resume from the next address while retaining candidate ambiguity.
- [ ] Investigate reporting and bounding progress within a single expensive table; a table limit is not a time bound.
- [x] Audit and retain packet metadata events under saturated channels.
- [ ] Repeat release and await user-run real-client/extension evidence.
## Flash discovery ordering

- [x] Scan all pages for fresh outgoing states before starting reverse-state trials; preserve ambiguity, buffer growth and reverse-only fallback.
- [ ] Investigate bounding work per reverse scan page and progress visibility without skipping candidates or weakening ambiguity detection.
- [ ] Repeat the release build and await user-run real-client and extension evidence.
## Flash frame validation

- [x] Validate encrypted frame lengths incrementally without copying the entire buffer; compare strict and partial cases with full-decryption fixtures.
- [ ] Investigate the remaining cost of reverse-only RC4 state recovery and cancellation under large inputs.
- [ ] Repeat release and await user-run real-client and extension evidence.
## Unity event delivery

- [x] Retain ordered Unity producer lifecycle events under saturation, defer peer admission with bounded cancellable waiting, and test the producer and forwarder together.
- [ ] Investigate remaining Flash reverse-only recovery cost.
- [ ] Repeat release for current code and obtain real-client and extension evidence when the user performs those tests.
## Unity forwarding backlog

- [x] Stop draining Unity forwarding sources when the control backlog is full, avoiding eviction of earlier lifecycle events.
- [x] Preserve lifecycle events in the Unity server producer with bounded concurrent admission and cancellation.
- [x] Verify both Unity event stages together; release remains tracked above.
## Nitro event saturation

- [x] Preserve ordered Nitro lifecycle events under producer queue saturation, with bounded concurrent admission, periodic flush and cancellable waiting.
- [x] Address Unity producer saturation and its separate forwarder eviction policy.
- [ ] Repeat the release build for current code; real-client verification remains with the user.
## Concurrent event preparation

- [x] Make the bounded event sink safe for concurrent producers and reserve lifecycle capacity under error flood.
- [x] Integrate and test the sink in Nitro and Unity.
## TCP lifecycle saturation

- [x] Retain and flush ordered TCP lifecycle notifications without blocking active forwarding; test a saturated channel and reconnect.
- [x] Audit and address Web/Unity lifecycle-event producers and bounded forwarding.
- [ ] Repeat the desktop/web release build after this TCP change.
- [ ] Investigate remaining Flash reverse-only scan costs; real-client compatibility is unverified.
## Latest RC4 discovery work

- [x] Skip lower-priority outgoing reverse trials after a fresh candidate from an earlier memory page, retaining ambiguity detection and final ciphertext validation.
- [ ] Address potentially expensive reverse searches without a fresh candidate.
- [x] Preserve TCP connection lifecycle events when the consumer event queue is saturated, without blocking active traffic.
- [ ] Real-client, protocol, and extension compatibility remains unverified; the user will perform real-client tests.
Reduce unnecessary RC4 reversal work after a fresh candidate is already retained across memory pages, while still scanning for competing fresh candidates and preserving ambiguity. Measure worst-case large-frame cost separately; the user handles real-client testing.

Investigate Flash recovery when at least two complete encrypted frames are followed by an incomplete tail below the buffer limit. Determine whether strict whole-buffer validation can stall a connection waiting for more traffic, and add a safe ambiguity-preserving fixture before changing behavior. Evaluate large-frame recovery cost. The user handles real-client testing.

Support a first encrypted Flash frame larger than the initial 64 KiB bootstrap buffer: grow the bounded buffer progressively up to the protocol limit, retain backpressure and test late completion and cancellation. Evaluate CPU/memory bounds of reversing large ciphertext. The user handles real-client testing.

Reproduce and correct encrypted Flash bootstrap overflow during slow key discovery using bounded socket backpressure. Assess incomplete trailing frames and a first encrypted frame larger than 64 KiB without selecting ambiguous keys. The user will test real clients.

Test and implement bounded Flash input backpressure during asynchronous key discovery: a full 64 KiB encrypted bootstrap buffer currently causes an error rather than pausing socket reads. Assess a first encrypted frame larger than the bootstrap limit separately. The user will test real clients.

Make Windows Flash memory scanning resumable across its five-second, 1 GiB and table-count limits. Preserve overlap and cancellation, test candidates beyond the first page and prevent restarting forever at address zero. The user will conduct actual-client testing.

Implement incremental, cancellable outgoing RC4 snapshot recovery across the entire candidate list without restarting at index zero after the time budget or blocking relay I/O. Preserve ambiguity detection, buffered ciphertext and cancellation; add deterministic late-candidate and moving-buffer fixtures. Real client tests are the user’s responsibility.

Prioritize investigation of the reported Flash connection failure: compare Rust attachment, handshake and RC4 discovery with pinned beta-29 Java and use isolated automated fixtures. The user will run real-client tests themselves. Also recover dropped TCP lifecycle events under saturation.

Audit Origins decoding for complete packets followed by a malformed chunk in one read, including encrypted and unencrypted paths; add deterministic fixtures and preserve valid prefixes where appropriate. Then reproduce dropped TCP lifecycle events during saturation.

Audit automatic Flash and Origins decoding when a valid complete frame precedes malformed input in one read. Determine whether their batch-returning decoders also drop the valid prefix; add deterministic fixtures and preserve ordering where appropriate. Also reproduce lifecycle-event loss under saturation.

Investigate lost TCP Connected/Disconnected events under a saturated event channel: desktop logger state and lifecycle actions can become stale. Reproduce disconnect/reconnect with a full queue and design bounded ordered lifecycle recovery without blocking packet processing. The TCP error fallback is opt-in for API consumers and coalesces older errors.

Investigate critical relay error visibility under saturated event queues: TCP uses nonblocking try_send for errors and packet events, so a send failure can be dropped. Reproduce with a bounded fixture and design a nonblocking durable error path; preserve packet throughput and lifecycle ordering. Partial delivery is inherently uncertain and should not be blindly retried.

Compare and document retry semantics with beta-29 for failed scheduled sends: Java ignores boolean send results; Rust retains rejected enqueues but cannot recover an accepted command lost after disconnect. Exercise disconnect races on real transports and determine whether any retry can duplicate an already delivered packet. Live clients remain unverified.

Compare beta-29 direct TCP writes and WebSocket send semantics with Rust asynchronous injection queues during disconnect, full queues and send failure. Java Scheduler ignores send return values; test whether pending jobs and error reporting match without claiming end-to-end delivery. Real-client behavior remains unverified.

Compare Java HState.CONNECTED transitions to Flash/Origins transport encryption readiness; reproduce scheduling during initial handshake and reconnect, and preserve pending occurrences until it is safe to send. Distinguish successful enqueue from network delivery; real clients remain unverified.

Next audit and bind Origins and manual TCP scheduled dispatch to their active session and current catalog, including metadata lookup before readiness, reconnect and lossy events. Flash, Unity and Nitro have session-bound snapshots, but enqueue acceptance is not confirmed network delivery; live clients remain unverified.

Next bind Nitro scheduled dispatch to its ready peer and metadata and reject injection after peer/catalog replacement; exercise event loss and reconnect. Then audit Origins and manual TCP. Unity and automatic Flash now have session-bound scheduler metadata; real-client compatibility remains unverified.

Audit scheduled dispatch for Origins, Nitro, Unity and manual TCP: their active connection may be visible before its current metadata, and dispatch/injection must be tied to the same session. Test ordering, event loss and replacement independently. Automatic Flash now uses session-bound catalog snapshots; real-client verification remains open.

Investigate and test desktop scheduler session readiness: Flash can become connected before Identified/PacketIdentifiers, while the desktop retains the previous version and metadata. Ensure pending named jobs cannot use stale IDs and preserve Origins/Nitro/Unity event ordering and manually loaded metadata. Real-client reconnect remains unverified.

Active .sched loading now works offline with deferred named identifiers, atomic replacement and non-starving retry. Next exercise two loopback relay connections with changed metadata and pending scheduled sends; visual UI and real-client reconnection remain open.

Scheduled expressions now resolve using current metadata and client format at send time. Next support Java-style active .sched loading while disconnected without prematurely resolving named identifiers; live reconnection remains open.

Small clock jumps now use Java-visible millisecond comparisons; deterministic 4 ms forward and 5 ms backward cases pass. Next compare scheduler restart/persistence and active job restoration with Java.

Pending aligned sends survive backward clock jumps and extreme forward jumps are counted without Instant underflow. Next compare small wall-clock jumps against Java and the current drift tolerance; real-client scheduling remains open.

Forward wall-clock jumps now replay crossed aligned deadlines, including queue retry. Next preserve queued catch-up deadlines through a backward jump and handle Instant underflow; real-client scheduling remains open.

Aligned jobs replay missed slots in bounded, retryable batches; eight cases match a Java fixture mirroring the beta-29 loop. Next compare forward/backward wall-clock jumps against Java and implement verified behavior. Live scheduler validation remains open.

Offset equal to interval remains importable and exportable but no longer sends, matching the Java modulo condition. Next build deterministic Java catch-up comparison fixtures and assess replay behavior; live client scheduling remains open.

Aligned schedule resume now fires at an exact boundary. Java replays missed slots after disconnection while Rust skips them; this material divergence remains open. Next compare the accepted offset-equals-interval case against Java runtime behavior.

Explicit Java-compatible absolute string reads now reject WEDGIE like beta-29; Rust absolute reads remain available. Next compare scheduler restart and catch-up behavior against the original Java implementation.

The explicit Java-compatible WEDGIE string reader matches nine beta-29 success, error and cursor fixtures; the transactional Rust reader remains unchanged. Next compare Java and Rust WEDGIE absolute-offset string reads and cursor behavior.

Legacy byte display matches beta-29 for all byte values and three frame formats. Next compare WEDGIE string parsing and cursor behavior at empty, truncated and malformed boundaries against the Java API.

Java logger size thresholds now apply to WEDGIE with full-frame length, backed by a beta-29 oracle. Next compare Java and Rust legacy byte display across all 256 byte values for EVA and WEDGIE. Live WEDGIE remains open.

Logger exports preserve distinct, ordered and complete names/hashes per Java. Next compare beta-29 WEDGIE packet length and byte-display behavior with the Rust logger; real clients remain unverified.

Byte-view log export now writes full eligible structures and retained display-limited packets; Java skip formatting has a fixture. Next compare logger metadata name/hash export limits and ordering with beta-29; real logger UI remains open.

Byte-view logger exports now use Java-style direction/header formatting and complete byte output. Next compare Java and Rust structure prediction and skipped/oversized packet export behavior; live logger validation remains open.

A synthetic WIRED import without save acknowledgement retries three times and reports incomplete. Next compare packet logger export formats with beta-29 Java; live WIRED gameplay remains open.

A synthetic WIRED trigger preset now reloads and imports with a simulated save acknowledgement. Next omit the WIRED save acknowledgement and verify that the extension reports an incomplete import; real WIRED gameplay remains open.

A synthetic WIRED trigger exports with its option, text and selected-furniture remapping. Next reload that preset and exercise its WIRED import using a simulated server; live WIRED behavior remains open.

A synthetic import now fails when final movement is unconfirmed. Next inspect a controlled WIRED preset fixture and identify the first missing behavior; live client and extension validation remain open.

G-Presets reports an incomplete simulated import when placement acknowledgement is missing; next test a missing movement confirmation. Live client and extension validation remain open.

G-Presets completed a one-item simulated import over loopback; next verify its behavior when placement acknowledgement is absent. Live, WIRED and complex preset imports remain open.

G-Presets has a simulated staging selection and first placement acknowledgement; next exercise subsequent movement and complete the isolated import.

G-Presets rejects an invalid simulated staging tile and aborts cleanly; next exercise a valid staging tile and placement acknowledgement.

G-Presets starts a simulated preset import and requests a staging location; next simulate the selected tile and placement acknowledgement.

G-Presets import readiness now changes after simulated catalog and controller rights; next exercise a controlled import and placement acknowledgement.

G-Presets refuses the simulated import when catalog prerequisites are absent; next investigate catalog setup and a controlled placement acknowledgement fixture.

G-Presets reloads the simulated exported preset through its own parser; next inspect requirements for an isolated import fixture.

A dedicated COM AIR client reached the Rust relay and the hosts redirect cleared; decrypted traffic, real extensions and disconnect cleanup remain unverified. Computer Use was stopped; do not resume window control without the user.

An isolated G-Presets fixture exports a simulated floor item with synthetic furnidata and WIRED disabled; full live export/import remains open. The user opened Rust as administrator for the dedicated COM session.

G-Presets fixture JAR and data are now both copied or scoped to per-test temporary directories; next inspect a genuine offline preset export fixture.

G-Presets tests explicitly isolate their data directory on Windows and Linux; earlier Windows runs could write the existing cache. Next inspect prerequisites for a real offline preset export fixture.

G-Presets virtual multi-page inventory is tested in Windows loopback; next inspect prerequisites for a genuine offline preset export fixture.

G-Presets assembled 599, 600, 601 and 1201 item inventories in loopback; next exercise a multi-page response to its own virtual inventory request.

G-Presets virtual inventory request, response blocking and state update pass in Windows loopback; next exercise multi-page inventory across the Java 600-item boundary.

G-Presets command blocking and feedback injection are exercised in loopback; next test an extension-originated inventory request toward the simulated server. The AIR administrator launch was canceled and must not be retried automatically.

The dedicated Habbo COM AIR process and socket passed a read-only diagnostic; complete elevated attachment, encrypted traffic and cleanup without disturbing the existing FR/QX session.

G-Presets loopback fixtures now observe floor movement and wall state updates; the separate AIR session is being prepared, while the existing WIRED TEST session must remain untouched.

G-Presets inventory and room item changes now have observable loopback tests; the user has prepared a dedicated AIR session for real relay validation.

The released G-Presets binary exposes expected incremental inventory state through an isolated observer; next observe floor and wall item state and updates. Live hotel and preset workflows remain open.

The released G-Presets binary handles one floor and one wall room item in two isolated Windows relay sessions; next investigate its incremental inventory updates and observable state. Live hotel and preset workflows remain open.

The released G-Presets binary parses a one-item inventory across two isolated Windows relay sessions; next exercise floor and wall room data through the same fixture. Real hotel and preset workflows remain open.

Unknown stuff-data tags and duplicate keys have beta-29 fixtures; next inspect the real G-Presets extension workflow and identify a safe offline integration test.

Stuff-data negative collection counts now match Java while high-score arrays reject negatives; next compare unknown tags and duplicate map keys against beta-29.

Negative furniture owner and item counts now have Java cursor fixtures; next compare malformed and unknown stuff-data formats against Java.

Wall ID number formats and floor direction boundaries have beta-29 fixtures; next compare furniture owner and item count failure behavior and cursor positions.

Pet flags and bot skill boundary values have beta-29 fixtures; next compare remaining room furniture placement and state formats against Java.

Entity-update fixtures now compare action ordering, malformed values and cursor positions; next compare pet and bot entity fields and serialization against beta-29.

Entity edge cases and Java serialization have differential fixtures; next compare entity-update action ordering, malformed values and cursor behavior against beta-29. Live client and extension tests remain open.

Status key: **partial** means implemented for selected cases only; **open** means no evidence of completion. All areas remain open to broader Java comparison and live validation. See `docs/PARITY.md` for details.

The local HTTPS fixture tolerates peers closing after the full response; the previous failed web run and subsequent successful run are recorded in `MIGRATION_PROGRESS.md`.

| Feature | Status | Next evidence or work |
|---|---|---|
| EVA framing, fields and mutations | Partial | Signed 8/16-bit operations and UTF-8 offset reads have Java oracle coverage; remaining helpers and regex/charset cases need fixtures. |
| WEDGIE codecs and expressions | Partial | Expand parsing corpus and validate a real Shockwave client. |
| Packet expressions and prediction | Partial | Broaden Java comparisons and metadata/client coverage. |
| Injection, packet tools and safety | Partial | CLI revision detection and real connection behavior. |
| TCP relay and reconnect | Partial | Real client, firewall and lifecycle tests. |
| RC4 and Flash attachment | Partial | Read-only process/socket and memory scan checked on an official AIR session; real encrypted traffic, key recovery, relay and multi-instance testing remain. |
| Origins encryption and attachment | Partial | Official client end-to-end testing. |
| Nitro proxy, crypto and assets | Partial | Real hotel and SOCKS servers, TLS fingerprint, interactive desktop controls and platform cleanup. |
| Unity communicator and WASM hooks | Partial | Real client revisions and extensions. |
| Java extension host | Partial | Live G-Presets workflows, other extensions and lifecycle parity. |
| G-Python and Node integrations | Partial | Real sessions and visual QtConsole validation. |
| Packet metadata and hotel detection | Partial | More providers, Unity discovery and real hotel checks. |
| Rules and scheduler | Partial | Restart recovery, catch-up semantics and remaining editor options. |
| Packet logger | Partial | Java export format, direction labels, visualization and WEDGIE behavior. |
| Settings and localization | Partial | All Java settings, complete translations and interactive import. |
| Room, entity, inventory and catalog APIs | Partial | Remaining parsers, more Java vectors and live extensions. |
| Extension store | Partial | More package/version cases, visual content and live workflows. |
| Desktop UI and themes | Partial | Complete layout/control parity, tray and interactive tests. |
| Windows distribution | Partial | Installer, signing and release QA. |
| Linux/macOS distribution | Partial | Desktop distribution and platform proxy helpers. |
| End-to-end equivalence | Open | Real supported clients, encryption, reconnect, extensions and cleanup. |
| Performance | Open | Representative comparable end-to-end Java and Rust benchmarks. |

Open-group backreferences, selected lookarounds, atomic groups, possessive quantifiers, nested classes and Java character properties have oracle coverage; full regex parity remains open. Friend, catalog and navigator cases have Java comparisons; next compare entity edge cases.

CI: serialized G-Python jobs passed on Windows and Linux in run 42723118432; continue monitoring intermittent kernel startup timeouts.
