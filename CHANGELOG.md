# Changelog

- Resume aligned schedules at an exact due boundary without duplicate sends.

- Add Java-compatible absolute string read semantics for WEDGIE and EVA.

- Add explicit beta-29-compatible WEDGIE string reading and CI oracle coverage.

- Compare all legacy logger byte representations with the released Java API.

- Apply Java logger size thresholds to WEDGIE packet frames.

- Preserve complete, ordered packet metadata in logger exports.

- Preserve complete structures and retained packet bytes in byte-view log exports.

- Align byte-view log exports with Java direction/header formatting and avoid truncating packet bytes.

- Verify G-Presets fails a simulated WIRED import after three unconfirmed save attempts.

- Exercise synthetic WIRED trigger preset reload and acknowledged import through G-Presets.

- Exercise synthetic WIRED trigger export through the released G-Presets extension.

- Verify G-Presets rejects an import with an unconfirmed final movement in loopback.

- Verify G-Presets reports an unacknowledged placement as incomplete.

- Exercise a complete one-item G-Presets import with a simulated server.

- Verify G-Presets first simulated placement and acknowledgement over the relay.

- Verify G-Presets invalid staging selection and import abort.

- Exercise G-Presets simulated import startup and staging prompt.

- Verify G-Presets import readiness with simulated catalog and controller rights.

- Verify G-Presets import refusal when catalog prerequisites are absent.

- Verify G-Presets reload of the simulated exported preset.

- Record live COM AIR socket routing and automatic hosts-entry cleanup.

- Exercise G-Presets preset export with synthetic room and furnidata.

- Isolate the G-Presets JAR path from legacy preset discovery during tests.

- Isolate G-Presets fixture data explicitly instead of relying on user.home on Windows.

- Verify G-Presets virtual inventory responses across multiple pages.

- Verify real G-Presets inventory paging at and across the 600-item boundary.

- Exercise real G-Presets virtual inventory request and response handling.

- Verify real G-Presets command blocking and client feedback injection over loopback.

- Record read-only diagnostic of the dedicated official AIR client.

- Verify G-Presets room-item position and state updates in the loopback fixture.

- Observe real G-Presets floor and wall state during simulated additions and removals.

- Verify real G-Presets incremental inventory state over loopback and retain original launcher coverage.

- Exercise real G-Presets floor and wall parsing over isolated relay sessions.

- Exercise actual G-Presets inventory parsing across isolated relay reconnects.

- Compare unknown stuff-data tags and duplicate map keys with beta-29.

- Match beta-29 negative stuff-data collection counts while retaining high-score array validation.

- Compare furniture collection count failures and cursors with beta-29.

- Compare wall furniture IDs and floor directions against beta-29.

- Compare pet flags and bot skills with beta-29 entity serialization.

- Expand Java entity-update action and cursor comparisons.

- Match beta-29 entity edge cases and expose its serialization separately from complete client wire records.

- Match Java navigator room sentinel flags and negative list counts.

- Compare nested beta-29 catalog index trees and document the Rust depth limit.

- Match Java catalog list count handling and compare offers and products.

- Stabilize the local metadata HTTPS fixture when the peer closes after a complete response.

- Add explicit beta-29 friend fragment pagination and parser compatibility.

- Add explicit beta-29 friend update cursor and construction compatibility.

- Compare beta-29 profiles and groups across flags and group counts.

- Expand beta-29 forum overview and view-mode comparisons.

- Match Java negative forum overview counts and expand thread comparisons.

- Match Java duplicate-owner resolution for floor and wall furniture collections.

- Add explicit beta-29 inventory pagination and parser compatibility, including original boundary defects.

- Expand Java regex Unicode script and block names and aliases.

- Resolve selected Java regex category, script and block property aliases.

- Add 89 Java Unicode, POSIX and character properties for Latin-1 regex input.

- Match selected recursive Java character-class intersection parsing cases.

- Match selected Java character-class syntax with consecutive ampersands.

- Support bounded nested Java regex character classes and intersections.

- Add bounded Java possessive quantifiers for atoms and groups.

- Add bounded Java atomic regex groups.

- Expand Java lookbehind width and overflow comparison fixtures.

- Match selected Java lookbehind width rejection cases for repeated groups.

- Add bounded Java lookbehind assertions with capture and width handling.

- Extend Java lookahead comparisons to repeated groups and backreferences.

- Retain selected Java captures from failed negative lookaheads.

- Add bounded Java positive lookaheads and negative lookaheads without captures.

- Support Java backreferences to groups still open during repeated matches.

- Combine Java regex backreferences with repeated groups and capture retention.

- Support bounded numbered and named Java regex backreferences.

- Support nested repeated Java groups with capture-aware rollback.

- Preserve Java captures for deterministic fixed-count inner repetitions.

- Support nested captures in nondeterministic repeated Java groups.

- Preserve GroupCurly nested captures across fixed repeated bodies and failed searches.

- Support variable-width captures in repeated Java groups.

- Support repeated Java groups with variable-width capture-free bodies.

- Support multiple fixed-width repeated Java groups without alternation.

- Track independent counters for bounded nested regex loops.

- Support sequential repeated alternative groups and capturing ancestors.

- Support a bounded quantified Java alternative group, including nullable branches.

- Preserve ordinary captures in nested Java regex alternation.

- Support bounded nested Java alternation without capture groups.

- Support Java alternation branches with captures before fallible suffixes.

- Fix greedy repeated-group capture retention during Java-style backtracking.

- Preserve Java failed-search captures in fixed reluctant group repetitions.

- Support branch-ending captures in top-level Java regex alternation.

- Support ordered top-level Java regex alternation without captures.

- Support Java COMMENTS regex whitespace, comments and scoped changes.

- Add opt-in read-only official AIR process, TCP ownership and scan diagnostics.

- Match Java UNIX_LINES regex dot and anchor behavior.

- Support Java embedded regex flags with enclosing-group restoration.

- Support scoped Java regex flags and restore their state at group boundaries.

- Document Java failed-search capture retention and preserve explicit rejection for affected patterns.

- Support fixed-width captures in greedy non-capturing repetitions with a positive minimum.

- Preserve captures around optional non-capturing regex groups.

- Support optional non-capturing regex groups in capture-free patterns.

- Support fixed-width, capture-free repeated non-capturing regex groups.

- Support unquantified Java non-capturing regex groups and nested capture numbering.

- Support Java Unicode predefined regex classes and word boundaries over Latin-1.

- Support Java Unicode case-insensitive Latin-1 literals and classes with exhaustive Java 21 pair comparisons.

- Route Flash and Origins metadata lookups through configured SOCKS when the web feature is present; no-web builds fail closed for that lookup.

- Enable authenticated SOCKS5 in desktop Nitro settings, including metadata and explicitly opted-in City helper requests.

- Route opt-in Nitro City helper uploads through SOCKS5 without forwarding uploads across redirects.

- Route Nitro packet metadata HTTPS and its cache refresh through SOCKS5; City helper and desktop enablement remain unfinished.

- Route web proxy HTTP, HTTPS, WebSocket and raw CONNECT upstreams through optional SOCKS5; auxiliary lookups and desktop enablement remain unfinished.

- Vendor Hudsucker 0.25.0 and add an optional WebSocket/raw CONNECT dialer; Nitro SOCKS integration remains unfinished.

- Add a cancellable asynchronous SOCKS5 CONNECT primitive; Nitro routing integration remains unfinished.

- Exercise released G-Presets over loopback relay connections and reconnect with its HTTPS requests isolated.

- Test Java extension WEDGIE injection before and after encryption, blocking and reconnect.

- Exercise beta-29 Java extension packet modification through encrypted Origins relay sessions and reconnect.

- Test encrypted Origins relay traffic, extension modification and reconnect after metadata initialization.

- Initialize Origins metadata before starting the extension session, with bounded cancellable lookup and an offline option.

- Test Origins discovery and metadata caching over local HTTPS; preserve the requested version when a discovered database is empty, as Java does.

- Discover the latest Origins release even with an explicit version, falling back to a valid supplied version on discovery failure.

- Test cancelled and replacement Nitro sessions against concurrent local HTTPS metadata responses and a shared cache; verify temporary fixture cleanup.

- Test cancelled Nitro session replacement and concurrent metadata cache persistence together.

- Prevent older concurrent Sulek refreshes within one process from overwriting a newer cache result.

- Exercise Sulek cache refresh, offline fallback and cancelled workers over a locally trusted HTTPS server.

- Refresh Sulek metadata caches after five minutes and retain a valid matching cache on fetch or parse failure.

- Test Nitro metadata success, HTTP failure, malformed and truncated responses, the size limit and cancellation over verified local HTTPS; verify extension forwarding after errors.
- Test that cancelled Nitro metadata lookups cannot replace a newer extension session.
- Load missing Nitro metadata without an extension host, with bounded cancellable lookup and an offline option.
- Reject Nitro metadata labeled for a different revision and test Unity static metadata across revisions.
- Load Flash packet metadata even when no extension host is active.
- Reject stale or unversioned preloaded metadata after automatic Flash revision detection.
- Synchronize the G-Python fixture shutdown after the host receives the final interception response.
- Compare UTF-16 replacement and long/short-field boundaries against Java.
- Encode Java UTF-16 code units, including unpaired surrogates, in five packet charsets.
- Add explicit UTF-16LE and BOM-sensitive UTF-16 packet string variants.
- Add strict and Java-style replacement UTF-16BE packet string operations.
- Compare Java Latin-1 replacement encoding across all Unicode scalar values and short-field boundaries.
- Add explicit Java-style ISO-8859-1 replacement encoding for EVA packet strings and typed fields.
- Add typed EVA packet field appends for the eight Java `appendObject` categories.
- Support Java `$0` and escaped replacement templates for nonempty literal substring patterns; full regex support remains open.
- Extend Java height-format comparisons to negative subnormals, powers of ten and entity/furniture packet bytes.
- Align selected Java 21 scientific height formatting, including smallest subnormal values.
- Parse Java-style decimal and hexadecimal floating-point height strings for entities and floor items.
- Align selected entity-update action delimiters and integer sign parsing with the Java API.
- Added a Flash oracle case demonstrating the shared false-identification risk on ordinary two-string packets.
- Stop Flash metadata initialization on visible peer EOF during lookup and preserve any prior extension session.
- Make Flash metadata waits cancellable on explicit stop, with bounded in-flight worker lookups; test empty-revision failure and a stalled provider through the relay.
- Register metadata packet identifiers as safe by revision and direction for TCP, Flash, Nitro and Unity, matching the Java connection.
- Added a controlled Flash relay and extension lifecycle fixture for identity variants.
- Flash identification accepts empty revisions and trailing fields like the pinned Java handler; the oracle also documents fragmentation differences.
- Added 36,864 targeted UTF-8 boundary combinations to the Java decoding oracle.
- Added 20,000 deterministic mixed byte strings of lengths 3â€“12 to the Java UTF-8 differential oracle.
- Expanded the beta-29 Java UTF-8 differential oracle to every two-byte sequence and mixed input at six short-field length boundaries; this is finite coverage.

## Unreleased

- Support Java global multiline regex anchors and combinations with dotall/case-insensitive modes.

- Support global Java dotall regex matching and combinations with case-insensitive mode.

- Support Java regex replacement without captures, including empty patterns and bounded zero-width expansion.

- Support Java 21 global ASCII case-insensitive regex matching with case-preserving captures.

- Support Java 21 word-boundary regex assertions over Latin-1 packet strings.

- Run G-Python integration tests serially in CI to reduce concurrent Jupyter startup contention.

- Support bounded Java start/end regex anchors, including final line terminators.

- Restore deeply nested Java regex captures inside repeated groups under explicit state limits.

- Support optional atoms in direct nested captures within repeated Java regex groups.

- Support optional atoms inside bounded repeated Java regex groups with capture retention.

- Support bounded repeated atoms within supported repeated Java regex capture groups.

- Support bounded repetition counts for variable-length Java regex groups with retained optional captures.

- Guard zero-width repeated Java regex bodies while preserving captures across iterations.

- Preserve multiple independent optional Java regex captures across bounded group repetition.

- Restore retained inner captures for a bounded subset of variable-length repeated Java regex groups.

- Support fixed-length repeated Java regex groups containing nested captures; record Java capture-retention behavior for variable-length groups.

- Support bounded repetition of one fixed-length Java regex capture group.

- Support bounded greedy and reluctant Java regex `{m}`, `{m,n}` and `{m,}` atom repetitions.

- Support bounded Java greedy and reluctant `*`/`+` repetition on individual regex atoms.

- Support bounded nested optional Java regex quantifiers with capture restoration.

- Support bounded non-overlapping optional Java regex capture groups.

- Support bounded iterative backtracking for multiple Java regex optional atoms.

- Support one bounded greedy or reluctant Java regex optional atom, including zero-width matches and captures.

- Support bounded Java regex control and Latin-1 hexadecimal escapes inside and outside character classes.

- Support unions of Java predefined regex classes within bounded bracket expressions.

- Support Java predefined ASCII regex classes and complements outside bracket expressions.

- Support bounded Java regex character classes, ranges, negation and selected escapes with Java differential coverage.

- Support bounded Java dot-wildcard matching and dynamic capture replacement, with Java differential corpus.

- Support Java quoted literal patterns and named fixed-pattern capture groups in bounded substring replacement.

- Handle bounded zero-width Java empty-group replacement at Latin-1 character boundaries.

- Support nested and empty capture groups and escaped metacharacters in nonempty fixed-pattern Java substring matches.

- Extend bounded Java substring replacement to multiple literal groups, including no-match replacement-validation timing.

- Add bounded substring replacement for a single literal capture group with Java-compatible replacement references, checked against the beta-29 API.

- Route Unity asset and game WebSocket proxy traffic through configured SOCKS, expose shared desktop controls, and test local TLS and refusal behavior.

- Share authenticated SOCKS HTTPS metadata transport with minimal builds, including Origins discovery and Flash metadata; verify loopback TLS and proxy refusal without direct fallback.

- EVA UTF-8 replacement decoding now treats malformed surrogate encodings like Java for the tested cases, instead of replacing each byte separately.
- EVA packets: add optional replacement-decoding UTF-8 reads for malformed short/long fields, including cursor-preserving offset reads.
- EVA packets: add cursor-preserving short/long byte and strict UTF-8 reads at an absolute offset, with Java API comparisons for valid strings.
- Packet core: add signed-byte read, random-access read, append and EVA replacement; compare negative boundary values with the original Java API.
- EVA packets: add signed 16-bit read, random-access read, append and replacement; compare boundary values and cursor behavior with the beta-29 Java API.
- Extend the Java hexdump differential fixture around the 256-byte boundary and to 1024 bytes.
- Java settings import preserves an explicitly selected Rust logger representation; imports without a choice still default to no primary byte view.
- Logger: exercise primary and secondary clicks on an empty-header row using simulated egui pointer events.
- Logger: optionally hide empty byte-view headers on screen and in copied displayed text; retain row actions through the row area.
- Logger: optionally omit empty byte-view headers from exported captures, retaining metadata and separators. The on-screen view and copy-displayed action retain their header.
- Logger: allow exports to include separators independently of the on-screen separator setting; Java preference imports enable this unless an explicit Rust choice exists.
- Logger: use the original localized incoming/outgoing labels in the display and export while retaining direction arrows.
- Document migration architecture and outstanding work in dedicated files. Existing history is recorded by Git commits and `docs/CONTINUATION.md`; this changelog begins with the current migration work.
- Logger: preserve Java-style direction capture on import; provide optional Java structure size and text filtering; support no primary byte view; order additional views as legacy, hexdump and raw hex when no primary view is selected.
- Logger: retain anti-spam history across reconnects and level changes with a bounded queue; retain the filtered count on clear and allow explicit reset.
- Manual extension launch: capture stdout and stderr for the extension console.
- Scheduler: accept a clock offset equal to the interval and update its boundary test.

These changes have focused tests; complete application parity and real-client validation remain outstanding. See `MIGRATION_PROGRESS.md` for exact validation and caveats.
