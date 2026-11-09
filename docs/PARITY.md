# Compatibility with 1.5.4-beta-29

Status describes source implementation and finite tests, not successful production use. No official Habbo client or G-Presets game session has been tested with this port.

| Area | Rust status | Remaining work |
|---|---|---|
| EVA_WIRE | Framing, primitive fields, Latin-1 and explicit UTF-8 strings, raw short and long fields for custom encodings, HPacket/HMessage serialization, typed mutations and bounded literal substring replacement with Java comparisons | Full Java regex substring semantics, remaining mutation helpers, other charsets and broader compatibility corpus |
| WEDGIE | Incoming/outgoing packet formats, fixed B64, VL64 and format-aware expressions | Wider parser corpus and official client regression |
| Packet expressions | Typed/numeric/named expressions, mixed raw display notation, bounded structure prediction, nested structures and Java comparisons | Broader prediction and editor corpus; metadata and client regression |
| Injection and tools | Multi-packet input, separate destination buttons, bounded history, EVA/WEDGIE conversion, numeric tools; TCP/Nitro/Unity metadata and observed-ID tracking and desktop injection, scheduler and extension safety checks with developer override; optional CLI revision checking | CLI revision detection, complete developer-mode UI, editor parity and real connection validation |
| Explicit TCP relay | Nonblocking bidirectional relay, bounded output, injection, ordered block/replace, reconnect, scoped hosts attachment, Raw-IP preconnected upstreams | Real client/firewall regression |
| RC4 | State import/export/rewind, manual keys and Windows negotiated discovery, bounded read-only heap scan, ambiguity rejection | Real AIR client regression; broaden memory-layout coverage |
| Origins crypto | DH substitution, HKDF-SHA256, ChaCha20 channels, encrypted framing and hosts attachment | Official client end-to-end live validation |
| Network extensions | Loopback host, one-use launch tokens, approval, flags, interception, injection, click, console, connection details, language changes | Full extension corpus, store and lifecycle parity |
| Existing Java API | Actual beta-29 Java extension fixture passes auth, name lookup, bidirectional mutation/blocking/injection; released G-Presets 1.6.5 authenticates and returns fixture packets in both directions | Real G-Presets game workflows and other existing extension binaries untested |
| Python/Node extensions | External runtimes, authenticated IPC, native G-Python/Jupyter console controls and explicit package installation/repair; real G-Python kernel fixtures on Windows/Linux | QtConsole visual workflow and real sessions |
| Packet identifiers | Direction-aware indexed database, beta-29 IPC, Sulek HTTPS lookup/cache, detected Flash revision, Unity JSON and TSV import | Unity client integration and broader remote-provider coverage |
| SOCKS5 | CONNECT, remote DNS, optional RFC1929 credentials | Wider interoperability tests |
| Rules/scheduler | Editable and reorderable saved rules, editable active jobs and finite or indefinite schedule templates, beta-29 `.sched` import/export, clock-aligned offsets, per-job pause/resume and reconnect retention, optional Windows global shortcuts | Non-Windows global shortcuts, interactive shortcut validation, automatic restoration after app restart, original catch-up behavior and remaining rule-editor options |
| Logging | Cached search/display strings and metadata search, virtualized rows, bounded packet size, names/hashes/IDs, replaced indicator, structure prediction, separators, anti-spam, legacy/raw-hex and bounded inline hexdump views, timestamps, auto-scroll, filtered export, native logger window with optional open/hide on connection | Native window interaction, original highlighting and exact inline hex layout, WEDGIE prediction, remaining filtering/window options, exact original export formatting and visual validation |
| Settings | Atomic save/load, unknown-field preservation, original cache import, notepad | Migration of every original setting |
| UI/theme/languages | Rust eframe desktop, light/dark theme, nine original resource files, localized tabs and an Extra panel with notepad, always-on-top, developer mode and client-side staff-permissions heuristic | Exact UI/layout, all controls translated, shortcuts, tray, interactive validation |
| Flash | Negotiation, Windows client memory discovery, socket owner detection, hosts attachment, Raw-IP mapping, Windows multi-instance heartbeat/lease and independent counters | Official client/firewall/multi-instance validation and non-Windows discovery |
| Origins attachment | Scoped hosts routing to the original port | Official client validation and non-Windows privileged helpers |
| Nitro | HTTP/TLS/WebSocket backend, beta-29 hotel matching/config, RC4/TripleDES/GCM/CTR adapters, assets, shared rules/injection/extensions, explicit current-user certificates and journaled Windows proxy cleanup | Real hotel sessions, Chrome TLS fingerprint, SOCKS upstream, non-Windows OS helpers |
| Unity connection | Authenticated TLS communicator, exact asset routes, gzip and cache handling, validated WASM hooks, browser reinjection and Java extensions | Official client revisions, G-Presets and non-Windows system helpers |
| Hotel detection | Flash/Origins lists, custom domain/revision, Nitro hello fallback, dynamic nitro.json, beta-29 hotel URL/prefixes and adapters | Live hotel regression and Unity discovery |
| Room/catalog/inventory/entity API | Native Rust room entities, movement, floor/wall furniture, inventory pages, furniture states, profiles/friends, catalog and navigator; selected packet vectors compared against the released Java API | Remaining parser APIs, broader Java differential coverage and live extension validation |
| Extension store/updater | Original catalogue, native search/filter/order, Maven-style version comparison with Java oracle, bounded archive install, separate-version updates, authenticated launch and managed uninstall | Broader version and package corpus, thumbnails/readme presentation |
| Windows packaging | Tested development EXE and CLI via Actions/prereleases | Installer, signing and release QA |
| Linux/macOS | Core tests on Linux; Windows desktop compiled | Desktop distribution and platform proxy helpers |
| beta-29 integration fixes | leet/habblet prefix matching and dynamic nitro.json ported | Chrome TLS fingerprint, privileged macOS helper, tray cropping |
| Performance gain | Unmeasured | Equivalent end-to-end workload benchmark against Java |

## Completion criteria

A complete port requires the remaining functionality above, tested through real supported Flash/Origins/Unity/Nitro connections, existing Java extensions including G-Presets, reconnect, encrypted traffic, certificate/proxy cleanup, settings migration and the complete UI workflow. Passing a finite protocol oracle or compiling an executable does not establish whole-application parity.

The Java UTF-8 replacement-decoding oracle covers all 65,536 two-byte inputs and mixed valid and malformed data at six short-field lengths through 65535. Offset and sequential reads are checked on those length cases. This is finite coverage; real extensions and all longer combinations remain unverified.

A deterministic sample of 20,000 byte strings of lengths 3–12 also matches Java replacement decoding locally. This does not exhaust longer inputs.

An additional 36,864 combinations target E0, ED, F0 and F4 boundary sequences; the local Java comparison passes. These tests do not establish exhaustive UTF-8 or real extension compatibility.

The CLI relay is generic plaintext EVA and cannot reliably infer a Flash revision from arbitrary traffic; `--revision` enables observed-ID checks. Java and Rust Flash extract two strings from a short outgoing packet and accept an empty revision or trailing bytes. The broader heuristic can misidentify other packets; real client handshakes remain unverified.

A focused oracle executes the pinned Java identification method with a stub superclass: normal input, trailing payload and an empty revision agree. Rust reassembles every two-part split of one hello; Java identification called with the two chunks does not, and throws for splits 7–23. The superclass is stubbed, so this is not a full Java transport or real-client test.

A controlled loopback Flash relay and extension protocol fixture covers normal and empty revisions with a trailing byte, interception, forwarding and disconnect using preloaded metadata. TCP may coalesce the two writes; deterministic frame fragmentation is covered separately. Real client and extension behavior and metadata lookup failures remain unverified.

Packet IDs from the supplied metadata are now registered as safe before they occur in traffic, as in Java `HProxy.verifyProxy`, for TCP/Flash, Nitro and Unity. Local transport fixtures check revision/direction isolation and a Flash extension sends a known, unobserved ID. Incorrect metadata can permit an incorrect ID; the registry remains bounded to 64 revisions. Actual client and extension validation remains outstanding.

Flash metadata lookup failure with an empty revision is covered through a local relay and extension fixture. Explicit stop or session close now stops waiting for a Flash lookup; up to four already-running network workers can continue and cache results. A controlled stalled-provider test exercises explicit stop through the full relay; an actual stalled HTTP request and real client behavior have not been validated. The relay detects visible peer EOF or reset during lookup and avoids starting a stale extension session in controlled tests. Unread socket data can conceal EOF until after lookup, and disconnect races remain possible.

A controlled non-handshake packet with header 999 and two ordinary strings is accepted as Flash identification by both Java and Rust. This heuristic can attach the wrong revision; real handshake evidence is needed to design a more selective detector.

Entity-update parsing now matches 11 selected beta-29 Java cases for trailing action separators, movement coordinates and malformed integer signs. The shared Java-style integer parser is also used by furniture IDs. Floating-point parsing now covers selected Java syntax and hexadecimal rounding; complete parser equivalence remains unverified.

Entity, movement and floor-item heights accept Java-style floating-point text, including hexadecimal literals. Eighteen selected vectors and 3,000 deterministic hexadecimal strings were compared against the beta-29 Java API. Decimal edge cases, serialization and real room traffic require broader validation.

Height formatting now matches Java 21 for the first 10,000 positive subnormal bit patterns, selected boundaries and approximately 5,000 deterministic random finite values. The previous output differed for the two smallest subnormals. This is finite coverage and does not prove equivalence for all doubles or Java versions.

Additional Java 21 vectors cover the first 10,000 negative subnormals, powers of ten and adjacent values. Seven difficult heights also match complete entity and floor-item packet bytes from the released Java API. The comparisons are finite and real client traffic remains untested.

The packet API offers Java-style replacement templates for nonempty literal substring patterns, including `$0` and backslash escapes, with ten Java oracle cases. Regex patterns, nonzero capture groups and empty patterns remain unsupported; Rust replacement is bounded and transactional and does not reproduce every Java error or partial mutation. Real extensions remain untested.
