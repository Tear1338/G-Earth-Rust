# Compatibility with 1.5.4-beta-29

Active .sched loading is available offline with deferred named IDs, source validation, atomic replacement and one-second non-starving retries. Loopback injection passes; real-client reconnect and visual UI remain unverified.

Scheduler packet expressions now resolve against current metadata and client format at dispatch, with a loopback relay test. Java and Rust both start with no active jobs automatically restored; disconnected named-schedule loading and real-client reconnection remain open.

Deterministic small scheduler clock jumps now follow Java-visible millisecond changes; a Java-loop fixture covers the forward case. Operating-system jitter, restart and real-client timing remain unverified.

Aligned scheduler backlog now survives backward rebases and large forward jumps without Instant underflow in Windows tests. Small clock changes, Java timing details and real clients remain unverified.

Forward scheduler wall-clock jumps replay crossed aligned slots in tested cases, matching a fixture mirroring Java beta-29. Backward jumps with backlog, extreme time shifts and real-client timing remain unverified.

Aligned scheduler catch-up matches eight deterministic cases from a Java fixture mirroring the beta-29 time-window loop. Per-dispatch batching, clock jumps and real-client timing remain distinct or unverified.

A schedule offset equal to its interval is accepted but never dispatched, matching the beta-29 Java modulo condition. Java missed-slot replay and live-client timing remain open.

Aligned schedule resume now emits at an exact boundary. Java replays elapsed scheduler slots after disconnection; Rust currently skips missed slots and does not claim parity for catch-up or real client scheduling.

The Java-compatible absolute string reader matches selected beta-29 WEDGIE rejection and EVA cursor cases; Rust also exposes independent WEDGIE absolute reads. Real Shockwave behavior remains unverified.

The explicit WEDGIE Java-compatible string reader matches nine beta-29 API fixtures, including cursor state on malformed data. Default Rust parsing remains transactional. Live Shockwave remains unverified.

Legacy byte display matches beta-29 for all 256 byte values and complete EVA/WEDGIE fixtures. This does not verify a live Shockwave connection.

Logger size thresholds now use beta-29 length semantics for EVA and both WEDGIE directions; a Java API oracle covers 18 boundary cases and Windows desktop tests cover the 1000/1001 WEDGIE boundary. Live Shockwave compatibility remains unverified.

Logger exports now preserve distinct names and hashes in beta-29 order, including empty and long metadata, in Windows tests. Full logger and live-client parity remain open.

Byte-view export now preserves eligible full structures and retained display-limited packet bytes; a skipped-packet fixture checks Java separator behavior. Prediction parity and live logger behavior remain open.

Byte-view log exports now follow selected beta-29 Java formatting and include all packet bytes; incoming/outgoing examples and Java hexdump oracle pass locally. Expression mode, structure rendering, oversized packets and live UI are not fully proven equivalent.

Released G-Presets retried a synthetic WIRED trigger save three times and reported incomplete when the loopback server omitted acknowledgement. Linux CI and real hotel behavior remain unverified.

Released G-Presets reloaded and imported a synthetic WIRED trigger preset over the Windows loopback relay, with simulated placement, movement and save acknowledgements. Linux CI and actual WIRED gameplay remain unverified.

Released G-Presets exported a synthetic WIRED trigger with configuration and selected-furniture ID remapping through the Windows loopback relay. Linux CI, WIRED import and real hotel behavior remain unverified.

Released G-Presets rejected an import with an unconfirmed final movement in a Windows synthetic loopback session. Linux CI, WIRED presets and real hotel imports remain unverified.

Released G-Presets reported a simulated import incomplete after a missing placement acknowledgement in Windows loopback. Linux CI and real hotel behavior remain unverified.

Released G-Presets completed a one-item import in two isolated Windows loopback sessions with synthetic data and server acknowledgements; the test checked the final position and stack-tile restoration. WIRED, variables, walls, Linux CI and real hotel imports remain unverified.

G-Presets sent a placement for simulated inventory, accepted a simulated ObjectAdd and associated the returned ID in two Windows loopback sessions. The fixture aborts afterward; full import and real hotel behavior remain unverified.

Released G-Presets rejected a simulated invalid staging tile and returned to its initial state after abort in two Windows loopback sessions. Valid placement and real hotel behavior remain unverified.

G-Presets accepted a synthetic preset import and reached staging-location selection in two Windows loopback sessions. No placement, complete import or live hotel behavior was verified.

The released G-Presets importer became ready after simulated catalog and controller messages in two Windows loopback sessions. No placement or actual hotel import was verified.

The released G-Presets binary refused a selected simulated preset import without catalog initialization and returned feedback in two Windows loopback sessions. This does not verify a successful import or live hotel behavior.

The released G-Presets binary reloaded a simulated exported preset and returned expected furniture fields in two Windows loopback sessions. Synthetic furnidata and disabled WIRED/variable/wall export limit this result; live import and export remain unverified.

A dedicated real COM AIR client established TCP connections through Rust and the owned hosts redirect was removed on acceptance; the separate FR/QX socket stayed established. Decrypted traffic, extension behavior, disconnect cleanup and actual protocol parity remain unverified.

The released G-Presets binary exported a simulated floor item with expected class and position in two isolated Windows sessions using synthetic furnidata and disabled WIRED/variable/wall export. Linux CI and real hotel export/import remain unverified.

G-Presets test runs use both a private JAR copy and isolated data directory to avoid loading unrelated legacy presets. Windows tests pass; Linux CI is pending.

The G-Presets test fixture explicitly isolates extension data on Windows and Linux. Earlier Windows fixture runs could access and write the existing G-Presets cache; its prior contents are unavailable. The fixed Windows rerun left the existing cache timestamp unchanged.

G-Presets assembled a 601-item virtual inventory and blocked both pages from the simulated client in two Windows loopback sessions. Linux CI and live hotel/preset export remain unverified.

The released G-Presets binary assembled 599, 600, 601 and 1201 items across one to three pages in two Windows loopback sessions. Linux CI and real hotel behavior remain unverified.

Released G-Presets sent a virtual inventory request, blocked its response from the simulated client, and updated its inventory in two Windows loopback sessions. Linux CI and real hotel/preset workflows remain unverified.

Released G-Presets blocked `:ep` and injected its expected unavailable-data feedback in two Windows loopback sessions; a following packet reached the simulated server. Linux CI, live hotel and complete preset export remain unverified.

A dedicated official Habbo COM AIR process passed read-only process/socket identification and completed a memory scan with one candidate. This is not proof of RC4 recovery or an attached relay; the separate FR/QX session must be preserved.

The released G-Presets binary exposed expected simulated floor-position and wall-state updates in two Windows loopback sessions. Linux CI for this addition and real hotel/preset workflows remain unverified.

A test launcher observed expected floor and wall item IDs in the released G-Presets binary after simulated room initialization, additions and removals across two Windows loopback sessions. Linux CI for this fixture and live hotel/preset workflows remain unverified.

G-Presets 1.6.5 incrementally added and removed simulated inventory items with expected public state across two Windows loopback sessions, observed via a test-only launcher; the original JAR launcher separately authenticated. Linux CI and real hotel/preset workflows remain unverified.

Released G-Presets 1.6.5 logged parsing one floor and one wall item in each of two isolated Windows relay sessions. The prior inventory fixture passed Linux CI; Linux CI for the extended fixture and real hotel/preset workflows remain unverified.

The pinned G-Presets 1.6.5 binary parsed a one-item inventory in two isolated Windows relay sessions, as confirmed by its debug log. Linux CI is pending; real hotel and preset workflows remain unverified.

Unknown stuff-data tags and duplicate keys match beta-29 in selected failure, cursor and serialization fixtures; live behavior remains unverified.

Negative map, string-list and integer-list counts normalize to empty as in beta-29; negative high-score array lengths fail with matching cursor positions. Windows GNU desktop/web release builds locally, but real client and extension compatibility remains unverified.

Negative floor and wall furniture owner/item counts fail at the same cursor positions as beta-29 in four fixtures. Real traffic remains unverified.

Furniture fixtures compare 12 wall ID forms and floor directions -1 through 8 against beta-29, including invalid cases. Real furniture traffic and extensions remain unverified.

Pet entity fixtures cover 64 flag combinations, while bot fixtures cover skill counts and signed-short boundaries; normalized bytes match beta-29 for these cases. Live client and extension behavior remains unverified.

Entity-update fixtures now compare 27 action strings and cursor positions against beta-29, including repeated and malformed actions. This finite corpus does not establish live compatibility.

Entity fixtures compare unknown types, gender cases, negative bot skill counts, invalid directions and entity/update counts against beta-29. The Java-compatible serializer reproduces its omitted Habbo integer; the client serializer keeps it. Real client and extension behavior remains unverified.

Navigator fixtures compare 256 room flag/sentinel combinations and negative list versus tag-array counts with beta-29. Live navigator and extension behavior remains unverified.

Catalog index fixtures compare nested children, offer IDs, visibility and cursor position. Java accepted a 65-level chain that Rust deliberately rejects beyond its 64-level depth bound.

Catalog fixtures compare multiple offers, all product types, limited products and front-page target forms with beta-29. Negative list counts match Java's empty-loop behavior; negative image arrays are rejected. Live catalog compatibility remains unverified.

The local metadata HTTPS fixture now tolerates a peer closing after the complete response. This addresses an intermittent test failure, not real-provider validation.

Friend fragment fixtures compare beta-29 bytes and cursors at sizes around 100 and 200, including Java's original incorrect count and repeated tails. Separate corrected paging is retained for clients; live extensions remain unverified.

Friend update fixtures cover duplicate/missing categories, mixed changes, removals, unknown relationship IDs and negative counts. Separate Java-compatible parsing/construction paths preserve its cursor reset and missing change markers; category order can differ from Java `HashMap`. Live extension behavior remains unverified.

Profile and group fixtures compare eight flag combinations, varying group counts and negative-count rejection with the beta-29 Java API. Live profile and extension compatibility remains unverified.

Forum overview fixtures compare three rows across all known view modes and an unknown-mode fallback with beta-29 getters and normalized output. Live forum and extension behavior remains unverified.

Forum thread overview fixtures cover flags, multiple rows, known and unknown states, and Java's empty-list interpretation of negative overview counts. Positive counts remain bounded; live forum and extension behavior remains unverified.

Floor and wall collection fixtures cover multiple, duplicate and missing owners against beta-29. Java uses `HashMap` owner order while Rust sorts IDs, so comparisons verify parsed semantics rather than identical ordering.

Inventory has separate corrected paging and bounded beta-29-compatible construction/parsing. Java oracle comparisons cover all four product types, all 23 special types, cursor positions and sizes around 600 and 1,200; Java's original page counts and contents contain defects at those boundaries. Live extensions remain unverified.

Java regex properties and 1,076 script/block names have exhaustive Latin-1 bitmap comparisons for eight flag combinations. Selected property and alias packet cases match beta-29; other regex behavior and live-session compatibility remain unverified.

Nested character classes and intersections match 540 beta-29 packet cases, including COMMENTS mode, Latin-1 case folding and selected recursive consecutive-ampersand cases. Complete regex and live-session compatibility remain unverified.

Possessive quantifiers match 600 beta-29 packet cases, including captures, empty repetitions and lookbehinds. Full Java regex and real-session parity remain unverified.

Atomic regex groups match 300 beta-29 packet cases with alternatives, captures, assertions and repetitions. Full regex and real-session parity remain unverified.

Selected positive and negative lookbehinds match 840 beta-29 packet cases, including variable widths, nested assertions and repeated captures. Selected Java rejections for indeterminate repeated groups are covered. More combinations and real-session compatibility remain unverified.

Selected positive and negative lookaheads, including captures in failed negative assertions and assertions inside repeated groups, match 300 beta-29 packet cases. Full Java regex and real-session compatibility remain unverified.

Open-group backreferences match 250 additional beta-29 packet cases, including named and repeated groups. Full Java regex and real-session compatibility remain unverified.

Status describes source implementation and finite tests, not successful production use. No official Habbo client or G-Presets game session has been tested end-to-end through this port.

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
| Nitro | HTTP/TLS/WebSocket backend, beta-29 hotel matching/config, RC4/TripleDES/GCM/CTR adapters, assets, shared rules/injection/extensions, explicit current-user certificates and journaled Windows proxy cleanup | Real hotel and SOCKS sessions, Chrome TLS fingerprint, interactive controls, non-Windows OS helpers |
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

A deterministic sample of 20,000 byte strings of lengths 3â€“12 also matches Java replacement decoding locally. This does not exhaust longer inputs.

An additional 36,864 combinations target E0, ED, F0 and F4 boundary sequences; the local Java comparison passes. These tests do not establish exhaustive UTF-8 or real extension compatibility.

The CLI relay is generic plaintext EVA and cannot reliably infer a Flash revision from arbitrary traffic; `--revision` enables observed-ID checks. Java and Rust Flash extract two strings from a short outgoing packet and accept an empty revision or trailing bytes. The broader heuristic can misidentify other packets; real client handshakes remain unverified.

A focused oracle executes the pinned Java identification method with a stub superclass: normal input, trailing payload and an empty revision agree. Rust reassembles every two-part split of one hello; Java identification called with the two chunks does not, and throws for splits 7â€“23. The superclass is stubbed, so this is not a full Java transport or real-client test.

A controlled loopback Flash relay and extension protocol fixture covers normal and empty revisions with a trailing byte, interception, forwarding and disconnect using preloaded metadata. TCP may coalesce the two writes; deterministic frame fragmentation is covered separately. Real client and extension behavior and metadata lookup failures remain unverified.

Packet IDs from the supplied metadata are now registered as safe before they occur in traffic, as in Java `HProxy.verifyProxy`, for TCP/Flash, Nitro and Unity. Local transport fixtures check revision/direction isolation and a Flash extension sends a known, unobserved ID. Incorrect metadata can permit an incorrect ID; the registry remains bounded to 64 revisions. Actual client and extension validation remains outstanding.

Flash metadata lookup failure with an empty revision is covered through a local relay and extension fixture. Explicit stop or session close now stops waiting for a Flash lookup; up to four already-running network workers can continue and cache results. A controlled stalled-provider test exercises explicit stop through the full relay; an actual stalled HTTP request and real client behavior have not been validated. The relay detects visible peer EOF or reset during lookup and avoids starting a stale extension session in controlled tests. Unread socket data can conceal EOF until after lookup, and disconnect races remain possible.

A controlled non-handshake packet with header 999 and two ordinary strings is accepted as Flash identification by both Java and Rust. This heuristic can attach the wrong revision; real handshake evidence is needed to design a more selective detector.

Entity-update parsing now matches 11 selected beta-29 Java cases for trailing action separators, movement coordinates and malformed integer signs. The shared Java-style integer parser is also used by furniture IDs. Floating-point parsing now covers selected Java syntax and hexadecimal rounding; complete parser equivalence remains unverified.

Entity, movement and floor-item heights accept Java-style floating-point text, including hexadecimal literals. Eighteen selected vectors and 3,000 deterministic hexadecimal strings were compared against the beta-29 Java API. Decimal edge cases, serialization and real room traffic require broader validation.

Height formatting now matches Java 21 for the first 10,000 positive subnormal bit patterns, selected boundaries and approximately 5,000 deterministic random finite values. The previous output differed for the two smallest subnormals. This is finite coverage and does not prove equivalence for all doubles or Java versions.

Additional Java 21 vectors cover the first 10,000 negative subnormals, powers of ten and adjacent values. Seven difficult heights also match complete entity and floor-item packet bytes from the released Java API. The comparisons are finite and real client traffic remains untested.

The packet API offers Java-style replacement templates for nonempty literal substring patterns, including `$0` and backslash escapes, with ten Java oracle cases. Regex patterns, nonzero capture groups and empty patterns remain unsupported; Rust replacement is bounded and transactional and does not reproduce every Java error or partial mutation. Real extensions remain untested.

`PacketField` and `append_fields` cover the eight Java `appendObject` types for EVA; a mixed vector matches Java bytes and cursor. Rust rejects non-Latin-1 strings and WEDGIE in this helper, and keeps earlier fields if a later append fails. A `fancy-regex` experiment differed from Java on zero-width iteration and default Unicode word classes; full regex replacement remains open.

EVA packets now offer explicit Java-style Latin-1 replacement encoding for short/long strings, replacement and `PacketField::StringJava`; strict APIs remain available. Selected Java vectors cover BMP and supplementary characters. Rust cannot represent unpaired UTF-16 surrogates; WEDGIE, all Unicode cases and real extensions remain unverified.

Java Latin-1 replacement encoding matches Rust for all 1,112,064 Unicode scalar values in chunked EVA short strings and at 65,535 bytes. At 65,536 bytes Java wraps the short length prefix; Rust rejects the malformed field. Unpaired Java UTF-16 surrogates and real extensions remain untested.

EVA UTF-16BE short and long strings now have typed append, read and offset-read operations, with strict or Java-like replacement decoding; short fields also support replacement. Selected malformed sequences, every single UTF-16 code unit and 10,000 deterministic byte strings match Java decoding. Arbitrary longer malformed sequences, unpaired-surrogate input, WEDGIE and real extensions remain unverified.

EVA string helpers also support UTF-16LE and BOM-sensitive UTF-16; an empty string in BOM mode has no BOM, and both byte orders are recognized on read. Selected vectors and 10,000 deterministic byte strings for each new mode match Java. This remains finite coverage; unpaired Java string inputs and real extensions remain unverified.

Java strings containing unpaired surrogates can now be supplied as UTF-16 units and encoded into EVA short/long fields or short replacements in Latin-1, UTF-8, UTF-16BE/LE or BOM-sensitive UTF-16. Selected cases and 4,096 deterministic unit strings match Java across the five encoders; real extensions and arbitrary malformed inputs remain unverified. Rust continues to reject oversized short fields that Java encodes with a wrapped length.

Selected Java UTF-16 replacement packets containing unpaired surrogates and long fields match for BE, LE and BOM-sensitive modes. Short-field overflow remains deliberately rejected where Java wraps the prefix. These are finite comparisons, not live extension validation.

Automatic Flash identification no longer trusts or passes preloaded metadata whose revision is absent or differs from the detected version. Rust attempts to fetch matching identifiers whether or not an extension host is active. Unversioned manually loaded metadata is therefore ignored in this mode. Controlled reconnect and extension-protocol tests cover the mismatch; real clients, network failures and UI behavior remain unverified.

The no-extension-host Flash metadata lookup is covered with a controlled provider for success, failure and forwarding. Real metadata-service failures and client sessions remain unverified.

Nitro rejects preloaded metadata labeled for another revision, including unversioned metadata, before registering safe IDs. Unity intentionally uses static metadata across revisions as Java does; incorrect Unity metadata can authorize incorrect IDs. Controlled Nitro and two-revision Unity fixtures cover these paths; real clients remain unverified. Nitro now fetches missing metadata without an extension host by default; `WebOptions::fetch_packet_info` disables the lookup for offline use.

Nitro metadata lookup is cancellable on peer close and limited to four in-flight workers. A controlled provider covers success and failure, while a full local proxy fixture checks stopping with a stalled provider. Workers already in flight can continue after cancellation; real metadata-service behavior and live clients remain unverified.

A controlled Nitro test cancels one blocked metadata lookup, starts a replacement connection and verifies that an extension protocol peer receives only the new database. This does not prove live hotel or real extension behavior.

A local HTTPS metadata fixture now exercises the actual JSON downloader for successful data, HTTP 503, malformed JSON, truncated and oversized responses, and cancellation during a stalled response, with a temporary CA trusted only by the test client. A controlled extension peer can initialize and forward a packet after each error. It does not validate the production metadata service, a real extension session or a live hotel.

Sulek caches refresh after five minutes and fall back to a valid matching cache on network or parse failure. Unlike Java, malformed downloaded JSON does not overwrite the last valid cache. Tests use controlled fetch results; production service and concurrent refresh behavior remain unverified.

A local HTTPS fixture now covers cache refresh, HTTP 503 fallback and a cancelled Nitro lookup whose worker finishes later and updates the cache. It verifies no stale Nitro session is published; concurrent cache writes and live service behavior remain open.

Within one process, an older concurrent cache refresh cannot overwrite a later-started refresh, including when the latter fails. The older caller can still receive its own result. Separate processes are not coordinated; the combined cancelled-session and concurrent HTTPS case remains to be tested.

A controlled Nitro session-replacement test now also checks that the shared cache retains the newer metadata after the cancelled older worker completes. It uses a simulated provider, not two HTTPS requests.

A local HTTPS race fixture combines cancellation, extension-session replacement and shared cache persistence; the newer metadata survives an older response. The fixture checks cleanup and does not establish live service or extension compatibility.

Origins discovery now prefers the latest Sulek release over a supplied version, like beta-29, and falls back to the supplied version if discovery fails. Rust also validates release strings; unsafe values trigger fallback. Tests use controlled responses; actual Origins clients and the production service remain unverified.

A local HTTPS fixture verifies Origins latest-release discovery, 503 fallback, metadata paths and cache persistence. Empty metadata now preserves the requested connection version, following Java PacketInfoManagerRemote. Actual Origins clients and the live service remain unverified.

The Origins relay now loads missing metadata before starting extensions, including without an extension host. Matching preloaded data is kept, mismatched data discarded, and the API supports offline lookup bypass. Controlled tests cover success, failure, extension initialization, stop and visible peer EOF; in-flight HTTP workers can continue and unread data can hide EOF. Full encrypted relay and real clients remain unverified.

A controlled full Origins relay fixture now covers metadata initialization, Bobba handshake, encrypted traffic in both directions, extension packet modification and reconnect. It uses simulated peers, not an official client or a real extension.

An extension compiled against the beta-29 Java API resolves a name and modifies WEDGIE packets in both directions over two controlled encrypted Origins relay sessions. The endpoints are fixtures; third-party extension workflows and a real client remain unverified.

The beta-29 Java extension fixture additionally injects named WEDGIE packets before encryption and in both directions after handshake, and blocks outgoing traffic across reconnects. Windows GNU desktop/web release compiled locally on equivalent production code. Real hotels and third-party game workflows remain unverified.

The released G-Presets fixture now attempts two loopback relay sessions and bidirectional interception; execution in the isolated CI job is pending. The test only compiled locally and does not represent a real game session.

The extended G-Presets loopback fixture failed in run 42636412302 when the first forwarded packet encountered EOF. The cause is not yet established; token-redacted diagnostics were added for the next run.

G-Presets rejected the original fixture host, causing the first disconnect. The revised fixture uses recognized host metadata and routes its HTTPS requests to a loopback proxy; CI validation is pending.

G-Presets 1.6.5 passed two controlled loopback relay sessions with bidirectional packets and reconnect in Actions run 42637109627. HTTPS is isolated through a non-serving loopback proxy. No live hotel, room, preset import or export was tested.

An asynchronous SOCKS5 primitive is tested with local proxies, including authentication, remote DNS and cancellation. Nitro HTTP and WebSocket routing are not yet connected to it; the desktop still rejects Nitro SOCKS.

Vendored Hudsucker now has an optional WebSocket/raw CONNECT dialer. Local tests cover success, failure without direct fallback, valid WSS and rejection of a wrong hostname. Nitro does not yet use it; HTTP connector and SOCKS integration remain open.

The web backend routes HTTP, HTTPS, WebSocket, WSS and raw CONNECT through optional SOCKS5, with local authenticated proxy and TLS fixtures. It refuses SOCKS when automatic metadata or the City helper is enabled; the desktop option and real SOCKS/hotel validation remain open.

Nitro metadata retrieval and its cache now use SOCKS when configured. Local authenticated HTTPS tests cover redirects, malformed and oversized responses and stale cache fallback. The City helper and desktop SOCKS option remain unavailable; real services remain unverified.

The opt-in City helper now uploads via configured SOCKS and rejects redirects and oversized responses; a local test confirms the upload is not attempted without opt-in. Desktop enablement and live hotel/service testing remain open.

Nitro desktop SOCKS settings now feed HTTP/TLS, WebSocket, raw CONNECT, metadata and the session-opted-in City helper. Local authenticated proxy fixtures and settings tests pass; actual SOCKS servers, hotels and interactive desktop controls remain unverified. Unity SOCKS remains unavailable.

Flash and Origins automatic and manual metadata requests now use configured SOCKS with the web feature. Minimal builds refuse those requests instead of falling back directly. Local authenticated fixtures cover discovery and metadata; real SOCKS/client sessions and desktop interaction remain unverified.

SOCKS metadata transport is shared with minimal builds: Flash and Origins retain authenticated SOCKS, proxy-side DNS, bounded HTTPS redirects/responses and no direct fallback. Loopback tests cover successful Origins discovery and metadata over authenticated SOCKS/TLS, rejected proxy connections and relay continuation. The minimal build now includes Tokio, Hyper and rustls dependencies; no real service, SOCKS server or game client was used. Unity SOCKS routing and live interoperability remain open.

Unity desktop now reuses the Nitro SOCKS settings and passes them to the asset proxy, following the pinned Java HttpProxyManager. A local authenticated SOCKS/TLS fixture modifies a Unity version asset and forwards a game WebSocket; a second fixture verifies proxy refusal does not fall back directly. The shared settings validation, seven SOCKS/web integration tests, desktop build and Clippy pass. Better Design guidance was applied, but the desktop UI has not been visually or interactively checked; real Unity clients, hotels and SOCKS servers remain unverified.

Packet substring replacement now supports one nonempty literal capture group, preserving Java’s preliminary raw-pattern containment check and `$0`/`$1` replacement semantics. Eight cases, including ambiguous references, invalid replacements, a missing candidate and Latin-1, were compared with the released beta-29 Java API JAR; separate tests cover bounded growth and transactional errors. General Java regex, nested or multiple capture groups and live extensions remain unverified.

Substring replacement also supports multiple nonempty literal capture groups with surrounding literal text. Eight further beta-29 Java API oracle cases cover group numbering, escaped replacements, raw-pattern containment, no regex match and invalid replacement timing. The implementation remains bounded and transactional on errors; nested/empty groups and general regex remain unsupported. Nineteen mutation tests, both Clippy configurations and desktop/web build pass locally.

Fixed-pattern substring replacement now handles nested or empty capture groups and escaped regex metacharacters when the overall match is nonempty. Six beta-29 Java API oracle cases cover numbering, empty groups, escaped dot/parenthesis and delayed replacement validation. Nineteen mutation tests, both Clippy configurations and desktop/web build pass locally. Empty-matching patterns, character classes, quantifiers, alternation and general Java regex remain unsupported.

Empty capture-group patterns now support zero-width matches at each Latin-1 character boundary. Six cases were compared with the released beta-29 Java API, including nested empty groups, invalid references and no eligible field; a separate large-packet test verifies transactional size limits. Twenty mutation tests, both Clippy configurations and desktop/web build pass locally. Full Java regex semantics remain incomplete.

Fixed-pattern substring replacement now recognizes Java `\Q...\E` quoting and named capture groups/references. Eleven cases were compared with the released beta-29 API, including empty or unterminated quoting, nested named captures and invalid names; focused tests cover transactional failures. Mutation tests, both Clippy configurations and desktop/web build pass. Dynamic regex constructs and real extension use remain unverified.

Fixed-length Java regex replacement now supports the dot wildcard with per-match numbered or named captures. Five targeted cases and a 120-packet corpus were compared against the released beta-29 Java API, including Latin-1 and Java line terminators. A comparison budget and field-size limits bound work, and expansion errors leave the packet unchanged. Twenty-two mutation tests, both Clippy configurations and desktop/web build pass locally; quantifiers, character classes, alternation and real extension use remain open.

The bounded fixed-length matcher now supports selected Java character classes, Latin-1 ranges, negation and selected escaped metacharacters. Seven targeted cases and 120 generated packets match the released beta-29 Java API. Unsupported class intersections and ambiguous constructs are rejected; quantifiers, predefined classes and full regex remain open. Twenty-three mutation tests, both Clippy configurations and desktop/web build pass locally.

Java predefined regex classes `\d`, `\w`, `\s` and their complements now work outside bracket expressions with fixed-length captures. A 120-packet differential corpus against the beta-29 Java API covers ASCII, Latin-1 and control characters. Twenty-three mutation tests, both Clippy configurations and desktop/web build pass; predefined classes inside brackets, Unicode flags and full regex semantics remain open.

Predefined Java regex classes and complements now work inside supported bracket unions and negations. Six targeted cases plus 120 generated packets were compared with the released beta-29 Java API. Java accepts a predefined class followed by a literal hyphen where the reverse range is invalid; the parser follows the tested behavior. Twenty-three mutation tests, both Clippy configurations and desktop/web build pass; class intersection and general regex remain incomplete.

Java regex control escapes and two-digit hexadecimal/four-digit Unicode escapes within Latin-1 are supported inside and outside bracket classes. A 140-packet corpus matches the released beta-29 Java API, and invalid or outside-Latin-1 escapes fail transactionally. Twenty-four mutation tests, both Clippy configurations and desktop/web build pass locally. Other escape forms, quantifiers and full Java regex remain incomplete.

The bounded matcher supports one greedy or reluctant `?` quantifier on a single atom, including dynamic captures and zero-width progress. Seven targeted cases and 140 generated packets match the released beta-29 Java API. Twenty-five mutation tests, both Clippy configurations and desktop/web build pass. Multiple quantifiers, quantified groups, possessive quantifiers and general Java regex remain unsupported.

Multiple greedy and reluctant optional atoms now use iterative backtracking with a shared work budget and bounded memory. A 160-packet corpus matches the released beta-29 Java API, including fallback from greedy choices, nested captures and zero-width matches; a focused unit test checks exhaustion of the work budget. Twenty-five mutation tests, both Clippy configurations and desktop/web build pass. Quantified groups, possessive and repetition quantifiers, and general regex remain open.

The iterative regex matcher now supports non-overlapping optional capture groups, including empty groups, nested captures and greedy/reluctant backtracking. Seven targeted cases and 140 generated packets match the released beta-29 Java API. The shared work bound remains tested; overlapping optional quantifiers, repetition/possessive quantifiers and full Java regex remain unsupported. Twenty-five mutation tests, both Clippy configurations and desktop/web build pass.

Nested and overlapping optional regex quantifiers now compile to an iterative bounded instruction program that restores capture positions on backtracking. A 160-packet corpus matches the released beta-29 Java API, including nested empty and unmatched captures. The shared work-budget test, 25 mutation tests, both Clippy configurations and desktop/web build pass. Repetition, possessive quantifiers and full Java regex remain unsupported.

Greedy and reluctant `*`/`+` on individual regex atoms now use bounded iterative execution and per-match captures. Eight targeted cases and 160 generated packets match the released beta-29 Java API; tests cover growth limits and a 40,000-byte reluctant match. Twenty-seven mutation tests, the work-budget test, both Clippy configurations and desktop/web build pass. Quantified groups, bounded repetitions, possessive quantifiers and full Java regex remain open.

Java bounded repetition `{m}`, `{m,n}` and `{m,}` on individual regex atoms now supports greedy and reluctant matching under the shared work budget. Eight targeted cases and 160 generated packets match the released beta-29 Java API, including zero-width cases and invalid bounds. Twenty-eight mutation tests, the budget test, both Clippy configurations and desktop/web build pass. Repetition of groups, possessive quantifiers and full Java regex remain open.

A single nonempty fixed-length capture group can now be repeated with Java greedy/reluctant `*`, `+` and bounded counts. Three targeted cases and 150 generated packets match the released beta-29 API, including last-iteration capture values. Tests cover rejected nested/combined quantifiers and a large field; 29 mutation tests, the work-budget test, both Clippy configurations and desktop/web build pass. Repeated nested groups and combinations with other quantifiers remain unsupported.

Fixed-length repeated Java regex groups may now contain nested captures; 150 generated packets match the released beta-29 API, with captures from the last iteration. Java also confirms `((a)?b)*` on `abb` retains inner capture `a` from the earlier iteration; Rust still rejects variable-length nested repetition transactionally. Twenty-nine mutation tests, the budget test, both Clippy configurations and desktop/web build pass locally.

A bounded iterative capture trail now handles repeated groups with one optional nested capture and a nonempty mandatory part, such as `((a)?b)*`. Two targeted cases and 200 generated packets match the released beta-29 Java API, including retained captures, greedy/reluctant choices and backtracking. State and work limits are tested; 29 mutation tests, both Clippy configurations and desktop/web build pass. Multiple nested optionals, nullable repeated bodies, bounded group repetitions with internal options and general Java regex remain open.

Repeated Java regex groups with multiple independent optional captures now use the bounded capture trail, preserving each prior value across iterations. A 200-packet corpus matches the released beta-29 Java API; unit tests verify independent capture retention, work/state limits and transactional rejection of nullable or more deeply nested bodies. Twenty-nine mutation tests, both Clippy configurations and desktop/web build pass. General nested repetition and nullable repeated bodies remain unsupported.

Nullable repeated Java regex bodies with independent optional captures now stop after a zero-width iteration while retaining prior captures. A 180-packet corpus matches the released beta-29 Java API; a focused test confirms `((a)?(b)?)*` on `ab` yields captures empty, `a`, `b` and terminates. The complete minimal workspace test suite passes with environment-dependent tests ignored; both Clippy configurations and desktop/web build pass. Bounded repeated groups with internal options and general Java regex remain open. No active Habbo client was detected for live validation.

Bounded `{m}`, `{m,n}` and `{m,}` repetitions now work for the supported variable-length Java regex groups with optional captures, including nullable bodies and retained captures. Seven targeted cases and 140 generated packets match the released beta-29 API; a state-limit test covers an extreme minimum. Twenty-nine mutation tests, both Clippy configurations and desktop/web build pass. Repeated atoms within those repeated groups, deeper capture nesting and general Java regex remain open.

The bounded capture-restoring VM now handles repeated atoms inside its supported repeated Java regex groups, including `*`, `+`, bounded counts, optional captures and zero-width iterations. A 180-packet corpus matches the released beta-29 API; five budget/state tests, 29 mutation tests, both Clippy configurations and desktop/web build pass. Optional atoms in repeated groups, deeper capture nesting and general Java regex remain open.

Optional atoms inside supported repeated Java regex groups now use the bounded capture VM, including nullable loops such as `(a?)*`. A 180-packet corpus matches the released beta-29 API; a focused test verifies retained nested capture for `((a)?b?)*` on `abb`. Six state/budget tests, 29 mutation tests, both Clippy configurations and desktop/web build pass. Optional atoms inside nonoptional nested captures and deeper group nesting remain open.

Repeated Java regex groups now support optional atoms inside direct nonoptional or optional nested captures, such as `((a?)b)*`. A 210-packet corpus matches the released beta-29 API; a focused test distinguishes a capture overwritten with empty from a skipped capture retaining its previous value. Seven budget/state tests, 29 mutation tests, both Clippy configurations and desktop/web build pass. More deeply nested captures and general Java regex remain open.

Repeated Java regex groups now support deeper nested capture events with optional descendants and bounded capture restoration. A 180-packet corpus and a 99-group depth case match the released beta-29 API. Seven budget/state tests, 29 mutation tests, both Clippy configurations and desktop/web build pass. Multiple repeated group quantifiers and general Java regex remain open.

Java regex anchors `^`, `$`, `\A`, `\Z` and `\z` are supported as bounded zero-width matches, including Java’s final CRLF and Latin-1 line terminators. Ten targeted cases and 144 generated packets match the released beta-29 Java API. Eight budget/state tests, 29 mutation tests, both Clippy configurations and desktop/web build pass. Anchors inside repeated groups and full Java regex remain unsupported.

Actions run 42721796496 failed its Windows G-Python job when two concurrent Jupyter kernels timed out after 20 seconds; the next run 42722422100 passed all eight jobs. The G-Python CI tests now run serially to reduce competition with isolated environment installs. All five serial G-Python tests pass locally on Windows, including real G-Python kernel injection and offscreen QtConsole. The exact runner cause remains unproven; the next Actions run must verify the mitigation.

Java 21 regex word boundaries `\b` and `\B` are supported as bounded zero-width matches over Latin-1, using the Java 21 ASCII word definition. A 175-packet corpus and empty/accented-character tests match the released beta-29 API. Nine budget/state tests, 29 mutation tests, both Clippy configurations and desktop/web build pass; Unicode regex flags and general Java regex remain open.

The Java 21 global `(?i)` regex flag is supported for ASCII case-insensitive literals, character classes and dynamic captures; non-ASCII Latin-1 is unchanged, as in Java without Unicode flags. A 175-packet corpus matches the released beta-29 API, including negated classes and quoted/escaped literals. Nine budget/state tests, 29 mutation tests, both Clippy configurations and desktop/web build pass. Embedded/Unicode flags and general Java regex remain open. Serialized G-Python Actions jobs passed on Windows and Linux in run 42723118432.

Java regex replacement now accepts patterns without capture groups, including empty patterns and `$0`; invalid references and size overflow remain transactional. Ten cases match the released beta-29 Java API, and a focused large-field test covers zero-width growth. Nine budget/state tests, 30 mutation tests, both Clippy configurations and desktop/web build pass. General regex syntax and live-extension compatibility remain open.

Java global dotall `(?s)` and leading combinations with `(?i)` now make dot match Latin-1 line terminators while preserving captures and bounded repetition. A 175-packet corpus matches the released beta-29 API; nine budget/state tests, 30 mutation tests, both Clippy configurations and desktop/web build pass. Other embedded flags and full Java regex remain open.

Java global multiline `(?m)` and leading combinations with `(?i)`/`(?s)` now distinguish line anchors from strict `\A`, `\Z` and `\z`, including empty input and CRLF. A 200-packet corpus matches the released beta-29 API; ten budget/state tests, 30 mutation tests, both Clippy configurations and desktop/web build pass. Anchors within repeated groups, embedded flags and general Java regex remain open.

Java global `(?u)` combined with `(?i)` now matches Latin-1 case pairs in literals and positive/negated classes; `(?u)` alone leaves case sensitive matching unchanged. All 65,536 Latin-1 pairs match Java 21 and 210 packet mutations match the released beta-29 API, including captures and flag combinations. The pair oracle also runs in CI. Thirty mutation tests, ten budget tests, both Clippy configurations and the desktop/web debug build pass locally. Full Java regex, embedded flags and live clients/extensions remain unverified.

Java global `(?U)` now enables Unicode predefined digit, word and whitespace classes, their complements, and word boundaries over Latin-1, and implies Unicode case folding when combined with `(?i)`. Java 21 comparisons cover all 256 bytes for each class and boundary, plus 200 packet mutations against the beta-29 API; both oracle checks run in CI. Thirty mutation tests, ten budget tests, both Clippy configurations and desktop/web debug compilation pass locally. Full Java regex and live clients/extensions remain unverified.

Unquantified Java non-capturing groups `(?:...)` now preserve nested captures and numbering, including empty groups. A 180-packet corpus matches the released beta-29 API. Quantifiers on non-capturing groups and unbalanced patterns are rejected transactionally; other regex semantics remain incomplete. Thirty-one mutation tests, ten budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Java non-capturing groups support bounded or unbounded greedy/reluctant repetition when the pattern has no captures and the repeated body consists of nonempty fixed-width atoms. A 140-packet corpus matches the released beta-29 API. Optional groups, repeated bodies containing quantifiers or assertions, and repeated non-capturing groups with captures remain rejected. Thirty-one mutation tests, ten budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Optional `(?:...)?` and reluctant `(?:...)??` groups now work in patterns without capture groups, including nesting and empty groups. A 140-packet corpus matches the released beta-29 API. Patterns combining optional non-capturing groups and captures are still rejected; full Java regex remains incomplete. Thirty-one mutation tests, ten budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Optional non-capturing groups can now contain or coexist with capture groups, including nested, named and empty groups. A 200-packet differential corpus checks Java beta-29 replacement bytes and cursor, including multiple capture references and greedy/reluctant forms. Thirty-one mutation tests, ten budget tests, both Clippy configurations and desktop/web debug compilation pass locally. Repeated non-capturing groups containing captures remain unsupported.

Greedy, non-capturing group repetitions with at least one iteration can now contain fixed-width captures; a 200-packet Java beta-29 corpus covers nested and named captures and suffix-driven backtracking. Non-greedy and zero-minimum repetitions with captures, capture ancestors, optional/repeated atoms within the body, and other complex structures remain rejected. Java retains a capture from a failed search attempt in a non-greedy zero-minimum case, while Rust clears it, so that form remains explicitly blocked. Thirty-one mutation tests, ten budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Java scoped inline regex flags for i, s, m, u and U, including disabling flags and nested restoration, now apply to the enclosed group. A 400-packet corpus matches the beta-29 Java API across captures, Unicode classes, anchors and repeat/optional forms; Java 21 confirms disabling U also disables Unicode case folding in that scope. Thirty-one mutation tests, eleven budget tests, both Clippy configurations and the desktop/web debug build pass locally. Unscoped flag changes inside a pattern, other flags and full regex semantics remain incomplete.

Java unscoped embedded regex flags i, s, m, u and U can now change within a pattern and restore their enclosing group state on exit. A 300-packet corpus matches the beta-29 Java API for nested changes, negation, Unicode case and line handling. Thirty-one mutation tests, eleven budget tests, both Clippy configurations and the desktop/web debug build pass locally. Unsupported Java flags and complete regex semantics remain open.

Java UNIX_LINES (?d) now applies to dot, multiline anchors, dollar and \Z, including scoped and embedded flag changes. Java 21 checks and 240 beta-29 packet comparisons cover LF, CR, CRLF, NEL, empty input and combinations with dotall/multiline. Thirty-one mutation tests, twelve budget tests, both Clippy configurations and desktop/web debug compilation pass locally. Complete Java regex and live client compatibility remain open.

Read-only Windows diagnostics were run against an already connected official AIR client on 2026-11-10: process enumeration and TCP owner matched the client, and an optimized scan read about 639 MB, completed and found one shuffled-table candidate. A debug scan hit its five-second limit after about 474 MB and found one candidate. No process memory or candidate values were logged. This does not prove that the candidate is an RC4 key, successful decryption, relay attachment or extension compatibility. An opt-in Windows test reproduces the process/socket/scan diagnostics without changing routing or the client.

Java COMMENTS (?x) mode now skips ASCII whitespace and # comments during regex parsing, including in classes, with scoped/embedded flag restoration, UNIX_LINES-aware comment endings, and literal escaped/quoted characters. A 380-packet beta-29 Java corpus covers these cases. The first character after a counted-closure brace remains unskipped as in Java; invalid examples are rejected transactionally. Thirty-two mutation tests, twelve budget tests, both Clippy configurations and desktop/web debug compilation pass locally. Full Java regex semantics remain incomplete.

Top-level Java regex alternation without captures now evaluates branches in source order, including empty alternatives, flags, anchors, optional atoms and supported repetitions. A 240-packet corpus matches the beta-29 API; nested alternatives and captures remain explicitly rejected. Thirty-three mutation tests, twelve budget tests, both Clippy configurations and desktop/web debug compilation pass locally. The full workspace suite and Windows GNU desktop/web release build passed for commit 68c5425; this does not establish live relay compatibility.

Top-level Java regex alternation now supports captures that end with their branch, including nested and named captures. A 200-packet beta-29 corpus checks branch order, unset groups, multiple references and named replacements. At that stage, branches with a fallible suffix after a capture, repeated capturing groups and nested alternation were conservatively rejected pending Java comparison. Thirty-three mutation tests, twelve budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Fixed-width reluctant non-capturing repetitions now retain captures from failed search starts like Java GroupCurly, and reset them between successful finds. The previously failing (?:(a)b)*?b case and 240 varied beta-29 packet comparisons pass, including nested/named/empty captures and bounded repetition. Greedy zero-minimum cases, nested repetition, alternatives with fallible capture suffixes and general capture restoration remain unsupported. Thirty-three mutation tests, thirteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Fixed-width greedy non-capturing repetitions now retain captures from the furthest explored iteration when backtracking, including zero-minimum repetition. A Java 21 probe exposed an earlier mismatch with different captures per iteration; a 240-packet beta-29 differential corpus and a focused regression test now cover it. Nested repetitions and alternatives with fallible capture suffixes remain unsupported. Thirty-three mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Top-level alternation now supports ordinary captures followed by a fallible suffix. Java 21 GroupTail restores ordinary captures when a branch fails; unlike GroupCurly nested captures, (a)c|b does not retain a failed capture. A 250-packet beta-29 corpus checks this behavior, nested and named captures, optional atoms and backtracking. Repeated capturing groups and nested alternation remain unsupported. Thirty-three mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Nested Java regex alternation without captures now uses a bounded branch-aware matcher, preserving ordered choices and backtracking through surrounding atom quantifiers. A 240-packet beta-29 corpus covers empty/nested branches, scoped flags and optional groups. Captures and repeated groups containing nested alternatives remain rejected; group nesting is capped at 128 for this matcher. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Nested Java regex alternation now supports ordinary capture groups with bounded GroupHead/GroupTail-style rollback, including named, empty and optional captures. A 240-packet beta-29 corpus checks branch choice and multiple replacement references. Quantified groups containing alternatives remain explicitly unsupported. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

A single quantified nested Java alternation group now supports greedy/reluctant and bounded repetitions with capture retention and zero-width-loop protection. The beta-29 oracle passes 280 packet cases plus 120 cases with nullable branches; internal progress captures cannot be referenced by replacement strings. Multiple repeated groups and some capturing-ancestor structures remain explicitly unsupported. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Multiple sequential quantified alternative groups and capturing ancestors now use separate bounded loop executions. A 250-packet beta-29 corpus covers greedy/reluctant combinations, nullable branches, named captures and bounded counts. Nested repeated groups remain rejected pending independent loop counters. The alternation matcher caps group nesting and repeated groups at 128. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

The bounded regex VM now uses persistent per-loop counters so nested repetitions restore their enclosing loop state during backtracking. A 200-packet beta-29 corpus covers nested greedy/reluctant and bounded alternative groups, named captures and nullable inner loops; the prior repetition budget tests still pass. The VM retains its 128-group and 262144-state bounds. Multiple repeated groups in patterns without nested alternation and other Java regex constructs remain incomplete. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Multiple fixed-width repeated groups now work even without nested alternation, including capturing ancestors and ordered top-level branches. A 250-packet beta-29 corpus covers greedy/reluctant and bounded cases, named captures and rollback. Repeated bodies containing variable-width constructs or nested captures remain conservatively rejected in this path pending GroupCurly comparison. The VM rejects more than 128 repeated groups before expensive validation. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Variable-width repeated Java groups without captures inside the repeated body now use the bounded loop VM, including nullable inner atoms and capturing ancestors. A 250-packet beta-29 corpus includes standalone and multiple greedy/reluctant repetitions. Repeated bodies containing captures still need GroupCurly-specific validation. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Variable-width repeated Java groups can now capture their own match in the bounded multi-group VM. A 250-packet beta-29 corpus covers greedy/reluctant repeats, nullable bodies, named captures, capturing ancestors and changing captures during backtracking. An attempted generic implementation of captures nested inside a repeated noncapturing group diverged from Java GroupCurly and remains explicitly rejected. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

For fixed-width deterministic repeated groups, the bounded VM now preserves nested captures using Java GroupCurly-style state across failed searches and backtracking, even alongside other repeated groups or capturing ancestors. A 250-packet beta-29 corpus covers varying captured bytes, greedy/reluctant bounds, named captures and branch changes; previous divergent cases now match. Variable-width bodies containing nested captures remain explicitly rejected. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Repeated Java groups with non-deterministic variable-width bodies can now contain nested captures; the bounded VM uses Loop-style rollback for optional captures and variable atom repetitions. A 250-packet beta-29 corpus matches named captures, nullable bodies, reluctant backtracking and capturing ancestors. Fixed-count inner repetitions and nested repeated groups in this GroupCurly-sensitive path remain explicitly rejected. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Fixed-count inner atom repetitions in deterministic GroupCurly-style groups now preserve nested captures during backtracking. A 250-packet beta-29 corpus covers zero/exact counts, named captures, reluctant repeats and optional ancestors. Nested repeated groups in this deterministic capture path remain conservatively rejected. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Nested repeated groups with captures now distinguish deterministic fixed-count bodies from non-deterministic bodies when selecting Java GroupCurly-style retention or Loop rollback. A 250-packet beta-29 corpus covers nested greedy/reluctant loops, exact counts, nullable bodies, named captures and capturing ancestors. Other regex constructs, performance limits and live relay behavior remain incomplete. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Java numbered and named regex backreferences now use capture-aware bounded matching, including unmatched versus empty captures, Latin-1 case folding, optional and repeated references, and ordered alternatives. A 360-packet beta-29 oracle corpus passes. At that stage, open-group references and combinations with repeated groups were unsupported; subsequent work below addresses selected cases. Thirty-five mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Java backreferences can now be combined with repeated groups, including references inside deterministic bodies and capture retention across backtracking. A 240-packet beta-29 corpus covers named/numbered references, repeated references and changing captures between iterations. At that stage, references to a currently open group remained unsupported; subsequent work addresses selected cases; full Java regex behavior is not established. Thirty-five mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.
