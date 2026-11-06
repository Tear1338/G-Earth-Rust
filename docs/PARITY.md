# Compatibility with 1.5.4-beta-29

Status describes source implementation and finite tests, not successful production use. No official Habbo client or G-Presets game session has been tested with this port.

| Area | Rust status | Remaining work |
|---|---|---|
| EVA_WIRE | Framing, primitive fields, Latin-1 and explicit UTF-8 strings, raw short and long fields for custom encodings, HPacket/HMessage serialization, typed mutations and bounded literal substring replacement with Java comparisons | Full Java regex substring semantics, remaining mutation helpers, other charsets and broader compatibility corpus |
| WEDGIE | Incoming/outgoing packet formats, fixed B64, VL64 and format-aware expressions | Wider parser corpus and official client regression |
| Packet expressions | Typed/numeric/named expressions, mixed raw display notation, bounded structure prediction, nested structures and Java comparisons | Broader prediction and editor corpus; metadata and client regression |
| Injection and tools | Multi-packet input with pre-validation, separate destination buttons, ordered queueing and partial-error reporting, bounded immediately persisted history, EVA/WEDGIE expression conversion, integer and unsigned-short encoding | UI interaction, full editor parity and real connection validation |
| Explicit TCP relay | Nonblocking bidirectional relay, bounded output, injection, ordered block/replace, reconnect, scoped hosts attachment, Raw-IP preconnected upstreams | Real client/firewall regression |
| RC4 | State import/export/rewind, manual keys and Windows negotiated discovery, bounded read-only heap scan, ambiguity rejection | Real AIR client regression; broaden memory-layout coverage |
| Origins crypto | DH substitution, HKDF-SHA256, ChaCha20 channels, encrypted framing and hosts attachment | Official client end-to-end live validation |
| Network extensions | Loopback host, one-use launch tokens, approval, flags, interception, injection, click, console, connection details, language changes | Full extension corpus, store and lifecycle parity |
| Existing Java API | Actual beta-29 Java extension fixture passes auth, name lookup, bidirectional mutation/blocking/injection; released G-Presets 1.6.5 authenticates and returns fixture packets in both directions | Real G-Presets game workflows and other existing extension binaries untested |
| Python/Node extensions | External runtimes, authenticated IPC, native G-Python/Jupyter console controls and explicit package installation/repair; real G-Python kernel fixtures on Windows/Linux | QtConsole visual workflow and real sessions |
| Packet identifiers | Direction-aware indexed database, beta-29 IPC, Sulek HTTPS lookup/cache, detected Flash revision, Unity JSON and TSV import | Unity client integration and broader remote-provider coverage |
| SOCKS5 | CONNECT, remote DNS, optional RFC1929 credentials | Wider interoperability tests |
| Rules/scheduler | Editable and reorderable saved rules, editable active jobs and finite or indefinite schedule templates, beta-29 `.sched` import/export, clock-aligned offsets, per-job pause/resume and reconnect retention, optional Windows global shortcuts | Non-Windows global shortcuts, interactive shortcut validation, automatic restoration after app restart, original catch-up behavior and remaining rule-editor options |
| Logging | Cached search/display strings and metadata search, virtualized rows, bounded packet size, names/hashes/IDs, replaced indicator, structure prediction, separators, anti-spam, legacy/raw-hex and bounded inline hexdump views, timestamps, auto-scroll, filtered export sharing display formatting | Original highlighting and exact inline hex layout, WEDGIE prediction, remaining filtering/window options, exact original export formatting and visual validation |
| Settings | Atomic save/load, unknown-field preservation, original cache import, notepad | Migration of every original setting |
| UI/theme/languages | Rust eframe desktop, light/dark theme, nine original resource files, localized tabs | Exact UI/layout, all controls translated, shortcuts, tray |
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
