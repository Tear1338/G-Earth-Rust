# Compatibility with 1.5.4-beta-29

Status describes source implementation and finite tests, not successful production use. No official Habbo client or G-Presets session has been tested with this port.

| Area | Rust status | Remaining work |
|---|---|---|
| EVA_WIRE | Framing, primitive fields, Latin-1, HPacket/HMessage serialization | Full upstream mutation and structure-prediction API |
| WEDGIE | Incoming/outgoing packet formats, fixed B64, VL64 and format-aware expressions | Wider parser corpus and official client regression |
| Packet expressions | Typed/numeric/named expressions, mixed raw display notation, lossless hex | Structure prediction and all editor conveniences |
| Explicit TCP relay | Nonblocking bidirectional relay, bounded output, injection, ordered block/replace, reconnect, scoped hosts attachment, Raw-IP preconnected upstreams | Real client/firewall regression |
| RC4 | State import/export/rewind, manual keys and Windows negotiated discovery, bounded read-only heap scan, ambiguity rejection | Real AIR client regression; broaden memory-layout coverage |
| Origins crypto | DH substitution, HKDF-SHA256, ChaCha20 channels, encrypted framing and hosts attachment | Official client end-to-end live validation |
| Network extensions | Loopback host, one-use launch tokens, approval, flags, interception, injection, click, console, connection details, language changes | Full extension corpus, store and lifecycle parity |
| Existing Java API | Actual beta-29 Java extension fixture passes auth, name lookup, bidirectional mutation/blocking/injection | G-Presets and other existing extension binaries untested |
| Python/Node extensions | External runtimes, authenticated IPC, native G-Python/Jupyter console controls and explicit package installation/repair; real G-Python kernel fixtures on Windows/Linux | QtConsole visual workflow and real sessions |
| Packet identifiers | Direction-aware database, beta-29 IPC, Sulek HTTPS lookup/cache, detected Flash revision, Unity JSON and TSV import | Unity client integration and broader remote-provider coverage |
| SOCKS5 | CONNECT, remote DNS, optional RFC1929 credentials | Wider interoperability tests |
| Rules/scheduler | Saved ordered rules and finite schedule templates | Every original scheduler and rule-editor option |
| Logging | Cached search/display strings, virtualized rows, count/byte budget, export | Original highlighting and complete filtering options |
| Settings | Atomic save/load, unknown-field preservation, original cache import, notepad | Migration of every original setting |
| UI/theme/languages | Rust eframe desktop, light/dark theme, nine original resource files, localized tabs | Exact UI/layout, all controls translated, shortcuts, tray |
| Flash | Negotiation, Windows client memory discovery, socket owner detection, hosts attachment, Raw-IP mapping and independent counters | Official client/firewall validation, Windows Raw-IP multi-instance lease and non-Windows discovery |
| Origins attachment | Scoped hosts routing to the original port | Official client validation and non-Windows privileged helpers |
| Nitro | HTTP/TLS/WebSocket backend, beta-29 hotel matching/config, RC4/TripleDES/GCM/CTR adapters, assets, shared rules/injection/extensions, explicit current-user certificates and journaled Windows proxy cleanup | Real hotel sessions, Chrome TLS fingerprint, SOCKS upstream, non-Windows OS helpers |
| Unity connection | Authenticated TLS communicator, exact asset routes, gzip and cache handling, validated WASM hooks, browser reinjection and Java extensions | Official client revisions, G-Presets and non-Windows system helpers |
| Hotel detection | Flash/Origins lists, custom domain/revision, Nitro hello fallback, dynamic nitro.json, beta-29 hotel URL/prefixes and adapters | Live hotel regression and Unity discovery |
| Room/catalog/inventory/entity API | Existing Java extensions retain their original Java parsers | Native Rust parser API parity |
| Extension store/updater | Original catalogue, native search/filter/order, bounded archive install, separate-version updates, authenticated launch and managed uninstall | Full Maven version edge cases, thumbnails/readme presentation and broader package corpus |
| Windows packaging | Tested development EXE and CLI via Actions/prereleases | Installer, signing and release QA |
| Linux/macOS | Core tests on Linux; Windows desktop compiled | Desktop distribution and platform proxy helpers |
| beta-29 integration fixes | leet/habblet prefix matching and dynamic nitro.json ported | Chrome TLS fingerprint, privileged macOS helper, tray cropping |
| Performance gain | Unmeasured | Equivalent end-to-end workload benchmark against Java |

## Completion criteria

A complete port requires the remaining functionality above, tested through real supported Flash/Origins/Unity/Nitro connections, existing Java extensions including G-Presets, reconnect, encrypted traffic, certificate/proxy cleanup, settings migration and the complete UI workflow. Passing a finite protocol oracle or compiling an executable does not establish whole-application parity.
