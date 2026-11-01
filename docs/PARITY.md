# Compatibility with 1.5.4-beta-29

Status describes source implementation and finite tests, not successful production use. No official Habbo client or G-Presets session has been tested with this port.

| Area | Rust status | Remaining work |
|---|---|---|
| EVA_WIRE | Framing, primitive fields, Latin-1, HPacket/HMessage serialization | Full upstream mutation and structure-prediction API |
| WEDGIE | Incoming/outgoing packet formats, fixed B64, VL64 and format-aware expressions | Wider parser corpus and official client regression |
| Packet expressions | Typed/numeric/named expressions, mixed raw display notation, lossless hex | Structure prediction and all editor conveniences |
| Explicit TCP relay | Nonblocking bidirectional relay, bounded output, injection, ordered block/replace, reconnect, scoped hosts attachment | Raw-IP and web providers |
| RC4 | State import/export/rewind, manual keys and Windows negotiated discovery, bounded read-only heap scan, ambiguity rejection | Real AIR client regression; broaden memory-layout coverage |
| Origins crypto | DH substitution, HKDF-SHA256, ChaCha20 channels, encrypted framing and hosts attachment | Official client end-to-end live validation |
| Network extensions | Loopback host, one-use launch tokens, approval, flags, interception, injection, click, console, connection details, language changes | Full extension corpus, store and lifecycle parity |
| Existing Java API | Actual beta-29 Java extension fixture passes auth, name lookup, bidirectional mutation/blocking/injection | G-Presets and other existing extension binaries untested |
| Python/Node extensions | External runtime launcher and common IPC | G-Python live console, package installation and live regression |
| Packet identifiers | Direction-aware database, beta-29 IPC, Sulek HTTPS lookup/cache, detected Flash revision, Unity JSON and TSV import | Unity client integration and broader remote-provider coverage |
| SOCKS5 | CONNECT, remote DNS, optional RFC1929 credentials | Wider interoperability tests |
| Rules/scheduler | Saved ordered rules and finite schedule templates | Every original scheduler and rule-editor option |
| Logging | Cached search/display strings, virtualized rows, count/byte budget, export | Original highlighting and complete filtering options |
| Settings | Atomic save/load, unknown-field preservation, original cache import, notepad | Migration of every original setting |
| UI/theme/languages | Rust eframe desktop, light/dark theme, nine original resource files, localized tabs | Exact UI/layout, all controls translated, shortcuts, tray |
| Flash | Negotiation, Windows client memory discovery, socket owner detection, hosts attachment, independent counters | Official client validation, raw-IP attachment and non-Windows discovery |
| Origins attachment | Scoped hosts routing to the original port | Official client validation and non-Windows privileged helpers |
| Nitro | Not implemented | HTTP/TLS/WebSocket proxy, assets, certificates, system proxy cleanup |
| Unity connection | Not implemented | WebSocket communicator, WASM patching, local file server |
| Hotel detection | Pinned Flash/Origins hotel lists, custom domain, detected Flash revision/identifier | Nitro/Unity discovery and hotel-specific adapters |
| Room/catalog/inventory/entity API | Existing Java extensions retain their original Java parsers | Native Rust parser API parity |
| Extension store/updater | Not implemented | Metadata, downloads, validation and lifecycle |
| Windows packaging | Tested development EXE and CLI via Actions/prereleases | Installer, signing and release QA |
| Linux/macOS | Core tests on Linux; Windows desktop compiled | Desktop distribution and platform proxy helpers |
| beta-29 integration fixes | Not ported completely | leet/habblet, Chrome TLS fingerprint, privileged macOS helper, tray cropping |
| Performance gain | Unmeasured | Equivalent end-to-end workload benchmark against Java |

## Completion criteria

A complete port requires the remaining functionality above, tested through real supported Flash/Origins/Unity/Nitro connections, existing Java extensions including G-Presets, reconnect, encrypted traffic, certificate/proxy cleanup, settings migration and the complete UI workflow. Passing a finite protocol oracle or compiling an executable does not establish whole-application parity.
