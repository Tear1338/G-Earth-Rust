# Compatibility with 1.5.4-beta-29

Status describes source implementation, not successful production use. CI results are separate evidence. No official Habbo client has been tested with this port.

| Area | Rust status | Remaining work |
|---|---|---|
| EVA_WIRE packet framing | Implemented | More malformed-input and differential coverage |
| Primitive fields and ISO-8859-1 strings | Implemented | Full HPacket mutation API and named placeholders |
| HPacket/HMessage serialization | Implemented | Broader extension corpus tests |
| Packet expressions | Numeric subset | Named headers, upstream display syntax and structure prediction |
| RC4 | Library implementation | Key discovery, negotiated state and per-direction client integration |
| Shockwave B64/VL64 integers | Library implementation | WEDGIE incoming/outgoing packet formats and connection support |
| Explicit plaintext TCP relay | Implemented | Encrypted session providers and SOCKS integration |
| Logging, bounded display and export | Implemented | Original highlighting, search options and extension logger |
| Inject/block/replace | Core implemented | Full original rule editor, expressions, packet name database |
| Scheduler | Basic implementation | Save/load, all original scheduling options and disconnect policy |
| Network extension protocol | EVA_WIRE codec implemented | TCP host, authentication, interception transactions, timeouts, store |
| Java extensions / G-Presets | Not supported | Java launcher or compatible external bridge and live regression tests |
| G-Python live console | Not implemented | Host API, Python console integration and package lifecycle |
| Flash connection | Not implemented | Client discovery, redirection and encryption bootstrap |
| Origins / Shockwave connection | Not implemented | WEDGIE framing, cipher variants and attachment |
| Nitro | Not implemented | HTTP/TLS/WebSocket proxy, assets, certificates, OS integration |
| Unity | Not implemented | WebSocket communicator, WASM patching, local file service |
| SOCKS upstream proxy | Not implemented | Authentication, routing, provider configuration |
| Hotel detection | Not implemented | Provider-specific discovery and supported hotels |
| Packet identifiers / sulek.dev | Not implemented | Providers, cache, hashes, schema and direction mapping |
| Room/catalog/inventory/entity parsers | Not implemented | Port G-Earth-Api parser classes and fixtures |
| Native desktop interface | Initial Rust interface | Match every original control, hotkeys, translations and layouts |
| Themes, translations, tray, shortcuts | Not implemented | OS lifecycle and original behavior |
| Settings persistence / migration | Not implemented | Atomic configuration storage and import from Java version |
| Extension store / updates | Not implemented | Distribution metadata, downloads, validation and lifecycle |
| Windows packaging | CI development artifact | Signed installer, upgrade/uninstall and release QA |
| Linux/macOS parity | Core tests only | Desktop packaging, proxy helpers and platform support matrix |
| beta-29 TLS fingerprint fixes | Not implemented | Equivalent TLS provider behavior and regression tests |
| Performance superiority | Unmeasured | Equivalent workload benchmarks against the Java version |

## Completion criteria

The port is complete only after the missing rows above are implemented and tested, including a real Flash/Origins/Unity/Nitro connection where supported upstream, an existing Java extension such as G-Presets, reconnection, encrypted traffic, certificate/proxy cleanup, settings migration and the full UI workflow. A working compiler or a passing packet test is insufficient.

The beta-29 fixes must be preserved: leet/habblet support, Chrome-compatible TLS behavior, macOS privileged helper, tray icon cropping and Unity header naming. They are tracked as outstanding, not silently omitted.
