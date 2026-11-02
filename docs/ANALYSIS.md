# Source and REA analysis

Reference: https://github.com/G-Realm/G-Earth

Pinned tag: `1.5.4-beta-29`; commit `242155c291b1109d6c9a02370f6a2af1ead41ea8`.

The pinned tree contains 675 entries and 347 Java source files. `UPSTREAM_FILES.tsv` retains the path inventory. Protocol and integration work uses the exact upstream HPacket, HMessage, HPacketFormat, NetworkExtensionCodec, NetworkExtensionMessage, HostInfo, PacketInfoManager, network extension authenticator/runner, packet handlers, Shockwave buffers/modifiers, BobbaCrypto classes, packet providers, Raw-IP providers/mappers and Cacher/UI settings.

REA opened the released `G-Earth-Api-1.5.4-beta-29.jar` and inspected its ZIP inventory: 181 files, 40 directories, no reported integrity contradictions. SHA-256: `7f318b32a793269eabb1afe2962887ede7d274f6da43b86323ce84d806ef3a51`.

REA's Java decompiler requires a running JEB MCP service, unavailable in this environment. Its native Windows PTY capture also reports unsupported descendant cleanup. These unavailable capabilities were not treated as successful reconstruction evidence. The source is public, so reviewed original source and executable Java oracles provide semantic evidence instead.

Static inventory does not establish runtime behavior, complete equivalence or performance. Local machine-specific evidence exports are excluded from Git. The portable source identity and limitations are recorded here.

## Architecture

Safe Rust core (`forbid(unsafe_code)`) separates packets/expressions, crypto, transport, SOCKS, packet identifiers, extensions, settings, rules and scheduling. RustCrypto supplies standard HKDF/SHA256/ChaCha20; num-bigint supplies the original Origins DH arithmetic; ureq supplies verified HTTPS lookup. The optional eframe desktop consumes the same core. A separate gearth-platform crate isolates the small unsafe Win32 FFI boundary; protocol and UI code remain safe Rust. Native access requests read/query permissions only, validates the selected Habbo/Flash process, closes owned handles and bounds memory reads, time and retained candidates.

One nonblocking relay loop handles both directions and injected frames. Output queues are bounded to 64 MiB per direction, with retained partial-write offsets. Independent RC4 input/output state accounts for blocked and injected traffic. Origins keeps separate client/server and header/data channels and preserves partial encrypted headers without advancing the nonce twice.

The extension host binds only loopback, bounds pending peers and queues, uses random one-use file-bound launch tokens, and requires approval for external debug extensions. Interception has a 500 ms transaction deadline; a missing or invalid response stops the session. Java extensions run in their own JVM and retain the upstream Java API/parser library; Rust does not pretend to reimplement every Java API class.

The UI caches expression/search strings and virtualizes log rows, with configurable row and byte budgets. Settings use bounded reads and atomic same-directory replacement. SOCKS passwords and RC4 keys are not saved.

## Flash discovery and redirection

The first Flash hello supplies revision/identifier; the server handshake selects outgoing and optional incoming encryption. The native helper scans private writable pages of the connecting process for shuffled 256-u32 states, with a 1 GiB/5 second scan bound and at most 8,192 distinct candidates. Prefix rejection keeps candidate validation cheap. Fresh states are preferred; reversing snapshots is accepted only when the result is unambiguous. Ambiguity waits for further evidence or ends the session rather than silently corrupting a payload.

The hostname is resolved before redirection and the listener is bound first. Only token-marked lines are added to the hosts file, guarded by a file lock; cleanup rereads the current contents and preserves unrelated later edits. Setup refuses pre-existing entries and other active/stale Rust leases. Explicit recovery removes only Rust-owned lines.

The test executable is copied as Habbo.exe inside an isolated temporary test directory and supplies word-state tables in its own heap. The integration test actually calls Windows process enumeration, VirtualQueryEx/ReadProcessMemory and TCP ownership APIs. It verifies blocking, replacement and injection through negotiated encryption; it does not touch the real system hosts file.

## Known limits

- No official Habbo session has been exercised. The implemented Windows discovery/hosts attachment path is validated with a separate controlled process, not a production AIR client.
- Nitro/Unity providers, Windows proxy/certificate controls and the native store now have controlled fixture evidence. Complete UI parity and production-session validation remain outstanding.
- Log delivery may drop observations under backpressure; displayed counts are not authoritative network counts.
- Hosts attachment prepares DNS and listeners on a worker. Explicit relay setup can still resolve DNS synchronously; shutdown may wait for bounded connection or identifier lookup timeouts.
- Sulek lookup is bounded and revision-cached; malformed, wrong-version and truncated caches are rejected. Tests use offline schemas and cache fixtures, not the live service.
- Nine original language resources are present; individual added controls remain partly English.
- Finite simulated and Java-oracle tests do not establish compatibility with arbitrary extensions.
- No benchmark demonstrates a gain over the original Java application.

## Unity reference

REA inventoried the released G-Wasm-Minimal-1.0.4.jar: SHA-256 81ede388f652652b5a7dd66cb111c3bdfb0526fd03ffa688fe8f8ea56c91e748, 107 files, 35 directories and no inventory integrity contradictions. Semantics come from the pinned Java patchers, the released JAR oracle and executable controlled WASM/browser fixtures, rather than inventory alone.
