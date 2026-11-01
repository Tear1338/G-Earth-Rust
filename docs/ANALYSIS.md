# Source and REA analysis

Reference: https://github.com/G-Realm/G-Earth

Pinned tag: `1.5.4-beta-29`; commit `242155c291b1109d6c9a02370f6a2af1ead41ea8`.

The pinned tree contains 675 entries and 347 Java source files. `UPSTREAM_FILES.tsv` retains the path inventory. Protocol and integration work uses the exact upstream HPacket, HMessage, HPacketFormat, NetworkExtensionCodec, NetworkExtensionMessage, HostInfo, PacketInfoManager, network extension authenticator/runner, packet handlers, Shockwave buffers/modifiers, BobbaCrypto classes, packet providers and Cacher/UI settings.

REA opened the released `G-Earth-Api-1.5.4-beta-29.jar` and inspected its ZIP inventory: 181 files, 40 directories, no reported integrity contradictions. SHA-256: `7f318b32a793269eabb1afe2962887ede7d274f6da43b86323ce84d806ef3a51`.

REA's Java decompiler requires a running JEB MCP service, unavailable in this environment. Its native Windows PTY capture also reports unsupported descendant cleanup. These unavailable capabilities were not treated as successful reconstruction evidence. The source is public, so reviewed original source and executable Java oracles provide semantic evidence instead.

Static inventory does not establish runtime behavior, complete equivalence or performance. Local machine-specific evidence exports are excluded from Git. The portable source identity and limitations are recorded here.

## Architecture

Safe Rust core (`forbid(unsafe_code)`) separates packets/expressions, crypto, transport, SOCKS, packet identifiers, extensions, settings, rules and scheduling. RustCrypto supplies standard HKDF/SHA256/ChaCha20; num-bigint supplies the original Origins DH arithmetic; ureq supplies verified HTTPS lookup. The optional eframe desktop consumes the same core.

One nonblocking relay loop handles both directions and injected frames. Output queues are bounded to 64 MiB per direction, with retained partial-write offsets. Independent RC4 input/output state accounts for blocked and injected traffic. Origins keeps separate client/server and header/data channels and preserves partial encrypted headers without advancing the nonce twice.

The extension host binds only loopback, bounds pending peers and queues, uses random one-use file-bound launch tokens, and requires approval for external debug extensions. Interception has a 500 ms transaction deadline; a missing or invalid response stops the session. Java extensions run in their own JVM and retain the upstream Java API/parser library; Rust does not pretend to reimplement every Java API class.

The UI caches expression/search strings and virtualizes log rows, with configurable row and byte budgets. Settings use bounded reads and atomic same-directory replacement. SOCKS passwords and RC4 keys are not saved.

## Known limits

- No official Habbo session has been exercised; automatic client attachment and Flash key discovery are absent.
- Nitro/Unity connection providers, system certificate/proxy lifecycle, extension store and complete UI parity are absent.
- Log delivery may drop observations under backpressure; displayed counts are not authoritative network counts.
- Remote DNS/connection setup is synchronous during relay setup; UI responsiveness during that setup needs improvement.
- The asynchronous Sulek lookup has bounded time and size but has only offline schema tests here.
- Nine original language resources are present; individual added controls remain partly English.
- Finite simulated and Java-oracle tests do not establish compatibility with arbitrary extensions.
- No benchmark demonstrates a gain over the original Java application.
