# G-Earth Rust

Rust port in progress of [G-Realm/G-Earth](https://github.com/G-Realm/G-Earth), based on **1.5.4-beta-29**, commit `242155c291b1109d6c9a02370f6a2af1ead41ea8`.

**Development version. This does not yet replace the original G-Earth.** Windows Flash state discovery and hosts-based Flash/Origins attachment are now implemented and tested with a controlled client process. Real hotel sessions, raw-IP attachment, Nitro and Unity connection providers remain outstanding. The Rust host now runs external Java extensions, verified with a fixture built against the actual beta-29 API; G-Presets itself has not been tested. [Feature-by-feature status](docs/PARITY.md).

## Implemented

- Bounded EVA_WIRE frame codec and packet readers/writers: byte, boolean, unsigned short, integer, long, float, double, ISO-8859-1 strings, long strings.
- Typed, named and raw packet expressions, upstream byte-display notation and lossless hexadecimal representation.
- EVA_WIRE, WEDGIE incoming/outgoing packet formats and their beta-29 extension IPC serialization.
- Explicit TCP relay with bidirectional logging, injection, ordered block/replace rules, reconnect and cancellation; authenticated SOCKS5 upstream routing and manual independent RC4 keys.
- Windows Flash negotiation and read-only RC4 discovery from the connecting client process; independent input/output counters, rejection of ambiguous snapshots, automatic revision detection and versioned packet-name caching.
- Hosts-based Flash/Origins attachment with a background setup worker, scoped redirect removal on connection/stop and explicit stale-redirect recovery.
- Origins transport: bidirectional plaintext framing, Diffie-Hellman substitution, HKDF-SHA256 keys and independent ChaCha20 header/data channels. Tested against original Java crypto vectors and simulated client/server sessions; a hosts-based attachment path is available, but has not been validated against the official client.
- Authenticated loopback extension host, one-use launch tokens, Java/Python/Node external processes, connection details, packet names, interception, injection, click callbacks, language updates and console output. Java extensions still need a Java runtime.
- Sulek HTTPS packet-name lookup, upstream Unity messages.json import and portable TSV databases, with direction-aware expression lookup.
- Saved block/replace rules and finite schedule templates, atomic settings, legacy cache import, notepad, light/dark themes and nine upstream language resources. Individual controls are not fully localized yet.
- Native Rust desktop application: Connection, Logger, Injection, Scheduler, Tools, Extensions and Info. Logger rows are virtualized and bounded by row count and byte budget.
- CLI and Windows desktop builds through GitHub Actions.

## Run

Install the stable Rust toolchain from [rust-lang.org](https://www.rust-lang.org/tools/install). Windows builds also require the Microsoft C++ build tools for the MSVC target.

```powershell
cargo test --locked --workspace --all-targets
cargo run --release --bin gearth-rust -- encode '{h:123}{i:42}{s:"hello"}'
cargo run --release --features desktop --bin gearth-desktop
```

For a compatible **unencrypted test client**, explicitly configure its endpoint as the local relay address (CLI defaults to EVA_WIRE; Origins, SOCKS and manual RC4 configuration are exposed in the desktop):

```powershell
cargo run --release --bin gearth-rust -- relay 127.0.0.1:1234 test-server.example:30000
```

CLI relay commands: `server EXPR`, `client EXPR`, `quit`. Binding is restricted to loopback. The program does not install certificates or change the operating system proxy. The desktop includes negotiated Flash decryption and scoped hostname attachment; see [Windows attachment](docs/ATTACHMENT.md) for setup and limitations.

## Validation

CI runs core and TCP loopback tests on Windows and Linux and builds the Windows desktop executable. A separate Java compatibility job downloads the pinned upstream beta-29 release, verifies its published SHA-256, invokes its actual API JAR and compares wire vectors against Rust. These finite checks cover only the declared vectors, not all G-Earth behavior.

The source tree was inspected through GitHub and the released API JAR inventoried using [REA](https://rea.tools/). REA's Java decompiler service is unavailable in this environment; source review and executable Java oracles supply the semantic checks. [Analysis notes](docs/ANALYSIS.md). A [packet-construction microbenchmark](docs/PERFORMANCE.md) measures one narrow workload; whole-application performance is unmeasured.

Tested development executables are published as prereleases on [GitHub Releases](https://github.com/Tear1338/G-Earth-Rust/releases). The latest validated builds are also available in [Actions artifacts](https://github.com/Tear1338/G-Earth-Rust/actions). Desktop hostname attachment changes only its marked hosts entries; the program does not install certificates or change the system proxy.

## Credits

Original G-Earth: **sirjonasxx and G-Realm contributors**. Rust port project: **1desirable1337 / Tear1338**. This is an independent port, not an official G-Realm release. Original MIT notice is retained in [LICENSE](LICENSE). Encoding layout attribution: Kepler / Quackster.

