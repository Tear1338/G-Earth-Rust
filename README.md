# G-Earth Rust

Rust port in progress of [G-Realm/G-Earth](https://github.com/G-Realm/G-Earth), based on **1.5.4-beta-29**, commit `242155c291b1109d6c9a02370f6a2af1ead41ea8`.

## Community

Want to join the community, get support, or share feedback and extensions? Join us on **Fluxer**!

<a href="https://fluxer.gg/OqH9tI3d">
  <img src="docs/assets/fluxer-logo.png" alt="Join our Fluxer community" width="48" height="48" align="left" />
</a>

**[Join the Fluxer Community →](https://fluxer.gg/OqH9tI3d)**  
Discussions, updates, help, and community extensions.

<br clear="left" />

**Development version. This does not yet replace the original G-Earth.** Windows Flash state discovery and hosts-based Flash/Origins attachment are now implemented and tested with a controlled client process. Raw-IP command mapping and preconnected relay behavior are implemented with mocked privileged commands and real loopback sockets. The Nitro HTTP/TLS/WebSocket provider, beta-29 hotel adapters and Windows proxy/certificate controls are also implemented with fixture tests. Unity WebGL hooks/communicator and a native extension store are implemented and tested with controlled fixtures. Real hotel/firewall sessions and exact UI parity remain outstanding. The Rust host runs external Java extensions, and the released G-Presets 1.6.5 authenticates in an isolated test; real G-Presets game workflows remain untested. [Feature-by-feature status](docs/PARITY.md).

## Implemented

- Bounded EVA_WIRE frame codec and packet readers/writers: byte, boolean, unsigned short, integer, long, float, double, ISO-8859-1 strings, long strings.
- Typed, named and raw packet expressions, upstream byte-display notation and lossless hexadecimal representation.
- EVA_WIRE, WEDGIE incoming/outgoing packet formats and their beta-29 extension IPC serialization.
- Explicit TCP relay with bidirectional logging, injection, ordered block/replace rules, reconnect and cancellation; authenticated SOCKS5 upstream routing and manual independent RC4 keys.
- Windows Flash negotiation and read-only RC4 discovery from the connecting client process; independent input/output counters, rejection of ambiguous snapshots, automatic revision detection and versioned packet-name caching.
- Hosts-based Flash/Origins attachment with a background setup worker, scoped redirect removal on connection/stop and explicit stale-redirect recovery.
- Flash Raw-IP attachment for Windows, Linux and macOS: original native mapping commands, three preconnected direct upstream sockets, SOCKS routing, lifecycle cleanup and a 55-second Windows multi-instance heartbeat with 60-second expiry. Privileged commands are mocked in tests; real firewall/alias and multi-instance client validation remain outstanding.
- Nitro browser mode: verified upstream TLS, EVA_WIRE WebSockets, built-in/dynamic hotel matching, Hubbe preludes, HabboSK RC4, Hartico PNG/TripleDES, HabboCity GCM/CTR, shared rules/injection and Java extensions. Explicit certificate controls and journaled Windows proxy restoration; see [Nitro setup and limits](docs/NITRO.md).
- Origins transport: bidirectional plaintext framing, Diffie-Hellman substitution, HKDF-SHA256 keys and independent ChaCha20 header/data channels. Tested against original Java crypto vectors and simulated client/server sessions; a hosts-based attachment path is available, but has not been validated against the official client.
- Authenticated loopback extension host, one-use launch tokens, Java/Python/Node external processes, connection details, packet names, interception, injection, click callbacks, language updates and console output. Java extensions still need a Java runtime.
- Sulek HTTPS packet-name lookup, upstream Unity messages.json import and portable TSV databases, with direction-aware expression lookup.
- Saved block/replace rules and finite/auto-starting schedule templates, atomic settings, full legacy Java cache import (`hotelsCache`, themes, history, logger settings, SOCKS), notepad, three themes (`G-Earth`, `G-Earth Dark`, `Tanji`), opt-in GitHub update check, Windows system tray, cross-OS global scheduler shortcuts (`Ctrl+Shift+0–9`), and complete localization across all nine upstream languages.
- Unity WebGL: authenticated local TLS communicator, gzip asset interception, four validated WASM hooks, SOCKS5 routing and browser reinjection, with an original-Java-patcher oracle. See [Unity setup](docs/UNITY.md).
- G-Python console: native dependency checks, authenticated Jupyter kernel and QtConsole launcher; existing scripting helpers are exposed. See [Python setup](docs/GPYTHON.md). Python and Qt are external runtimes.
- Native extension store: search/filter/order, categories/systems/unstable warnings, bounded installation, separate-version updates, authenticated launch and uninstall. See [Store behavior](docs/STORE.md).
- Native Rust desktop application: Connection (with saved custom hotels), Logger (with one-step export & WEDGIE structure prediction), Injection, Scheduler, Tools, Extensions, Extra and Info. Logger rows are virtualized and bounded by row count and byte budget.
- Multi-OS CLI and desktop packages through GitHub Actions: Windows portable EXE & Inno Setup installer (`G-Earth-Rust-Setup-x64.exe`), macOS `.app` ZIP bundle, and Linux `.desktop` tarball.

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

CLI relay commands: `server EXPR`, `client EXPR`, `quit`. Binding is restricted to loopback. The CLI TCP relay does not modify system proxy settings. The desktop includes negotiated Flash decryption, scoped hostname attachment and Flash Raw-IP attachment; see [attachment setup and limits](docs/ATTACHMENT.md).

For CLI packet-ID checks, append `--revision VERSION`: only IDs observed in original traffic for that revision and direction can be injected. `--developer` overrides the check. Plaintext EVA_WIRE relays also auto-detect Flash hello (header 4000) revisions when observed on the wire; when no revision is provided or observed, unobserved IDs remain permitted.

## Validation

CI runs core and TCP loopback tests on Windows, Linux and macOS and builds desktop packages for all three platforms. A separate Java compatibility job downloads the pinned upstream beta-29 release, verifies its published SHA-256, invokes its actual API JAR and compares wire vectors against Rust. These finite checks cover only the declared vectors, not all G-Earth behavior.

The source tree was inspected through GitHub and the released API JAR inventoried using [REA](https://rea.tools/). REA's Java decompiler service is unavailable in this environment; source review and executable Java oracles supply the semantic checks. [Analysis notes](docs/ANALYSIS.md). A [packet-construction and relay microbenchmark](docs/PERFORMANCE.md) measures narrow synthetic workloads; whole-application performance is unmeasured.

Validated development builds and installers are published on [GitHub Releases](https://github.com/Tear1338/G-Earth-Rust/releases) and in [Actions artifacts](https://github.com/Tear1338/G-Earth-Rust/actions). Desktop hostname attachment changes its marked hosts entries. Raw IP changes a loopback alias or NAT rule and requires administrator/root privileges; read its platform warnings before use. Browser mode changes the system proxy (Windows Internet Settings, macOS `networksetup`, or Linux GNOME `gsettings`) only when started with that option enabled; public-certificate installation/removal requires its separate explicit buttons.

## Credits

Original G-Earth: **sirjonasxx and G-Realm contributors**. Rust port project: **1desirable1337 / Tear1338**. This is an independent port, not an official G-Realm release. Original MIT notice is retained in [LICENSE](LICENSE). Encoding layout attribution: Kepler / Quackster.

