# G-Earth Rust

Rust port in progress of [G-Realm/G-Earth](https://github.com/G-Realm/G-Earth), based on **1.5.4-beta-29**, commit `242155c291b1109d6c9a02370f6a2af1ead41ea8`.

**Development version. This does not yet replace the original G-Earth.** Automatic attachment to official Habbo clients and execution of existing Java extensions are not implemented. Do not use this version expecting G-Presets to work. [Feature-by-feature status](docs/PARITY.md).

## Implemented

- Bounded EVA_WIRE frame codec and packet readers/writers: byte, boolean, unsigned short, integer, long, float, double, ISO-8859-1 strings, long strings.
- Numeric packet expressions, strict validation, lossless hexadecimal representation and conversion tools.
- HPacket/HMessage serialization and EVA_WIRE network-extension message codec based on beta-29.
- Explicit plaintext TCP relay with bidirectional logging, packet injection, ordered block/replace rules, reconnect and cancellation.
- Scheduler with finite repetitions and no burst of catch-up packets after a delayed tick.
- Independent RC4 implementation with state import/export and rewind; Shockwave B64/VL64 integer codecs. These are library components, not working client attachment.
- Native Rust desktop application: Connection, Logger, Injection, Scheduler, Tools, Extensions status and Info. The logger keeps at most 5,000 rows and virtualizes visible rows.
- CLI and Windows desktop builds through GitHub Actions.

## Run

Install the stable Rust toolchain from [rust-lang.org](https://www.rust-lang.org/tools/install). Windows builds also require the Microsoft C++ build tools for the MSVC target.

```powershell
cargo test --all-targets
cargo run --release --bin gearth-rust -- encode '{h:123}{i:42}{s:"hello"}'
cargo run --release --features desktop --bin gearth-desktop
```

For a compatible **unencrypted test client**, explicitly configure its endpoint as the local relay address:

```powershell
cargo run --release --bin gearth-rust -- relay 127.0.0.1:1234 test-server.example:30000
```

CLI relay commands: `server EXPR`, `client EXPR`, `quit`. Binding is restricted to loopback. The program does not install certificates or change the operating system proxy. It does not decrypt an official Habbo session automatically.

## Validation

CI runs core and TCP loopback tests on Windows and Linux and builds the Windows desktop executable. A separate Java compatibility job downloads the pinned upstream beta-29 release, verifies its published SHA-256, invokes its actual API JAR and compares wire vectors against Rust. These finite checks cover only the declared vectors, not all G-Earth behavior.

The source tree was inspected through GitHub and the released API JAR inventoried using [REA](https://rea.tools/). [Analysis notes](docs/ANALYSIS.md). No benchmark against the original application has established a performance gain yet.

## Credits

Original G-Earth: **sirjonasxx and G-Realm contributors**. Rust port project: **1desirable1337 / Tear1338**. This is an independent port, not an official G-Realm release. Original MIT notice is retained in [LICENSE](LICENSE). Encoding layout attribution: Kepler / Quackster.

