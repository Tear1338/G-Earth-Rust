<div align="center">

<img src="resources/themes/gearth_logo.png" alt="G-Earth Rust" width="96" />

# G-Earth Rust

**Fast, native Rust desktop & CLI port of [G-Earth 1.5.4-beta-29](https://github.com/G-Realm/G-Earth)**  
Built for **Flash**, **Origins**, **Unity WebGL**, **Nitro**, and **HabboCity** — with a Power Packet Logger, targeted PAC proxy, multi-source G-ExtensionStore, and full extension compatibility.

[![Latest Release](https://img.shields.io/github/v/release/Tear1338/G-Earth-Rust?style=flat-square&logo=github&color=2b7a78)](https://github.com/Tear1338/G-Earth-Rust/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/Tear1338/G-Earth-Rust/total?style=flat-square&color=3a86ff)](https://github.com/Tear1338/G-Earth-Rust/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/Tear1338/G-Earth-Rust/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Tear1338/G-Earth-Rust/actions)
[![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-555555?style=flat-square)](#download--quick-start)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

</div>

---

## Community

Want to join the community, get support, or share feedback and extensions? Join us on **Fluxer**!

<a href="https://fluxer.gg/OqH9tI3d">
  <img src="docs/assets/fluxer-logo.png" alt="Join our Fluxer community" width="48" height="48" align="left" />
</a>

**[Join the Fluxer Community →](https://fluxer.gg/OqH9tI3d)**  
Discussions, updates, help, and community extensions.

<br clear="left" />

---

## Download & Quick Start

Get up and running in **3 steps**:

1. **Download** the latest package from [**GitHub Releases**](https://github.com/Tear1338/G-Earth-Rust/releases/latest):
   - **Windows**: `G-Earth-Rust-Setup-x64.exe` (installer) or portable `gearth-desktop-windows-x64.exe`
   - **macOS**: `G-Earth-Rust-macOS-app.zip`
   - **Linux**: `G-Earth-Rust-Linux.tar.gz`
2. **Choose your client mode** in the **Connection** tab:
   - `Flash` · `Origins` · `Unity` · `Nitro` · **`City`** *(dedicated mode for `https://habbocity.fr/hotel`)*
3. **Connect**:
   - **Flash / Origins**: click **Connect** (run as Administrator/root for hosts or Raw-IP attachment).
   - **Nitro / City**: install the local public CA certificate once via **Prepare certificate**, keep **Configure system proxy** + **Targeted PAC proxy** enabled, click **Connect**, then reload your hotel (`Ctrl+F5`).

> **Automatic updates**: G-Earth Rust includes a built-in update checker and one-click updater (with SHA-256 verification) in the **Info** tab.

---

## Key Features

### Supported Client Modes

| Mode | Protocol / Transport | Highlights |
|---|---|---|
| **Flash** | EVA_WIRE + RC4 | Read-only client RC4 memory discovery, auto revision detection, hosts & Raw-IP attachment, SOCKS5 |
| **Origins** | WEDGIE + DH / HKDF / ChaCha20 | Bidirectional framing, WEDGIE structure prediction, Sulek Origins packet identifiers |
| **Unity** | WebGL WASM hooks + local TLS | Authenticated local communicator, gzip asset patching, browser reinjection |
| **Nitro** | HTTPS / WSS MITM (`hudsucker`) | Built-in & dynamic `nitro.json` hotels (Hubbe, HabboSK, Hartico, Leet…), targeted PAC proxy |
| **City** | HabboCity 2026 EvaWire (`wss://websocket.habbocity.fr`) | Link-control passthrough (`7701–7705`), seamless WebSocket migration, automatic targeted `*.habbocity.fr` PAC proxy |

### Targeted PAC Proxy & Status Indicator
- **Zero interference with other apps**: in **City** and **Nitro** modes, G-Earth serves a local `http://127.0.0.1:<port>/proxy.pac` script so **only your game's domains** (e.g., `*.habbocity.fr`) go through the proxy while Discord, YouTube, and every other app stay `DIRECT`.
- **Crash-safe restoration**: previous Windows/macOS/Linux proxy settings are journaled and automatically restored on abort, exit, or crash recovery.
- **Live status-bar badge**: displays the active proxy mode (`PAC Proxy` / `System Proxy`) with a one-click **Disable proxy** button.

### Power Packet Logger
- **Friendly & Classic views**: toggle between rich decoded field cards with a side-by-side **Packet Inspector** and the classic beta-29 monospace view, inside the main tab or as an independent OS window.
- **One-click noise suppression & Presets**: filter out pings, keepalives, and HabboCity link frames in one click, hide individual headers from the context menu, and save/load complete **Filter Presets**.
- **Copy as G-Python / Java**: generate ready-to-paste `g_python` (`HPacket` + `ext.send_to_server/client` + `intercept`) and **G-Earth Java API** snippets directly from any logged packet.
- **Live Stats & Top Headers**: real-time packets/second (`↓ in · ↑ out`) with clickable Top Headers chips (left-click to filter, right-click to hide).
- **Custom Packet Names**: name undocumented headers (such as HabboCity custom packets) right from the logger, persisted in `custom-packets.json` with JSON import/export and preserved across Sulek catalog refreshes.

### Extensions, Multi-Source Store & G-Python
- **Full beta-29 extension IPC (`127.0.0.1:9092`)**: runs `.jar`, `.py`, `.py3`, `.exe`, `.sh`, and `.js` extensions with one-use launch tokens, approval prompts, inactive-row restart/uninstall, and colorized Extension Console.
- **Multi-source G-ExtensionStore**: browse and install extensions from the official `sirjonasxx/G-ExtensionStore`, **`Tear1338/G-ExtensionStore`**, or any custom GitHub repository in an independent OS window.
- **Theme sync**: `G-Earth`, `G-Earth Dark`, and `Tanji` themes automatically synchronize to connected extensions via `HostInfo`.
- **G-Python shell**: native dependency check and authenticated Jupyter / QtConsole launcher.

### Injection, Rules, Scheduler & Localization
- Typed, named, and lossless hex packet expressions (`{out:Chat}{s:"hello"}{i:0}`), live corruption diagnostics, and saved injection history.
- Ordered **Block / Replace** rules, finite & auto-starting **Scheduler** templates, and cross-OS global hotkeys (`Ctrl+Shift+0–9`).
- Live **Tools** (`Packet ↔ Expression`, `Int` / `UShort` encoders), Notepad, Windows system tray, and complete localization in **9 languages** (`EN`, `FR`, `DE`, `ES`, `FI`, `IT`, `NL`, `PT`, `TR`).

---

## Build from Source & CLI

Install the stable Rust toolchain from [rust-lang.org](https://www.rust-lang.org/tools/install).

```powershell
# Run workspace tests
cargo test --locked --workspace --all-targets

# Launch the desktop application
cargo run --release --features desktop --bin gearth-desktop

# CLI packet encoder
cargo run --release --bin gearth-rust -- encode '{h:123}{i:42}{s:"hello"}'

# CLI loopback TCP relay
cargo run --release --bin gearth-rust -- relay 127.0.0.1:1234 test-server.example:30000
```

Desktop CLI flags: `-c / --connect <flash|origins|unity|nitro|city>`, `--host <HOST>`, `--port <PORT>`, `-t / --theme <light|dark|tanji>`, `-d / --debug`.

---

## Documentation

| Guide | Description |
|---|---|
| [Feature Parity](docs/PARITY.md) | Feature-by-feature status vs. G-Earth 1.5.4-beta-29 |
| [Nitro & City Setup](docs/NITRO.md) | HTTPS proxy, CA certificate, PAC routing, and hotel adapters |
| [Flash / Origins Attachment](docs/ATTACHMENT.md) | Hosts redirection, Raw-IP mapping, and privilege requirements |
| [Unity WebGL](docs/UNITY.md) | Local TLS communicator and WASM asset hooks |
| [G-ExtensionStore](docs/STORE.md) | Store catalog format, custom repositories, and installation |
| [G-Python Console](docs/GPYTHON.md) | Python environment setup and Jupyter/QtConsole integration |
| [Global Hotkeys](docs/HOTKEYS.md) | Scheduler shortcut bindings on Windows, macOS, and Linux |
| [Validation & Benchmarks](docs/VALIDATION.md) | CI matrix, Java 21 differential tests, and [microbenchmarks](docs/PERFORMANCE.md) |

---

## Validation & Security Notes

- GitHub Actions runs unit/integration tests and builds native packages across **Windows, macOS, and Linux**, alongside a **Java 21 compatibility job** comparing Rust wire vectors directly against the pinned upstream beta-29 API JAR.
- Hostname/Raw-IP attachment modifies scoped hosts or loopback/NAT entries and requires elevated privileges. Browser mode modifies OS proxy settings only when explicitly enabled, and root CA installation/removal always requires explicit user action.

## Credits & License

- **Original G-Earth**: **sirjonasxx** and **G-Realm** contributors ([G-Realm/G-Earth](https://github.com/G-Realm/G-Earth), based on `1.5.4-beta-29`).
- **Rust port**: **1desirable1337 / Tear1338** — independent port, not an official G-Realm release.
- **Encoding layout attribution**: Kepler / Quackster.
- Licensed under the [MIT License](LICENSE).
