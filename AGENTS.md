# AGENTS.md — G-Earth Rust

Guidance for AI coding agents and contributors working on **G-Earth Rust** (`Tear1338/G-Earth-Rust`), a native Rust desktop & CLI port of G-Earth `1.5.4-beta-29` supporting **Flash**, **Origins**, **Unity WebGL**, **Nitro**, and **HabboCity**.

---

## 1. Repository Layout

- `src/lib.rs` — Core safe Rust library (`#![forbid(unsafe_code)]`):
  - Protocol & packets: `packet.rs`, `encoding.rs`, `expression.rs`, `structure_prediction.rs`, `packet_info.rs`, `packet_tools.rs`, `packet_safety.rs`, `parsers/`
  - Crypto & client modes: `crypto.rs`, `flash.rs`, `shockwave.rs`, `nitro.rs`, `nitro_assets.rs`, `nitro_city.rs`, `unity_assets.rs`, `unity_connection.rs`, `unity_server.rs`, `unity_wasm.rs`
  - Networking & proxies: `relay.rs`, `attachment.rs`, `raw_ip_lease.rs`, `web_ca.rs`, `web_proxy.rs`, `socks.rs`, `socks_http.rs`, `web_socks.rs`
  - Automation & extensions: `rules.rs`, `injection.rs`, `scheduler.rs`, `schedule_file.rs`, `extension.rs`, `extension_host.rs`, `extension_store.rs`, `gpython.rs`, `admin_service.rs`, `settings.rs`, `i18n.rs`, `update_checker.rs`
  - Generated Java 21 regex/Unicode tables: `java_regex_properties.rs`, `java_unicode_names.rs`, `java_character_names.rs` (verified against JDK 21 in CI)
- `src/desktop.rs` — `eframe`/`egui` desktop UI binary (`gearth-desktop`), supported by UI modules:
  - `src/theme_ui.rs` — `G-Earth`, `G-Earth Dark`, `Fluxer` (`#4641D9`), and `Tanji` themes, custom accent colors, embedded logos, and `VectorIcon` painter helpers
  - `src/doctor.rs` — Non-blocking **Connection Doctor** diagnostics, 1-click fixes, and multi-hotel `ConnectionProfile` presets
  - `src/logger_ui.rs` — Friendly logger decoding, noise detection, filter presets, G-Python/Java snippet generation, live stats, packet diff (`A vs B`), injection favorites, and field builder helpers
  - `src/store_ui.rs` — Multi-source **G-ExtensionStore** UI (`sirjonasxx/G-ExtensionStore`, `Tear1338/G-ExtensionStore`, custom repos)
  - `src/gpython_ui.rs` — G-Python shell / Jupyter / QtConsole UI
- `src/main.rs` — CLI binary (`gearth-rust`).
- `crates/gearth-platform/` — Isolated OS/FFI crate containing all `unsafe` code:
  - Process/memory scanning (`windows.rs`, `linux.rs`, `macos.rs`)
  - System proxy / PAC / CA trust management (`web_settings.rs`, `unix_web_settings.rs`)
  - macOS privileged `/etc/hosts`, `lo0` loopback aliases, 1-click admin relaunch, and Flash client re-signing (`macos_hosts.rs`, `macos_flash_prep.rs`)
  - Cross-platform helpers: `port_checker.rs`, `ip_mapping.rs`, `hotkeys.rs`, `tray.rs`, `file_dialog.rs`, `process_tree.rs`
- `crates/hudsucker/` — Vendored MITM HTTP/HTTPS/WSS proxy crate.
- `locales/` — 9 Java `.properties` UI translation files (`de`, `en`, `es`, `fi`, `fr`, `it`, `nl`, `pt`, `tr`).
- `packaging/` — Windows Inno Setup (`packaging/windows/gearth-rust.iss`), macOS `.app` bundle (`packaging/macos/`), Linux `.desktop` + installer (`packaging/linux/`).
- `tests/` — Rust integration tests and JDK 21 / beta-29 Java compatibility oracles.
- `.github/workflows/ci.yml` — Multi-OS validation, Java compatibility oracles, and automated GitHub Release publishing on `v*` tags.

---

## 2. Build, Test, and Lint Commands

Always run with `--locked` (CI enforces `--locked` everywhere):

```bash
# Format check
cargo fmt --all -- --check

# Core workspace tests (no desktop feature)
cargo test --locked --workspace --all-targets

# i18n completeness across all 9 locales
cargo test --locked --test i18n

# Platform crate tests (proxy guards, macOS scripts, port checker, scanners)
cargo test --locked -p gearth-platform

# Desktop UI binary unit tests (theme, doctor, logger_ui, profiles, rules)
cargo test --locked --features desktop --bin gearth-desktop

# Full Clippy check (must pass with zero warnings)
cargo clippy --locked --features "desktop web" --all-targets -- -D warnings

# Build desktop release binary
cargo build --locked --release --features desktop --bin gearth-desktop
```

---

## 3. Hard Invariants & Conventions

1. **Zero `unsafe` in core**: `src/lib.rs` enforces `#![forbid(unsafe_code)]`. Any OS API / FFI call must live in `crates/gearth-platform/` with safe wrappers and unit tests.
2. **Locked dependencies**: Never modify `Cargo.lock` or add new crates unless explicitly requested.
3. **9-language i18n parity**: Every `rust.*` key referenced by the UI must be defined in **all 9** files in `locales/messages_{de,en,es,fi,fr,it,nl,pt,tr}.properties`. Always verify with `cargo test --locked --test i18n`.
4. **egui font & glyph safety**: `egui`'s bundled `Ubuntu-Light` font lacks many geometric/symbol glyphs (`▸`, `▾`, `★`, `▶`, `Δ`, `↔`, `↑`, `↓`), which render as tofu squares (`□`). Always use `theme_ui::VectorIcon` / `egui::Painter` shapes or verified ASCII/Latin glyphs (`→`, `←`, `·`).
5. **egui layout wrapping**: `egui::Frame::show` inherits its parent's layout. Never place multi-line wrapped text or vertical lists inside `ui.horizontal(|ui| Frame::show(...))` — use `ui.indent(...)` or `ui.vertical(...)` with explicit `.wrap()` and clamped `set_min_width`/`set_max_width` so right-aligned footer buttons cannot be pushed off-screen.
6. **External extension compatibility**:
   - Extension IPC listens on `127.0.0.1:9092` (beta-29 wire protocol).
   - Java beta-29 extensions only recognize `"G-Earth"`, `"G-Earth Dark"`, and `"Tanji"`. Always send `AppTheme::extension_theme_name()` (which maps `Fluxer` → `"G-Earth Dark"`) to `ExtensionHost::set_theme`.
7. **Settings persistence**: Keep `settings.json` schema v1 backward-compatible (store new keys in `settings.values` / `settings.booleans`). Desktop settings auto-save silently via debounced fingerprinting (`poll_auto_save_settings`) and on `Drop`.
8. **Shell script line endings**: Keep **LF** (`\n`) line endings and executable permissions (`+x`) on `packaging/macos/make_app_bundle.sh` and `packaging/linux/install.sh`.

---

## 4. Platform-Specific Rules

- **Windows**:
  - System proxy uses crash-safe journaled registry writes (`GEARTH-PROXY-2`); **City** and **Nitro** modes default to targeted PAC (`http://127.0.0.1:<port>/proxy.pac`) so non-game apps stay `DIRECT`.
  - Release builds use `RUSTFLAGS="-C target-feature=+crt-static"` and verify PE imports + embedded icon (`tools/check_pe_imports.py`, `tools/check_pe_icon.py`).
- **macOS**:
  - CI builds a **Universal binary** (`aarch64-apple-darwin` + `x86_64-apple-darwin` via `lipo`) with `MACOSX_DEPLOYMENT_TARGET="11.0"`, generates `AppIcon.icns`, ad-hoc signs with `codesign --force --deep --sign -`, and archives via `ditto`.
  - macOS `lo0` only has `127.0.0.1` by default: single-host Flash/Origins binds `127.0.0.1`; multi-hotel Auto-detect aliases `127.0.0.x` via `ensure_macos_loopback_aliases`.
  - Flash memory scanning (`task_for_pid`) requires root privileges and ad-hoc re-signed `Habbo.app` (`get-task-allow`). Non-elevated Flash/Origins launches offer a 1-click admin relaunch (`relaunch_macos_as_admin`) preserving `GEARTH_RUST_CONFIG` and `HOME`.
  - **AppleScript gotcha**: `ip` is a reserved keyword in AppleScript; never name a variable `ip`. Every AppleScript constant in `crates/gearth-platform/src/macos_hosts.rs` must be included in `applescripts_compile_cleanly_with_osacompile`.
- **HabboCity (`City` mode)**:
  - Keep the system/PAC proxy active after initial connect because HabboCity migrates WebSocket links (`7705` → `7702`).
  - Normalize default `:443` / `:80` ports in `Hotel::matches` and strip `alt-svc` headers to prevent HTTP/3 bypasses.

---

## 5. CI & Release Workflow

- Pushing to `main` runs the full CI matrix (`core`, `desktop`, `macos`, `linux-desktop`, `java-compatibility`, `web`, `gpresets`, `gpython`).
- Pushing an annotated tag `vX.Y.Z` triggers the `publish-release` job in `.github/workflows/ci.yml`, which publishes an official (non-draft, non-prerelease) GitHub Release with all 13 cross-platform assets and `SHA256SUMS.txt` (consumed by the built-in auto-updater in `src/update_checker.rs`).
- Note: `java-compatibility` occasionally hits transient GitHub raw HTTP 429 rate limits when `main` and a `v*` tag run simultaneously; `gh run rerun <run-id> --failed` resolves it cleanly.
