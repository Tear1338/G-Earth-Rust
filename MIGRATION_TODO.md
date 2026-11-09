# Migration tasks

Status key: **partial** means implemented for selected cases only; **open** means no evidence of completion. All areas remain open to broader Java comparison and live validation. See `docs/PARITY.md` for details.

| Feature | Status | Next evidence or work |
|---|---|---|
| EVA framing, fields and mutations | Partial | Signed 8/16-bit operations and UTF-8 offset reads have Java oracle coverage; remaining helpers and regex/charset cases need fixtures. |
| WEDGIE codecs and expressions | Partial | Expand parsing corpus and validate a real Shockwave client. |
| Packet expressions and prediction | Partial | Broaden Java comparisons and metadata/client coverage. |
| Injection, packet tools and safety | Partial | CLI revision detection and real connection behavior. |
| TCP relay and reconnect | Partial | Real client, firewall and lifecycle tests. |
| RC4 and Flash attachment | Partial | Real AIR traffic, memory layouts and multi-instance testing. |
| Origins encryption and attachment | Partial | Official client end-to-end testing. |
| Nitro proxy, crypto and assets | Partial | Real hotel and SOCKS servers, TLS fingerprint, interactive desktop controls and platform cleanup. |
| Unity communicator and WASM hooks | Partial | Real client revisions and extensions. |
| Java extension host | Partial | Live G-Presets workflows, other extensions and lifecycle parity. |
| G-Python and Node integrations | Partial | Real sessions and visual QtConsole validation. |
| Packet metadata and hotel detection | Partial | More providers, Unity discovery and real hotel checks. |
| Rules and scheduler | Partial | Restart recovery, catch-up semantics and remaining editor options. |
| Packet logger | Partial | Java export format, direction labels, visualization and WEDGIE behavior. |
| Settings and localization | Partial | All Java settings, complete translations and interactive import. |
| Room, entity, inventory and catalog APIs | Partial | Remaining parsers, more Java vectors and live extensions. |
| Extension store | Partial | More package/version cases, visual content and live workflows. |
| Desktop UI and themes | Partial | Complete layout/control parity, tray and interactive tests. |
| Windows distribution | Partial | Installer, signing and release QA. |
| Linux/macOS distribution | Partial | Desktop distribution and platform proxy helpers. |
| End-to-end equivalence | Open | Real supported clients, encryption, reconnect, extensions and cleanup. |
| Performance | Open | Representative comparable end-to-end Java and Rust benchmarks. |

Next: compare optional Java regex quantifiers, captures and zero-width behavior against the released API. Full Java regex and live extension validation remain open.
