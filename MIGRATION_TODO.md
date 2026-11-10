# Migration tasks

The released G-Presets binary parses a one-item inventory across two isolated Windows relay sessions; next exercise floor and wall room data through the same fixture. Real hotel and preset workflows remain open.

Unknown stuff-data tags and duplicate keys have beta-29 fixtures; next inspect the real G-Presets extension workflow and identify a safe offline integration test.

Stuff-data negative collection counts now match Java while high-score arrays reject negatives; next compare unknown tags and duplicate map keys against beta-29.

Negative furniture owner and item counts now have Java cursor fixtures; next compare malformed and unknown stuff-data formats against Java.

Wall ID number formats and floor direction boundaries have beta-29 fixtures; next compare furniture owner and item count failure behavior and cursor positions.

Pet flags and bot skill boundary values have beta-29 fixtures; next compare remaining room furniture placement and state formats against Java.

Entity-update fixtures now compare action ordering, malformed values and cursor positions; next compare pet and bot entity fields and serialization against beta-29.

Entity edge cases and Java serialization have differential fixtures; next compare entity-update action ordering, malformed values and cursor behavior against beta-29. Live client and extension tests remain open.

Status key: **partial** means implemented for selected cases only; **open** means no evidence of completion. All areas remain open to broader Java comparison and live validation. See `docs/PARITY.md` for details.

The local HTTPS fixture tolerates peers closing after the full response; the previous failed web run and subsequent successful run are recorded in `MIGRATION_PROGRESS.md`.

| Feature | Status | Next evidence or work |
|---|---|---|
| EVA framing, fields and mutations | Partial | Signed 8/16-bit operations and UTF-8 offset reads have Java oracle coverage; remaining helpers and regex/charset cases need fixtures. |
| WEDGIE codecs and expressions | Partial | Expand parsing corpus and validate a real Shockwave client. |
| Packet expressions and prediction | Partial | Broaden Java comparisons and metadata/client coverage. |
| Injection, packet tools and safety | Partial | CLI revision detection and real connection behavior. |
| TCP relay and reconnect | Partial | Real client, firewall and lifecycle tests. |
| RC4 and Flash attachment | Partial | Read-only process/socket and memory scan checked on an official AIR session; real encrypted traffic, key recovery, relay and multi-instance testing remain. |
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

Open-group backreferences, selected lookarounds, atomic groups, possessive quantifiers, nested classes and Java character properties have oracle coverage; full regex parity remains open. Friend, catalog and navigator cases have Java comparisons; next compare entity edge cases.

CI: serialized G-Python jobs passed on Windows and Linux in run 42723118432; continue monitoring intermittent kernel startup timeouts.
