# Migration tasks

Byte-view logger exports now use Java-style direction/header formatting and complete byte output. Next compare Java and Rust structure prediction and skipped/oversized packet export behavior; live logger validation remains open.

A synthetic WIRED import without save acknowledgement retries three times and reports incomplete. Next compare packet logger export formats with beta-29 Java; live WIRED gameplay remains open.

A synthetic WIRED trigger preset now reloads and imports with a simulated save acknowledgement. Next omit the WIRED save acknowledgement and verify that the extension reports an incomplete import; real WIRED gameplay remains open.

A synthetic WIRED trigger exports with its option, text and selected-furniture remapping. Next reload that preset and exercise its WIRED import using a simulated server; live WIRED behavior remains open.

A synthetic import now fails when final movement is unconfirmed. Next inspect a controlled WIRED preset fixture and identify the first missing behavior; live client and extension validation remain open.

G-Presets reports an incomplete simulated import when placement acknowledgement is missing; next test a missing movement confirmation. Live client and extension validation remain open.

G-Presets completed a one-item simulated import over loopback; next verify its behavior when placement acknowledgement is absent. Live, WIRED and complex preset imports remain open.

G-Presets has a simulated staging selection and first placement acknowledgement; next exercise subsequent movement and complete the isolated import.

G-Presets rejects an invalid simulated staging tile and aborts cleanly; next exercise a valid staging tile and placement acknowledgement.

G-Presets starts a simulated preset import and requests a staging location; next simulate the selected tile and placement acknowledgement.

G-Presets import readiness now changes after simulated catalog and controller rights; next exercise a controlled import and placement acknowledgement.

G-Presets refuses the simulated import when catalog prerequisites are absent; next investigate catalog setup and a controlled placement acknowledgement fixture.

G-Presets reloads the simulated exported preset through its own parser; next inspect requirements for an isolated import fixture.

A dedicated COM AIR client reached the Rust relay and the hosts redirect cleared; decrypted traffic, real extensions and disconnect cleanup remain unverified. Computer Use was stopped; do not resume window control without the user.

An isolated G-Presets fixture exports a simulated floor item with synthetic furnidata and WIRED disabled; full live export/import remains open. The user opened Rust as administrator for the dedicated COM session.

G-Presets fixture JAR and data are now both copied or scoped to per-test temporary directories; next inspect a genuine offline preset export fixture.

G-Presets tests explicitly isolate their data directory on Windows and Linux; earlier Windows runs could write the existing cache. Next inspect prerequisites for a real offline preset export fixture.

G-Presets virtual multi-page inventory is tested in Windows loopback; next inspect prerequisites for a genuine offline preset export fixture.

G-Presets assembled 599, 600, 601 and 1201 item inventories in loopback; next exercise a multi-page response to its own virtual inventory request.

G-Presets virtual inventory request, response blocking and state update pass in Windows loopback; next exercise multi-page inventory across the Java 600-item boundary.

G-Presets command blocking and feedback injection are exercised in loopback; next test an extension-originated inventory request toward the simulated server. The AIR administrator launch was canceled and must not be retried automatically.

The dedicated Habbo COM AIR process and socket passed a read-only diagnostic; complete elevated attachment, encrypted traffic and cleanup without disturbing the existing FR/QX session.

G-Presets loopback fixtures now observe floor movement and wall state updates; the separate AIR session is being prepared, while the existing WIRED TEST session must remain untouched.

G-Presets inventory and room item changes now have observable loopback tests; the user has prepared a dedicated AIR session for real relay validation.

The released G-Presets binary exposes expected incremental inventory state through an isolated observer; next observe floor and wall item state and updates. Live hotel and preset workflows remain open.

The released G-Presets binary handles one floor and one wall room item in two isolated Windows relay sessions; next investigate its incremental inventory updates and observable state. Live hotel and preset workflows remain open.

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
