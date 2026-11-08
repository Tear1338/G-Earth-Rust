# G-Earth Rust migration progress

Last updated: 2026-11-08. Baseline: Java 1.5.4-beta-29; current status and changes are tracked in the GitHub main branch.

The migration is **not complete**. Implemented code and finite fixtures do not establish live-client compatibility or performance gains. See `docs/PARITY.md` and `docs/CONTINUATION.md` for detailed evidence and limitations.

## Implemented and partially validated

- Packet framing, primitive codecs, expressions, selected mutations and Java comparison fixtures.
- TCP, Nitro and Unity transports, rules, scheduler, logger, settings, packet metadata and an extension host.
- Rust desktop interface, Windows attachment helpers, G-Python integration, extension store and native data parsers.
- Selected original Java API and G-Presets binary compatibility fixtures; no live G-Presets or official hotel session established.
- Latest published commit adds scheduler/settings fixes, logger, extension handling, UI translations and additional Java differential tests.
- Compared logger reconnection and level switching against pinned beta-29 source. Rust retains anti-spam history across reconnects and all level switches, including disabled mode. The per-header queue is deliberately capped at 15 timestamps, unlike Java, so extreme traffic can differ.
- Manual extension launches now capture stdout/stderr for the extension console, like store launches. Host unit tests, a manually launched Python fixture and all-targets Clippy pass locally. All eight validation jobs in Actions run 42511342499 passed, including the new Python fixture on Windows and Linux; real extensions still need validation.
- A deterministic test compares selected anti-spam level transitions, including disabled mode, with a direct model of the pinned Java queue algorithm. Seven local filter tests and a 10,000-packet bounded-memory test pass. This is a behavioral model, not execution of the original JavaFX controller; extreme unbounded traffic is deliberately different.
- Comparing the original Java logger confirmed clearing displayed packets does not reset the filtered counter. Rust now preserves that counter and offers a separate reset button. Seven desktop logger tests, eleven translation tests and desktop Clippy pass locally; interactive use remains unverified.
- The Windows logger can choose a .txt export path in a native save dialog. Windows filter tests, five capture tests and desktop Clippy pass; selecting the path and exporting still require separate actions and the dialog remains untested interactively.
- Logger has an optional Java-like capture mode that discards unchecked directions after anti-spam while leaving previously captured rows visible; the default retains Rust's existing reversible display filter. Direction combinations, preference persistence, translations and desktop Clippy pass locally; interactive validation remains outstanding.
- Logger timestamps use the original localized label on their own line in the display and text export. Seven desktop logger tests and desktop Clippy pass; visual layout and timing in a live session remain unverified.
- Blocked/replaced markers now use localized bracketed labels on their own line in the logger and export, as in the Java controller. Seven desktop tests and Clippy pass locally; full metadata layout and live visuals remain unfinished.
- Logger names, hashes and IDs use individual brackets on a line preceding blocked/replaced markers, following the original Java ordering for tested cases. Desktop tests cover multiple names and hashes; metadata remains size bounded and visual behavior is unverified.
- Importing valid Java logger settings now enables Java-like direction capture unless an explicit Rust preference already exists. Fourteen settings integration tests, seven settings unit tests and all-targets Clippy pass locally.
- The logger can select no primary byte representation, as in Java; importing valid Java logger settings selects it when no Rust choice exists, while preserving independently enabled byte views. Existing Rust installations retain their default expression view. Focused representation, settings, translation and desktop tests and desktop Clippy pass locally; interactive behavior remains unverified.
- An optional Java structure limit suppresses structure prediction for EVA packets over 2000 bytes (excluding their four-byte prefix). Java settings import enables it unless a Rust choice already exists; the default Rust behavior is retained. Local tests cover the boundary and exported output. Non-EVA behavior and interactive UI are not verified against Java.
- An optional Java structure text filter hides expressions that Java's `cleanTextContent` would change. Its decision is made before Rust truncates long output, and is cached independently of the option, so toggling it affects retained packets. Tests cover control characters, Unicode, export and settings import; interactive UI and full Java-generated expression parity remain unverified.
- When no primary byte representation is chosen, additional logger views now follow Java's legacy, hexdump, raw-hex order in display and export. A desktop export regression test covers the three views; other primary-view combinations and exact Java formatting still differ.
- Added `MIGRATION_TODO.md`, `MIGRATION_ARCHITECTURE.md` and `CHANGELOG.md` to track individually scoped work, the Rust architecture and recent changes. The matrix describes partial work and does not mark live compatibility complete.
- Logger direction text now uses the original localized incoming/outgoing labels in display and export, retaining Rust direction arrows. Local UI-rendering/export tests, translations, desktop Clippy and a debug build pass; Java's exact header layout and interactive appearance remain unverified.
- Logger exports can include a separator for every packet even when on-screen separators are disabled; importing Java settings enables this unless already chosen in Rust. Focused settings, translation, export and desktop tests and debug compilation pass. Java renders and exports its separator as part of the log itself, so Rust's independent export option is not exact visual parity.
- Logger exports can omit the byte-view header when no byte views are selected, as Java does. Java settings import enables this unless an explicit Rust choice exists. Metadata and separators remain. Focused settings, translation, desktop/export tests, Clippy and debug compilation pass; full Java output formatting and visual behavior remain different.
- An independent screen option hides that header when every byte view is disabled; copied displayed text follows the on-screen setting. Java settings import enables it unless an explicit Rust preference exists. Focused tests cover selection logic, settings and export, and desktop compilation; visual appearance and row interactions need interactive validation. Other Java layout differences remain.
- A simulated egui pointer test verifies that primary and secondary clicks reach the hidden-header row. Eight desktop logger tests, focused logger/settings tests, desktop Clippy and a debug build pass; the full visual application and actual context-menu flow still require interactive testing.
- Importing Java logger settings now preserves an explicitly selected Rust primary representation, which has no direct Java equivalent; without a saved choice it still selects no primary byte view. Tests cover both import cases and save/reload, plus preservation of an explicit hidden-header choice. Settings/logger integration tests, 41 library tests excluding two blocked socket cases, desktop Clippy and a debug build pass.
- Ran the original beta-29 Java hexdump implementation against Rust locally using Java 21. The byte-for-byte oracle passes 13 lengths from zero through 1024 bytes, including 255, 256 and 257; this is finite formatting coverage, not live-client validation.
- EVA packet API now has signed 16-bit sequential and absolute-offset reads, append and replacement. Boundary values, replacement bytes and cursor behavior match selected beta-29 Java API vectors; local tests cover truncation, protected headers and explicit WEDGIE rejection. The Java oracle, 41 available library tests, workspace/all-targets Clippy and a debug CLI build pass; real-client and WEDGIE signed-short semantics remain unverified.
- Signed-byte sequential/absolute reads and append now complement unsigned byte operations, with EVA replacement. Selected negative and boundary values, replacement bytes and cursor behavior match the beta-29 Java API oracle. Local mutation tests, 41 available library tests, all-targets Clippy and a debug CLI build pass; WEDGIE and real extensions remain unverified.

## Remaining work

- Complete real end-to-end validation for Flash, Origins, Nitro and Unity, including encryption, reconnect, extensions, G-Presets and cleanup.
- Complete UI and behavior parity, translations, logger formatting, scheduler recovery, extension store and remaining Java packet APIs.
- Validate and extend Windows client discovery, multi-instance support, upstream proxy handling, and Linux/macOS platform support.
- Complete installer, signing, release QA and representative Java-versus-Rust performance benchmarks.
- Restore reliable CI across all targets and keep Java compatibility oracles running.

## Current issues and validation

- GitHub Actions run 42510568958 failed in the Linux/Windows core and web jobs because a settings unit test still rejected an offset equal to the interval. The test was corrected. Follow-up run 42510869830 passed all eight validation jobs (Windows/Linux core, desktop, web, Java compatibility, G-Presets and G-Python on both systems); development publishing was skipped.
- GitHub Actions run 42513347986 passed all eight validation jobs; its development publishing job was skipped. The GitHub commits page subsequently showed eight successful checks and one skipped check for commit `9d58e65`, and successful checks for the earlier no-byte-representation and size-limit commits. The byte-view ordering commit requires its own CI result.
- Local Git metadata remains behind GitHub main because the workspace `.git` is read-only. The working tree contains previously published changes; compare against the actual remote tree before publishing any new files.
- The latest complete local library run passed 41 tests, failed two relay socket tests because this environment denied local loopback connections (Windows error 10013), and ignored one Python fixture. Focused logger/settings integration tests, desktop logger tests, formatting and a desktop debug build passed. GitHub Actions is the independent network-fixture check.
- Windows GNU release build succeeded for the source of commit `3ec69f57cfc29bb930b68fae0c306ebfa4c23c1d`; only the hexdump test cases changed during that build. The release is not a live-client or visual validation.
- Official client/game workflows, performance benefit and full visual equivalence remain unverified.

## Exact next step

Inspect GitHub Actions for the latest code commit and fix any failures. Compare the remaining Java packet primitive and mutation APIs with Rust, then implement the next independently testable EVA operation; validate the no-byte-view logger interaction visually when a safe desktop test session is available.
