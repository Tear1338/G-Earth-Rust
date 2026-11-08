# G-Earth Rust migration progress

Last updated: 2026-11-08. Baseline: Java 1.5.4-beta-29; GitHub main `1cdf3365287b2036fb7c341a80e0b20fd8e3cdab`.

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
- The logger can select no primary byte representation, as in Java; importing valid Java logger settings selects it while preserving independently enabled byte views. Existing Rust installations retain their default expression view. Focused representation, settings, translation and desktop tests and desktop Clippy pass locally; interactive behavior remains unverified.
- An optional Java structure limit suppresses structure prediction for EVA packets over 2000 bytes (excluding their four-byte prefix). Java settings import enables it unless a Rust choice already exists; the default Rust behavior is retained. Local tests cover the boundary and exported output. Non-EVA behavior and interactive UI are not verified against Java.

## Remaining work

- Complete real end-to-end validation for Flash, Origins, Nitro and Unity, including encryption, reconnect, extensions, G-Presets and cleanup.
- Complete UI and behavior parity, translations, logger formatting, scheduler recovery, extension store and remaining Java packet APIs.
- Validate and extend Windows client discovery, multi-instance support, upstream proxy handling, and Linux/macOS platform support.
- Complete installer, signing, release QA and representative Java-versus-Rust performance benchmarks.
- Restore reliable CI across all targets and keep Java compatibility oracles running.

## Current issues and validation

- GitHub Actions run 42510568958 failed in the Linux/Windows core and web jobs because a settings unit test still rejected an offset equal to the interval. The test was corrected. Follow-up run 42510869830 passed all eight validation jobs (Windows/Linux core, desktop, web, Java compatibility, G-Presets and G-Python on both systems); development publishing was skipped.
- GitHub Actions run 42513347986 passed all eight validation jobs; its development publishing job was skipped. This run predates the no-byte-representation change, which has been validated locally but still needs its own complete CI result.
- Local Git metadata remains behind GitHub main because the workspace `.git` is read-only. The working tree contains previously published changes; compare against the actual remote tree before publishing any new files.
- The complete local library run passed 39 of 41 tests; two relay socket tests failed because this environment denied local loopback connections (Windows error 10013). GitHub Actions is the independent network-fixture check.
- Official client/game workflows, performance benefit and full visual equivalence remain unverified.

## Exact next step

Inspect GitHub Actions for the latest code commit and fix any failures. Compare the Java logger's structure cleaning and line output against Rust, then add a focused parity test while retaining existing Rust options.
