# G-Earth Rust migration progress

Last updated: 2026-11-08. Baseline: Java 1.5.4-beta-29; GitHub main `1cdf3365287b2036fb7c341a80e0b20fd8e3cdab`.

The migration is **not complete**. Implemented code and finite fixtures do not establish live-client compatibility or performance gains. See `docs/PARITY.md` and `docs/CONTINUATION.md` for detailed evidence and limitations.

## Implemented and partially validated

- Packet framing, primitive codecs, expressions, selected mutations and Java comparison fixtures.
- TCP, Nitro and Unity transports, rules, scheduler, logger, settings, packet metadata and an extension host.
- Rust desktop interface, Windows attachment helpers, G-Python integration, extension store and native data parsers.
- Selected original Java API and G-Presets binary compatibility fixtures; no live G-Presets or official hotel session established.
- Latest published commit adds scheduler/settings fixes, logger, extension handling, UI translations and additional Java differential tests.
- Compared logger reconnection against pinned beta-29 source: anti-spam history survives reconnects in Java. Rust now retains it as well; 5 local filter tests and desktop Clippy pass. Mode-switch semantics remain different.
- Manual extension launches now capture stdout/stderr for the extension console, like store launches. Host unit tests, a manually launched Python fixture and all-targets Clippy pass locally; real extensions still need validation. CI includes the Python fixture on Windows and Linux.

## Remaining work

- Complete real end-to-end validation for Flash, Origins, Nitro and Unity, including encryption, reconnect, extensions, G-Presets and cleanup.
- Complete UI and behavior parity, translations, logger formatting, scheduler recovery, extension store and remaining Java packet APIs.
- Validate and extend Windows client discovery, multi-instance support, upstream proxy handling, and Linux/macOS platform support.
- Complete installer, signing, release QA and representative Java-versus-Rust performance benchmarks.
- Restore reliable CI across all targets and keep Java compatibility oracles running.

## Current issues and validation

- GitHub Actions run 42510568958 failed in the Linux/Windows core and web jobs because a settings unit test still rejected an offset equal to the interval. The test was corrected. Follow-up run 42510869830 passed all eight validation jobs (Windows/Linux core, desktop, web, Java compatibility, G-Presets and G-Python on both systems); development publishing was skipped.
- Local Git metadata remains behind GitHub main because the workspace `.git` is read-only. The working tree contains previously published changes; compare against the actual remote tree before publishing any new files.
- The complete local library run passed 39 of 41 tests; two relay socket tests failed because this environment denied local loopback connections (Windows error 10013). GitHub Actions is the independent network-fixture check.
- Official client/game workflows, performance benefit and full visual equivalence remain unverified.

## Exact next step

Inspect the GitHub Actions run for the manual-extension console capture and fix any failures. Then compare Java and Rust logger anti-spam behavior when changing levels, including bounded memory and representative Java oracle cases; preserve the current implementation if exact behavior would introduce unbounded memory use.
