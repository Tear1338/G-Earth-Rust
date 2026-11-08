# G-Earth Rust migration progress

Last updated: 2026-11-08. Baseline: Java 1.5.4-beta-29; GitHub main `1cdf3365287b2036fb7c341a80e0b20fd8e3cdab`.

The migration is **not complete**. Implemented code and finite fixtures do not establish live-client compatibility or performance gains. See `docs/PARITY.md` and `docs/CONTINUATION.md` for detailed evidence and limitations.

## Implemented and partially validated

- Packet framing, primitive codecs, expressions, selected mutations and Java comparison fixtures.
- TCP, Nitro and Unity transports, rules, scheduler, logger, settings, packet metadata and an extension host.
- Rust desktop interface, Windows attachment helpers, G-Python integration, extension store and native data parsers.
- Selected original Java API and G-Presets binary compatibility fixtures; no live G-Presets or official hotel session established.
- Latest published commit adds scheduler/settings fixes, logger, extension handling, UI translations and additional Java differential tests.

## Remaining work

- Complete real end-to-end validation for Flash, Origins, Nitro and Unity, including encryption, reconnect, extensions, G-Presets and cleanup.
- Complete UI and behavior parity, translations, logger formatting, scheduler recovery, extension store and remaining Java packet APIs.
- Validate and extend Windows client discovery, multi-instance support, upstream proxy handling, and Linux/macOS platform support.
- Complete installer, signing, release QA and representative Java-versus-Rust performance benchmarks.
- Restore reliable CI across all targets and keep Java compatibility oracles running.

## Current issues and validation

- GitHub Actions run 42510568958 failed in the Linux/Windows core and web jobs: a settings unit test still rejected an offset equal to the interval after Java-compatible support was added. The test now checks equality is accepted and larger offsets rejected; the corrected unit passes locally. Java compatibility, G-Presets fixture and both G-Python jobs passed; desktop is still running.
- Local Git metadata remains behind GitHub main because the workspace `.git` is read-only. The working tree contains previously published changes; compare against the actual remote tree before publishing any new files.
- The complete local library run passed 39 of 41 tests; two relay socket tests failed because this environment denied local loopback connections (Windows error 10013). GitHub Actions is the independent network-fixture check.
- Official client/game workflows, performance benefit and full visual equivalence remain unverified.

## Exact next step

Inspect the GitHub Actions run for the scheduler boundary correction and resolve any remaining failures. Then compare the logger's automatic reconnection behavior with beta-29 and implement a verified missing behavior without depending on live-client access.
