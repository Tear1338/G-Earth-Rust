# Changelog

- Test Nitro metadata success, HTTP failure, malformed and truncated responses, the size limit and cancellation over verified local HTTPS; verify extension forwarding after errors.
- Test that cancelled Nitro metadata lookups cannot replace a newer extension session.
- Load missing Nitro metadata without an extension host, with bounded cancellable lookup and an offline option.
- Reject Nitro metadata labeled for a different revision and test Unity static metadata across revisions.
- Load Flash packet metadata even when no extension host is active.
- Reject stale or unversioned preloaded metadata after automatic Flash revision detection.
- Synchronize the G-Python fixture shutdown after the host receives the final interception response.
- Compare UTF-16 replacement and long/short-field boundaries against Java.
- Encode Java UTF-16 code units, including unpaired surrogates, in five packet charsets.
- Add explicit UTF-16LE and BOM-sensitive UTF-16 packet string variants.
- Add strict and Java-style replacement UTF-16BE packet string operations.
- Compare Java Latin-1 replacement encoding across all Unicode scalar values and short-field boundaries.
- Add explicit Java-style ISO-8859-1 replacement encoding for EVA packet strings and typed fields.
- Add typed EVA packet field appends for the eight Java `appendObject` categories.
- Support Java `$0` and escaped replacement templates for nonempty literal substring patterns; full regex support remains open.
- Extend Java height-format comparisons to negative subnormals, powers of ten and entity/furniture packet bytes.
- Align selected Java 21 scientific height formatting, including smallest subnormal values.
- Parse Java-style decimal and hexadecimal floating-point height strings for entities and floor items.
- Align selected entity-update action delimiters and integer sign parsing with the Java API.
- Added a Flash oracle case demonstrating the shared false-identification risk on ordinary two-string packets.
- Stop Flash metadata initialization on visible peer EOF during lookup and preserve any prior extension session.
- Make Flash metadata waits cancellable on explicit stop, with bounded in-flight worker lookups; test empty-revision failure and a stalled provider through the relay.
- Register metadata packet identifiers as safe by revision and direction for TCP, Flash, Nitro and Unity, matching the Java connection.
- Added a controlled Flash relay and extension lifecycle fixture for identity variants.
- Flash identification accepts empty revisions and trailing fields like the pinned Java handler; the oracle also documents fragmentation differences.
- Added 36,864 targeted UTF-8 boundary combinations to the Java decoding oracle.
- Added 20,000 deterministic mixed byte strings of lengths 3–12 to the Java UTF-8 differential oracle.
- Expanded the beta-29 Java UTF-8 differential oracle to every two-byte sequence and mixed input at six short-field length boundaries; this is finite coverage.

## Unreleased

- EVA UTF-8 replacement decoding now treats malformed surrogate encodings like Java for the tested cases, instead of replacing each byte separately.
- EVA packets: add optional replacement-decoding UTF-8 reads for malformed short/long fields, including cursor-preserving offset reads.
- EVA packets: add cursor-preserving short/long byte and strict UTF-8 reads at an absolute offset, with Java API comparisons for valid strings.
- Packet core: add signed-byte read, random-access read, append and EVA replacement; compare negative boundary values with the original Java API.
- EVA packets: add signed 16-bit read, random-access read, append and replacement; compare boundary values and cursor behavior with the beta-29 Java API.
- Extend the Java hexdump differential fixture around the 256-byte boundary and to 1024 bytes.
- Java settings import preserves an explicitly selected Rust logger representation; imports without a choice still default to no primary byte view.
- Logger: exercise primary and secondary clicks on an empty-header row using simulated egui pointer events.
- Logger: optionally hide empty byte-view headers on screen and in copied displayed text; retain row actions through the row area.
- Logger: optionally omit empty byte-view headers from exported captures, retaining metadata and separators. The on-screen view and copy-displayed action retain their header.
- Logger: allow exports to include separators independently of the on-screen separator setting; Java preference imports enable this unless an explicit Rust choice exists.
- Logger: use the original localized incoming/outgoing labels in the display and export while retaining direction arrows.
- Document migration architecture and outstanding work in dedicated files. Existing history is recorded by Git commits and `docs/CONTINUATION.md`; this changelog begins with the current migration work.
- Logger: preserve Java-style direction capture on import; provide optional Java structure size and text filtering; support no primary byte view; order additional views as legacy, hexdump and raw hex when no primary view is selected.
- Logger: retain anti-spam history across reconnects and level changes with a bounded queue; retain the filtered count on clear and allow explicit reset.
- Manual extension launch: capture stdout and stderr for the extension console.
- Scheduler: accept a clock offset equal to the interval and update its boundary test.

These changes have focused tests; complete application parity and real-client validation remain outstanding. See `MIGRATION_PROGRESS.md` for exact validation and caveats.
