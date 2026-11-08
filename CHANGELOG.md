# Changelog

## Unreleased

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
