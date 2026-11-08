# Changelog

## Unreleased

- Logger: use the original localized incoming/outgoing labels in the display and export while retaining direction arrows.
- Document migration architecture and outstanding work in dedicated files. Existing history is recorded by Git commits and `docs/CONTINUATION.md`; this changelog begins with the current migration work.
- Logger: preserve Java-style direction capture on import; provide optional Java structure size and text filtering; support no primary byte view; order additional views as legacy, hexdump and raw hex when no primary view is selected.
- Logger: retain anti-spam history across reconnects and level changes with a bounded queue; retain the filtered count on clear and allow explicit reset.
- Manual extension launch: capture stdout and stderr for the extension console.
- Scheduler: accept a clock offset equal to the interval and update its boundary test.

These changes have focused tests; complete application parity and real-client validation remain outstanding. See `MIGRATION_PROGRESS.md` for exact validation and caveats.
