# Rust migration architecture

Catalog index parsing has a 64-level depth limit, deliberately stricter than the observed beta-29 Java parser, and a shared node budget. A nested Java fixture verifies selected fields and cursor positions.

Catalog parsers distinguish Java list loops, where negative counts produce empty lists, from image/text arrays, where negative lengths fail. Positive counts and tree depth remain bounded.

The local metadata HTTPS test requires response writes to succeed but permits shutdown after the peer has already closed; this fixture does not replace live provider validation.

Friend fragment paging exposes corrected `construct_fragments` for client packets and bounded `construct_java_fragments`/`parse_fragment_java` for beta-29's repeated-tail and exact-boundary count behavior.

Friend updates expose `HFriendUpdate::parse_java` and `HFriend::construct_java_update` for beta-29's cursor/count and marker-omission behavior, alongside the valid wire-format constructors. Unknown relationship IDs remain readable as raw values, with `java_relationship_status` returning `None` and serialization rejecting them.

Profile and group parsers have beta-29 getter and normalized-byte fixtures covering flags, group collections and negative group counts; live behavior remains unverified.

Forum overview parsing has beta-29 getter and normalized-output fixtures for known and unknown view modes and multiple rows; these finite fixtures do not establish live parity.

Forum overview parsers follow Java's empty-list behavior for negative counts while retaining a bounded limit for positive counts. Unknown thread states normalize to the Java default when serialized.

Floor and wall collection construction resolves duplicate owners before rejecting a missing final owner name, as in beta-29. Rust sorts owner IDs while Java uses `HashMap`; parsed collection semantics are compared independently of ordering.

Inventory exposes corrected `construct_pages` for client-ready pages and bounded `construct_java_packets`/`parse_java` for the released Java API's distinct pagination and cursor behavior. Java's original emits incorrect counts at exact 600-item boundaries and includes subsequent items in earlier pages.

Java regex properties use generated Java 21 Latin-1 bitmaps for eight flag combinations. The generator and exhaustive oracle live in `tests/JavaRegexPropertyGenerator.java`; generated script and block name tables and their reproducible source generator are in `src/java_unicode_names.rs` and `tests/generate_java_unicode_names.py`.

Character classes support bounded nesting, union and recursively parsed intersection over Latin-1 sets, with per-operand case folding. Selected consecutive ampersand combinations match beta-29; full grammar parity remains unverified.

Possessive quantifiers use bounded atomic subprograms around their atom or group repetition. Width analysis distinguishes possessive group repetitions inside lookbehinds; beta-29 comparison remains finite.

Atomic groups reuse the bounded assertion subprogram mechanism but advance to the committed match endpoint. Their captures and rollback have finite beta-29 coverage.

Lookbehinds use minimum and maximum widths calculated from the regex tree, and run their bodies with a shared comparison budget and an expected end position. Width analysis detects selected nondeterministic repetitions and overflowing group bounds, following Java's study step. The 840-case beta-29 corpus exercises selected bounds and captures; wider combinations remain unverified.

The bounded regex VM evaluates lookaheads atomically with a shared comparison budget and retains selected positive and negative assertion captures after failed searches. Beta-29 differential fixtures include lookaheads inside repeated groups; wider combinations require further comparison.

Open-group backreferences retain the last closed capture in the bounded matcher, matching 250 beta-29 packet cases. Java regex parity remains partial.

The baseline is G-Earth 1.5.4-beta-29, upstream commit `242155c291b1109d6c9a02370f6a2af1ead41ea8`. This document describes the existing port, not a claim of complete equivalence.

| Area | Main implementation | Responsibility |
|---|---|---|
| Packet core | `src/packet.rs`, `encoding.rs`, `expression.rs`, `structure_prediction.rs` | Packet framing, fields, expression parsing and structure prediction. |
| Transports | `relay.rs`, `flash.rs`, `shockwave.rs`, `nitro*.rs`, `unity*.rs` | Client connection and protocol-specific traffic. Web transports use the `web` feature. |
| Traffic processing | `rules.rs`, `injection.rs`, `scheduler.rs`, `packet_safety.rs` | Rules, packet injection, schedules and observed-ID safety checks. |
| Extensions | `extension_host.rs`, `extension.rs`, `extension_store.rs`, `gpython.rs` | Extension IPC, lifecycle, installation and Python integration. |
| Client-facing data | `packet_info.rs`, `parsers/`, `admin_service.rs` | Metadata, selected Java API data structures and optional client-side controls. |
| Desktop | `desktop.rs`, `logger_display.rs`, `logger_filter.rs`, `i18n.rs` | eframe UI, logger and translations. |
| Settings and platform | `settings.rs`, `attachment.rs`, `crates/gearth-platform/` | Persistent preferences, attachment and OS-specific helpers. |

The shared `socks_http.rs` transport supplies bounded HTTPS metadata through SOCKS for both minimal and web builds; the minimal build therefore includes Tokio, Hyper and rustls. Web-specific proxy and City helper paths remain in `web_socks.rs`. Unity and Nitro share desktop SOCKS settings and the web proxy dialer; Unity communicator traffic remains local.

Packet substring replacement offers a bounded literal path and a bounded regex capture-group path with optional groups, repeated atoms and a limited capture-restoring repeated-group VM; neither implements general Java regex.

Compatibility is checked with Rust tests and selected fixtures generated by the released Java API; the CI workflow also exercises Java extensions, G-Presets and G-Python in controlled environments. Such fixtures do not establish compatibility with a live hotel. `docs/PARITY.md`, `docs/CONTINUATION.md` and `MIGRATION_PROGRESS.md` contain the limitations and evidence.

The packet core exposes signed and unsigned 8-bit operations and signed/unsigned EVA 16-bit operations, as well as cursor-preserving UTF-8 reads at absolute EVA offsets. Signed-short methods and UTF-8 offset reads currently reject WEDGIE formats; signed-byte replacement is also EVA-only. Strict UTF-8 reads reject malformed input, while optional replacement-decoding methods handle selected malformed sequences like Java; exhaustive equivalence is not established. Original Java and live Shockwave behavior have not been established for those WEDGIE paths.

The web-feature SOCKS module includes an asynchronous, cancellable SOCKS5 CONNECT primitive. It is not wired into Nitro; Hudsucker currently opens WebSockets directly, so enabling only an HTTP connector would leak around the configured proxy.

The pinned Hudsucker 0.25.0 source is vendored under `crates/hudsucker` with its licenses and an optional upstream dialer covering WebSockets and raw CONNECT. HTTP uses a separate connector. The hook is currently unused by Nitro; see its patch note and parity tracking.

`WebOptions::upstream_socks` now routes HTTP, HTTPS, WebSockets and raw CONNECT through the async SOCKS transport. Startup refuses this option when metadata fetching or the City helper is enabled until those auxiliary requests also support SOCKS.

When SOCKS is configured, Nitro metadata HTTPS now uses the same SOCKS transport and revision cache; redirects are HTTPS-only and bounded. The City helper still cannot be enabled with SOCKS.

With SOCKS configured, the session-opted-in Nitro City helper also uses authenticated SOCKS and bounded HTTPS; it does not follow upload redirects.

The desktop Nitro panel shares validated SOCKS settings with the relay, applies them to manual Nitro metadata retrieval and the browser proxy, and retains session-only City Helper opt-in. Unity still rejects SOCKS.

Flash and Origins metadata fetching uses the same SOCKS HTTPS path when `web` is enabled. A minimal no-web build refuses SOCKS metadata lookup rather than connecting directly; the relay continues without names.

Java global `(?u)` combined with `(?i)` now matches Latin-1 case pairs in literals and positive/negated classes; `(?u)` alone leaves case sensitive matching unchanged. All 65,536 Latin-1 pairs match Java 21 and 210 packet mutations match the released beta-29 API, including captures and flag combinations. The pair oracle also runs in CI. Thirty mutation tests, ten budget tests, both Clippy configurations and the desktop/web debug build pass locally. Full Java regex, embedded flags and live clients/extensions remain unverified.

Java global `(?U)` now enables Unicode predefined digit, word and whitespace classes, their complements, and word boundaries over Latin-1, and implies Unicode case folding when combined with `(?i)`. Java 21 comparisons cover all 256 bytes for each class and boundary, plus 200 packet mutations against the beta-29 API; both oracle checks run in CI. Thirty mutation tests, ten budget tests, both Clippy configurations and desktop/web debug compilation pass locally. Full Java regex and live clients/extensions remain unverified.

Unquantified Java non-capturing groups `(?:...)` now preserve nested captures and numbering, including empty groups. A 180-packet corpus matches the released beta-29 API. Quantifiers on non-capturing groups and unbalanced patterns are rejected transactionally; other regex semantics remain incomplete. Thirty-one mutation tests, ten budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Java non-capturing groups support bounded or unbounded greedy/reluctant repetition when the pattern has no captures and the repeated body consists of nonempty fixed-width atoms. A 140-packet corpus matches the released beta-29 API. Optional groups, repeated bodies containing quantifiers or assertions, and repeated non-capturing groups with captures remain rejected. Thirty-one mutation tests, ten budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Optional `(?:...)?` and reluctant `(?:...)??` groups now work in patterns without capture groups, including nesting and empty groups. A 140-packet corpus matches the released beta-29 API. Patterns combining optional non-capturing groups and captures are still rejected; full Java regex remains incomplete. Thirty-one mutation tests, ten budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Optional non-capturing groups can now contain or coexist with capture groups, including nested, named and empty groups. A 200-packet differential corpus checks Java beta-29 replacement bytes and cursor, including multiple capture references and greedy/reluctant forms. Thirty-one mutation tests, ten budget tests, both Clippy configurations and desktop/web debug compilation pass locally. Repeated non-capturing groups containing captures remain unsupported.

Greedy, non-capturing group repetitions with at least one iteration can now contain fixed-width captures; a 200-packet Java beta-29 corpus covers nested and named captures and suffix-driven backtracking. Non-greedy and zero-minimum repetitions with captures, capture ancestors, optional/repeated atoms within the body, and other complex structures remain rejected. Java retains a capture from a failed search attempt in a non-greedy zero-minimum case, while Rust clears it, so that form remains explicitly blocked. Thirty-one mutation tests, ten budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Java scoped inline regex flags for i, s, m, u and U, including disabling flags and nested restoration, now apply to the enclosed group. A 400-packet corpus matches the beta-29 Java API across captures, Unicode classes, anchors and repeat/optional forms; Java 21 confirms disabling U also disables Unicode case folding in that scope. Thirty-one mutation tests, eleven budget tests, both Clippy configurations and the desktop/web debug build pass locally. Unscoped flag changes inside a pattern, other flags and full regex semantics remain incomplete.

Java unscoped embedded regex flags i, s, m, u and U can now change within a pattern and restore their enclosing group state on exit. A 300-packet corpus matches the beta-29 Java API for nested changes, negation, Unicode case and line handling. Thirty-one mutation tests, eleven budget tests, both Clippy configurations and the desktop/web debug build pass locally. Unsupported Java flags and complete regex semantics remain open.

Java UNIX_LINES (?d) now applies to dot, multiline anchors, dollar and \Z, including scoped and embedded flag changes. Java 21 checks and 240 beta-29 packet comparisons cover LF, CR, CRLF, NEL, empty input and combinations with dotall/multiline. Thirty-one mutation tests, twelve budget tests, both Clippy configurations and desktop/web debug compilation pass locally. Complete Java regex and live client compatibility remain open.

Read-only Windows diagnostics were run against an already connected official AIR client on 2026-11-10: process enumeration and TCP owner matched the client, and an optimized scan read about 639 MB, completed and found one shuffled-table candidate. A debug scan hit its five-second limit after about 474 MB and found one candidate. No process memory or candidate values were logged. This does not prove that the candidate is an RC4 key, successful decryption, relay attachment or extension compatibility. An opt-in Windows test reproduces the process/socket/scan diagnostics without changing routing or the client.

Java COMMENTS (?x) mode now skips ASCII whitespace and # comments during regex parsing, including in classes, with scoped/embedded flag restoration, UNIX_LINES-aware comment endings, and literal escaped/quoted characters. A 380-packet beta-29 Java corpus covers these cases. The first character after a counted-closure brace remains unskipped as in Java; invalid examples are rejected transactionally. Thirty-two mutation tests, twelve budget tests, both Clippy configurations and desktop/web debug compilation pass locally. Full Java regex semantics remain incomplete.

Top-level Java regex alternation without captures now evaluates branches in source order, including empty alternatives, flags, anchors, optional atoms and supported repetitions. A 240-packet corpus matches the beta-29 API; nested alternatives and captures remain explicitly rejected. Thirty-three mutation tests, twelve budget tests, both Clippy configurations and desktop/web debug compilation pass locally. The full workspace suite and Windows GNU desktop/web release build passed for commit 68c5425; this does not establish live relay compatibility.

Top-level Java regex alternation now supports captures that end with their branch, including nested and named captures. A 200-packet beta-29 corpus checks branch order, unset groups, multiple references and named replacements. At that stage, branches with a fallible suffix after a capture, repeated capturing groups and nested alternation were conservatively rejected pending Java comparison. Thirty-three mutation tests, twelve budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Fixed-width reluctant non-capturing repetitions now retain captures from failed search starts like Java GroupCurly, and reset them between successful finds. The previously failing (?:(a)b)*?b case and 240 varied beta-29 packet comparisons pass, including nested/named/empty captures and bounded repetition. Greedy zero-minimum cases, nested repetition, alternatives with fallible capture suffixes and general capture restoration remain unsupported. Thirty-three mutation tests, thirteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Fixed-width greedy non-capturing repetitions now retain captures from the furthest explored iteration when backtracking, including zero-minimum repetition. A Java 21 probe exposed an earlier mismatch with different captures per iteration; a 240-packet beta-29 differential corpus and a focused regression test now cover it. Nested repetitions and alternatives with fallible capture suffixes remain unsupported. Thirty-three mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Top-level alternation now supports ordinary captures followed by a fallible suffix. Java 21 GroupTail restores ordinary captures when a branch fails; unlike GroupCurly nested captures, (a)c|b does not retain a failed capture. A 250-packet beta-29 corpus checks this behavior, nested and named captures, optional atoms and backtracking. Repeated capturing groups and nested alternation remain unsupported. Thirty-three mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Nested Java regex alternation without captures now uses a bounded branch-aware matcher, preserving ordered choices and backtracking through surrounding atom quantifiers. A 240-packet beta-29 corpus covers empty/nested branches, scoped flags and optional groups. Captures and repeated groups containing nested alternatives remain rejected; group nesting is capped at 128 for this matcher. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Nested Java regex alternation now supports ordinary capture groups with bounded GroupHead/GroupTail-style rollback, including named, empty and optional captures. A 240-packet beta-29 corpus checks branch choice and multiple replacement references. Quantified groups containing alternatives remain explicitly unsupported. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

A single quantified nested Java alternation group now supports greedy/reluctant and bounded repetitions with capture retention and zero-width-loop protection. The beta-29 oracle passes 280 packet cases plus 120 cases with nullable branches; internal progress captures cannot be referenced by replacement strings. Multiple repeated groups and some capturing-ancestor structures remain explicitly unsupported. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Multiple sequential quantified alternative groups and capturing ancestors now use separate bounded loop executions. A 250-packet beta-29 corpus covers greedy/reluctant combinations, nullable branches, named captures and bounded counts. Nested repeated groups remain rejected pending independent loop counters. The alternation matcher caps group nesting and repeated groups at 128. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

The bounded regex VM now uses persistent per-loop counters so nested repetitions restore their enclosing loop state during backtracking. A 200-packet beta-29 corpus covers nested greedy/reluctant and bounded alternative groups, named captures and nullable inner loops; the prior repetition budget tests still pass. The VM retains its 128-group and 262144-state bounds. Multiple repeated groups in patterns without nested alternation and other Java regex constructs remain incomplete. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Multiple fixed-width repeated groups now work even without nested alternation, including capturing ancestors and ordered top-level branches. A 250-packet beta-29 corpus covers greedy/reluctant and bounded cases, named captures and rollback. Repeated bodies containing variable-width constructs or nested captures remain conservatively rejected in this path pending GroupCurly comparison. The VM rejects more than 128 repeated groups before expensive validation. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Variable-width repeated Java groups without captures inside the repeated body now use the bounded loop VM, including nullable inner atoms and capturing ancestors. A 250-packet beta-29 corpus includes standalone and multiple greedy/reluctant repetitions. Repeated bodies containing captures still need GroupCurly-specific validation. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Variable-width repeated Java groups can now capture their own match in the bounded multi-group VM. A 250-packet beta-29 corpus covers greedy/reluctant repeats, nullable bodies, named captures, capturing ancestors and changing captures during backtracking. An attempted generic implementation of captures nested inside a repeated noncapturing group diverged from Java GroupCurly and remains explicitly rejected. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

For fixed-width deterministic repeated groups, the bounded VM now preserves nested captures using Java GroupCurly-style state across failed searches and backtracking, even alongside other repeated groups or capturing ancestors. A 250-packet beta-29 corpus covers varying captured bytes, greedy/reluctant bounds, named captures and branch changes; previous divergent cases now match. Variable-width bodies containing nested captures remain explicitly rejected. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Repeated Java groups with non-deterministic variable-width bodies can now contain nested captures; the bounded VM uses Loop-style rollback for optional captures and variable atom repetitions. A 250-packet beta-29 corpus matches named captures, nullable bodies, reluctant backtracking and capturing ancestors. Fixed-count inner repetitions and nested repeated groups in this GroupCurly-sensitive path remain explicitly rejected. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Fixed-count inner atom repetitions in deterministic GroupCurly-style groups now preserve nested captures during backtracking. A 250-packet beta-29 corpus covers zero/exact counts, named captures, reluctant repeats and optional ancestors. Nested repeated groups in this deterministic capture path remain conservatively rejected. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Nested repeated groups with captures now distinguish deterministic fixed-count bodies from non-deterministic bodies when selecting Java GroupCurly-style retention or Loop rollback. A 250-packet beta-29 corpus covers nested greedy/reluctant loops, exact counts, nullable bodies, named captures and capturing ancestors. Other regex constructs, performance limits and live relay behavior remain incomplete. Thirty-four mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Java numbered and named regex backreferences now use capture-aware bounded matching, including unmatched versus empty captures, Latin-1 case folding, optional and repeated references, and ordered alternatives. A 360-packet beta-29 oracle corpus passes. At that stage, open-group references and combinations with repeated groups were unsupported; subsequent work below addresses selected cases. Thirty-five mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.

Java backreferences can now be combined with repeated groups, including references inside deterministic bodies and capture retention across backtracking. A 240-packet beta-29 corpus covers named/numbered references, repeated references and changing captures between iterations. At that stage, references to a currently open group remained unsupported; subsequent work addresses selected cases; full Java regex behavior is not established. Thirty-five mutation tests, fourteen budget tests, both Clippy configurations and desktop/web debug compilation pass locally.
