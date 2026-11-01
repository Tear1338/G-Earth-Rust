# Validation record

Expanded transport and extension implementation validated at commit `1ece5611c846c04c919ce8ffc272df316115f8a2`:
https://github.com/Tear1338/G-Earth-Rust/actions/runs/41255104561

| Check | Result |
|---|---|
| Core tests on Ubuntu and Windows | Passed |
| Core Clippy, warnings rejected | Passed |
| Optimized CLI on Ubuntu and Windows | Compiled |
| Windows desktop | Compiled |
| Actual beta-29 Java API wire oracle | Passed |
| Original Java Bobba crypto oracle | Passed |
| Actual beta-29 Java extension fixture | Passed |
| Native desktop visual test | Not performed |
| Official client/hotel connection | Not performed |
| Existing G-Presets binary | Not performed |
| Complete application equivalence | Incomplete; see PARITY.md |
| Java-versus-Rust performance | Not measured |

The differential oracle compares 35 vectors: 18 original EVA/encoding vectors, four WEDGIE packet/message vectors and 13 Origins DH/HKDF/nonce/ChaCha vectors. The Java API comes from the pinned upstream Windows release, whose SHA-256 is verified before execution. BobbaCrypto classes are compiled from the pinned upstream commit and use the upstream release's Bouncy Castle dependency.

The Java fixture extends the actual beta-29 Extension class. It is launched with an authenticated file-bound token, receives the packet identifier database, injects a named packet, blocks a selected value and mutates traffic in both directions through an actual loopback TCP relay.

Additional tests cover fragmented/coalesced framing, cancellation, reconnect, logging backpressure, independent RC4 counters after block/injection, complete simulated encrypted Origins negotiation, byte-by-byte encrypted input fragmentation, SOCKS authentication/remote DNS, extension approval/replay/timeouts, expression syntax, atomic settings/migration and language resources.

Packet-provider parsing and extension language-update tests were added after the run above; their results must be checked in the latest Actions run before use:
https://github.com/Tear1338/G-Earth-Rust/actions

Ordinary core runs skip the two environment-dependent Java tests; the dedicated Java job runs them explicitly. CI generates development artifacts. Temporary bootstrap CI generates Cargo.lock and formatted source; after importing those artifacts, validation is switched back to locked dependencies and formatting checks.

Passing these checks is finite protocol evidence, not a complete application port.
