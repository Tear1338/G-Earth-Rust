# Validation record

Furniture parsing has an additional differential fixture: JavaStuffOracle generates all eight state formats and one example each of floor furniture, wall furniture and an inventory item with the released beta-29 API JAR. Rust compares the resulting wire bytes and reads them back. The comparison is finite; these formats and entity parsing still need broader independent oracle coverage.

Windows Flash and hosts attachment have additional [native integration evidence](FLASH_VALIDATION.md), including automatic process identification, real cross-process memory reads, encrypted traffic and scoped cleanup. Latest passing reference: [41329358947](https://github.com/Tear1338/G-Earth-Rust/actions/runs/41329358947).

Earlier expanded transport and extension implementation validated at commit `1ece5611c846c04c919ce8ffc272df316115f8a2`:
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
| Java-versus-Rust performance | Packet microbenchmark only; whole application unmeasured |

The differential oracle compares 35 vectors: 18 original EVA/encoding vectors, four WEDGIE packet/message vectors and 13 Origins DH/HKDF/nonce/ChaCha vectors. The Java API comes from the pinned upstream Windows release, whose SHA-256 is verified before execution. BobbaCrypto classes are compiled from the pinned upstream commit and use the upstream release's Bouncy Castle dependency.

The Java fixture extends the actual beta-29 Extension class. It is launched with an authenticated file-bound token, receives the packet identifier database, injects a named packet, blocks a selected value and mutates traffic in both directions through an actual loopback TCP relay.

Additional tests cover fragmented/coalesced framing, cancellation, reconnect, logging backpressure, independent RC4 counters after block/injection, complete simulated encrypted Origins negotiation, byte-by-byte encrypted input fragmentation, SOCKS authentication/remote DNS, extension approval/replay/timeouts, expression syntax, atomic settings/migration and language resources.

Packet-provider parsing and extension language-update tests passed on Windows and Ubuntu in run 41256195145. The allocation optimization passed the Java oracle and Java extension fixture in run 41257089100; all core tests, Clippy and desktop compilation passed in that run as well.

A finite packet-construction microbenchmark is recorded in PERFORMANCE.md. Its result does not establish application-wide performance.

Nitro validation is documented in [NITRO.md](NITRO.md). Run [41334348534](https://github.com/Tear1338/G-Earth-Rust/actions/runs/41334348534) verifies the actual beta-29 Java extension over both TCP and a Nitro WebSocket, and five independent JCE hotel-crypto vectors. Separate web fixtures cover HTTP/WSS, rules/injections, Hubbe matching and rejection of an untrusted upstream certificate. Windows registry fixtures verify exact restoration, owner locking, crash-journal recovery and preservation of later user changes in isolated keys.

Ordinary runs skip environment-dependent Java tests; the dedicated Java job runs them explicitly. CI generates development artifacts. The validated Cargo.lock and rustfmt output have been imported directly. CI now checks formatting and uses locked dependencies.

Raw-IP validation uses fake command runners to compare Windows, Linux and macOS mapping arguments with beta-29, guard fixtures for cleanup/retry policy and a real loopback relay fixture proving consumption of preconnected upstream sockets with no direct fallback. Locked lease fixtures cover two owners, stale expiry, malformed-data preservation and last-owner-only mapping removal. No privileged command or real firewall/alias change is executed by automated tests. Real client/firewall and simultaneous multi-instance sessions remain unvalidated.

Passing these checks is finite protocol evidence, not a complete application port.

G-Python validation is documented in [GPYTHON.md](GPYTHON.md). The dedicated Windows/Linux jobs run published G-Python 0.1.6 inside a real Jupyter kernel, verify named interception, bidirectional injection/modification and blocking, check the kernel PID after stop, and start the real QtConsole with Qt in offscreen mode. The installer fixture separately creates an isolated virtual environment and validates the explicit package-installation path; a second fixture proves that pre-cancellation leaves the environment unchanged. Local Windows GNU validation passed all five G-Python tests on 2026-11-02, as well as core tests and core/desktop Clippy. The updated cross-platform Actions matrix has not run yet. Interactive visual parity and real hotel scripts remain untested.
