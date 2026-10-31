# Validation record

Run: https://github.com/Tear1338/G-Earth-Rust/actions/runs/41251832791

Tested implementation commit: `ee66c4fe8455d3e596d2621ec2e18f9b4a8f00e5`.

| Check | Result |
|---|---|
| Core on Ubuntu | Passed |
| Core on Windows | Passed |
| Clippy on both core builds, warnings rejected | Passed |
| Optimized CLI builds on Windows/Linux | Passed |
| Windows desktop release compilation | Passed |
| Byte comparison against actual beta-29 Java API | Passed for the finite oracle vector set |
| Native desktop visual test | Not performed |
| Official Habbo client connection | Not performed; providers missing |
| Existing Java extension / G-Presets | Not performed; host missing |
| Whole-application parity | Incomplete; see PARITY.md |
| Performance versus the Java application | Not measured |

Core coverage includes 22 packet/encoding/crypto/rules/scheduler tests and five TCP loopback tests. The Java oracle is a separate CI job and is explicitly ignored in ordinary core test runs. It checks 18 emitted vectors covering packets, Latin-1, numeric fields, HMessage serialization, VL64 values and a B64 value.

The TCP tests exercise both directions, concurrent injection, blocking, replacement, reconnection, truncated frames, cancellation and logging backpressure. The Windows blocking-reader failures were corrected by using a nonblocking event loop with bounded output queues and explicit partial-write offsets.

The source was formatted with rustfmt, and Cargo.lock records the dependency resolution used by the build. Subsequent CI runs enforce formatting and use locked dependencies.

Passing these tests does not establish complete equivalence with G-Earth beta-29. The Windows executable is a development build.
