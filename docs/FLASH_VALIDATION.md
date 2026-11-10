# Flash and attachment validation

Passing reference run: [41329358947](https://github.com/Tear1338/G-Earth-Rust/actions/runs/41329358947), implementation `06741a3e157fb6bf9296264fc0329833a4720c52`.

All four validation jobs passed: Ubuntu core, Windows core, Windows desktop compilation and Java compatibility. Tests run for the whole Cargo workspace, including the native platform crate. Warnings are rejected by Clippy.

The Windows integration fixture runs a separate controlled process named Habbo.exe. The relay identifies the connecting process through Windows TCP ownership information, scans its actual private memory, finds RC4 word tables and handles the plaintext-to-encrypted transition. A mock server verifies blocking and replacement; the client and server verify injection in both directions and subsequent cipher state. No real client is launched and no real system hosts file is modified by this test.

Additional fixtures cover actual read-only process access and cancellation, exact-range memory reads, shuffled-table recognition, fragmented hello messages, coalesced plaintext/encrypted input, independent output counters and rejection of ambiguous reverse states that would corrupt a payload. Temporary hosts files verify conflicts, line injection rejection, scoped cleanup, preservation of later edits and explicit stale-redirect recovery. Packet caches are tested for direction/name preservation, version mismatch, truncation and atomic replacement.

The existing Java fixture and the 35-vector differential oracle still pass. This is evidence for the declared workloads, not proof of compatibility with a production AIR release or G-Presets. Live Flash/Origins, Nitro/Unity, OS certificate/proxy lifecycle, exact UI parity and whole-application performance remain unvalidated or unimplemented as listed in PARITY.md.

The packaging check passed: it inspects PE imports without executing the EXE and rejects an unexpected external Visual C++ runtime dependency. The archive includes the EXE, README, license and documentation. See the latest Actions run for the exact packaged build.

## Read-only official AIR diagnostic

Read-only Windows diagnostics were run against an already connected official AIR client on 2026-11-10: process enumeration and TCP owner matched the client, and an optimized scan read about 639 MB, completed and found one shuffled-table candidate. A debug scan hit its five-second limit after about 474 MB and found one candidate. No process memory or candidate values were logged. This does not prove that the candidate is an RC4 key, successful decryption, relay attachment or extension compatibility. An opt-in Windows test reproduces the process/socket/scan diagnostics without changing routing or the client.

On Windows, select an already established client socket and set `GEARTH_LIVE_PID`, `GEARTH_LIVE_LOCAL`, and `GEARTH_LIVE_REMOTE` to its process ID and local/remote socket addresses. Run `cargo test --release --test live_air_diagnostic -- --ignored --nocapture`. The diagnostic reads client private writable memory and reports aggregate counts; it does not modify process memory, routing or proxy settings. Scan completeness and candidate counts depend on process layout and timing.
