# Flash and attachment validation

Passing reference run: [41328870381](https://github.com/Tear1338/G-Earth-Rust/actions/runs/41328870381), implementation `8b3f924b78898ee2de8e7c3f6a9274c18536087e`.

All four validation jobs passed: Ubuntu core, Windows core, Windows desktop compilation and Java compatibility. Tests run for the whole Cargo workspace, including the native platform crate. Warnings are rejected by Clippy.

The Windows integration fixture runs a separate controlled process named Habbo.exe. The relay identifies the connecting process through Windows TCP ownership information, scans its actual private memory, finds RC4 word tables and handles the plaintext-to-encrypted transition. A mock server verifies blocking and replacement; the client and server verify injection in both directions and subsequent cipher state. No real client is launched and no real system hosts file is modified by this test.

Additional fixtures cover actual read-only process access and cancellation, exact-range memory reads, shuffled-table recognition, fragmented hello messages, coalesced plaintext/encrypted input, independent output counters and rejection of ambiguous reverse states that would corrupt a payload. Temporary hosts files verify conflicts, line injection rejection, scoped cleanup, preservation of later edits and explicit stale-redirect recovery. Packet caches are tested for direction/name preservation, version mismatch, truncation and atomic replacement.

The existing Java fixture and the 35-vector differential oracle still pass. This is evidence for the declared workloads, not proof of compatibility with a production AIR release or G-Presets. Live Flash/Origins, Nitro/Unity, OS certificate/proxy lifecycle, exact UI parity and whole-application performance remain unvalidated or unimplemented as listed in PARITY.md.

The final packaging check inspects PE imports without executing the EXE and rejects an unexpected external Visual C++ runtime dependency. See the latest Actions run for the exact packaged build.
