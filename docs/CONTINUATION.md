# Continuation state

The requested goal is a complete Rust replacement for G-Earth 1.5.4-beta-29, with original functionality and a GitHub project. The repository is Tear1338/G-Earth-Rust. It remains a development port; do not describe a passing component test as whole-application parity.

The upstream reference remains commit `242155c291b1109d6c9a02370f6a2af1ead41ea8`. Read PARITY.md, ATTACHMENT.md, FLASH_VALIDATION.md and VALIDATION.md, then inspect the current working tree and latest Actions run before changing code. External edits may have occurred since this note.

Implemented foundations include EVA/WEDGIE packets, expressions, RC4/Origins crypto, bounded relay, rules/schedules, settings/languages, packet providers/cache, a Java-compatible extension host, Windows Flash negotiation and read-only memory discovery, TCP-owner process selection and scoped hosts routing. Native memory and proxy tests use a controlled child process and temporary files. No real system hosts entries were changed during development tests.

The next major missing provider is Nitro. Its upstream implementation lives under `protocol/connection/proxy/nitro`, with common HTTP/TLS support in `protocol/connection/proxy/http` and hotel adapters in `services/nitro`. Preserve the hello-4000 fallback, exact hotel URL matching, per-hotel packet modifiers and beta-29 leet/habblet and TLS fingerprint behavior. A raw WebSocket relay alone is not equivalent to this provider.

Unity additionally requires the communicator, HTTP asset interception, framework/loader injection and validated WASM rewriting. See `services/unity_tools` and its four codepatchers, plus the bundled JS resources. The first communicator frame is the revision; subsequent binary frames begin with direction 0/1, followed by EVA_WIRE data. Do not label only the JSON packet-name provider as a Unity connection implementation.

Other missing areas include raw-IP redirection, non-Windows privileged helpers, the extension store/updater, the live Python console, exact UI/shortcuts/tray behavior, full localization and validation with real client sessions and G-Presets. Whole-application performance remains unmeasured; PERFORMANCE.md covers only packet construction.

REA artifact inspection supplied provenance. JEB/Ghidra were unavailable in this environment; the public pinned source and Java behavioral oracles supply semantic evidence. Do not claim unavailable decompilation or native replay succeeded.

Rust was not installed on the development host. Builds/tests run in Actions; validated rustfmt output and Cargo.lock must be recorded before requiring locked/check-only CI. Local Git history was synchronized with verified GitHub objects when normal network fetch was unavailable. The normal shell network cannot resolve external hosts in this sandbox, while the GitHub connector can fetch source, push reviewed trees and retrieve Actions artifacts/logs.

Do not add an automatic workflow push to main as a convenience: that write-access expansion was previously rejected. Source and dependency updates are published directly through the authorized GitHub connection. Development prerelease publishing has also encountered an integration-permission error; validated Actions artifacts remain the build distribution.
