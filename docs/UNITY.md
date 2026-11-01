# Unity WebGL

Select **Browser client (Nitro / Unity)** and choose **Unity WebGL**. Prepare the public certificate and explicitly install it for your Windows account if using automatic browser-proxy setup. Start the browser proxy, then reload the official WebGL client. Packet identifiers use the bundled beta-29 messages.json unless you select another JSON/TSV file.

The Rust backend binds a TLS communicator to loopback and generates a fresh session token. It patches only the five original images.habbo.com WebGL asset routes: Version.txt, data.gz, wasm.gz, framework.js.gz and loader.js. Data payloads pass through; modified responses discard cache validators, update their length and retain their gzip envelope. The framework receives the revision, local port and token.

WASM rewriting locates all four beta-29 signatures before changing anything. The key hook runs before its original body. Incoming, outgoing and return-byte hooks retain original exported copies for reinjection. The re-encoder remaps calls, exports, tables, globals and start references and validates the resulting module. Missing or ambiguous hooks produce an error. Cache entries are bound to the original WASM SHA-256 and patch format, and corrupted entries are regenerated.

The communicator accepts the revision and direction-prefixed EVA_WIRE packets. It shares logging, rules, scheduling, injections and the original Java extension IPC. It bounds handshakes, frames and queues and supports reconnect. The browser bridge falls back to its original functions after the communicator closes.

The previous Windows proxy is restored when the game connects, on Stop and on orderly exit; the existing recovery journal handles interrupted sessions. Linux/macOS proxy and trust-store helpers still require work.

Controlled tests execute patched WASM, the browser hooks and a real authenticated TLS WebSocket against Rust, including block/replace, bidirectional injection and disconnect fallback. Separate tests run the original released G-Wasm JAR and pinned Java patchers through the same WASM runtime assertions. A real beta-29 Java extension exercises Unity name lookup, injection and mutations. These fixtures do not establish compatibility with a live official client revision or G-Presets.
