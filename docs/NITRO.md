# Nitro browser connections

The desktop's **Nitro / HTML5 browser** mode uses the Rust HTTP, HTTPS and WebSocket backend. It shares the packet logger, saved block/replace rules, scheduler, injection controls and Java extension host with TCP connections. This is a development implementation of beta-29 behavior; real hotel sessions have not been validated.

1. Select Nitro, choose a loopback listening address and prepare the public certificate.
2. On Windows, explicitly install that certificate for your current account if using automatic browser-proxy setup. The private key stays in the application's certificate-authority directory; it is never installed in the certificate store.
3. Start the browser proxy, then reload the hotel. The application restores the previous Windows proxy when the Nitro game connects, on Stop and on orderly exit. A journal and an exclusive owner lock allow the recovery button to restore an interrupted session without overwriting a later proxy owner.
4. When finished, stop the connection. The separate removal button removes this application's public certificate from your current-user Root store. It does not remove machine-wide roots.

With automatic Windows proxy setup disabled, configure a test browser to use the displayed proxy address and trust the public certificate in that browser. Linux/macOS system-proxy and certificate-store helpers are not implemented. The original Flash/Origins attachment mode remains separate.

## Hotel selection

The beta-29 list includes HabboCity, Hartico, HabboSK, Hubbe ST/BIZ and leet/habblet endpoints. Query strings are removed before matching; a final `*` matches a URL prefix. Unknown endpoints are recognized by a valid first outgoing EVA_WIRE packet with header 4000. Other WebSockets pass through.

Place an original-format `nitro.json` beside the application's settings file. Dynamic configurations take precedence over built-ins. The optional URL field in the UI also accepts one URL or prefix per line.

```json
[{"name":"My test hotel","websocketUrls":["wss://game.example.invalid/*"]}]
```

Hubbe ST bypasses its first outgoing binary prelude. HabboSK maintains independent RC4 read/write streams and changes keys after its random-key exchange. Hartico extracts its TripleDES key locally from the green-channel bits of the logo PNG and changes outgoing transport after the authentication packet.

HabboCity uses an authenticated AES-GCM handshake and independent AES-CTR streams derived from the SSO and salts. Import a Nitro Helper JSON result, or explicitly opt in for the current session to send the hotel's crypto WASM asset to `https://nitro.sulek.dev/habbocity`. The opt-in starts disabled, is not saved and only applies to that exact asset. No development test uploads an asset or contacts a hotel. Invalid/non-WASM files are rejected before the helper request.

Upstream certificates are validated on HTTP and WebSocket TLS connections. Tests can supply an additional root without modifying system trust. Chrome TLS fingerprint emulation is still missing; hotels that require that fingerprint can reject this client. Nitro SOCKS routing is also missing and produces an explicit error when a SOCKS setting is present.

## Evidence and limits

Fixtures cover plain HTTP, WSS with a private upstream root, rejection of an untrusted upstream root, packet blocking/replacement, bidirectional injection, dynamic configuration and the Hubbe prelude. Codec tests cover RC4, PNG key extraction, TripleDES authentication switching and GCM/CTR stream independence. Five independent Java JCE vectors check GCM with 12- and 16-byte nonces, TripleDES/CBC and segmented AES/CTR. An actual beta-29 Java extension fixture exercises the Nitro connection pipeline separately.

Registry tests use isolated `Software\G-Earth-Rust\Tests` keys and owned temporary files. They do not change the real Internet Settings key or certificate stores. Production cleanup is journaled before modifying settings; an external proxy change is preserved. Passing fixtures does not establish compatibility with every live hotel, G-Presets or the full original GUI.
