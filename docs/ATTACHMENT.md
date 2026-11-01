# Windows Flash / Origins attachment

This development build implements hostname routing and Flash RC4 discovery. Its automated tests use a controlled Windows process and temporary hosts files. A real official-client session has not yet been validated; Nitro, Unity, raw-IP redirection and full application parity remain outstanding.

1. Extract the Windows desktop artifact from the latest successful Actions run. Keep the original G-Earth installation available; Java extensions still require its Java runtime or an installed Java 21 runtime.
2. Close other proxies that own the original game port or have redirected the selected hostname. Run the Rust desktop with administrator rights if it must edit the Windows hosts file.
3. Open Connection, then Official client attachment. Select the hotel; the field also accepts a custom hostname. Flash uses port 30000, Origins 40001. For custom ports use the explicit relay fields and configure the test client endpoint accordingly.
4. Keep process selection on Automatic to identify the process from the accepted TCP connection. This allows starting the listener before opening/restarting Habbo and distinguishes concurrent clients. A manual process selection applies only to that live PID.
5. Click Attach official client, wait for the listener, then open/reconnect the client. Restarting the client can be necessary to clear its own DNS cache.
6. The application removes its hostname redirect after the TCP connection is accepted. Stop/normal exit also attempts cleanup. After a crash, close other Rust instances before using Recover redirects.

The application refuses to replace existing unowned hosts entries. Cleanup preserves unrelated entries and later edits. It never installs certificates or modifies system proxy settings. Do not enable explicit RC4 keys together with automatic discovery: explicit keys apply from byte zero; automatic mode starts at the negotiated transition.

Flash revision and client identifier come from the hello packet. The extension connection is initialized after loading identifiers for that revision, with a bounded HTTPS lookup and revision cache. A provider failure is displayed and the connection can continue without named headers. TSV/JSON imports remain available.

The Windows helper reads only the selected client's private writable memory; it does not inject code or write client memory. Scan time, bytes and candidate count are bounded. Unsupported layouts, unavailable processes and ambiguous recovery produce an error/timeout rather than a guessed key. No key material or memory dump is written to logs or saved in settings.

The native integration fixture covers actual process-memory reads, automatic TCP ownership, encrypted traffic in both directions, block/replace rules and injection. It supplies a controlled layout; passing it does not establish compatibility with every AIR release, endpoint or extension. G-Presets itself remains untested.
