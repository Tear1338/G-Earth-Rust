# Windows Flash / Origins attachment

This development build implements hostname routing, Flash Raw-IP routing and Flash RC4 discovery. Its automated tests use a controlled Windows process, temporary hosts files, mocked privileged mapping commands and real loopback sockets. A real official-client/firewall session has not yet been validated; full application parity remains outstanding.

1. Extract the Windows desktop artifact from the latest successful Actions run. Keep the original G-Earth installation available; Java extensions still require its Java runtime or an installed Java 21 runtime.
2. Close other proxies that own the original game port or have redirected the selected hostname. Run the Rust desktop with administrator rights if it must edit the Windows hosts file.
3. Open Connection, then Official client attachment. Select the hotel; the field also accepts a custom hostname. Flash uses port 30000, Origins 40001. For custom ports use the explicit relay fields and configure the test client endpoint accordingly.
4. Keep process selection on Automatic to identify the process from the accepted TCP connection. This allows starting the listener before opening/restarting Habbo and distinguishes concurrent clients. A manual process selection applies only to that live PID.
5. Click Attach official client, wait for the listener, then open/reconnect the client. Restarting the client can be necessary to clear its own DNS cache.
6. The application removes its hostname redirect after the TCP connection is accepted. Stop/normal exit also attempts cleanup. After a crash, close other Rust instances before using Recover redirects.

The application refuses to replace existing unowned hosts entries. Cleanup preserves unrelated entries and later edits. It never installs certificates or modifies system proxy settings as part of TCP attachment. Do not enable explicit RC4 keys together with automatic discovery: explicit keys apply from byte zero; automatic mode starts at the negotiated transition.

## Raw IP (Flash only)

Enter the hotel's **IPv4 address** instead of a hostname and use port 30000. Raw IP listens on `0.0.0.0:30000`, matching the original provider. Direct mode opens three server connections before installing the mapping, preventing the relay from intercepting its own upstream traffic. SOCKS mode creates its upstream through the configured proxy instead. Direct mode never falls back to a new connection after the preconnected pool is exhausted.

- **Windows:** runs the original `netsh` DNS-enable command, adds the hotel `/32` alias to the `Loopback` interface, keeps that alias for the session and deletes it on stop. The original enable command sets DNS on interface `1` to DHCP; review this side effect before use. Administrator rights and an interface named `Loopback` are required.
- **Linux:** adds/deletes the original `iptables` NAT `OUTPUT` DNAT rule to `127.0.0.1`. The rule is not port-scoped, matching beta-29, and therefore redirects all TCP ports to the selected hotel IP while active. Root or `CAP_NET_ADMIN` is required.
- **macOS:** adds/deletes the original `ifconfig lo0` alias. Root privileges are required. This path is implemented but has not been executed on macOS.

On non-Windows systems the mapping is removed after the client/server connection is accepted. On Windows it remains until stop/normal exit so the established connection keeps its route. Cleanup is retried after an ordinary failure, but a crash can leave an alias or NAT rule behind. The beta-29 Windows shared heartbeat/cache that coordinates several G-Earth instances is not ported yet; use only one Raw-IP instance per hotel.

Tests verify exact command arguments through fake runners, idempotent/retryable guard cleanup and real bidirectional use of preconnected sockets. They never invoke `netsh`, `iptables` or `ifconfig`. Actual privileged commands, the original client's routing, crash recovery and multi-instance behavior still require validation on disposable systems.

Flash revision and client identifier come from the hello packet. The extension connection is initialized after loading identifiers for that revision, with a bounded HTTPS lookup and revision cache. A provider failure is displayed and the connection can continue without named headers. TSV/JSON imports remain available.

The Windows helper reads only the selected client's private writable memory; it does not inject code or write client memory. Scan time, bytes and candidate count are bounded. Unsupported layouts, unavailable processes and ambiguous recovery produce an error/timeout rather than a guessed key. No key material or memory dump is written to logs or saved in settings.

The native integration fixture covers actual process-memory reads, automatic TCP ownership, encrypted traffic in both directions, block/replace rules and injection. It supplies a controlled layout; passing it does not establish compatibility with every AIR release, endpoint or extension. G-Presets itself remains untested.
