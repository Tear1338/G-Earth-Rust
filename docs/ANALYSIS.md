# Source and REA analysis

Reference repository: https://github.com/G-Realm/G-Earth

Pinned tag: `1.5.4-beta-29`; commit: `242155c291b1109d6c9a02370f6a2af1ead41ea8`.

The GitHub tree at that tag has 675 entries and 347 Java source files. The full path inventory is retained in `UPSTREAM_FILES.tsv` to support continued porting. The protocol work was informed by HPacket.java, HMessage.java, HPacketFormat.java, NetworkExtensionCodec.java, NetworkExtensionMessage.java, HostInfo.java and PacketInfoManager.java at that exact tag.

REA was used to open the released `G-Earth-Api-1.5.4-beta-29.jar` and inspect its ZIP inventory. SHA-256: `7f318b32a793269eabb1afe2962887ede7d274f6da43b86323ce84d806ef3a51`. Inventory: 181 files, 40 directories, no reported integrity contradictions.

REA inventory is bounded static artifact evidence. It neither decompiles Java semantics nor establishes runtime behavior, whole-program equivalence or performance. The local evidence export is excluded from Git because it includes machine-specific paths. This repository publishes only the portable summary and source identity.

The Java compatibility CI job supplies behavioral evidence for a finite packet/encoding vector set by executing the actual upstream API JAR. The full application and its external native dependencies have not been exercised.

## Architecture

The standard-library-only core separates protocol, expressions, crypto, rules, scheduling and transport. The optional eframe desktop depends on the core. Packet processing runs on transport threads; bounded non-blocking log delivery prevents a slow UI from holding up network traffic. Individual write locks preserve complete frames during concurrent injection. Session cancellation shuts down both sockets before worker joins.

The relay deliberately exposes only its implemented unencrypted protocol. Unsupported packet formats are rejected in the extension codec. Provider integration is outstanding.

## Known limits

- A saturated logging queue drops observations; the UI observed count is not a network packet count.
- DNS resolution and connection setup are synchronous at relay creation. Stop may wait for an in-progress connection attempt's bounded timeout.
- Extension messages have codecs but no extension server or Java launcher.
- The desktop interface follows familiar G-Earth areas but is not pixel-identical or functionally complete.
- RC4 is provided only for compatibility work; it is not used automatically by the relay.
- Build and test outcomes are available in Actions; source inspection alone does not prove they pass.
