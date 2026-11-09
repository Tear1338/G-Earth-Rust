# Local Hudsucker patch

This directory vendors the published `hudsucker` 0.25.0 crate from crates.io,
licensed under MIT OR Apache-2.0 (see the included licenses). The local patch
adds an optional TCP dialer for WebSocket and raw CONNECT upstreams so G-Earth
can route them through a SOCKS proxy without changing the original URI or TLS
verification. HTTP requests use the separately configured HTTP connector.
When no dialer is supplied, the upstream connection behavior remains unchanged.
Dialer failures must never fall back to a direct connection.

The original crates.io checksum is
`3a1d7c1c828ff6db12ddafb16768ecbac920df6301778d0eb78e95da0e44d94b`.
The local manifest also declares a standalone workspace, and Rust sources have
been formatted with the repository's stable `cargo fmt` check.
