# Packet construction microbenchmark

Measured build: c3953b88a8ecd328d7c28dc039a1896f8f68cc10.
Run: https://github.com/Tear1338/G-Earth-Rust/actions/runs/41257089100

The same Ubuntu runner executed the actual beta-29 Java HPacket and optimized Rust Packet. Each sample constructs 250,000 packets: header 123, i32 loop index, Latin-1 string "hello", and true boolean. Both emit checksum 36366936. Five warm-up batches precede five measured batches. Startup is excluded; Rust uses a release build and Java a warmed Java 21 JVM with a 256 MiB heap.

| Sample | Java ms | Rust ms |
|---|---:|---:|
| 1 | 22.392267 | 11.838897 |
| 2 | 22.510224 | 8.213739 |
| 3 | 21.587073 | 17.366550 |
| 4 | 22.797162 | 10.058729 |
| 5 | 23.024518 | 8.233076 |
| Median | 22.510224 | 10.058729 |

The median ratio is about 2.24 for this workload. Rust reserves room for a small packet and appends ASCII short strings directly, avoiding temporary allocations. Earlier unoptimized Rust results were slower than Java; they remain in development-11 downloads.

This is a narrow microbenchmark, not an end-to-end speed claim. Samples show runner noise, implementations have different allocation/GC behavior, and Java and Rust optimizer barriers differ. No confidence interval, network latency, memory peak, GUI throughput, large-packet workload or real hotel session was measured. The full application cannot yet be compared at feature parity.

Reproduce using tests/JavaBenchmark.java against the pinned API JAR and cargo run --release --bin gearth-benchmark. CSV measurements accompany the development release.
