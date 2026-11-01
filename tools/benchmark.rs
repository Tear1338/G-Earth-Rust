//! Finite packet-construction microbenchmark, not an end-to-end application benchmark.
use gearth_rust::packet::Packet;
use std::{hint::black_box, time::Instant};
fn sample(iterations: usize) -> (u128, u64) {
    let start = Instant::now();
    let mut checksum = 0u64;
    for i in 0..iterations {
        let mut p = Packet::new(123);
        p.put_i32(i as i32)
            .unwrap()
            .put_string("hello")
            .unwrap()
            .put_bool(true)
            .unwrap();
        let bytes = black_box(p.bytes());
        checksum = checksum.wrapping_add(bytes[9] as u64 + bytes.len() as u64);
        black_box(&p);
    }
    (start.elapsed().as_nanos(), checksum)
}
fn main() {
    let iterations = 250_000;
    for _ in 0..5 {
        black_box(sample(iterations));
    }
    println!("runtime,workload,iterations,nanoseconds,checksum");
    for _ in 0..5 {
        let (elapsed, checksum) = sample(iterations);
        println!("rust,construct_packet,{iterations},{elapsed},{checksum}");
    }
}
