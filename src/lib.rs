//! Rust implementation of the EVA_WIRE packet core. See docs/PARITY.md for scope.
#![forbid(unsafe_code)]
pub mod crypto;
pub mod encoding;
pub mod expression;
pub mod extension;
pub mod packet;
pub mod relay;
pub mod rules;
pub mod scheduler;
