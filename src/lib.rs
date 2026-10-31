//! Rust implementation of the EVA_WIRE packet core. See docs/PARITY.md for scope.
#![forbid(unsafe_code)]
pub mod crypto;
pub mod encoding;
pub mod expression;
pub mod extension;
pub mod extension_host;
pub mod packet_info;
pub mod packet;
pub mod relay;
pub mod rules;
pub mod scheduler;
pub mod socks;
pub mod settings;
pub mod i18n;
