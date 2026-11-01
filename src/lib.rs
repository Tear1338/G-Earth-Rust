//! Rust implementation of the EVA_WIRE packet core. See docs/PARITY.md for scope.
#![forbid(unsafe_code)]
pub mod crypto;
pub mod attachment;
pub mod flash;
pub mod encoding;
pub mod expression;
pub mod extension;
pub mod extension_host;
pub mod i18n;
pub mod packet;
pub mod packet_info;
pub mod relay;
pub mod rules;
pub mod scheduler;
pub mod settings;
pub mod shockwave;
pub mod socks;
