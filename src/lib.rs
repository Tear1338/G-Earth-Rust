//! Rust implementation of the EVA_WIRE packet core. See docs/PARITY.md for scope.
#![forbid(unsafe_code)]
pub mod attachment;
pub mod connection;
pub mod crypto;
pub mod encoding;
pub mod expression;
pub mod extension;
pub mod extension_host;
pub mod extension_store;
pub mod flash;
pub mod gpython;
pub mod i18n;
mod maven_version;
pub mod packet;
pub mod packet_info;
pub mod parsers;
mod raw_ip_lease;
pub mod relay;
pub mod rules;
pub mod schedule_file;
pub mod scheduler;
pub mod settings;
pub mod shockwave;
pub mod socks;
pub mod structure_prediction;
#[cfg(feature = "web")]
pub mod web_ca;
#[cfg(feature = "web")]
pub mod web_proxy;

#[cfg(feature = "web")]
pub mod nitro;

#[cfg(feature = "web")]
pub mod nitro_assets;

#[cfg(feature = "web")]
pub mod nitro_city;

#[cfg(feature = "web")]
pub mod unity_server;
#[cfg(feature = "web")]
pub mod unity_wasm;

#[cfg(feature = "web")]
pub mod unity_assets;
#[cfg(feature = "web")]
pub mod unity_connection;
