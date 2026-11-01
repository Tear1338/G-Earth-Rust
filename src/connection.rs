//! Shared desktop controls for TCP and browser connections.
use crate::{
    packet::{Direction, Packet},
    relay::Relay,
    rules::Rules,
};
use std::io;
pub enum Connection {
    Tcp(Relay),
    #[cfg(feature = "web")]
    Web(crate::web_proxy::WebProxy),
    #[cfg(feature = "web")]
    Unity(crate::unity_connection::UnityConnection),
}
impl Connection {
    pub fn connected(&self) -> bool {
        match self {
            Self::Tcp(relay) => relay.connected(),
            #[cfg(feature = "web")]
            Self::Web(proxy) => proxy.connected(),
            #[cfg(feature = "web")]
            Self::Unity(proxy) => proxy.connected(),
        }
    }
    pub fn inject(&self, direction: Direction, packet: Packet) -> io::Result<()> {
        match self {
            Self::Tcp(relay) => relay.inject(direction, packet),
            #[cfg(feature = "web")]
            Self::Web(proxy) => proxy.inject(direction, packet),
            #[cfg(feature = "web")]
            Self::Unity(proxy) => proxy.inject(direction, packet),
        }
    }
    pub fn set_rules(&self, rules: Rules) -> io::Result<()> {
        match self {
            Self::Tcp(relay) => relay.set_rules(rules),
            #[cfg(feature = "web")]
            Self::Web(proxy) => proxy.set_rules(rules),
            #[cfg(feature = "web")]
            Self::Unity(proxy) => proxy.set_rules(rules),
        }
    }
}
