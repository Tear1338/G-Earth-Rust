//! Client-side permissions display, matching beta-29's AdminService heuristic.
use crate::packet::{Direction, Message, Packet, PacketFormat};

#[derive(Default)]
pub struct AdminService {
    enabled: bool,
    original: Option<Packet>,
}
impl AdminService {
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    pub fn on_connect(&mut self) {
        self.original = None;
    }
    pub fn set_enabled(&mut self, enabled: bool) -> Option<Packet> {
        if self.enabled == enabled {
            return None;
        }
        self.enabled = enabled;
        self.original.as_ref().map(|packet| {
            let mut packet = packet.clone();
            if enabled {
                Self::modify(&mut packet);
            }
            packet
        })
    }
    fn modify(packet: &mut Packet) {
        // The caller has checked the complete EVA wire frame length.
        packet.replace_i32(6, 7).expect("validated packet");
        packet.replace_i32(10, 7).expect("validated packet");
        packet.replace_bool(14, true).expect("validated packet");
    }
    pub fn on_message(&mut self, message: &mut Message) {
        let packet = &mut message.packet;
        if !self.enabled
            || message.direction != Direction::ToClient
            || packet.format() != PacketFormat::EvaWire
            || packet.bytes().len() != 15
            || packet.bytes()[14] > 1
            || self
                .original
                .as_ref()
                .is_some_and(|original| original.header() != packet.header())
        {
            return;
        }
        self.original = Some(packet.clone());
        Self::modify(packet);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn message(header: u16, direction: Direction, last: u8) -> Message {
        let mut packet = Packet::new(header);
        packet.append(&[0, 0, 0, 1, 0, 0, 0, 2, last]).unwrap();
        Message {
            packet,
            direction,
            index: 0,
            blocked: false,
        }
    }
    #[test]
    fn permissions_are_modified_and_original_can_be_restored() {
        let mut service = AdminService::default();
        let mut incoming = message(11, Direction::ToClient, 0);
        let original = incoming.packet.bytes().to_vec();
        service.on_message(&mut incoming);
        assert_eq!(incoming.packet.bytes(), original);
        assert!(service.set_enabled(true).is_none());
        service.on_message(&mut incoming);
        assert_eq!(incoming.packet.body(), &[0, 0, 0, 7, 0, 0, 0, 7, 1]);
        let mut other = message(12, Direction::ToClient, 0);
        service.on_message(&mut other);
        assert_eq!(other.packet.body()[3], 1);
        assert_eq!(service.set_enabled(false).unwrap().bytes(), original);
        assert_eq!(
            service.set_enabled(true).unwrap().body(),
            &[0, 0, 0, 7, 0, 0, 0, 7, 1]
        );
        service.on_connect();
        assert!(service.set_enabled(false).is_none());
    }
    #[test]
    fn ignores_outgoing_invalid_boolean_and_shockwave() {
        let mut service = AdminService::default();
        service.set_enabled(true);
        let mut outgoing = message(10, Direction::ToServer, 1);
        let mut invalid = message(10, Direction::ToClient, 2);
        let mut shock = Message {
            packet: Packet::new_with_format(PacketFormat::WedgieIncoming, 10).unwrap(),
            direction: Direction::ToClient,
            index: 0,
            blocked: false,
        };
        let before = (
            outgoing.packet.clone(),
            invalid.packet.clone(),
            shock.packet.clone(),
        );
        service.on_message(&mut outgoing);
        service.on_message(&mut invalid);
        service.on_message(&mut shock);
        assert_eq!(outgoing.packet, before.0);
        assert_eq!(invalid.packet, before.1);
        assert_eq!(shock.packet, before.2);
        assert!(service.set_enabled(false).is_none());
    }
}
