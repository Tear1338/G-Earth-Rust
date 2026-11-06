use crate::{
    expression,
    packet::{error, Direction, Message, Packet, PacketFormat, Result},
    packet_info::PacketInfoManager,
};
#[derive(Clone)]
pub enum Action {
    Block,
    Replace(Packet),
}
#[derive(Clone)]
pub struct Rule {
    pub enabled: bool,
    pub direction: Direction,
    pub header: u16,
    pub action: Action,
}
#[derive(Default)]
pub struct Rules {
    pub entries: Vec<Rule>,
}
impl Rules {
    /// An invalid editor draft must not keep a previous transient rule active.
    pub fn editor_rule(
        enabled: bool,
        direction: Direction,
        header: u16,
        replacement: &str,
        format: PacketFormat,
        packet_info: &PacketInfoManager,
    ) -> Result<Option<Rule>> {
        if !enabled {
            return Ok(None);
        }
        if format != PacketFormat::EvaWire && header >= 4096 {
            return Err(error("Shockwave header must be between 0 and 4095"));
        }
        let action = if replacement.trim().is_empty() {
            Action::Block
        } else {
            Action::Replace(expression::parse_with_format(
                replacement,
                format,
                Some((direction, packet_info)),
            )?)
        };
        Ok(Some(Rule {
            enabled: true,
            direction,
            header,
            action,
        }))
    }

    pub fn apply(&self, message: &mut Message) {
        for rule in &self.entries {
            if rule.enabled
                && rule.direction == message.direction
                && rule.header == message.packet.header()
            {
                match &rule.action {
                    Action::Block => {
                        message.blocked = true;
                        break;
                    }
                    Action::Replace(p) => {
                        message.packet = p.clone();
                        message.packet.edited = true;
                    }
                }
            }
        }
    }
}
