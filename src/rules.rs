use crate::packet::{Direction, Message, Packet};
#[derive(Clone)]
pub enum Action { Block, Replace(Packet) }
#[derive(Clone)]
pub struct Rule { pub enabled: bool, pub direction: Direction, pub header: u16, pub action: Action }
#[derive(Default)]
pub struct Rules { pub entries: Vec<Rule> }
impl Rules {
    pub fn apply(&self, message: &mut Message) {
        for rule in &self.entries {
            if rule.enabled && rule.direction == message.direction && rule.header == message.packet.header() {
                match &rule.action { Action::Block => { message.blocked = true; break; }, Action::Replace(p) => { message.packet = p.clone(); message.packet.edited = true; } }
            }
        }
    }
}
