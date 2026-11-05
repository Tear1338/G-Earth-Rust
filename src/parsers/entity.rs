//! Basic position type from the original G-Earth extension API.
use crate::packet::{error, Packet, Result};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HPoint {
    pub x: i32,
    pub y: i32,
    pub z: f64,
}

impl HPoint {
    pub fn new(x: i32, y: i32) -> Self {
        Self { x, y, z: 0.0 }
    }

    pub fn with_height(x: i32, y: i32, z: f64) -> Self {
        Self { x, y, z }
    }
}

impl fmt::Display for HPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({},{},{})", self.x, self.y, super::java_double(self.z))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HDirection {
    North,
    NorthEast,
    East,
    SouthEast,
    South,
    SouthWest,
    West,
    NorthWest,
}

impl HDirection {
    fn parse(value: i32) -> Result<Self> {
        [
            Self::North,
            Self::NorthEast,
            Self::East,
            Self::SouthEast,
            Self::South,
            Self::SouthWest,
            Self::West,
            Self::NorthWest,
        ]
        .get(usize::try_from(value).unwrap_or(usize::MAX))
        .copied()
        .ok_or_else(|| error("invalid entity direction"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HAction {
    None,
    Move,
    Sit,
    Lay,
    Sign,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HStance {
    Sit,
    Lay,
}

/// One entry from the beta-29 avatar movement/update packet.
#[derive(Clone, Debug, PartialEq)]
pub struct HEntityUpdate {
    pub index: i32,
    pub is_controller: bool,
    pub tile: HPoint,
    pub moving_to: Option<HPoint>,
    /// Original HSign ordinal, from 0 (zero) to 18 (invisible).
    pub sign: Option<u8>,
    pub stance: Option<HStance>,
    pub action: Option<HAction>,
    pub head_facing: HDirection,
    pub body_facing: HDirection,
}

fn java_integer(text: &str) -> Result<i32> {
    let (negative, text) = match text.strip_prefix('-') {
        Some(s) => (true, s),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let (radix, digits) = if let Some(s) = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .or_else(|| text.strip_prefix('#'))
    {
        (16, s)
    } else if text.len() > 1 && text.starts_with('0') {
        (8, &text[1..])
    } else {
        (10, text)
    };
    let value = i64::from_str_radix(digits, radix).map_err(|_| error("invalid entity integer"))?;
    i32::try_from(if negative { -value } else { value })
        .map_err(|_| error("entity integer outside range"))
}

impl HEntityUpdate {
    pub fn parse(packet: &mut Packet) -> Result<Vec<Self>> {
        let count = usize::try_from(packet.read_i32()?)
            .map_err(|_| error("negative entity update count"))?;
        if count > 65_536 {
            return Err(error("too many entity updates"));
        }
        let mut updates = Vec::with_capacity(count);
        for _ in 0..count {
            let index = packet.read_i32()?;
            let x = packet.read_i32()?;
            let y = packet.read_i32()?;
            let z = packet
                .read_string()?
                .parse::<f64>()
                .map_err(|_| error("invalid entity height"))?;
            let head_facing = HDirection::parse(packet.read_i32()?)?;
            let body_facing = HDirection::parse(packet.read_i32()?)?;
            let action_data = packet.read_string()?;
            let mut update = Self {
                index,
                is_controller: false,
                tile: HPoint::with_height(x, y, z),
                moving_to: None,
                sign: None,
                stance: None,
                action: None,
                head_facing,
                body_facing,
            };
            for item in action_data.split('/') {
                let mut fields = item.split(' ');
                let key = fields.next().unwrap_or("");
                let Some(value) = fields.next() else {
                    continue;
                };
                match key {
                    "flatctrl" => {
                        update.is_controller = true;
                        update.action = Some(HAction::None);
                    }
                    "mv" => {
                        let values: Vec<_> = value.split(',').collect();
                        if values.len() >= 3 {
                            update.moving_to = Some(HPoint::with_height(
                                java_integer(values[0])?,
                                java_integer(values[1])?,
                                values[2]
                                    .parse()
                                    .map_err(|_| error("invalid movement height"))?,
                            ));
                        }
                        update.action = Some(HAction::Move);
                    }
                    "sit" => {
                        update.action = Some(HAction::Sit);
                        update.stance = Some(HStance::Sit);
                    }
                    "lay" => {
                        update.action = Some(HAction::Lay);
                        update.stance = Some(HStance::Lay);
                    }
                    "sign" => {
                        let sign = java_integer(value)?;
                        if !(0..=18).contains(&sign) {
                            return Err(error("invalid entity sign"));
                        }
                        update.sign = Some(sign as u8);
                        update.action = Some(HAction::Sign);
                    }
                    _ => {}
                }
            }
            updates.push(update);
        }
        Ok(updates)
    }
}

#[cfg(test)]
mod tests {
    use super::{HAction, HDirection, HEntityUpdate, HPoint, HStance};
    use crate::packet::Packet;

    #[test]
    fn point_formats_coordinates_like_the_java_api() {
        assert_eq!(HPoint::new(2, -3).to_string(), "(2,-3,0.0)");
        assert_eq!(HPoint::with_height(1, 2, -0.0).to_string(), "(1,2,-0.0)");
        assert_eq!(
            HPoint::with_height(1, 2, 10_000_000.0).to_string(),
            "(1,2,1.0E7)"
        );
        assert_ne!(
            HPoint::with_height(1, 2, f64::NAN),
            HPoint::with_height(1, 2, f64::NAN)
        );
    }

    #[test]
    fn update_parses_actions_and_signed_java_integer_coordinates() {
        let mut packet = Packet::new(1);
        packet
            .put_i32(1)
            .unwrap()
            .put_i32(12)
            .unwrap()
            .put_i32(3)
            .unwrap()
            .put_i32(4)
            .unwrap()
            .put_string("1.5")
            .unwrap()
            .put_i32(1)
            .unwrap()
            .put_i32(4)
            .unwrap()
            .put_string("/flatctrl 1/mv 0x10,-02,2.25/sit 1/sign 11/")
            .unwrap();
        let update = HEntityUpdate::parse(&mut packet).unwrap().remove(0);
        assert_eq!(update.index, 12);
        assert!(update.is_controller);
        assert_eq!(update.tile, HPoint::with_height(3, 4, 1.5));
        assert_eq!(update.moving_to, Some(HPoint::with_height(16, -2, 2.25)));
        assert_eq!(update.head_facing, HDirection::NorthEast);
        assert_eq!(update.stance, Some(HStance::Sit));
        assert_eq!(update.action, Some(HAction::Sign));
        assert_eq!(update.sign, Some(11));
    }
}
