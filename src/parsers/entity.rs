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
    pub(crate) fn parse(value: i32) -> Result<Self> {
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

/// Type-specific fields of a room entity in the original packet order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HEntityDetails {
    Habbo {
        gender: String,
        group_id: i32,
        group_status: i32,
        favorite_group: String,
        extra_text: String,
        achievement: i32,
        moderator: bool,
        unknown: i32,
    },
    Pet {
        pet_type: i32,
        owner_id: i32,
        owner_name: String,
        rarity: i32,
        flags: [bool; 6],
        level: i32,
        posture: String,
    },
    OldBot,
    Bot {
        gender: String,
        owner_id: i32,
        owner_name: String,
        skills: Vec<u16>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct HEntity {
    pub id: i32,
    pub name: String,
    pub motto: String,
    pub figure_id: String,
    pub index: i32,
    pub tile: HPoint,
    pub unknown: i32,
    pub details: HEntityDetails,
    pub last_update: Option<HEntityUpdate>,
}

impl HEntity {
    pub fn read(packet: &mut Packet) -> Result<Self> {
        let id = packet.read_i32()?;
        let name = packet.read_string()?;
        let motto = packet.read_string()?;
        let figure_id = packet.read_string()?;
        let index = packet.read_i32()?;
        let x = packet.read_i32()?;
        let y = packet.read_i32()?;
        let z = super::parse_java_double(&packet.read_string()?)
            .ok_or_else(|| error("invalid entity height"))?;
        let unknown = packet.read_i32()?;
        let details = match packet.read_i32()? {
            1 => HEntityDetails::Habbo {
                gender: packet.read_string()?,
                group_id: packet.read_i32()?,
                group_status: packet.read_i32()?,
                favorite_group: packet.read_string()?,
                extra_text: packet.read_string()?,
                achievement: packet.read_i32()?,
                moderator: packet.read_bool()?,
                unknown: packet.read_i32()?,
            },
            2 => HEntityDetails::Pet {
                pet_type: packet.read_i32()?,
                owner_id: packet.read_i32()?,
                owner_name: packet.read_string()?,
                rarity: packet.read_i32()?,
                flags: [
                    packet.read_bool()?,
                    packet.read_bool()?,
                    packet.read_bool()?,
                    packet.read_bool()?,
                    packet.read_bool()?,
                    packet.read_bool()?,
                ],
                level: packet.read_i32()?,
                posture: packet.read_string()?,
            },
            3 => HEntityDetails::OldBot,
            4 => {
                let gender = packet.read_string()?;
                let owner_id = packet.read_i32()?;
                let owner_name = packet.read_string()?;
                let count = usize::try_from(packet.read_i32()?)
                    .map_err(|_| error("negative bot skill count"))?;
                if count > 65_536 {
                    return Err(error("too many bot skills"));
                }
                let mut skills = Vec::with_capacity(count);
                for _ in 0..count {
                    skills.push(packet.read_u16()?);
                }
                HEntityDetails::Bot {
                    gender,
                    owner_id,
                    owner_name,
                    skills,
                }
            }
            _ => return Err(error("unknown room entity type")),
        };
        Ok(Self {
            id,
            name,
            motto,
            figure_id,
            index,
            tile: HPoint::with_height(x, y, z),
            unknown,
            details,
            last_update: None,
        })
    }
    pub fn append(&self, packet: &mut Packet) -> Result<()> {
        packet
            .put_i32(self.id)?
            .put_string(&self.name)?
            .put_string(&self.motto)?
            .put_string(&self.figure_id)?
            .put_i32(self.index)?
            .put_i32(self.tile.x)?
            .put_i32(self.tile.y)?
            .put_string(&super::java_double(self.tile.z))?
            .put_i32(self.unknown)?;
        match &self.details {
            HEntityDetails::Habbo {
                gender,
                group_id,
                group_status,
                favorite_group,
                extra_text,
                achievement,
                moderator,
                unknown,
            } => {
                packet
                    .put_i32(1)?
                    .put_string(gender)?
                    .put_i32(*group_id)?
                    .put_i32(*group_status)?
                    .put_string(favorite_group)?
                    .put_string(extra_text)?
                    .put_i32(*achievement)?
                    .put_bool(*moderator)?
                    .put_i32(*unknown)?;
            }
            HEntityDetails::Pet {
                pet_type,
                owner_id,
                owner_name,
                rarity,
                flags,
                level,
                posture,
            } => {
                packet
                    .put_i32(2)?
                    .put_i32(*pet_type)?
                    .put_i32(*owner_id)?
                    .put_string(owner_name)?
                    .put_i32(*rarity)?;
                for flag in flags {
                    packet.put_bool(*flag)?;
                }
                packet.put_i32(*level)?.put_string(posture)?;
            }
            HEntityDetails::OldBot => {
                packet.put_i32(3)?;
            }
            HEntityDetails::Bot {
                gender,
                owner_id,
                owner_name,
                skills,
            } => {
                if skills.len() > 65_536 {
                    return Err(error("too many bot skills"));
                }
                packet
                    .put_i32(4)?
                    .put_string(gender)?
                    .put_i32(*owner_id)?
                    .put_string(owner_name)?
                    .put_i32(skills.len() as i32)?;
                for skill in skills {
                    packet.put_u16(*skill)?;
                }
            }
        }
        Ok(())
    }
    pub fn parse(packet: &mut Packet) -> Result<Vec<Self>> {
        let n = usize::try_from(packet.read_i32()?).map_err(|_| error("negative entity count"))?;
        if n > 65_536 {
            return Err(error("too many room entities"));
        }
        let mut entities = Vec::with_capacity(n);
        for _ in 0..n {
            entities.push(Self::read(packet)?);
        }
        Ok(entities)
    }
    /// Construct a room-entity packet in the same order as beta-29's constructPacket.
    pub fn construct(entities: &[Self], header: u16) -> Result<Packet> {
        if entities.len() > 65_536 {
            return Err(error("too many room entities"));
        }
        let mut packet = Packet::new(header);
        packet.put_i32(entities.len() as i32)?;
        for entity in entities {
            entity.append(&mut packet)?;
        }
        Ok(packet)
    }
    pub fn apply_update(&mut self, update: &HEntityUpdate) -> bool {
        if self.index != update.index {
            return false;
        }
        self.tile = update.tile;
        self.last_update = Some(update.clone());
        true
    }
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

pub(crate) fn java_integer(text: &str) -> Result<i32> {
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
    if digits.is_empty() || !digits.bytes().all(|b| (b as char).is_digit(radix)) {
        return Err(error("invalid entity integer"));
    }
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
            let z = super::parse_java_double(&packet.read_string()?)
                .ok_or_else(|| error("invalid entity height"))?;
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
                let mut fields = item.trim_end_matches(' ').split(' ');
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
                        let values: Vec<_> = value.trim_end_matches(',').split(',').collect();
                        if values.len() >= 3 {
                            update.moving_to = Some(HPoint::with_height(
                                java_integer(values[0])?,
                                java_integer(values[1])?,
                                super::parse_java_double(values[2])
                                    .ok_or_else(|| error("invalid movement height"))?,
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
    use super::{HAction, HDirection, HEntity, HEntityDetails, HEntityUpdate, HPoint, HStance};
    use crate::packet::Packet;

    #[test]
    fn construct_entity_packet_matches_beta29_java_vector() {
        let entity = HEntity {
            id: 17,
            name: "Bot".into(),
            motto: "hello".into(),
            figure_id: "figure".into(),
            index: 23,
            tile: HPoint::with_height(3, 4, 1.5),
            unknown: 5,
            details: HEntityDetails::OldBot,
            last_update: None,
        };
        let packet = HEntity::construct(&[entity.clone(), entity], 42).unwrap();
        let expected = crate::expression::parse_hex(concat!(
            "00000068002a00000002",
            "000000110003426f74000568656c6c6f0006666967757265",
            "0000001700000003000000040003312e350000000500000003",
            "000000110003426f74000568656c6c6f0006666967757265",
            "0000001700000003000000040003312e350000000500000003"
        ))
        .unwrap();
        assert_eq!(packet.bytes(), expected);
    }

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
    #[test]
    fn java_action_delimiters_and_integer_signs_match_selected_cases() {
        for text in ["-+1", "--1", "0x-1", "0x+1", "08", "2147483648"] {
            assert!(super::java_integer(text).is_err(), "{text}");
        }
        assert_eq!(super::java_integer("-0x80000000").unwrap(), i32::MIN);
        assert_eq!(super::java_integer("+0x7fffffff").unwrap(), i32::MAX);
        for (text, expected_action, expected_position) in [
            ("sit ", None, None),
            ("flatctrl ", None, None),
            ("mv 1,2,", Some(HAction::Move), None),
            (
                "mv 1,2,3,",
                Some(HAction::Move),
                Some(HPoint::with_height(1, 2, 3.0)),
            ),
        ] {
            let mut packet = Packet::new(1);
            packet
                .put_i32(1)
                .unwrap()
                .put_i32(1)
                .unwrap()
                .put_i32(1)
                .unwrap()
                .put_i32(1)
                .unwrap()
                .put_string("0")
                .unwrap()
                .put_i32(0)
                .unwrap()
                .put_i32(0)
                .unwrap()
                .put_string(text)
                .unwrap();
            let update = HEntityUpdate::parse(&mut packet).unwrap().remove(0);
            assert_eq!(update.action, expected_action, "{text:?}");
            assert_eq!(update.moving_to, expected_position, "{text:?}");
        }
    }

    #[test]
    fn room_entity_variants_round_trip() {
        let details = [
            HEntityDetails::Habbo {
                gender: "M".into(),
                group_id: 1,
                group_status: 2,
                favorite_group: "g".into(),
                extra_text: "x".into(),
                achievement: 3,
                moderator: true,
                unknown: 4,
            },
            HEntityDetails::Pet {
                pet_type: 1,
                owner_id: 2,
                owner_name: "Alice".into(),
                rarity: 3,
                flags: [true, false, true, false, true, false],
                level: 4,
                posture: "sit".into(),
            },
            HEntityDetails::OldBot,
            HEntityDetails::Bot {
                gender: "F".into(),
                owner_id: 8,
                owner_name: "Bob".into(),
                skills: vec![0, 65535],
            },
        ];
        let mut expected = Vec::new();
        for (index, detail) in details.into_iter().enumerate() {
            let entity = HEntity {
                id: index as i32,
                name: "name".into(),
                motto: "motto".into(),
                figure_id: "figure".into(),
                index: index as i32,
                tile: HPoint::with_height(1, 2, 3.5),
                unknown: 5,
                details: detail,
                last_update: None,
            };
            expected.push(entity);
        }
        let mut packet = HEntity::construct(&expected, 1).unwrap();
        assert_eq!(HEntity::parse(&mut packet).unwrap(), expected);
        let mut empty = HEntity::construct(&[], 7).unwrap();
        assert_eq!(empty.header(), 7);
        assert!(HEntity::parse(&mut empty).unwrap().is_empty());
    }
}
