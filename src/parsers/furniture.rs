//! Furniture structures compatible with the beta-29 extension API.
use super::entity::{java_integer, HDirection, HPoint};
use super::stuffdata::StuffData;
use crate::packet::{error, Packet, Result};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HWallItem {
    pub id: i32,
    pub type_id: i32,
    pub location: String,
    pub state: String,
    pub seconds_to_expiration: i32,
    pub usage_policy: i32,
    pub owner_id: i32,
    pub owner_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HFloorItem {
    pub id: i32,
    pub type_id: i32,
    pub tile: HPoint,
    pub facing: HDirection,
    pub size_z: String,
    pub extra: i32,
    pub stuff: StuffData,
    pub seconds_to_expiration: i32,
    pub usage_policy: i32,
    pub owner_id: i32,
    pub owner_name: Option<String>,
    pub static_class: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HProductType {
    WallItem,
    FloorItem,
    Effect,
    Badge,
}
impl HProductType {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_uppercase().as_str() {
            "I" => Ok(Self::WallItem),
            "S" => Ok(Self::FloorItem),
            "E" => Ok(Self::Effect),
            "B" => Ok(Self::Badge),
            _ => Err(error("invalid inventory product type")),
        }
    }
    fn code(self) -> &'static str {
        match self {
            Self::WallItem => "I",
            Self::FloorItem => "S",
            Self::Effect => "E",
            Self::Badge => "B",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HInventoryItem {
    pub placement_id: i32,
    pub product_type: HProductType,
    pub id: i32,
    pub type_id: i32,
    pub special_type: i32,
    pub stuff: StuffData,
    pub recyclable: bool,
    pub tradeable: bool,
    pub groupable: bool,
    pub sellable: bool,
    pub seconds_to_expiration: i32,
    pub rent_period_started: bool,
    pub room_id: i32,
    pub floor_details: Option<(String, i32)>,
}
impl HInventoryItem {
    pub fn read(packet: &mut Packet) -> Result<Self> {
        let placement_id = packet.read_i32()?;
        let product_type = HProductType::parse(&packet.read_string()?)?;
        let id = packet.read_i32()?;
        let type_id = packet.read_i32()?;
        let special_type = packet.read_i32()?;
        if !(1..=23).contains(&special_type) {
            return Err(error("invalid inventory special type"));
        }
        let stuff = StuffData::read(packet)?;
        let recyclable = packet.read_bool()?;
        let tradeable = packet.read_bool()?;
        let groupable = packet.read_bool()?;
        let sellable = packet.read_bool()?;
        let seconds_to_expiration = packet.read_i32()?;
        let rent_period_started = packet.read_bool()?;
        let room_id = packet.read_i32()?;
        let floor_details = if product_type == HProductType::FloorItem {
            Some((packet.read_string()?, packet.read_i32()?))
        } else {
            None
        };
        Ok(Self {
            placement_id,
            product_type,
            id,
            type_id,
            special_type,
            stuff,
            recyclable,
            tradeable,
            groupable,
            sellable,
            seconds_to_expiration,
            rent_period_started,
            room_id,
            floor_details,
        })
    }
    pub fn append(&self, packet: &mut Packet) -> Result<()> {
        if !(1..=23).contains(&self.special_type)
            || (self.product_type == HProductType::FloorItem) != self.floor_details.is_some()
        {
            return Err(error("invalid inventory item"));
        }
        packet
            .put_i32(self.placement_id)?
            .put_string(self.product_type.code())?
            .put_i32(self.id)?
            .put_i32(self.type_id)?
            .put_i32(self.special_type)?;
        self.stuff.append(packet)?;
        packet
            .put_bool(self.recyclable)?
            .put_bool(self.tradeable)?
            .put_bool(self.groupable)?
            .put_bool(self.sellable)?
            .put_i32(self.seconds_to_expiration)?
            .put_bool(self.rent_period_started)?
            .put_i32(self.room_id)?;
        if let Some((slot, extra)) = &self.floor_details {
            packet.put_string(slot)?.put_i32(*extra)?;
        }
        Ok(())
    }
    /// Read a single inventory page, including its page count and page index.
    pub fn parse_page(packet: &mut Packet) -> Result<(i32, i32, Vec<Self>)> {
        let pages = packet.read_i32()?;
        let index = packet.read_i32()?;
        let n = count(packet)?;
        let mut items = Vec::with_capacity(n);
        for _ in 0..n {
            items.push(Self::read(packet)?);
        }
        Ok((pages, index, items))
    }
    /// Split inventory into pages of at most 600 items.
    pub fn construct_pages(items: &[Self], header: u16) -> Result<Vec<Packet>> {
        if items.len() > 65_536 {
            return Err(error("too many inventory entries"));
        }
        let pages = items.len().div_ceil(600);
        let mut result = Vec::with_capacity(pages);
        for (index, chunk) in items.chunks(600).enumerate() {
            let mut packet = Packet::new(header);
            packet
                .put_i32(pages as i32)?
                .put_i32(index as i32)?
                .put_i32(chunk.len() as i32)?;
            for item in chunk {
                item.append(&mut packet)?;
            }
            result.push(packet);
        }
        Ok(result)
    }
}

impl HFloorItem {
    pub fn read(packet: &mut Packet) -> Result<Self> {
        let id = packet.read_i32()?;
        let type_id = packet.read_i32()?;
        let x = packet.read_i32()?;
        let y = packet.read_i32()?;
        let facing = HDirection::parse(packet.read_i32()?)?;
        let z = packet
            .read_string()?
            .parse()
            .map_err(|_| error("invalid furniture height"))?;
        let size_z = packet.read_string()?;
        let extra = packet.read_i32()?;
        let stuff = StuffData::read(packet)?;
        let seconds_to_expiration = packet.read_i32()?;
        let usage_policy = packet.read_i32()?;
        let owner_id = packet.read_i32()?;
        let static_class = if type_id < 0 {
            Some(packet.read_string()?)
        } else {
            None
        };
        Ok(Self {
            id,
            type_id,
            tile: HPoint::with_height(x, y, z),
            facing,
            size_z,
            extra,
            stuff,
            seconds_to_expiration,
            usage_policy,
            owner_id,
            owner_name: None,
            static_class,
        })
    }
    pub fn append(&self, packet: &mut Packet) -> Result<()> {
        if (self.type_id < 0) != self.static_class.is_some() {
            return Err(error("static furniture class does not match type"));
        }
        packet
            .put_i32(self.id)?
            .put_i32(self.type_id)?
            .put_i32(self.tile.x)?
            .put_i32(self.tile.y)?
            .put_i32(self.facing as i32)?
            .put_string(&super::java_double(self.tile.z))?
            .put_string(&self.size_z)?
            .put_i32(self.extra)?;
        self.stuff.append(packet)?;
        packet
            .put_i32(self.seconds_to_expiration)?
            .put_i32(self.usage_policy)?
            .put_i32(self.owner_id)?;
        if let Some(class) = &self.static_class {
            packet.put_string(class)?;
        }
        Ok(())
    }
    pub fn parse(packet: &mut Packet) -> Result<Vec<Self>> {
        let mut owners = BTreeMap::new();
        for _ in 0..count(packet)? {
            owners.insert(packet.read_i32()?, packet.read_string()?);
        }
        let n = count(packet)?;
        let mut items = Vec::with_capacity(n);
        for _ in 0..n {
            let mut item = Self::read(packet)?;
            item.owner_name = owners.get(&item.owner_id).cloned();
            items.push(item);
        }
        Ok(items)
    }
    pub fn construct(items: &[Self], header: u16) -> Result<Packet> {
        if items.len() > 65_536 {
            return Err(error("too many furniture entries"));
        }
        let mut owners = BTreeMap::new();
        for item in items {
            owners.insert(
                item.owner_id,
                item.owner_name
                    .as_deref()
                    .ok_or_else(|| error("furniture owner name missing"))?,
            );
        }
        let mut packet = Packet::new(header);
        packet.put_i32(owners.len() as i32)?;
        for (id, name) in owners {
            packet.put_i32(id)?.put_string(name)?;
        }
        packet.put_i32(items.len() as i32)?;
        for item in items {
            item.append(&mut packet)?;
        }
        Ok(packet)
    }
}

fn count(packet: &mut Packet) -> Result<usize> {
    let count =
        usize::try_from(packet.read_i32()?).map_err(|_| error("negative furniture count"))?;
    if count > 65_536 {
        return Err(error("too many furniture entries"));
    }
    Ok(count)
}

impl HWallItem {
    pub fn read(packet: &mut Packet) -> Result<Self> {
        Ok(Self {
            id: java_integer(&packet.read_string()?)?,
            type_id: packet.read_i32()?,
            location: packet.read_string()?,
            state: packet.read_string()?,
            seconds_to_expiration: packet.read_i32()?,
            usage_policy: packet.read_i32()?,
            owner_id: packet.read_i32()?,
            owner_name: None,
        })
    }

    pub fn append(&self, packet: &mut Packet) -> Result<()> {
        packet
            .put_string(&self.id.to_string())?
            .put_i32(self.type_id)?
            .put_string(&self.location)?
            .put_string(&self.state)?
            .put_i32(self.seconds_to_expiration)?
            .put_i32(self.usage_policy)?
            .put_i32(self.owner_id)?;
        Ok(())
    }

    pub fn parse(packet: &mut Packet) -> Result<Vec<Self>> {
        let owners_count = count(packet)?;
        let mut owners = BTreeMap::new();
        for _ in 0..owners_count {
            owners.insert(packet.read_i32()?, packet.read_string()?);
        }
        let items_count = count(packet)?;
        let mut items = Vec::with_capacity(items_count);
        for _ in 0..items_count {
            let mut item = Self::read(packet)?;
            item.owner_name = owners.get(&item.owner_id).cloned();
            items.push(item);
        }
        Ok(items)
    }

    pub fn construct(items: &[Self], header: u16) -> Result<Packet> {
        if items.len() > 65_536 {
            return Err(error("too many furniture entries"));
        }
        let mut owners = BTreeMap::new();
        for item in items {
            owners.insert(
                item.owner_id,
                item.owner_name
                    .as_deref()
                    .ok_or_else(|| error("furniture owner name missing"))?,
            );
        }
        let mut packet = Packet::new(header);
        packet.put_i32(owners.len() as i32)?;
        for (id, name) in owners {
            packet.put_i32(id)?.put_string(name)?;
        }
        packet.put_i32(items.len() as i32)?;
        for item in items {
            item.append(&mut packet)?;
        }
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wall_items_round_trip_with_shared_owners() {
        let first = HWallItem {
            id: 123,
            type_id: 456,
            location: ":w=1,2 l=3,4 r".into(),
            state: "hello".into(),
            seconds_to_expiration: -1,
            usage_policy: 2,
            owner_id: 42,
            owner_name: Some("Alice".into()),
        };
        let mut second = first.clone();
        second.id = 124;
        let expected = vec![first, second];
        let mut packet = HWallItem::construct(&expected, 55).unwrap();
        assert_eq!(HWallItem::parse(&mut packet).unwrap(), expected);
    }
    #[test]
    fn floor_item_round_trips_with_state_and_static_class() {
        let item = HFloorItem {
            id: 77,
            type_id: -5,
            tile: HPoint::with_height(3, 4, 1.5),
            facing: HDirection::East,
            size_z: "1.0".into(),
            extra: 9,
            stuff: StuffData {
                flags: 256,
                serial: Some((2, 100)),
                value: super::super::stuffdata::StuffValue::Legacy("3".into()),
            },
            seconds_to_expiration: -1,
            usage_policy: 2,
            owner_id: 42,
            owner_name: Some("Alice".into()),
            static_class: Some("static".into()),
        };
        let mut packet = HFloorItem::construct(std::slice::from_ref(&item), 12).unwrap();
        assert_eq!(HFloorItem::parse(&mut packet).unwrap(), vec![item]);
    }
    #[test]
    fn inventory_pages_round_trip_at_page_boundary() {
        let item = HInventoryItem {
            placement_id: 1,
            product_type: HProductType::FloorItem,
            id: 2,
            type_id: 3,
            special_type: 1,
            stuff: StuffData {
                flags: 0,
                serial: None,
                value: super::super::stuffdata::StuffValue::Empty,
            },
            recyclable: true,
            tradeable: true,
            groupable: false,
            sellable: true,
            seconds_to_expiration: -1,
            rent_period_started: false,
            room_id: 9,
            floor_details: Some(("slot".into(), 7)),
        };
        let items = vec![item; 601];
        let mut pages = HInventoryItem::construct_pages(&items, 44).unwrap();
        assert_eq!(pages.len(), 2);
        let (total, index, first) = HInventoryItem::parse_page(&mut pages[0]).unwrap();
        assert_eq!((total, index, first.len()), (2, 0, 600));
        let (_, index, last) = HInventoryItem::parse_page(&mut pages[1]).unwrap();
        assert_eq!((index, last.len()), (1, 1));
        assert_eq!(last[0], items[600]);
    }
}
