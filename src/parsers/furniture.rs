//! Furniture structures compatible with the beta-29 extension API.
use super::entity::java_integer;
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
}
