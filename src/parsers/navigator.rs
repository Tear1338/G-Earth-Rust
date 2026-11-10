//! Navigator search results from the beta-29 extension API.
use crate::packet::{error, Packet, Result};

fn count(packet: &mut Packet) -> Result<usize> {
    let n = usize::try_from(packet.read_i32()?).map_err(|_| error("negative navigator count"))?;
    if n > 65_536 {
        return Err(error("navigator count exceeds limit"));
    }
    Ok(n)
}
fn loop_count(packet: &mut Packet) -> Result<usize> {
    let n = packet.read_i32()?.max(0) as usize;
    if n > 65_536 {
        return Err(error("navigator count exceeds limit"));
    }
    Ok(n)
}
fn size(n: usize) -> Result<i32> {
    if n > 65_536 {
        return Err(error("navigator count exceeds limit"));
    }
    Ok(n as i32)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NavigatorRoom {
    pub flat_id: i32,
    pub name: String,
    pub owner_id: i32,
    pub owner_name: String,
    pub door_mode: i32,
    pub user_count: i32,
    pub max_user_count: i32,
    pub description: String,
    pub trade_mode: i32,
    pub score: i32,
    pub ranking: i32,
    pub category_id: i32,
    pub tags: Vec<String>,
    pub official_picture: Option<String>,
    pub group: Option<(i32, String, String)>,
    pub advertisement: Option<(String, String, i32)>,
    pub show_owner: bool,
    pub allow_pets: bool,
    pub display_entry_ad: bool,
}
impl NavigatorRoom {
    pub fn read(packet: &mut Packet) -> Result<Self> {
        let flat_id = packet.read_i32()?;
        let name = packet.read_string()?;
        let owner_id = packet.read_i32()?;
        let owner_name = packet.read_string()?;
        let door_mode = packet.read_i32()?;
        let user_count = packet.read_i32()?;
        let max_user_count = packet.read_i32()?;
        let description = packet.read_string()?;
        let trade_mode = packet.read_i32()?;
        let score = packet.read_i32()?;
        let ranking = packet.read_i32()?;
        let category_id = packet.read_i32()?;
        let n = count(packet)?;
        let mut tags = Vec::with_capacity(n);
        for _ in 0..n {
            tags.push(packet.read_string()?);
        }
        let flags = packet.read_i32()?;
        let official_picture = if flags & 1 != 0 {
            Some(packet.read_string()?)
        } else {
            None
        };
        let group = if flags & 2 != 0 {
            Some((
                packet.read_i32()?,
                packet.read_string()?,
                packet.read_string()?,
            ))
        } else {
            None
        };
        let advertisement = if flags & 4 != 0 {
            Some((
                packet.read_string()?,
                packet.read_string()?,
                packet.read_i32()?,
            ))
        } else {
            None
        };
        Ok(Self {
            flat_id,
            name,
            owner_id,
            owner_name,
            door_mode,
            user_count,
            max_user_count,
            description,
            trade_mode,
            score,
            ranking,
            category_id,
            tags,
            official_picture,
            group,
            advertisement,
            show_owner: flags & 8 != 0,
            allow_pets: flags & 16 != 0,
            display_entry_ad: flags & 32 != 0,
        })
    }
    pub fn append(&self, packet: &mut Packet) -> Result<()> {
        packet
            .put_i32(self.flat_id)?
            .put_string(&self.name)?
            .put_i32(self.owner_id)?
            .put_string(&self.owner_name)?
            .put_i32(self.door_mode)?
            .put_i32(self.user_count)?
            .put_i32(self.max_user_count)?
            .put_string(&self.description)?
            .put_i32(self.trade_mode)?
            .put_i32(self.score)?
            .put_i32(self.ranking)?
            .put_i32(self.category_id)?
            .put_i32(size(self.tags.len())?)?;
        for tag in &self.tags {
            packet.put_string(tag)?;
        }
        let mut flags = 0;
        if self.official_picture.is_some() {
            flags |= 1;
        }
        if self.group.as_ref().is_some_and(|(id, _, _)| *id != -1) {
            flags |= 2;
        }
        if self
            .advertisement
            .as_ref()
            .is_some_and(|(_, _, minutes)| *minutes != -1)
        {
            flags |= 4;
        }
        if self.show_owner {
            flags |= 8;
        }
        if self.allow_pets {
            flags |= 16;
        }
        if self.display_entry_ad {
            flags |= 32;
        }
        packet.put_i32(flags)?;
        if let Some(picture) = &self.official_picture {
            packet.put_string(picture)?;
        }
        if let Some((id, name, badge)) = self.group.as_ref().filter(|(id, _, _)| *id != -1) {
            packet.put_i32(*id)?.put_string(name)?.put_string(badge)?;
        }
        if let Some((name, description, minutes)) = self
            .advertisement
            .as_ref()
            .filter(|(_, _, minutes)| *minutes != -1)
        {
            packet
                .put_string(name)?
                .put_string(description)?
                .put_i32(*minutes)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NavigatorBlock {
    pub search_code: String,
    pub text: String,
    pub action_allowed: i32,
    pub force_closed: bool,
    pub view_mode: i32,
    pub rooms: Vec<NavigatorRoom>,
}
impl NavigatorBlock {
    pub fn read(packet: &mut Packet) -> Result<Self> {
        let search_code = packet.read_string()?;
        let text = packet.read_string()?;
        let action_allowed = packet.read_i32()?;
        let force_closed = packet.read_bool()?;
        let view_mode = packet.read_i32()?;
        let n = loop_count(packet)?;
        let mut rooms = Vec::with_capacity(n);
        for _ in 0..n {
            rooms.push(NavigatorRoom::read(packet)?);
        }
        Ok(Self {
            search_code,
            text,
            action_allowed,
            force_closed,
            view_mode,
            rooms,
        })
    }
    pub fn append(&self, packet: &mut Packet) -> Result<()> {
        packet
            .put_string(&self.search_code)?
            .put_string(&self.text)?
            .put_i32(self.action_allowed)?
            .put_bool(self.force_closed)?
            .put_i32(self.view_mode)?
            .put_i32(size(self.rooms.len())?)?;
        for room in &self.rooms {
            room.append(packet)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NavigatorSearchResult {
    pub search_code: String,
    pub filtering_data: String,
    pub blocks: Vec<NavigatorBlock>,
}
impl NavigatorSearchResult {
    pub fn read(packet: &mut Packet) -> Result<Self> {
        let search_code = packet.read_string()?;
        let filtering_data = packet.read_string()?;
        let n = loop_count(packet)?;
        let mut blocks = Vec::with_capacity(n);
        for _ in 0..n {
            blocks.push(NavigatorBlock::read(packet)?);
        }
        Ok(Self {
            search_code,
            filtering_data,
            blocks,
        })
    }
    pub fn append(&self, packet: &mut Packet) -> Result<()> {
        packet
            .put_string(&self.search_code)?
            .put_string(&self.filtering_data)?
            .put_i32(size(self.blocks.len())?)?;
        for block in &self.blocks {
            block.append(packet)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn navigator_round_trip_preserves_optional_room_data() {
        let room = NavigatorRoom {
            flat_id: 1,
            name: "Room".into(),
            owner_id: 2,
            owner_name: "Alice".into(),
            door_mode: 0,
            user_count: 3,
            max_user_count: 20,
            description: "Test".into(),
            trade_mode: 1,
            score: 4,
            ranking: 5,
            category_id: 6,
            tags: vec!["tag".into()],
            official_picture: Some("pic".into()),
            group: Some((7, "group".into(), "badge".into())),
            advertisement: Some(("ad".into(), "details".into(), 8)),
            show_owner: true,
            allow_pets: true,
            display_entry_ad: false,
        };
        let expected = NavigatorSearchResult {
            search_code: "popular".into(),
            filtering_data: "".into(),
            blocks: vec![NavigatorBlock {
                search_code: "popular".into(),
                text: "Popular".into(),
                action_allowed: 1,
                force_closed: false,
                view_mode: 0,
                rooms: vec![room],
            }],
        };
        let mut packet = Packet::new(1);
        expected.append(&mut packet).unwrap();
        assert_eq!(NavigatorSearchResult::read(&mut packet).unwrap(), expected);
        let mut sentinel = expected.blocks[0].rooms[0].clone();
        sentinel.group = Some((-1, "group".into(), "badge".into()));
        sentinel.advertisement = Some(("ad".into(), "details".into(), -1));
        let mut packet = Packet::new(1);
        sentinel.append(&mut packet).unwrap();
        let normalized = NavigatorRoom::read(&mut packet).unwrap();
        assert_eq!(normalized.group, None);
        assert_eq!(normalized.advertisement, None);
    }

    #[test]
    fn negative_block_and_room_counts_are_empty_like_java() {
        let mut blocks = Packet::new(1);
        blocks
            .put_string("search")
            .unwrap()
            .put_string("filter")
            .unwrap()
            .put_i32(-1)
            .unwrap();
        assert!(NavigatorSearchResult::read(&mut blocks)
            .unwrap()
            .blocks
            .is_empty());
        let mut rooms = Packet::new(1);
        rooms
            .put_string("code")
            .unwrap()
            .put_string("text")
            .unwrap()
            .put_i32(1)
            .unwrap()
            .put_bool(false)
            .unwrap()
            .put_i32(0)
            .unwrap()
            .put_i32(-1)
            .unwrap();
        assert!(NavigatorBlock::read(&mut rooms).unwrap().rooms.is_empty());
    }
}
