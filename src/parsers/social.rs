//! Profile, group and friend data from the beta-29 extension API.
use crate::packet::{error, Packet, Result};
use std::collections::BTreeMap;

fn count(packet: &mut Packet) -> Result<usize> {
    let n =
        usize::try_from(packet.read_i32()?).map_err(|_| error("negative social entry count"))?;
    if n > 65_536 {
        return Err(error("too many social entries"));
    }
    Ok(n)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HGroup {
    pub id: i32,
    pub name: String,
    pub badge_code: String,
    pub primary_color: String,
    pub secondary_color: String,
    pub favorite: bool,
    pub owner_id: i32,
    pub has_forum: bool,
}
impl HGroup {
    pub fn read(packet: &mut Packet) -> Result<Self> {
        Ok(Self {
            id: packet.read_i32()?,
            name: packet.read_string()?,
            badge_code: packet.read_string()?,
            primary_color: packet.read_string()?,
            secondary_color: packet.read_string()?,
            favorite: packet.read_bool()?,
            owner_id: packet.read_i32()?,
            has_forum: packet.read_bool()?,
        })
    }
    pub fn append(&self, packet: &mut Packet) -> Result<()> {
        packet
            .put_i32(self.id)?
            .put_string(&self.name)?
            .put_string(&self.badge_code)?
            .put_string(&self.primary_color)?
            .put_string(&self.secondary_color)?
            .put_bool(self.favorite)?
            .put_i32(self.owner_id)?
            .put_bool(self.has_forum)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HUserProfile {
    pub id: i32,
    pub username: String,
    pub motto: String,
    pub figure: String,
    pub creation_date: String,
    pub achievement_score: i32,
    pub friend_count: i32,
    pub is_friend: bool,
    pub is_requested_friend: bool,
    pub is_online: bool,
    pub groups: Vec<HGroup>,
    pub last_access_since: i32,
    pub open_profile: bool,
}
impl HUserProfile {
    pub fn read(packet: &mut Packet) -> Result<Self> {
        let id = packet.read_i32()?;
        let username = packet.read_string()?;
        let motto = packet.read_string()?;
        let figure = packet.read_string()?;
        let creation_date = packet.read_string()?;
        let achievement_score = packet.read_i32()?;
        let friend_count = packet.read_i32()?;
        let is_friend = packet.read_bool()?;
        let is_requested_friend = packet.read_bool()?;
        let is_online = packet.read_bool()?;
        let n = count(packet)?;
        let mut groups = Vec::with_capacity(n);
        for _ in 0..n {
            groups.push(HGroup::read(packet)?);
        }
        let last_access_since = packet.read_i32()?;
        let open_profile = packet.read_bool()?;
        Ok(Self {
            id,
            username,
            motto,
            figure,
            creation_date,
            achievement_score,
            friend_count,
            is_friend,
            is_requested_friend,
            is_online,
            groups,
            last_access_since,
            open_profile,
        })
    }
    pub fn append(&self, packet: &mut Packet) -> Result<()> {
        if self.groups.len() > 65_536 {
            return Err(error("too many profile groups"));
        }
        packet
            .put_i32(self.id)?
            .put_string(&self.username)?
            .put_string(&self.motto)?
            .put_string(&self.figure)?
            .put_string(&self.creation_date)?
            .put_i32(self.achievement_score)?
            .put_i32(self.friend_count)?
            .put_bool(self.is_friend)?
            .put_bool(self.is_requested_friend)?
            .put_bool(self.is_online)?
            .put_i32(self.groups.len() as i32)?;
        for group in &self.groups {
            group.append(packet)?;
        }
        packet
            .put_i32(self.last_access_since)?
            .put_bool(self.open_profile)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HFriend {
    pub id: i32,
    pub name: String,
    pub male: bool,
    pub online: bool,
    pub following_allowed: bool,
    pub figure: String,
    pub category_id: i32,
    pub motto: String,
    pub real_name: String,
    pub facebook_id: String,
    pub persisted_message_user: bool,
    pub vip_member: bool,
    pub pocket_habbo_user: bool,
    pub relationship_status: u16,
    pub category_name: Option<String>,
}
impl HFriend {
    pub fn read(packet: &mut Packet) -> Result<Self> {
        let id = packet.read_i32()?;
        let name = packet.read_string()?;
        let male = packet.read_i32()? != 0;
        let online = packet.read_bool()?;
        let following_allowed = packet.read_bool()?;
        let figure = packet.read_string()?;
        let category_id = packet.read_i32()?;
        let motto = packet.read_string()?;
        let real_name = packet.read_string()?;
        let facebook_id = packet.read_string()?;
        let persisted_message_user = packet.read_bool()?;
        let vip_member = packet.read_bool()?;
        let pocket_habbo_user = packet.read_bool()?;
        let relationship_status = packet.read_u16()?;
        if relationship_status > 3 {
            return Err(error("invalid friend relationship status"));
        }
        Ok(Self {
            id,
            name,
            male,
            online,
            following_allowed,
            figure,
            category_id,
            motto,
            real_name,
            facebook_id,
            persisted_message_user,
            vip_member,
            pocket_habbo_user,
            relationship_status,
            category_name: None,
        })
    }
    pub fn append(&self, packet: &mut Packet) -> Result<()> {
        if self.relationship_status > 3 {
            return Err(error("invalid friend relationship status"));
        }
        packet
            .put_i32(self.id)?
            .put_string(&self.name)?
            .put_i32(i32::from(self.male))?
            .put_bool(self.online)?
            .put_bool(self.following_allowed)?
            .put_string(&self.figure)?
            .put_i32(self.category_id)?
            .put_string(&self.motto)?
            .put_string(&self.real_name)?
            .put_string(&self.facebook_id)?
            .put_bool(self.persisted_message_user)?
            .put_bool(self.vip_member)?
            .put_bool(self.pocket_habbo_user)?
            .put_u16(self.relationship_status)?;
        Ok(())
    }
    pub fn parse_fragment(packet: &mut Packet) -> Result<(i32, i32, Vec<Self>)> {
        let pages = packet.read_i32()?;
        let index = packet.read_i32()?;
        let n = count(packet)?;
        let mut friends = Vec::with_capacity(n);
        for _ in 0..n {
            friends.push(Self::read(packet)?);
        }
        Ok((pages, index, friends))
    }
    pub fn construct_fragments(friends: &[Self], header: u16) -> Result<Vec<Packet>> {
        if friends.len() > 65_536 {
            return Err(error("too many friends"));
        }
        let pages = friends.len().div_ceil(100);
        let mut packets = Vec::with_capacity(pages);
        for (index, chunk) in friends.chunks(100).enumerate() {
            let mut packet = Packet::new(header);
            packet
                .put_i32(pages as i32)?
                .put_i32(index as i32)?
                .put_i32(chunk.len() as i32)?;
            for friend in chunk {
                friend.append(&mut packet)?;
            }
            packets.push(packet);
        }
        Ok(packets)
    }
    pub fn parse_update(packet: &mut Packet) -> Result<(Vec<Self>, Vec<i32>)> {
        let mut categories = BTreeMap::new();
        for _ in 0..count(packet)? {
            categories.insert(packet.read_i32()?, packet.read_string()?);
        }
        let n = count(packet)?;
        let mut friends = Vec::new();
        let mut removed = Vec::new();
        for _ in 0..n {
            if packet.read_i32()? == -1 {
                removed.push(packet.read_i32()?);
            } else {
                let mut friend = Self::read(packet)?;
                friend.category_name = categories.get(&friend.category_id).cloned();
                friends.push(friend);
            }
        }
        Ok((friends, removed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_and_friend_packets_round_trip() {
        let group = HGroup {
            id: 7,
            name: "Group".into(),
            badge_code: "B".into(),
            primary_color: "1".into(),
            secondary_color: "2".into(),
            favorite: true,
            owner_id: 9,
            has_forum: false,
        };
        let profile = HUserProfile {
            id: 9,
            username: "Alice".into(),
            motto: "hi".into(),
            figure: "hd".into(),
            creation_date: "today".into(),
            achievement_score: 3,
            friend_count: 2,
            is_friend: true,
            is_requested_friend: false,
            is_online: true,
            groups: vec![group],
            last_access_since: 4,
            open_profile: true,
        };
        let mut packet = Packet::new(1);
        profile.append(&mut packet).unwrap();
        assert_eq!(HUserProfile::read(&mut packet).unwrap(), profile);
        let friend = HFriend {
            id: 8,
            name: "Bob".into(),
            male: true,
            online: true,
            following_allowed: false,
            figure: "hr".into(),
            category_id: 2,
            motto: "m".into(),
            real_name: "".into(),
            facebook_id: "".into(),
            persisted_message_user: false,
            vip_member: true,
            pocket_habbo_user: false,
            relationship_status: 1,
            category_name: None,
        };
        let friends = vec![friend; 101];
        let mut packets = HFriend::construct_fragments(&friends, 2).unwrap();
        assert_eq!(packets.len(), 2);
        let (pages, index, first) = HFriend::parse_fragment(&mut packets[0]).unwrap();
        assert_eq!((pages, index, first.len()), (2, 0, 100));
        let (_, _, last) = HFriend::parse_fragment(&mut packets[1]).unwrap();
        assert_eq!(last[0], friends[100]);
        let mut update = Packet::new(3);
        update
            .put_i32(1)
            .unwrap()
            .put_i32(2)
            .unwrap()
            .put_string("Friends")
            .unwrap()
            .put_i32(2)
            .unwrap()
            .put_i32(0)
            .unwrap();
        friends[0].append(&mut update).unwrap();
        update.put_i32(-1).unwrap().put_i32(99).unwrap();
        let (changed, removed) = HFriend::parse_update(&mut update).unwrap();
        assert_eq!(changed[0].category_name.as_deref(), Some("Friends"));
        assert_eq!(removed, vec![99]);
    }
}
