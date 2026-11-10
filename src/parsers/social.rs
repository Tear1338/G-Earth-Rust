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

/// A friend-list update. The type for an upsert is supplied by the caller;
/// -1 is reserved for removals in the beta-29 parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HFriendChange {
    Upsert { change_type: i32, friend: HFriend },
    Removed(i32),
}

/// Categories and changes in their original packet order, including unused categories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HFriendUpdate {
    pub categories: Vec<(i32, String)>,
    pub changes: Vec<HFriendChange>,
}

impl HFriendUpdate {
    pub fn parse(packet: &mut Packet) -> Result<Self> {
        Self::parse_inner(packet, false)
    }
    /// Match beta-29's static update parsers, which reset the read cursor and
    /// interpret negative category and update counts as empty loops.
    pub fn parse_java(packet: &mut Packet) -> Result<Self> {
        packet.reset();
        Self::parse_inner(packet, true)
    }
    fn parse_inner(packet: &mut Packet, java: bool) -> Result<Self> {
        let read_count = |packet: &mut Packet| -> Result<usize> {
            if !java {
                return count(packet);
            }
            let count = packet.read_i32()?.max(0) as usize;
            if count > 65_536 {
                return Err(error("too many social entries"));
            }
            Ok(count)
        };
        let category_count = read_count(packet)?;
        let mut categories = Vec::with_capacity(category_count);
        let mut lookup = BTreeMap::new();
        for _ in 0..category_count {
            let id = packet.read_i32()?;
            let name = packet.read_string()?;
            lookup.insert(id, name.clone());
            categories.push((id, name));
        }
        let n = read_count(packet)?;
        let mut changes = Vec::with_capacity(n);
        for _ in 0..n {
            let change_type = packet.read_i32()?;
            if change_type == -1 {
                changes.push(HFriendChange::Removed(packet.read_i32()?));
            } else {
                let mut friend = HFriend::read(packet)?;
                friend.category_name = lookup.get(&friend.category_id).cloned();
                changes.push(HFriendChange::Upsert {
                    change_type,
                    friend,
                });
            }
        }
        Ok(Self {
            categories,
            changes,
        })
    }
    pub fn construct(&self, header: u16) -> Result<Packet> {
        construct_friend_update(&self.categories, &self.changes, header)
    }
}

fn construct_friend_update(
    categories: &[(i32, String)],
    changes: &[HFriendChange],
    header: u16,
) -> Result<Packet> {
    if categories.len() > 65_536 || changes.len() > 65_536 {
        return Err(error("too many friend categories or changes"));
    }
    let mut packet = Packet::new(header);
    packet.put_i32(categories.len() as i32)?;
    for (id, name) in categories {
        packet.put_i32(*id)?.put_string(name)?;
    }
    packet.put_i32(changes.len() as i32)?;
    for change in changes {
        match change {
            HFriendChange::Upsert {
                change_type,
                friend,
            } => {
                if *change_type == -1 {
                    return Err(error("friend change type -1 is reserved for removals"));
                }
                packet.put_i32(*change_type)?;
                friend.append(&mut packet)?;
            }
            HFriendChange::Removed(id) => {
                packet.put_i32(-1)?.put_i32(*id)?;
            }
        }
    }
    Ok(packet)
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
    /// Java returns null for an unrecognized relationship ID.
    pub fn java_relationship_status(&self) -> Option<u16> {
        (self.relationship_status <= 3).then_some(self.relationship_status)
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
    /// Match beta-29's static fragment parser, which seeks directly to byte 14.
    pub fn parse_fragment_java(packet: &mut Packet) -> Result<Vec<Self>> {
        packet.set_cursor(14)?;
        let n = count(packet)?;
        let mut friends = Vec::with_capacity(n);
        for _ in 0..n {
            friends.push(Self::read(packet)?);
        }
        Ok(friends)
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
        let mut friends = Vec::new();
        let mut removed = Vec::new();
        for change in Self::parse_update_changes(packet)? {
            match change {
                HFriendChange::Upsert { friend, .. } => friends.push(friend),
                HFriendChange::Removed(id) => removed.push(id),
            }
        }
        Ok((friends, removed))
    }
    /// Parse friend changes in wire order, retaining each non-removal type.
    pub fn parse_update_changes(packet: &mut Packet) -> Result<Vec<HFriendChange>> {
        Ok(HFriendUpdate::parse(packet)?.changes)
    }
    /// Reproduce beta-29's `constructUpdatePacket`, which omits change types.
    /// Java's HashMap can serialize category entries in a different order.
    pub fn construct_java_update(friends: &[Self], header: u16) -> Result<Packet> {
        if friends.len() > 65_536 {
            return Err(error("too many friend changes"));
        }
        let mut categories = BTreeMap::new();
        for friend in friends {
            if let Some(name) = &friend.category_name {
                categories.insert(friend.category_id, name);
            }
        }
        let mut packet = Packet::new(header);
        packet.put_i32(categories.len() as i32)?;
        for (id, name) in categories {
            packet.put_i32(id)?.put_string(name)?;
        }
        packet.put_i32(friends.len() as i32)?;
        for friend in friends {
            friend.append(&mut packet)?;
        }
        Ok(packet)
    }
    /// Construct an update with explicit change types and optional removals.
    pub fn construct_update(changes: &[HFriendChange], header: u16) -> Result<Packet> {
        if changes.len() > 65_536 {
            return Err(error("too many friend changes"));
        }
        let mut categories = BTreeMap::new();
        for change in changes {
            if let HFriendChange::Upsert {
                change_type,
                friend,
            } = change
            {
                if *change_type == -1 {
                    return Err(error("friend change type -1 is reserved for removals"));
                }
                if let Some(name) = &friend.category_name {
                    categories.insert(friend.category_id, name);
                }
            }
        }
        let categories: Vec<_> = categories
            .into_iter()
            .map(|(id, name)| (id, name.clone()))
            .collect();
        construct_friend_update(&categories, changes, header)
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
        let changes = vec![
            HFriendChange::Upsert {
                change_type: 0,
                friend: changed[0].clone(),
            },
            HFriendChange::Removed(99),
        ];
        let mut built = HFriend::construct_update(&changes, 3).unwrap();
        assert_eq!(built.bytes(), update.bytes());
        let java_vector = crate::expression::parse_hex(concat!(
            "00000046000300000001000000020007467269656e64730000000200000000",
            "000000080003426f62000000010100000268720000000200016d0000000000",
            "01000001ffffffff00000063"
        ))
        .unwrap();
        assert_eq!(built.bytes(), java_vector);
        let (roundtrip, removed) = HFriend::parse_update(&mut built).unwrap();
        assert_eq!(roundtrip, changed);
        assert_eq!(removed, [99]);
        assert!(HFriend::construct_update(
            &[HFriendChange::Upsert {
                change_type: -1,
                friend: changed[0].clone(),
            }],
            3
        )
        .is_err());
        let interleaved = vec![
            HFriendChange::Removed(99),
            HFriendChange::Upsert {
                change_type: 2,
                friend: changed[0].clone(),
            },
            HFriendChange::Removed(7),
            HFriendChange::Upsert {
                change_type: 0,
                friend: changed[0].clone(),
            },
        ];
        let mut original = HFriend::construct_update(&interleaved, 3).unwrap();
        let parsed = HFriend::parse_update_changes(&mut original).unwrap();
        assert_eq!(parsed, interleaved);
        assert_eq!(
            HFriend::construct_update(&parsed, 3).unwrap().bytes(),
            original.bytes()
        );
        let mut legacy_packet = HFriend::construct_update(&interleaved, 3).unwrap();
        let (friends, removed) = HFriend::parse_update(&mut legacy_packet).unwrap();
        assert_eq!(friends, vec![changed[0].clone(), changed[0].clone()]);
        assert_eq!(removed, [99, 7]);
        let full = HFriendUpdate {
            categories: vec![
                (9, "Unused".into()),
                (2, "Earlier".into()),
                (2, "Friends".into()),
            ],
            changes: interleaved,
        };
        let mut packet = full.construct(3).unwrap();
        let parsed = HFriendUpdate::parse(&mut packet).unwrap();
        assert_eq!(parsed, full);
        assert_eq!(parsed.construct(3).unwrap().bytes(), packet.bytes());
        packet.set_cursor(10).unwrap();
        assert_eq!(HFriendUpdate::parse_java(&mut packet).unwrap(), full);

        let mut original_friend = Packet::new(1);
        friends[0].append(&mut original_friend).unwrap();
        let mut invalid = original_friend.bytes().to_vec();
        let end = invalid.len();
        invalid[end - 2..].copy_from_slice(&[0xff, 0xff]);
        let unknown = HFriend::read(&mut Packet::from_bytes(invalid).unwrap()).unwrap();
        assert_eq!(unknown.java_relationship_status(), None);
        assert!(unknown.append(&mut Packet::new(1)).is_err());
    }
}
