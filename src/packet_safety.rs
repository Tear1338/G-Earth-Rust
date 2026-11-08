//! Tracking packet IDs observed in traffic or supplied by packet metadata per revision.
use crate::{packet::Direction, packet_info::PacketInfoManager};
use std::collections::{HashMap, HashSet};

const MAX_REVISIONS: usize = 64;
const MAX_REVISION_BYTES: usize = 1024;

#[derive(Default)]
pub struct PacketSafety {
    revisions: HashMap<String, HashSet<(Direction, u16)>>,
    developer_mode: bool,
}

impl PacketSafety {
    pub fn set_developer_mode(&mut self, enabled: bool) {
        self.developer_mode = enabled;
    }

    pub fn may_send_with_current_mode(
        &self,
        revision: Option<&str>,
        direction: Direction,
        header: u16,
    ) -> bool {
        self.may_send(revision, direction, header, self.developer_mode)
    }
    /// Empty revisions are ignored, as they are in the Java traffic listener.
    /// Returns false if a new revision cannot be tracked within the bounds.
    pub fn observe(&mut self, revision: &str, direction: Direction, header: u16) -> bool {
        if revision.is_empty() || revision.len() > MAX_REVISION_BYTES {
            return false;
        }
        if let Some(entries) = self.revisions.get_mut(revision) {
            entries.insert((direction, header));
            return true;
        }
        if self.revisions.len() >= MAX_REVISIONS {
            return false;
        }
        self.revisions
            .entry(revision.to_owned())
            .or_default()
            .insert((direction, header));
        true
    }

    /// Register identifiers supplied by the connection's packet metadata.
    /// Java also registers metadata for an empty revision; traffic observations
    /// alone do not create that entry. Returns false when revision bounds are hit.
    pub fn register_metadata(&mut self, revision: &str, metadata: &PacketInfoManager) -> bool {
        if revision.len() > MAX_REVISION_BYTES {
            return false;
        }
        if !self.revisions.contains_key(revision) && self.revisions.len() >= MAX_REVISIONS {
            return false;
        }
        let entries = self.revisions.entry(revision.to_owned()).or_default();
        entries.extend(
            metadata
                .entries()
                .iter()
                .map(|entry| (entry.direction, entry.header)),
        );
        true
    }

    /// A missing revision is treated as safe by the original Java connection;
    /// a present but empty revision is not, unless developer mode is enabled.
    pub fn is_safe(&self, revision: Option<&str>, direction: Direction, header: u16) -> bool {
        match revision {
            None => true,
            Some(revision) => self
                .revisions
                .get(revision)
                .is_some_and(|entries| entries.contains(&(direction, header))),
        }
    }

    pub fn may_send(
        &self,
        revision: Option<&str>,
        direction: Direction,
        header: u16,
        developer_mode: bool,
    ) -> bool {
        developer_mode || self.is_safe(revision, direction, header)
    }
}
