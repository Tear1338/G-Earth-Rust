//! Tracking of packet IDs observed for each hotel revision.
//!
//! The Java connection uses this information to distinguish observed packet
//! IDs from IDs that have not appeared in normal traffic. This registry is an
//! in-memory building block; transport enforcement is not yet wired up.
use crate::packet::Direction;
use std::collections::{HashMap, HashSet};

const MAX_REVISIONS: usize = 64;
const MAX_REVISION_BYTES: usize = 1024;

#[derive(Default)]
pub struct PacketSafety {
    revisions: HashMap<String, HashSet<(Direction, u16)>>,
}

impl PacketSafety {
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
