//! Multi-packet injection parsing and bounded, persistent history.
use crate::{
    expression,
    packet::{error, Direction, Packet, PacketFormat, Result, MAX_FRAME},
    packet_info::PacketInfoManager,
};
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, io, path::Path};

const MAX_BATCH: usize = 256;
const HISTORY_LIMIT: usize = 69;
const HISTORY_ENTRY_LIMIT: usize = 8192;
// History is stored as a JSON string inside the settings JSON. Account for both
// layers of escaping so unusual packet text cannot fill the entire settings file.
const HISTORY_SETTINGS_LIMIT: usize = 512 * 1024;

/// Check each destination independently because packet names and formats can differ.
pub fn valid_destinations(
    input: &str,
    server_format: PacketFormat,
    client_format: PacketFormat,
    info: &PacketInfoManager,
) -> (bool, bool) {
    (
        parse_packets(input, server_format, Direction::ToServer, info).is_ok(),
        parse_packets(input, client_format, Direction::ToClient, info).is_ok(),
    )
}

/// Validate the whole batch before submitting any packet to the connection.
pub fn parse_packets(
    input: &str,
    format: PacketFormat,
    direction: Direction,
    info: &PacketInfoManager,
) -> Result<Vec<Packet>> {
    if input.len() > MAX_FRAME {
        return Err(error("injection input is too large"));
    }
    let input = input.trim_end_matches(['\r', '\n']);
    if input.is_empty() {
        return Err(error("enter a packet"));
    }
    let mut packets = Vec::new();
    let mut start = 0;
    let mut field = false;
    let mut quoted = false;
    let mut escaped = false;
    for (index, c) in input.char_indices() {
        if field && quoted && escaped {
            escaped = false;
            continue;
        }
        if field && quoted && c == '\\' {
            escaped = true;
            continue;
        }
        if field && c == '"' {
            quoted = !quoted;
            continue;
        }
        if !quoted && c == '{' {
            field = true;
        }
        if !quoted && c == '}' {
            field = false;
        }
        if !field && c == '\n' {
            push_packet(
                &mut packets,
                input[start..index].trim_end_matches('\r'),
                format,
                direction,
                info,
            )?;
            start = index + 1;
        }
    }
    push_packet(&mut packets, &input[start..], format, direction, info)?;
    Ok(packets)
}

fn push_packet(
    packets: &mut Vec<Packet>,
    text: &str,
    format: PacketFormat,
    direction: Direction,
    info: &PacketInfoManager,
) -> Result<()> {
    if packets.len() >= MAX_BATCH {
        return Err(error("too many packets in one injection"));
    }
    let packet = expression::parse_with_format(text, format, Some((direction, info)))
        .map_err(|e| error(&format!("packet {}: {e}", packets.len() + 1)))?;
    packets.push(packet);
    Ok(())
}

/// Submit packets in order and report how many were accepted before an error.
pub fn enqueue_packets<E>(
    packets: Vec<Packet>,
    mut enqueue: impl FnMut(Packet) -> std::result::Result<(), E>,
) -> std::result::Result<usize, (usize, E)> {
    let mut accepted = 0;
    for packet in packets {
        if let Err(error) = enqueue(packet) {
            return Err((accepted, error));
        }
        accepted += 1;
    }
    Ok(accepted)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub expression: String,
    pub direction: String,
}

#[derive(Default)]
pub struct InjectionHistory {
    entries: VecDeque<HistoryEntry>,
}
impl InjectionHistory {
    pub fn entries(&self) -> &VecDeque<HistoryEntry> {
        &self.entries
    }
    pub fn clear(&mut self) {
        self.entries.clear();
    }
    pub fn record(&mut self, expression: &str, direction: Direction) -> bool {
        if expression.is_empty() || expression.len() > HISTORY_ENTRY_LIMIT {
            return false;
        }
        if self.entries.front().is_some_and(|entry| {
            entry.expression == expression && entry.direction == direction.name()
        }) {
            return true;
        }
        self.entries.push_front(HistoryEntry {
            expression: expression.into(),
            direction: direction.name().into(),
        });
        self.trim_to_limits();
        true
    }
    pub fn from_json(value: &str) -> Self {
        let entries: Vec<HistoryEntry> = serde_json::from_str(value).unwrap_or_default();
        let entries = entries
            .into_iter()
            .filter(|entry| {
                !entry.expression.is_empty()
                    && entry.expression.len() <= HISTORY_ENTRY_LIMIT
                    && Direction::parse(&entry.direction).is_ok()
            })
            .take(HISTORY_LIMIT)
            .collect();
        let mut history = Self { entries };
        history.trim_to_limits();
        history
    }
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.entries).expect("history contains serializable strings")
    }
    fn trim_to_limits(&mut self) {
        self.entries.truncate(HISTORY_LIMIT);
        while !self.entries.is_empty()
            && serde_json::to_string(&self.to_json())
                .expect("serializable history")
                .len()
                > HISTORY_SETTINGS_LIMIT
        {
            self.entries.pop_back();
        }
    }

    /// Update only history in the current settings file, preserving unrelated settings.
    pub fn save_to_settings(&self, path: &Path) -> io::Result<()> {
        let mut settings = match crate::settings::Settings::read(path) {
            Ok(settings) => settings,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                crate::settings::Settings::default()
            }
            Err(error) => return Err(error),
        };
        settings
            .values
            .insert("injection_history".into(), self.to_json());
        settings.save(path)
    }
}
