//! Packet representation options for the built-in logger.
use crate::{
    expression,
    packet::{Direction, PacketFormat},
};
use std::{fs::OpenOptions, io, path::Path};

/// Java shows no byte header when all byte views are disabled.
pub fn hide_empty_byte_header(
    enabled: bool,
    representation: PacketRepresentation,
    extra_legacy: bool,
    extra_hex_dump: bool,
    extra_raw_hex: bool,
) -> bool {
    enabled
        && representation == PacketRepresentation::NoBytes
        && !extra_legacy
        && !extra_hex_dump
        && !extra_raw_hex
}

/// Keep the display choice while optionally including separators in exports.
pub fn export_separators(display_separators: bool, force_export: bool) -> bool {
    display_separators || force_export
}

/// Decide whether a packet enters the logger's retained capture.
pub fn capture_direction(
    direction: Direction,
    incoming: bool,
    outgoing: bool,
    selected_only: bool,
) -> bool {
    !selected_only
        || match direction {
            Direction::ToClient => incoming,
            Direction::ToServer => outgoing,
        }
}

/// In capture-only mode direction choices affect future packets, not retained rows.
pub fn displayed_directions(incoming: bool, outgoing: bool, selected_only: bool) -> (bool, bool) {
    if selected_only {
        (true, true)
    } else {
        (incoming, outgoing)
    }
}

/// Visibility of the optional logger panel and its connection lifecycle options.
#[derive(Default)]
pub struct LoggerWindow {
    pub open: bool,
    pub open_on_connect: bool,
    pub hide_on_disconnect: bool,
    pub always_on_top: bool,
}
impl LoggerWindow {
    pub fn on_connect(&mut self) {
        if self.open_on_connect {
            self.open = true;
        }
    }
    pub fn on_disconnect(&mut self) {
        if self.hide_on_disconnect {
            self.open = false;
        }
    }
}

#[cfg(test)]
mod window_tests {
    use super::LoggerWindow;

    #[test]
    fn visibility_follows_enabled_lifecycle_options() {
        let mut window = LoggerWindow::default();
        window.on_connect();
        assert!(!window.open);
        window.open_on_connect = true;
        window.always_on_top = true;
        window.on_connect();
        assert!(window.open);
        window.on_disconnect();
        assert!(window.open);
        window.hide_on_disconnect = true;
        window.on_disconnect();
        assert!(!window.open);
        assert!(window.always_on_top);
        window.open_on_connect = false;
        window.open = true;
        window.on_connect();
        assert!(window.open);
    }
}

/// Replace a capture only after its complete contents have been written and flushed.
pub fn write_atomic(
    path: &Path,
    write: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|error| io::Error::other(error.to_string()))?;
    let suffix = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temporary = parent.join(format!(".gearth-capture-{suffix}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = write(&mut file).and_then(|_| file.sync_all());
    drop(file);
    let result = result.and_then(|_| std::fs::rename(&temporary, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PacketRepresentation {
    #[default]
    Expression,
    NoBytes,
    Legacy,
    RawHex,
    HexDump,
}

/// beta-29 omits byte representations for large EVA packets, but keeps the
/// packet and its structured display available. `frame_len` includes the
/// four-byte EVA length prefix, while Java's HPacket.length() excludes it.
pub fn skip_large_eva_representations(frame_len: usize, hex_dump_enabled: bool) -> bool {
    skip_java_packet_representations(PacketFormat::EvaWire, frame_len, hex_dump_enabled)
}

/// Java's logger uses the EVA body length but the complete WEDGIE frame length.
pub fn java_packet_length(format: PacketFormat, frame_len: usize) -> usize {
    if format == PacketFormat::EvaWire {
        frame_len.saturating_sub(4)
    } else {
        frame_len
    }
}

pub fn skip_java_packet_representations(
    format: PacketFormat,
    frame_len: usize,
    hex_dump_enabled: bool,
) -> bool {
    let packet_len = java_packet_length(format, frame_len);
    packet_len > 4000 || (hex_dump_enabled && packet_len > 1000)
}

pub fn allow_java_packet_structure(
    format: PacketFormat,
    frame_len: usize,
    java_limit: bool,
) -> bool {
    !java_limit || java_packet_length(format, frame_len) <= 2000
}

/// Java's logger limits structure rendering by the EVA length field, excluding
/// its four-byte prefix. Other packet formats retain their existing behavior.
pub fn allow_eva_structure(frame_len: usize, java_limit: bool) -> bool {
    allow_java_packet_structure(PacketFormat::EvaWire, frame_len, java_limit)
}

/// Whether Java's cleanTextContent would leave this expression unchanged.
pub fn java_structure_is_clean(value: &str) -> bool {
    value.trim_matches(|c: char| c <= '\u{20}') == value
        && !value
            .chars()
            .any(|c| (c <= '\u{1f}' || c == '\u{7f}') && c != '\n' && c != '\t')
}

impl PacketRepresentation {
    pub fn translation_key(self) -> &'static str {
        match self {
            Self::Expression => "tab.tools.expression",
            Self::NoBytes => "rust.logger.no_representation",
            Self::Legacy => "ext.logger.menu.packets.displaydetails.byterep.legacy",
            Self::RawHex => "ext.logger.menu.packets.displaydetails.byterep.rawhex",
            Self::HexDump => "ext.logger.menu.packets.displaydetails.byterep.hexdump",
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Expression => "Expression",
            Self::NoBytes => "No bytes",
            Self::Legacy => "Legacy",
            Self::RawHex => "Raw hex",
            Self::HexDump => "Hexdump",
        }
    }

    pub fn from_setting(value: &str) -> Self {
        match value {
            "No bytes" => Self::NoBytes,
            "Legacy" => Self::Legacy,
            "Raw hex" => Self::RawHex,
            "Hexdump" => Self::HexDump,
            _ => Self::Expression,
        }
    }
}

/// Format at most `byte_limit` bytes; preserve the stored packet for injection.
pub fn represent(bytes: &[u8], mode: PacketRepresentation, byte_limit: usize) -> String {
    let shown = &bytes[..bytes.len().min(byte_limit)];
    let mut result = match mode {
        PacketRepresentation::Legacy => expression::wire_display(shown),
        PacketRepresentation::RawHex => {
            use std::fmt::Write;
            let mut result = String::with_capacity(shown.len().saturating_mul(2));
            for byte in shown {
                write!(result, "{byte:02x}").expect("writing to string");
            }
            result
        }
        PacketRepresentation::HexDump => return hex_dump(bytes, byte_limit),
        PacketRepresentation::Expression | PacketRepresentation::NoBytes => return String::new(),
    };
    if shown.len() < bytes.len() {
        result.push('…');
    }
    result
}

/// Render the original logger's 16-byte lines, with printable character annotations.
pub fn hex_dump(bytes: &[u8], byte_limit: usize) -> String {
    use std::fmt::Write;
    if bytes.is_empty() {
        return "empty".into();
    }
    let shown = &bytes[..bytes.len().min(byte_limit)];
    let mut output = String::new();
    for (line, chunk) in shown.chunks(16).enumerate() {
        write!(output, "{:08x}  ", line * 16).unwrap();
        for value in chunk.iter().take(8) {
            write!(output, "{value:02x} ").unwrap();
        }
        output.push(' ');
        for value in chunk.iter().skip(8) {
            write!(output, "{value:02x} ").unwrap();
        }
        for _ in chunk.len()..16 {
            output.push_str("   ");
        }
        output.push_str(" |");
        for byte in chunk {
            output.push(match byte {
                b' ' => '\u{2423}',
                b'\t' => '\u{2192}',
                b'\n' => '\u{00b6}',
                b'\r' => '\u{00a4}',
                33..=126 => char::from(*byte),
                _ => '\u{25a1}',
            });
        }
        output.push_str("|\n");
    }
    write!(output, "{:08x}", shown.len()).unwrap();
    if shown.len() < bytes.len() {
        write!(output, "\n[{} bytes not shown]", bytes.len() - shown.len()).unwrap();
    }
    output
}
