//! Packet representation options for the built-in logger.
use crate::expression;
use std::{fs::OpenOptions, io, path::Path};

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
    Legacy,
    RawHex,
    HexDump,
}

/// beta-29 omits byte representations for large EVA packets, but keeps the
/// packet and its structured display available. `frame_len` includes the
/// four-byte EVA length prefix, while Java's HPacket.length() excludes it.
pub fn skip_large_eva_representations(frame_len: usize, hex_dump_enabled: bool) -> bool {
    let packet_len = frame_len.saturating_sub(4);
    packet_len > 4000 || (hex_dump_enabled && packet_len > 1000)
}

impl PacketRepresentation {
    pub fn translation_key(self) -> &'static str {
        match self {
            Self::Expression => "tab.tools.expression",
            Self::Legacy => "ext.logger.menu.packets.displaydetails.byterep.legacy",
            Self::RawHex => "ext.logger.menu.packets.displaydetails.byterep.rawhex",
            Self::HexDump => "ext.logger.menu.packets.displaydetails.byterep.hexdump",
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Expression => "Expression",
            Self::Legacy => "Legacy",
            Self::RawHex => "Raw hex",
            Self::HexDump => "Hexdump",
        }
    }

    pub fn from_setting(value: &str) -> Self {
        match value {
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
        PacketRepresentation::Expression => return String::new(),
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
