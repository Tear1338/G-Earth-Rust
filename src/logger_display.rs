//! Packet representation options for the built-in logger.
use crate::expression;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PacketRepresentation {
    #[default]
    Expression,
    Legacy,
    RawHex,
    HexDump,
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
