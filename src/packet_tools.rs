//! Packet conversions shared by the built-in tools panel.
use crate::{
    expression,
    packet::{error, Direction, Packet, PacketFormat, Result},
    packet_info::PacketInfoManager,
    structure_prediction,
};

pub fn encode_i32(value: &str) -> Result<String> {
    let value = value
        .trim()
        .parse::<i32>()
        .map_err(|_| error("invalid 32-bit integer"))?;
    Ok(expression::wire_display(&value.to_be_bytes()))
}

pub fn encode_u16(value: &str) -> Result<String> {
    let value = value
        .trim()
        .parse::<u16>()
        .map_err(|_| error("unsigned short must be between 0 and 65535"))?;
    Ok(expression::wire_display(&value.to_be_bytes()))
}

fn decode_raw<const N: usize>(input: &str) -> Result<[u8; N]> {
    if input.len() > 4096 {
        return Err(error("encoded value is too long"));
    }
    let packet = expression::parse(&format!("{{h:0}}{input}"))?;
    packet
        .body()
        .try_into()
        .map_err(|_| error("encoded value has the wrong byte length"))
}

pub fn decode_i32(input: &str) -> Result<i32> {
    Ok(i32::from_be_bytes(decode_raw(input)?))
}
pub fn decode_u16(input: &str) -> Result<u16> {
    Ok(u16::from_be_bytes(decode_raw(input)?))
}

pub fn expression_to_hex(
    input: &str,
    format: PacketFormat,
    direction: Direction,
    info: &PacketInfoManager,
) -> Result<String> {
    let packet = expression::parse_with_format(input, format, Some((direction, info)))?;
    Ok(expression::hex(packet.bytes()))
}

pub fn hex_to_expression(input: &str, format: PacketFormat) -> Result<String> {
    let packet = Packet::from_bytes_with_format(format, expression::parse_hex(input)?)?;
    Ok(expression::to_lossless_expression(&packet))
}

/// Produce G-Earth's legacy packet notation from a typed or named expression.
pub fn expression_to_wire(
    input: &str,
    format: PacketFormat,
    direction: Direction,
    info: &PacketInfoManager,
) -> Result<String> {
    let packet = expression::parse_with_format(input, format, Some((direction, info)))?;
    Ok(expression::wire_display(packet.bytes()))
}

/// Prefer a readable structure when it reconstructs the exact bytes; otherwise retain
/// the compatible legacy notation instead of silently losing packet data.
pub fn wire_to_expression(
    input: &str,
    format: PacketFormat,
    direction: Direction,
    info: &PacketInfoManager,
    unity: bool,
) -> Result<(String, bool)> {
    let packet = expression::parse_with_format(input, format, Some((direction, info)))?;
    if let Ok((candidate, _)) =
        structure_prediction::expression_with_metadata(&packet, direction, info, unity)
    {
        if !candidate.is_empty()
            && expression::parse_with_format(&candidate, format, Some((direction, info)))
                .is_ok_and(|reconstructed| reconstructed.bytes() == packet.bytes())
        {
            return Ok((candidate, true));
        }
    }
    Ok((expression::wire_display(packet.bytes()), false))
}

/// Limit desktop preview work while leaving the underlying packet unchanged.
pub fn hex_preview(packet: &Packet, max_bytes: usize) -> String {
    let bytes = packet.bytes();
    let shown = bytes.len().min(max_bytes);
    let mut result = expression::hex(&bytes[..shown]);
    if shown < bytes.len() {
        use std::fmt::Write;
        write!(result, " ... ({} bytes omitted)", bytes.len() - shown).unwrap();
    }
    result
}
