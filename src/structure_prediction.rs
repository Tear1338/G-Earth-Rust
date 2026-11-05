//! Bounded port of beta-29's heuristic packet structure predictor.
use crate::packet::{error, Packet, PacketFormat, Result};

const MAX_BYTES: usize = 256 * 1024;
const MAX_SCAN: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Node {
    previous: usize,
    code: char,
    score: f64,
}

fn candidate_string(bytes: &[u8], pos: usize) -> Option<&[u8]> {
    let len = u16::from_be_bytes(bytes.get(pos..pos + 2)?.try_into().ok()?) as usize;
    bytes.get(pos + 2..pos.checked_add(2)?.checked_add(len)?)
}
fn common(b: u8) -> usize {
    if matches!(b, b'\n' | b'\r' | b'\t') {
        1
    } else if (32..=126).contains(&b) {
        2
    } else {
        0
    }
}
fn string_score(bytes: &[u8], scan: &mut usize) -> Result<f64> {
    *scan = scan
        .checked_add(bytes.len())
        .ok_or_else(|| error("prediction scan budget exceeded"))?;
    if *scan > MAX_SCAN {
        return Err(error("prediction scan budget exceeded"));
    }
    if bytes.is_empty() {
        return Ok(0.8);
    }
    let len = bytes.len() as f64;
    let penalties = [
        -1.0 / (len * 0.3 + 2.0) + 0.5,
        -1.0 / (len + 2.0) + 1.0,
        if bytes.len() == 1 {
            0.9
        } else if bytes.len() == 2 {
            0.98
        } else {
            1.0
        },
    ];
    let mut score = 1.0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let remaining = bytes.len() - i;
        let utf = if b & 0xe0 == 0xc0 && remaining >= 2 && bytes[i + 1] & 0xc0 == 0x80 {
            2
        } else if b & 0xf0 == 0xe0
            && remaining >= 3
            && bytes[i + 1] & 0xc0 == 0x80
            && bytes[i + 2] & 0xc0 == 0x80
        {
            3
        } else if b & 0xf8 == 0xf0
            && remaining >= 4
            && bytes[i + 1] & 0xc0 == 0x80
            && bytes[i + 2] & 0xc0 == 0x80
            && bytes[i + 3] & 0xc0 == 0x80
        {
            4
        } else {
            0
        };
        if utf > 0 {
            for _ in 0..utf {
                score *= penalties[2];
            }
            i += utf;
        } else {
            score *= penalties[common(b)];
            if score < 0.001 {
                return Ok(0.0);
            }
            i += 1;
        }
    }
    Ok(score)
}
fn int_score(bytes: &[u8], pos: usize, scan: &mut usize) -> Result<f64> {
    let b = &bytes[pos..pos + 4];
    let value = i32::from_be_bytes(b.try_into().unwrap());
    let first = u16::from_be_bytes([b[0], b[1]]);
    let second = u16::from_be_bytes([b[2], b[3]]);
    if first != 0 && matches!(second, 0 | 1 | 256 | 257) {
        return Ok(0.05);
    }
    if value == 256 {
        return Ok(0.04);
    }
    if first == 2 {
        if let Some(s) = candidate_string(bytes, pos) {
            return Ok(1.0 - string_score(s, scan)?);
        }
    }
    if b.iter().all(|byte| common(*byte) == 2) {
        return Ok(0.2);
    }
    if pos > 0 {
        if let Some(s) = candidate_string(bytes, pos - 1) {
            if s.len() > 2 && s.len() < 10 {
                let score = string_score(s, scan)?;
                if score > 0.5 {
                    return Ok(1.0 - score);
                }
            }
        }
    }
    let offset = (pos + 6) as f64 / 1_000_000_000.0;
    Ok(if value == -1 {
        1.0 - offset
    } else if value == 0 {
        0.99 - offset
    } else if value % 256 == 0 || (value != 1 && value % 256 == 1) {
        0.06 - offset
    } else if value >= -1 {
        0.92 - offset
    } else {
        0.8 - offset
    })
}

/// Predicts primitive field codes. The Unity option enables its extra long/short heuristics.
/// The heuristic is intentionally bounded and returns an error for oversized or costly inputs.
pub fn predict(packet: &Packet, unity: bool) -> Result<String> {
    if packet.format() != PacketFormat::EvaWire {
        return Err(error("structure prediction requires EVA_WIRE"));
    }
    let bytes = packet.body();
    if bytes.len() > MAX_BYTES {
        return Err(error("packet exceeds structure prediction limit"));
    }
    let mut nodes = vec![None; bytes.len() + 1];
    nodes[0] = Some(Node {
        previous: 0,
        code: '\0',
        score: 0.0,
    });
    let mut scan = 0usize;
    for pos in 0..bytes.len() {
        let current = nodes[pos]
            .expect("byte candidate reaches every position")
            .score;
        let mut update = |next: usize, code: char, probability: f64| {
            if probability <= 0.0 {
                return;
            }
            let score = current + probability.ln();
            if nodes[next].is_none_or(|node| score > node.score) {
                nodes[next] = Some(Node {
                    previous: pos,
                    code,
                    score,
                });
            }
        };
        let b = bytes[pos];
        if b <= 1 {
            update(pos + 1, 'B', if b == 1 { 0.6 } else { 0.5 });
        }
        update(pos + 1, 'b', 0.4);
        if bytes.len() - pos >= 4 {
            update(pos + 4, 'i', int_score(bytes, pos, &mut scan)?);
        }
        if let Some(s) = candidate_string(bytes, pos) {
            let score =
                (string_score(s, &mut scan)? - (pos + 6) as f64 / 1_000_000_000_000.0).max(0.0);
            update(pos + 2 + s.len(), 's', score);
        }
        if unity && bytes.len() - pos >= 8 {
            let first = i32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap());
            let second = i32::from_be_bytes(bytes[pos + 4..pos + 8].try_into().unwrap());
            let zeros = bytes[pos + 4..pos + 8].iter().filter(|b| **b == 0).count();
            let score = if second > 196_608 && first == 0 && zeros < 2 {
                int_score(bytes, pos, &mut scan)? * int_score(bytes, pos + 4, &mut scan)?
                    + 0.0000000001
            } else {
                0.0
            };
            update(pos + 8, 'l', score);
        }
        if unity && bytes.len() - pos >= 2 {
            let value = i16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
            let score =
                if pos == 0 && value == 0 && packet.bytes().len().saturating_sub(4) == pos + 8 {
                    1.0
                } else if value <= 0 {
                    0.0
                } else if value < 1000 {
                    0.5
                } else {
                    let unit = |b: u8| {
                        if b == 0 {
                            0.5
                        } else if b == 1 {
                            0.6
                        } else {
                            0.4
                        }
                    };
                    unit(bytes[pos]) * unit(bytes[pos + 1]) + 0.00000001
                };
            update(pos + 2, 'u', score);
        }
    }
    let mut out = String::new();
    let mut at = bytes.len();
    while at > 0 {
        let node = nodes[at].expect("complete byte path");
        out.push(node.code);
        at = node.previous;
    }
    Ok(out.chars().rev().collect())
}

/// Produces the numeric-header expression used by beta-29 when no identifier is known.
pub fn predicted_expression(packet: &Packet, unity: bool) -> Result<String> {
    let structure = predict(packet, unity)?;
    expression_from_structure(packet, &structure, None)
}

#[derive(Debug)]
enum Field {
    Value(u8),
    Repeat(Vec<Field>),
}

fn parse_fields(bytes: &[u8], at: &mut usize, depth: usize) -> Result<Vec<Field>> {
    if depth > 64 {
        return Err(error("structure nesting limit exceeded"));
    }
    let mut fields = Vec::new();
    while *at < bytes.len() {
        let code = bytes[*at];
        *at += 1;
        match code {
            b')' if depth > 0 => return Ok(fields),
            b')' => return Err(error("unexpected structure close")),
            b'(' => fields.push(Field::Repeat(parse_fields(bytes, at, depth + 1)?)),
            b'i' | b's' | b'd' | b'f' | b'b' | b'B' | b'l' | b'u' => {
                fields.push(Field::Value(code))
            }
            _ => return Err(error("unknown structure field")),
        }
    }
    if depth > 0 {
        return Err(error("unterminated structure group"));
    }
    Ok(fields)
}

/// Formats an upstream structure, including count-prefixed nested repetitions.
pub fn expression_from_structure(
    packet: &Packet,
    structure: &str,
    identifier: Option<&str>,
) -> Result<String> {
    if structure.len() > MAX_BYTES {
        return Err(error("packet structure exceeds limit"));
    }
    let mut at = 0;
    let fields = parse_fields(structure.as_bytes(), &mut at, 0)?;
    let mut reader = packet.clone();
    reader.reset();
    let mut output = identifier
        .map(|name| format!("{{{name}}}"))
        .unwrap_or_else(|| format!("{{h:{}}}", packet.header() as i16));
    fn append(
        fields: &[Field],
        reader: &mut Packet,
        out: &mut String,
        budget: &mut usize,
    ) -> Result<()> {
        use std::fmt::Write as _;
        let mut previous = 0i32;
        for field in fields {
            *budget = budget
                .checked_sub(1)
                .ok_or_else(|| error("structure expansion limit exceeded"))?;
            match field {
                Field::Repeat(nested) => {
                    let repeats = usize::try_from(previous.max(0)).unwrap_or(usize::MAX);
                    if repeats > *budget {
                        return Err(error("structure expansion limit exceeded"));
                    }
                    for _ in 0..repeats {
                        append(nested, reader, out, budget)?;
                    }
                }
                Field::Value(code) => match code {
                    b'B' => write!(out, "{{b:{}}}", reader.read_bool()?).unwrap(),
                    b'b' => write!(out, "{{b:{}}}", reader.read_u8()?).unwrap(),
                    b'i' => {
                        previous = reader.read_i32()?;
                        write!(out, "{{i:{previous}}}").unwrap();
                    }
                    b'l' => write!(out, "{{l:{}}}", reader.read_i64()?).unwrap(),
                    b'u' => write!(out, "{{u:{}}}", reader.read_u16()? as i16).unwrap(),
                    b'd' => write!(
                        out,
                        "{{d:{}}}",
                        crate::parsers::java_double(reader.read_f64()?)
                    )
                    .unwrap(),
                    b'f' => {
                        let value = reader.read_f32()?;
                        let shortest = format!("{value:?}")
                            .parse::<f64>()
                            .map_err(|_| error("invalid floating-point field"))?;
                        write!(out, "{{f:{}}}", crate::parsers::java_double(shortest)).unwrap();
                    }
                    b's' => {
                        let value = reader
                            .read_string()?
                            .replace('\\', "\\\\")
                            .replace('"', "\\\"")
                            .replace('\r', "\\r");
                        write!(out, "{{s:\"{value}\"}}").unwrap();
                    }
                    _ => return Err(error("unsupported structure field")),
                },
            }
            if out.len() > MAX_SCAN {
                return Err(error("structure output exceeds limit"));
            }
        }
        Ok(())
    }
    let mut budget = 1_000_000;
    append(&fields, &mut reader, &mut output, &mut budget)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn predicts_common_fields_and_handles_empty() {
        let mut p = Packet::new(1);
        assert_eq!(predict(&p, false).unwrap(), "");
        p.put_i32(42)
            .unwrap()
            .put_string("hello")
            .unwrap()
            .put_bool(true)
            .unwrap();
        assert_eq!(predict(&p, false).unwrap(), "isB");
    }
    #[test]
    fn rejects_excessive_input() {
        let mut p = Packet::new(1);
        p.append(&vec![0; MAX_BYTES + 1]).unwrap();
        assert!(predict(&p, false).is_err());
    }
    #[test]
    fn rejects_unbounded_or_malformed_structure_expansion() {
        let mut packet = Packet::new(1);
        packet.put_i32(i32::MAX).unwrap();
        assert!(expression_from_structure(&packet, "i()", None).is_err());
        assert!(expression_from_structure(&packet, "i(", None).is_err());
        assert!(expression_from_structure(&packet, &"(".repeat(66), None).is_err());
    }
}
