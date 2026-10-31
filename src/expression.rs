use crate::packet::{error, latin1_encode, Packet, Result};

/// Parse numeric EVA_WIRE expressions, e.g. {h:123}{i:42}{s:"hello"}{b:true}.
/// Named headers and expression prediction are tracked separately in PARITY.md.
pub fn parse(expression: &str) -> Result<Packet> {
    let mut rest = expression.trim(); let mut packet: Option<Packet> = None;
    while !rest.is_empty() {
        if !rest.starts_with('{') { return Err(error("expected '{'")); }
        let mut quoted = false; let mut escaped = false; let mut end = None;
        for (i,c) in rest.char_indices().skip(1) {
            if escaped { escaped = false; continue; }
            if c == '\\' && quoted { escaped = true; continue; }
            if c == '"' { quoted = !quoted; }
            if c == '}' && !quoted { end = Some(i); break; }
        }
        let end = end.ok_or_else(|| error("unterminated expression field"))?;
        let (kind,value) = rest[1..end].split_once(':').ok_or_else(|| error("missing ':'"))?;
        let value = value.trim();
        if packet.is_none() {
            if kind != "h" { return Err(error("first field must be a numeric header")); }
            packet = Some(Packet::new(value.parse().map_err(|_| error("invalid header"))?));
        } else {
            let p = packet.as_mut().unwrap();
            match kind {
                "i" => { p.put_i32(value.parse().map_err(|_| error("invalid integer"))?)?; }
                "l" => { p.put_i64(value.parse().map_err(|_| error("invalid long"))?)?; }
                "u" => { p.put_u16(value.parse().map_err(|_| error("invalid unsigned short"))?)?; }
                "b" => { match value { "true" => {p.put_bool(true)?;}, "false" => {p.put_bool(false)?;}, _ => {p.put_u8(value.parse().map_err(|_| error("invalid byte"))?)?;} } }
                "d" => { p.put_f64(value.parse().map_err(|_| error("invalid double"))?)?; }
                "f" => { p.put_f32(value.parse().map_err(|_| error("invalid float"))?)?; }
                "s" => { p.put_string(&unquote(value)?)?; }
                "ls" => { p.put_long_string(&unquote(value)?)?; }
                "hex" => { p.append(&parse_hex(value)?)?; }
                _ => return Err(error("unsupported expression field")),
            }
        }
        rest = rest[end+1..].trim_start();
    }
    let mut p = packet.ok_or_else(|| error("empty expression"))?; p.edited = false; Ok(p)
}
fn unquote(value: &str) -> Result<String> {
    if !value.starts_with('"') || !value.ends_with('"') || value.len()<2 { return Err(error("string must use double quotes")); }
    let mut result = String::new(); let mut chars = value[1..value.len()-1].chars();
    while let Some(c) = chars.next() {
        if c == '\\' { result.push(match chars.next() { Some('n')=>'\n',Some('r')=>'\r',Some('t')=>'\t',Some('"')=>'"',Some('\\')=>'\\', _=>return Err(error("invalid string escape")) }); }
        else { result.push(c); }
    }
    latin1_encode(&result)?; Ok(result)
}
pub fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len()%2 != 0 || !compact.is_ascii() { return Err(error("hex requires pairs of ASCII digits")); }
    (0..compact.len()).step_by(2).map(|i| u8::from_str_radix(&compact[i..i+2],16).map_err(|_| error("invalid hex"))).collect()
}
pub fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ") }
pub fn to_lossless_expression(p: &Packet) -> String { format!("{{h:{}}}{{hex:{}}}",p.header(),hex(p.body())) }
