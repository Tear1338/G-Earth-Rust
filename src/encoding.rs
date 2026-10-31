use crate::packet::{error, Result};

/// Shockwave fixed-width integer encoding (not MIME base64).
pub fn encode_b64(value: u32, width: usize) -> Result<Vec<u8>> {
    if !(1..=6).contains(&width) || (width < 6 && u64::from(value) >= (1u64 << (width*6))) { return Err(error("base64 integer does not fit")); }
    Ok((0..width).map(|i| 64+((u64::from(value) >> ((width-1-i)*6)) & 63) as u8).collect())
}
pub fn decode_b64(bytes: &[u8]) -> Result<u32> {
    if bytes.is_empty() || bytes.len()>6 { return Err(error("invalid base64 integer width")); }
    let mut n = 0u64;
    for b in bytes { if !(64..=127).contains(b) { return Err(error("invalid base64 integer byte")); } n = (n<<6)|u64::from(b-64); }
    u32::try_from(n).map_err(|_| error("base64 integer overflow"))
}
/// VL64 encoding follows Kepler/G-Earth's signed magnitude layout.
pub fn encode_vl64(value: i32) -> Vec<u8> {
    let mut magnitude = value.unsigned_abs(); let mut bytes = vec![64+(magnitude&3) as u8]; magnitude >>= 2;
    while magnitude != 0 { bytes.push(64+(magnitude&63) as u8); magnitude >>= 6; }
    bytes[0] |= ((bytes.len() as u8)<<3) | if value < 0 {4} else {0}; bytes
}
pub fn decode_vl64(bytes: &[u8]) -> Result<(i32,usize)> {
    let first = *bytes.first().ok_or_else(|| error("missing VL64"))?;
    let n = ((first>>3)&7) as usize;
    if !(1..=6).contains(&n) || bytes.len()<n || bytes[..n].iter().any(|b| !(64..=127).contains(b)) { return Err(error("invalid VL64")); }
    let mut value = u64::from(first&3);
    for (i,b) in bytes[1..n].iter().enumerate() { value |= u64::from(b&63) << (2+i*6); }
    let signed = if first&4 != 0 { -(value as i64) } else { value as i64 };
    Ok((i32::try_from(signed).map_err(|_| error("VL64 overflow"))?,n))
}
