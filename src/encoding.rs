use crate::packet::{error, Result};

/// Shockwave fixed-width integer encoding (not MIME base64).
pub fn encode_b64(value: u32, width: usize) -> Result<Vec<u8>> {
    if !(1..=6).contains(&width) || (width < 6 && u64::from(value) >= (1u64 << (width * 6))) {
        return Err(error("base64 integer does not fit"));
    }
    Ok((0..width)
        .map(|i| 64 + ((u64::from(value) >> ((width - 1 - i) * 6)) & 63) as u8)
        .collect())
}
pub fn decode_b64(bytes: &[u8]) -> Result<u32> {
    if bytes.is_empty() || bytes.len() > 6 {
        return Err(error("invalid base64 integer width"));
    }
    let mut n = 0u64;
    for b in bytes {
        if !(64..=127).contains(b) {
            return Err(error("invalid base64 integer byte"));
        }
        n = (n << 6) | u64::from(b - 64);
    }
    u32::try_from(n).map_err(|_| error("base64 integer overflow"))
}
/// VL64 encoding follows Kepler/G-Earth's signed magnitude layout.
pub fn encode_vl64(value: i32) -> Vec<u8> {
    let mut magnitude = value.unsigned_abs();
    let mut bytes = vec![64 + (magnitude & 3) as u8];
    magnitude >>= 2;
    while magnitude != 0 {
        bytes.push(64 + (magnitude & 63) as u8);
        magnitude >>= 6;
    }
    bytes[0] |= ((bytes.len() as u8) << 3) | if value < 0 { 4 } else { 0 };
    bytes
}
pub fn decode_vl64(bytes: &[u8]) -> Result<(i32, usize)> {
    let first = *bytes.first().ok_or_else(|| error("missing VL64"))?;
    let n = ((first >> 3) & 7) as usize;
    if !(1..=6).contains(&n)
        || bytes.len() < n
        || bytes[..n].iter().any(|b| !(64..=127).contains(b))
    {
        return Err(error("invalid VL64"));
    }
    let mut value = u64::from(first & 3);
    for (i, b) in bytes[1..n].iter().enumerate() {
        value |= u64::from(b & 63) << (2 + i * 6);
    }
    let signed = if first & 4 != 0 {
        -(value as i64)
    } else {
        value as i64
    };
    Ok((
        i32::try_from(signed).map_err(|_| error("VL64 overflow"))?,
        n,
    ))
}

#[cfg(test)]
mod java_oracle_tests {
    use super::*;

    #[test]
    fn vl64_and_base64_match_beta29_java_recorded_vectors() {
        let vl64_vectors: &[(i32, &str)] = &[
            (0, "48"),
            (1, "49"),
            (-1, "4d"),
            (2, "4a"),
            (-2, "4e"),
            (3, "4b"),
            (-3, "4f"),
            (4, "5041"),
            (-4, "5441"),
            (63, "534f"),
            (-63, "574f"),
            (64, "5050"),
            (-64, "5450"),
            (255, "537f"),
            (-255, "577f"),
            (256, "584041"),
            (65535, "637f7f43"),
            (-65535, "677f7f43"),
            (1_000_000, "6050427d"),
            (-1_000_000, "6450427d"),
            (i32::MAX, "737f7f7f7f5f"),
            (-i32::MAX, "777f7f7f7f5f"),
        ];
        for &(value, expected_hex) in vl64_vectors {
            let encoded = encode_vl64(value);
            let actual_hex: String = encoded.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(actual_hex, expected_hex, "VL64 encode mismatch for {value}");
            let (decoded, consumed) = decode_vl64(&encoded).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, encoded.len());
        }

        let b64_vectors: &[(u32, usize, &str)] = &[
            (0, 1, "40"),
            (63, 1, "7f"),
            (0, 2, "4040"),
            (4095, 2, "7f7f"),
            (1234, 2, "5352"),
            (0, 3, "404040"),
            (262_143, 3, "7f7f7f"),
            (100_000, 4, "40585a60"),
        ];
        for &(value, width, expected_hex) in b64_vectors {
            let encoded = encode_b64(value, width).unwrap();
            let actual_hex: String = encoded.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                actual_hex, expected_hex,
                "Base64 encode mismatch for ({value}, {width})"
            );
            assert_eq!(decode_b64(&encoded).unwrap(), value);
        }
    }
}
