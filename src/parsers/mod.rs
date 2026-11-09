//! Native Rust parsers for the beta-29 extension API data model.
pub mod catalog;
pub mod entity;
pub mod forums;
pub mod furniture;
pub mod navigator;
pub mod social;
pub mod stuffdata;

/// Parse the syntax accepted by Java Double.parseDouble for packet height fields.
pub(crate) fn parse_java_double(text: &str) -> Option<f64> {
    use num_bigint::BigUint;

    // String.trim in the Java implementation removes code points through U+0020.
    let text = text.trim_matches(|c: char| c <= '\u{20}');
    let (negative, unsigned) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    match unsigned {
        "NaN" => return Some(f64::NAN),
        "Infinity" => {
            return Some(if negative {
                f64::NEG_INFINITY
            } else {
                f64::INFINITY
            })
        }
        _ => {}
    }
    let unsigned = unsigned
        .strip_suffix(['f', 'F', 'd', 'D'])
        .unwrap_or(unsigned);
    if let Some(hex) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
    {
        let (mantissa, exponent) = hex.split_once(['p', 'P'])?;
        let exponent_digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        if exponent_digits.is_empty() || !exponent_digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let exponent = exponent
            .parse::<i64>()
            .unwrap_or(if exponent.starts_with('-') {
                -1_000_000
            } else {
                1_000_000
            });
        let mut digits = Vec::with_capacity(mantissa.len());
        let mut fractional = false;
        let mut fractional_digits = 0i64;
        for b in mantissa.bytes() {
            if b == b'.' && !fractional {
                fractional = true;
                continue;
            }
            if !b.is_ascii_hexdigit() {
                return None;
            }
            digits.push(b);
            if fractional {
                fractional_digits += 1;
            }
        }
        if digits.is_empty() {
            return None;
        }
        let number = BigUint::parse_bytes(&digits, 16)?;
        let sign = if negative { 1u64 << 63 } else { 0 };
        if number.bits() == 0 {
            return Some(f64::from_bits(sign));
        }
        let power = exponent.saturating_sub(fractional_digits.saturating_mul(4));
        let mut binary_exponent = (number.bits() as i64 - 1).saturating_add(power);
        if binary_exponent > 1023 {
            return Some(f64::from_bits(sign | (0x7ffu64 << 52)));
        }
        if binary_exponent < -1075 {
            return Some(f64::from_bits(sign));
        }
        let target = if binary_exponent >= -1022 {
            binary_exponent - 52
        } else {
            -1074
        };
        let shift = target.saturating_sub(power);
        let mut rounded = if shift > 0 {
            let shift = shift as usize;
            let mut quotient = &number >> shift;
            let guard = number.bit((shift - 1) as u64);
            let sticky = number
                .trailing_zeros()
                .is_some_and(|n| n < (shift - 1) as u64);
            if guard && (sticky || quotient.bit(0)) {
                quotient += 1u8;
            }
            quotient
        } else {
            &number << (-shift) as usize
        };
        if binary_exponent >= -1022 && rounded.bits() > 53 {
            rounded >>= 1usize;
            binary_exponent += 1;
            if binary_exponent > 1023 {
                return Some(f64::from_bits(sign | (0x7ffu64 << 52)));
            }
        }
        let significand = rounded.to_u64_digits().first().copied().unwrap_or(0);
        let bits = if binary_exponent >= -1022 {
            (((binary_exponent + 1023) as u64) << 52) | (significand & ((1u64 << 52) - 1))
        } else {
            significand
        };
        Some(f64::from_bits(sign | bits))
    } else {
        let mut chars = unsigned.bytes().peekable();
        let mut digits = 0;
        while chars.peek().is_some_and(u8::is_ascii_digit) {
            chars.next();
            digits += 1;
        }
        if chars.peek() == Some(&b'.') {
            chars.next();
            while chars.peek().is_some_and(u8::is_ascii_digit) {
                chars.next();
                digits += 1;
            }
        }
        if digits == 0 {
            return None;
        }
        if matches!(chars.peek(), Some(b'e' | b'E')) {
            chars.next();
            if matches!(chars.peek(), Some(b'+' | b'-')) {
                chars.next();
            }
            let mut exponent_digits = 0;
            while chars.peek().is_some_and(u8::is_ascii_digit) {
                chars.next();
                exponent_digits += 1;
            }
            if exponent_digits == 0 {
                return None;
            }
        }
        if chars.next().is_some() {
            return None;
        }
        let value: f64 = unsigned.parse().ok()?;
        Some(if negative { -value } else { value })
    }
}

pub(crate) fn java_double(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value == f64::INFINITY {
        return "Infinity".into();
    }
    if value == f64::NEG_INFINITY {
        return "-Infinity".into();
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }

    let negative = value.is_sign_negative();
    let repr = format!("{:?}", value.abs());
    let (mantissa, exponent) = match repr.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().unwrap_or(0)),
        None => (repr.as_str(), 0),
    };
    let mut digits = mantissa.replace('.', "");
    let mut point = mantissa.find('.').unwrap_or(mantissa.len()) as i32 + exponent;
    let leading = digits.bytes().take_while(|byte| *byte == b'0').count();
    digits.drain(..leading);
    point -= leading as i32;
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    debug_assert!(!digits.is_empty());

    let scientific = value.abs() >= 10_000_000.0 || value.abs() < 0.001;
    // Java uses at least two significant decimal digits when selecting the
    // closest scientific representation, including for subnormal values.
    if scientific && digits.len() == 1 {
        let rounded = format!("{:.1e}", value.abs());
        let (mantissa, exponent) = rounded.split_once('e').expect("scientific formatting");
        let exponent: i32 = exponent.parse().expect("scientific exponent");
        return format!("{}{mantissa}E{exponent}", if negative { "-" } else { "" });
    }
    let mut output = String::new();
    if negative {
        output.push('-');
    }
    if scientific {
        output.push(digits.as_bytes()[0] as char);
        output.push('.');
        if digits.len() == 1 {
            output.push('0');
        } else {
            output.push_str(&digits[1..]);
        }
        output.push('E');
        output.push_str(&(point - 1).to_string());
    } else if point <= 0 {
        output.push_str("0.");
        output.extend(std::iter::repeat_n('0', (-point) as usize));
        output.push_str(&digits);
    } else if point as usize >= digits.len() {
        output.push_str(&digits);
        output.extend(std::iter::repeat_n('0', point as usize - digits.len()));
        output.push_str(".0");
    } else {
        let point = point as usize;
        output.push_str(&digits[..point]);
        output.push('.');
        output.push_str(&digits[point..]);
    }
    output
}

#[cfg(test)]
mod java_double_tests {
    use super::parse_java_double;

    #[test]
    fn java_scientific_format_uses_closest_two_digit_subnormals() {
        assert_eq!(super::java_double(f64::from_bits(1)), "4.9E-324");
        assert_eq!(super::java_double(f64::from_bits(2)), "9.9E-324");
        assert_eq!(super::java_double(-f64::from_bits(1)), "-4.9E-324");
    }

    #[test]
    fn java_height_syntax_and_hex_rounding_boundaries() {
        for (text, bits) in [
            (" 1.25f ", 1.25f64.to_bits()),
            ("-0.0D", (-0.0f64).to_bits()),
            ("0x1.8p1", 3.0f64.to_bits()),
            ("0x1.00000000000008p0", 1.0f64.to_bits()),
            ("0x1.00000000000018p0", 1.0f64.to_bits() + 2),
            ("0x1p-1074", 1),
            ("0x1p-1075", 0),
            ("0x1.8p-1075", 1),
            ("0x0.fffffffffffff8p-1022", 1u64 << 52),
            ("0x1p1024", f64::INFINITY.to_bits()),
        ] {
            assert_eq!(parse_java_double(text).unwrap().to_bits(), bits, "{text}");
        }
        for text in ["inf", "nan", "1_0", "0x1", "0x.p1", "1ff", "NaNf"] {
            assert!(parse_java_double(text).is_none(), "{text}");
        }
    }
}
