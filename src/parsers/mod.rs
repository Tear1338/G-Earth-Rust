//! Native Rust parsers for the beta-29 extension API data model.
pub mod catalog;
pub mod entity;
pub mod furniture;
pub mod social;
pub mod stuffdata;

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
