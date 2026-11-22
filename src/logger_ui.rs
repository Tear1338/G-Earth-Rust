//! Beginner-friendly packet logger formatting, field decoding, and UI helpers.
use eframe::egui;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedField {
    pub kind: &'static str,
    pub value: String,
    pub is_string: bool,
}

/// Extract typed payload fields from a G-Earth structured/predicted expression.
/// Example: `{out:Chat}{s:"hello"}{i:0}{b:true}` -> `[String("hello"), Int("0"), Bool("true")]`.
pub fn parse_expression_fields(expr: &str) -> Vec<DecodedField> {
    let mut fields = Vec::new();
    let bytes = expr.as_bytes();
    let mut i = 0;
    while i < bytes.len() && fields.len() < 64 {
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        i += 1;
        let start = i;
        let mut in_quotes = false;
        let mut escaped = false;
        while i < bytes.len() {
            let b = bytes[i];
            if in_quotes {
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    in_quotes = false;
                }
            } else if b == b'"' {
                in_quotes = true;
            } else if b == b'}' {
                break;
            }
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'}' {
            break;
        }
        let token = &expr[start..i];
        i += 1;

        if let Some((tag, raw_val)) = token.split_once(':') {
            let tag = tag.trim();
            let val = raw_val.trim();
            match tag {
                "out" | "in" | "h" | "id" => {}
                "s" => fields.push(DecodedField {
                    kind: "Texte",
                    value: val.to_owned(),
                    is_string: true,
                }),
                "i" => fields.push(DecodedField {
                    kind: "Int",
                    value: val.to_owned(),
                    is_string: false,
                }),
                "u" => fields.push(DecodedField {
                    kind: "Short",
                    value: val.to_owned(),
                    is_string: false,
                }),
                "l" => fields.push(DecodedField {
                    kind: "Long",
                    value: val.to_owned(),
                    is_string: false,
                }),
                "b" => {
                    let kind = if val == "true" || val == "false" {
                        "Bool"
                    } else {
                        "Byte"
                    };
                    fields.push(DecodedField {
                        kind,
                        value: val.to_owned(),
                        is_string: false,
                    });
                }
                "B" => fields.push(DecodedField {
                    kind: "Bool",
                    value: val.to_owned(),
                    is_string: false,
                }),
                "d" => fields.push(DecodedField {
                    kind: "Double",
                    value: val.to_owned(),
                    is_string: false,
                }),
                "f" => fields.push(DecodedField {
                    kind: "Float",
                    value: val.to_owned(),
                    is_string: false,
                }),
                _ => {}
            }
        }
    }
    fields
}

/// Produce a concise, human-readable one-line preview of decoded packet fields.
pub fn summarize_fields(fields: &[DecodedField], empty_label: &str, max_chars: usize) -> String {
    if fields.is_empty() {
        return empty_label.to_owned();
    }
    let mut out = String::new();
    for (idx, field) in fields.iter().enumerate() {
        if idx > 0 {
            out.push_str("  ·  ");
        }
        if field.is_string {
            out.push_str(&field.value);
        } else {
            out.push_str(field.kind);
            out.push('=');
            out.push_str(&field.value);
        }
        if out.chars().count() >= max_chars {
            let truncated: String = out.chars().take(max_chars.saturating_sub(1)).collect();
            return format!("{truncated}…");
        }
    }
    out
}

/// Format an epoch millisecond timestamp as readable `HH:MM:SS.mmm` (UTC).
pub fn format_clock_time(timestamp_ms: u64) -> String {
    let total_secs = timestamp_ms / 1000;
    let ms = timestamp_ms % 1000;
    let secs = total_secs % 60;
    let mins = (total_secs / 60) % 60;
    let hours = (total_secs / 3600) % 24;
    format!("{hours:02}:{mins:02}:{secs:02}.{ms:03}")
}

/// Draw a compact rounded badge pill (e.g. `→ OUT`, `← IN`, `ID 1234`).
pub fn badge_pill(ui: &mut egui::Ui, text: &str, bg: egui::Color32, fg: egui::Color32) {
    egui::Frame::none()
        .fill(bg)
        .rounding(egui::Rounding::same(3.0))
        .inner_margin(egui::Margin::symmetric(5.0, 1.0))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).color(fg).strong().size(11.0));
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_typed_fields_and_skips_header_tokens() {
        let expr = r#"{out:Chat}{s:"hello \"world\""}{i:42}{b:true}{b:7}{d:3.5}{l:9001}{u:12}"#;
        let fields = parse_expression_fields(expr);
        assert_eq!(fields.len(), 7);
        assert_eq!(fields[0].kind, "Texte");
        assert_eq!(fields[0].value, r#""hello \"world\"""#);
        assert!(fields[0].is_string);
        assert_eq!(fields[1].kind, "Int");
        assert_eq!(fields[1].value, "42");
        assert_eq!(fields[2].kind, "Bool");
        assert_eq!(fields[2].value, "true");
        assert_eq!(fields[3].kind, "Byte");
        assert_eq!(fields[3].value, "7");
        assert_eq!(fields[4].kind, "Double");
        assert_eq!(fields[5].kind, "Long");
        assert_eq!(fields[6].kind, "Short");
    }

    #[test]
    fn summarizes_fields_and_formats_clock_time() {
        let fields = parse_expression_fields(r#"{h:100}{s:"salut"}{i:5}"#);
        assert_eq!(
            summarize_fields(&fields, "(empty)", 120),
            r#""salut"  ·  Int=5"#
        );
        assert_eq!(summarize_fields(&[], "(empty)", 120), "(empty)");
        assert_eq!(format_clock_time(3_661_045), "01:01:01.045");
    }
}
