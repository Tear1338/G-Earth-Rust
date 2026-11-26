//! Beginner-friendly packet logger formatting, field decoding, snippet export, presets, and stats.
use eframe::egui;
use gearth_rust::packet::Direction;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedField {
    pub kind: &'static str,
    pub value: String,
    pub is_string: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketSnapshot {
    pub direction: Direction,
    pub header: u16,
    pub title: String,
    pub expression: String,
    pub fields: Vec<DecodedField>,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldDiffKind {
    Same,
    Changed,
    Added,
    Removed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDiffRow {
    pub index: usize,
    pub kind: FieldDiffKind,
    pub left: Option<DecodedField>,
    pub right: Option<DecodedField>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteDiffChunk {
    pub offset: usize,
    pub left: Option<u8>,
    pub right: Option<u8>,
    pub changed: bool,
}

pub fn diff_packet_fields(left: &[DecodedField], right: &[DecodedField]) -> Vec<FieldDiffRow> {
    let max_len = left.len().max(right.len());
    let mut rows = Vec::with_capacity(max_len);
    for idx in 0..max_len {
        let l = left.get(idx).cloned();
        let r = right.get(idx).cloned();
        let kind = match (&l, &r) {
            (Some(a), Some(b)) if a == b => FieldDiffKind::Same,
            (Some(_), Some(_)) => FieldDiffKind::Changed,
            (None, Some(_)) => FieldDiffKind::Added,
            (Some(_), None) => FieldDiffKind::Removed,
            (None, None) => FieldDiffKind::Same,
        };
        rows.push(FieldDiffRow {
            index: idx,
            kind,
            left: l,
            right: r,
        });
    }
    rows
}

pub fn diff_packet_bytes(left: &[u8], right: &[u8], limit: usize) -> Vec<ByteDiffChunk> {
    let len = left.len().max(right.len()).min(limit);
    let mut out = Vec::with_capacity(len);
    for offset in 0..len {
        let l = left.get(offset).copied();
        let r = right.get(offset).copied();
        out.push(ByteDiffChunk {
            offset,
            left: l,
            right: r,
            changed: l != r,
        });
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InjectionFavorite {
    pub name: String,
    pub direction: Direction,
    pub expression: String,
}

pub fn parse_injection_favorites(raw: &str) -> Vec<InjectionFavorite> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(trimmed)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items.into_iter().take(128) {
        let Some(name) = item
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= 80)
        else {
            continue;
        };
        let Some(expression) = item
            .get("expression")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty() && s.len() <= 16384)
        else {
            continue;
        };
        let direction = item
            .get("direction")
            .and_then(|v| v.as_str())
            .and_then(|s| Direction::parse(s).ok())
            .unwrap_or(Direction::ToServer);
        out.push(InjectionFavorite {
            name: name.to_owned(),
            direction,
            expression: expression.to_owned(),
        });
    }
    out
}

pub fn serialize_injection_favorites(favorites: &[InjectionFavorite]) -> String {
    let arr: Vec<serde_json::Value> = favorites
        .iter()
        .map(|f| {
            serde_json::json!({
                "name": f.name,
                "direction": f.direction.name(),
                "expression": f.expression,
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
}

pub const BUILDER_FIELD_KINDS: &[&str] =
    &["Header", "String", "Int", "Bool", "Short", "Byte", "Long"];

pub fn format_builder_token(kind: &str, value: &str) -> String {
    let trimmed = value.trim();
    match kind {
        "Header" => format!("{{h:{}}}", if trimmed.is_empty() { "0" } else { trimmed }),
        "String" => format!("{{s:\"{}\"}}", escape_double_quoted(value)),
        "Int" => format!("{{i:{}}}", if trimmed.is_empty() { "0" } else { trimmed }),
        "Bool" => {
            let v = if trimmed.eq_ignore_ascii_case("true") || trimmed == "1" {
                "true"
            } else {
                "false"
            };
            format!("{{b:{v}}}")
        }
        "Short" => format!("{{u:{}}}", if trimmed.is_empty() { "0" } else { trimmed }),
        "Byte" => format!(
            "{{byte:{}}}",
            if trimmed.is_empty() { "0" } else { trimmed }
        ),
        "Long" => format!("{{l:{}}}", if trimmed.is_empty() { "0" } else { trimmed }),
        _ => format!("{{s:\"{}\"}}", escape_double_quoted(value)),
    }
}

/// Detect common high-frequency / noisy keepalive & ping packets (Nitro, Flash, HabboCity).
pub fn is_noisy_packet(direction: Direction, header: u16, names: &str) -> bool {
    // HabboCity link control frames (7701..=7705)
    if (7701..=7705).contains(&header) {
        return true;
    }
    // Common Nitro / PRODUCTION-201611291003-338511768 ping/latency/telemetry headers
    let noisy_id = match direction {
        Direction::ToServer => matches!(header, 295 | 215 | 2596 | 170 | 3457),
        Direction::ToClient => matches!(header, 10 | 3928),
    };
    if noisy_id {
        return true;
    }
    if !names.is_empty() {
        let lower = names.to_ascii_lowercase();
        for token in [
            "ping",
            "pong",
            "latency",
            "keepalive",
            "heartbeat",
            "eventtracker",
            "eventlog",
            "clientpong",
            "clientping",
        ] {
            if lower.contains(token) {
                return true;
            }
        }
    }
    false
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoggerFilterPreset {
    pub name: String,
    pub query: String,
    pub hide_noisy: bool,
    pub incoming: bool,
    pub outgoing: bool,
    pub hidden_headers: Vec<(Direction, u16)>,
}

pub fn parse_filter_presets(raw: &str) -> Vec<LoggerFilterPreset> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(trimmed)
    else {
        return Vec::new();
    };
    let mut presets = Vec::new();
    for item in items.into_iter().take(64) {
        let Some(name) = item
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= 80)
        else {
            continue;
        };
        let query = item
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let hide_noisy = item
            .get("hide_noisy")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let incoming = item
            .get("incoming")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let outgoing = item
            .get("outgoing")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let mut hidden_headers = Vec::new();
        if let Some(arr) = item.get("hidden_headers").and_then(|v| v.as_array()) {
            for entry in arr.iter().take(256) {
                let dir = entry
                    .get("direction")
                    .and_then(|v| v.as_str())
                    .and_then(|s| Direction::parse(s).ok());
                let header = entry
                    .get("header")
                    .and_then(|v| v.as_u64())
                    .and_then(|n| u16::try_from(n).ok());
                if let (Some(d), Some(h)) = (dir, header) {
                    if !hidden_headers.contains(&(d, h)) {
                        hidden_headers.push((d, h));
                    }
                }
            }
        }
        presets.push(LoggerFilterPreset {
            name: name.to_owned(),
            query,
            hide_noisy,
            incoming,
            outgoing,
            hidden_headers,
        });
    }
    presets
}

pub fn serialize_filter_presets(presets: &[LoggerFilterPreset]) -> String {
    let arr: Vec<serde_json::Value> = presets
        .iter()
        .map(|p| {
            let hidden: Vec<serde_json::Value> = p
                .hidden_headers
                .iter()
                .map(|(d, h)| serde_json::json!({ "direction": d.name(), "header": h }))
                .collect();
            serde_json::json!({
                "name": p.name,
                "query": p.query,
                "hide_noisy": p.hide_noisy,
                "incoming": p.incoming,
                "outgoing": p.outgoing,
                "hidden_headers": hidden,
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
}

pub fn format_hidden_headers_setting(hidden: &HashSet<(Direction, u16)>) -> String {
    let mut sorted: Vec<_> = hidden.iter().copied().collect();
    sorted.sort_by(|a, b| (a.0.name(), a.1).cmp(&(b.0.name(), b.1)));
    let arr: Vec<serde_json::Value> = sorted
        .into_iter()
        .map(|(d, h)| serde_json::json!({ "direction": d.name(), "header": h }))
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
}

pub fn parse_hidden_headers_setting(raw: &str) -> HashSet<(Direction, u16)> {
    let mut set = HashSet::new();
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(raw.trim())
    else {
        return set;
    };
    for entry in items.into_iter().take(512) {
        let dir = entry
            .get("direction")
            .and_then(|v| v.as_str())
            .and_then(|s| Direction::parse(s).ok());
        let header = entry
            .get("header")
            .and_then(|v| v.as_u64())
            .and_then(|n| u16::try_from(n).ok());
        if let (Some(d), Some(h)) = (dir, header) {
            set.insert((d, h));
        }
    }
    set
}

fn python_field_literal(field: &DecodedField) -> String {
    match field.kind {
        "Bool" => {
            if field.value.eq_ignore_ascii_case("true") {
                "True".into()
            } else {
                "False".into()
            }
        }
        _ => field.value.clone(),
    }
}

fn java_field_literal(field: &DecodedField) -> String {
    match field.kind {
        "Byte" => format!("(byte) {}", field.value),
        "Short" => format!("(short) {}", field.value),
        "Long" => format!("{}L", field.value),
        "Float" => format!("{}f", field.value),
        _ => field.value.clone(),
    }
}

fn escape_double_quoted(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Generate a ready-to-use G-Python snippet for a logged packet.
pub fn to_gpython_snippet(
    direction: Direction,
    header: u16,
    name: Option<&str>,
    expression: &str,
    fields: &[DecodedField],
) -> String {
    let primary_name = name
        .and_then(|n| n.split(" / ").next())
        .map(str::trim)
        .filter(|n| !n.is_empty());
    let header_arg = match primary_name {
        Some(n) => format!("\"{}\"", escape_double_quoted(n)),
        None => header.to_string(),
    };
    let (send_fn, dir_const, dir_label) = match direction {
        Direction::ToServer => ("send_to_server", "Direction.TO_SERVER", "TOSERVER"),
        Direction::ToClient => ("send_to_client", "Direction.TO_CLIENT", "TOCLIENT"),
    };
    let title = primary_name
        .map(|n| format!("{n} (ID {header})"))
        .unwrap_or_else(|| format!("ID {header}"));
    let mut args = vec![header_arg.clone()];
    for f in fields {
        args.push(python_field_literal(f));
    }
    let build_line = if !fields.is_empty() || !expression.contains("{hex:") {
        format!("packet = HPacket({})", args.join(", "))
    } else {
        format!(
            "packet = HPacket.from_string(\"{}\")",
            escape_double_quoted(expression)
        )
    };
    format!(
        "from g_python.hpacket import HPacket\nfrom g_python.hdirection import Direction\n\n# {title} - {dir_label}\n{build_line}\next.{send_fn}(packet)\n\n# Intercept:\n# def on_packet(message):\n#     packet = message.packet\n# ext.intercept({dir_const}, on_packet, {header_arg})"
    )
}

/// Generate a ready-to-use G-Earth Java API snippet for a logged packet.
pub fn to_java_snippet(
    direction: Direction,
    header: u16,
    name: Option<&str>,
    expression: &str,
    fields: &[DecodedField],
) -> String {
    let primary_name = name
        .and_then(|n| n.split(" / ").next())
        .map(str::trim)
        .filter(|n| !n.is_empty());
    let (send_fn, dir_enum, dir_label) = match direction {
        Direction::ToServer => ("sendToServer", "HMessage.Direction.TOSERVER", "TOSERVER"),
        Direction::ToClient => ("sendToClient", "HMessage.Direction.TOCLIENT", "TOCLIENT"),
    };
    let title = primary_name
        .map(|n| format!("{n} (ID {header})"))
        .unwrap_or_else(|| format!("ID {header}"));
    let build_line = if !fields.is_empty() || !expression.contains("{hex:") {
        let mut args = Vec::new();
        if let Some(n) = primary_name {
            args.push(format!("\"{}\"", escape_double_quoted(n)));
            args.push(dir_enum.to_owned());
        } else {
            args.push(header.to_string());
        }
        for f in fields {
            args.push(java_field_literal(f));
        }
        format!("HPacket packet = new HPacket({});", args.join(", "))
    } else {
        format!(
            "HPacket packet = new HPacket(\"{}\");",
            escape_double_quoted(expression)
        )
    };
    let intercept_target = match primary_name {
        Some(n) => format!("\"{}\"", escape_double_quoted(n)),
        None => header.to_string(),
    };
    format!(
        "// {title} - {dir_label}\n{build_line}\n{send_fn}(packet);\n\n// Intercept:\n// intercept({dir_enum}, {intercept_target}, hMessage -> {{\n//     HPacket p = hMessage.getPacket();\n// }});"
    )
}

/// Lightweight rolling statistics for the Packet Logger (packets/sec + top headers).
#[derive(Default)]
pub struct LoggerStats {
    recent: VecDeque<(Instant, Direction)>,
    counts: HashMap<(Direction, u16), u64>,
    pub total_in: u64,
    pub total_out: u64,
    started_at: Option<Instant>,
}

impl LoggerStats {
    const WINDOW: Duration = Duration::from_secs(5);

    pub fn record(&mut self, direction: Direction, header: u16, now: Instant) {
        if self.started_at.is_none() {
            self.started_at = Some(now);
        }
        self.prune(now);
        if self.recent.len() >= 10_000 {
            self.recent.pop_front();
        }
        self.recent.push_back((now, direction));
        *self.counts.entry((direction, header)).or_insert(0) += 1;
        match direction {
            Direction::ToClient => self.total_in = self.total_in.saturating_add(1),
            Direction::ToServer => self.total_out = self.total_out.saturating_add(1),
        }
    }

    fn prune(&mut self, now: Instant) {
        while self
            .recent
            .front()
            .is_some_and(|(ts, _)| now.saturating_duration_since(*ts) > Self::WINDOW)
        {
            self.recent.pop_front();
        }
    }

    /// Returns `(total_per_sec, incoming_per_sec, outgoing_per_sec)` over the rolling 5s window.
    pub fn rates(&mut self, now: Instant) -> (f64, f64, f64) {
        self.prune(now);
        if self.recent.is_empty() {
            return (0.0, 0.0, 0.0);
        }
        let elapsed = self
            .started_at
            .map(|start| now.saturating_duration_since(start).as_secs_f64())
            .unwrap_or(5.0)
            .clamp(1.0, Self::WINDOW.as_secs_f64());
        let mut inc = 0usize;
        let mut out = 0usize;
        for (_, dir) in &self.recent {
            match dir {
                Direction::ToClient => inc += 1,
                Direction::ToServer => out += 1,
            }
        }
        let total = (inc + out) as f64 / elapsed;
        (total, inc as f64 / elapsed, out as f64 / elapsed)
    }

    pub fn top_headers(&self, limit: usize) -> Vec<(Direction, u16, u64)> {
        let mut items: Vec<_> = self
            .counts
            .iter()
            .map(|(&(dir, header), &count)| (dir, header, count))
            .collect();
        items.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.1.cmp(&b.1)));
        items.truncate(limit);
        items
    }

    pub fn reset(&mut self) {
        self.recent.clear();
        self.counts.clear();
        self.total_in = 0;
        self.total_out = 0;
        self.started_at = None;
    }
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

    #[test]
    fn noisy_packet_detection_covers_pings_and_city_links() {
        assert!(is_noisy_packet(Direction::ToServer, 2596, ""));
        assert!(is_noisy_packet(Direction::ToClient, 3928, ""));
        assert!(is_noisy_packet(Direction::ToClient, 7701, ""));
        assert!(is_noisy_packet(Direction::ToServer, 999, "LatencyPing"));
        assert!(!is_noisy_packet(Direction::ToServer, 1314, "Chat"));
    }

    #[test]
    fn filter_presets_and_hidden_headers_roundtrip() {
        let presets = vec![LoggerFilterPreset {
            name: "Chat only".into(),
            query: "chat".into(),
            hide_noisy: true,
            incoming: true,
            outgoing: false,
            hidden_headers: vec![(Direction::ToClient, 1640), (Direction::ToServer, 2596)],
        }];
        let json = serialize_filter_presets(&presets);
        let parsed = parse_filter_presets(&json);
        assert_eq!(parsed, presets);

        let mut hidden = HashSet::new();
        hidden.insert((Direction::ToClient, 10));
        hidden.insert((Direction::ToServer, 295));
        let encoded = format_hidden_headers_setting(&hidden);
        assert_eq!(parse_hidden_headers_setting(&encoded), hidden);
    }

    #[test]
    fn snippet_generators_emit_valid_gpython_and_java() {
        let fields = parse_expression_fields(r#"{out:Chat}{s:"salut"}{i:0}{b:true}"#);
        let py = to_gpython_snippet(
            Direction::ToServer,
            1314,
            Some("Chat"),
            r#"{out:Chat}{s:"salut"}{i:0}{b:true}"#,
            &fields,
        );
        assert!(py.contains(r#"HPacket("Chat", "salut", 0, True)"#));
        assert!(py.contains("ext.send_to_server(packet)"));
        assert!(py.contains("Direction.TO_SERVER"));

        let java = to_java_snippet(
            Direction::ToServer,
            1314,
            Some("Chat"),
            r#"{out:Chat}{s:"salut"}{i:0}{b:true}"#,
            &fields,
        );
        assert!(
            java.contains(r#"new HPacket("Chat", HMessage.Direction.TOSERVER, "salut", 0, true)"#)
        );
        assert!(java.contains("sendToServer(packet);"));

        let raw_py =
            to_gpython_snippet(Direction::ToClient, 9999, None, "{h:9999}{hex:01 02}", &[]);
        assert!(raw_py.contains(r#"HPacket.from_string("{h:9999}{hex:01 02}")"#));
        assert!(raw_py.contains("ext.send_to_client(packet)"));
    }

    #[test]
    fn logger_stats_tracks_rates_and_top_headers() {
        let mut stats = LoggerStats::default();
        let t0 = Instant::now();
        stats.record(Direction::ToClient, 1640, t0);
        stats.record(Direction::ToClient, 1640, t0);
        stats.record(Direction::ToServer, 1314, t0);
        let (total, inc, out) = stats.rates(t0);
        assert!(total >= 2.9 && inc >= 1.9 && out >= 0.9);
        let top = stats.top_headers(2);
        assert_eq!(
            top,
            vec![
                (Direction::ToClient, 1640, 2),
                (Direction::ToServer, 1314, 1)
            ]
        );
        stats.reset();
        assert!(stats.top_headers(5).is_empty());
    }

    #[test]
    fn diff_and_favorites_and_builder_work() {
        let a = parse_expression_fields(r#"{h:10}{s:"hello"}{i:1}"#);
        let b = parse_expression_fields(r#"{h:10}{s:"world"}{i:1}{b:true}"#);
        let rows = diff_packet_fields(&a, &b);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].kind, FieldDiffKind::Changed);
        assert_eq!(rows[1].kind, FieldDiffKind::Same);
        assert_eq!(rows[2].kind, FieldDiffKind::Added);

        let bdiff = diff_packet_bytes(&[0, 1, 2], &[0, 9, 2, 4], 64);
        assert_eq!(bdiff.len(), 4);
        assert!(!bdiff[0].changed);
        assert!(bdiff[1].changed);
        assert!(!bdiff[2].changed);
        assert!(bdiff[3].changed);

        let favs = vec![InjectionFavorite {
            name: "Say hi".into(),
            direction: Direction::ToServer,
            expression: r#"{out:Chat}{s:"hi"}{i:0}"#.into(),
        }];
        let json = serialize_injection_favorites(&favs);
        assert_eq!(parse_injection_favorites(&json), favs);

        assert_eq!(format_builder_token("Header", "1314"), "{h:1314}");
        assert_eq!(format_builder_token("String", r#"a"b"#), r#"{s:"a\"b"}"#);
        assert_eq!(format_builder_token("Int", "42"), "{i:42}");
        assert_eq!(format_builder_token("Bool", "1"), "{b:true}");
        assert_eq!(format_builder_token("Short", "7"), "{u:7}");
    }
}
