//! Original beta-29 language resources, with Java .properties decoding.
use std::collections::HashMap;
pub const LANGUAGES: &[(&str, &str)] = &[
    ("en", "English"),
    ("fr", "Français"),
    ("de", "Deutsch"),
    ("es", "Español"),
    ("fi", "Suomi"),
    ("it", "Italiano"),
    ("nl", "Nederlands"),
    ("pt", "Português"),
    ("tr", "Türkçe"),
];
const BUNDLES: &[(&str, &str)] = &[
    ("en", include_str!("../locales/messages_en.properties")),
    ("fr", include_str!("../locales/messages_fr.properties")),
    ("de", include_str!("../locales/messages_de.properties")),
    ("es", include_str!("../locales/messages_es.properties")),
    ("fi", include_str!("../locales/messages_fi.properties")),
    ("it", include_str!("../locales/messages_it.properties")),
    ("nl", include_str!("../locales/messages_nl.properties")),
    ("pt", include_str!("../locales/messages_pt.properties")),
    ("tr", include_str!("../locales/messages_tr.properties")),
];
#[derive(Clone)]
pub struct I18n {
    values: HashMap<String, String>,
}
impl I18n {
    pub fn new(language: &str) -> Self {
        let mut values = parse_properties(BUNDLES[0].1);
        if let Some((_, s)) = BUNDLES.iter().find(|(l, _)| *l == language) {
            values.extend(parse_properties(s));
        }
        Self { values }
    }
    pub fn text(&self, key: &str) -> String {
        self.values
            .get(key)
            .cloned()
            .unwrap_or_else(|| key.to_owned())
    }
}
pub fn parse_properties(source: &str) -> HashMap<String, String> {
    parse_properties_inner(source, false).expect("permissive decoding cannot fail")
}

/// Decode properties with Java's strict handling of malformed Unicode escapes.
pub fn try_parse_properties(source: &str) -> Result<HashMap<String, String>, &'static str> {
    parse_properties_inner(source, true)
}

fn parse_properties_inner(
    source: &str,
    strict: bool,
) -> Result<HashMap<String, String>, &'static str> {
    let mut values = HashMap::new();
    let mut combined = String::new();
    let source = source.replace("\r\n", "\n").replace('\r', "\n");
    let mut continuing = false;
    // The final empty line also flushes a continuation at end of file.
    for raw in source.split('\n').chain(std::iter::once("")) {
        let raw = raw.trim_start_matches([' ', '\t', '\x0c']);
        if !continuing && (raw.is_empty() || raw.starts_with(['#', '!'])) {
            continue;
        }
        combined.push_str(raw);
        if combined.chars().rev().take_while(|c| *c == '\\').count() % 2 == 1 {
            combined.pop();
            continuing = true;
            continue;
        }
        continuing = false;
        let line = std::mem::take(&mut combined);
        if line.is_empty() {
            continue;
        }
        let mut escaped = false;
        let mut separator = None;
        for (i, c) in line.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if c == '\\' {
                escaped = true;
                continue;
            }
            if c == '=' || c == ':' || matches!(c, ' ' | '\t' | '\x0c') {
                separator = Some(i);
                break;
            }
        }
        let (key, value) = match separator {
            Some(i) => {
                let mut rest = line[i..].trim_start_matches([' ', '\t', '\x0c']);
                if rest.starts_with(['=', ':']) {
                    rest = rest[1..].trim_start_matches([' ', '\t', '\x0c']);
                }
                (&line[..i], rest)
            }
            None => (line.as_str(), ""),
        };
        values.insert(unescape(key, strict)?, unescape(value, strict)?);
    }
    Ok(values)
}

fn unescape(s: &str, strict: bool) -> Result<String, &'static str> {
    let mut output = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        let c = if c == '\\' {
            match chars.next() {
                Some('u') => {
                    let hex: String = chars.by_ref().take(4).collect();
                    if hex.len() == 4 && hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                        output.push(u16::from_str_radix(&hex, 16).expect("four hex digits"));
                    } else if strict {
                        return Err("malformed Unicode escape");
                    } else {
                        output.push(0xfffd);
                    }
                    continue;
                }
                Some('n') => '\n',
                Some('r') => '\r',
                Some('t') => '\t',
                Some('f') => '\x0c',
                Some(c) => c,
                None => '\\',
            }
        } else {
            c
        };
        let mut temp = [0; 2];
        output.extend_from_slice(c.encode_utf16(&mut temp));
    }
    Ok(String::from_utf16_lossy(&output))
}

#[cfg(test)]
mod interface_tests {
    use super::{I18n, LANGUAGES};

    #[test]
    fn main_controls_are_localized_with_an_english_fallback() {
        let keys = [
            "rust.logger.pause",
            "rust.logger.filter",
            "rust.logger.packet_limit",
            "rust.logger.additional",
            "rust.logger.split",
            "rust.logger.extra",
            "rust.logger.export_path",
            "rust.logger.export",
            "rust.direction.server",
            "rust.direction.client",
            "rust.rule.title",
            "rust.rule.enabled",
            "rust.rule.header",
            "rust.rule.replacement",
            "rust.rule.save",
            "rust.rule.add",
            "rust.rule.cancel",
            "rust.action.remove",
            "rust.action.edit",
            "rust.action.up",
            "rust.action.down",
            "rust.scheduler.count",
            "rust.scheduler.forever",
            "rust.scheduler.align",
            "rust.scheduler.offset",
            "rust.scheduler.active_save",
            "rust.scheduler.template_save",
            "rust.scheduler.add",
            "rust.scheduler.cancel_edit",
            "rust.scheduler.cancel_all",
            "rust.scheduler.run_saved",
            "rust.scheduler.clear_saved",
            "rust.scheduler.paused_start",
            "rust.scheduler.pause",
            "rust.scheduler.resume",
            "rust.settings.save",
            "rust.settings.reload",
            "rust.settings.dark",
            "rust.connection.browser",
            "rust.connection.attachment",
            "rust.connection.refresh",
            "rust.connection.automatic",
            "rust.connection.attach",
            "rust.connection.local",
            "rust.connection.remote",
            "rust.connection.options",
            "rust.connection.listen",
            "rust.connection.stop",
            "rust.injection.invalid",
            "rust.injection.connect",
        ];
        for (language, _) in LANGUAGES {
            let bundle = I18n::new(language);
            for key in keys {
                assert_ne!(bundle.text(key), key, "missing {key} for {language}");
            }
        }
        let french = I18n::new("fr");
        assert_eq!(french.text("rust.direction.server"), "Vers le serveur");
        assert_eq!(french.text("rust.scheduler.resume"), "Reprendre");
        assert_eq!(
            french.text("rust.settings.save"),
            "Enregistrer les paramètres"
        );
        assert_eq!(I18n::new("de").text("rust.settings.save"), "Save settings");
    }
}
