//! Versioned configuration, with atomic replacement and explicit legacy import.
use crate::{
    expression,
    packet::Direction,
    rules::{Action, Rule},
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};
const MAX_SETTINGS: usize = 2 * 1024 * 1024;

fn host_and_port(host: &str, port: u64) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleTemplate {
    pub expression: String,
    pub direction: Direction,
    pub interval_ms: u64,
    /// Optional phase within the interval, measured against the Unix clock.
    pub offset_ms: Option<u64>,
    /// Start the template paused when it is activated.
    pub paused: bool,
    /// Zero means repeat until cancelled.
    pub repeat: u32,
}
#[derive(Clone, Debug)]
pub struct Settings {
    pub values: BTreeMap<String, String>,
    pub booleans: BTreeMap<String, bool>,
    pub rules: Vec<(bool, Direction, u16, Option<String>)>,
    pub schedules: Vec<ScheduleTemplate>,
    pub log_limit: usize,
    pub log_bytes: usize,
    pub extra: serde_json::Map<String, Value>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            values: BTreeMap::from([
                ("listen".into(), "127.0.0.1:1234".into()),
                ("language".into(), "en".into()),
            ]),
            booleans: BTreeMap::new(),
            rules: Vec::new(),
            schedules: Vec::new(),
            log_limit: 5000,
            log_bytes: 16 * 1024 * 1024,
            extra: serde_json::Map::new(),
        }
    }
}

impl Settings {
    pub fn default_path() -> PathBuf {
        if let Some(override_path) = std::env::var_os("GEARTH_RUST_CONFIG") {
            return PathBuf::from(override_path);
        }
        let base = if cfg!(windows) {
            std::env::var_os("APPDATA").map(PathBuf::from)
        } else {
            std::env::var_os("XDG_CONFIG_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|s| PathBuf::from(s).join(".config")))
        };
        base.unwrap_or_else(|| PathBuf::from("."))
            .join("G-Earth-Rust")
            .join("settings.json")
    }
    pub fn get(&self, key: &str) -> &str {
        self.values.get(key).map(String::as_str).unwrap_or("")
    }
    /// Preserve the old Rust behavior for settings saved before the checkbox existed.
    pub fn socks_enabled(&self) -> bool {
        self.booleans
            .get("socks_enabled")
            .copied()
            .unwrap_or_else(|| !self.get("socks_proxy").trim().is_empty())
    }
    pub fn read(path: &Path) -> io::Result<Self> {
        use std::io::Read;
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(MAX_SETTINGS as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_SETTINGS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "settings file too large",
            ));
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        Self::from_json(value)
    }
    fn from_json(value: Value) -> io::Result<Self> {
        let mut result = Self::default();
        let mut object = value
            .as_object()
            .cloned()
            .ok_or_else(|| io::Error::other("settings must be an object"))?;
        let version = object
            .remove("schema_version")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);
        if version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported settings schema version",
            ));
        }
        if let Some(values) = object.remove("values") {
            for (k, v) in values
                .as_object()
                .ok_or_else(|| io::Error::other("invalid settings values"))?
            {
                result.values.insert(
                    k.clone(),
                    v.as_str()
                        .ok_or_else(|| io::Error::other("setting must be a string"))?
                        .into(),
                );
            }
        }
        if let Some(values) = object.remove("booleans") {
            for (k, v) in values
                .as_object()
                .ok_or_else(|| io::Error::other("invalid boolean settings"))?
            {
                result.booleans.insert(
                    k.clone(),
                    v.as_bool()
                        .ok_or_else(|| io::Error::other("setting must be a boolean"))?,
                );
            }
        }
        if let Some(n) = object.remove("log_limit") {
            result.log_limit = usize::try_from(
                n.as_u64()
                    .ok_or_else(|| io::Error::other("invalid log limit"))?,
            )
            .map_err(io::Error::other)?;
        }
        if let Some(n) = object.remove("log_bytes") {
            result.log_bytes = usize::try_from(
                n.as_u64()
                    .ok_or_else(|| io::Error::other("invalid log byte limit"))?,
            )
            .map_err(io::Error::other)?;
        }
        if !(16..=50000).contains(&result.log_limit)
            || !(4096..=512 * 1024 * 1024).contains(&result.log_bytes)
        {
            return Err(io::Error::other("log limits outside supported range"));
        }
        if let Some(rules) = object.remove("rules") {
            for rule in rules
                .as_array()
                .ok_or_else(|| io::Error::other("invalid rule list"))?
            {
                let enabled = rule["enabled"].as_bool().unwrap_or(true);
                let direction = Direction::parse(
                    rule["direction"]
                        .as_str()
                        .ok_or_else(|| io::Error::other("missing rule direction"))?,
                )
                .map_err(io::Error::other)?;
                let header = u16::try_from(
                    rule["header"]
                        .as_u64()
                        .ok_or_else(|| io::Error::other("invalid rule header"))?,
                )
                .map_err(io::Error::other)?;
                let replacement = rule["replacement"].as_str().map(str::to_owned);
                if let Some(p) = &replacement {
                    expression::parse(p).map_err(io::Error::other)?;
                }
                result.rules.push((enabled, direction, header, replacement));
            }
        }
        if let Some(schedules) = object.remove("schedules") {
            for schedule in schedules
                .as_array()
                .ok_or_else(|| io::Error::other("invalid schedule list"))?
            {
                let expression = schedule["expression"]
                    .as_str()
                    .ok_or_else(|| io::Error::other("missing schedule expression"))?
                    .to_owned();
                let direction = Direction::parse(
                    schedule["direction"]
                        .as_str()
                        .ok_or_else(|| io::Error::other("missing schedule direction"))?,
                )
                .map_err(io::Error::other)?;
                let interval_ms = schedule["interval_ms"]
                    .as_u64()
                    .filter(|n| *n > 0 && *n <= crate::scheduler::MAX_INTERVAL_MS)
                    .ok_or_else(|| io::Error::other("invalid schedule interval"))?;
                let repeat = u32::try_from(
                    schedule["repeat"]
                        .as_u64()
                        .ok_or_else(|| io::Error::other("invalid schedule repetitions"))?,
                )
                .map_err(io::Error::other)?;
                let offset_ms = match schedule.get("offset_ms") {
                    None | Some(Value::Null) => None,
                    Some(value) => Some(
                        value
                            .as_u64()
                            .filter(|n| *n <= interval_ms)
                            .ok_or_else(|| io::Error::other("invalid schedule offset"))?,
                    ),
                };
                let paused = match schedule.get("paused") {
                    None => false,
                    Some(value) => value
                        .as_bool()
                        .ok_or_else(|| io::Error::other("invalid schedule paused flag"))?,
                };
                result.schedules.push(ScheduleTemplate {
                    expression,
                    direction,
                    interval_ms,
                    offset_ms,
                    paused,
                    repeat,
                });
            }
        }
        result.extra = object;
        Ok(result)
    }
    pub fn to_json(&self) -> Value {
        let mut object = self.extra.clone();
        object.insert("schema_version".into(), json!(1));
        object.insert("values".into(), json!(self.values));
        object.insert("booleans".into(), json!(self.booleans));
        object.insert("log_limit".into(), json!(self.log_limit));
        object.insert("log_bytes".into(), json!(self.log_bytes));
        object.insert("rules".into(),Value::Array(self.rules.iter().map(|(enabled,direction,header,replacement)|json!({"enabled":enabled,"direction":direction.name(),"header":header,"replacement":replacement})).collect()));
        object.insert("schedules".into(),Value::Array(self.schedules.iter().map(|s|json!({"expression":s.expression,"direction":s.direction.name(),"interval_ms":s.interval_ms,"offset_ms":s.offset_ms,"paused":s.paused,"repeat":s.repeat})).collect()));
        Value::Object(object)
    }
    pub fn save(&self, path: &Path) -> io::Result<()> {
        Self::from_json(self.to_json())?;
        let bytes = serde_json::to_vec_pretty(&self.to_json()).map_err(io::Error::other)?;
        if bytes.len() > MAX_SETTINGS {
            return Err(io::Error::other("settings file too large"));
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
        let name = random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let temporary = parent.join(format!(".gearth-{name}.tmp"));
        let outcome = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, path)
        })();
        if outcome.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        outcome
    }
    /// Persist templates without overwriting unrelated settings already on disk.
    pub fn save_schedules(path: &Path, schedules: &[ScheduleTemplate]) -> io::Result<()> {
        let mut current = match Self::read(path) {
            Ok(settings) => settings,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Self::default(),
            Err(error) => return Err(error),
        };
        current.schedules = schedules.to_vec();
        current.save(path)
    }
    /// Persist saved rules without replacing other on-disk settings.
    pub fn save_rules(
        path: &Path,
        rules: &[(bool, Direction, u16, Option<String>)],
    ) -> io::Result<()> {
        let mut current = match Self::read(path) {
            Ok(settings) => settings,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Self::default(),
            Err(error) => return Err(error),
        };
        current.rules = rules.to_vec();
        current.save(path)
    }
    pub fn compiled_rules(&self) -> io::Result<Vec<Rule>> {
        self.compiled_rules_for(false)
    }
    /// Update one saved rule without changing its enabled state or position.
    pub fn replace_saved_rule(
        &mut self,
        index: usize,
        direction: Direction,
        header: u16,
        replacement: Option<String>,
    ) -> io::Result<()> {
        let rule = self
            .rules
            .get_mut(index)
            .ok_or_else(|| io::Error::other("saved rule no longer exists"))?;
        rule.1 = direction;
        rule.2 = header;
        rule.3 = replacement;
        Ok(())
    }
    /// Move an existing rule without changing the relative order of the others.
    pub fn move_saved_rule(&mut self, from: usize, to: usize) -> io::Result<()> {
        if from >= self.rules.len() || to >= self.rules.len() {
            return Err(io::Error::other("saved rule no longer exists"));
        }
        let rule = self.rules.remove(from);
        self.rules.insert(to, rule);
        Ok(())
    }
    pub fn compiled_rules_for(&self, origins: bool) -> io::Result<Vec<Rule>> {
        self.rules
            .iter()
            .map(|(enabled, direction, header, replacement)| {
                let format = if origins {
                    if *direction == Direction::ToServer {
                        crate::packet::PacketFormat::WedgieOutgoing
                    } else {
                        crate::packet::PacketFormat::WedgieIncoming
                    }
                } else {
                    crate::packet::PacketFormat::EvaWire
                };
                Ok(Rule {
                    enabled: *enabled,
                    direction: *direction,
                    header: *header,
                    action: match replacement {
                        Some(s) => Action::Replace(
                            expression::parse_with_format(s, format, None)
                                .map_err(io::Error::other)?,
                        ),
                        None => Action::Block,
                    },
                })
            })
            .collect()
    }
    /// Compile enabled rules independently so one invalid rule cannot keep a
    /// previously installed ruleset in place or prevent valid rules from updating.
    pub fn compiled_rules_independent(&self, origins: bool) -> (Vec<Rule>, Vec<(usize, String)>) {
        let mut entries = Vec::new();
        let mut errors = Vec::new();
        for (index, (enabled, direction, header, replacement)) in self.rules.iter().enumerate() {
            if !enabled {
                continue;
            }
            if origins && *header >= 4096 {
                errors.push((index, "Shockwave header must be between 0 and 4095".into()));
                continue;
            }
            let format = if origins {
                if *direction == Direction::ToServer {
                    crate::packet::PacketFormat::WedgieOutgoing
                } else {
                    crate::packet::PacketFormat::WedgieIncoming
                }
            } else {
                crate::packet::PacketFormat::EvaWire
            };
            let action = match replacement {
                None => Ok(Action::Block),
                Some(text) => {
                    expression::parse_with_format(text, format, None).map(Action::Replace)
                }
            };
            match action {
                Ok(action) => entries.push(Rule {
                    enabled: true,
                    direction: *direction,
                    header: *header,
                    action,
                }),
                Err(error) => errors.push((index, error.to_string())),
            }
        }
        (entries, errors)
    }
    pub fn import_java_cache(&mut self, value: Value) -> io::Result<()> {
        if !value.is_object() {
            return Err(io::Error::other("Java cache must be a JSON object"));
        }
        // LanguageBundle stores the Java enum name, not its locale code.
        if let Some(language) = value["language"].as_str() {
            let locale = match language {
                "ENGLISH" => Some("en"),
                "DUTCH" => Some("nl"),
                "FRENCH" => Some("fr"),
                "GERMAN" => Some("de"),
                "SPANISH" => Some("es"),
                "PORTUGUESE" => Some("pt"),
                "ITALIAN" => Some("it"),
                "FINNISH" => Some("fi"),
                "TURKISH" => Some("tr"),
                _ => None,
            };
            if let Some(locale) = locale {
                self.values.insert("language".into(), locale.into());
            }
        }
        if let Some(theme) = value["theme"].as_str() {
            // ThemeFactory falls back to the light G-Earth theme for unknown
            // titles. Tanji is also light; its distinct appearance is not ported.
            self.booleans
                .insert("dark_mode".into(), theme == "G-Earth Dark");
        }
        if let (Some(host), Some(port)) = (
            value["last_connection_settings"]["host"].as_str(),
            value["last_connection_settings"]["port"].as_u64(),
        ) {
            if port <= 65535 {
                self.values
                    .insert("remote".into(), host_and_port(host, port));
            }
        }
        if let Some(mode) = value["last_client_mode"].as_str() {
            self.values.insert("client_type".into(), mode.into());
            let selected = match mode {
                "FLASH" => Some((false, false, false)),
                "SHOCKWAVE" => Some((true, false, false)),
                "NITRO" => Some((false, true, false)),
                "UNITY" => Some((false, true, true)),
                _ => None,
            };
            if let Some((origins, nitro, unity)) = selected {
                self.booleans.insert("origins".into(), origins);
                self.booleans.insert("nitro".into(), nitro);
                self.booleans.insert("unity".into(), unity);
            }
        }
        if let Some(text) = value["notepad_text"].as_str() {
            self.values.insert("notepad".into(), text.into());
        }
        if let Some(enabled) = value["develop_mode"].as_bool() {
            self.booleans.insert("developer_mode".into(), enabled);
        }
        if let Some(enabled) = value["always_admin"].as_bool() {
            self.booleans.insert("always_admin".into(), enabled);
        }
        if let Some(enabled) = value["use_gpython"].as_bool() {
            self.booleans.insert("python_enabled".into(), enabled);
        }
        // beta-29 stores these in the exact menu order from UiLoggerController.
        // Reject malformed or differently sized lists, as Java does for old layouts.
        if let Some(items) = value["LOGGER_SETTINGS"]
            .as_array()
            .filter(|items| items.len() == 21 && items.iter().all(serde_json::Value::is_boolean))
        {
            for (index, key) in [
                (0, "incoming"),
                (1, "outgoing"),
                (2, "logger_structure"),
                (3, "logger_autoscroll"),
                (4, "logger_skip_big"),
                (5, "logger_names"),
                (6, "logger_hashes"),
                (7, "logger_message_id"),
                (8, "logger_open_on_connect"),
                (9, "logger_clear_on_connect"),
                (10, "logger_hide_on_disconnect"),
                (11, "logger_clear_on_disconnect"),
                (17, "logger_timestamp"),
                (18, "logger_extra_hex_dump"),
                (19, "logger_extra_legacy"),
                (20, "logger_extra_raw_hex"),
            ] {
                self.booleans
                    .insert(key.into(), items[index].as_bool().unwrap());
            }
            let selected: Vec<_> = ["None", "Low", "Medium", "High", "Ultra"]
                .iter()
                .enumerate()
                .filter(|(index, _)| items[12 + index].as_bool() == Some(true))
                .map(|(_, mode)| *mode)
                .collect();
            if let [mode] = selected.as_slice() {
                self.values.insert("logger_antispam".into(), (*mode).into());
            }
            // Java's byte representations are independent of its main expression.
            self.values
                .insert("logger_representation".into(), "Expression".into());
        }
        if let Some(entries) = value["INJECTED_HISTORY"].as_array() {
            let history = crate::injection::InjectionHistory::from_java_cache(entries);
            if entries.is_empty() || !history.entries().is_empty() {
                self.values
                    .insert("injection_history".into(), history.to_json());
            }
        }
        if let (Some(host), Some(port)) = (
            value["socks_config"]["ip"].as_str(),
            value["socks_config"]["port"].as_u64(),
        ) {
            if port <= 65535 {
                self.values
                    .insert("socks_proxy".into(), host_and_port(host, port));
                // Java saves the address independently of the unchecked-at-startup proxy toggle.
                self.booleans.insert("socks_enabled".into(), false);
            }
        }
        self.extra.insert("legacy_java_cache".into(), value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ScheduleTemplate, Settings};
    use crate::packet::Direction;

    #[test]
    fn java_python_console_preference_is_preserved() {
        for enabled in [true, false] {
            let mut settings = Settings::default();
            settings
                .import_java_cache(serde_json::json!({"use_gpython": enabled}))
                .unwrap();
            let restored = Settings::from_json(settings.to_json()).unwrap();
            assert_eq!(restored.booleans.get("python_enabled"), Some(&enabled));
        }
        let mut settings = Settings::default();
        settings.booleans.insert("python_enabled".into(), false);
        settings
            .import_java_cache(serde_json::json!({"use_gpython": "invalid"}))
            .unwrap();
        assert_eq!(settings.booleans.get("python_enabled"), Some(&false));
    }

    #[test]
    fn java_language_and_theme_preferences_are_imported_and_persisted() {
        for (original, locale) in [
            ("ENGLISH", "en"),
            ("DUTCH", "nl"),
            ("FRENCH", "fr"),
            ("GERMAN", "de"),
            ("SPANISH", "es"),
            ("PORTUGUESE", "pt"),
            ("ITALIAN", "it"),
            ("FINNISH", "fi"),
            ("TURKISH", "tr"),
        ] {
            let mut settings = Settings::default();
            settings
                .import_java_cache(
                    serde_json::json!({"language": original, "theme": "G-Earth Dark"}),
                )
                .unwrap();
            let restored = Settings::from_json(settings.to_json()).unwrap();
            assert_eq!(restored.get("language"), locale);
            assert_eq!(restored.booleans.get("dark_mode"), Some(&true));
            assert_eq!(restored.extra["legacy_java_cache"]["language"], original);
        }
        for theme in ["G-Earth", "Tanji", "unknown"] {
            let mut settings = Settings::default();
            settings.booleans.insert("dark_mode".into(), true);
            settings
                .import_java_cache(serde_json::json!({"theme": theme}))
                .unwrap();
            assert_eq!(settings.booleans.get("dark_mode"), Some(&false));
        }
    }

    #[test]
    fn malformed_java_language_and_theme_do_not_override_preferences() {
        let mut settings = Settings::default();
        settings.values.insert("language".into(), "fr".into());
        settings.booleans.insert("dark_mode".into(), true);
        settings
            .import_java_cache(serde_json::json!({"language": "UNKNOWN", "theme": 12}))
            .unwrap();
        assert_eq!(settings.get("language"), "fr");
        assert_eq!(settings.booleans.get("dark_mode"), Some(&true));
    }

    #[test]
    fn java_client_permissions_choice_is_imported_and_persisted() {
        let mut settings = Settings::default();
        settings
            .import_java_cache(serde_json::json!({"always_admin": true}))
            .unwrap();
        let loaded = Settings::from_json(settings.to_json()).unwrap();
        assert_eq!(loaded.booleans.get("always_admin"), Some(&true));
    }

    #[test]
    fn java_logger_window_options_round_trip() {
        let mut items = vec![false; 21];
        items[8] = true;
        items[10] = true;
        let mut settings = Settings::default();
        settings
            .import_java_cache(serde_json::json!({"LOGGER_SETTINGS": items}))
            .unwrap();
        let loaded = Settings::from_json(settings.to_json()).unwrap();
        assert_eq!(loaded.booleans.get("logger_open_on_connect"), Some(&true));
        assert_eq!(
            loaded.booleans.get("logger_hide_on_disconnect"),
            Some(&true)
        );
    }

    #[test]
    fn java_proxy_address_is_imported_without_enabling_proxy() {
        let mut settings = Settings::default();
        settings
            .values
            .insert("socks_proxy".into(), "old:42".into());
        assert!(settings.socks_enabled());
        settings
            .import_java_cache(serde_json::json!({"socks_config": {"ip": "::1", "port": 1080}}))
            .unwrap();
        assert_eq!(settings.get("socks_proxy"), "[::1]:1080");
        assert!(!settings.socks_enabled());
        let mut restored = Settings::from_json(settings.to_json()).unwrap();
        assert!(!restored.socks_enabled());
        restored.booleans.insert("socks_enabled".into(), true);
        assert!(restored.socks_enabled());
        restored.booleans.remove("socks_enabled");
        assert!(restored.socks_enabled());
        restored.values.insert("socks_proxy".into(), "  ".into());
        assert!(!restored.socks_enabled());
    }

    #[test]
    fn repeating_schedule_survives_settings_round_trip() {
        let mut settings = Settings::default();
        settings.schedules.push(ScheduleTemplate {
            expression: "{h:1}".into(),
            direction: Direction::ToServer,
            interval_ms: 500,
            offset_ms: Some(125),
            paused: true,
            repeat: 0,
        });
        let loaded = Settings::from_json(settings.to_json()).unwrap();
        assert_eq!(loaded.schedules[0].repeat, 0);
        assert_eq!(loaded.schedules[0].interval_ms, 500);
        assert_eq!(loaded.schedules[0].offset_ms, Some(125));
        assert!(loaded.schedules[0].paused);
        let mut legacy = settings.to_json();
        legacy["schedules"][0]
            .as_object_mut()
            .unwrap()
            .remove("offset_ms");
        legacy["schedules"][0]
            .as_object_mut()
            .unwrap()
            .remove("paused");
        let legacy = Settings::from_json(legacy).unwrap();
        assert_eq!(legacy.schedules[0].offset_ms, None);
        assert!(!legacy.schedules[0].paused);
        let mut invalid = settings.to_json();
        invalid["schedules"][0]["offset_ms"] = serde_json::json!(500);
        assert_eq!(
            Settings::from_json(invalid.clone()).unwrap().schedules[0].offset_ms,
            Some(500)
        );
        invalid["schedules"][0]["offset_ms"] = serde_json::json!(501);
        assert!(Settings::from_json(invalid).is_err());
    }
}
