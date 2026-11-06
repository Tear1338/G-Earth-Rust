use gearth_rust::settings::Settings;
use std::{fs, path::PathBuf};

fn path() -> PathBuf {
    let mut random = [0; 8];
    getrandom::fill(&mut random).unwrap();
    std::env::temp_dir().join(format!(
        "gearth-settings-{:016x}.json",
        u64::from_be_bytes(random)
    ))
}
#[test]
fn save_replace_load_and_preserve_unknown_fields() {
    let path = path();
    let mut settings = Settings::default();
    settings
        .values
        .insert("remote".into(), "test.example:30000".into());
    settings
        .extra
        .insert("future_field".into(), serde_json::json!({"keep":true}));
    settings.save(&path).unwrap();
    settings
        .values
        .insert("remote".into(), "second.example:30001".into());
    settings.save(&path).unwrap();
    let loaded = Settings::read(&path).unwrap();
    assert_eq!(loaded.get("remote"), "second.example:30001");
    assert_eq!(loaded.extra["future_field"]["keep"], true);
    fs::remove_file(path).unwrap();
}
#[test]
fn malformed_config_is_rejected_without_overwriting() {
    let path = path();
    fs::write(&path, "{broken").unwrap();
    assert!(Settings::read(&path).is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "{broken");
    fs::remove_file(path).unwrap();
}
#[test]
fn imports_real_beta29_cache_keys_and_retains_all_original_values() {
    let mut settings = Settings::default();
    let original = serde_json::json!({"last_connection_settings":{"host":"game.example","port":30000,"auto_detect":false},"last_client_mode":"FLASH","socks_config":{"ip":"127.0.0.1","port":1080},"notepad_text":"hello","unknown":42});
    settings.import_java_cache(original.clone()).unwrap();
    assert_eq!(settings.get("remote"), "game.example:30000");
    assert_eq!(settings.get("socks_proxy"), "127.0.0.1:1080");
    assert_eq!(settings.extra["legacy_java_cache"], original);
}

#[test]
fn importing_java_client_mode_overrides_previous_rust_mode() {
    let mut settings = Settings::default();
    for (mode, expected) in [
        ("UNITY", (false, true, true)),
        ("NITRO", (false, true, false)),
        ("SHOCKWAVE", (true, false, false)),
        ("FLASH", (false, false, false)),
    ] {
        settings
            .import_java_cache(serde_json::json!({"last_client_mode": mode}))
            .unwrap();
        assert_eq!(
            (
                settings.booleans["origins"],
                settings.booleans["nitro"],
                settings.booleans["unity"]
            ),
            expected
        );
    }
    settings
        .import_java_cache(serde_json::json!({"last_client_mode": "FUTURE"}))
        .unwrap();
    assert_eq!(
        (
            settings.booleans["origins"],
            settings.booleans["nitro"],
            settings.booleans["unity"]
        ),
        (false, false, false)
    );
    assert_eq!(settings.get("client_type"), "FUTURE");
}

#[test]
fn importing_java_ipv6_addresses_adds_required_brackets() {
    let mut settings = Settings::default();
    settings
        .import_java_cache(serde_json::json!({
            "last_connection_settings": {"host": "2001:db8::1", "port": 30000},
            "socks_config": {"ip": "::1", "port": 1080}
        }))
        .unwrap();
    assert_eq!(settings.get("remote"), "[2001:db8::1]:30000");
    assert_eq!(settings.get("socks_proxy"), "[::1]:1080");
}

#[test]
fn imports_java_injection_history_without_inventing_destinations() {
    use gearth_rust::injection::InjectionHistory;
    let mut settings = Settings::default();
    let entry = |text: &str| {
        serde_json::json!({
            "packetFormat": "EVA_WIRE", "packetsAsString": text, "description": "fixture"
        })
        .to_string()
    };
    let cache =
        serde_json::json!({"INJECTED_HISTORY": [entry("{h:42}"), "malformed", entry("{h:9}")]});
    settings.import_java_cache(cache.clone()).unwrap();
    let history = InjectionHistory::from_json(settings.get("injection_history"));
    assert_eq!(history.entries().len(), 2);
    assert_eq!(history.entries()[0].expression, "{h:42}");
    assert_eq!(history.entries()[1].expression, "{h:9}");
    assert!(history
        .entries()
        .iter()
        .all(|entry| entry.direction.is_empty()));
    let path = path();
    settings.save(&path).unwrap();
    let loaded = Settings::read(&path).unwrap();
    assert_eq!(
        InjectionHistory::from_json(loaded.get("injection_history")).entries(),
        history.entries()
    );
    assert_eq!(loaded.extra["legacy_java_cache"], cache);
    fs::remove_file(path).unwrap();
    let previous = settings.get("injection_history").to_owned();
    settings
        .import_java_cache(serde_json::json!({"INJECTED_HISTORY": ["invalid"]}))
        .unwrap();
    assert_eq!(settings.get("injection_history"), previous);
}

#[test]
fn incompatible_saved_rule_does_not_prevent_other_rules_from_updating() {
    use gearth_rust::{
        packet::{Direction, Message, Packet, PacketFormat},
        rules::Rules,
    };
    let mut settings = Settings {
        rules: vec![
            (true, Direction::ToServer, 1, Some("{h:5000}".into())),
            (true, Direction::ToServer, 2, None),
            (false, Direction::ToServer, 3, Some("{h:5000}".into())),
            (true, Direction::ToServer, 4, Some("{h:5}".into())),
        ],
        ..Settings::default()
    };
    let (entries, errors) = settings.compiled_rules_independent(true);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].0, 0);
    assert_eq!(entries.len(), 2);
    let rules = Rules { entries };
    let mut blocked = Message {
        packet: Packet::new_with_format(PacketFormat::WedgieOutgoing, 2).unwrap(),
        direction: Direction::ToServer,
        index: 0,
        blocked: false,
    };
    rules.apply(&mut blocked);
    assert!(blocked.blocked);
    let mut replaced = Message {
        packet: Packet::new_with_format(PacketFormat::WedgieOutgoing, 4).unwrap(),
        direction: Direction::ToServer,
        index: 0,
        blocked: false,
    };
    rules.apply(&mut replaced);
    assert_eq!(replaced.packet.header(), 5);
    let mut invalid = Message {
        packet: Packet::new_with_format(PacketFormat::WedgieOutgoing, 1).unwrap(),
        direction: Direction::ToServer,
        index: 0,
        blocked: false,
    };
    rules.apply(&mut invalid);
    assert_eq!(invalid.packet.header(), 1);
    assert!(!invalid.blocked);
    settings.rules[0].0 = false;
    assert!(settings.compiled_rules_independent(true).1.is_empty());
    assert!(settings.compiled_rules_independent(false).1.is_empty());
    settings.rules.push((true, Direction::ToClient, 5000, None));
    assert_eq!(settings.compiled_rules_independent(true).1[0].0, 4);
    assert!(settings.compiled_rules_independent(false).1.is_empty());
    let info = gearth_rust::packet_info::PacketInfoManager::default();
    assert!(Rules::editor_rule(
        true,
        Direction::ToServer,
        5000,
        "",
        PacketFormat::WedgieOutgoing,
        &info
    )
    .is_err());
    assert!(Rules::editor_rule(
        false,
        Direction::ToServer,
        5000,
        "",
        PacketFormat::WedgieOutgoing,
        &info
    )
    .unwrap()
    .is_none());
}

#[test]
fn editing_and_reordering_saved_rules_preserves_state_and_changes_ordered_behavior() {
    use gearth_rust::{
        packet::{Direction, Message, Packet},
        rules::Rules,
    };
    let mut settings = Settings {
        rules: vec![
            (true, Direction::ToServer, 1, Some("{h:2}".into())),
            (true, Direction::ToServer, 1, None),
            (false, Direction::ToClient, 8, None),
        ],
        ..Settings::default()
    };
    let run = |settings: &Settings| {
        let mut message = Message {
            packet: Packet::new(1),
            direction: Direction::ToServer,
            index: 0,
            blocked: false,
        };
        Rules {
            entries: settings.compiled_rules_independent(false).0,
        }
        .apply(&mut message);
        message
    };
    assert!(!run(&settings).blocked);
    settings.move_saved_rule(1, 0).unwrap();
    assert!(run(&settings).blocked);
    settings
        .replace_saved_rule(2, Direction::ToClient, 9, Some("{h:10}".into()))
        .unwrap();
    assert_eq!(
        settings.rules[2],
        (false, Direction::ToClient, 9, Some("{h:10}".into()))
    );
    let before = settings.rules.clone();
    assert!(settings.move_saved_rule(10, 0).is_err());
    assert!(settings.move_saved_rule(0, 10).is_err());
    assert!(settings
        .replace_saved_rule(10, Direction::ToServer, 1, None)
        .is_err());
    assert_eq!(settings.rules, before);
    let path = path();
    settings.save(&path).unwrap();
    assert_eq!(Settings::read(&path).unwrap().rules, before);
    fs::remove_file(path).unwrap();
}
