use gearth_rust::i18n::{parse_properties, I18n, LANGUAGES};

#[test]
fn store_controls_have_french_labels_and_english_fallbacks() {
    let keys = [
        "title",
        "load",
        "search",
        "reverse",
        "outdated",
        "all_systems",
        "all_clients",
        "all_frameworks",
        "all_categories",
        "matches",
        "installed",
        "install_update",
        "install_older",
        "install",
        "installed_versions",
        "installed_hint",
        "launch",
        "uninstall",
        "sort_rating",
        "sort_alphabetical",
        "sort_updated",
        "sort_new",
    ];
    let english = I18n::new("en");
    let french = I18n::new("fr");
    let german = I18n::new("de");
    for name in keys {
        let key = format!("rust.store.{name}");
        assert_ne!(english.text(&key), key);
        assert_ne!(french.text(&key), english.text(&key), "untranslated {key}");
        assert_eq!(german.text(&key), english.text(&key));
    }
}

#[test]
fn logger_copy_and_inspection_controls_have_french_labels() {
    let en = I18n::new("en");
    let fr = I18n::new("fr");
    for key in [
        "rust.logger.copy_displayed",
        "rust.logger.inspect_bytes",
        "rust.logger.packet_bytes",
        "rust.logger.copy_dump",
        "rust.logger.reset_filtered",
        "rust.logger.capture_selected_only",
        "rust.logger.capture_selected_hint",
    ] {
        assert_ne!(en.text(key), key);
        assert_ne!(fr.text(key), en.text(key));
    }
}

#[test]
fn connection_and_browser_controls_are_available_in_french_and_english() {
    let keys = [
        "rust.connection.flash_crypto",
        "rust.connection.attachment_hint",
        "rust.connection.recover_redirects",
        "rust.connection.redirects_removed",
        "rust.connection.hotel_version",
        "rust.connection.client_identifier",
        "rust.connection.packet_identifiers",
        "rust.connection.socks_proxy",
        "rust.connection.socks_user",
        "rust.connection.socks_password",
        "rust.connection.outgoing_key",
        "rust.connection.incoming_key",
        "rust.connection.key_hint",
        "rust.browser.unity_connection",
        "rust.browser.nitro_connection",
        "rust.browser.local_address",
        "rust.browser.configure_proxy",
        "rust.browser.proxy_hint",
        "rust.browser.restore_proxy",
        "rust.browser.prepare_certificate",
        "rust.browser.certificate_hint",
        "rust.browser.install_certificate",
        "rust.browser.remove_certificate",
        "rust.browser.unity_identifiers",
        "rust.browser.unity_hint",
        "rust.browser.manual_proxy_hint",
        "rust.browser.nitro_options",
        "rust.browser.websocket_hint",
        "rust.browser.city_keys",
        "rust.browser.city_helper",
        "rust.connection.load_sulek",
        "rust.connection.loading_identifiers",
        "rust.connection.identifier_count",
        "rust.browser.proxy_restored",
        "rust.browser.certificate_ready",
        "rust.browser.public_certificate",
        "rust.browser.load_nitro_identifiers",
        "rust.browser.start_proxy",
    ];
    let english = I18n::new("en");
    let french = I18n::new("fr");
    for key in keys {
        assert_ne!(english.text(key), key, "missing English: {key}");
        assert_ne!(french.text(key), english.text(key), "missing French: {key}");
        assert_eq!(
            I18n::new("de").text(key),
            english.text(key),
            "fallback: {key}"
        );
    }
    assert!(french
        .text("rust.browser.city_helper")
        .contains("https://nitro.sulek.dev/habbocity"));
}

#[test]
fn strict_properties_reject_malformed_unicode_in_keys_and_values() {
    use gearth_rust::i18n::try_parse_properties;
    for input in ["key=\\u12", "key=\\u12xz", "\\u+123=value", "key=\\u00é0"] {
        assert!(try_parse_properties(input).is_err(), "accepted {input:?}");
    }
    let values = try_parse_properties("\\u006b=\\u00e9\nemoji=\\uD83E\\uDD80").unwrap();
    assert_eq!(values["k"], "é");
    assert_eq!(values["emoji"], "🦀");
    assert_eq!(parse_properties("key=\\u12")["key"], "�");
}

#[test]
fn scheduler_and_tool_controls_have_translations_and_fallbacks() {
    let keys = [
        "rust.scheduler.active_count",
        "rust.scheduler.started",
        "rust.scheduler.start_failed",
        "rust.scheduler.file",
        "rust.scheduler.import",
        "rust.scheduler.imported",
        "rust.scheduler.import_failed",
        "rust.scheduler.load_active",
        "rust.scheduler.load_active_hint",
        "rust.scheduler.loaded_active",
        "rust.scheduler.loaded_offline_hint",
        "rust.scheduler.resolve_pending",
        "rust.scheduler.waiting_session",
        "rust.connection.coalesced_errors",
        "rust.scheduler.load_failed",
        "rust.scheduler.export_templates",
        "rust.scheduler.exported_templates",
        "rust.scheduler.export_active",
        "rust.scheduler.export_active_hint",
        "rust.scheduler.exported_active",
        "rust.scheduler.export_failed",
        "rust.scheduler.saved_hint",
        "rust.tools.packet_format",
        "rust.tools.expression_to_hex",
        "rust.tools.hex_to_expression",
        "rust.tools.expression_to_packet",
        "rust.tools.packet_to_expression",
        "rust.tools.converted",
        "rust.tools.structure_unavailable",
        "rust.tools.copy_output",
        "rust.tools.reuse_output",
    ];
    let french = I18n::new("fr");
    let english = I18n::new("en");
    for key in keys {
        assert_ne!(french.text(key), key);
        assert_ne!(french.text(key), english.text(key), "untranslated: {key}");
        for (language, _) in LANGUAGES {
            assert_ne!(
                I18n::new(language).text(key),
                key,
                "missing {key} for {language}"
            );
        }
    }
    assert_eq!(
        french.text("rust.scheduler.load_active"),
        "Charger et remplacer les planifications actives"
    );
    assert_eq!(
        I18n::new("de").text("rust.tools.copy_output"),
        "Copy output"
    );
}

#[test]
fn extension_controls_have_french_labels_and_english_fallbacks() {
    let keys = [
        "server_unavailable",
        "server",
        "runtime",
        "file",
        "launch",
        "launched",
        "allow",
        "open",
        "disconnect",
        "console",
    ];
    for (language, _) in LANGUAGES {
        let bundle = I18n::new(language);
        for key in keys {
            let key = format!("rust.extensions.{key}");
            assert_ne!(bundle.text(&key), key, "missing {key} for {language}");
        }
    }
    assert_eq!(
        I18n::new("fr").text("rust.extensions.launch"),
        "Lancer l'extension"
    );
    assert_eq!(
        I18n::new("fr").text("rust.extensions.disconnect"),
        "D\u{e9}connecter"
    );
    assert_eq!(
        I18n::new("de").text("rust.extensions.launch"),
        "Launch extension"
    );
}

#[test]
fn properties_comments_line_endings_and_final_continuation_match_java() {
    let cases: &[(&str, &[(&str, &str)])] = &[
        ("# comment\\\nhello=world\n", &[("hello", "world")]),
        ("! comment\\\rnext=value\r", &[("next", "value")]),
        ("name=value\\", &[("name", "value")]),
        (
            "first=one\rsecond=two\r\nthird=three\n",
            &[("first", "one"), ("second", "two"), ("third", "three")],
        ),
        ("joined=one\\\n    two\n", &[("joined", "onetwo")]),
        (
            "joined=one\\\n\nother=yes\n",
            &[("joined", "one"), ("other", "yes")],
        ),
        (
            "key\\ name : value\\ with\\ spaces\n",
            &[("key name", "value with spaces")],
        ),
    ];
    for (source, expected) in cases {
        let actual = parse_properties(source);
        let expected: std::collections::HashMap<String, String> = expected
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        assert_eq!(actual, expected, "source: {source:?}");
    }
}

#[test]
fn logger_choices_resolve_in_every_supported_language() {
    use gearth_rust::{logger_display::PacketRepresentation, logger_filter::AntiSpam};
    for (language, _) in LANGUAGES {
        let i18n = I18n::new(language);
        for mode in [
            AntiSpam::None,
            AntiSpam::Low,
            AntiSpam::Medium,
            AntiSpam::High,
            AntiSpam::Ultra,
        ] {
            assert_ne!(i18n.text(mode.translation_key()), mode.translation_key());
        }
        for mode in [
            PacketRepresentation::Expression,
            PacketRepresentation::NoBytes,
            PacketRepresentation::Legacy,
            PacketRepresentation::RawHex,
        ] {
            assert_ne!(i18n.text(mode.translation_key()), mode.translation_key());
        }
    }
    assert_eq!(
        I18n::new("fr").text(AntiSpam::Medium.translation_key()),
        "Moyen"
    );
    assert_eq!(
        I18n::new("fr").text("ext.logger.element.skipped"),
        "paquet ignoré"
    );
}
#[test]
fn decodes_escaped_unicode_surrogates_and_continuations() {
    let values =
        parse_properties("# comment\na\\=b = caf\\u00e9\nx=one\\\n  two\nemoji=\\uD83E\\uDD80\n");
    assert_eq!(values["a=b"], "café");
    assert_eq!(values["x"], "onetwo");
    assert_eq!(values["emoji"], "🦀");
}
#[test]
fn every_original_language_has_core_tabs() {
    for (language, _) in LANGUAGES {
        let bundle = I18n::new(language);
        for key in [
            "tab.connection",
            "tab.injection",
            "tab.extensions",
            "tab.scheduler",
            "tab.info",
            "rust.logger.tab",
            "rust.logger.title",
            "rust.connection.test_client_hint",
        ] {
            assert_ne!(bundle.text(key), key, "{language}");
        }
    }
    assert_eq!(I18n::new("fr").text("tab.connection"), "Connexion");
    assert_eq!(I18n::new("fr").text("rust.logger.tab"), "Journal");
    assert_eq!(I18n::new("fr").text("tab.extra.notepad"), "Bloc-notes");
}

#[test]
fn developer_confirmation_has_translated_choices_and_fallbacks() {
    for (language, _) in LANGUAGES {
        let bundle = I18n::new(language);
        assert_ne!(
            bundle.text("rust.confirmation.yes"),
            "rust.confirmation.yes"
        );
        assert_ne!(bundle.text("rust.confirmation.no"), "rust.confirmation.no");
        assert_ne!(
            bundle.text("tab.extra.options.developmode.alert.title"),
            "tab.extra.options.developmode.alert.title"
        );
    }
    let french = I18n::new("fr");
    assert_eq!(french.text("rust.confirmation.yes"), "Oui");
    assert_eq!(french.text("rust.confirmation.no"), "Non");
}
