use gearth_rust::i18n::{parse_properties, I18n, LANGUAGES};

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
        ] {
            assert_ne!(bundle.text(key), key, "{language}");
        }
    }
    assert_eq!(I18n::new("fr").text("tab.connection"), "Connexion");
}
