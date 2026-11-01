use gearth_rust::i18n::{parse_properties, I18n, LANGUAGES};
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
