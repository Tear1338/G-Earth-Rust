#![cfg(feature = "web")]
use gearth_rust::unity_assets::{self, AssetKind, UnityAsset, UnityAssets};
use std::io::{Read, Write};
fn settings() -> UnityAssets {
    UnityAssets {
        websocket_port: 12345,
        token: "a".repeat(64),
        cache_directory: std::env::temp_dir().join("unused-gearth-unity-assets-test"),
    }
}
#[test]
fn matches_only_original_hosts_paths_and_safe_revisions() {
    let prefix = "/habbo-webgl-clients/TEST-1/WebGL/habbo2020-global-prod/";
    for (tail, kind) in [
        ("StreamingAssets/Version.txt", AssetKind::Version),
        ("Build/habbo2020-global-prod.data.gz", AssetKind::Data),
        ("Build/habbo2020-global-prod.wasm.gz", AssetKind::Wasm),
        (
            "Build/habbo2020-global-prod.framework.js.gz",
            AssetKind::Framework,
        ),
        ("Build/habbo2020-global-prod.loader.js", AssetKind::Loader),
    ] {
        let asset =
            UnityAsset::from_url("images.habbo.com", &format!("{prefix}{tail}?cache=1")).unwrap();
        assert_eq!(asset.kind, kind);
        assert_eq!(asset.revision, "TEST-1");
        assert!(
            UnityAsset::from_url("images.habbo.com.evil.invalid", &format!("{prefix}{tail}"))
                .is_none()
        );
    }
    assert!(UnityAsset::from_url(
        "images.habbo.com",
        "/habbo-webgl-clients/a\"b/WebGL/habbo2020-global-prod/StreamingAssets/Version.txt"
    )
    .is_none());
}
#[test]
fn modifies_framework_and_loader_and_fails_before_serving_unsupported_code() {
    let source="var Module=typeof unityFramework!=\"undefined\"?unityFramework:{};function createWasm(){var wasmImports={};return {};};var asm=createWasm();var _malloc=function(){};var _free=function(){};";
    let output = unity_assets::framework("TEST-1", &settings(), source).unwrap();
    assert!(output.contains("const revision = \"TEST-1\""));
    assert!(output.contains("/?token="));
    assert!(output.contains(&"a".repeat(64)));
    assert!(output.contains("wasmImports[\"g_incoming_packet\"]"));
    assert!(!output.contains("{{"));
    assert!(!output.contains("var _malloc"));
    assert!(unity_assets::framework("TEST-1", &settings(), "incompatible future client").is_err());
    assert_eq!(
        unity_assets::loader("fetch(\"Last-Modified\");fetch(\"ETag\");").unwrap(),
        "fetch(\"G-Last-Modified\");fetch(\"G-ETag\");"
    );
}
#[test]
fn preserves_gzip_envelope_and_rewrites_version_locally() {
    let asset = UnityAsset {
        revision: "TEST-1".into(),
        kind: AssetKind::Version,
    };
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(b"1.2.3").unwrap();
    let compressed = encoder.finish().unwrap();
    let output = unity_assets::modify(&asset, &compressed, &settings()).unwrap();
    assert!(output.starts_with(&[0x1f, 0x8b]));
    let mut text = String::new();
    flate2::read::GzDecoder::new(output.as_slice())
        .read_to_string(&mut text)
        .unwrap();
    assert_eq!(text, "1.2.3 - G-Earth Rust");
}
#[test]
fn cache_is_bound_to_source_bytes_and_rejects_corrupted_entries() {
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            if let Ok(entries) = std::fs::read_dir(&self.0) {
                for entry in entries.flatten() {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    let mut random = [0; 16];
    getrandom::fill(&mut random).unwrap();
    let directory = Directory(std::env::temp_dir().join(format!(
            "gearth-unity-cache-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
    )));
    std::fs::create_dir(&directory.0).unwrap();
    let mut settings = settings();
    settings.cache_directory = directory.0.clone();
    let asset = UnityAsset {
        revision: "TEST-1".into(),
        kind: AssetKind::Wasm,
    };
    let source = include_str!("fixtures/unity_hooks.wat");
    let input = wat::parse_str(source).unwrap();
    let first = unity_assets::modify(&asset, &input, &settings).unwrap();
    let cached = std::fs::read_dir(&directory.0)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::write(&cached, b"corrupted cache").unwrap();
    assert_eq!(
        unity_assets::modify(&asset, &input, &settings).unwrap(),
        first
    );
    assert_eq!(std::fs::read(cached).unwrap(), first);
    let changed = wat::parse_str(source.replace(
        "i32.const 1 i32.const 2 i32.xor",
        "i32.const 3 i32.const 2 i32.xor",
    ))
    .unwrap();
    assert_ne!(
        unity_assets::modify(&asset, &changed, &settings).unwrap(),
        first
    );
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 2);
}
