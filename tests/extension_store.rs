use gearth_rust::extension_store::{self, Catalog, Query, Sort};
use serde_json::json;
use std::{
    cmp::Ordering,
    io::{Cursor, Write},
    path::PathBuf,
};
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gearth-store-test-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if let (Ok(path), Ok(temp)) = (self.0.canonicalize(), std::env::temp_dir().canonicalize()) {
            if path.parent() == Some(temp.as_path())
                && path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("gearth-store-test-"))
            {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }
}
fn catalog() -> Catalog {
    let config = json!({"categories":[{"name":"Building","description":"Build tools","icon":"build.png"}],"frameworks":[{"name":"Native","developers":["Fixture"],"languages":["Java"],"source":"https://example.invalid/","installation":{"required":false}}]});
    let base = json!({"title":"Fixture Tool","description":"Build a controlled fixture","authors":[{"name":"Fixture Author","username":"FixtureUser","extensionsCount":1,"reputation":10}],"version":"1.0","categories":["Building"],"source":"https://example.invalid/","stable":true,"framework":{"name":"Native","version":"1.5"},"language":"Java","commands":{"default":["java","-jar","tool.jar","-p","{port}","-f","{filename}","-c","{cookie}"]},"compatibility":{"systems":["Windows","Linux"],"clients":["Unity"]},"submissionDate":"31-12-2024 23:00:00","updateDate":"02-01-2025 12:00:00","isOutdated":false,"rating":10});
    let mut second = base.clone();
    second["title"] = json!("Another Tool");
    second["rating"] = json!(100);
    second["isOutdated"] = json!(true);
    second["updateDate"] = json!("15-12-2024 12:00:00");
    Catalog::parse(
        extension_store::STORE_SOURCE,
        extension_store::STORE_VERSION,
        &serde_json::to_vec(&config).unwrap(),
        &serde_json::to_vec(&vec![base, second]).unwrap(),
    )
    .unwrap()
}
fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in files {
        archive
            .start_file(
                *name,
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        archive.write_all(bytes).unwrap();
    }
    archive.finish().unwrap().into_inner()
}
#[test]
fn catalog_queries_preserve_original_search_filters_and_orderings() {
    let catalog = catalog();
    assert_eq!(catalog.query(&Query::default()).len(), 1);
    assert_eq!(
        catalog
            .query(&Query {
                text: "FixtureUser",
                ..Default::default()
            })
            .len(),
        1
    );
    assert!(catalog
        .query(&Query {
            os: Some("Mac"),
            ..Default::default()
        })
        .is_empty());
    assert!(catalog
        .query(&Query {
            client: Some("Flash"),
            ..Default::default()
        })
        .is_empty());
    assert_eq!(
        catalog
            .query(&Query {
                category: Some("Building"),
                framework: Some("Native"),
                ..Default::default()
            })
            .len(),
        1
    );
    assert_eq!(
        catalog.query(&Query {
            include_outdated: true,
            ..Default::default()
        })[0]
            .title,
        "Another Tool"
    );
    assert_eq!(
        catalog.query(&Query {
            include_outdated: true,
            sort: Sort::LastUpdated,
            ..Default::default()
        })[0]
            .title,
        "Fixture Tool"
    );
    assert_eq!(
        catalog.query(&Query {
            include_outdated: true,
            sort: Sort::Rating,
            reverse: true,
            ..Default::default()
        })[0]
            .title,
        "Fixture Tool"
    );
    assert_eq!(
        extension_store::uri_component("A/B &é"),
        "A%2FB%20%26%C3%A9"
    );
}
#[test]
fn installation_is_atomic_versioned_and_uninstall_stays_inside_its_managed_root() {
    let directory = Directory::new();
    let root = directory.0.join("installed");
    let catalog = catalog();
    let bytes = archive(&[
        ("tool.jar", b"inert fixture, never executed"),
        ("data/config.json", b"{}"),
    ]);
    let record =
        extension_store::install_archive(&catalog, &catalog.extensions[0], &root, &bytes).unwrap();
    assert_eq!(
        std::fs::read(record.directory.join("extension/tool.jar")).unwrap(),
        b"inert fixture, never executed"
    );
    assert_eq!(extension_store::installed(&root).unwrap().len(), 1);
    assert!(
        extension_store::install_archive(&catalog, &catalog.extensions[0], &root, &bytes).is_err()
    );
    let mut updated = catalog.clone();
    updated.extensions[0].version = "2.0".into();
    let second =
        extension_store::install_archive(&updated, &updated.extensions[0], &root, &bytes).unwrap();
    assert_eq!(extension_store::installed(&root).unwrap().len(), 2);
    assert!(record.directory.is_dir());
    let outside = directory.0.join("keep.txt");
    std::fs::write(&outside, b"preserve").unwrap();
    let mut invalid = second.clone();
    invalid.directory = directory.0.clone();
    assert!(extension_store::uninstall(&root, &invalid).is_err());
    assert_eq!(std::fs::read(&outside).unwrap(), b"preserve");
    extension_store::uninstall(&root, &record).unwrap();
    assert!(!record.directory.exists());
    assert!(second.directory.exists());
}

#[test]
fn installed_command_comes_from_the_catalogue_entry() {
    let directory = Directory::new();
    let root = directory.0.join("installed");
    let catalog = catalog();
    let mut supplied = catalog.extensions[0].clone();
    supplied.commands.common = vec!["unexpected-command".into()];
    supplied.commands.windows = Some(vec!["unexpected-command".into()]);
    supplied.commands.linux = Some(vec!["unexpected-command".into()]);
    supplied.commands.mac = Some(vec!["unexpected-command".into()]);
    let bytes = archive(&[("tool.jar", b"fixture")]);
    let installed = extension_store::install_archive(&catalog, &supplied, &root, &bytes).unwrap();
    assert_eq!(
        installed.command,
        catalog.extensions[0].commands.for_platform()
    );
    assert_eq!(
        extension_store::installed(&root).unwrap()[0].command,
        installed.command
    );
}

#[test]
fn update_status_uses_the_newest_version_and_matching_catalogue() {
    use extension_store::InstallStatus;
    let directory = Directory::new();
    let catalog = catalog();
    let extension = &catalog.extensions[0];
    let bytes = archive(&[("tool.jar", b"fixture")]);
    let record =
        extension_store::install_archive(&catalog, extension, &directory.0, &bytes).unwrap();
    let mut older = record.clone();
    older.version = "0.9".into();
    let mut newer = record.clone();
    newer.version = "2.0".into();
    assert_eq!(
        extension_store::install_status(&catalog, extension, &[]),
        InstallStatus::NotInstalled
    );
    assert_eq!(
        extension_store::install_status(&catalog, extension, &[older.clone()]),
        InstallStatus::UpdateAvailable
    );
    assert_eq!(
        extension_store::install_status(&catalog, extension, &[older, newer.clone()]),
        InstallStatus::OlderVersion
    );
    assert_eq!(
        extension_store::install_status(&catalog, extension, &[newer.clone(), record.clone()]),
        InstallStatus::Installed
    );
    newer.source = "other/catalogue".into();
    assert_eq!(
        extension_store::install_status(&catalog, extension, &[newer]),
        InstallStatus::NotInstalled
    );
    let mut same_version_other_source = record;
    same_version_other_source.source = "other/catalogue".into();
    assert_eq!(
        extension_store::install_status(&catalog, extension, &[same_version_other_source]),
        InstallStatus::NotInstalled
    );
}
#[test]
fn rejects_traversal_and_rolls_back_partially_extracted_archives() {
    let directory = Directory::new();
    let root = directory.0.join("installed");
    let catalog = catalog();
    for name in [
        "../escape.txt",
        "/absolute.txt",
        "C:/escape.txt",
        "nested\\..\\escape.txt",
    ] {
        let bytes = archive(&[("good.txt", b"good"), (name, b"bad")]);
        assert!(
            extension_store::install_archive(&catalog, &catalog.extensions[0], &root, &bytes)
                .is_err()
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    }
    assert!(!directory.0.join("escape.txt").exists());
}
#[test]
fn version_order_covers_release_candidates_numeric_components_and_service_packs() {
    for (a, b, expected) in [
        ("1.0.0", "1.0", Ordering::Equal),
        ("1.10", "1.9", Ordering::Greater),
        ("1.4.0-rc2", "1.4.0", Ordering::Less),
        ("1.4.0-rc2", "1.4.0-rc1", Ordering::Greater),
        ("1.0-beta", "1.0-alpha", Ordering::Greater),
        ("1.0-sp1", "1.0", Ordering::Greater),
        ("1.0-final", "1.0", Ordering::Equal),
        ("1-a", "1-alpha", Ordering::Greater),
        ("1-a1", "1-alpha1", Ordering::Equal),
        ("1-1", "1.1", Ordering::Less),
    ] {
        assert_eq!(
            extension_store::compare_versions(a, b),
            expected,
            "{a} vs {b}"
        );
    }
}
#[test]
#[ignore = "requires pinned original store JSON; supplied by Java compatibility CI"]
fn original_catalog_snapshot_parses_and_retains_all_items() {
    let config = std::fs::read(
        std::env::var_os("GEARTH_STORE_CONFIG").expect("store config fixture required"),
    )
    .unwrap();
    let extensions = std::fs::read(
        std::env::var_os("GEARTH_STORE_EXTENSIONS").expect("store extension fixture required"),
    )
    .unwrap();
    let catalog = Catalog::parse(
        extension_store::STORE_SOURCE,
        extension_store::STORE_VERSION,
        &config,
        &extensions,
    )
    .unwrap();
    assert_eq!(catalog.extensions.len(), 105);
    assert!(catalog
        .config
        .frameworks
        .iter()
        .any(|framework| framework.name == "G-Python"));
    assert!(
        catalog
            .query(&Query {
                include_outdated: true,
                ..Default::default()
            })
            .len()
            > 100
    );
}

#[test]
fn multi_source_defaults_persistence_and_merged_queries_work() {
    let defaults = extension_store::default_sources();
    assert_eq!(defaults.len(), 2);
    assert_eq!(defaults[0].repo, extension_store::STORE_SOURCE);
    assert_eq!(defaults[1].repo, extension_store::CUSTOM_STORE_SOURCE);

    let dir = Directory::new();
    let loaded_initial = extension_store::load_sources(&dir.0);
    assert_eq!(loaded_initial, defaults);

    let mut custom_list = defaults.clone();
    custom_list.push(extension_store::StoreSource::new(
        "Example/CustomStore",
        "main",
    ));
    extension_store::save_sources(&dir.0, &custom_list).unwrap();
    assert_eq!(extension_store::load_sources(&dir.0), custom_list);

    let official = catalog();
    let mut custom = catalog();
    custom.source = extension_store::CUSTOM_STORE_SOURCE.into();
    custom.version = "main".into();
    custom.extensions[0].title = "Tear Custom Ext".into();
    custom.extensions[0].rating = 500;
    custom.extensions[0].update_date = "01-06-2026 12:00:00".into();
    custom.extensions.truncate(1);

    assert_eq!(
        official.archive_url(&official.extensions[0]),
        "https://raw.githubusercontent.com/sirjonasxx/G-ExtensionStore/repo/1.5.3/store/extensions/Fixture%20Tool/extension.zip"
    );
    assert_eq!(
        custom.archive_url(&custom.extensions[0]),
        "https://raw.githubusercontent.com/Tear1338/G-ExtensionStore/main/store/extensions/Tear%20Custom%20Ext/extension.zip"
    );

    let multi = extension_store::MultiCatalog::from_catalogs(vec![official, custom]);
    let all = multi.query(&Query::default(), None);
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].1.title, "Tear Custom Ext");
    assert_eq!(all[0].0.source, extension_store::CUSTOM_STORE_SOURCE);
    assert_eq!(all[1].1.title, "Fixture Tool");
    assert_eq!(all[1].0.source, extension_store::STORE_SOURCE);

    let only_custom = multi.query(
        &Query::default(),
        Some(extension_store::CUSTOM_STORE_SOURCE),
    );
    assert_eq!(only_custom.len(), 1);
    assert_eq!(only_custom[0].1.title, "Tear Custom Ext");
}
