//! Automatic Java & JavaFX runtime resolution for G-Earth `.jar` extensions.
//!
//! Many G-Earth extensions (including G-Presets and G-ExtensionStore Java extensions)
//! require JavaFX modules (`javafx.controls`, `javafx.fxml`, `javafx.web`, etc.) that
//! are absent from standard Oracle/Temurin JDK 17/21 builds. This module:
//! 1. Inspects the JAR manifest (`Build-Jdk`) to route legacy Java 8 extensions to a local
//!    Java 8 runtime with `jfxrt.jar` (matching beta-29 `NormalExtensionRunner`).
//! 2. Checks whether the selected Java runtime already bundles `javafx.controls`.
//! 3. Otherwise downloads and caches the 7 official Maven Central OpenJFX 21.0.2 module
//!    JARs once into the G-Earth data directory and injects `--module-path` + `--add-modules`.
use std::{
    collections::HashMap,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Mutex, OnceLock},
    time::Duration,
};

const OPENJFX_VERSION: &str = "21.0.2";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_JAVAFX_JAR_BYTES: u64 = 48 * 1024 * 1024;
const OPENJFX_MODULES: &[&str] = &[
    "base", "graphics", "controls", "fxml", "media", "web", "swing",
];
const ADD_MODULES_ARG: &str =
    "javafx.base,javafx.controls,javafx.fxml,javafx.graphics,javafx.media,javafx.swing,javafx.web";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JavaLaunchPlan {
    pub executable: PathBuf,
    pub extra_jvm_args: Vec<String>,
}

fn platform_javafx_classifier() -> Option<&'static str> {
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Some("win")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("linux")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("linux-aarch64")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("mac-aarch64")
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some("mac")
    } else {
        None
    }
}

/// Inspect `META-INF/MANIFEST.MF` inside a JAR and return `true` when `Build-Jdk` starts with `1.8`.
pub fn jar_requires_java8(jar_path: &Path) -> bool {
    let Ok(file) = fs::File::open(jar_path) else {
        return false;
    };
    let Ok(mut archive) = zip::ZipArchive::new(file) else {
        return false;
    };
    let Ok(entry) = archive.by_name("META-INF/MANIFEST.MF") else {
        return false;
    };
    let mut bytes = Vec::new();
    if entry
        .take(MAX_MANIFEST_BYTES)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return false;
    }
    let text = String::from_utf8_lossy(&bytes);
    manifest_requires_java8(&text)
}

pub fn manifest_requires_java8(manifest: &str) -> bool {
    for line in manifest.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed
            .strip_prefix("Build-Jdk:")
            .or_else(|| trimmed.strip_prefix("Build-Jdk-Spec:"))
        {
            let value = rest.trim();
            return value.starts_with("1.8") || value == "8";
        }
    }
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JavaProbe {
    UnavailableOrLegacy,
    ModularWithJavaFx,
    ModularWithoutJavaFx,
}

fn probe_java(java_exe: &Path) -> JavaProbe {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, JavaProbe>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(map) = cache.lock() {
        if let Some(&cached) = map.get(java_exe) {
            return cached;
        }
    }
    let mut cmd = Command::new(java_exe);
    cmd.arg("--list-modules")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    let probed = match cmd.output() {
        Ok(out) if out.status.success() => {
            if String::from_utf8_lossy(&out.stdout).contains("javafx.controls") {
                JavaProbe::ModularWithJavaFx
            } else {
                JavaProbe::ModularWithoutJavaFx
            }
        }
        _ => JavaProbe::UnavailableOrLegacy,
    };
    if let Ok(mut map) = cache.lock() {
        map.insert(java_exe.to_path_buf(), probed);
    }
    probed
}

/// Check whether `java_exe --list-modules` reports built-in `javafx.controls`.
pub fn java_has_javafx(java_exe: &Path) -> bool {
    probe_java(java_exe) == JavaProbe::ModularWithJavaFx
}

fn find_java8_with_javafx() -> Option<PathBuf> {
    let exe_name = if cfg!(windows) { "java.exe" } else { "java" };
    let roots: Vec<PathBuf> = if cfg!(windows) {
        vec![
            PathBuf::from(r"C:\Program Files\Java"),
            PathBuf::from(r"C:\Program Files (x86)\Java"),
            PathBuf::from(r"C:\Program Files\BellSoft"),
            PathBuf::from(r"C:\Program Files\Zulu"),
        ]
    } else if cfg!(target_os = "macos") {
        vec![PathBuf::from("/Library/Java/JavaVirtualMachines")]
    } else {
        vec![PathBuf::from("/usr/lib/jvm")]
    };
    for root in roots {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if !(name.contains("1.8")
                || name.contains("java-8")
                || name.contains("jre8")
                || name.contains("jdk8"))
            {
                continue;
            }
            let candidates = [
                path.join("bin").join(exe_name),
                path.join("Contents/Home/bin").join(exe_name),
            ];
            for candidate in candidates {
                let Some(home) = candidate.parent().and_then(Path::parent) else {
                    continue;
                };
                let has_jfx = home.join("lib/ext/jfxrt.jar").is_file()
                    || home.join("jre/lib/ext/jfxrt.jar").is_file();
                if candidate.is_file() && has_jfx {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn find_bundled_javafx_java() -> Option<PathBuf> {
    let exe_name = if cfg!(windows) { "java.exe" } else { "java" };
    if let Ok(exe) = std::env::current_exe() {
        for dir in exe.ancestors().skip(1).take(5) {
            let candidate = dir.join("jre").join("bin").join(exe_name);
            if candidate.is_file() && java_has_javafx(&candidate) {
                return Some(candidate);
            }
        }
    }
    if cfg!(windows) {
        for root in [
            PathBuf::from(r"C:\Program Files\BellSoft"),
            PathBuf::from(r"C:\Program Files\Zulu"),
        ] {
            let Ok(entries) = fs::read_dir(root) else {
                continue;
            };
            for entry in entries.flatten() {
                let candidate = entry.path().join("bin").join(exe_name);
                if candidate.is_file() && java_has_javafx(&candidate) {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

/// Ensure the 7 official Maven Central OpenJFX 21.0.2 JARs exist in `javafx_dir`.
pub fn ensure_javafx_modules(javafx_dir: &Path) -> io::Result<PathBuf> {
    let classifier = platform_javafx_classifier().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "automatic OpenJFX download is unsupported on this architecture",
        )
    })?;
    fs::create_dir_all(javafx_dir)?;
    let mut missing = Vec::new();
    for module in OPENJFX_MODULES {
        let filename = format!("javafx-{module}-{OPENJFX_VERSION}-{classifier}.jar");
        let dest = javafx_dir.join(&filename);
        if !dest.is_file() || fs::metadata(&dest).map_or(true, |m| m.len() < 1024) {
            missing.push((*module, filename, dest));
        }
    }
    if missing.is_empty() {
        return Ok(javafx_dir.to_path_buf());
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(60))
        .build();
    for (module, filename, dest) in missing {
        let url = format!(
            "https://repo.maven.apache.org/maven2/org/openjfx/javafx-{module}/{OPENJFX_VERSION}/{filename}"
        );
        let response = agent
            .get(&url)
            .set("User-Agent", "G-Earth-Rust")
            .call()
            .map_err(|e| io::Error::other(format!("failed to download OpenJFX {module}: {e}")))?;
        let tmp = javafx_dir.join(format!(".{filename}.{}.tmp", std::process::id()));
        let mut reader = response.into_reader();
        let mut file = fs::File::create(&tmp)?;
        let mut buf = [0u8; 64 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total = total.saturating_add(n as u64);
            if total > MAX_JAVAFX_JAR_BYTES {
                drop(file);
                let _ = fs::remove_file(&tmp);
                return Err(io::Error::other(format!(
                    "OpenJFX {module} JAR exceeded size limit"
                )));
            }
            file.write_all(&buf[..n])?;
        }
        file.sync_all()?;
        drop(file);
        if dest.exists() {
            let _ = fs::remove_file(&dest);
        }
        fs::rename(&tmp, &dest)?;
    }
    Ok(javafx_dir.to_path_buf())
}

pub fn default_javafx_cache_dir() -> PathBuf {
    crate::settings::Settings::default_path()
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("javafx-{OPENJFX_VERSION}"))
}

/// Resolve the Java executable and any required JavaFX `--module-path` flags for launching a JAR.
pub fn resolve_java_launch(
    preferred_java: &Path,
    jar_path: Option<&Path>,
    javafx_cache_dir: &Path,
) -> io::Result<JavaLaunchPlan> {
    // Preserve explicit nonexistent runtime paths so callers report NotFound.
    if preferred_java.components().count() > 1 && !preferred_java.is_file() {
        return Ok(JavaLaunchPlan {
            executable: preferred_java.to_path_buf(),
            extra_jvm_args: Vec::new(),
        });
    }

    if let Some(jar) = jar_path {
        if jar_requires_java8(jar) {
            if let Some(java8) = find_java8_with_javafx() {
                return Ok(JavaLaunchPlan {
                    executable: java8,
                    extra_jvm_args: Vec::new(),
                });
            }
        }
    }

    let candidate = if preferred_java.as_os_str().is_empty() {
        PathBuf::from(if cfg!(windows) { "java.exe" } else { "java" })
    } else {
        preferred_java.to_path_buf()
    };

    match probe_java(&candidate) {
        JavaProbe::ModularWithJavaFx | JavaProbe::UnavailableOrLegacy => Ok(JavaLaunchPlan {
            executable: candidate,
            extra_jvm_args: Vec::new(),
        }),
        JavaProbe::ModularWithoutJavaFx => {
            if let Some(bundled) = find_bundled_javafx_java() {
                return Ok(JavaLaunchPlan {
                    executable: bundled,
                    extra_jvm_args: Vec::new(),
                });
            }
            let modules_dir = ensure_javafx_modules(javafx_cache_dir)?;
            Ok(JavaLaunchPlan {
                executable: candidate,
                extra_jvm_args: vec![
                    "--module-path".into(),
                    modules_dir.to_string_lossy().into_owned(),
                    "--add-modules".into(),
                    ADD_MODULES_ARG.into(),
                ],
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_java8_vs_modern_build_jdk_from_manifest() {
        assert!(manifest_requires_java8(
            "Manifest-Version: 1.0\r\nBuild-Jdk: 1.8.0_391\r\nMain-Class: ext.Main\r\n"
        ));
        assert!(manifest_requires_java8("Build-Jdk-Spec: 8\n"));
        assert!(!manifest_requires_java8(
            "Manifest-Version: 1.0\r\nBuild-Jdk: 21.0.8\r\nMain-Class: extension.GPresetsLauncher\r\n"
        ));
        assert!(!manifest_requires_java8("Manifest-Version: 1.0\n"));
    }

    #[test]
    fn cached_javafx_modules_require_no_network_download() {
        let Some(classifier) = platform_javafx_classifier() else {
            return;
        };
        let dir = std::env::temp_dir().join(format!(
            "gearth-jfx-cache-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        for module in OPENJFX_MODULES {
            let name = format!("javafx-{module}-{OPENJFX_VERSION}-{classifier}.jar");
            fs::write(dir.join(name), vec![0u8; 2048]).unwrap();
        }
        let resolved = ensure_javafx_modules(&dir).unwrap();
        assert_eq!(resolved, dir);
        let _ = fs::remove_dir_all(&dir);
    }
}
