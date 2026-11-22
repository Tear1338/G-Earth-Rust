//! macOS Habbo Flash client ad-hoc re-signing helper, ported from beta-29
//! `MacOSFlashClientResigner.java` / `MacOSFlashClientPreparation.java`.
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(any(target_os = "macos", test))]
use std::{fs, path::Path, time::SystemTime};
use std::{io, path::PathBuf};

#[cfg(any(target_os = "macos", test))]
const HABBO_APP_NAME: &str = "Habbo.app";
#[cfg(any(target_os = "macos", test))]
const HABBO_EXECUTABLE: &str = "Contents/MacOS/Habbo";
#[cfg(any(target_os = "macos", test))]
const GET_TASK_ALLOW: &str = "com.apple.security.get-task-allow";
#[cfg(any(target_os = "macos", test))]
const ENTITLEMENTS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.get-task-allow</key>
    <true/>
</dict>
</plist>
"#;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MacosFlashPrepStatus {
    NotInstalled,
    AlreadyPrepared(PathBuf),
    NeedsPreparation(PathBuf),
    Unsupported,
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Debug)]
struct CommandOutput {
    exit_code: i32,
    combined: String,
}

#[cfg(any(target_os = "macos", test))]
trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput>;
}

#[cfg(target_os = "macos")]
struct SystemRunner;

#[cfg(target_os = "macos")]
impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        let output = Command::new(program).args(args).output()?;
        let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
        if !output.stderr.is_empty() {
            if !combined.is_empty() && !combined.ends_with('\n') {
                combined.push('\n');
            }
            combined.push_str(&String::from_utf8_lossy(&output.stderr));
        }
        Ok(CommandOutput {
            exit_code: output.status.code().unwrap_or(-1),
            combined,
        })
    }
}

#[cfg(any(target_os = "macos", test))]
fn locate_in(air_downloads: &Path) -> io::Result<Option<PathBuf>> {
    if !air_downloads.is_dir() {
        return Ok(None);
    }
    let mut best: Option<(SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(air_downloads)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let app = path.join(HABBO_APP_NAME);
        if !app.join(HABBO_EXECUTABLE).is_file() {
            continue;
        }
        let modified = fs::metadata(&app)
            .and_then(|meta| meta.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        if best
            .as_ref()
            .is_none_or(|(best_time, _)| modified > *best_time)
        {
            best = Some((modified, app));
        }
    }
    Ok(best.map(|(_, app)| app))
}

#[cfg(any(target_os = "macos", test))]
fn is_prepared_with(executable: &Path, runner: &impl CommandRunner) -> io::Result<bool> {
    let exe_str = executable.to_string_lossy();
    let entitlements = runner.run(
        "/usr/bin/codesign",
        &["-d", "--entitlements", "-", &exe_str],
    )?;
    let details = runner.run("/usr/bin/codesign", &["-dv", "--verbose=4", &exe_str])?;

    let ad_hoc = details
        .combined
        .lines()
        .any(|line| line.trim() == "Signature=adhoc");
    let hardened_runtime = details
        .combined
        .lines()
        .filter(|line| line.starts_with("CodeDirectory "))
        .any(|line| line.contains("runtime"));
    let has_get_task_allow = entitlements.combined.contains(GET_TASK_ALLOW)
        && (entitlements.combined.contains("<true/>")
            || entitlements.combined.contains("[Bool] true"));

    Ok(entitlements.exit_code == 0
        && has_get_task_allow
        && details.exit_code == 0
        && ad_hoc
        && !hardened_runtime)
}

#[cfg(any(target_os = "macos", test))]
fn next_backup_path(parent: &Path) -> PathBuf {
    let initial = parent.join("Habbo.gearth-original.app");
    if !initial.exists() {
        return initial;
    }
    let mut suffix = 1u32;
    loop {
        let candidate = parent.join(format!("Habbo.gearth-original-{suffix}.app"));
        if !candidate.exists() {
            return candidate;
        }
        suffix += 1;
    }
}

#[cfg(any(target_os = "macos", test))]
fn unique_temp_dir(parent: &Path, prefix: &str) -> io::Result<PathBuf> {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0..100u32 {
        let candidate = parent.join(format!("{prefix}{pid}-{nanos}-{attempt}"));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate temporary directory for Habbo preparation",
    ))
}

#[cfg(any(target_os = "macos", test))]
fn require_success(output: &CommandOutput, operation: &str) -> io::Result<()> {
    if output.exit_code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "Failed to {operation}: {}",
            output.combined.trim()
        )))
    }
}

#[cfg(any(target_os = "macos", test))]
fn resign_with(
    habbo_app: &Path,
    is_running: bool,
    runner: &impl CommandRunner,
) -> io::Result<PathBuf> {
    if is_running {
        return Err(io::Error::other(
            "Habbo is running. Close it before preparing the client.",
        ));
    }
    let parent = habbo_app
        .parent()
        .ok_or_else(|| io::Error::other("Habbo.app has no parent directory"))?;
    let temp_dir = unique_temp_dir(&std::env::temp_dir(), "gearth-habbo-")?;
    let mut staging_dir: Option<PathBuf> = None;

    let result = (|| -> io::Result<PathBuf> {
        let temp_app = temp_dir.join(HABBO_APP_NAME);
        let entitlements_path = temp_dir.join("habbo.entitlements");
        require_success(
            &runner.run(
                "/usr/bin/ditto",
                &[&habbo_app.to_string_lossy(), &temp_app.to_string_lossy()],
            )?,
            "copy Habbo",
        )?;
        fs::write(&entitlements_path, ENTITLEMENTS)?;

        let temp_exe = temp_app.join(HABBO_EXECUTABLE);
        require_success(
            &runner.run(
                "/usr/bin/codesign",
                &[
                    "--force",
                    "--sign",
                    "-",
                    "--entitlements",
                    &entitlements_path.to_string_lossy(),
                    &temp_exe.to_string_lossy(),
                ],
            )?,
            "sign the Habbo executable",
        )?;

        if !is_prepared_with(&temp_exe, runner)? {
            return Err(io::Error::other(
                "The prepared Habbo executable did not pass signature verification.",
            ));
        }

        let stage = unique_temp_dir(parent, ".gearth-habbo-stage-")?;
        let staged_app = stage.join(HABBO_APP_NAME);
        staging_dir = Some(stage);
        require_success(
            &runner.run(
                "/usr/bin/ditto",
                &[&temp_app.to_string_lossy(), &staged_app.to_string_lossy()],
            )?,
            "stage Habbo",
        )?;

        let backup = next_backup_path(parent);
        fs::rename(habbo_app, &backup)?;
        if let Err(install_err) = fs::rename(&staged_app, habbo_app) {
            let _ = fs::rename(&backup, habbo_app);
            return Err(install_err);
        }
        Ok(backup)
    })();

    let _ = fs::remove_dir_all(&temp_dir);
    if let Some(stage) = staging_dir {
        let _ = fs::remove_dir_all(stage);
    }
    result
}

#[cfg(target_os = "macos")]
fn default_air_downloads() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Habbo Launcher")
            .join("downloads")
            .join("air")
    })
}

pub fn check_macos_flash_client() -> io::Result<MacosFlashPrepStatus> {
    #[cfg(target_os = "macos")]
    {
        let Some(air_downloads) = default_air_downloads() else {
            return Ok(MacosFlashPrepStatus::NotInstalled);
        };
        let Some(app) = locate_in(&air_downloads)? else {
            return Ok(MacosFlashPrepStatus::NotInstalled);
        };
        let prepared = is_prepared_with(&app.join(HABBO_EXECUTABLE), &SystemRunner)?;
        Ok(if prepared {
            MacosFlashPrepStatus::AlreadyPrepared(app)
        } else {
            MacosFlashPrepStatus::NeedsPreparation(app)
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(MacosFlashPrepStatus::Unsupported)
    }
}

pub fn prepare_macos_flash_client() -> io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let air_downloads =
            default_air_downloads().ok_or_else(|| io::Error::other("HOME directory is not set"))?;
        let app = locate_in(&air_downloads)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Habbo.app not found"))?;
        let running = crate::macos::processes()
            .map(|procs| {
                procs
                    .iter()
                    .any(|p| p.executable.eq_ignore_ascii_case("habbo"))
            })
            .unwrap_or(false);
        resign_with(&app, running, &SystemRunner)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "macOS Flash client preparation is only available on macOS",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeRunner {
        commands: RefCell<Vec<(String, Vec<String>)>>,
        prepared_after_sign: bool,
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
            self.commands.borrow_mut().push((
                program.to_owned(),
                args.iter().map(|a| (*a).to_owned()).collect(),
            ));
            if program == "/usr/bin/ditto" && args.len() == 2 {
                let src = Path::new(args[0]);
                let dst = Path::new(args[1]);
                let dst_exe = dst.join(HABBO_EXECUTABLE);
                fs::create_dir_all(dst_exe.parent().unwrap())?;
                fs::copy(src.join(HABBO_EXECUTABLE), dst_exe)?;
                return Ok(CommandOutput {
                    exit_code: 0,
                    combined: String::new(),
                });
            }
            if program == "/usr/bin/codesign" && args.first() == Some(&"--force") {
                return Ok(CommandOutput {
                    exit_code: 0,
                    combined: String::new(),
                });
            }
            if program == "/usr/bin/codesign" && args.first() == Some(&"-d") {
                return Ok(CommandOutput {
                    exit_code: 0,
                    combined: if self.prepared_after_sign {
                        "<key>com.apple.security.get-task-allow</key><true/>".into()
                    } else {
                        String::new()
                    },
                });
            }
            if program == "/usr/bin/codesign" && args.first() == Some(&"-dv") {
                return Ok(CommandOutput {
                    exit_code: 0,
                    combined: if self.prepared_after_sign {
                        "Signature=adhoc\nCodeDirectory v=20400 flags=0x2(adhoc)".into()
                    } else {
                        "Signature=adhoc\nCodeDirectory v=20500 flags=0x10000(runtime)".into()
                    },
                });
            }
            Ok(CommandOutput {
                exit_code: 1,
                combined: "unexpected command".into(),
            })
        }
    }

    #[test]
    fn locates_resigns_verifies_and_backs_up_habbo_app() {
        let root = unique_temp_dir(&std::env::temp_dir(), "gearth-macos-prep-test-").unwrap();
        let app = root.join("100").join(HABBO_APP_NAME);
        let exe = app.join(HABBO_EXECUTABLE);
        fs::create_dir_all(exe.parent().unwrap()).unwrap();
        fs::write(&exe, b"habbo-bin").unwrap();

        assert_eq!(locate_in(&root).unwrap().as_deref(), Some(app.as_path()));

        let running_runner = FakeRunner {
            commands: RefCell::new(Vec::new()),
            prepared_after_sign: true,
        };
        assert!(resign_with(&app, true, &running_runner).is_err());

        let unverified_runner = FakeRunner {
            commands: RefCell::new(Vec::new()),
            prepared_after_sign: false,
        };
        assert!(resign_with(&app, false, &unverified_runner).is_err());
        assert!(app.join(HABBO_EXECUTABLE).is_file());

        let ok_runner = FakeRunner {
            commands: RefCell::new(Vec::new()),
            prepared_after_sign: true,
        };
        let backup = resign_with(&app, false, &ok_runner).unwrap();
        assert_eq!(
            backup.file_name().and_then(|n| n.to_str()),
            Some("Habbo.gearth-original.app")
        );
        assert!(backup.join(HABBO_EXECUTABLE).is_file());
        assert!(app.join(HABBO_EXECUTABLE).is_file());
        assert_eq!(
            next_backup_path(app.parent().unwrap())
                .file_name()
                .and_then(|n| n.to_str()),
            Some("Habbo.gearth-original-1.app")
        );
        let _ = fs::remove_dir_all(&root);
    }
}
