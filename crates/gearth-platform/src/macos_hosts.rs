//! Privileged macOS `/etc/hosts` writer using `osascript ... with administrator privileges`.
//! Ported from beta-29 macOS privileged hosts management.
#[cfg(any(target_os = "macos", test))]
use std::{
    ffi::OsString,
    fs,
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use std::{io, net::Ipv4Addr, path::Path};

#[cfg(any(target_os = "macos", test))]
const COPY_HOSTS_SCRIPT: &str = "\
on run argv
  set src to item 1 of argv
  set dst to item 2 of argv
  do shell script \"/bin/cp \" & quoted form of src & \" \" & quoted form of dst & \" && /bin/chmod 644 \" & quoted form of dst with administrator privileges
end run";

#[cfg(any(target_os = "macos", test))]
const ALIAS_LOOPBACK_SCRIPT: &str = "\
on run argv
  set shellCmd to \"\"
  repeat with addr in argv
    if shellCmd is not \"\" then
      set shellCmd to shellCmd & \" && \"
    end if
    set shellCmd to shellCmd & \"/sbin/ifconfig lo0 alias \" & quoted form of (addr as text) & \" up\"
  end repeat
  if shellCmd is not \"\" then
    do shell script shellCmd with administrator privileges
  end if
end run";

#[cfg(any(target_os = "macos", test))]
const RELAUNCH_ADMIN_SCRIPT: &str = "\
on run argv
  set exePath to item 1 of argv as text
  set cfgPath to item 2 of argv as text
  set userHome to item 3 of argv as text
  set envPrefix to \"GEARTH_RUST_CONFIG=\" & quoted form of cfgPath
  if userHome is not \"\" then
    set envPrefix to envPrefix & \" HOME=\" & quoted form of userHome
  end if
  set cmdStr to \"sleep 0.4; exec \" & envPrefix & \" \" & quoted form of exePath
  repeat with i from 4 to (count of argv)
    set cmdStr to cmdStr & \" \" & quoted form of (item i of argv as text)
  end repeat
  do shell script \"/bin/sh -c \" & quoted form of cmdStr & \" </dev/null >/dev/null 2>&1 &\" with administrator privileges
end run";

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ScriptOutput {
    success: bool,
    code: Option<i32>,
    stderr: String,
}

#[cfg(any(target_os = "macos", test))]
struct TempFileGuard(PathBuf);

#[cfg(any(target_os = "macos", test))]
impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(any(target_os = "macos", test))]
fn write_macos_hosts_with_runner(
    path: &Path,
    content: &str,
    temp_dir: &Path,
    mut run: impl FnMut(&Path, &[OsString]) -> io::Result<ScriptOutput>,
) -> io::Result<()> {
    let target_str = path.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "hosts path is not valid UTF-8")
    })?;
    if target_str.is_empty() || target_str.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid hosts target path",
        ));
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temp_path = temp_dir.join(format!("gearth-hosts-{}-{stamp}.tmp", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600));
    }
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    drop(file);
    let _guard = TempFileGuard(temp_path.clone());

    let args = vec![
        OsString::from("-e"),
        OsString::from(COPY_HOSTS_SCRIPT),
        OsString::from("--"),
        temp_path.into_os_string(),
        path.as_os_str().to_os_string(),
    ];
    let output = run(Path::new("/usr/bin/osascript"), &args)?;
    if output.success {
        return Ok(());
    }
    let detail = output.stderr.trim();
    if detail.contains("-128") || detail.contains("User canceled") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "administrator prompt for /etc/hosts was cancelled",
        ));
    }
    Err(io::Error::other(if detail.is_empty() {
        format!(
            "privileged /etc/hosts update failed with status {:?}",
            output.code
        )
    } else {
        format!("privileged /etc/hosts update failed: {detail}")
    }))
}

/// Write `content` to `path` (e.g. `/etc/hosts`) via macOS `osascript` administrator prompt.
pub fn write_macos_hosts_privileged(path: &Path, content: &str) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::process::{Command, Stdio};
        let temp_dir = std::env::temp_dir();
        write_macos_hosts_with_runner(path, content, &temp_dir, |program, args| {
            let output = Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()?;
            Ok(ScriptOutput {
                success: output.status.success(),
                code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, content);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "macOS privileged hosts editing is only available on macOS",
        ))
    }
}

#[cfg(any(target_os = "macos", test))]
fn ensure_loopback_aliases_with_runner(
    ips: &[Ipv4Addr],
    elevated: bool,
    mut run: impl FnMut(&Path, &[OsString]) -> io::Result<ScriptOutput>,
) -> io::Result<()> {
    let mut needed: Vec<String> = Vec::new();
    for &ip in ips {
        if !ip.is_loopback() || ip == Ipv4Addr::LOCALHOST {
            continue;
        }
        let s = ip.to_string();
        if !needed.contains(&s) {
            needed.push(s);
        }
    }
    if needed.is_empty() {
        return Ok(());
    }
    if elevated {
        for ip in &needed {
            let args = vec![
                OsString::from("lo0"),
                OsString::from("alias"),
                OsString::from(ip),
                OsString::from("up"),
            ];
            let output = run(Path::new("/sbin/ifconfig"), &args)?;
            if !output.success {
                let detail = output.stderr.trim();
                return Err(io::Error::other(if detail.is_empty() {
                    format!(
                        "ifconfig lo0 alias {ip} failed with status {:?}",
                        output.code
                    )
                } else {
                    format!("ifconfig lo0 alias {ip} failed: {detail}")
                }));
            }
        }
        return Ok(());
    }
    let mut args = vec![
        OsString::from("-e"),
        OsString::from(ALIAS_LOOPBACK_SCRIPT),
        OsString::from("--"),
    ];
    args.extend(needed.into_iter().map(OsString::from));
    let output = run(Path::new("/usr/bin/osascript"), &args)?;
    if output.success {
        return Ok(());
    }
    let detail = output.stderr.trim();
    if detail.contains("-128") || detail.contains("User canceled") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "administrator prompt for macOS loopback aliases was cancelled",
        ));
    }
    Err(io::Error::other(if detail.is_empty() {
        format!(
            "privileged macOS loopback alias setup failed with status {:?}",
            output.code
        )
    } else {
        format!("privileged macOS loopback alias setup failed: {detail}")
    }))
}

/// Ensure additional `127.0.0.x` loopback addresses are aliased on macOS `lo0` so multi-hotel
/// auto-detect listeners can bind them without `EADDRNOTAVAIL` (os error 49).
pub fn ensure_macos_loopback_aliases(ips: &[Ipv4Addr]) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::{
            net::TcpListener,
            process::{Command, Stdio},
        };
        let missing: Vec<Ipv4Addr> = ips
            .iter()
            .copied()
            .filter(|&ip| {
                ip.is_loopback() && ip != Ipv4Addr::LOCALHOST && TcpListener::bind((ip, 0)).is_err()
            })
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        ensure_loopback_aliases_with_runner(&missing, crate::is_elevated(), |program, args| {
            let output = Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()?;
            Ok(ScriptOutput {
                success: output.status.success(),
                code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = ips;
        Ok(())
    }
}

#[cfg(any(target_os = "macos", test))]
fn relaunch_as_admin_with_runner(
    exe: &Path,
    config_path: &Path,
    user_home: Option<&Path>,
    extra_args: &[String],
    mut run: impl FnMut(&Path, &[OsString]) -> io::Result<ScriptOutput>,
) -> io::Result<()> {
    let exe_str = exe
        .to_str()
        .filter(|s| !s.is_empty() && !s.contains('\0'))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid executable path"))?;
    let cfg_str = config_path
        .to_str()
        .filter(|s| !s.is_empty() && !s.contains('\0'))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid config path"))?;
    let home_str = user_home
        .and_then(|p| p.to_str())
        .filter(|s| !s.contains('\0'))
        .unwrap_or("");
    let mut args = vec![
        OsString::from("-e"),
        OsString::from(RELAUNCH_ADMIN_SCRIPT),
        OsString::from("--"),
        OsString::from(exe_str),
        OsString::from(cfg_str),
        OsString::from(home_str),
    ];
    for arg in extra_args {
        if arg.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid argument for admin relaunch",
            ));
        }
        args.push(OsString::from(arg));
    }
    let output = run(Path::new("/usr/bin/osascript"), &args)?;
    if output.success {
        return Ok(());
    }
    let detail = output.stderr.trim();
    if detail.contains("-128") || detail.contains("User canceled") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "administrator relaunch was cancelled",
        ));
    }
    Err(io::Error::other(if detail.is_empty() {
        format!(
            "macOS administrator relaunch failed with status {:?}",
            output.code
        )
    } else {
        format!("macOS administrator relaunch failed: {detail}")
    }))
}

/// Relaunch the macOS desktop binary with administrator privileges via a single `osascript`
/// prompt, preserving the user's `GEARTH_RUST_CONFIG` and `HOME` paths.
pub fn relaunch_macos_as_admin(
    exe: &Path,
    config_path: &Path,
    user_home: Option<&Path>,
    extra_args: &[String],
) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::process::{Command, Stdio};
        relaunch_as_admin_with_runner(exe, config_path, user_home, extra_args, |program, args| {
            let output = Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output()?;
            Ok(ScriptOutput {
                success: output.status.success(),
                code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (exe, config_path, user_home, extra_args);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "macOS administrator relaunch is only available on macOS",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_safe_osascript_argv_and_cleans_up_temp_file() {
        let dir =
            std::env::temp_dir().join(format!("gearth-macos-hosts-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let mut captured_tmp: Option<PathBuf> = None;
        let result = write_macos_hosts_with_runner(
            Path::new("/etc/hosts"),
            "127.0.0.1 localhost\n",
            &dir,
            |program, args| {
                assert_eq!(program, Path::new("/usr/bin/osascript"));
                assert_eq!(args[0], "-e");
                assert!(args[1]
                    .to_string_lossy()
                    .contains("with administrator privileges"));
                assert_eq!(args[2], "--");
                let tmp = PathBuf::from(&args[3]);
                assert_eq!(fs::read_to_string(&tmp).unwrap(), "127.0.0.1 localhost\n");
                assert_eq!(args[4], "/etc/hosts");
                captured_tmp = Some(tmp);
                Ok(ScriptOutput {
                    success: true,
                    code: Some(0),
                    stderr: String::new(),
                })
            },
        );
        assert!(result.is_ok());
        assert!(!captured_tmp.unwrap().exists());

        let cancelled = write_macos_hosts_with_runner(
            Path::new("/etc/hosts"),
            "127.0.0.1 localhost\n",
            &dir,
            |_, _| {
                Ok(ScriptOutput {
                    success: false,
                    code: Some(1),
                    stderr: "execution error: User canceled. (-128)".into(),
                })
            },
        );
        assert_eq!(
            cancelled.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn loopback_alias_helper_skips_localhost_and_batches_non_root_osascript() {
        let mut calls = Vec::new();
        ensure_loopback_aliases_with_runner(
            &[
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(127, 0, 0, 2),
                Ipv4Addr::new(127, 0, 0, 3),
                Ipv4Addr::new(127, 0, 0, 2),
            ],
            false,
            |program, args| {
                calls.push((
                    program.to_path_buf(),
                    args.iter()
                        .map(|a| a.to_string_lossy().into_owned())
                        .collect::<Vec<_>>(),
                ));
                Ok(ScriptOutput {
                    success: true,
                    code: Some(0),
                    stderr: String::new(),
                })
            },
        )
        .unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, Path::new("/usr/bin/osascript"));
        assert_eq!(&calls[0].1[3..], &["127.0.0.2", "127.0.0.3"]);
    }

    #[test]
    fn relaunch_admin_helper_preserves_config_home_and_args() {
        let mut captured: Vec<String> = Vec::new();
        relaunch_as_admin_with_runner(
            Path::new("/Applications/G-Earth Rust.app/Contents/MacOS/gearth-desktop"),
            Path::new("/Users/drex/.config/G-Earth-Rust/settings.json"),
            Some(Path::new("/Users/drex")),
            &["--connect".into(), "flash".into()],
            |program, args| {
                assert_eq!(program, Path::new("/usr/bin/osascript"));
                captured = args
                    .iter()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect();
                Ok(ScriptOutput {
                    success: true,
                    code: Some(0),
                    stderr: String::new(),
                })
            },
        )
        .unwrap();
        assert_eq!(
            &captured[3..],
            &[
                "/Applications/G-Earth Rust.app/Contents/MacOS/gearth-desktop",
                "/Users/drex/.config/G-Earth-Rust/settings.json",
                "/Users/drex",
                "--connect",
                "flash",
            ]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn applescripts_compile_cleanly_with_osacompile() {
        use std::process::Command;
        let dir =
            std::env::temp_dir().join(format!("gearth-osacompile-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        for (idx, script) in [
            COPY_HOSTS_SCRIPT,
            ALIAS_LOOPBACK_SCRIPT,
            RELAUNCH_ADMIN_SCRIPT,
        ]
        .iter()
        .enumerate()
        {
            let out = dir.join(format!("script-{idx}.scpt"));
            let output = Command::new("/usr/bin/osacompile")
                .arg("-o")
                .arg(&out)
                .arg("-e")
                .arg(script)
                .output()
                .expect("osacompile must execute on macOS");
            assert!(
                output.status.success(),
                "AppleScript {idx} failed to compile: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
