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
use std::{io, path::Path};

#[cfg(any(target_os = "macos", test))]
const COPY_HOSTS_SCRIPT: &str = "\
on run argv
  set src to item 1 of argv
  set dst to item 2 of argv
  do shell script \"/bin/cp \" & quoted form of src & \" \" & quoted form of dst & \" && /bin/chmod 644 \" & quoted form of dst with administrator privileges
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
}
