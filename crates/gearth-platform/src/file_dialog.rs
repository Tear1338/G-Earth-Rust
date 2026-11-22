//! Native open/save file pickers for Windows, macOS, and Linux.
use std::{io, path::PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    Extension,
    Schedule,
    Json,
    Text,
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn default_extension(kind: FileKind) -> Option<&'static str> {
    match kind {
        FileKind::Extension => None,
        FileKind::Schedule => Some("sched"),
        FileKind::Json => Some("json"),
        FileKind::Text => Some("txt"),
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn ensure_save_extension(path: PathBuf, kind: FileKind, save: bool) -> PathBuf {
    if !save {
        return path;
    }
    if path.extension().is_some() {
        return path;
    }
    match default_extension(kind) {
        Some(ext) => path.with_extension(ext),
        None => path,
    }
}

#[cfg(windows)]
mod windows {
    use super::FileKind;
    use std::{ffi::OsString, io, os::windows::ffi::OsStringExt, path::PathBuf};
    use windows_sys::Win32::UI::{
        Controls::Dialogs::{
            CommDlgExtendedError, GetOpenFileNameW, GetSaveFileNameW, OFN_EXPLORER,
            OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST,
            OPENFILENAMEW,
        },
        Input::KeyboardAndMouse::GetActiveWindow,
    };

    pub(super) fn filter(kind: FileKind) -> Vec<u16> {
        let text = match kind {
            FileKind::Extension => {
                "Extensions (*.jar;*.exe;*.py;*.py3;*.js;*.sh)\0*.jar;*.exe;*.py;*.py3;*.js;*.sh\0All files (*.*)\0*.*\0\0"
            }
            FileKind::Schedule => "Schedule files (*.sched)\0*.sched\0All files (*.*)\0*.*\0\0",
            FileKind::Json => "JSON files (*.json)\0*.json\0All files (*.*)\0*.*\0\0",
            FileKind::Text => "Text files (*.txt)\0*.txt\0All files (*.*)\0*.*\0\0",
        };
        text.encode_utf16().collect()
    }

    pub(super) fn choose_file(kind: FileKind, save: bool) -> io::Result<Option<PathBuf>> {
        let filter = filter(kind);
        let default_extension: Vec<u16> = match kind {
            FileKind::Schedule => "sched\0".encode_utf16().collect(),
            FileKind::Json => "json\0".encode_utf16().collect(),
            FileKind::Text => "txt\0".encode_utf16().collect(),
            FileKind::Extension => vec![0],
        };
        let mut file = vec![0u16; 32768];
        let mut dialog = OPENFILENAMEW {
            lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
            // The window belongs to this UI thread, so the dialog remains modal to it.
            hwndOwner: unsafe { GetActiveWindow() },
            lpstrFilter: filter.as_ptr(),
            nFilterIndex: 1,
            lpstrFile: file.as_mut_ptr(),
            nMaxFile: file.len() as u32,
            lpstrDefExt: default_extension.as_ptr(),
            Flags: OFN_EXPLORER
                | OFN_NOCHANGEDIR
                | OFN_PATHMUSTEXIST
                | if save {
                    OFN_OVERWRITEPROMPT
                } else {
                    OFN_FILEMUSTEXIST
                },
            ..Default::default()
        };
        // The buffers and the structure remain valid until the modal API returns.
        let selected = unsafe {
            if save {
                GetSaveFileNameW(&mut dialog)
            } else {
                GetOpenFileNameW(&mut dialog)
            }
        };
        if selected == 0 {
            let error = unsafe { CommDlgExtendedError() };
            return if error == 0 {
                Ok(None)
            } else {
                Err(io::Error::other(format!(
                    "Windows dialog error 0x{error:04x}"
                )))
            };
        }
        let len = file.iter().position(|&c| c == 0).unwrap_or(file.len());
        Ok(Some(PathBuf::from(OsString::from_wide(&file[..len]))))
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
mod unix {
    use super::{ensure_save_extension, FileKind};
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    use std::process::{Command, Stdio};
    use std::{io, path::PathBuf};

    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct DialogOutput {
        pub(super) status_code: Option<i32>,
        pub(super) stdout: String,
        pub(super) stderr: String,
    }

    #[cfg(any(target_os = "macos", test))]
    pub(super) fn macos_script(kind: FileKind, save: bool) -> &'static str {
        if save {
            match kind {
                FileKind::Schedule => {
                    r#"POSIX path of (choose file name default name "schedule.sched")"#
                }
                FileKind::Json => r#"POSIX path of (choose file name default name "export.json")"#,
                FileKind::Text => r#"POSIX path of (choose file name default name "packets.txt")"#,
                FileKind::Extension => r#"POSIX path of (choose file name)"#,
            }
        } else {
            match kind {
                FileKind::Extension => {
                    r#"POSIX path of (choose file of type {"jar", "py", "py3", "js", "sh", "exe", "command", "public.unix-executable"})"#
                }
                FileKind::Schedule => r#"POSIX path of (choose file of type {"sched"})"#,
                FileKind::Json => r#"POSIX path of (choose file of type {"json"})"#,
                FileKind::Text => r#"POSIX path of (choose file of type {"txt"})"#,
            }
        }
    }

    #[cfg(any(target_os = "macos", test))]
    pub(super) fn parse_macos_output(
        output: &DialogOutput,
        kind: FileKind,
        save: bool,
    ) -> io::Result<Option<PathBuf>> {
        if output.status_code == Some(0) {
            let trimmed = output.stdout.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                return Ok(None);
            }
            return Ok(Some(ensure_save_extension(
                PathBuf::from(trimmed),
                kind,
                save,
            )));
        }
        if output.stderr.contains("-128") || output.stderr.contains("User canceled") {
            return Ok(None);
        }
        let detail = output.stderr.trim();
        Err(io::Error::other(if detail.is_empty() {
            format!(
                "macOS file dialog failed with status {:?}",
                output.status_code
            )
        } else {
            format!("macOS file dialog failed: {detail}")
        }))
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn zenity_args(kind: FileKind, save: bool) -> Vec<&'static str> {
        let mut args = vec!["--file-selection"];
        if save {
            args.push("--save");
            args.push("--confirm-overwrite");
        }
        args.push(match kind {
            FileKind::Extension => {
                "--file-filter=Extensions (*.jar *.exe *.py *.py3 *.js *.sh) | *.jar *.exe *.py *.py3 *.js *.sh"
            }
            FileKind::Schedule => "--file-filter=Schedule files (*.sched) | *.sched",
            FileKind::Json => "--file-filter=JSON files (*.json) | *.json",
            FileKind::Text => "--file-filter=Text files (*.txt) | *.txt",
        });
        args.push("--file-filter=All files | *");
        args
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn kdialog_args(kind: FileKind, save: bool) -> Vec<&'static str> {
        let filter = match kind {
            FileKind::Extension => "*.jar *.exe *.py *.py3 *.js *.sh|Extensions",
            FileKind::Schedule => "*.sched|Schedule files",
            FileKind::Json => "*.json|JSON files",
            FileKind::Text => "*.txt|Text files",
        };
        vec![
            if save {
                "--getsavefilename"
            } else {
                "--getopenfilename"
            },
            ".",
            filter,
        ]
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn parse_linux_output(
        program: &str,
        output: &DialogOutput,
        kind: FileKind,
        save: bool,
    ) -> io::Result<Option<PathBuf>> {
        match output.status_code {
            Some(0) => {
                let trimmed = output.stdout.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    return Ok(None);
                }
                Ok(Some(ensure_save_extension(
                    PathBuf::from(trimmed),
                    kind,
                    save,
                )))
            }
            Some(1) => Ok(None),
            code => {
                let detail = output.stderr.trim();
                Err(io::Error::other(if detail.is_empty() {
                    format!("{program} dialog failed with status {code:?}")
                } else {
                    format!("{program} dialog failed: {detail}")
                }))
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn run_command(program: &str, args: &[&str]) -> io::Result<DialogOutput> {
        let output = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        Ok(DialogOutput {
            status_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    #[cfg(target_os = "macos")]
    pub(super) fn choose_file(kind: FileKind, save: bool) -> io::Result<Option<PathBuf>> {
        let output = run_command("/usr/bin/osascript", &["-e", macos_script(kind, save)])?;
        parse_macos_output(&output, kind, save)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn choose_file(kind: FileKind, save: bool) -> io::Result<Option<PathBuf>> {
        let zenity = zenity_args(kind, save);
        match run_command("zenity", &zenity) {
            Ok(output) => parse_linux_output("zenity", &output, kind, save),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let kdialog = kdialog_args(kind, save);
                match run_command("kdialog", &kdialog) {
                    Ok(output) => parse_linux_output("kdialog", &output, kind, save),
                    Err(err) if err.kind() == io::ErrorKind::NotFound => Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "install zenity or kdialog for native Linux file dialogs, or type the path manually",
                    )),
                    Err(err) => Err(err),
                }
            }
            Err(error) => Err(error),
        }
    }
}

/// Show a native file picker; cancelling it leaves the current path unchanged.
pub fn choose_file(kind: FileKind, save: bool) -> io::Result<Option<PathBuf>> {
    #[cfg(windows)]
    {
        windows::choose_file(kind, save)
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        unix::choose_file(kind, save)
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        let _ = (kind, save);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native file dialog is unavailable on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn filters_are_double_nul_terminated_and_have_pairs() {
        for kind in [
            FileKind::Extension,
            FileKind::Schedule,
            FileKind::Json,
            FileKind::Text,
        ] {
            let value = windows::filter(kind);
            assert!(value.ends_with(&[0, 0]));
            let pairs: Vec<_> = value[..value.len() - 2].split(|c| *c == 0).collect();
            assert_eq!(pairs.len(), 4);
            assert!(pairs.iter().all(|s| !s.is_empty()));
        }
    }

    #[test]
    fn macos_dialog_parsing_handles_selection_extension_and_cancellation() {
        assert!(unix::macos_script(FileKind::Schedule, false).contains("sched"));
        assert!(unix::macos_script(FileKind::Text, true).contains("packets.txt"));
        let selected = unix::parse_macos_output(
            &unix::DialogOutput {
                status_code: Some(0),
                stdout: "/tmp/capture\n".into(),
                stderr: String::new(),
            },
            FileKind::Text,
            true,
        )
        .unwrap();
        assert_eq!(selected, Some(PathBuf::from("/tmp/capture.txt")));
        let cancelled = unix::parse_macos_output(
            &unix::DialogOutput {
                status_code: Some(1),
                stdout: String::new(),
                stderr: "execution error: User canceled. (-128)\n".into(),
            },
            FileKind::Json,
            false,
        )
        .unwrap();
        assert_eq!(cancelled, None);
    }

    #[test]
    fn linux_dialog_arguments_and_output_handle_save_and_cancel() {
        let zenity = unix::zenity_args(FileKind::Schedule, true);
        assert!(zenity.contains(&"--save"));
        assert!(zenity.contains(&"--confirm-overwrite"));
        let kdialog = unix::kdialog_args(FileKind::Json, false);
        assert_eq!(kdialog[0], "--getopenfilename");
        let saved = unix::parse_linux_output(
            "zenity",
            &unix::DialogOutput {
                status_code: Some(0),
                stdout: "/tmp/rules\n".into(),
                stderr: String::new(),
            },
            FileKind::Schedule,
            true,
        )
        .unwrap();
        assert_eq!(saved, Some(PathBuf::from("/tmp/rules.sched")));
        let cancelled = unix::parse_linux_output(
            "zenity",
            &unix::DialogOutput {
                status_code: Some(1),
                stdout: String::new(),
                stderr: String::new(),
            },
            FileKind::Text,
            false,
        )
        .unwrap();
        assert_eq!(cancelled, None);
    }
}
