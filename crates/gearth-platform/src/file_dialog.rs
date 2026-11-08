use std::{ffi::OsString, io, os::windows::ffi::OsStringExt, path::PathBuf};
use windows_sys::Win32::UI::{
    Controls::Dialogs::{
        CommDlgExtendedError, GetOpenFileNameW, GetSaveFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST,
        OFN_NOCHANGEDIR, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW,
    },
    Input::KeyboardAndMouse::GetActiveWindow,
};

#[derive(Clone, Copy)]
pub enum FileKind {
    Extension,
    Schedule,
    Json,
    Text,
}

fn filter(kind: FileKind) -> Vec<u16> {
    let text = match kind {
        FileKind::Extension => {
            "Extensions (*.jar;*.exe;*.py)\0*.jar;*.exe;*.py\0All files (*.*)\0*.*\0\0"
        }
        FileKind::Schedule => "Schedule files (*.sched)\0*.sched\0All files (*.*)\0*.*\0\0",
        FileKind::Json => "JSON files (*.json)\0*.json\0All files (*.*)\0*.*\0\0",
        FileKind::Text => "Text files (*.txt)\0*.txt\0All files (*.*)\0*.*\0\0",
    };
    text.encode_utf16().collect()
}

/// Show a Windows file picker; cancelling it leaves the current path unchanged.
pub fn choose_file(kind: FileKind, save: bool) -> io::Result<Option<PathBuf>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_are_double_nul_terminated_and_have_pairs() {
        for kind in [
            FileKind::Extension,
            FileKind::Schedule,
            FileKind::Json,
            FileKind::Text,
        ] {
            let value = filter(kind);
            assert!(value.ends_with(&[0, 0]));
            let pairs: Vec<_> = value[..value.len() - 2].split(|c| *c == 0).collect();
            assert_eq!(pairs.len(), 4);
            assert!(pairs.iter().all(|s| !s.is_empty()));
        }
    }
}
