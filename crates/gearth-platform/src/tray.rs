//! Optional native system-tray icon, isolated on a dedicated worker thread.
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayEvent {
    Show,
    Quit,
}

pub struct SystemTray {
    #[cfg(windows)]
    inner: windows::State,
}

impl SystemTray {
    /// Register a tray icon for the application. Non-Windows platforms return Unsupported.
    pub fn start(tooltip: &str, wake: impl Fn() + Send + 'static) -> io::Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self {
                inner: windows::State::start(tooltip, wake)?,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (tooltip, wake);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "system tray integration currently requires Windows",
            ))
        }
    }

    pub fn try_recv(&self) -> Option<TrayEvent> {
        #[cfg(windows)]
        {
            self.inner.try_recv()
        }
        #[cfg(not(windows))]
        {
            None
        }
    }
}

#[cfg(any(windows, test))]
fn encode_tooltip_utf16(text: &str) -> [u16; 128] {
    let mut buffer = [0u16; 128];
    for (slot, unit) in buffer.iter_mut().take(127).zip(text.encode_utf16()) {
        *slot = unit;
    }
    buffer
}

#[cfg(windows)]
mod windows {
    use super::{encode_tooltip_utf16, TrayEvent};
    use std::{
        cell::RefCell,
        io, mem, ptr,
        sync::mpsc,
        thread::{self, JoinHandle},
        time::Duration,
    };
    use windows_sys::Win32::{
        Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM},
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            Shell::{
                Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE,
                NOTIFYICONDATAW,
            },
            WindowsAndMessaging::{
                AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
                DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, LoadIconW,
                PostMessageW, PostQuitMessage, RegisterClassW, SetForegroundWindow, TrackPopupMenu,
                TranslateMessage, UnregisterClassW, CW_USEDEFAULT, IDI_APPLICATION, MF_STRING, MSG,
                TPM_BOTTOMALIGN, TPM_LEFTALIGN, TPM_RETURNCMD, WM_APP, WM_CLOSE, WM_CONTEXTMENU,
                WM_DESTROY, WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_RBUTTONUP, WNDCLASSW,
            },
        },
    };

    const WM_TRAY: u32 = WM_APP + 1;
    const CMD_SHOW: u32 = 1001;
    const CMD_QUIT: u32 = 1002;
    const TRAY_ID: u32 = 1;

    struct CallbackContext {
        tx: mpsc::SyncSender<TrayEvent>,
        wake: Box<dyn Fn() + Send>,
    }

    thread_local! {
        static CONTEXT: RefCell<Option<CallbackContext>> = const { RefCell::new(None) };
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(Some(0)).collect()
    }

    fn emit(event: TrayEvent) {
        CONTEXT.with(|cell| {
            if let Some(ctx) = cell.borrow().as_ref() {
                if ctx.tx.try_send(event).is_ok() {
                    (ctx.wake)();
                }
            }
        });
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_TRAY => {
                let mouse_msg = (lparam as u32) & 0xffff;
                if mouse_msg == WM_LBUTTONDBLCLK || mouse_msg == WM_LBUTTONUP {
                    emit(TrayEvent::Show);
                    return 0;
                }
                if mouse_msg == WM_RBUTTONUP || mouse_msg == WM_CONTEXTMENU {
                    let menu = unsafe { CreatePopupMenu() };
                    if !menu.is_null() {
                        let show_label = wide("Show G-Earth Rust");
                        let quit_label = wide("Exit");
                        unsafe {
                            AppendMenuW(menu, MF_STRING, CMD_SHOW as usize, show_label.as_ptr());
                            AppendMenuW(menu, MF_STRING, CMD_QUIT as usize, quit_label.as_ptr());
                            let mut pt = POINT::default();
                            GetCursorPos(&mut pt);
                            SetForegroundWindow(hwnd);
                            let selected = TrackPopupMenu(
                                menu,
                                TPM_RETURNCMD | TPM_LEFTALIGN | TPM_BOTTOMALIGN,
                                pt.x,
                                pt.y,
                                0,
                                hwnd,
                                ptr::null(),
                            );
                            DestroyMenu(menu);
                            if selected == CMD_SHOW as i32 {
                                emit(TrayEvent::Show);
                            } else if selected == CMD_QUIT as i32 {
                                emit(TrayEvent::Quit);
                            }
                        }
                    }
                    return 0;
                }
                0
            }
            WM_CLOSE => {
                unsafe {
                    DestroyWindow(hwnd);
                }
                0
            }
            WM_DESTROY => {
                unsafe {
                    PostQuitMessage(0);
                }
                0
            }
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    pub struct State {
        hwnd_raw: isize,
        thread: Option<JoinHandle<()>>,
        events: mpsc::Receiver<TrayEvent>,
    }

    impl State {
        pub fn start(tooltip: &str, wake: impl Fn() + Send + 'static) -> io::Result<Self> {
            let (events_tx, events) = mpsc::sync_channel(16);
            let (ready_tx, ready) = mpsc::sync_channel::<io::Result<isize>>(1);
            let tip = encode_tooltip_utf16(tooltip);
            let thread = thread::Builder::new()
                .name("gearth-tray".into())
                .spawn(move || {
                    let class_name = wide(&format!("GEarthRustTray_{}", std::process::id()));
                    let instance = unsafe { GetModuleHandleW(ptr::null()) };
                    let wc = WNDCLASSW {
                        lpfnWndProc: Some(wnd_proc),
                        hInstance: instance,
                        lpszClassName: class_name.as_ptr(),
                        ..Default::default()
                    };
                    let atom = unsafe { RegisterClassW(&wc) };
                    if atom == 0 {
                        let _ = ready_tx.send(Err(io::Error::last_os_error()));
                        return;
                    }
                    let hwnd = unsafe {
                        CreateWindowExW(
                            0,
                            class_name.as_ptr(),
                            class_name.as_ptr(),
                            0,
                            CW_USEDEFAULT,
                            CW_USEDEFAULT,
                            0,
                            0,
                            ptr::null_mut(),
                            ptr::null_mut(),
                            instance,
                            ptr::null(),
                        )
                    };
                    if hwnd.is_null() {
                        let error = io::Error::last_os_error();
                        unsafe {
                            UnregisterClassW(class_name.as_ptr(), instance);
                        }
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                    // Embedded resource ID 1 is populated by build.rs / resources/gearth_icon.rc.
                    let icon = unsafe {
                        let embedded = LoadIconW(instance, ptr::without_provenance::<u16>(1));
                        if embedded.is_null() {
                            LoadIconW(ptr::null_mut(), IDI_APPLICATION)
                        } else {
                            embedded
                        }
                    };
                    let mut nid: NOTIFYICONDATAW = unsafe { mem::zeroed() };
                    nid.cbSize = mem::size_of::<NOTIFYICONDATAW>() as u32;
                    nid.hWnd = hwnd;
                    nid.uID = TRAY_ID;
                    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
                    nid.uCallbackMessage = WM_TRAY;
                    nid.hIcon = icon;
                    nid.szTip = tip;
                    if unsafe { Shell_NotifyIconW(NIM_ADD, &nid) } == 0 {
                        unsafe {
                            DestroyWindow(hwnd);
                            UnregisterClassW(class_name.as_ptr(), instance);
                        }
                        let _ = ready_tx.send(Err(io::Error::other(
                            "Windows Shell_NotifyIconW(NIM_ADD) failed",
                        )));
                        return;
                    }
                    CONTEXT.with(|cell| {
                        *cell.borrow_mut() = Some(CallbackContext {
                            tx: events_tx,
                            wake: Box::new(wake),
                        });
                    });
                    if ready_tx.send(Ok(hwnd as isize)).is_err() {
                        unsafe {
                            Shell_NotifyIconW(NIM_DELETE, &nid);
                            DestroyWindow(hwnd);
                            UnregisterClassW(class_name.as_ptr(), instance);
                        }
                        CONTEXT.with(|cell| {
                            cell.borrow_mut().take();
                        });
                        return;
                    }
                    let mut msg = MSG::default();
                    while unsafe { GetMessageW(&mut msg, ptr::null_mut(), 0, 0) } > 0 {
                        unsafe {
                            TranslateMessage(&msg);
                            DispatchMessageW(&msg);
                        }
                    }
                    unsafe {
                        Shell_NotifyIconW(NIM_DELETE, &nid);
                        UnregisterClassW(class_name.as_ptr(), instance);
                    }
                    CONTEXT.with(|cell| {
                        cell.borrow_mut().take();
                    });
                })?;

            match ready.recv_timeout(Duration::from_secs(5)) {
                Ok(Ok(hwnd_raw)) => Ok(Self {
                    hwnd_raw,
                    thread: Some(thread),
                    events,
                }),
                Ok(Err(error)) => {
                    let _ = thread.join();
                    Err(error)
                }
                Err(error) => Err(io::Error::other(format!("tray startup failed: {error}"))),
            }
        }

        pub fn try_recv(&self) -> Option<TrayEvent> {
            self.events.try_recv().ok()
        }
    }

    impl Drop for State {
        fn drop(&mut self) {
            if self.hwnd_raw != 0 {
                unsafe {
                    PostMessageW(self.hwnd_raw as HWND, WM_CLOSE, 0, 0);
                }
                self.hwnd_raw = 0;
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_tooltip_truncates_safely_with_nul_terminator() {
        let short = encode_tooltip_utf16("G-Earth Rust");
        assert_eq!(short[0], b'G' as u16);
        assert_eq!(short[12], 0);
        let long = encode_tooltip_utf16(&"A".repeat(200));
        assert_eq!(long[126], b'A' as u16);
        assert_eq!(long[127], 0);
    }
}
