//! Optional global scheduler shortcuts (Ctrl+Shift+0 through Ctrl+Shift+9).
//! Registration is owned by one dedicated worker thread on Windows, Linux (X11), and macOS.
use std::io;

pub struct GlobalHotkeys {
    available: [bool; 10],
    #[cfg(windows)]
    inner: windows::State,
    #[cfg(target_os = "linux")]
    inner: linux_x11::State,
    #[cfg(target_os = "macos")]
    inner: macos_tap::State,
}
impl GlobalHotkeys {
    /// Register Ctrl+Shift+0 through Ctrl+Shift+9. Keys already owned by other
    /// applications are reported in `available` and remain untouched.
    pub fn start(wake: impl Fn() + Send + 'static) -> io::Result<Self> {
        #[cfg(windows)]
        {
            let (inner, available) = windows::State::start(wake)?;
            Ok(Self { available, inner })
        }
        #[cfg(target_os = "linux")]
        {
            let (inner, available) = linux_x11::State::start(wake)?;
            Ok(Self { available, inner })
        }
        #[cfg(target_os = "macos")]
        {
            let (inner, available) = macos_tap::State::start(wake)?;
            Ok(Self { available, inner })
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            let _ = wake;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "global scheduler shortcuts are not available on this platform",
            ))
        }
    }
    pub fn available(&self) -> &[bool; 10] {
        &self.available
    }
    pub fn try_recv(&self) -> Option<usize> {
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        {
            self.inner.try_recv()
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            None
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn macos_digit_from_keycode(keycode: u16) -> Option<usize> {
    // macOS ANSI virtual keycodes (Carbon Events.h kVK_ANSI_0..kVK_ANSI_9).
    match keycode {
        29 => Some(0),
        18 => Some(1),
        19 => Some(2),
        20 => Some(3),
        21 => Some(4),
        23 => Some(5),
        22 => Some(6),
        26 => Some(7),
        28 => Some(8),
        25 => Some(9),
        _ => None,
    }
}

#[cfg(any(windows, target_os = "linux", test))]
mod registration {
    pub trait Registrar {
        fn register(&mut self, id: usize) -> bool;
        fn unregister(&mut self, id: usize);
    }
    pub struct Registration<R: Registrar> {
        registrar: R,
        available: [bool; 10],
    }
    impl<R: Registrar> Registration<R> {
        pub fn acquire(mut registrar: R) -> Self {
            let mut available = [false; 10];
            for (id, state) in available.iter_mut().enumerate() {
                *state = registrar.register(id);
            }
            Self {
                registrar,
                available,
            }
        }
        pub fn available(&self) -> [bool; 10] {
            self.available
        }
    }
    impl<R: Registrar> Drop for Registration<R> {
        fn drop(&mut self) {
            for (id, registered) in self.available.iter().copied().enumerate() {
                if registered {
                    self.registrar.unregister(id);
                }
            }
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::registration::{Registrar, Registration};
    use std::{
        io, ptr,
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        },
        thread::{self, JoinHandle},
        time::Duration,
    };
    use windows_sys::Win32::{
        System::Threading::GetCurrentThreadId,
        UI::{
            Input::KeyboardAndMouse::{
                RegisterHotKey, UnregisterHotKey, MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT, VK_0,
            },
            WindowsAndMessaging::{PeekMessageW, MSG, PM_REMOVE, WM_HOTKEY},
        },
    };

    struct NativeRegistrar;
    impl Registrar for NativeRegistrar {
        fn register(&mut self, id: usize) -> bool {
            // A null HWND associates the hotkey with this worker's message queue.
            unsafe {
                RegisterHotKey(
                    ptr::null_mut(),
                    id as i32,
                    MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT,
                    u32::from(VK_0) + id as u32,
                ) != 0
            }
        }
        fn unregister(&mut self, id: usize) {
            unsafe {
                UnregisterHotKey(ptr::null_mut(), id as i32);
            }
        }
    }

    pub struct State {
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
        events: mpsc::Receiver<usize>,
        #[cfg(test)]
        thread_id: u32,
    }
    impl State {
        pub fn start(wake: impl Fn() + Send + 'static) -> io::Result<(Self, [bool; 10])> {
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = stop.clone();
            let (events_tx, events) = mpsc::sync_channel(32);
            let (ready_tx, ready) = mpsc::sync_channel(1);
            let thread = thread::Builder::new()
                .name("gearth-hotkeys".into())
                .spawn(move || {
                    // Force creation of the worker's Windows message queue before signalling readiness.
                    let mut initial = MSG::default();
                    unsafe {
                        PeekMessageW(&mut initial, ptr::null_mut(), WM_HOTKEY, WM_HOTKEY, 0);
                    }
                    let registration = Registration::acquire(NativeRegistrar);
                    let available = registration.available();
                    let thread_id = unsafe { GetCurrentThreadId() };
                    if ready_tx.send((available, thread_id)).is_err()
                        || !available.iter().any(|value| *value)
                    {
                        return;
                    }
                    while !worker_stop.load(Ordering::Acquire) {
                        let mut message = MSG::default();
                        for _ in 0..128 {
                            let has_message = unsafe {
                                PeekMessageW(
                                    &mut message,
                                    ptr::null_mut(),
                                    WM_HOTKEY,
                                    WM_HOTKEY,
                                    PM_REMOVE,
                                )
                            } != 0;
                            if !has_message {
                                break;
                            }
                            let index = message.wParam;
                            if index < 10 && available[index] && events_tx.try_send(index).is_ok() {
                                wake();
                            }
                        }
                        thread::park_timeout(Duration::from_millis(20));
                    }
                    // Registration drops on the same thread which registered the keys.
                    drop(registration);
                })?;
            let (available, _thread_id) = match ready.recv_timeout(Duration::from_secs(5)) {
                Ok((available, thread_id)) if available.iter().any(|value| *value) => {
                    (available, thread_id)
                }
                Ok(_) => {
                    let _ = thread.join();
                    return Err(io::Error::other(
                        "all Ctrl+Shift+number shortcuts are unavailable",
                    ));
                }
                Err(error) => {
                    stop.store(true, Ordering::Release);
                    thread.thread().unpark();
                    // Detach on startup timeout rather than block the user interface.
                    return Err(io::Error::other(format!("shortcut setup failed: {error}")));
                }
            };
            Ok((
                Self {
                    stop,
                    thread: Some(thread),
                    events,
                    #[cfg(test)]
                    thread_id: _thread_id,
                },
                available,
            ))
        }
        pub fn try_recv(&self) -> Option<usize> {
            self.events.try_recv().ok()
        }
    }
    impl Drop for State {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                thread.thread().unpark();
                let _ = thread.join();
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows_sys::Win32::UI::WindowsAndMessaging::PostThreadMessageW;

        #[test]
        #[ignore = "temporarily registers global shortcuts; run only on an isolated Windows runner"]
        fn windows_hotkey_message_roundtrip() {
            let (wake_tx, wake_rx) = mpsc::channel();
            let (state, available) = State::start(move || {
                let _ = wake_tx.send(());
            })
            .unwrap();
            let index = available
                .iter()
                .position(|value| *value)
                .expect("at least one shortcut");
            assert_ne!(
                unsafe { PostThreadMessageW(state.thread_id, WM_HOTKEY, index, 0) },
                0
            );
            wake_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            assert_eq!(state.try_recv(), Some(index));
            drop(state);
            let mut registrar = NativeRegistrar;
            assert!(registrar.register(index), "shortcut was not released");
            registrar.unregister(index);
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_x11 {
    use super::registration::{Registrar, Registration};
    use std::{
        ffi::{c_char, c_int, c_uint, c_ulong, c_void},
        io, mem, ptr,
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        },
        thread::{self, JoinHandle},
        time::Duration,
    };

    const KEY_PRESS: c_int = 2;
    const SHIFT_MASK: c_uint = 1 << 0;
    const LOCK_MASK: c_uint = 1 << 1;
    const CONTROL_MASK: c_uint = 1 << 2;
    const MOD2_MASK: c_uint = 1 << 4;
    const GRAB_MODE_ASYNC: c_int = 1;
    const BASE_MODS: c_uint = CONTROL_MASK | SHIFT_MASK;
    const MOD_VARIANTS: [c_uint; 4] = [
        BASE_MODS,
        BASE_MODS | LOCK_MASK,
        BASE_MODS | MOD2_MASK,
        BASE_MODS | LOCK_MASK | MOD2_MASK,
    ];

    #[repr(C)]
    struct XKeyEvent {
        kind: c_int,
        serial: c_ulong,
        send_event: c_int,
        display: *mut c_void,
        window: c_ulong,
        root: c_ulong,
        subwindow: c_ulong,
        time: c_ulong,
        x: c_int,
        y: c_int,
        x_root: c_int,
        y_root: c_int,
        state: c_uint,
        keycode: c_uint,
        same_screen: c_int,
    }

    #[repr(C)]
    union XEvent {
        kind: c_int,
        key: mem::ManuallyDrop<XKeyEvent>,
        pad: [libc::c_long; 24],
    }

    struct X11Api {
        handle: *mut c_void,
        open_display: unsafe extern "C" fn(*const c_char) -> *mut c_void,
        close_display: unsafe extern "C" fn(*mut c_void) -> c_int,
        default_root_window: unsafe extern "C" fn(*mut c_void) -> c_ulong,
        keysym_to_keycode: unsafe extern "C" fn(*mut c_void, c_ulong) -> u8,
        grab_key:
            unsafe extern "C" fn(*mut c_void, c_int, c_uint, c_ulong, c_int, c_int, c_int) -> c_int,
        ungrab_key: unsafe extern "C" fn(*mut c_void, c_int, c_uint, c_ulong) -> c_int,
        pending: unsafe extern "C" fn(*mut c_void) -> c_int,
        next_event: unsafe extern "C" fn(*mut c_void, *mut XEvent) -> c_int,
        flush: unsafe extern "C" fn(*mut c_void) -> c_int,
    }

    impl X11Api {
        fn load() -> io::Result<Self> {
            // SAFETY: dlopen/dlsym on standard libX11.so.6 with NUL-terminated names.
            unsafe {
                let handle = libc::dlopen(c"libX11.so.6".as_ptr(), libc::RTLD_LAZY);
                if handle.is_null() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "global shortcuts on Linux require an X11 session with libX11.so.6",
                    ));
                }
                let sym = |name: &std::ffi::CStr| -> io::Result<*mut c_void> {
                    let ptr = libc::dlsym(handle, name.as_ptr());
                    if ptr.is_null() {
                        Err(io::Error::other(format!(
                            "missing libX11 symbol {}",
                            name.to_string_lossy()
                        )))
                    } else {
                        Ok(ptr)
                    }
                };
                let loaded = (|| -> io::Result<Self> {
                    Ok(Self {
                        handle,
                        open_display: mem::transmute::<
                            *mut c_void,
                            unsafe extern "C" fn(*const c_char) -> *mut c_void,
                        >(sym(c"XOpenDisplay")?),
                        close_display: mem::transmute::<
                            *mut c_void,
                            unsafe extern "C" fn(*mut c_void) -> c_int,
                        >(sym(c"XCloseDisplay")?),
                        default_root_window: mem::transmute::<
                            *mut c_void,
                            unsafe extern "C" fn(*mut c_void) -> c_ulong,
                        >(sym(c"XDefaultRootWindow")?),
                        keysym_to_keycode: mem::transmute::<
                            *mut c_void,
                            unsafe extern "C" fn(*mut c_void, c_ulong) -> u8,
                        >(sym(c"XKeysymToKeycode")?),
                        grab_key: mem::transmute::<
                            *mut c_void,
                            unsafe extern "C" fn(
                                *mut c_void,
                                c_int,
                                c_uint,
                                c_ulong,
                                c_int,
                                c_int,
                                c_int,
                            ) -> c_int,
                        >(sym(c"XGrabKey")?),
                        ungrab_key: mem::transmute::<
                            *mut c_void,
                            unsafe extern "C" fn(*mut c_void, c_int, c_uint, c_ulong) -> c_int,
                        >(sym(c"XUngrabKey")?),
                        pending: mem::transmute::<
                            *mut c_void,
                            unsafe extern "C" fn(*mut c_void) -> c_int,
                        >(sym(c"XPending")?),
                        next_event: mem::transmute::<
                            *mut c_void,
                            unsafe extern "C" fn(*mut c_void, *mut XEvent) -> c_int,
                        >(sym(c"XNextEvent")?),
                        flush: mem::transmute::<
                            *mut c_void,
                            unsafe extern "C" fn(*mut c_void) -> c_int,
                        >(sym(c"XFlush")?),
                    })
                })();
                if loaded.is_err() {
                    libc::dlclose(handle);
                }
                loaded
            }
        }
    }

    impl Drop for X11Api {
        fn drop(&mut self) {
            unsafe {
                libc::dlclose(self.handle);
            }
        }
    }

    struct X11Registrar<'a> {
        api: &'a X11Api,
        display: *mut c_void,
        root: c_ulong,
        keycodes: [u8; 10],
    }

    impl Registrar for X11Registrar<'_> {
        fn register(&mut self, id: usize) -> bool {
            let code = self.keycodes[id];
            if code == 0 {
                return false;
            }
            for mods in MOD_VARIANTS {
                unsafe {
                    (self.api.grab_key)(
                        self.display,
                        c_int::from(code),
                        mods,
                        self.root,
                        0,
                        GRAB_MODE_ASYNC,
                        GRAB_MODE_ASYNC,
                    );
                }
            }
            unsafe {
                (self.api.flush)(self.display);
            }
            true
        }

        fn unregister(&mut self, id: usize) {
            let code = self.keycodes[id];
            if code == 0 {
                return;
            }
            for mods in MOD_VARIANTS {
                unsafe {
                    (self.api.ungrab_key)(self.display, c_int::from(code), mods, self.root);
                }
            }
            unsafe {
                (self.api.flush)(self.display);
            }
        }
    }

    pub struct State {
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
        events: mpsc::Receiver<usize>,
    }

    impl State {
        pub fn start(wake: impl Fn() + Send + 'static) -> io::Result<(Self, [bool; 10])> {
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = stop.clone();
            let (events_tx, events) = mpsc::sync_channel(32);
            let (ready_tx, ready) = mpsc::sync_channel::<io::Result<[bool; 10]>>(1);
            let thread = thread::Builder::new()
                .name("gearth-hotkeys-x11".into())
                .spawn(move || {
                    let api = match X11Api::load() {
                        Ok(api) => api,
                        Err(error) => {
                            let _ = ready_tx.send(Err(error));
                            return;
                        }
                    };
                    let display = unsafe { (api.open_display)(ptr::null()) };
                    if display.is_null() {
                        let _ = ready_tx.send(Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "cannot open X11 display for global shortcuts",
                        )));
                        return;
                    }
                    let root = unsafe { (api.default_root_window)(display) };
                    let mut keycodes = [0u8; 10];
                    for (digit, slot) in keycodes.iter_mut().enumerate() {
                        // XK_0..=XK_9 are 0x0030..=0x0039.
                        *slot =
                            unsafe { (api.keysym_to_keycode)(display, 0x0030 + digit as c_ulong) };
                    }
                    let registration = Registration::acquire(X11Registrar {
                        api: &api,
                        display,
                        root,
                        keycodes,
                    });
                    let available = registration.available();
                    if ready_tx.send(Ok(available)).is_err() || !available.iter().any(|v| *v) {
                        drop(registration);
                        unsafe {
                            (api.close_display)(display);
                        }
                        return;
                    }
                    while !worker_stop.load(Ordering::Acquire) {
                        while unsafe { (api.pending)(display) } > 0 {
                            let mut event: XEvent = unsafe { mem::zeroed() };
                            unsafe {
                                (api.next_event)(display, &mut event);
                            }
                            if unsafe { event.kind } == KEY_PRESS {
                                let key = unsafe { &event.key };
                                if (key.state & BASE_MODS) == BASE_MODS {
                                    if let Some(index) =
                                        keycodes.iter().position(|&c| u32::from(c) == key.keycode)
                                    {
                                        if available[index] && events_tx.try_send(index).is_ok() {
                                            wake();
                                        }
                                    }
                                }
                            }
                        }
                        thread::park_timeout(Duration::from_millis(20));
                    }
                    drop(registration);
                    unsafe {
                        (api.close_display)(display);
                    }
                })?;

            match ready.recv_timeout(Duration::from_secs(5)) {
                Ok(Ok(available)) if available.iter().any(|v| *v) => Ok((
                    Self {
                        stop,
                        thread: Some(thread),
                        events,
                    },
                    available,
                )),
                Ok(Ok(_)) => {
                    let _ = thread.join();
                    Err(io::Error::other(
                        "all Ctrl+Shift+number shortcuts are unavailable",
                    ))
                }
                Ok(Err(error)) => {
                    let _ = thread.join();
                    Err(error)
                }
                Err(error) => {
                    stop.store(true, Ordering::Release);
                    thread.thread().unpark();
                    Err(io::Error::other(format!("shortcut setup failed: {error}")))
                }
            }
        }

        pub fn try_recv(&self) -> Option<usize> {
            self.events.try_recv().ok()
        }
    }

    impl Drop for State {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                thread.thread().unpark();
                let _ = thread.join();
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod macos_tap {
    use super::macos_digit_from_keycode;
    use std::{
        ffi::c_void,
        io, mem, ptr,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc, Arc,
        },
        thread::{self, JoinHandle},
        time::Duration,
    };

    const K_CG_SESSION_EVENT_TAP: u32 = 1;
    const K_CG_HEAD_INSERT_EVENT_TAP: u32 = 0;
    const K_CG_EVENT_TAP_OPTION_LISTEN_ONLY: u32 = 1;
    const K_CG_EVENT_KEY_DOWN: u32 = 10;
    const K_CG_KEYBOARD_EVENT_KEYCODE: u32 = 9;
    const K_CG_EVENT_FLAG_MASK_SHIFT: u64 = 1 << 17;
    const K_CG_EVENT_FLAG_MASK_CONTROL: u64 = 1 << 18;

    type TapCallback =
        unsafe extern "C" fn(*mut c_void, u32, *mut c_void, *mut c_void) -> *mut c_void;

    struct TapContext {
        tx: mpsc::SyncSender<usize>,
        wake: Box<dyn Fn() + Send>,
        get_flags: unsafe extern "C" fn(*mut c_void) -> u64,
        get_int_field: unsafe extern "C" fn(*mut c_void, u32) -> i64,
    }

    unsafe extern "C" fn tap_callback(
        _proxy: *mut c_void,
        event_type: u32,
        event: *mut c_void,
        user_info: *mut c_void,
    ) -> *mut c_void {
        if event_type == K_CG_EVENT_KEY_DOWN && !user_info.is_null() {
            let ctx = unsafe { &*(user_info as *const TapContext) };
            let flags = unsafe { (ctx.get_flags)(event) };
            let required = K_CG_EVENT_FLAG_MASK_CONTROL | K_CG_EVENT_FLAG_MASK_SHIFT;
            if (flags & required) == required {
                let keycode = unsafe { (ctx.get_int_field)(event, K_CG_KEYBOARD_EVENT_KEYCODE) };
                if let Ok(code) = u16::try_from(keycode) {
                    if let Some(digit) = macos_digit_from_keycode(code) {
                        if ctx.tx.try_send(digit).is_ok() {
                            (ctx.wake)();
                        }
                    }
                }
            }
        }
        event
    }

    pub struct State {
        stop: Arc<AtomicBool>,
        run_loop_ptr: Arc<AtomicUsize>,
        stop_fn: unsafe extern "C" fn(*mut c_void),
        thread: Option<JoinHandle<()>>,
        events: mpsc::Receiver<usize>,
    }

    impl State {
        pub fn start(wake: impl Fn() + Send + 'static) -> io::Result<(Self, [bool; 10])> {
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = stop.clone();
            let run_loop_ptr = Arc::new(AtomicUsize::new(0));
            let worker_loop = run_loop_ptr.clone();
            let (events_tx, events) = mpsc::sync_channel(32);
            let (ready_tx, ready) =
                mpsc::sync_channel::<io::Result<unsafe extern "C" fn(*mut c_void)>>(1);

            let thread = thread::Builder::new()
                .name("gearth-hotkeys-macos".into())
                .spawn(move || unsafe {
                    let app_svc = libc::dlopen(
                        c"/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices"
                            .as_ptr(),
                        libc::RTLD_LAZY,
                    );
                    let cf = libc::dlopen(
                        c"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
                            .as_ptr(),
                        libc::RTLD_LAZY,
                    );
                    if app_svc.is_null() || cf.is_null() {
                        if !app_svc.is_null() {
                            libc::dlclose(app_svc);
                        }
                        if !cf.is_null() {
                            libc::dlclose(cf);
                        }
                        let _ = ready_tx.send(Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "macOS ApplicationServices/CoreFoundation unavailable",
                        )));
                        return;
                    }
                    let ax_trusted: unsafe extern "C" fn() -> bool =
                        mem::transmute(libc::dlsym(app_svc, c"AXIsProcessTrusted".as_ptr()));
                    if !ax_trusted() {
                        libc::dlclose(app_svc);
                        libc::dlclose(cf);
                        let _ = ready_tx.send(Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "grant Accessibility permission in System Settings > Privacy & Security > Accessibility to enable global shortcuts",
                        )));
                        return;
                    }
                    let tap_create: unsafe extern "C" fn(
                        u32,
                        u32,
                        u32,
                        u64,
                        TapCallback,
                        *mut c_void,
                    ) -> *mut c_void =
                        mem::transmute(libc::dlsym(app_svc, c"CGEventTapCreate".as_ptr()));
                    let tap_enable: unsafe extern "C" fn(*mut c_void, bool) =
                        mem::transmute(libc::dlsym(app_svc, c"CGEventTapEnable".as_ptr()));
                    let get_flags: unsafe extern "C" fn(*mut c_void) -> u64 =
                        mem::transmute(libc::dlsym(app_svc, c"CGEventGetFlags".as_ptr()));
                    let get_int_field: unsafe extern "C" fn(*mut c_void, u32) -> i64 =
                        mem::transmute(libc::dlsym(
                            app_svc,
                            c"CGEventGetIntegerValueField".as_ptr(),
                        ));
                    let create_source: unsafe extern "C" fn(
                        *const c_void,
                        *mut c_void,
                        isize,
                    ) -> *mut c_void = mem::transmute(libc::dlsym(
                        cf,
                        c"CFMachPortCreateRunLoopSource".as_ptr(),
                    ));
                    let get_current: unsafe extern "C" fn() -> *mut c_void =
                        mem::transmute(libc::dlsym(cf, c"CFRunLoopGetCurrent".as_ptr()));
                    let add_source: unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_void) =
                        mem::transmute(libc::dlsym(cf, c"CFRunLoopAddSource".as_ptr()));
                    let run_loop: unsafe extern "C" fn() =
                        mem::transmute(libc::dlsym(cf, c"CFRunLoopRun".as_ptr()));
                    let stop_loop: unsafe extern "C" fn(*mut c_void) =
                        mem::transmute(libc::dlsym(cf, c"CFRunLoopStop".as_ptr()));
                    let cf_release: unsafe extern "C" fn(*mut c_void) =
                        mem::transmute(libc::dlsym(cf, c"CFRelease".as_ptr()));
                    let common_modes_sym = libc::dlsym(cf, c"kCFRunLoopCommonModes".as_ptr());
                    let common_modes = *(common_modes_sym as *const *const c_void);

                    let ctx = Box::new(TapContext {
                        tx: events_tx,
                        wake: Box::new(wake),
                        get_flags,
                        get_int_field,
                    });
                    let ctx_ptr = Box::into_raw(ctx);
                    let mask = 1u64 << K_CG_EVENT_KEY_DOWN;
                    let tap = tap_create(
                        K_CG_SESSION_EVENT_TAP,
                        K_CG_HEAD_INSERT_EVENT_TAP,
                        K_CG_EVENT_TAP_OPTION_LISTEN_ONLY,
                        mask,
                        tap_callback,
                        ctx_ptr.cast(),
                    );
                    if tap.is_null() {
                        drop(Box::from_raw(ctx_ptr));
                        libc::dlclose(app_svc);
                        libc::dlclose(cf);
                        let _ = ready_tx.send(Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "macOS refused to create global shortcut event tap",
                        )));
                        return;
                    }
                    let source = create_source(ptr::null(), tap, 0);
                    let current = get_current();
                    add_source(current, source, common_modes);
                    tap_enable(tap, true);
                    worker_loop.store(current as usize, Ordering::Release);
                    if ready_tx.send(Ok(stop_loop)).is_ok() && !worker_stop.load(Ordering::Acquire) {
                        run_loop();
                    }
                    worker_loop.store(0, Ordering::Release);
                    tap_enable(tap, false);
                    cf_release(source);
                    cf_release(tap);
                    drop(Box::from_raw(ctx_ptr));
                    libc::dlclose(app_svc);
                    libc::dlclose(cf);
                })?;

            match ready.recv_timeout(Duration::from_secs(5)) {
                Ok(Ok(stop_fn)) => Ok((
                    Self {
                        stop,
                        run_loop_ptr,
                        stop_fn,
                        thread: Some(thread),
                        events,
                    },
                    [true; 10],
                )),
                Ok(Err(error)) => {
                    let _ = thread.join();
                    Err(error)
                }
                Err(error) => {
                    stop.store(true, Ordering::Release);
                    Err(io::Error::other(format!("shortcut setup failed: {error}")))
                }
            }
        }

        pub fn try_recv(&self) -> Option<usize> {
            self.events.try_recv().ok()
        }
    }

    impl Drop for State {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let ptr = self.run_loop_ptr.load(Ordering::Acquire) as *mut c_void;
            if !ptr.is_null() {
                unsafe {
                    (self.stop_fn)(ptr);
                }
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        macos_digit_from_keycode,
        registration::{Registrar, Registration},
    };
    use std::sync::{Arc, Mutex};
    struct Fake {
        released: Arc<Mutex<Vec<usize>>>,
    }
    impl Registrar for Fake {
        fn register(&mut self, id: usize) -> bool {
            id != 3 && id != 8
        }
        fn unregister(&mut self, id: usize) {
            self.released.lock().unwrap().push(id);
        }
    }
    #[test]
    fn registers_available_keys_and_releases_only_owned_keys() {
        let released = Arc::new(Mutex::new(Vec::new()));
        {
            let registration = Registration::acquire(Fake {
                released: released.clone(),
            });
            assert!(!registration.available()[3]);
            assert!(!registration.available()[8]);
            assert!(registration.available()[0]);
            assert!(released.lock().unwrap().is_empty());
        }
        assert_eq!(*released.lock().unwrap(), vec![0, 1, 2, 4, 5, 6, 7, 9]);
    }

    #[test]
    fn macos_ansi_keycodes_map_all_ten_digits() {
        let expected = [29, 18, 19, 20, 21, 23, 22, 26, 28, 25];
        for (digit, code) in expected.into_iter().enumerate() {
            assert_eq!(macos_digit_from_keycode(code), Some(digit));
        }
        assert_eq!(macos_digit_from_keycode(0), None);
    }
}
