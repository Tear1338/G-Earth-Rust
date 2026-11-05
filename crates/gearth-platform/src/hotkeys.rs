//! Optional global scheduler shortcuts. Registration is owned by one thread.
use std::io;

pub struct GlobalHotkeys {
    available: [bool; 10],
    #[cfg(windows)]
    inner: windows::State,
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
        #[cfg(not(windows))]
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

#[cfg(test)]
mod tests {
    use super::registration::{Registrar, Registration};
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
}
