//! G-Python/Jupyter launch orchestration; Python and Qt remain external runtimes.
use crate::extension_host::ExtensionHost;
use gearth_platform::ProcessTree;
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
const BOOTSTRAP: &str = include_str!("../resources/g_python/bootstrap.py");
#[derive(Debug, Clone)]
pub struct Dependencies {
    pub python: Vec<u32>,
    pub packages: BTreeMap<String, Option<String>>,
    pub issues: Vec<String>,
}
impl Dependencies {
    pub fn missing(&self) -> Vec<String> {
        let mut missing = self
            .packages
            .iter()
            .filter(|(_, version)| version.is_none())
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        missing.extend(self.issues.iter().cloned());
        if self.python.as_slice() < [3, 11].as_slice() {
            missing.push("Python >= 3.11".into());
        }
        if self
            .packages
            .get("g-python")
            .and_then(|version| version.as_ref())
            .is_some_and(|version| {
                crate::extension_store::compare_versions(version, "0.1.6").is_lt()
            })
        {
            missing.push("g-python >= 0.1.6".into());
        }
        missing
    }
}
pub fn probe(python: &Path) -> io::Result<Dependencies> {
    let mut command = Command::new(python);
    command
        .args(["-u", "-c", BOOTSTRAP, "probe"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    ProcessTree::prepare(&mut command);
    let mut child = command.spawn()?;
    let tree = match ProcessTree::attach(&child) {
        Ok(tree) => tree,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            drop(tree);
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Python dependency check timed out",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    if !status.success() {
        return Err(io::Error::other("Python dependency check failed"));
    }
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .take(65537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(io::Error::other("Python dependency report exceeds limit"));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let python = serde_json::from_value(value["python"].clone()).map_err(io::Error::other)?;
    let packages = serde_json::from_value(value["packages"].clone()).map_err(io::Error::other)?;
    let issues = serde_json::from_value(value["issues"].clone()).map_err(io::Error::other)?;
    drop(tree);
    Ok(Dependencies {
        python,
        packages,
        issues,
    })
}
/// Installs the validated package set only after an explicit UI action.
/// The selected environment can be partially modified if pip is interrupted.
pub fn install_dependencies(python: &Path, cancel: &AtomicBool) -> io::Result<Dependencies> {
    if cancel.load(Ordering::Relaxed) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "Python package installation cancelled; the selected environment was not changed",
        ));
    }
    let before = probe(python)?;
    if before.python.as_slice() < [3, 11].as_slice() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Python >= 3.11 is required; the selected environment was not changed",
        ));
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "Python package installation cancelled; the selected environment was not changed",
        ));
    }
    let mut command = Command::new(python);
    command
        .args([
            "-I",
            "-m",
            "pip",
            "--isolated",
            "--disable-pip-version-check",
            "install",
            "--no-input",
            "--only-binary=:all:",
        ])
        .args([
            "g-python==0.1.6",
            "qtconsole",
            "PyQt5",
            "jupyter-console",
            "jupyter-client",
            "ipykernel",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    ProcessTree::prepare(&mut command);
    let mut child = command.spawn()?;
    let tree = match ProcessTree::attach(&child) {
        Ok(tree) => tree,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let deadline = Instant::now() + Duration::from_secs(300);
    let status = loop {
        if cancel.load(Ordering::Relaxed) {
            drop(tree);
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Python package installation cancelled; run the dependency check before retrying",
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                drop(tree);
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            drop(tree);
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Python package installation timed out; run the dependency check before retrying",
            ));
        }
        thread::sleep(Duration::from_millis(50));
    };
    drop(tree);
    if !status.success() {
        return Err(io::Error::other(format!(
            "Python package installation failed with status {status}; use the displayed terminal command for detailed logs"
        )));
    }
    probe(python)
}
fn init_script(port: u16, filename: &str, cookie: &str, title: &str) -> String {
    let info = serde_json::json!({"title":title,"description":"G-Python scripting console","version":"1.0","author":""});
    let args = serde_json::json!([
        "--port",
        port.to_string(),
        "--filename",
        filename,
        "--auth-token",
        cookie
    ]);
    format!("from time import sleep\nfrom g_python.gextension import Extension\nfrom g_python.hmessage import Direction, HMessage\nfrom g_python.hpacket import HPacket\nfrom g_python import hparsers, hunityparsers, htools, hunitytools\next = Extension({info}, {args}, {{'can_leave': False}}, silent=True)\next.start()\nHPacket.default_extension = ext\nsend_to_client = ext.send_to_client\nsend_to_server = ext.send_to_server\non_event = ext.on_event\nintercept = ext.intercept\nstart = ext.start\nstop = ext.stop\nis_closed = ext.is_closed\nwrite_to_console = ext.write_to_console\nrequest_flags = ext.request_flags\n")
}
pub struct PythonConsole {
    child: Option<Child>,
    input: Option<ChildStdin>,
    tree: Option<ProcessTree>,
    events: Receiver<String>,
    pub ready: bool,
    pub window_running: bool,
}
impl PythonConsole {
    pub fn launch(python: &Path, host: &Arc<ExtensionHost>, title: &str) -> io::Result<Self> {
        Self::launch_inner(python, host, title, None, false)
    }
    /// Controlled fixture mode exercises the real kernel/API without opening a GUI.
    pub fn launch_fixture(
        python: &Path,
        host: &Arc<ExtensionHost>,
        script: &str,
    ) -> io::Result<Self> {
        Self::launch_inner(python, host, "G-Python fixture", Some(script), false)
    }
    /// Runs the actual Qt process with Qt's offscreen platform for CI smoke checks.
    pub fn launch_offscreen_fixture(python: &Path, host: &Arc<ExtensionHost>) -> io::Result<Self> {
        Self::launch_inner(python, host, "G-Python Qt fixture", None, true)
    }
    fn launch_inner(
        python: &Path,
        host: &Arc<ExtensionHost>,
        title: &str,
        fixture: Option<&str>,
        offscreen: bool,
    ) -> io::Result<Self> {
        if title.len() > 256 || title.contains('\0') {
            return Err(io::Error::other("invalid console title"));
        }
        let filename = "g-python-console";
        let cookie = host.register_launch(filename)?;
        let config = serde_json::json!({"cookie":cookie,"init":init_script(host.address.port(),filename,&cookie,title),"headless":fixture.is_some(),"fixture":fixture.unwrap_or("")});
        let mut command = Command::new(python);
        command
            .args(["-u", "-c", BOOTSTRAP])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if offscreen {
            command.env("QT_QPA_PLATFORM", "offscreen");
        }
        ProcessTree::prepare(&mut command);
        let mut child = command.spawn()?;
        let tree = match ProcessTree::attach(&child) {
            Ok(tree) => tree,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let mut input = child.stdin.take().unwrap();
        if let Err(error) = writeln!(input, "{config}") {
            drop(tree);
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let mut output = child.stdout.take().unwrap();
        let (send, events) = mpsc::sync_channel(64);
        thread::spawn(move || {
            let mut buffer = [0; 4096];
            let mut pending = String::new();
            while let Ok(count) = output.read(&mut buffer) {
                if count == 0 {
                    break;
                }
                pending.push_str(&String::from_utf8_lossy(&buffer[..count]));
                while let Some(index) = pending.find('\n') {
                    let line = pending.drain(..=index).collect::<String>();
                    let _ = send.try_send(line.trim().to_owned());
                }
                if pending.len() > 8192 {
                    pending.clear();
                }
            }
        });
        Ok(Self {
            child: Some(child),
            input: Some(input),
            tree: Some(tree),
            events,
            ready: false,
            window_running: false,
        })
    }
    pub fn poll(&mut self) -> Vec<String> {
        self.events
            .try_iter()
            .map(|line| {
                if line == "GEARTH_PYTHON_READY" {
                    self.ready = true;
                }
                if line == "GEARTH_QT_RUNNING" {
                    self.window_running = true;
                }
                line
            })
            .collect()
    }
    pub fn exited(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Python console is stopped"))?
            .try_wait()
    }
    pub fn stop(&mut self) {
        if let Some(mut input) = self.input.take() {
            let _ = writeln!(input, "stop");
        }
        if let Some(mut child) = self.child.take() {
            let tree = self.tree.take();
            // Keep the UI responsive while Jupyter closes sockets and removes its connection file.
            thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(3);
                while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(20));
                }
                drop(tree);
                let _ = child.kill();
                let _ = child.wait();
            });
        }
    }
}
impl Drop for PythonConsole {
    fn drop(&mut self) {
        self.stop();
    }
}
