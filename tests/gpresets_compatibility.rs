//! Controlled startup check for the user's released G-Presets extension.
use gearth_rust::{
    extension_host::{ExtensionHost, HostEvent},
    packet::{Direction, Message, Packet},
};
use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        if self.0.parent() == Some(std::env::temp_dir().as_path())
            && self
                .0
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("gearth-gpresets-"))
        {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
#[ignore = "requires pinned G-Presets, JavaFX and a virtual display"]
fn released_gpresets_authenticates_to_the_rust_host() {
    let jar = PathBuf::from(std::env::var_os("GEARTH_GPRESETS_JAR").expect("pinned G-Presets JAR"));
    let modules = std::env::var_os("GEARTH_JAVAFX_MODULES").expect("JavaFX module directory");
    let mut random = [0; 16];
    getrandom::fill(&mut random).unwrap();
    let suffix = random
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let directory = Directory(std::env::temp_dir().join(format!("gearth-gpresets-{suffix}")));
    fs::create_dir(&directory.0).unwrap();
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    let filename = "GPresets-1.6.5.jar";
    let token = host.register_launch(filename).unwrap();
    let stdout = fs::File::create(directory.0.join("stdout.log")).unwrap();
    let stderr = fs::File::create(directory.0.join("stderr.log")).unwrap();
    let mut process = Process(
        Command::new("java")
            .current_dir(&directory.0)
            .arg(format!("-Duser.home={}", directory.0.display()))
            .arg("--module-path")
            .arg(modules)
            .arg("--add-modules=javafx.controls,javafx.fxml,javafx.web,javafx.swing")
            .arg("-jar")
            .arg(jar)
            .args([
                "-p",
                &host.address.port().to_string(),
                "-f",
                filename,
                "-c",
                &token,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut connected = false;
    while Instant::now() < deadline {
        if let Ok(HostEvent::Connected { info, .. }) =
            events.recv_timeout(Duration::from_millis(100))
        {
            if info.title == "G-Presets" {
                connected = true;
                break;
            }
        }
        if process.0.try_wait().unwrap().is_some() {
            break;
        }
    }
    if !connected {
        let log = fs::read_to_string(directory.0.join("stderr.log"))
            .unwrap_or_default()
            .replace(&token, "[token]");
        panic!(
            "G-Presets did not authenticate: {}",
            log.chars().take(8000).collect::<String>()
        );
    }
    // Exercise both IPC directions without connecting to a real hotel.
    for (index, direction) in [Direction::ToServer, Direction::ToClient]
        .into_iter()
        .enumerate()
    {
        let mut packet = Packet::new(77);
        packet.put_i32(123).unwrap();
        let mut message = Message {
            packet,
            direction,
            index: index as i32,
            blocked: false,
        };
        host.intercept(&mut message)
            .expect("G-Presets must return the intercepted fixture packet");
        assert_eq!(message.packet.header(), 77);
        assert_eq!(message.packet.read_i32().unwrap(), 123);
        assert!(!message.blocked);
    }
    host.stop();
}
