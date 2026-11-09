use gearth_rust::{
    extension_host::{ConnectionDetails, ExtensionHost},
    gpython::{self, PythonConsole},
    packet::{Direction, Message, Packet},
    packet_info::{PacketInfo, PacketInfoManager},
};
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gearth-gpython-install-{}",
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if let (Ok(path), Ok(temp)) = (self.0.canonicalize(), std::env::temp_dir().canonicalize()) {
            if path.parent() == Some(temp.as_path())
                && path.file_name().is_some_and(|name| {
                    name.to_string_lossy()
                        .starts_with("gearth-gpython-install-")
                })
            {
                let _ = std::fs::remove_dir_all(path);
            }
        }
    }
}
fn isolated_python(directory: &Path) -> PathBuf {
    directory.join(if cfg!(windows) {
        "Scripts/python.exe"
    } else {
        "bin/python"
    })
}
fn create_isolated_python(directory: &Path) -> PathBuf {
    assert!(Command::new("python")
        .args(["-m", "venv"])
        .arg(directory)
        .status()
        .unwrap()
        .success());
    isolated_python(directory)
}
#[test]
#[ignore = "creates an isolated venv; executed in gpython CI"]
fn pre_cancelled_installer_does_not_modify_the_environment() {
    let directory = Directory::new();
    let python = create_isolated_python(&directory.0);
    let error = gpython::install_dependencies(&python, &AtomicBool::new(true)).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
    assert_eq!(
        gpython::probe(&python).unwrap().packages.get("g-python"),
        Some(&None)
    );
}
#[test]
#[ignore = "creates an isolated venv and downloads the validated package set; executed in gpython CI"]
fn installer_repairs_an_isolated_python_environment() {
    let directory = Directory::new();
    let python = create_isolated_python(&directory.0);
    let report = gpython::install_dependencies(&python, &AtomicBool::new(false)).unwrap();
    assert!(report.missing().is_empty(), "{:?}", report.missing());
    assert_eq!(
        report.packages.get("g-python").and_then(Option::as_deref),
        Some("0.1.6")
    );
}
#[test]
#[ignore = "requires the pinned G-Python package and Jupyter kernel; executed in gpython CI"]
fn original_gpython_kernel_authenticates_and_injects_through_the_rust_host() {
    let python = Path::new("python");
    let report = gpython::probe(python).unwrap();
    assert!(report.missing().is_empty(), "{:?}", report.missing());
    let (host, host_events) =
        ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    host.start_connection(ConnectionDetails {
        host: "fixture.invalid".into(),
        port: 1234,
        version: "TEST".into(),
        identifier: "fixture".into(),
        client_type: "FLASH".into(),
        packets: PacketInfoManager::new(
            "TEST",
            vec![
                (77, "TestOutgoing", Direction::ToServer),
                (78, "TestIncoming", Direction::ToClient),
                (91, "TestInjection", Direction::ToServer),
            ]
            .into_iter()
            .map(|(header, name, direction)| PacketInfo {
                header,
                name: Some(name.into()),
                hash: None,
                structure: Some("i".into()),
                direction,
                source: "fixture".into(),
            })
            .collect(),
        ),
    })
    .unwrap();
    let mut console =
        PythonConsole::launch_fixture(python, &host, include_str!("gpython_kernel_fixture.py"))
            .unwrap();
    let deadline = Instant::now() + Duration::from_secs(50);
    let mut injected_server = false;
    let mut injected_client = false;
    let mut finished = false;
    let mut ready = false;
    let mut extension_id = None;
    let mut exit_deadline = None;
    loop {
        for line in console.poll() {
            assert!(!line.starts_with("GEARTH_PYTHON_ERROR"), "{line}");
        }
        ready |= console.ready;
        for event in host_events.try_iter() {
            if let gearth_rust::extension_host::HostEvent::Connected { id, .. } = event {
                extension_id = Some(id);
            }
        }
        for (direction, mut packet) in host.take_injections() {
            match packet.header() {
                91 => {
                    assert!(!injected_server);
                    assert_eq!(direction, Direction::ToServer);
                    assert_eq!(packet.read_i32().unwrap(), 17);
                    injected_server = true;
                    for (header, value, direction) in [
                        (77, 5, Direction::ToServer),
                        (77, 13, Direction::ToServer),
                        (78, 7, Direction::ToClient),
                    ] {
                        let mut packet = Packet::new(header);
                        packet.put_i32(value).unwrap();
                        let mut message = Message {
                            packet,
                            direction,
                            index: value,
                            blocked: false,
                        };
                        host.intercept(&mut message).unwrap();
                        assert_eq!(message.blocked, value == 13);
                        if !message.blocked {
                            assert_eq!(message.packet.read_i32().unwrap(), value + 100);
                        }
                    }
                }
                92 => {
                    assert_eq!(direction, Direction::ToClient);
                    assert_eq!(packet.read_i32().unwrap(), 18);
                    injected_client = true;
                }
                93 => {
                    assert_eq!(packet.read_i32().unwrap(), 3);
                    let mut acknowledgment = Packet::new(78);
                    acknowledgment.put_i32(99).unwrap();
                    let mut message = Message {
                        packet: acknowledgment,
                        direction: Direction::ToClient,
                        index: 99,
                        blocked: false,
                    };
                    host.intercept(&mut message).unwrap();
                    assert!(!message.blocked);
                    assert_eq!(message.packet.read_i32().unwrap(), 199);
                    host.click(extension_id.expect("connected G-Python extension id"))
                        .unwrap();
                    finished = true;
                }
                header => panic!("Unexpected Python injection {header}"),
            }
        }
        if let Some(status) = console.exited().unwrap() {
            assert!(status.success(), "Python kernel fixture failed: {status}");
            if ready && injected_server && injected_client && finished {
                break;
            }
            // Output and IPC are collected by other threads, which may still have
            // events to deliver after the child process has exited.
            let grace =
                exit_deadline.get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
            assert!(Instant::now() < *grace, "Python exited before all events arrived: ready={ready}, server={injected_server}, client={injected_client}, finished={finished}");
        }
        assert!(Instant::now() < deadline, "Python kernel fixture timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
    console.stop();
    host.stop();
}

#[test]
#[ignore = "requires Python/Jupyter/psutil; executed in gpython CI on Linux and Windows"]
fn stopping_a_console_terminates_its_kernel() {
    let python = Path::new("python");
    let (host, events) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    let mut console = PythonConsole::launch_fixture(
        python,
        &host,
        "import os, time\nwrite_to_console('kernel-pid=' + str(os.getpid()))\ntime.sleep(60)\n",
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(40);
    // The real kernel reports its PID through authenticated extension IPC.
    let pid = loop {
        for line in console.poll() {
            assert!(!line.starts_with("GEARTH_PYTHON_ERROR"), "{line}");
        }
        let found = events.try_iter().find_map(|event| match event {
            gearth_rust::extension_host::HostEvent::Console { text, .. } => text
                .split_once("kernel-pid=")
                .and_then(|(_, pid)| pid.parse::<u32>().ok()),
            _ => None,
        });
        if let Some(pid) = found {
            break pid;
        }
        assert!(Instant::now() < deadline, "kernel did not start");
        std::thread::sleep(Duration::from_millis(10));
    };
    console.stop();
    host.stop();
    let check="import sys,time,psutil\npid=int(sys.argv[1])\nend=time.monotonic()+12\nwhile time.monotonic()<end:\n try:\n  p=psutil.Process(pid)\n  if not p.is_running() or p.status()==psutil.STATUS_ZOMBIE: break\n except psutil.NoSuchProcess: break\n time.sleep(.1)\nelse: raise SystemExit('kernel survived console shutdown')\n";
    assert!(Command::new(python)
        .args(["-c", check, &pid.to_string()])
        .status()
        .unwrap()
        .success());
}

#[test]
#[ignore = "requires Python/Jupyter/PyQt5; executed in gpython CI"]
fn actual_qtconsole_starts_in_the_selected_python_environment() {
    let (host, _) = ExtensionHost::start("127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
    let mut console = PythonConsole::launch_offscreen_fixture(Path::new("python"), &host).unwrap();
    let deadline = Instant::now() + Duration::from_secs(40);
    while !console.window_running {
        for line in console.poll() {
            assert!(!line.starts_with("GEARTH_PYTHON_ERROR"), "{line}");
        }
        assert!(
            console.exited().unwrap().is_none(),
            "QtConsole exited during startup"
        );
        assert!(Instant::now() < deadline, "QtConsole startup timed out");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(console.ready);
    console.stop();
    host.stop();
}
