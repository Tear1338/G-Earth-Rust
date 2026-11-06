use gearth_rust::packet::{read_frame, write_frame, Packet};
use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    time::Duration,
};

struct TestProcess(Child);
impl Drop for TestProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn launch(developer: bool) -> (TestProcess, TcpStream, TcpStream) {
    let remote = TcpListener::bind("127.0.0.1:0").unwrap();
    let local = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = local.local_addr().unwrap();
    drop(local);
    let mut command = Command::new(env!("CARGO_BIN_EXE_gearth-rust"));
    command
        .args([
            "relay",
            &address.to_string(),
            &remote.local_addr().unwrap().to_string(),
            "--revision",
            "test-revision",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if developer {
        command.arg("--developer");
    }
    let mut process = TestProcess(command.spawn().unwrap());
    let mut stdout = BufReader::new(process.0.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert!(line.starts_with("Listening at"), "{line}");
    let client = TcpStream::connect(address).unwrap();
    let (server, _) = remote.accept().unwrap();
    loop {
        line.clear();
        assert_ne!(stdout.read_line(&mut line).unwrap(), 0);
        if line.starts_with("Connected(") {
            break;
        }
    }
    // Keep stdout open while the child writes its event log.
    process.0.stdout = Some(stdout.into_inner());
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    (process, client, server)
}

#[test]
fn cli_checks_observed_ids_by_direction_and_allows_developer_override() {
    let (mut process, mut client, mut server) = launch(false);
    let input = process.0.stdin.as_mut().unwrap();
    writeln!(input, "server {{h:321}}").unwrap();
    let mut errors = BufReader::new(process.0.stderr.take().unwrap());
    let mut error = String::new();
    errors.read_line(&mut error).unwrap();
    assert!(
        error.contains("packet ID 321 has not been observed"),
        "{error}"
    );

    write_frame(&mut client, &Packet::new(321)).unwrap();
    assert_eq!(read_frame(&mut server).unwrap().header(), 321);
    writeln!(input, "client {{h:321}}").unwrap();
    error.clear();
    errors.read_line(&mut error).unwrap();
    assert!(
        error.contains("packet ID 321 has not been observed"),
        "{error}"
    );
    writeln!(input, "server {{h:321}}").unwrap();
    assert_eq!(read_frame(&mut server).unwrap().header(), 321);
    drop(process);

    let (mut process, _client, mut server) = launch(true);
    writeln!(process.0.stdin.as_mut().unwrap(), "server {{h:322}}").unwrap();
    assert_eq!(read_frame(&mut server).unwrap().header(), 322);
}
