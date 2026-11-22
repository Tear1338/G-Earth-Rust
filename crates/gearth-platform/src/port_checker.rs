//! Cross-platform detection of which process is holding a listening TCP port.
//! Ported from beta-29 `WindowsPortChecker.java` and `UnixPortChecker.java`.
use std::{
    io,
    process::{Command, Stdio},
};

#[cfg(any(windows, unix))]
fn run_command_stdout(program: &str, args: &[&str]) -> io::Result<String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    let output = cmd.output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parse Windows `netstat -ano` output for a `LISTENING` TCP socket on `port` and return its PID.
#[cfg(any(windows, test))]
pub fn parse_windows_netstat_pid(output: &str, port: u16) -> Option<u32> {
    let suffix = format!(":{port}");
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 || !parts[0].eq_ignore_ascii_case("TCP") || !parts[1].ends_with(&suffix)
        {
            continue;
        }
        if !parts[3].eq_ignore_ascii_case("LISTENING")
            && !parts[3].eq_ignore_ascii_case("ABHÖREN")
            && parts[2] != "0.0.0.0:0"
            && parts[2] != "[::]:0"
        {
            continue;
        }
        if let Some(pid) = parts[4].parse::<u32>().ok().filter(|&pid| pid != 0) {
            return Some(pid);
        }
    }
    None
}

/// Parse `tasklist /fi "PID eq <pid>" /nh /fo CSV` output to extract the executable name.
#[cfg(any(windows, test))]
pub fn parse_windows_tasklist_name(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('"') {
            continue;
        }
        let rest = &trimmed[1..];
        let end = rest.find('"')?;
        let name = rest[..end].trim();
        if !name.is_empty() {
            return Some(name.to_owned());
        }
    }
    None
}

/// Parse `lsof -nP -iTCP:<port> -sTCP:LISTEN -F pc` output into `"name (PID pid)"`.
#[cfg(any(unix, test))]
pub fn parse_unix_lsof_owner(output: &str) -> Option<String> {
    let mut pid: Option<String> = None;
    let mut cmd: Option<String> = None;
    for line in output.lines() {
        if let Some(val) = line
            .strip_prefix('p')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            pid = Some(val.to_owned());
        } else if let Some(val) = line
            .strip_prefix('c')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cmd = Some(val.to_owned());
        }
        if let (Some(c), Some(p)) = (&cmd, &pid) {
            return Some(format!("{c} (PID {p})"));
        }
    }
    cmd.or_else(|| pid.map(|p| format!("PID {p}")))
}

/// Return a human-readable description of the process listening on `port`, if detectable.
pub fn process_using_port(port: u16) -> Option<String> {
    #[cfg(windows)]
    {
        let netstat = run_command_stdout("netstat", &["-ano"]).ok()?;
        let pid = parse_windows_netstat_pid(&netstat, port)?;
        let filter = format!("PID eq {pid}");
        let name = run_command_stdout("tasklist", &["/fi", &filter, "/nh", "/fo", "CSV"])
            .ok()
            .and_then(|out| parse_windows_tasklist_name(&out));
        Some(match name {
            Some(exe) => format!("{exe} (PID {pid})"),
            None => format!("PID {pid}"),
        })
    }
    #[cfg(unix)]
    {
        let port_spec = format!("-iTCP:{port}");
        let output =
            run_command_stdout("lsof", &["-nP", &port_spec, "-sTCP:LISTEN", "-F", "pc"]).ok()?;
        parse_unix_lsof_owner(&output)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = port;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_netstat_and_tasklist_for_english_and_localized_os() {
        let netstat = "\
  Proto  Local Address          Foreign Address        State           PID\n\
  TCP    127.0.0.2:30000        0.0.0.0:0              LISTENING       4512\n\
  TCP    0.0.0.0:40001          0.0.0.0:0              ECOUTE          9876\n";
        assert_eq!(parse_windows_netstat_pid(netstat, 30000), Some(4512));
        assert_eq!(parse_windows_netstat_pid(netstat, 40001), Some(9876));
        assert_eq!(parse_windows_netstat_pid(netstat, 9092), None);

        let csv = "\"G-Earth.exe\",\"4512\",\"Console\",\"1\",\"84 120 Ko\"\r\n";
        assert_eq!(
            parse_windows_tasklist_name(csv).as_deref(),
            Some("G-Earth.exe")
        );
    }

    #[test]
    fn parses_unix_lsof_output() {
        let lsof = "p1234\ncjava\nn127.0.0.2:30000\n";
        assert_eq!(
            parse_unix_lsof_owner(lsof).as_deref(),
            Some("java (PID 1234)")
        );
        assert_eq!(parse_unix_lsof_owner(""), None);
    }
}
