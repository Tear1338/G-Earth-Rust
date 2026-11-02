//! Native Raw-IP redirection commands, isolated behind an injectable runner.
use std::{
    ffi::{OsStr, OsString},
    io,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub trait IpMapper: Send {
    fn enable(&mut self) -> io::Result<()>;
    fn add_mapping(
        &mut self,
        ip: Ipv4Addr,
        listen_port: u16,
        intercept_port: u16,
    ) -> io::Result<()>;
    fn delete_mapping(
        &mut self,
        ip: Ipv4Addr,
        listen_port: u16,
        intercept_port: u16,
    ) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MapperKind {
    Windows,
    Linux,
    MacOs,
}

#[derive(Debug, PartialEq, Eq)]
struct CommandSpec {
    program: PathBuf,
    args: Vec<OsString>,
}

trait CommandRunner: Send {
    fn run(&mut self, command: &CommandSpec) -> io::Result<()>;
}

struct SystemCommandRunner;
impl CommandRunner for SystemCommandRunner {
    fn run(&mut self, command: &CommandSpec) -> io::Result<()> {
        let mut process = Command::new(&command.program);
        process
            .args(&command.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            process.creation_flags(0x08000000);
        }
        let output = process.output()?;
        if output.status.success() {
            return Ok(());
        }
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim().chars().take(2048).collect::<String>();
        Err(io::Error::other(format!(
            "{} failed with status {}{}",
            command.program.display(),
            output.status,
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        )))
    }
}

struct NativeIpMapper {
    kind: MapperKind,
    netsh: PathBuf,
    runner: Box<dyn CommandRunner>,
}
impl NativeIpMapper {
    fn new(kind: MapperKind, runner: Box<dyn CommandRunner>) -> Self {
        let netsh = if kind == MapperKind::Windows {
            Path::new(&std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
                .join("System32")
                .join("netsh.exe")
        } else {
            PathBuf::new()
        };
        Self {
            kind,
            netsh,
            runner,
        }
    }
    fn command(&self, program: &Path, args: &[&OsStr]) -> CommandSpec {
        CommandSpec {
            program: program.into(),
            args: args.iter().map(|arg| (*arg).into()).collect(),
        }
    }
    fn mapping_command(&self, ip: Ipv4Addr, add: bool) -> io::Result<CommandSpec> {
        let ip = ip.to_string();
        let ip = OsStr::new(&ip);
        Ok(match self.kind {
            MapperKind::Windows => {
                let action = if add { "add" } else { "delete" };
                let mut command = self.command(
                    &self.netsh,
                    &[
                        OsStr::new("interface"),
                        OsStr::new("ip"),
                        OsStr::new(action),
                        OsStr::new("address"),
                        OsStr::new("Loopback"),
                        ip,
                    ],
                );
                if add {
                    command.args.push("255.255.255.255".into());
                }
                command
            }
            MapperKind::Linux => {
                let action = if add { "-A" } else { "-D" };
                self.command(
                    Path::new("iptables"),
                    &[
                        OsStr::new("-t"),
                        OsStr::new("nat"),
                        OsStr::new(action),
                        OsStr::new("OUTPUT"),
                        OsStr::new("-p"),
                        OsStr::new("tcp"),
                        OsStr::new("-d"),
                        ip,
                        OsStr::new("-j"),
                        OsStr::new("DNAT"),
                        OsStr::new("--to-destination"),
                        OsStr::new("127.0.0.1"),
                    ],
                )
            }
            MapperKind::MacOs => self.command(
                Path::new("ifconfig"),
                &[
                    OsStr::new("lo0"),
                    OsStr::new(if add { "alias" } else { "-alias" }),
                    ip,
                ],
            ),
        })
    }
}
impl IpMapper for NativeIpMapper {
    fn enable(&mut self) -> io::Result<()> {
        if self.kind == MapperKind::Windows {
            self.runner.run(&self.command(
                &self.netsh,
                &[
                    OsStr::new("interface"),
                    OsStr::new("ip"),
                    OsStr::new("set"),
                    OsStr::new("dns"),
                    OsStr::new("1"),
                    OsStr::new("dhcp"),
                ],
            ))?;
        }
        Ok(())
    }
    fn add_mapping(
        &mut self,
        ip: Ipv4Addr,
        _listen_port: u16,
        _intercept_port: u16,
    ) -> io::Result<()> {
        self.runner.run(&self.mapping_command(ip, true)?)
    }
    fn delete_mapping(
        &mut self,
        ip: Ipv4Addr,
        _listen_port: u16,
        _intercept_port: u16,
    ) -> io::Result<()> {
        self.runner.run(&self.mapping_command(ip, false)?)
    }
}

pub fn system_ip_mapper() -> io::Result<Box<dyn IpMapper>> {
    let kind = if cfg!(windows) {
        MapperKind::Windows
    } else if cfg!(target_os = "macos") {
        MapperKind::MacOs
    } else if cfg!(unix) {
        MapperKind::Linux
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Raw-IP redirection is unsupported on this operating system",
        ));
    };
    Ok(Box::new(NativeIpMapper::new(
        kind,
        Box::new(SystemCommandRunner),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct RecordingRunner {
        commands: Arc<Mutex<Vec<CommandSpec>>>,
        fail: bool,
    }
    impl CommandRunner for RecordingRunner {
        fn run(&mut self, command: &CommandSpec) -> io::Result<()> {
            self.commands.lock().unwrap().push(CommandSpec {
                program: command.program.clone(),
                args: command.args.clone(),
            });
            if self.fail {
                Err(io::Error::other("fixture failure"))
            } else {
                Ok(())
            }
        }
    }
    fn strings(command: &CommandSpec) -> Vec<String> {
        command
            .args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }
    #[test]
    fn windows_commands_match_the_original_mapper() {
        let runner = RecordingRunner::default();
        let commands = runner.commands.clone();
        let mut mapper = NativeIpMapper::new(MapperKind::Windows, Box::new(runner));
        mapper.enable().unwrap();
        let ip = Ipv4Addr::new(192, 0, 2, 10);
        mapper.add_mapping(ip, 30000, 30000).unwrap();
        mapper.delete_mapping(ip, 30000, 30000).unwrap();
        let commands = commands.lock().unwrap();
        assert_eq!(commands.len(), 3);
        assert!(commands[0].program.ends_with("netsh.exe"));
        assert_eq!(
            strings(&commands[0]),
            ["interface", "ip", "set", "dns", "1", "dhcp"]
        );
        assert_eq!(
            strings(&commands[1]),
            [
                "interface",
                "ip",
                "add",
                "address",
                "Loopback",
                "192.0.2.10",
                "255.255.255.255"
            ]
        );
        assert_eq!(
            strings(&commands[2]),
            [
                "interface",
                "ip",
                "delete",
                "address",
                "Loopback",
                "192.0.2.10"
            ]
        );
    }
    #[test]
    fn linux_and_mac_commands_match_the_original_mappers() {
        let runner = RecordingRunner::default();
        let commands = runner.commands.clone();
        let mut linux = NativeIpMapper::new(MapperKind::Linux, Box::new(runner.clone()));
        linux.enable().unwrap();
        let ip = Ipv4Addr::new(192, 0, 2, 20);
        linux.add_mapping(ip, 30000, 30000).unwrap();
        linux.delete_mapping(ip, 30000, 30000).unwrap();
        let mut mac = NativeIpMapper::new(MapperKind::MacOs, Box::new(runner));
        mac.add_mapping(ip, 30000, 30000).unwrap();
        mac.delete_mapping(ip, 30000, 30000).unwrap();
        let commands = commands.lock().unwrap();
        assert_eq!(commands.len(), 4);
        assert_eq!(commands[0].program, Path::new("iptables"));
        assert_eq!(
            strings(&commands[0]),
            [
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "-d",
                "192.0.2.20",
                "-j",
                "DNAT",
                "--to-destination",
                "127.0.0.1"
            ]
        );
        assert_eq!(strings(&commands[1])[2], "-D");
        assert_eq!(strings(&commands[2]), ["lo0", "alias", "192.0.2.20"]);
        assert_eq!(strings(&commands[3]), ["lo0", "-alias", "192.0.2.20"]);
    }
    #[test]
    fn command_failures_are_not_silently_ignored() {
        let runner = RecordingRunner {
            fail: true,
            ..Default::default()
        };
        let mut mapper = NativeIpMapper::new(MapperKind::Linux, Box::new(runner));
        assert!(mapper
            .add_mapping(Ipv4Addr::new(192, 0, 2, 30), 30000, 30000)
            .is_err());
    }
}
