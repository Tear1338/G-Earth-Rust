//! macOS and Linux system-proxy lifecycle and user root-CA helpers, isolated behind an injectable runner.
use sha1::{Digest, Sha1};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::{Command, Stdio};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[cfg(any(target_os = "macos", test))]
const BYPASS_DOMAINS: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "::1",
    "*.local",
    "discord.com",
    "*.discord.com",
    "discordapp.com",
    "*.discordapp.com",
    "github.com",
    "*.github.com",
    "*.openai.com",
    "*.chatgpt.com",
];

#[cfg(any(target_os = "linux", test))]
const LINUX_IGNORE_HOSTS: &str = "['localhost', '127.0.0.0/8', '::1', 'discord.com', '*.discord.com', 'discordapp.com', '*.discordapp.com', 'github.com', '*.github.com', '*.openai.com', '*.chatgpt.com']";
const MAX_JOURNAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_CERT_BYTES: usize = 65536;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommandSpec {
    program: PathBuf,
    args: Vec<OsString>,
}

impl CommandSpec {
    fn new(program: impl Into<PathBuf>, args: &[&str]) -> Self {
        Self {
            program: program.into(),
            args: args.iter().map(OsString::from).collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommandOutput {
    success: bool,
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

trait CommandRunner: Send {
    fn run(&mut self, spec: &CommandSpec) -> io::Result<CommandOutput>;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
struct SystemCommandRunner;
#[cfg(any(target_os = "macos", target_os = "linux"))]
impl CommandRunner for SystemCommandRunner {
    fn run(&mut self, spec: &CommandSpec) -> io::Result<CommandOutput> {
        let output = Command::new(&spec.program)
            .args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        Ok(CommandOutput {
            success: output.status.success(),
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

fn require_success(spec: &CommandSpec, output: CommandOutput) -> io::Result<String> {
    if output.success {
        return Ok(output.stdout);
    }
    let detail = output.stderr.trim();
    let detail: String = detail.chars().take(1024).collect();
    Err(io::Error::other(if detail.is_empty() {
        format!(
            "{} failed with status {:?}",
            spec.program.display(),
            output.code
        )
    } else {
        format!(
            "{} failed with status {:?}: {detail}",
            spec.program.display(),
            output.code
        )
    }))
}

fn run_checked(runner: &mut dyn CommandRunner, spec: &CommandSpec) -> io::Result<String> {
    let output = runner.run(spec)?;
    require_success(spec, output)
}

pub(crate) fn thumbprint_upper(der: &[u8]) -> io::Result<String> {
    if der.is_empty() || der.len() > MAX_CERT_BYTES {
        return Err(io::Error::other("invalid public certificate size"));
    }
    Ok(Sha1::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect())
}

fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension("pending");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend((value.len() as u32).to_le_bytes());
    out.extend(value);
}

fn push_str(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
}

fn read_bytes<'a>(tail: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    let len = tail
        .get(..4)
        .ok_or_else(|| io::Error::other("truncated saved proxy state"))?;
    let size = u32::from_le_bytes(len.try_into().unwrap()) as usize;
    *tail = &tail[4..];
    let (value, rest) = tail
        .split_at_checked(size)
        .ok_or_else(|| io::Error::other("truncated saved proxy value"))?;
    *tail = rest;
    Ok(value)
}

fn read_str(tail: &mut &[u8]) -> io::Result<String> {
    String::from_utf8(read_bytes(tail)?.to_vec())
        .map_err(|_| io::Error::other("invalid UTF-8 in saved proxy state"))
}

fn read_u16(tail: &mut &[u8]) -> io::Result<u16> {
    let raw = read_bytes(tail)?;
    let arr: [u8; 2] = raw
        .try_into()
        .map_err(|_| io::Error::other("invalid saved proxy port"))?;
    Ok(u16::from_le_bytes(arr))
}

#[cfg(any(target_os = "macos", test))]
fn read_bool(tail: &mut &[u8]) -> io::Result<bool> {
    match read_bytes(tail)? {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(io::Error::other("invalid saved proxy flag")),
    }
}

fn read_journal_file(journal: &Path) -> io::Result<Option<Vec<u8>>> {
    let file = match File::open(journal) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take((MAX_JOURNAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(io::Error::other("saved proxy state exceeds 4 MiB"));
    }
    Ok(Some(bytes))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn state_directory() -> io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("HOME directory unavailable"))?
        .join("Library")
        .join("Application Support")
        .join("G-Earth-Rust");
    #[cfg(target_os = "linux")]
    let base = std::env::var_os("XDG_STATE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("state"))
        })
        .ok_or_else(|| io::Error::other("Linux state directory unavailable"))?
        .join("G-Earth-Rust");
    fs::create_dir_all(&base)?;
    Ok(base)
}

fn acquire_proxy_lock(lock_path: &Path, busy_message: &str) -> io::Result<File> {
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)?;
    lock.try_lock()
        .map_err(|_| io::Error::new(io::ErrorKind::AlreadyExists, busy_message))?;
    Ok(lock)
}

// ---------------------------------------------------------------------------
// macOS networksetup proxy + Security.framework CA management
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "macos", test))]
mod macos_impl {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(super) struct MacEndpoint {
        pub(super) enabled: bool,
        pub(super) server: String,
        pub(super) port: u16,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MacServiceState {
        service: String,
        http: MacEndpoint,
        https: MacEndpoint,
        bypass: Vec<String>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MacJournal {
        owned_host: String,
        owned_port: u16,
        services: Vec<MacServiceState>,
    }

    fn parse_macos_services(output: &str) -> Vec<String> {
        output
            .lines()
            .map(str::trim)
            .filter(|line| {
                !line.is_empty() && !line.starts_with('*') && !line.starts_with("An asterisk (*)")
            })
            .map(str::to_owned)
            .collect()
    }

    fn parse_macos_endpoint(output: &str) -> io::Result<MacEndpoint> {
        let mut enabled = None;
        let mut server = String::new();
        let mut port = 0u16;
        for line in output.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            match key {
                "Enabled" => enabled = Some(value.eq_ignore_ascii_case("yes")),
                "Server" => server = value.to_owned(),
                "Port" => {
                    port = if value.is_empty() {
                        0
                    } else {
                        value.parse().map_err(|_| {
                            io::Error::other(format!("invalid macOS proxy port: {value}"))
                        })?
                    };
                }
                _ => {}
            }
        }
        let enabled =
            enabled.ok_or_else(|| io::Error::other("unexpected networksetup proxy output"))?;
        Ok(MacEndpoint {
            enabled,
            server,
            port,
        })
    }

    fn parse_macos_bypass(output: &str) -> Vec<String> {
        let trimmed = output.trim();
        if trimmed.is_empty() || trimmed.starts_with("There aren't any Bypass Domains") {
            return Vec::new();
        }
        trimmed
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }

    fn encode_mac_journal(journal: &MacJournal) -> Vec<u8> {
        let mut bytes = b"GEARTH-MAC-PROXY-1\0".to_vec();
        push_str(&mut bytes, &journal.owned_host);
        push_bytes(&mut bytes, &journal.owned_port.to_le_bytes());
        push_bytes(&mut bytes, &(journal.services.len() as u32).to_le_bytes());
        for service in &journal.services {
            push_str(&mut bytes, &service.service);
            for endpoint in [&service.http, &service.https] {
                push_bytes(&mut bytes, &[u8::from(endpoint.enabled)]);
                push_str(&mut bytes, &endpoint.server);
                push_bytes(&mut bytes, &endpoint.port.to_le_bytes());
            }
            push_bytes(&mut bytes, &(service.bypass.len() as u32).to_le_bytes());
            for domain in &service.bypass {
                push_str(&mut bytes, domain);
            }
        }
        bytes
    }

    fn decode_mac_journal(bytes: &[u8]) -> io::Result<MacJournal> {
        let mut tail = bytes
            .strip_prefix(b"GEARTH-MAC-PROXY-1\0")
            .ok_or_else(|| io::Error::other("invalid saved macOS proxy state"))?;
        let owned_host = read_str(&mut tail)?;
        let owned_port = read_u16(&mut tail)?;
        let count_raw = read_bytes(&mut tail)?;
        let count = u32::from_le_bytes(
            count_raw
                .try_into()
                .map_err(|_| io::Error::other("invalid macOS service count"))?,
        ) as usize;
        if count > 1024 {
            return Err(io::Error::other("too many saved macOS network services"));
        }
        let mut services = Vec::with_capacity(count);
        for _ in 0..count {
            let service = read_str(&mut tail)?;
            let http = MacEndpoint {
                enabled: read_bool(&mut tail)?,
                server: read_str(&mut tail)?,
                port: read_u16(&mut tail)?,
            };
            let https = MacEndpoint {
                enabled: read_bool(&mut tail)?,
                server: read_str(&mut tail)?,
                port: read_u16(&mut tail)?,
            };
            let bypass_count_raw = read_bytes(&mut tail)?;
            let bypass_count = u32::from_le_bytes(
                bypass_count_raw
                    .try_into()
                    .map_err(|_| io::Error::other("invalid macOS bypass count"))?,
            ) as usize;
            if bypass_count > 4096 {
                return Err(io::Error::other("too many saved macOS bypass domains"));
            }
            let mut bypass = Vec::with_capacity(bypass_count);
            for _ in 0..bypass_count {
                bypass.push(read_str(&mut tail)?);
            }
            services.push(MacServiceState {
                service,
                http,
                https,
                bypass,
            });
        }
        if !tail.is_empty() {
            return Err(io::Error::other("unexpected trailing macOS proxy data"));
        }
        Ok(MacJournal {
            owned_host,
            owned_port,
            services,
        })
    }

    fn macos_restore_endpoint(
        runner: &mut dyn CommandRunner,
        service: &str,
        secure: bool,
        original: &MacEndpoint,
    ) -> io::Result<()> {
        let set_cmd = if secure {
            "-setsecurewebproxy"
        } else {
            "-setwebproxy"
        };
        let state_cmd = if secure {
            "-setsecurewebproxystate"
        } else {
            "-setwebproxystate"
        };
        if !original.server.is_empty() && original.port != 0 {
            let port = original.port.to_string();
            run_checked(
                runner,
                &CommandSpec::new(
                    "/usr/sbin/networksetup",
                    &[set_cmd, service, &original.server, &port],
                ),
            )?;
        }
        run_checked(
            runner,
            &CommandSpec::new(
                "/usr/sbin/networksetup",
                &[
                    state_cmd,
                    service,
                    if original.enabled { "on" } else { "off" },
                ],
            ),
        )?;
        Ok(())
    }

    fn macos_restore_bypass(
        runner: &mut dyn CommandRunner,
        service: &str,
        domains: &[String],
    ) -> io::Result<()> {
        let mut args = vec!["-setproxybypassdomains".to_owned(), service.to_owned()];
        if domains.is_empty() {
            args.push("Empty".to_owned());
        } else {
            args.extend(domains.iter().cloned());
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_checked(runner, &CommandSpec::new("/usr/sbin/networksetup", &refs))?;
        Ok(())
    }

    fn macos_restore_journal(
        runner: &mut dyn CommandRunner,
        journal: &MacJournal,
    ) -> io::Result<()> {
        for entry in &journal.services {
            let current_http = parse_macos_endpoint(&run_checked(
                runner,
                &CommandSpec::new("/usr/sbin/networksetup", &["-getwebproxy", &entry.service]),
            )?)?;
            let current_https = parse_macos_endpoint(&run_checked(
                runner,
                &CommandSpec::new(
                    "/usr/sbin/networksetup",
                    &["-getsecurewebproxy", &entry.service],
                ),
            )?)?;
            let owns_http = current_http.enabled
                && current_http.server == journal.owned_host
                && current_http.port == journal.owned_port;
            let owns_https = current_https.enabled
                && current_https.server == journal.owned_host
                && current_https.port == journal.owned_port;
            if owns_http {
                macos_restore_endpoint(runner, &entry.service, false, &entry.http)?;
            }
            if owns_https {
                macos_restore_endpoint(runner, &entry.service, true, &entry.https)?;
            }
            if owns_http || owns_https {
                macos_restore_bypass(runner, &entry.service, &entry.bypass)?;
            }
        }
        Ok(())
    }

    pub(super) fn macos_recover_at(
        runner: &mut dyn CommandRunner,
        journal_path: &Path,
    ) -> io::Result<()> {
        let Some(bytes) = read_journal_file(journal_path)? else {
            return Ok(());
        };
        let journal = decode_mac_journal(&bytes)?;
        macos_restore_journal(runner, &journal)?;
        remove_file_if_exists(journal_path)
    }

    pub(super) struct MacProxyGuard {
        journal_path: PathBuf,
        lock: Option<File>,
        journal: MacJournal,
        runner: Box<dyn CommandRunner>,
        pub(super) active: bool,
    }

    impl MacProxyGuard {
        pub(super) fn activate_at(
            mut runner: Box<dyn CommandRunner>,
            lock_path: &Path,
            address: SocketAddr,
        ) -> io::Result<Self> {
            if !address.ip().is_loopback() || address.port() == 0 {
                return Err(io::Error::other(
                    "system proxy must point to a bound loopback listener",
                ));
            }
            let lock = acquire_proxy_lock(
                lock_path,
                "another G-Earth Rust instance controls the system proxy",
            )?;
            let journal_path = lock_path.with_extension("state");
            macos_recover_at(&mut *runner, &journal_path)?;

            let services_raw = run_checked(
                &mut *runner,
                &CommandSpec::new("/usr/sbin/networksetup", &["-listallnetworkservices"]),
            )?;
            let service_names = parse_macos_services(&services_raw);
            if service_names.is_empty() {
                return Err(io::Error::other("no enabled macOS network services found"));
            }

            let mut snapshots = Vec::with_capacity(service_names.len());
            for service in service_names {
                let http = parse_macos_endpoint(&run_checked(
                    &mut *runner,
                    &CommandSpec::new("/usr/sbin/networksetup", &["-getwebproxy", &service]),
                )?)?;
                let https = parse_macos_endpoint(&run_checked(
                    &mut *runner,
                    &CommandSpec::new("/usr/sbin/networksetup", &["-getsecurewebproxy", &service]),
                )?)?;
                let bypass = parse_macos_bypass(&run_checked(
                    &mut *runner,
                    &CommandSpec::new(
                        "/usr/sbin/networksetup",
                        &["-getproxybypassdomains", &service],
                    ),
                )?);
                snapshots.push(MacServiceState {
                    service,
                    http,
                    https,
                    bypass,
                });
            }

            let host = address.ip().to_string();
            let port = address.port();
            let port_text = port.to_string();
            let journal = MacJournal {
                owned_host: host.clone(),
                owned_port: port,
                services: snapshots,
            };
            write_atomic(&journal_path, &encode_mac_journal(&journal))?;

            let mut bypass_args = Vec::with_capacity(BYPASS_DOMAINS.len() + 2);
            for entry in &journal.services {
                let apply = (|| -> io::Result<()> {
                    run_checked(
                        &mut *runner,
                        &CommandSpec::new(
                            "/usr/sbin/networksetup",
                            &["-setwebproxy", &entry.service, &host, &port_text],
                        ),
                    )?;
                    run_checked(
                        &mut *runner,
                        &CommandSpec::new(
                            "/usr/sbin/networksetup",
                            &["-setwebproxystate", &entry.service, "on"],
                        ),
                    )?;
                    run_checked(
                        &mut *runner,
                        &CommandSpec::new(
                            "/usr/sbin/networksetup",
                            &["-setsecurewebproxy", &entry.service, &host, &port_text],
                        ),
                    )?;
                    run_checked(
                        &mut *runner,
                        &CommandSpec::new(
                            "/usr/sbin/networksetup",
                            &["-setsecurewebproxystate", &entry.service, "on"],
                        ),
                    )?;
                    bypass_args.clear();
                    bypass_args.push("-setproxybypassdomains");
                    bypass_args.push(&entry.service);
                    bypass_args.extend_from_slice(BYPASS_DOMAINS);
                    run_checked(
                        &mut *runner,
                        &CommandSpec::new("/usr/sbin/networksetup", &bypass_args),
                    )?;
                    Ok(())
                })();
                if let Err(error) = apply {
                    let _ = macos_restore_journal(&mut *runner, &journal);
                    let _ = remove_file_if_exists(&journal_path);
                    return Err(error);
                }
            }

            Ok(Self {
                journal_path,
                lock: Some(lock),
                journal,
                runner,
                active: true,
            })
        }

        pub(super) fn restore(&mut self) -> io::Result<()> {
            if !self.active {
                return Ok(());
            }
            macos_restore_journal(&mut *self.runner, &self.journal)?;
            remove_file_if_exists(&self.journal_path)?;
            self.active = false;
            self.lock.take();
            Ok(())
        }
    }

    impl Drop for MacProxyGuard {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }

    fn macos_login_keychain(runner: &mut dyn CommandRunner) -> io::Result<String> {
        let raw = run_checked(
            runner,
            &CommandSpec::new("/usr/bin/security", &["default-keychain", "-d", "user"]),
        )?;
        let path = raw.trim().trim_matches('"').trim();
        if path.is_empty() {
            return Err(io::Error::other(
                "cannot determine macOS user login keychain",
            ));
        }
        Ok(path.to_owned())
    }

    pub(super) fn macos_certificate_trusted_with(
        runner: &mut dyn CommandRunner,
        der: &[u8],
        temp_dir: &Path,
    ) -> io::Result<bool> {
        let hash = thumbprint_upper(der)?;
        let temp_cert = temp_dir.join(format!("gearth-verify-{}-{hash}.cer", std::process::id()));
        fs::write(&temp_cert, der)?;
        let cert_str = temp_cert.to_string_lossy().into_owned();
        let result = runner.run(&CommandSpec::new(
            "/usr/bin/security",
            &["verify-cert", "-c", &cert_str],
        ));
        let _ = remove_file_if_exists(&temp_cert);
        Ok(result?.success)
    }

    pub(super) fn macos_install_certificate_with(
        runner: &mut dyn CommandRunner,
        path: &Path,
    ) -> io::Result<()> {
        let path = path.canonicalize()?;
        if !path.is_file() || fs::metadata(&path)?.len() > MAX_CERT_BYTES as u64 {
            return Err(io::Error::other("invalid public certificate file"));
        }
        let keychain = macos_login_keychain(runner)?;
        let cert = path.to_string_lossy().into_owned();
        run_checked(
            runner,
            &CommandSpec::new(
                "/usr/bin/security",
                &[
                    "add-trusted-cert",
                    "-r",
                    "trustRoot",
                    "-k",
                    &keychain,
                    &cert,
                ],
            ),
        )?;
        Ok(())
    }

    pub(super) fn macos_remove_certificate_with(
        runner: &mut dyn CommandRunner,
        der: &[u8],
    ) -> io::Result<()> {
        let hash = thumbprint_upper(der)?;
        let keychain = macos_login_keychain(runner)?;
        run_checked(
            runner,
            &CommandSpec::new(
                "/usr/bin/security",
                &["delete-certificate", "-Z", &hash, &keychain],
            ),
        )?;
        Ok(())
    }
}

#[cfg(test)]
use macos_impl::MacEndpoint;
#[cfg(any(target_os = "macos", test))]
use macos_impl::{
    macos_certificate_trusted_with, macos_install_certificate_with, macos_recover_at,
    macos_remove_certificate_with, MacProxyGuard,
};

// ---------------------------------------------------------------------------
// Linux GNOME gsettings proxy + user NSS certutil CA management
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "linux", test))]
mod linux_impl {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct LinuxProxySnapshot {
        mode: String,
        ignore_hosts: String,
        http_host: String,
        http_port: String,
        https_host: String,
        https_port: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct LinuxJournal {
        owned_host: String,
        owned_port: u16,
        before: LinuxProxySnapshot,
    }

    fn encode_linux_journal(journal: &LinuxJournal) -> Vec<u8> {
        let mut bytes = b"GEARTH-LINUX-PROXY-1\0".to_vec();
        push_str(&mut bytes, &journal.owned_host);
        push_bytes(&mut bytes, &journal.owned_port.to_le_bytes());
        push_str(&mut bytes, &journal.before.mode);
        push_str(&mut bytes, &journal.before.ignore_hosts);
        push_str(&mut bytes, &journal.before.http_host);
        push_str(&mut bytes, &journal.before.http_port);
        push_str(&mut bytes, &journal.before.https_host);
        push_str(&mut bytes, &journal.before.https_port);
        bytes
    }

    fn decode_linux_journal(bytes: &[u8]) -> io::Result<LinuxJournal> {
        let mut tail = bytes
            .strip_prefix(b"GEARTH-LINUX-PROXY-1\0")
            .ok_or_else(|| io::Error::other("invalid saved Linux proxy state"))?;
        let owned_host = read_str(&mut tail)?;
        let owned_port = read_u16(&mut tail)?;
        let before = LinuxProxySnapshot {
            mode: read_str(&mut tail)?,
            ignore_hosts: read_str(&mut tail)?,
            http_host: read_str(&mut tail)?,
            http_port: read_str(&mut tail)?,
            https_host: read_str(&mut tail)?,
            https_port: read_str(&mut tail)?,
        };
        if !tail.is_empty() {
            return Err(io::Error::other("unexpected trailing Linux proxy data"));
        }
        Ok(LinuxJournal {
            owned_host,
            owned_port,
            before,
        })
    }

    fn gsettings_get(
        runner: &mut dyn CommandRunner,
        schema: &str,
        key: &str,
    ) -> io::Result<String> {
        Ok(run_checked(
            runner,
            &CommandSpec::new("gsettings", &["get", schema, key]),
        )?
        .trim()
        .to_owned())
    }

    fn gsettings_set(
        runner: &mut dyn CommandRunner,
        schema: &str,
        key: &str,
        value: &str,
    ) -> io::Result<()> {
        run_checked(
            runner,
            &CommandSpec::new("gsettings", &["set", schema, key, value]),
        )?;
        Ok(())
    }

    fn read_linux_proxy_snapshot(runner: &mut dyn CommandRunner) -> io::Result<LinuxProxySnapshot> {
        Ok(LinuxProxySnapshot {
            mode: gsettings_get(runner, "org.gnome.system.proxy", "mode")?,
            ignore_hosts: gsettings_get(runner, "org.gnome.system.proxy", "ignore-hosts")?,
            http_host: gsettings_get(runner, "org.gnome.system.proxy.http", "host")?,
            http_port: gsettings_get(runner, "org.gnome.system.proxy.http", "port")?,
            https_host: gsettings_get(runner, "org.gnome.system.proxy.https", "host")?,
            https_port: gsettings_get(runner, "org.gnome.system.proxy.https", "port")?,
        })
    }

    fn gsettings_quoted(value: &str) -> String {
        format!("'{value}'")
    }

    fn linux_restore_journal(
        runner: &mut dyn CommandRunner,
        journal: &LinuxJournal,
    ) -> io::Result<()> {
        let current = read_linux_proxy_snapshot(runner)?;
        let owned_host = gsettings_quoted(&journal.owned_host);
        let owned_port = journal.owned_port.to_string();
        let owns_http = current.http_host == owned_host && current.http_port == owned_port;
        let owns_https = current.https_host == owned_host && current.https_port == owned_port;
        if current.mode == "'manual'" && (owns_http || owns_https) {
            if owns_http {
                gsettings_set(
                    runner,
                    "org.gnome.system.proxy.http",
                    "host",
                    &journal.before.http_host,
                )?;
                gsettings_set(
                    runner,
                    "org.gnome.system.proxy.http",
                    "port",
                    &journal.before.http_port,
                )?;
            }
            if owns_https {
                gsettings_set(
                    runner,
                    "org.gnome.system.proxy.https",
                    "host",
                    &journal.before.https_host,
                )?;
                gsettings_set(
                    runner,
                    "org.gnome.system.proxy.https",
                    "port",
                    &journal.before.https_port,
                )?;
            }
            if current.ignore_hosts == LINUX_IGNORE_HOSTS {
                gsettings_set(
                    runner,
                    "org.gnome.system.proxy",
                    "ignore-hosts",
                    &journal.before.ignore_hosts,
                )?;
            }
            gsettings_set(
                runner,
                "org.gnome.system.proxy",
                "mode",
                &journal.before.mode,
            )?;
        }
        Ok(())
    }

    pub(super) fn linux_recover_at(
        runner: &mut dyn CommandRunner,
        journal_path: &Path,
    ) -> io::Result<()> {
        let Some(bytes) = read_journal_file(journal_path)? else {
            return Ok(());
        };
        let journal = decode_linux_journal(&bytes)?;
        linux_restore_journal(runner, &journal)?;
        remove_file_if_exists(journal_path)
    }

    pub(super) struct LinuxProxyGuard {
        journal_path: PathBuf,
        lock: Option<File>,
        journal: LinuxJournal,
        runner: Box<dyn CommandRunner>,
        pub(super) active: bool,
    }

    impl LinuxProxyGuard {
        pub(super) fn activate_at(
            mut runner: Box<dyn CommandRunner>,
            lock_path: &Path,
            address: SocketAddr,
        ) -> io::Result<Self> {
            if !address.ip().is_loopback() || address.port() == 0 {
                return Err(io::Error::other(
                    "system proxy must point to a bound loopback listener",
                ));
            }
            let lock = acquire_proxy_lock(
                lock_path,
                "another G-Earth Rust instance controls the system proxy",
            )?;
            let journal_path = lock_path.with_extension("state");
            linux_recover_at(&mut *runner, &journal_path)?;

            let before = read_linux_proxy_snapshot(&mut *runner)?;
            let host = address.ip().to_string();
            let port = address.port();
            let journal = LinuxJournal {
                owned_host: host.clone(),
                owned_port: port,
                before,
            };
            write_atomic(&journal_path, &encode_linux_journal(&journal))?;

            let quoted_host = gsettings_quoted(&host);
            let port_text = port.to_string();
            let apply = (|| -> io::Result<()> {
                gsettings_set(
                    &mut *runner,
                    "org.gnome.system.proxy.http",
                    "host",
                    &quoted_host,
                )?;
                gsettings_set(
                    &mut *runner,
                    "org.gnome.system.proxy.http",
                    "port",
                    &port_text,
                )?;
                gsettings_set(
                    &mut *runner,
                    "org.gnome.system.proxy.https",
                    "host",
                    &quoted_host,
                )?;
                gsettings_set(
                    &mut *runner,
                    "org.gnome.system.proxy.https",
                    "port",
                    &port_text,
                )?;
                gsettings_set(
                    &mut *runner,
                    "org.gnome.system.proxy",
                    "ignore-hosts",
                    LINUX_IGNORE_HOSTS,
                )?;
                gsettings_set(&mut *runner, "org.gnome.system.proxy", "mode", "'manual'")?;
                Ok(())
            })();
            if let Err(error) = apply {
                let _ = linux_restore_journal(&mut *runner, &journal);
                let _ = remove_file_if_exists(&journal_path);
                return Err(error);
            }

            Ok(Self {
                journal_path,
                lock: Some(lock),
                journal,
                runner,
                active: true,
            })
        }

        pub(super) fn restore(&mut self) -> io::Result<()> {
            if !self.active {
                return Ok(());
            }
            linux_restore_journal(&mut *self.runner, &self.journal)?;
            remove_file_if_exists(&self.journal_path)?;
            self.active = false;
            self.lock.take();
            Ok(())
        }
    }

    impl Drop for LinuxProxyGuard {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }

    pub(super) fn nss_nickname(der: &[u8]) -> io::Result<String> {
        let hash = thumbprint_upper(der)?;
        Ok(format!("G-Earth-Rust-CA-{}", &hash[..16]))
    }

    #[cfg(target_os = "linux")]
    pub(super) fn linux_nss_db() -> io::Result<PathBuf> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::other("HOME directory unavailable"))?;
        Ok(home.join(".pki").join("nssdb"))
    }

    pub(super) fn linux_certificate_trusted_with(
        runner: &mut dyn CommandRunner,
        nssdb: &Path,
        der: &[u8],
    ) -> io::Result<bool> {
        let nickname = nss_nickname(der)?;
        if !nssdb.join("cert9.db").is_file() {
            return Ok(false);
        }
        let db_arg = format!("sql:{}", nssdb.display());
        let output = runner.run(&CommandSpec::new("certutil", &["-d", &db_arg, "-L"]))?;
        if !output.success {
            return Ok(false);
        }
        for line in output.stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix(&nickname) {
                let trust = rest.trim();
                if trust.starts_with('C') {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub(super) fn linux_install_certificate_with(
        runner: &mut dyn CommandRunner,
        nssdb: &Path,
        path: &Path,
    ) -> io::Result<()> {
        let path = path.canonicalize()?;
        if !path.is_file() || fs::metadata(&path)?.len() > MAX_CERT_BYTES as u64 {
            return Err(io::Error::other("invalid public certificate file"));
        }
        let der = fs::read(&path)?;
        let nickname = nss_nickname(&der)?;
        fs::create_dir_all(nssdb)?;
        let db_arg = format!("sql:{}", nssdb.display());
        if !nssdb.join("cert9.db").is_file() {
            run_checked(
                runner,
                &CommandSpec::new("certutil", &["-d", &db_arg, "-N", "--empty-password"]),
            )?;
        }
        let cert_path = path.to_string_lossy().into_owned();
        run_checked(
            runner,
            &CommandSpec::new(
                "certutil",
                &[
                    "-d", &db_arg, "-A", "-t", "C,,", "-n", &nickname, "-i", &cert_path,
                ],
            ),
        )?;
        Ok(())
    }

    pub(super) fn linux_remove_certificate_with(
        runner: &mut dyn CommandRunner,
        nssdb: &Path,
        der: &[u8],
    ) -> io::Result<()> {
        let nickname = nss_nickname(der)?;
        let db_arg = format!("sql:{}", nssdb.display());
        run_checked(
            runner,
            &CommandSpec::new("certutil", &["-d", &db_arg, "-D", "-n", &nickname]),
        )?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
use linux_impl::linux_nss_db;
#[cfg(test)]
use linux_impl::nss_nickname;
#[cfg(any(target_os = "linux", test))]
use linux_impl::{
    linux_certificate_trusted_with, linux_install_certificate_with, linux_recover_at,
    linux_remove_certificate_with, LinuxProxyGuard,
};

// ---------------------------------------------------------------------------
// Platform dispatch exposed to lib.rs
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub(crate) struct ProxyGuard(MacProxyGuard);

#[cfg(target_os = "linux")]
pub(crate) struct ProxyGuard(LinuxProxyGuard);

#[cfg(target_os = "macos")]
impl ProxyGuard {
    pub(crate) fn has_stale_journal() -> bool {
        state_directory()
            .map(|dir| dir.join("system-proxy.state").is_file())
            .unwrap_or(false)
    }
    pub(crate) fn activate(address: SocketAddr) -> io::Result<Self> {
        let dir = state_directory()?;
        MacProxyGuard::activate_at(
            Box::new(SystemCommandRunner),
            &dir.join("system-proxy.lock"),
            address,
        )
        .map(Self)
    }

    pub(crate) fn recover() -> io::Result<()> {
        let dir = state_directory()?;
        let lock_path = dir.join("system-proxy.lock");
        let _lock = acquire_proxy_lock(
            &lock_path,
            "close the G-Earth Rust instance that controls the proxy first",
        )?;
        let mut runner = SystemCommandRunner;
        macos_recover_at(&mut runner, &lock_path.with_extension("state"))
    }

    pub(crate) fn restore(&mut self) -> io::Result<()> {
        self.0.restore()
    }
}

#[cfg(target_os = "linux")]
impl ProxyGuard {
    pub(crate) fn has_stale_journal() -> bool {
        state_directory()
            .map(|dir| dir.join("system-proxy.state").is_file())
            .unwrap_or(false)
    }
    pub(crate) fn activate(address: SocketAddr) -> io::Result<Self> {
        let dir = state_directory()?;
        LinuxProxyGuard::activate_at(
            Box::new(SystemCommandRunner),
            &dir.join("system-proxy.lock"),
            address,
        )
        .map(Self)
    }

    pub(crate) fn recover() -> io::Result<()> {
        let dir = state_directory()?;
        let lock_path = dir.join("system-proxy.lock");
        let _lock = acquire_proxy_lock(
            &lock_path,
            "close the G-Earth Rust instance that controls the proxy first",
        )?;
        let mut runner = SystemCommandRunner;
        linux_recover_at(&mut runner, &lock_path.with_extension("state"))
    }

    pub(crate) fn restore(&mut self) -> io::Result<()> {
        self.0.restore()
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn certificate_trusted(der: &[u8]) -> io::Result<bool> {
    let mut runner = SystemCommandRunner;
    macos_certificate_trusted_with(&mut runner, der, &std::env::temp_dir())
}

#[cfg(target_os = "macos")]
pub(crate) fn install_certificate(path: &Path) -> io::Result<()> {
    let mut runner = SystemCommandRunner;
    macos_install_certificate_with(&mut runner, path)
}

#[cfg(target_os = "macos")]
pub(crate) fn remove_certificate(der: &[u8]) -> io::Result<()> {
    let mut runner = SystemCommandRunner;
    macos_remove_certificate_with(&mut runner, der)
}

#[cfg(target_os = "linux")]
pub(crate) fn certificate_trusted(der: &[u8]) -> io::Result<bool> {
    let mut runner = SystemCommandRunner;
    linux_certificate_trusted_with(&mut runner, &linux_nss_db()?, der)
}

#[cfg(target_os = "linux")]
pub(crate) fn install_certificate(path: &Path) -> io::Result<()> {
    let mut runner = SystemCommandRunner;
    linux_install_certificate_with(&mut runner, &linux_nss_db()?, path)
}

#[cfg(target_os = "linux")]
pub(crate) fn remove_certificate(der: &[u8]) -> io::Result<()> {
    let mut runner = SystemCommandRunner;
    linux_remove_certificate_with(&mut runner, &linux_nss_db()?, der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(prefix: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let id = format!(
                "{prefix}-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let dir = std::env::temp_dir().join(id);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone, Default)]
    struct FakeMacState {
        services: Vec<(String, bool)>,
        http: HashMap<String, MacEndpoint>,
        https: HashMap<String, MacEndpoint>,
        bypass: HashMap<String, Vec<String>>,
        commands: Vec<Vec<String>>,
    }

    #[derive(Clone)]
    struct FakeMacRunner(Arc<Mutex<FakeMacState>>);
    impl CommandRunner for FakeMacRunner {
        fn run(&mut self, spec: &CommandSpec) -> io::Result<CommandOutput> {
            let args: Vec<String> = spec
                .args
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let mut state = self.0.lock().unwrap();
            state.commands.push(args.clone());
            let stdout = match args.first().map(String::as_str) {
                Some("-listallnetworkservices") => {
                    let mut out = String::from(
                        "An asterisk (*) denotes that a network service is disabled.\n",
                    );
                    for (name, enabled) in &state.services {
                        if *enabled {
                            out.push_str(name);
                        } else {
                            out.push('*');
                            out.push_str(name);
                        }
                        out.push('\n');
                    }
                    out
                }
                Some("-getwebproxy") => {
                    let ep = state.http.get(&args[1]).unwrap();
                    format!(
                        "Enabled: {}\nServer: {}\nPort: {}\nAuthenticated Proxy Enabled: 0\n",
                        if ep.enabled { "Yes" } else { "No" },
                        ep.server,
                        ep.port
                    )
                }
                Some("-getsecurewebproxy") => {
                    let ep = state.https.get(&args[1]).unwrap();
                    format!(
                        "Enabled: {}\nServer: {}\nPort: {}\nAuthenticated Proxy Enabled: 0\n",
                        if ep.enabled { "Yes" } else { "No" },
                        ep.server,
                        ep.port
                    )
                }
                Some("-getproxybypassdomains") => {
                    let domains = state.bypass.get(&args[1]).cloned().unwrap_or_default();
                    if domains.is_empty() {
                        format!("There aren't any Bypass Domains set on {}.\n", args[1])
                    } else {
                        domains.join("\n") + "\n"
                    }
                }
                Some("-setwebproxy") => {
                    let ep = state.http.get_mut(&args[1]).unwrap();
                    ep.server = args[2].clone();
                    ep.port = args[3].parse().unwrap();
                    String::new()
                }
                Some("-setwebproxystate") => {
                    state.http.get_mut(&args[1]).unwrap().enabled = args[2] == "on";
                    String::new()
                }
                Some("-setsecurewebproxy") => {
                    let ep = state.https.get_mut(&args[1]).unwrap();
                    ep.server = args[2].clone();
                    ep.port = args[3].parse().unwrap();
                    String::new()
                }
                Some("-setsecurewebproxystate") => {
                    state.https.get_mut(&args[1]).unwrap().enabled = args[2] == "on";
                    String::new()
                }
                Some("-setproxybypassdomains") => {
                    let list = if args.get(2).map(String::as_str) == Some("Empty") {
                        Vec::new()
                    } else {
                        args[2..].to_vec()
                    };
                    state.bypass.insert(args[1].clone(), list);
                    String::new()
                }
                _ => panic!("unexpected networksetup args: {args:?}"),
            };
            Ok(CommandOutput {
                success: true,
                code: Some(0),
                stdout,
                stderr: String::new(),
            })
        }
    }

    fn sample_mac_state() -> Arc<Mutex<FakeMacState>> {
        let mut state = FakeMacState {
            services: vec![("Wi-Fi".into(), true), ("Bluetooth PAN".into(), false)],
            ..Default::default()
        };
        state.http.insert(
            "Wi-Fi".into(),
            MacEndpoint {
                enabled: false,
                server: "old.proxy.invalid".into(),
                port: 8080,
            },
        );
        state.https.insert(
            "Wi-Fi".into(),
            MacEndpoint {
                enabled: false,
                server: String::new(),
                port: 0,
            },
        );
        state
            .bypass
            .insert("Wi-Fi".into(), vec!["*.local".into(), "169.254/16".into()]);
        Arc::new(Mutex::new(state))
    }

    #[test]
    fn macos_proxy_guard_activates_restores_and_preserves_external_changes() {
        let dir = TempDir::new("gearth-mac-proxy");
        let state = sample_mac_state();
        let mut guard = MacProxyGuard::activate_at(
            Box::new(FakeMacRunner(state.clone())),
            &dir.0.join("system-proxy.lock"),
            "127.0.0.1:9090".parse().unwrap(),
        )
        .unwrap();
        {
            let locked = state.lock().unwrap();
            assert_eq!(
                locked.http["Wi-Fi"],
                MacEndpoint {
                    enabled: true,
                    server: "127.0.0.1".into(),
                    port: 9090
                }
            );
            assert_eq!(
                locked.https["Wi-Fi"],
                MacEndpoint {
                    enabled: true,
                    server: "127.0.0.1".into(),
                    port: 9090
                }
            );
            assert!(locked.bypass["Wi-Fi"].contains(&"discord.com".to_string()));
        }
        // A second guard must be rejected while the first holds the lock.
        assert!(MacProxyGuard::activate_at(
            Box::new(FakeMacRunner(state.clone())),
            &dir.0.join("system-proxy.lock"),
            "127.0.0.1:9091".parse().unwrap(),
        )
        .is_err());

        guard.restore().unwrap();
        {
            let locked = state.lock().unwrap();
            assert!(!locked.http["Wi-Fi"].enabled);
            assert_eq!(locked.http["Wi-Fi"].server, "old.proxy.invalid");
            assert_eq!(locked.http["Wi-Fi"].port, 8080);
            assert!(!locked.https["Wi-Fi"].enabled);
            assert_eq!(
                locked.bypass["Wi-Fi"],
                vec!["*.local".to_string(), "169.254/16".to_string()]
            );
        }

        // Simulate crash recovery when user later replaced HTTP proxy externally.
        let mut crashed = MacProxyGuard::activate_at(
            Box::new(FakeMacRunner(state.clone())),
            &dir.0.join("system-proxy.lock"),
            "127.0.0.1:9092".parse().unwrap(),
        )
        .unwrap();
        crashed.active = false;
        drop(crashed);
        state.lock().unwrap().http.get_mut("Wi-Fi").unwrap().server = "user.proxy.invalid".into();
        let mut runner = FakeMacRunner(state.clone());
        macos_recover_at(&mut runner, &dir.0.join("system-proxy.state")).unwrap();
        let locked = state.lock().unwrap();
        // User's HTTP change is preserved; still-owned HTTPS proxy is restored.
        assert_eq!(locked.http["Wi-Fi"].server, "user.proxy.invalid");
        assert!(!locked.https["Wi-Fi"].enabled);
    }

    #[derive(Clone, Default)]
    struct FakeLinuxState {
        values: HashMap<(String, String), String>,
    }

    #[derive(Clone)]
    struct FakeLinuxRunner(Arc<Mutex<FakeLinuxState>>);
    impl CommandRunner for FakeLinuxRunner {
        fn run(&mut self, spec: &CommandSpec) -> io::Result<CommandOutput> {
            let args: Vec<String> = spec
                .args
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let mut state = self.0.lock().unwrap();
            let stdout = match args.first().map(String::as_str) {
                Some("get") => format!("{}\n", state.values[&(args[1].clone(), args[2].clone())]),
                Some("set") => {
                    state
                        .values
                        .insert((args[1].clone(), args[2].clone()), args[3].clone());
                    String::new()
                }
                _ => panic!("unexpected gsettings args: {args:?}"),
            };
            Ok(CommandOutput {
                success: true,
                code: Some(0),
                stdout,
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn linux_proxy_guard_activates_recovers_and_preserves_external_changes() {
        let dir = TempDir::new("gearth-linux-proxy");
        let state = Arc::new(Mutex::new(FakeLinuxState {
            values: HashMap::from([
                (
                    ("org.gnome.system.proxy".into(), "mode".into()),
                    "'none'".into(),
                ),
                (
                    ("org.gnome.system.proxy".into(), "ignore-hosts".into()),
                    "['localhost']".into(),
                ),
                (
                    ("org.gnome.system.proxy.http".into(), "host".into()),
                    "''".into(),
                ),
                (
                    ("org.gnome.system.proxy.http".into(), "port".into()),
                    "0".into(),
                ),
                (
                    ("org.gnome.system.proxy.https".into(), "host".into()),
                    "''".into(),
                ),
                (
                    ("org.gnome.system.proxy.https".into(), "port".into()),
                    "0".into(),
                ),
            ]),
        }));
        let mut guard = LinuxProxyGuard::activate_at(
            Box::new(FakeLinuxRunner(state.clone())),
            &dir.0.join("system-proxy.lock"),
            "127.0.0.1:9191".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            state.lock().unwrap().values[&("org.gnome.system.proxy".into(), "mode".into())],
            "'manual'"
        );
        guard.restore().unwrap();
        assert_eq!(
            state.lock().unwrap().values[&("org.gnome.system.proxy".into(), "mode".into())],
            "'none'"
        );
        assert_eq!(
            state.lock().unwrap().values[&("org.gnome.system.proxy".into(), "ignore-hosts".into())],
            "['localhost']"
        );

        // External change after simulated crash must be preserved on recovery.
        let mut crashed = LinuxProxyGuard::activate_at(
            Box::new(FakeLinuxRunner(state.clone())),
            &dir.0.join("system-proxy.lock"),
            "127.0.0.1:9192".parse().unwrap(),
        )
        .unwrap();
        crashed.active = false;
        drop(crashed);
        state.lock().unwrap().values.insert(
            ("org.gnome.system.proxy.http".into(), "host".into()),
            "'external.example'".into(),
        );
        state.lock().unwrap().values.insert(
            ("org.gnome.system.proxy.https".into(), "host".into()),
            "'external.example'".into(),
        );
        let mut runner = FakeLinuxRunner(state.clone());
        linux_recover_at(&mut runner, &dir.0.join("system-proxy.state")).unwrap();
        assert_eq!(
            state.lock().unwrap().values[&("org.gnome.system.proxy".into(), "mode".into())],
            "'manual'"
        );
    }

    struct ScriptedRunner {
        responses: Vec<CommandOutput>,
        recorded: Vec<(PathBuf, Vec<String>)>,
    }
    impl CommandRunner for ScriptedRunner {
        fn run(&mut self, spec: &CommandSpec) -> io::Result<CommandOutput> {
            self.recorded.push((
                spec.program.clone(),
                spec.args
                    .iter()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect(),
            ));
            Ok(self.responses.remove(0))
        }
    }

    #[test]
    fn macos_and_linux_ca_helpers_emit_expected_commands() {
        let dir = TempDir::new("gearth-ca-helpers");
        let cert_path = dir.0.join("proxy-ca.cer");
        let der = b"synthetic-public-certificate-der";
        fs::write(&cert_path, der).unwrap();

        let mut mac_runner = ScriptedRunner {
            responses: vec![
                CommandOutput {
                    success: true,
                    code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                },
                CommandOutput {
                    success: true,
                    code: Some(0),
                    stdout: "    \"/Users/test/Library/Keychains/login.keychain-db\"\n".into(),
                    stderr: String::new(),
                },
                CommandOutput {
                    success: true,
                    code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                },
                CommandOutput {
                    success: true,
                    code: Some(0),
                    stdout: "    \"/Users/test/Library/Keychains/login.keychain-db\"\n".into(),
                    stderr: String::new(),
                },
                CommandOutput {
                    success: true,
                    code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                },
            ],
            recorded: Vec::new(),
        };
        assert!(macos_certificate_trusted_with(&mut mac_runner, der, &dir.0).unwrap());
        macos_install_certificate_with(&mut mac_runner, &cert_path).unwrap();
        macos_remove_certificate_with(&mut mac_runner, der).unwrap();
        assert_eq!(mac_runner.recorded[0].1[0], "verify-cert");
        assert_eq!(mac_runner.recorded[2].1[0], "add-trusted-cert");
        assert_eq!(mac_runner.recorded[4].1[0], "delete-certificate");

        let nssdb = dir.0.join("nssdb");
        fs::create_dir_all(&nssdb).unwrap();
        fs::write(nssdb.join("cert9.db"), b"").unwrap();
        let nickname = nss_nickname(der).unwrap();
        let mut linux_runner = ScriptedRunner {
            responses: vec![
                CommandOutput {
                    success: true,
                    code: Some(0),
                    stdout: format!("{nickname}                                C,,\n"),
                    stderr: String::new(),
                },
                CommandOutput {
                    success: true,
                    code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                },
                CommandOutput {
                    success: true,
                    code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                },
            ],
            recorded: Vec::new(),
        };
        assert!(linux_certificate_trusted_with(&mut linux_runner, &nssdb, der).unwrap());
        linux_install_certificate_with(&mut linux_runner, &nssdb, &cert_path).unwrap();
        linux_remove_certificate_with(&mut linux_runner, &nssdb, der).unwrap();
        assert_eq!(linux_runner.recorded[1].1[2], "-A");
        assert_eq!(linux_runner.recorded[2].1[2], "-D");
    }
}
