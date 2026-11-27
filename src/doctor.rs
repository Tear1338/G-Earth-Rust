//! Non-blocking Connection Doctor diagnostics for Flash, Origins, Unity, Nitro, and City modes.
use gearth_rust::{attachment::HostsRedirect, nitro_city::CityKeys, web_ca::ProxyIdentity};
use std::{
    fs::File,
    io::Read,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoctorMode {
    Flash,
    Origins,
    Unity,
    Nitro,
    City,
}

impl DoctorMode {
    pub fn from_flags(origins: bool, nitro: bool, unity: bool, city: bool) -> Self {
        if nitro && unity {
            Self::Unity
        } else if nitro && city {
            Self::City
        } else if nitro {
            Self::Nitro
        } else if origins {
            Self::Origins
        } else {
            Self::Flash
        }
    }

    pub fn is_browser(self) -> bool {
        matches!(self, Self::Unity | Self::Nitro | Self::City)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckSeverity {
    Ok,
    Warn,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixAction {
    InstallCertificate,
    PickFreePort,
    EnablePacProxy,
    RestoreProxy,
    CleanHosts,
    EnableCityHelper,
    ClearCityKey,
    #[cfg(target_os = "macos")]
    RelaunchAsAdmin,
    #[cfg(target_os = "macos")]
    PrepareMacosFlash,
}

impl FixAction {
    pub fn label_key(self) -> &'static str {
        match self {
            Self::InstallCertificate => "rust.doctor.fix.install_cert",
            Self::PickFreePort => "rust.doctor.fix.free_port",
            Self::EnablePacProxy => "rust.doctor.fix.enable_pac",
            Self::RestoreProxy => "rust.doctor.fix.restore_proxy",
            Self::CleanHosts => "rust.doctor.fix.clean_hosts",
            Self::EnableCityHelper => "rust.doctor.fix.enable_city",
            Self::ClearCityKey => "rust.doctor.fix.clear_key",
            #[cfg(target_os = "macos")]
            Self::RelaunchAsAdmin => "rust.doctor.fix.relaunch_admin",
            #[cfg(target_os = "macos")]
            Self::PrepareMacosFlash => "rust.doctor.fix.prepare_flash",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoctorItem {
    pub label_key: &'static str,
    pub detail_key: &'static str,
    pub detail_arg: Option<String>,
    pub severity: CheckSeverity,
    pub fix: Option<FixAction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoctorReport {
    pub mode: DoctorMode,
    pub items: Vec<DoctorItem>,
    pub cert_trusted: bool,
}

impl DoctorReport {
    pub fn error_count(&self) -> usize {
        self.items
            .iter()
            .filter(|i| i.severity == CheckSeverity::Error)
            .count()
    }

    pub fn warn_count(&self) -> usize {
        self.items
            .iter()
            .filter(|i| i.severity == CheckSeverity::Warn)
            .count()
    }

    pub fn overall_severity(&self) -> CheckSeverity {
        if self.error_count() > 0 {
            CheckSeverity::Error
        } else if self.warn_count() > 0 {
            CheckSeverity::Warn
        } else {
            CheckSeverity::Ok
        }
    }
}

#[derive(Clone, Debug)]
pub struct DoctorRequest {
    pub mode: DoctorMode,
    pub active: bool,
    pub listen: String,
    pub connection_port: String,
    pub auto_detect: bool,
    pub system_proxy: bool,
    pub system_proxy_pac: bool,
    pub allow_city_helper: bool,
    pub city_key_path: String,
    pub identity_dir: PathBuf,
    pub hosts_path: PathBuf,
}

pub fn find_free_loopback_port() -> Option<u16> {
    TcpListener::bind(("127.0.0.1", 0))
        .ok()
        .and_then(|listener| listener.local_addr().ok())
        .map(|addr| addr.port())
        .filter(|&port| port != 0)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionProfile {
    pub name: String,
    pub mode: DoctorMode,
    pub host: String,
    pub port: String,
    pub listen: String,
    pub auto_detect: bool,
    pub system_proxy: bool,
    pub system_proxy_pac: bool,
    pub nitro_urls: String,
    pub allow_city_helper: bool,
    pub city_key_path: String,
}

impl DoctorMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flash => "flash",
            Self::Origins => "origins",
            Self::Unity => "unity",
            Self::Nitro => "nitro",
            Self::City => "city",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "flash" => Some(Self::Flash),
            "origins" | "shockwave" => Some(Self::Origins),
            "unity" => Some(Self::Unity),
            "nitro" => Some(Self::Nitro),
            "city" | "habbocity" => Some(Self::City),
            _ => None,
        }
    }
}

pub fn builtin_profiles() -> Vec<ConnectionProfile> {
    vec![
        ConnectionProfile {
            name: "HabboCity (PAC)".into(),
            mode: DoctorMode::City,
            host: "habbocity.fr".into(),
            port: "30000".into(),
            listen: "127.0.0.1:9090".into(),
            auto_detect: false,
            system_proxy: true,
            system_proxy_pac: true,
            nitro_urls: String::new(),
            allow_city_helper: true,
            city_key_path: String::new(),
        },
        ConnectionProfile {
            name: "Habbo FR (Flash)".into(),
            mode: DoctorMode::Flash,
            host: "game-fr.habbo.com".into(),
            port: "30000".into(),
            listen: "127.0.0.1:9090".into(),
            auto_detect: true,
            system_proxy: false,
            system_proxy_pac: true,
            nitro_urls: String::new(),
            allow_city_helper: false,
            city_key_path: String::new(),
        },
        ConnectionProfile {
            name: "Habbo Origins".into(),
            mode: DoctorMode::Origins,
            host: "game-od.habbo.com".into(),
            port: "40001".into(),
            listen: "127.0.0.1:9090".into(),
            auto_detect: true,
            system_proxy: false,
            system_proxy_pac: true,
            nitro_urls: String::new(),
            allow_city_helper: false,
            city_key_path: String::new(),
        },
        ConnectionProfile {
            name: "Nitro (PAC)".into(),
            mode: DoctorMode::Nitro,
            host: String::new(),
            port: "30000".into(),
            listen: "127.0.0.1:9090".into(),
            auto_detect: false,
            system_proxy: true,
            system_proxy_pac: true,
            nitro_urls: String::new(),
            allow_city_helper: false,
            city_key_path: String::new(),
        },
    ]
}

pub fn parse_connection_profiles(raw: &str) -> Vec<ConnectionProfile> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(trimmed)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items.into_iter().take(64) {
        let Some(name) = item
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= 80)
        else {
            continue;
        };
        let Some(mode) = item
            .get("mode")
            .and_then(|v| v.as_str())
            .and_then(DoctorMode::parse)
        else {
            continue;
        };
        out.push(ConnectionProfile {
            name: name.to_owned(),
            mode,
            host: item
                .get("host")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
            port: item
                .get("port")
                .and_then(|v| v.as_str())
                .unwrap_or("30000")
                .to_owned(),
            listen: item
                .get("listen")
                .and_then(|v| v.as_str())
                .unwrap_or("127.0.0.1:9090")
                .to_owned(),
            auto_detect: item
                .get("auto_detect")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            system_proxy: item
                .get("system_proxy")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            system_proxy_pac: item
                .get("system_proxy_pac")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            nitro_urls: item
                .get("nitro_urls")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
            allow_city_helper: item
                .get("allow_city_helper")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            city_key_path: item
                .get("city_key_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
        });
    }
    out
}

pub fn serialize_connection_profiles(profiles: &[ConnectionProfile]) -> String {
    let arr: Vec<serde_json::Value> = profiles
        .iter()
        .map(|p| {
            serde_json::json!({
                "name": p.name,
                "mode": p.mode.as_str(),
                "host": p.host,
                "port": p.port,
                "listen": p.listen,
                "auto_detect": p.auto_detect,
                "system_proxy": p.system_proxy,
                "system_proxy_pac": p.system_proxy_pac,
                "nitro_urls": p.nitro_urls,
                "allow_city_helper": p.allow_city_helper,
                "city_key_path": p.city_key_path,
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
}

fn check_port_availability(addr: SocketAddr, active: bool, allow_pick_free: bool) -> DoctorItem {
    if active {
        return DoctorItem {
            label_key: "rust.doctor.check.port",
            detail_key: "rust.doctor.port_active",
            detail_arg: Some(addr.to_string()),
            severity: CheckSeverity::Ok,
            fix: None,
        };
    }
    match TcpListener::bind(addr) {
        Ok(listener) => {
            drop(listener);
            DoctorItem {
                label_key: "rust.doctor.check.port",
                detail_key: "rust.doctor.port_ok",
                detail_arg: Some(addr.to_string()),
                severity: CheckSeverity::Ok,
                fix: None,
            }
        }
        Err(_) => {
            let owner = gearth_platform::process_using_port(addr.port())
                .map(|proc_name| format!("{addr} · {proc_name}"))
                .unwrap_or_else(|| addr.to_string());
            DoctorItem {
                label_key: "rust.doctor.check.port",
                detail_key: "rust.doctor.port_busy",
                detail_arg: Some(owner),
                severity: CheckSeverity::Error,
                fix: allow_pick_free.then_some(FixAction::PickFreePort),
            }
        }
    }
}

fn check_city_config(allow_city_helper: bool, city_key_path: &str) -> DoctorItem {
    let trimmed = city_key_path.trim();
    if !trimmed.is_empty() {
        let mut bytes = Vec::new();
        let valid = File::open(Path::new(trimmed))
            .and_then(|file| {
                file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
                CityKeys::from_json(&bytes)
            })
            .map(|_| ());
        if let Err(err) = valid {
            return DoctorItem {
                label_key: "rust.doctor.check.city",
                detail_key: "rust.doctor.city_key_invalid",
                detail_arg: Some(err.to_string()),
                severity: CheckSeverity::Error,
                fix: Some(FixAction::ClearCityKey),
            };
        }
    }
    if !allow_city_helper {
        DoctorItem {
            label_key: "rust.doctor.check.city",
            detail_key: "rust.doctor.city_helper_off",
            detail_arg: None,
            severity: CheckSeverity::Warn,
            fix: Some(FixAction::EnableCityHelper),
        }
    } else {
        DoctorItem {
            label_key: "rust.doctor.check.city",
            detail_key: "rust.doctor.city_ready",
            detail_arg: None,
            severity: CheckSeverity::Ok,
            fix: None,
        }
    }
}

pub fn run_diagnostics(req: DoctorRequest) -> DoctorReport {
    let mut items = Vec::new();
    let mut cert_trusted = false;

    if req.mode.is_browser() {
        // 1. Proxy CA certificate check
        let cert_item = match ProxyIdentity::ensure(&req.identity_dir) {
            Ok(identity) => match gearth_platform::certificate_trusted(&identity.certificate_der) {
                Ok(true) => {
                    cert_trusted = true;
                    DoctorItem {
                        label_key: "rust.doctor.check.cert",
                        detail_key: "rust.doctor.cert_ok",
                        detail_arg: None,
                        severity: CheckSeverity::Ok,
                        fix: None,
                    }
                }
                Ok(false) => DoctorItem {
                    label_key: "rust.doctor.check.cert",
                    detail_key: "rust.doctor.cert_missing",
                    detail_arg: None,
                    severity: if req.system_proxy {
                        CheckSeverity::Error
                    } else {
                        CheckSeverity::Warn
                    },
                    fix: Some(FixAction::InstallCertificate),
                },
                Err(err) => DoctorItem {
                    label_key: "rust.doctor.check.cert",
                    detail_key: "rust.doctor.cert_error",
                    detail_arg: Some(err.to_string()),
                    severity: CheckSeverity::Warn,
                    fix: Some(FixAction::InstallCertificate),
                },
            },
            Err(err) => DoctorItem {
                label_key: "rust.doctor.check.cert",
                detail_key: "rust.doctor.cert_error",
                detail_arg: Some(err.to_string()),
                severity: CheckSeverity::Error,
                fix: Some(FixAction::InstallCertificate),
            },
        };
        items.push(cert_item);

        // 2. Local proxy port availability
        let port_item = match req.listen.trim().parse::<SocketAddr>() {
            Ok(addr) if addr.port() != 0 => check_port_availability(addr, req.active, true),
            _ => DoctorItem {
                label_key: "rust.doctor.check.port",
                detail_key: "rust.doctor.port_invalid",
                detail_arg: Some(req.listen.trim().to_owned()),
                severity: CheckSeverity::Error,
                fix: Some(FixAction::PickFreePort),
            },
        };
        items.push(port_item);

        // 3. System proxy / PAC routing check
        let proxy_item = if !req.active && gearth_platform::has_stale_system_proxy() {
            DoctorItem {
                label_key: "rust.doctor.check.proxy",
                detail_key: "rust.doctor.proxy_stale",
                detail_arg: None,
                severity: CheckSeverity::Warn,
                fix: Some(FixAction::RestoreProxy),
            }
        } else if !req.system_proxy {
            DoctorItem {
                label_key: "rust.doctor.check.proxy",
                detail_key: "rust.doctor.proxy_off_warn",
                detail_arg: None,
                severity: CheckSeverity::Warn,
                fix: Some(FixAction::EnablePacProxy),
            }
        } else if req.mode != DoctorMode::Unity && !req.system_proxy_pac {
            DoctorItem {
                label_key: "rust.doctor.check.proxy",
                detail_key: "rust.doctor.proxy_full_warn",
                detail_arg: None,
                severity: CheckSeverity::Warn,
                fix: Some(FixAction::EnablePacProxy),
            }
        } else if req.mode == DoctorMode::Unity {
            DoctorItem {
                label_key: "rust.doctor.check.proxy",
                detail_key: "rust.doctor.proxy_sys_ok",
                detail_arg: None,
                severity: CheckSeverity::Ok,
                fix: None,
            }
        } else {
            let scope = if req.mode == DoctorMode::City {
                "*.habbocity.fr"
            } else {
                "Nitro"
            };
            DoctorItem {
                label_key: "rust.doctor.check.proxy",
                detail_key: "rust.doctor.proxy_pac_ok",
                detail_arg: Some(scope.into()),
                severity: CheckSeverity::Ok,
                fix: None,
            }
        };
        items.push(proxy_item);

        // 4. City mode helper & optional key file check
        if req.mode == DoctorMode::City {
            items.push(check_city_config(req.allow_city_helper, &req.city_key_path));
        }
    } else {
        // 1. Administrator / root check
        #[cfg(target_os = "macos")]
        let admin_item = if gearth_platform::is_elevated() {
            DoctorItem {
                label_key: "rust.doctor.check.admin",
                detail_key: "rust.doctor.admin_ok",
                detail_arg: None,
                severity: CheckSeverity::Ok,
                fix: None,
            }
        } else {
            DoctorItem {
                label_key: "rust.doctor.check.admin",
                detail_key: "rust.doctor.admin_macos",
                detail_arg: None,
                severity: CheckSeverity::Warn,
                fix: Some(FixAction::RelaunchAsAdmin),
            }
        };
        #[cfg(not(target_os = "macos"))]
        let admin_item = if gearth_platform::is_elevated() {
            DoctorItem {
                label_key: "rust.doctor.check.admin",
                detail_key: "rust.doctor.admin_ok",
                detail_arg: None,
                severity: CheckSeverity::Ok,
                fix: None,
            }
        } else {
            DoctorItem {
                label_key: "rust.doctor.check.admin",
                detail_key: "rust.doctor.admin_missing",
                detail_arg: None,
                severity: CheckSeverity::Error,
                fix: None,
            }
        };
        items.push(admin_item);

        // 2. Stale hosts file redirects check
        let hosts_item = if !req.active && HostsRedirect::has_stale(&req.hosts_path) {
            DoctorItem {
                label_key: "rust.doctor.check.hosts",
                detail_key: "rust.doctor.hosts_stale",
                detail_arg: None,
                severity: CheckSeverity::Warn,
                fix: Some(FixAction::CleanHosts),
            }
        } else {
            DoctorItem {
                label_key: "rust.doctor.check.hosts",
                detail_key: "rust.doctor.hosts_ok",
                detail_arg: None,
                severity: CheckSeverity::Ok,
                fix: None,
            }
        };
        items.push(hosts_item);

        // 3. Target attachment port availability
        let default_port = if req.mode == DoctorMode::Origins {
            40001u16
        } else {
            30000u16
        };
        let check_ip = if cfg!(target_os = "macos") {
            [127, 0, 0, 1]
        } else {
            [127, 0, 0, 2]
        };
        let port_item = if req.auto_detect {
            check_port_availability(
                SocketAddr::from((check_ip, default_port)),
                req.active,
                false,
            )
        } else {
            match req.connection_port.trim().parse::<u16>() {
                Ok(port) if port != 0 => {
                    check_port_availability(SocketAddr::from((check_ip, port)), req.active, true)
                }
                _ => DoctorItem {
                    label_key: "rust.doctor.check.port",
                    detail_key: "rust.doctor.port_invalid",
                    detail_arg: Some(req.connection_port.trim().to_owned()),
                    severity: CheckSeverity::Error,
                    fix: Some(FixAction::PickFreePort),
                },
            }
        };
        items.push(port_item);

        // 4. macOS Flash client signing check
        #[cfg(target_os = "macos")]
        if req.mode == DoctorMode::Flash {
            if let Ok(status) = gearth_platform::check_macos_flash_client() {
                match status {
                    gearth_platform::MacosFlashPrepStatus::AlreadyPrepared(_) => {
                        items.push(DoctorItem {
                            label_key: "rust.doctor.check.macos_flash",
                            detail_key: "rust.doctor.macos_flash_ok",
                            detail_arg: None,
                            severity: CheckSeverity::Ok,
                            fix: None,
                        });
                    }
                    gearth_platform::MacosFlashPrepStatus::NeedsPreparation(_) => {
                        items.push(DoctorItem {
                            label_key: "rust.doctor.check.macos_flash",
                            detail_key: "rust.doctor.macos_flash_needs_prep",
                            detail_arg: None,
                            severity: CheckSeverity::Warn,
                            fix: Some(FixAction::PrepareMacosFlash),
                        });
                    }
                    gearth_platform::MacosFlashPrepStatus::NotInstalled
                    | gearth_platform::MacosFlashPrepStatus::Unsupported => {}
                }
            }
        }
    }

    DoctorReport {
        mode: req.mode,
        items,
        cert_trusted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_free_port_and_detects_occupied_port() {
        let free = find_free_loopback_port().expect("free port");
        assert!(free > 0);
        let occupied = TcpListener::bind(("127.0.0.1", 0)).expect("bind occupied");
        let addr = occupied.local_addr().unwrap();
        let item = check_port_availability(addr, false, true);
        assert_eq!(item.severity, CheckSeverity::Error);
        assert_eq!(item.detail_key, "rust.doctor.port_busy");
        assert_eq!(item.fix, Some(FixAction::PickFreePort));

        let active_item = check_port_availability(addr, true, true);
        assert_eq!(active_item.severity, CheckSeverity::Ok);
        assert_eq!(active_item.detail_key, "rust.doctor.port_active");
    }

    #[test]
    fn city_config_flags_missing_key_and_disabled_helper() {
        let bad_key = check_city_config(true, "Z:/definitely/does/not/exist-city.key");
        assert_eq!(bad_key.severity, CheckSeverity::Error);
        assert_eq!(bad_key.fix, Some(FixAction::ClearCityKey));

        let off = check_city_config(false, "");
        assert_eq!(off.severity, CheckSeverity::Warn);
        assert_eq!(off.fix, Some(FixAction::EnableCityHelper));

        let ok = check_city_config(true, "");
        assert_eq!(ok.severity, CheckSeverity::Ok);
        assert_eq!(ok.fix, None);
    }

    #[test]
    fn hosts_stale_detection_finds_marked_lines_only() {
        let dir = std::env::temp_dir().join(format!("gearth-doctor-hosts-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost\n").unwrap();
        assert!(!HostsRedirect::has_stale(&path));

        let token = "a".repeat(64);
        std::fs::write(
            &path,
            format!("127.0.0.1 localhost\n127.0.0.1 game-fr.habbo.com # G-Earth-Rust:{token}\n"),
        )
        .unwrap();
        assert!(HostsRedirect::has_stale(&path));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn connection_profiles_roundtrip_and_builtins_cover_modes() {
        let builtins = builtin_profiles();
        assert!(builtins
            .iter()
            .any(|p| p.mode == DoctorMode::City && p.system_proxy_pac));
        assert!(builtins.iter().any(|p| p.mode == DoctorMode::Flash));
        assert!(builtins.iter().any(|p| p.mode == DoctorMode::Origins));
        assert!(builtins.iter().any(|p| p.mode == DoctorMode::Nitro));

        let json = serialize_connection_profiles(&builtins);
        let parsed = parse_connection_profiles(&json);
        assert_eq!(parsed, builtins);
    }
}
