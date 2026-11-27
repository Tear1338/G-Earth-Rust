#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;
mod doctor;
mod gpython_ui;
mod logger_ui;
mod store_ui;
mod theme_ui;
use gearth_rust::{
    connection::Connection,
    crypto::Rc4,
    expression,
    extension_host::{ConnectionDetails, ExtensionHost, HostEvent},
    i18n::{I18n, LANGUAGES},
    injection::{self, InjectionHistory},
    logger_display::{self, PacketRepresentation},
    logger_filter::{AntiSpam, LoggerFilter},
    packet::{Direction, Message, PacketFormat},
    packet_info::PacketInfoManager,
    packet_tools,
    relay::RelayOptions,
    relay::{Config, Event, Relay},
    rules::{Action, Rule, Rules},
    schedule_file,
    scheduler::{ScheduleDraft, ScheduleSpec, Scheduler},
    settings::{ScheduleTemplate, Settings},
    socks::SocksConfig,
    web_ca::ProxyIdentity,
    web_proxy::{fetch_nitro_metadata, WebOptions, WebProxy, NITRO_REVISION},
};
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    io::Read,
    path::{Path, PathBuf},
    process::Child,
    sync::mpsc::Receiver,
    sync::{Arc, OnceLock},
    time::{Duration, Instant, SystemTime},
};
use theme_ui::{
    dark_mode_pill_switch, format_hex_color, group_box, icon_action, parse_hex_color,
    parse_interval_spec, tab_button, vector_icon_button, vector_text_button, AppTheme, ThemeLogos,
    VectorIcon, ACCENT_PRESETS,
};

// Both lazy prediction caches count against the capture byte budget.
const LOG_PREDICTION_LIMIT: usize = 1024;

fn configured_socks(
    enabled: bool,
    proxy: &str,
    user: &str,
    password: &str,
) -> std::io::Result<Option<SocksConfig>> {
    if !enabled {
        return Ok(None);
    }
    let proxy = proxy.trim();
    let (host, port) = proxy
        .rsplit_once(':')
        .ok_or_else(|| std::io::Error::other("SOCKS5 proxy requires host:port"))?;
    let valid_host = if let Some(ip) = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        ip.parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        !host.is_empty()
            && !host.contains(['[', ']', ':'])
            && !host.chars().any(char::is_whitespace)
    };
    if !valid_host || !port.parse::<u16>().is_ok_and(|port| port != 0) {
        return Err(std::io::Error::other(
            "SOCKS5 proxy requires a valid host and port",
        ));
    }
    let credentials = if user.is_empty() && password.is_empty() {
        None
    } else if user.is_empty() || password.is_empty() || user.len() > 255 || password.len() > 255 {
        return Err(std::io::Error::other(
            "SOCKS5 username and password must both be 1–255 bytes",
        ));
    } else {
        Some((user.to_owned(), password.to_owned()))
    };
    Ok(Some(SocksConfig {
        proxy: proxy.to_owned(),
        credentials,
    }))
}

#[cfg(test)]
mod socks_settings_tests {
    use super::configured_socks;

    #[test]
    fn validates_proxy_and_preserves_optional_credentials() {
        assert!(configured_socks(false, "bad", "user", "")
            .unwrap()
            .is_none());
        let configured = configured_socks(true, " localhost:1080 ", "user:name", "p@ss")
            .unwrap()
            .unwrap();
        assert_eq!(configured.proxy, "localhost:1080");
        assert_eq!(
            configured.credentials.unwrap(),
            ("user:name".into(), "p@ss".into())
        );
        assert!(configured_socks(true, "[::1]:1080", "", "")
            .unwrap()
            .unwrap()
            .credentials
            .is_none());
        for proxy in [
            "",
            "localhost",
            ":1080",
            "localhost:0",
            "localhost:65536",
            "::1:1080",
            "[bad]:1080",
            "bad host:1080",
        ] {
            assert!(configured_socks(true, proxy, "", "").is_err(), "{proxy}");
        }
        assert!(configured_socks(true, "localhost:1080", "user", "").is_err());
        assert!(configured_socks(true, "localhost:1080", "", "password").is_err());
        assert!(configured_socks(true, "localhost:1080", &"é".repeat(128), "password").is_err());
    }
}

fn browse_path(
    ui: &mut egui::Ui,
    path: &mut String,
    kind: gearth_platform::FileKind,
    save: bool,
    i18n: &I18n,
    status: &mut String,
) {
    let label = if save {
        "rust.dialog.choose_save"
    } else {
        "rust.dialog.browse"
    };
    if ui.button(i18n.text(label)).clicked() {
        match gearth_platform::choose_file(kind, save) {
            Ok(Some(selected)) => match selected.into_os_string().into_string() {
                Ok(selected) => *path = selected,
                Err(_) => *status = i18n.text("rust.dialog.invalid_path"),
            },
            Ok(None) => {}
            Err(error) => *status = format!("{}: {error}", i18n.text("rust.dialog.failed")),
        }
    }
}

fn with_gearth_icon(viewport: egui::ViewportBuilder) -> egui::ViewportBuilder {
    static ICON: OnceLock<Option<Arc<egui::IconData>>> = OnceLock::new();
    match ICON.get_or_init(|| {
        eframe::icon_data::from_png_bytes(include_bytes!("../resources/g_earth_icon.png"))
            .ok()
            .map(Arc::new)
    }) {
        Some(icon) => viewport.with_icon(icon.clone()),
        None => viewport,
    }
}

#[cfg(test)]
mod window_icon_tests {
    use super::*;

    #[test]
    fn original_icon_decodes_and_is_reused_for_native_windows() {
        let main = with_gearth_icon(egui::ViewportBuilder::default())
            .icon
            .unwrap();
        let logger = with_gearth_icon(egui::ViewportBuilder::default())
            .icon
            .unwrap();
        assert_eq!((main.width, main.height), (64, 64));
        assert_eq!(main.rgba.len(), 64 * 64 * 4);
        assert!(Arc::ptr_eq(&main, &logger));
    }

    #[test]
    fn themes_resolve_tanji_and_preserve_legacy_dark_mode_fallback() {
        assert_eq!(
            AppTheme::from_settings(Some("Tanji"), false),
            AppTheme::Tanji
        );
        assert_eq!(
            AppTheme::from_settings(Some("G-Earth Dark"), false),
            AppTheme::GEarthDark
        );
        assert_eq!(
            AppTheme::from_settings(Some("G-Earth"), true),
            AppTheme::GEarth
        );
        assert_eq!(AppTheme::from_settings(None, true), AppTheme::GEarthDark);
        assert_eq!(AppTheme::from_settings(None, false), AppTheme::GEarth);
        assert_ne!(
            AppTheme::Tanji.visuals().panel_fill,
            AppTheme::GEarth.visuals().panel_fill
        );
        assert!(!AppTheme::Tanji.visuals().dark_mode);
        assert!(AppTheme::GEarthDark.visuals().dark_mode);
        assert_eq!(
            AppTheme::from_settings(Some("Fluxer"), false),
            AppTheme::Fluxer
        );
        assert!(AppTheme::Fluxer.visuals().dark_mode);
        assert_eq!(
            AppTheme::Fluxer.palette().primary_accent,
            egui::Color32::from_rgb(0x46, 0x41, 0xd9)
        );
        assert_eq!(AppTheme::Fluxer.extension_theme_name(), "G-Earth Dark");
        let custom = egui::Color32::from_rgb(0x22, 0xa0, 0x6b);
        assert_eq!(
            super::parse_hex_color(&super::format_hex_color(custom)),
            Some(custom)
        );
        assert_eq!(
            AppTheme::Fluxer
                .palette_with_accent(Some(custom))
                .primary_accent,
            custom
        );
    }
}

fn bounded_log_prediction(mut value: String) -> String {
    if value.len() > LOG_PREDICTION_LIMIT {
        let mut end = LOG_PREDICTION_LIMIT - "…".len();
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
        value.push('…');
    }
    value.shrink_to_fit();
    value
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CliClientMode {
    Flash,
    Origins,
    Unity,
    Nitro,
    City,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LaunchArgs {
    connect_client: Option<CliClientMode>,
    host: Option<String>,
    port: Option<u16>,
    debug_stdout: bool,
    theme: Option<AppTheme>,
}

fn parse_cli_client_mode(raw: &str) -> Option<CliClientMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "flash" => Some(CliClientMode::Flash),
        "origins" | "shockwave" => Some(CliClientMode::Origins),
        "unity" => Some(CliClientMode::Unity),
        "nitro" => Some(CliClientMode::Nitro),
        "city" | "habbocity" => Some(CliClientMode::City),
        _ => None,
    }
}

fn parse_cli_theme(raw: &str) -> Option<AppTheme> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "tanji" => Some(AppTheme::Tanji),
        "fluxer" => Some(AppTheme::Fluxer),
        "dark" | "g-earth dark" | "gearth-dark" => Some(AppTheme::GEarthDark),
        "light" | "g-earth" | "gearth" => Some(AppTheme::GEarth),
        _ => None,
    }
}

fn parse_cli_args(args: &[String]) -> LaunchArgs {
    let mut parsed = LaunchArgs::default();
    let mut idx = 0usize;
    while idx < args.len() {
        let arg = args[idx].as_str();
        if let Some(val) = arg
            .strip_prefix("--connect=")
            .or_else(|| arg.strip_prefix("-c="))
        {
            if let Some(mode) = parse_cli_client_mode(val) {
                parsed.connect_client = Some(mode);
            }
        } else if arg == "--connect" || arg == "-c" {
            if let Some(next) = args.get(idx + 1) {
                if let Some(mode) = parse_cli_client_mode(next) {
                    parsed.connect_client = Some(mode);
                    idx += 1;
                }
            }
        } else if let Some(val) = arg.strip_prefix("--host=") {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                parsed.host = Some(trimmed.to_owned());
            }
        } else if arg == "--host" {
            if let Some(next) = args.get(idx + 1) {
                let trimmed = next.trim();
                if !trimmed.is_empty() {
                    parsed.host = Some(trimmed.to_owned());
                }
                idx += 1;
            }
        } else if let Some(val) = arg.strip_prefix("--port=") {
            if let Ok(port) = val.trim().parse::<u16>() {
                if port != 0 {
                    parsed.port = Some(port);
                }
            }
        } else if arg == "--port" {
            if let Some(next) = args.get(idx + 1) {
                if let Ok(port) = next.trim().parse::<u16>() {
                    if port != 0 {
                        parsed.port = Some(port);
                    }
                }
                idx += 1;
            }
        } else if arg == "--debug" || arg == "-d" {
            parsed.debug_stdout = true;
        } else if let Some(val) = arg
            .strip_prefix("--theme=")
            .or_else(|| arg.strip_prefix("-t="))
        {
            if let Some(theme) = parse_cli_theme(val) {
                parsed.theme = Some(theme);
            }
        } else if arg == "-t" || arg == "--theme" {
            if let Some(next) = args.get(idx + 1) {
                if let Some(theme) = parse_cli_theme(next) {
                    parsed.theme = Some(theme);
                    idx += 1;
                }
            }
        }
        idx += 1;
    }
    parsed
}

fn main() -> eframe::Result<()> {
    gearth_rust::update_checker::cleanup_old_binary();
    let initial_title = format!(
        "G-Earth 1.5.4-beta-29 (G-Earth-Rust · {})",
        gearth_rust::update_checker::current_build_tag()
    );
    eframe::run_native(
        &initial_title,
        eframe::NativeOptions {
            viewport: with_gearth_icon(
                egui::ViewportBuilder::default()
                    .with_inner_size([740.0, 470.0])
                    .with_min_inner_size([700.0, 380.0]),
            ),
            ..Default::default()
        },
        Box::new(|_| Ok(Box::<Desktop>::default())),
    )
}
#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Connection,
    Logger,
    Injection,
    Scheduler,
    Tools,
    Extensions,
    Extra,
    Info,
}
struct Desktop {
    tab: Tab,
    always_on_top: bool,
    always_on_top_applied: bool,
    admin_warning_open: bool,
    listen: String,
    remote: String,
    status: String,
    relay: Option<Connection>,
    events: Option<Receiver<Event>>,
    logs: VecDeque<LogRow>,
    filter: String,
    logger_search_cache: Option<(String, HashSet<(Direction, u16)>)>,
    outgoing: bool,
    incoming: bool,
    paused: bool,
    packet_limit: usize,
    logger_additional: bool,
    logger_structure: bool,
    logger_java_structure_limit: bool,
    logger_java_structure_clean: bool,
    logger_split: bool,
    logger_export_separators: bool,
    logger_export_hide_empty_header: bool,
    logger_display_hide_empty_header: bool,
    logger_names: bool,
    logger_hashes: bool,
    logger_message_id: bool,
    logger_friendly: bool,
    selected_log_index: Option<i32>,
    logger_representation: PacketRepresentation,
    logger_extra_legacy: bool,
    logger_extra_raw_hex: bool,
    logger_extra_hex_dump: bool,
    logger_skip_big: bool,
    logger_timestamp: bool,
    logger_autoscroll: bool,
    logger_capture_selected_only: bool,
    logger_clear_on_connect: bool,
    logger_clear_on_disconnect: bool,
    logger_window: logger_display::LoggerWindow,
    logger_connection_active: bool,
    logger_antispam: AntiSpam,
    logger_filter: LoggerFilter,
    logger_filtered: u64,
    logger_hide_noisy: bool,
    logger_hidden_headers: HashSet<(Direction, u16)>,
    logger_presets: Vec<logger_ui::LoggerFilterPreset>,
    logger_preset_name: String,
    logger_stats: logger_ui::LoggerStats,
    logger_show_stats: bool,
    custom_packet_names: Vec<(Direction, u16, String)>,
    custom_names_window_open: bool,
    custom_name_direction: Direction,
    custom_name_header: u16,
    custom_name_input: String,
    rename_header_dialog: Option<(Direction, u16, String)>,
    diff_base: Option<logger_ui::PacketSnapshot>,
    diff_pair: Option<(logger_ui::PacketSnapshot, logger_ui::PacketSnapshot)>,
    packet_dump: Option<String>,
    expression: String,
    direction: Direction,
    injection_history: InjectionHistory,
    injection_favorites: Vec<logger_ui::InjectionFavorite>,
    injection_right_tab_favorites: bool,
    injection_fav_name: String,
    builder_field_kind: String,
    builder_field_value: String,
    schedule_draft: ScheduleDraft,
    interval_ms: u64,
    align_schedule: bool,
    schedule_offset_ms: u64,
    repeat: u32,
    repeat_forever: bool,
    schedule_edit: Option<usize>,
    active_schedule_edit: Option<u64>,
    schedule_path: String,
    scheduler: Scheduler,
    scheduler_auto_start: bool,
    scheduler_hotkeys: Option<gearth_platform::GlobalHotkeys>,
    system_tray: Option<gearth_platform::SystemTray>,
    tray_initialized: bool,
    custom_hotels: Vec<String>,
    auto_update: bool,
    startup_update_checked: bool,
    update_task: Option<Receiver<std::io::Result<gearth_rust::update_checker::UpdateInfo>>>,
    update_result: Option<Result<gearth_rust::update_checker::UpdateInfo, String>>,
    update_apply_task:
        Option<Receiver<std::io::Result<gearth_rust::update_checker::UpdateApplyOutcome>>>,
    update_apply_error: Option<String>,
    update_close_requested: bool,
    block_header: u16,
    block_enabled: bool,
    block_direction: Direction,
    editing_saved_rule: Option<usize>,
    rule_errors: Vec<(usize, String)>,
    tool_input: String,
    tool_output: String,
    tool_int: String,
    tool_int_encoded: String,
    tool_ushort: String,
    tool_ushort_encoded: String,
    export_path: String,
    total: u64,
    display_dropped: u64,
    extension_host: Option<Arc<ExtensionHost>>,
    extension_events: Option<Receiver<HostEvent>>,
    extension_runtime: String,
    extension_path: String,
    extension_install_permanent: bool,
    extensions_autostarted: bool,
    extension_autostart_rx: Option<Receiver<std::io::Result<Child>>>,
    extension_processes: Vec<Child>,
    extension_launch_task: Option<Receiver<std::io::Result<Child>>>,
    extension_console: VecDeque<String>,
    known_installed_extensions: BTreeMap<String, gearth_rust::extension::ExtensionInfo>,
    confirm_uninstall_extension: bool,
    confirm_uninstall_ext: Option<(Option<u64>, String, String)>,
    confirm_uninstall_dont_ask: bool,
    pending_ext_approvals: VecDeque<(u64, gearth_rust::extension::ExtensionInfo)>,
    remember_ext_approval: Option<bool>,
    remember_ext_approval_box: bool,
    launch_args_auto_connect: bool,
    hotel_version: String,
    client_identifier: String,
    packet_database: String,
    packet_info: PacketInfoManager,
    packet_safety: Arc<std::sync::Mutex<gearth_rust::packet_safety::PacketSafety>>,
    admin_service: Arc<std::sync::Mutex<gearth_rust::admin_service::AdminService>>,
    always_admin: bool,
    python_enabled: bool,
    developer_mode: bool,
    developer_mode_confirmation: bool,
    advanced_options: bool,
    disable_decryption: bool,
    debug_stdout: bool,
    socks_proxy: String,
    socks_enabled: bool,
    socks_user: String,
    socks_password: String,
    outgoing_key: String,
    incoming_key: String,
    settings: Settings,
    settings_path: PathBuf,
    settings_loaded: bool,
    legacy_cache_path: String,
    theme: AppTheme,
    custom_accent: Option<egui::Color32>,
    accent_picker_open: bool,
    language: String,
    i18n: I18n,
    notepad: String,
    logs_bytes: usize,
    replacement_expression: String,
    origins: bool,
    nitro: bool,
    unity: bool,
    city: bool,
    system_proxy: bool,
    system_proxy_pac: bool,
    proxy_guard: Option<gearth_platform::SystemProxyGuard>,
    public_certificate: Option<(PathBuf, Vec<u8>)>,
    certificate_task: Option<Receiver<std::io::Result<String>>>,
    nitro_urls: String,
    allow_city_helper: bool,
    city_key_path: String,
    flash_auto: bool,
    flash_pid: u32,
    client_processes: Vec<gearth_platform::ClientProcess>,
    attachment_host: String,
    attachment_pending: Option<Receiver<std::io::Result<gearth_rust::attachment::Attachment>>>,
    attachment_worker: Option<std::thread::JoinHandle<()>>,
    redirect: Option<gearth_rust::attachment::AttachmentRedirect>,
    packet_download: Option<Receiver<std::io::Result<PacketInfoManager>>>,
    store: store_ui::StoreUi,
    python_console: gpython_ui::PythonUi,
    auto_detect: bool,
    connection_port: String,
    connected_endpoint: Option<String>,
    connection_error: Option<String>,
    doctor_report: Option<doctor::DoctorReport>,
    doctor_task: Option<Receiver<doctor::DoctorReport>>,
    doctor_expanded: bool,
    #[cfg(target_os = "macos")]
    relaunch_admin_task: Option<Receiver<std::io::Result<()>>>,
    connection_profiles: Vec<doctor::ConnectionProfile>,
    active_profile_name: String,
    new_profile_name: String,
    last_saved_settings_hash: Option<u64>,
    settings_dirty_since: Option<Instant>,
    schedule_interval_input: String,
    ext_console_open: bool,
    ext_store_open: bool,
    ext_install_open: bool,
    ext_gpython_open: bool,
    donate_dialog_open: bool,
    last_window_title: String,
    logos: Option<ThemeLogos>,
}
struct LogRow {
    message: Message,
    timestamp_ms: Option<u64>,
    expression: String,
    search: String,
    bytes: usize,
    skipped: bool,
    unity: bool,
    predicted_structure: OnceLock<String>,
    packet_expression: OnceLock<(String, bool, bool)>,
    packet_metadata: OnceLock<(String, String)>,
}
fn invalidate_log_expressions(logs: &mut VecDeque<LogRow>) {
    for row in logs {
        row.packet_expression.take();
        row.packet_metadata.take();
    }
}
fn clear_log_contents(logs: &mut VecDeque<LogRow>, bytes: &mut usize) {
    logs.clear();
    *bytes = 0;
}
fn matching_packet_metadata(info: &PacketInfoManager, filter: &str) -> HashSet<(Direction, u16)> {
    if filter.is_empty() {
        return HashSet::new();
    }
    info.entries()
        .iter()
        .filter(|entry| {
            [&entry.name, &entry.hash]
                .into_iter()
                .flatten()
                .any(|s| s.to_lowercase().contains(filter))
        })
        .map(|entry| (entry.direction, entry.header))
        .collect()
}
fn log_row_matches(
    row: &LogRow,
    filter: &str,
    metadata: &HashSet<(Direction, u16)>,
    outgoing: bool,
    incoming: bool,
) -> bool {
    let message = &row.message;
    let visible = match message.direction {
        Direction::ToServer => outgoing,
        Direction::ToClient => incoming,
    };
    visible
        && (filter.is_empty()
            || row.search.contains(filter)
            || metadata.contains(&(message.direction, message.packet.header())))
}
fn log_packet_metadata(
    info: &PacketInfoManager,
    direction: Direction,
    header: u16,
) -> (String, String) {
    let mut names = Vec::new();
    let mut hashes = Vec::new();
    let mut name_len = 0;
    let mut hash_len = 0;
    for item in info.by_header(direction, header) {
        if let Some(name) = item.name.as_deref() {
            if name_len < LOG_PREDICTION_LIMIT && !names.contains(&name) {
                name_len += name.len() + 3;
                names.push(name);
            }
        }
        if let Some(hash) = item.hash.as_deref() {
            if hash_len < LOG_PREDICTION_LIMIT && !hashes.contains(&hash) {
                hash_len += hash.len() + 3;
                hashes.push(hash);
            }
        }
        if name_len >= LOG_PREDICTION_LIMIT && hash_len >= LOG_PREDICTION_LIMIT {
            break;
        }
    }
    (
        bounded_log_prediction(names.join("][")),
        bounded_log_prediction(hashes.join("][")),
    )
}

#[derive(Clone, Copy)]
struct LogDisplayOptions<'a> {
    additional: bool,
    names: bool,
    hashes: bool,
    message_id: bool,
    representation: PacketRepresentation,
    extra_legacy: bool,
    extra_raw_hex: bool,
    extra_hex_dump: bool,
    skip_big: bool,
    skipped_label: &'a str,
    timestamp: bool,
    timestamp_label: &'a str,
    blocked_label: &'a str,
    replaced_label: &'a str,
    incoming_label: &'a str,
    outgoing_label: &'a str,
    structure: bool,
    java_structure_limit: bool,
    java_structure_clean: bool,
    export_hide_empty_header: bool,
}

struct RenderedLogRow {
    timestamp: Option<String>,
    metadata: Option<String>,
    marker: Option<String>,
    header: String,
    extra_representations: Vec<String>,
    dump: Option<String>,
    extra_raw_hex: Option<String>,
    structure: Option<String>,
}

fn logger_row_response(
    inner: egui::Response,
    outer: egui::Response,
    hidden: bool,
) -> egui::Response {
    if hidden {
        inner.union(outer.interact(egui::Sense::click()))
    } else {
        inner
    }
}

// beta-29 colors incoming traffic red, outgoing traffic blue, and both
// blocked/replaced markers yellow. Darker variants remain legible on light UI.
fn log_colors(direction: Direction, dark: bool) -> (egui::Color32, egui::Color32, egui::Color32) {
    let (normal, hex) = match (direction, dark) {
        (Direction::ToClient, true) => (
            egui::Color32::from_rgb(178, 34, 34),
            egui::Color32::from_rgb(240, 98, 98),
        ),
        (Direction::ToServer, true) => (
            egui::Color32::from_rgb(0, 102, 204),
            egui::Color32::from_rgb(79, 183, 247),
        ),
        (Direction::ToClient, false) => (
            egui::Color32::from_rgb(155, 30, 30),
            egui::Color32::from_rgb(155, 30, 30),
        ),
        (Direction::ToServer, false) => (
            egui::Color32::from_rgb(0, 75, 155),
            egui::Color32::from_rgb(0, 75, 155),
        ),
    };
    let marker = if dark {
        egui::Color32::YELLOW
    } else {
        egui::Color32::from_rgb(130, 70, 0)
    };
    (normal, hex, marker)
}

fn log_header_layout(
    header: &str,
    marker: Option<&str>,
    normal: egui::Color32,
    highlight: egui::Color32,
    size: f32,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let format = |color| egui::TextFormat {
        font_id: egui::FontId::monospace(size),
        color,
        ..Default::default()
    };
    if let Some((start, text)) =
        marker.and_then(|text| header.find(text).map(|start| (start, text)))
    {
        job.append(&header[..start], 0.0, format(normal));
        job.append(text, 0.0, format(highlight));
        job.append(&header[start + text.len()..], 0.0, format(normal));
    } else {
        job.append(header, 0.0, format(normal));
    }
    job
}

fn render_log_row(
    row: &LogRow,
    info: &PacketInfoManager,
    options: LogDisplayOptions<'_>,
) -> RenderedLogRow {
    let message = &row.message;
    let packet = &message.packet;
    let additional = if options.additional {
        let length = if packet.format() == PacketFormat::EvaWire {
            packet.bytes().len().saturating_sub(4)
        } else {
            packet.bytes().len()
        };
        format!("(h: {}, l: {length})  ", packet.header())
    } else {
        String::new()
    };
    let mut metadata = String::new();
    if options.names || options.hashes {
        let (names, hashes) = row
            .packet_metadata
            .get_or_init(|| log_packet_metadata(info, message.direction, packet.header()));
        if options.names && !names.is_empty() {
            metadata.push_str(&format!("[{names}]"));
        }
        if options.hashes && !hashes.is_empty() {
            metadata.push_str(&format!("[{hashes}]"));
        }
    }
    if options.message_id {
        metadata.push_str(&format!("[{}]", packet.header()));
    }
    let has_byte_representation = !matches!(
        options.representation,
        PacketRepresentation::Expression | PacketRepresentation::NoBytes
    ) || options.extra_legacy
        || options.extra_raw_hex
        || options.extra_hex_dump;
    let omit_representations = options.skip_big
        && has_byte_representation
        && logger_display::skip_java_packet_representations(
            packet.format(),
            packet.bytes().len(),
            options.representation == PacketRepresentation::HexDump || options.extra_hex_dump,
        );
    let inline_dump = !omit_representations
        && (options.representation == PacketRepresentation::HexDump || options.extra_hex_dump)
        && !row.skipped;
    let representation = if row.skipped
        || (omit_representations && options.representation == PacketRepresentation::Expression)
    {
        std::borrow::Cow::Borrowed(row.expression.as_str())
    } else if omit_representations {
        std::borrow::Cow::Borrowed(options.skipped_label)
    } else if options.representation == PacketRepresentation::HexDump && !row.skipped {
        std::borrow::Cow::Borrowed("")
    } else if row.skipped || options.representation == PacketRepresentation::Expression {
        std::borrow::Cow::Borrowed(row.expression.as_str())
    } else {
        std::borrow::Cow::Owned(logger_display::represent(
            packet.bytes(),
            options.representation,
            1024,
        ))
    };
    let timestamp = options
        .timestamp
        .then_some(row.timestamp_ms)
        .flatten()
        .map(|ms| format!("({}: {ms})", options.timestamp_label));
    let marker = if message.blocked {
        Some(format!("[{}]", options.blocked_label))
    } else if packet.edited {
        Some(format!("[{}]", options.replaced_label))
    } else {
        None
    };
    let header = format!(
        "#{:06}  {} {}  {}{}",
        message.index,
        if message.direction == Direction::ToServer {
            "→"
        } else {
            "←"
        },
        if message.direction == Direction::ToServer {
            options.outgoing_label
        } else {
            options.incoming_label
        },
        additional,
        representation
    );
    let dump = inline_dump.then(|| logger_display::hex_dump(packet.bytes(), 128));
    let mut extra_representations = Vec::new();
    let mut extra_raw_hex = None;
    if !row.skipped
        && omit_representations
        && options.representation == PacketRepresentation::Expression
    {
        extra_representations.push(options.skipped_label.into());
    }
    if !row.skipped && !omit_representations {
        for (enabled, mode) in [
            (options.extra_legacy, PacketRepresentation::Legacy),
            (options.extra_raw_hex, PacketRepresentation::RawHex),
        ] {
            if enabled && options.representation != mode {
                let text = format!(
                    "{}: {}",
                    mode.name(),
                    logger_display::represent(packet.bytes(), mode, 1024)
                );
                if mode == PacketRepresentation::RawHex {
                    extra_raw_hex = Some(text);
                } else {
                    extra_representations.push(text);
                }
            }
        }
    }
    let structure = if options.structure
        && !row.skipped
        && logger_display::allow_java_packet_structure(
            packet.format(),
            packet.bytes().len(),
            options.java_structure_limit,
        ) {
        let (expression, known, clean) = row.packet_expression.get_or_init(|| {
            let (expression, known) = gearth_rust::structure_prediction::expression_with_metadata(
                packet,
                message.direction,
                info,
                row.unity,
            )
            .unwrap_or_default();
            let clean = logger_display::java_structure_is_clean(&expression);
            (bounded_log_prediction(expression), known, clean)
        });
        (!expression.is_empty() && (!options.java_structure_clean || *clean)).then(|| {
            format!(
                "{}: {expression}",
                if *known { "Structure" } else { "Predicted" }
            )
        })
    } else {
        None
    };
    RenderedLogRow {
        timestamp,
        metadata: (!metadata.is_empty()).then_some(metadata),
        marker,
        header,
        extra_representations,
        dump,
        extra_raw_hex,
        structure,
    }
}

// Java exports every distinct name, then every distinct hash, in metadata order.
// The interactive logger deliberately keeps a bounded cache, so export must
// read directly from the packet catalog instead of reusing that cache.
fn write_log_metadata(
    output: &mut impl std::io::Write,
    row: &LogRow,
    info: &PacketInfoManager,
    options: LogDisplayOptions<'_>,
) -> std::io::Result<()> {
    let packet = &row.message.packet;
    let mut wrote = false;
    for names in [true, false] {
        if (names && !options.names) || (!names && !options.hashes) {
            continue;
        }
        let mut seen = HashSet::new();
        for item in info.by_header(row.message.direction, packet.header()) {
            let value = if names {
                item.name.as_deref()
            } else {
                item.hash.as_deref()
            };
            if let Some(value) = value {
                if seen.insert(value) {
                    write!(output, "[{value}]")?;
                    wrote = true;
                }
            }
        }
    }
    if options.message_id {
        write!(output, "[{}]", packet.header())?;
        wrote = true;
    }
    if wrote {
        writeln!(output)?;
    }
    Ok(())
}

fn write_log_capture<'a>(
    mut output: impl std::io::Write,
    rows: impl IntoIterator<Item = &'a LogRow>,
    info: &PacketInfoManager,
    options: LogDisplayOptions<'_>,
    split: bool,
) -> std::io::Result<()> {
    for row in rows {
        let rendered = render_log_row(row, info, options);
        if let Some(timestamp) = rendered.timestamp {
            writeln!(output, "{timestamp}")?;
        }
        write_log_metadata(&mut output, row, info, options)?;
        if let Some(marker) = rendered.marker {
            writeln!(output, "{marker}")?;
        }
        // Java's byte views export the same text shown by its packet logger.
        // The Rust-only expression view keeps its existing enriched layout.
        if options.representation != PacketRepresentation::Expression
            && !(options.representation == PacketRepresentation::NoBytes
                && !options.export_hide_empty_header
                && !options.extra_legacy
                && !options.extra_raw_hex
                && !options.extra_hex_dump)
        {
            let packet = &row.message.packet;
            let legacy =
                options.representation == PacketRepresentation::Legacy || options.extra_legacy;
            let hex =
                options.representation == PacketRepresentation::HexDump || options.extra_hex_dump;
            let raw =
                options.representation == PacketRepresentation::RawHex || options.extra_raw_hex;
            if legacy || hex || raw {
                let skipped = options.skip_big
                    && logger_display::skip_java_packet_representations(
                        packet.format(),
                        packet.bytes().len(),
                        hex,
                    );
                if skipped {
                    write!(output, "{}", options.skipped_label)?;
                } else {
                    let direction = if row.message.direction == Direction::ToClient {
                        options.incoming_label
                    } else {
                        options.outgoing_label
                    };
                    write!(output, "{direction}[{}] -> ", packet.header())?;
                    if legacy {
                        writeln!(
                            output,
                            "{}",
                            logger_display::represent(
                                packet.bytes(),
                                PacketRepresentation::Legacy,
                                usize::MAX
                            )
                        )?;
                    }
                    if hex {
                        writeln!(
                            output,
                            "{}",
                            logger_display::hex_dump(packet.bytes(), usize::MAX)
                        )?;
                    }
                    if raw {
                        writeln!(
                            output,
                            "{}",
                            logger_display::represent(
                                packet.bytes(),
                                PacketRepresentation::RawHex,
                                usize::MAX
                            )
                        )?;
                    }
                }
            }
            // The on-screen cache is bounded for responsiveness; exports must not
            // silently truncate an otherwise valid Java-sized structure.
            if options.structure
                && logger_display::allow_java_packet_structure(
                    packet.format(),
                    packet.bytes().len(),
                    options.java_structure_limit,
                )
            {
                let (text, _) = gearth_rust::structure_prediction::expression_with_metadata(
                    packet,
                    row.message.direction,
                    info,
                    row.unity,
                )
                .unwrap_or_default();
                if !text.is_empty()
                    && (!options.java_structure_clean
                        || logger_display::java_structure_is_clean(&text))
                {
                    writeln!(output, "{text}")?;
                }
            }
            if split {
                writeln!(output, "--------------------")?;
            }
            continue;
        }
        if !logger_display::hide_empty_byte_header(
            options.export_hide_empty_header,
            options.representation,
            options.extra_legacy,
            options.extra_hex_dump,
            options.extra_raw_hex,
        ) {
            writeln!(output, "{}", rendered.header)?;
        }
        for representation in rendered.extra_representations {
            writeln!(output, "{representation}")?;
        }
        if let Some(dump) = rendered.dump {
            writeln!(output, "{dump}")?;
        }
        if let Some(raw_hex) = rendered.extra_raw_hex {
            writeln!(output, "{raw_hex}")?;
        }
        if let Some(structure) = rendered.structure {
            writeln!(output, "{structure}")?;
        }
        if split {
            writeln!(output, "--------------------")?;
        }
    }
    output.flush()
}
fn parse_custom_hotels(raw: &str) -> Vec<String> {
    let mut hotels = Vec::new();
    for line in raw.lines() {
        let host = line.trim();
        if !host.is_empty()
            && !hotels
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(host))
        {
            hotels.push(host.to_owned());
        }
    }
    hotels
}

fn combine_rules(
    mut saved: Vec<Rule>,
    draft: gearth_rust::packet::Result<Option<Rule>>,
) -> (Rules, Option<gearth_rust::packet::PacketError>) {
    let error = match draft {
        Ok(Some(rule)) => {
            saved.push(rule);
            None
        }
        Ok(None) => None,
        Err(error) => Some(error),
    };
    (Rules { entries: saved }, error)
}
impl Default for Desktop {
    fn default() -> Self {
        let host = (9092..=9107).find_map(|port| {
            ExtensionHost::start(
                format!("127.0.0.1:{port}").parse().unwrap(),
                std::env::args().skip(1).collect(),
            )
            .ok()
        });
        let (extension_host, extension_events) = match host {
            Some((h, e)) => (Some(h), Some(e)),
            None => (None, None),
        };
        let mut desktop = Self {
            tab: Tab::Connection,
            always_on_top: false,
            always_on_top_applied: false,
            admin_warning_open: false,
            python_console: gpython_ui::PythonUi::default(),
            listen: "127.0.0.1:1234".into(),
            remote: "".into(),
            status: "Disconnected".into(),
            relay: None,
            events: None,
            logs: VecDeque::new(),
            filter: String::new(),
            logger_search_cache: None,
            outgoing: true,
            incoming: true,
            paused: false,
            packet_limit: 8000,
            logger_additional: true,
            logger_structure: true,
            logger_java_structure_limit: false,
            logger_java_structure_clean: false,
            logger_split: true,
            logger_export_separators: false,
            logger_export_hide_empty_header: false,
            logger_display_hide_empty_header: false,
            logger_names: true,
            logger_hashes: false,
            logger_message_id: false,
            logger_friendly: true,
            selected_log_index: None,
            logger_representation: PacketRepresentation::Expression,
            logger_extra_legacy: false,
            logger_extra_raw_hex: false,
            logger_extra_hex_dump: false,
            logger_skip_big: false,
            logger_timestamp: false,
            logger_autoscroll: true,
            logger_capture_selected_only: false,
            logger_clear_on_connect: false,
            logger_clear_on_disconnect: false,
            logger_window: logger_display::LoggerWindow::default(),
            logger_connection_active: false,
            logger_antispam: AntiSpam::None,
            logger_filter: LoggerFilter::default(),
            logger_filtered: 0,
            logger_hide_noisy: false,
            logger_hidden_headers: HashSet::new(),
            logger_presets: Vec::new(),
            logger_preset_name: String::new(),
            logger_stats: logger_ui::LoggerStats::default(),
            logger_show_stats: false,
            custom_packet_names: Vec::new(),
            custom_names_window_open: false,
            custom_name_direction: Direction::ToClient,
            custom_name_header: 0,
            custom_name_input: String::new(),
            rename_header_dialog: None,
            diff_base: None,
            diff_pair: None,
            packet_dump: None,
            expression: "{h:123}{i:42}{s:\"hello\"}".into(),
            direction: Direction::ToServer,
            injection_history: InjectionHistory::default(),
            injection_favorites: Vec::new(),
            injection_right_tab_favorites: false,
            injection_fav_name: String::new(),
            builder_field_kind: "String".into(),
            builder_field_value: String::new(),
            schedule_draft: ScheduleDraft {
                expression: r#"{in:Chat}{i:-1}{s:"Frank loves G-Earth"}{i:0}{i:33}{i:0}{i:0}"#
                    .into(),
                direction: Direction::ToClient,
            },
            interval_ms: 500,
            align_schedule: true,
            schedule_offset_ms: 0,
            repeat: 1,
            repeat_forever: true,
            schedule_edit: None,
            active_schedule_edit: None,
            schedule_path: "gearth.sched".into(),
            scheduler: Scheduler::default(),
            scheduler_auto_start: false,
            scheduler_hotkeys: None,
            system_tray: None,
            tray_initialized: false,
            custom_hotels: Vec::new(),
            auto_update: true,
            startup_update_checked: false,
            update_task: None,
            update_result: None,
            update_apply_task: None,
            update_apply_error: None,
            update_close_requested: false,
            block_header: 0,
            block_enabled: false,
            block_direction: Direction::ToServer,
            editing_saved_rule: None,
            rule_errors: Vec::new(),
            tool_input: String::new(),
            tool_output: String::new(),
            tool_int: String::new(),
            tool_int_encoded: String::new(),
            tool_ushort: String::new(),
            tool_ushort_encoded: String::new(),
            export_path: "gearth.capture".into(),
            total: 0,
            display_dropped: 0,
            extension_host,
            extension_events,
            extension_runtime: find_java().to_string_lossy().into_owned(),
            extension_path: String::new(),
            extension_install_permanent: true,
            extensions_autostarted: false,
            extension_autostart_rx: None,
            extension_processes: Vec::new(),
            extension_launch_task: None,
            extension_console: VecDeque::new(),
            known_installed_extensions: BTreeMap::new(),
            confirm_uninstall_extension: true,
            confirm_uninstall_ext: None,
            confirm_uninstall_dont_ask: false,
            pending_ext_approvals: VecDeque::new(),
            remember_ext_approval: None,
            remember_ext_approval_box: false,
            launch_args_auto_connect: false,
            hotel_version: String::new(),
            client_identifier: String::new(),
            packet_database: String::new(),
            packet_info: PacketInfoManager::default(),
            packet_safety: Arc::new(std::sync::Mutex::new(
                gearth_rust::packet_safety::PacketSafety::default(),
            )),
            admin_service: Arc::new(std::sync::Mutex::new(
                gearth_rust::admin_service::AdminService::default(),
            )),
            always_admin: false,
            python_enabled: true,
            developer_mode: false,
            developer_mode_confirmation: false,
            advanced_options: false,
            disable_decryption: false,
            debug_stdout: false,
            socks_proxy: String::new(),
            socks_enabled: false,
            socks_user: String::new(),
            socks_password: String::new(),
            outgoing_key: String::new(),
            incoming_key: String::new(),
            settings: Settings::default(),
            settings_path: Settings::default_path(),
            settings_loaded: false,
            legacy_cache_path: String::new(),
            theme: AppTheme::GEarth,
            custom_accent: None,
            accent_picker_open: false,
            language: "en".into(),
            i18n: I18n::new("en"),
            notepad: String::new(),
            logs_bytes: 0,
            replacement_expression: String::new(),
            origins: false,
            nitro: false,
            unity: false,
            city: false,
            system_proxy: cfg!(windows),
            system_proxy_pac: cfg!(windows),
            proxy_guard: None,
            public_certificate: None,
            certificate_task: None,
            nitro_urls: String::new(),
            allow_city_helper: false,
            city_key_path: String::new(),
            flash_auto: false,
            flash_pid: 0,
            client_processes: gearth_platform::habbo_processes().unwrap_or_default(),
            attachment_host: "game-fr.habbo.com".into(),
            attachment_pending: None,
            attachment_worker: None,
            redirect: None,
            packet_download: None,
            store: store_ui::StoreUi::new(
                Settings::default_path()
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join("extensions"),
            ),
            auto_detect: true,
            connection_port: "30000".into(),
            connected_endpoint: None,
            connection_error: None,
            doctor_report: None,
            doctor_task: None,
            doctor_expanded: false,
            #[cfg(target_os = "macos")]
            relaunch_admin_task: None,
            connection_profiles: Vec::new(),
            active_profile_name: String::new(),
            new_profile_name: String::new(),
            last_saved_settings_hash: None,
            settings_dirty_since: None,
            schedule_interval_input: "500+0".into(),
            ext_console_open: false,
            ext_store_open: false,
            ext_install_open: false,
            ext_gpython_open: false,
            donate_dialog_open: false,
            last_window_title: String::new(),
            logos: None,
        };
        if let Some(host) = &desktop.extension_host {
            if let Err(error) = host.set_packet_safety(desktop.packet_safety.clone()) {
                desktop.status = format!("Extension packet safety unavailable: {error}");
            }
        }
        desktop.load_settings();
        let cli_args: Vec<String> = std::env::args().skip(1).collect();
        desktop.apply_launch_args(&parse_cli_args(&cli_args));
        desktop
    }
}
impl Desktop {
    fn compile_schedules(
        &self,
        templates: &[ScheduleTemplate],
        allow_deferred_names: bool,
    ) -> gearth_rust::packet::Result<Vec<(ScheduleSpec, bool, bool)>> {
        schedule_file::compile_active(
            templates,
            &self.packet_info,
            |direction| self.packet_format(direction),
            allow_deferred_names,
        )
    }

    fn read_schedule_file(&self) -> std::io::Result<Vec<ScheduleTemplate>> {
        let file = std::fs::File::open(&self.schedule_path)?;
        let mut bytes = Vec::new();
        file.take((schedule_file::MAX_SCHEDULE_FILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        let text = String::from_utf8(bytes).map_err(std::io::Error::other)?;
        schedule_file::parse(&text)
    }

    fn update_rules(&mut self) {
        let (entries, errors) = self
            .settings
            .compiled_rules_independent(self.origins && !self.nitro);
        self.rule_errors = errors;
        let (rules, draft_error) = combine_rules(
            entries,
            Rules::editor_rule(
                self.block_enabled,
                self.block_direction,
                self.block_header,
                &self.replacement_expression,
                self.packet_format(self.block_direction),
                &self.packet_info,
            ),
        );
        if let Some(relay) = &self.relay {
            if let Err(e) = relay.set_rules(rules) {
                self.status = format!("Could not update rules: {e}");
                return;
            }
        }
        if !self.rule_errors.is_empty() || draft_error.is_some() {
            let mut messages = Vec::new();
            if !self.rule_errors.is_empty() {
                messages.push(format!(
                    "Saved rules skipped: {}",
                    self.rule_errors
                        .iter()
                        .map(|(i, _)| (i + 1).to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if let Some(error) = draft_error {
                messages.push(format!("Editor rule disabled: {error}"));
            }
            self.status = messages.join("; ");
        }
    }
    fn poll(&mut self) {
        if let Some(hotkeys) = &self.scheduler_hotkeys {
            for index in std::iter::from_fn(|| hotkeys.try_recv()).take(32) {
                if let Some(job) = self.scheduler.jobs.get(index) {
                    let paused = !job.paused;
                    if let Err(error) = self.scheduler.set_paused(index, paused, Instant::now()) {
                        self.status = error.to_string();
                    } else {
                        self.status = format!(
                            "Schedule {} {}",
                            index + 1,
                            if paused { "paused" } else { "resumed" }
                        );
                    }
                }
            }
        }
        let mut recheck_doctor = false;
        if let Some(task) = &self.certificate_task {
            match task.try_recv() {
                Ok(result) => {
                    self.status = result.unwrap_or_else(|e| e.to_string());
                    self.certificate_task = None;
                    recheck_doctor = true;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.status = "Certificate operation stopped".into();
                    self.certificate_task = None;
                    recheck_doctor = true;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(task) = &self.doctor_task {
            match task.try_recv() {
                Ok(report) => {
                    if report.overall_severity() != doctor::CheckSeverity::Ok {
                        self.doctor_expanded = true;
                    }
                    self.doctor_report = Some(report);
                    self.doctor_task = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.doctor_task = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if recheck_doctor {
            self.start_doctor_check();
        }
        #[cfg(target_os = "macos")]
        if let Some(task) = &self.relaunch_admin_task {
            match task.try_recv() {
                Ok(Ok(())) => {
                    self.relaunch_admin_task = None;
                    if let Some(host) = self.extension_host.take() {
                        host.stop();
                    }
                    self.update_close_requested = true;
                }
                Ok(Err(e)) => {
                    self.relaunch_admin_task = None;
                    self.status = e.to_string();
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.relaunch_admin_task = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        let mut auto_apply_info = None;
        if let Some(task) = &self.update_task {
            match task.try_recv() {
                Ok(result) => {
                    match result {
                        Ok(info) => {
                            if info.outdated
                                && self.auto_update
                                && self.relay.is_none()
                                && self.attachment_pending.is_none()
                                && self.update_apply_task.is_none()
                                && info.checksums_url.is_some()
                                && (info.asset_download_url.is_some()
                                    || info.setup_download_url.is_some())
                            {
                                auto_apply_info = Some(info.clone());
                            }
                            self.update_result = Some(Ok(info));
                        }
                        Err(e) => {
                            self.update_result = Some(Err(e.to_string()));
                        }
                    }
                    self.update_task = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.update_task = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(info) = auto_apply_info {
            self.start_update_apply(info);
        }
        if let Some(task) = &self.update_apply_task {
            match task.try_recv() {
                Ok(Ok(_)) => {
                    self.update_apply_task = None;
                    self.update_apply_error = None;
                    self.save_settings();
                    self.update_close_requested = true;
                }
                Ok(Err(error)) => {
                    let message = format!("{}: {error}", self.i18n.text("rust.info.update_failed"));
                    self.update_apply_error = Some(message.clone());
                    self.status = message;
                    self.update_apply_task = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.update_apply_task = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(pending) = &self.attachment_pending {
            match pending.try_recv() {
                Ok(result) => {
                    match result {
                        Ok(attachment) => {
                            self.relay = Some(Connection::Tcp(attachment.relay));
                            self.events = Some(attachment.events);
                            self.redirect = Some(attachment.redirect);
                            self.connection_error = None;
                            self.status =
                                "Waiting for the official client; reconnect Habbo now".into();
                            self.update_rules();
                        }
                        Err(e) => {
                            let msg = format!("Attachment failed: {e}");
                            self.connection_error = Some(msg.clone());
                            self.status = msg;
                        }
                    };
                    self.attachment_pending = None;
                    if let Some(worker) = self.attachment_worker.take() {
                        let _ = worker.join();
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.attachment_pending = None;
                    self.status = "Attachment worker stopped".into();
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }

        if let Some(download) = &self.packet_download {
            match download.try_recv() {
                Ok(result) => {
                    match result {
                        Ok(database) => {
                            self.hotel_version = database.version.clone();
                            self.status =
                                format!("Loaded {} packet identifiers", database.entries().len());
                            let session_updated = match &self.relay {
                                Some(Connection::Tcp(relay)) => {
                                    relay.update_schedule_metadata(database.clone())
                                }
                                #[cfg(feature = "web")]
                                Some(Connection::Unity(unity)) => {
                                    unity.update_schedule_metadata(database.clone())
                                }
                                #[cfg(feature = "web")]
                                Some(Connection::Web(proxy)) => {
                                    proxy.update_schedule_metadata(database.clone())
                                }
                                _ => false,
                            };
                            if session_updated {
                                if let Ok(mut safety) = self.packet_safety.lock() {
                                    safety.register_metadata(&database.version, &database);
                                }
                            }
                            self.packet_info =
                                database.with_custom_names(&self.custom_packet_names);
                            invalidate_log_expressions(&mut self.logs);
                            self.logger_search_cache = None;
                            self.packet_database.clear();
                        }
                        Err(e) => self.status = format!("Packet lookup failed: {e}"),
                    };
                    self.packet_download = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.status = "Packet lookup worker stopped".into();
                    self.packet_download = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        let ext_dir_poll = self.extensions_dir();
        let mut pending_auto_actions: Vec<(u64, bool)> = Vec::new();
        if let Some(events) = &self.extension_events {
            for event in events.try_iter().take(256) {
                let line = match event {
                    HostEvent::Console { id, text } => format!("#{id} {text}"),
                    HostEvent::Error { id, text } => format!("#{id} [red]ERROR: {text}"),
                    HostEvent::Pending { id, info } => {
                        let title = info.title.clone();
                        if let Some(allow) = self.remember_ext_approval {
                            pending_auto_actions.push((id, allow));
                        } else if !self.pending_ext_approvals.iter().any(|(pid, _)| *pid == id) {
                            self.pending_ext_approvals.push_back((id, info));
                        }
                        format!("#{id} [orange]{title} is waiting for approval")
                    }
                    HostEvent::Connected { id, info } => {
                        let title = info.title.clone();
                        self.pending_ext_approvals.retain(|(pid, _)| *pid != id);
                        if let Some(fname) = &info.file {
                            if gearth_rust::extension_host::is_installed_file(&ext_dir_poll, fname)
                            {
                                self.known_installed_extensions
                                    .insert(fname.clone(), info.clone());
                            }
                        }
                        format!("#{id} [green]{title} connected")
                    }
                    HostEvent::Disconnected(id) => {
                        self.pending_ext_approvals.retain(|(pid, _)| *pid != id);
                        format!("#{id} [grey]disconnected")
                    }
                };
                if self.extension_console.len() == 512 {
                    self.extension_console.pop_front();
                }
                self.extension_console.push_back(line);
            }
        }
        if !pending_auto_actions.is_empty() {
            if let Some(host) = &self.extension_host {
                for (id, allow) in pending_auto_actions {
                    let res = if allow {
                        host.approve(id)
                    } else {
                        host.disconnect(id)
                    };
                    if let Err(e) = res {
                        self.status = e.to_string();
                    }
                }
            }
        }
        if let Some(task) = &self.extension_launch_task {
            match task.try_recv() {
                Ok(Ok(child)) => {
                    self.extension_processes.push(child);
                    self.status = self.i18n.text("rust.extensions.launched");
                    self.extension_launch_task = None;
                }
                Ok(Err(e)) => {
                    self.status = e.to_string();
                    self.extension_launch_task = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.extension_launch_task = None;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(rx) = &self.extension_autostart_rx {
            let mut disconnected = false;
            loop {
                match rx.try_recv() {
                    Ok(Ok(child)) => self.extension_processes.push(child),
                    Ok(Err(e)) => {
                        if self.extension_console.len() == 512 {
                            self.extension_console.pop_front();
                        }
                        self.extension_console
                            .push_back(format!("#0 Auto-start failed: {e}"));
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
            if disconnected {
                self.extension_autostart_rx = None;
            }
        }
        self.extension_processes
            .retain_mut(|p| !matches!(p.try_wait(), Ok(Some(_))));
        let mut relay_events_drained = true;
        let mut auto_start_schedules = false;
        let mut finish_single_session_tcp = false;
        let mut recheck_doctor_after_events = false;
        if let Some(events) = &self.events {
            let mut processed_events = 0;
            for event in events.try_iter().take(512) {
                processed_events += 1;
                match event {
                    Event::Status(status) => self.status = status,
                    Event::PacketIdentifiers(database) => {
                        self.packet_info = database.with_custom_names(&self.custom_packet_names);
                        invalidate_log_expressions(&mut self.logs);
                        self.logger_search_cache = None;
                    }
                    Event::Packet(message) => {
                        self.total += 1;
                        self.logger_stats.record(
                            message.direction,
                            message.packet.header(),
                            Instant::now(),
                        );
                        if self.debug_stdout {
                            println!(
                                "[{}] #{} {}",
                                message.direction.name(),
                                message.index,
                                expression::to_lossless_expression(&message.packet)
                            );
                        }
                        if !self.paused {
                            if self.logger_filter.suppress(&message, Instant::now()) {
                                self.logger_filtered = self.logger_filtered.saturating_add(1);
                                continue;
                            }
                            if !logger_display::capture_direction(
                                message.direction,
                                self.incoming,
                                self.outgoing,
                                self.logger_capture_selected_only,
                            ) {
                                continue;
                            }
                            let packet_size = if message.packet.format() == PacketFormat::EvaWire {
                                message.packet.bytes().len().saturating_sub(4)
                            } else {
                                message.packet.bytes().len()
                            };
                            let skipped = packet_size >= self.packet_limit;
                            let expression = if skipped {
                                format!("[packet too large to display: {packet_size} bytes]")
                            } else {
                                expression::to_lossless_expression(&message.packet)
                            };
                            let search = format!(
                                "{} {}",
                                message.packet.header(),
                                expression.to_lowercase()
                            );
                            let bytes = message.packet.bytes().len()
                                + expression.len()
                                + search.len()
                                + 4 * LOG_PREDICTION_LIMIT;
                            if bytes > self.settings.log_bytes {
                                self.display_dropped += 1;
                                continue;
                            }
                            while self.logs.len() >= self.settings.log_limit
                                || self.logs_bytes + bytes > self.settings.log_bytes
                            {
                                if let Some(old) = self.logs.pop_front() {
                                    self.logs_bytes -= old.bytes;
                                } else {
                                    break;
                                }
                                self.display_dropped += 1;
                            }
                            self.logs_bytes += bytes;
                            self.logs.push_back(LogRow {
                                message,
                                timestamp_ms: SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .ok()
                                    .and_then(|d| u64::try_from(d.as_millis()).ok()),
                                expression,
                                search,
                                bytes,
                                skipped,
                                unity: matches!(self.relay.as_ref(), Some(Connection::Unity(_))),
                                predicted_structure: OnceLock::new(),
                                packet_expression: OnceLock::new(),
                                packet_metadata: OnceLock::new(),
                            });
                        }
                    }
                    Event::Listening(a) => self.status = format!("Listening on {a}"),
                    Event::Connected(a) => {
                        auto_start_schedules = true;
                        self.logger_connection_active = true;
                        self.connected_endpoint = Some(a.clone());
                        self.connection_error = None;
                        self.logger_window.on_connect();
                        if self.logger_clear_on_connect {
                            clear_log_contents(&mut self.logs, &mut self.logs_bytes);
                        }
                        self.status = format!("Connected to {a}");
                        // Keep the system proxy active in City mode (HabboCity migrates links
                        // via 7705 -> 7702) and when targeted PAC is active (PAC only touches game
                        // hosts and leaves all other browser tabs/apps direct).
                        let keep_proxy = self.city
                            || self
                                .proxy_guard
                                .as_ref()
                                .is_some_and(gearth_platform::SystemProxyGuard::is_pac);
                        if !keep_proxy {
                            if let Some(guard) = &mut self.proxy_guard {
                                match guard.restore() {
                                    Ok(()) => self.proxy_guard = None,
                                    Err(e) => {
                                        self.status =
                                            format!("Connected; proxy restoration failed: {e}")
                                    }
                                }
                            }
                        }
                        if let Some(redirect) = &mut self.redirect {
                            if redirect.restore_on_connect() {
                                match redirect.restore() {
                                    Ok(()) => {
                                        self.redirect = None;
                                    }
                                    Err(e) => {
                                        self.status =
                                            format!("Connected; redirect restoration failed: {e}")
                                    }
                                }
                            }
                        }
                        recheck_doctor_after_events = true;
                    }
                    Event::Identified {
                        version,
                        identifier,
                    } => {
                        self.hotel_version = version;
                        self.client_identifier = identifier;
                    }
                    Event::Disconnected => {
                        self.logger_connection_active = false;
                        self.connected_endpoint = None;
                        self.logger_window.on_disconnect();
                        if self.logger_clear_on_disconnect {
                            clear_log_contents(&mut self.logs, &mut self.logs_bytes);
                        }
                        if matches!(
                            self.relay.as_ref(),
                            Some(Connection::Tcp(tcp)) if tcp.is_single_session()
                        ) {
                            finish_single_session_tcp = true;
                            self.status = "Disconnected".into();
                        } else {
                            self.status = "Client disconnected; listening".into();
                            // Re-enable the system proxy if it was restored on connect while the
                            // local proxy is still waiting for the user to reload their hotel.
                            if self.system_proxy && self.proxy_guard.is_none() {
                                let reactivated = match self.relay.as_ref() {
                                    Some(Connection::Web(proxy)) => {
                                        if self.system_proxy_pac {
                                            let label = if self.city {
                                                "*.habbocity.fr".to_owned()
                                            } else {
                                                format!("Nitro ({})", proxy.address)
                                            };
                                            Some(gearth_platform::SystemProxyGuard::activate_pac(
                                                proxy.address,
                                                &proxy.pac_url,
                                                label,
                                            ))
                                        } else {
                                            Some(gearth_platform::SystemProxyGuard::activate(
                                                proxy.address,
                                            ))
                                        }
                                    }
                                    Some(Connection::Unity(unity)) => Some(
                                        gearth_platform::SystemProxyGuard::activate(unity.address),
                                    ),
                                    _ => None,
                                };
                                if let Some(result) = reactivated {
                                    match result {
                                        Ok(guard) => self.proxy_guard = Some(guard),
                                        Err(e) => {
                                            self.status = format!(
                                                "Client disconnected; proxy activation failed: {e}"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Event::Error(e) => self.status = e,
                }
            }
            relay_events_drained = processed_events < 512;
        }
        if finish_single_session_tcp {
            if let Some(redirect) = &mut self.redirect {
                match redirect.restore() {
                    Ok(()) => self.redirect = None,
                    Err(e) => {
                        self.status = format!("Disconnected; redirect restoration failed: {e}")
                    }
                }
            }
            self.relay.take();
            self.events = None;
            self.scheduler.jobs.clear();
            self.active_schedule_edit = None;
            recheck_doctor_after_events = true;
        }
        if recheck_doctor_after_events {
            self.start_doctor_check();
        }
        if auto_start_schedules
            && self.scheduler_auto_start
            && self.scheduler.jobs.is_empty()
            && !self.settings.schedules.is_empty()
        {
            if let Err(e) = self
                .compile_schedules(&self.settings.schedules, true)
                .and_then(|specs| {
                    self.scheduler
                        .add_batch_deferred(specs, (Instant::now(), SystemTime::now()))
                })
            {
                self.status = format!("{}: {e}", self.i18n.text("rust.scheduler.start_failed"));
            }
        }
        if let Some(relay) = &self.relay {
            if relay.connected() {
                let mut blocked = None;
                let mut unresolved = None;
                let shockwave = self.origins && !self.nitro;
                enum ScheduleSession {
                    Waiting,
                    Tcp(gearth_rust::relay::TcpScheduleContext),
                    #[cfg(feature = "web")]
                    Unity(gearth_rust::unity_server::UnityScheduleContext),
                    #[cfg(feature = "web")]
                    Nitro(gearth_rust::web_proxy::NitroScheduleContext),
                }
                let session = match relay {
                    Connection::Tcp(tcp) => tcp
                        .schedule_context()
                        .map_or(ScheduleSession::Waiting, ScheduleSession::Tcp),
                    #[cfg(feature = "web")]
                    Connection::Unity(unity) => unity
                        .schedule_context()
                        .map_or(ScheduleSession::Waiting, ScheduleSession::Unity),
                    #[cfg(feature = "web")]
                    Connection::Web(proxy) => proxy
                        .schedule_context()
                        .map_or(ScheduleSession::Waiting, ScheduleSession::Nitro),
                };
                let waiting_for_session =
                    self.i18n.text("rust.scheduler.waiting_session").to_owned();
                let result: std::io::Result<()> = self.scheduler.dispatch_jobs_with_retry(
                    Instant::now(),
                    SystemTime::now(),
                    |job| {
                        let direction = job.direction;
                        let format = if shockwave {
                            if direction == Direction::ToServer {
                                PacketFormat::WedgieOutgoing
                            } else {
                                PacketFormat::WedgieIncoming
                            }
                        } else {
                            PacketFormat::EvaWire
                        };
                        let (info, version) = match &session {
                            ScheduleSession::Waiting => {
                                unresolved.get_or_insert_with(|| waiting_for_session.clone());
                                return Ok(None);
                            }
                            ScheduleSession::Tcp(context) => {
                                (context.packets.as_ref(), &context.version)
                            }
                            #[cfg(feature = "web")]
                            ScheduleSession::Unity(context) => {
                                (context.packets.as_ref(), &context.version)
                            }
                            #[cfg(feature = "web")]
                            ScheduleSession::Nitro(context) => {
                                (context.packets.as_ref(), &context.version)
                            }
                        };
                        let packet = match job.resolve_packet(format, info) {
                            Ok(packet) => packet,
                            Err(error) => {
                                unresolved.get_or_insert_with(|| error.to_string());
                                return Ok(None);
                            }
                        };
                        let allowed = self
                            .packet_safety
                            .lock()
                            .map_err(|_| std::io::Error::other("Packet safety state unavailable"))?
                            .may_send(
                                Some(version),
                                direction,
                                packet.header(),
                                self.developer_mode,
                            );
                        if !allowed {
                            blocked.get_or_insert(packet.header());
                            return Ok(Some(false));
                        }
                        match (&session, relay) {
                            (ScheduleSession::Tcp(context), Connection::Tcp(tcp)) => {
                                tcp.inject_for_session(context, direction, packet.into_owned())?
                            }
                            #[cfg(feature = "web")]
                            (ScheduleSession::Unity(context), Connection::Unity(unity)) => {
                                unity.inject_for_session(context, direction, packet.into_owned())?
                            }
                            #[cfg(feature = "web")]
                            (ScheduleSession::Nitro(context), Connection::Web(proxy)) => {
                                proxy.inject_for_session(context, direction, packet.into_owned())?
                            }
                            _ => relay.inject(direction, packet.into_owned())?,
                        }
                        Ok(Some(true))
                    },
                );
                if let Err(e) = result {
                    self.status = e.to_string();
                } else if let Some(error) = unresolved {
                    self.status = format!(
                        "{}: {error}",
                        self.i18n.text("rust.scheduler.resolve_pending")
                    );
                } else if let Some(header) = blocked {
                    self.status = format!("Scheduled packet {header} was not sent: ID not observed for this hotel version and direction");
                }
            }
        }
        if let Some(Connection::Tcp(relay)) = &self.relay {
            if let Some(errors) = relay.missed_errors(relay_events_drained) {
                self.status = if errors.count == 1 {
                    errors.latest
                } else {
                    self.i18n
                        .text("rust.connection.coalesced_errors")
                        .replace("{count}", &errors.count.to_string())
                        .replace("{error}", &errors.latest)
                };
            }
        }
    }
    fn connection_state_display(&self) -> (String, egui::Color32) {
        if self.relay.as_ref().is_some_and(Connection::connected) {
            (
                self.i18n.text("tab.connection.state.connected"),
                egui::Color32::from_rgb(0x39, 0x84, 0x39),
            )
        } else if self.relay.is_some() || self.attachment_pending.is_some() {
            (
                self.i18n.text("tab.connection.state.waiting"),
                egui::Color32::from_rgb(0xd5, 0x85, 0x12),
            )
        } else {
            (
                self.i18n.text("tab.connection.state.notconnected"),
                self.theme
                    .palette_with_accent(self.custom_accent)
                    .text_muted,
            )
        }
    }
    fn start_flash_or_origins_attach(&mut self) {
        self.connection_error = None;
        self.connected_endpoint = None;
        #[cfg(target_os = "macos")]
        if !gearth_platform::is_elevated() {
            let mode = if self.origins { "origins" } else { "flash" };
            self.start_macos_admin_relaunch(Some(mode));
            return;
        }
        if !cfg!(target_os = "macos") && !gearth_platform::is_elevated() {
            self.admin_warning_open = true;
            self.status = self.i18n.text("alert.adminvalidator.content");
            return;
        }
        let default_port = if self.origins { 40001u16 } else { 30000u16 };
        let auto_detect = self.auto_detect;
        let port = if auto_detect {
            default_port
        } else {
            match self.connection_port.trim().parse::<u16>() {
                Ok(port) if port != 0 => port,
                _ => {
                    let msg = self.i18n.text("alert.invalidconnection.content");
                    self.connection_error = Some(msg.clone());
                    self.status = msg;
                    return;
                }
            }
        };
        let host = self.attachment_host.trim().to_owned();
        if !auto_detect && host.is_empty() {
            let msg = self.i18n.text("alert.invalidconnection.content");
            self.connection_error = Some(msg.clone());
            self.status = msg;
            return;
        }
        let remote_fallback_host = if host.is_empty() {
            if self.origins {
                "game-od.habbo.com".to_owned()
            } else {
                "game-fr.habbo.com".to_owned()
            }
        } else {
            host.clone()
        };
        self.remote = format!("{remote_fallback_host}:{port}");
        self.flash_auto = !self.origins && !self.disable_decryption;
        match self.relay_options() {
            Ok(options) => {
                let path = gearth_rust::attachment::HostsRedirect::system_path();
                let (send, receive) = std::sync::mpsc::channel();
                self.attachment_pending = Some(receive);
                self.status = "Resolving hotel and preparing the local listener...".into();
                if auto_detect {
                    let base_hotels = if self.origins {
                        gearth_rust::attachment::ORIGINS_HOTELS
                    } else {
                        gearth_rust::attachment::FLASH_HOTELS
                    };
                    let mut candidates: Vec<(String, u16)> = base_hotels
                        .iter()
                        .map(|h| ((*h).to_owned(), default_port))
                        .collect();
                    for custom in &self.custom_hotels {
                        if let Some((h, p)) = custom.rsplit_once(':') {
                            if let Ok(parsed_port) = p.parse::<u16>() {
                                candidates.push((h.trim().to_owned(), parsed_port));
                                continue;
                            }
                        }
                        candidates.push((custom.trim().to_owned(), default_port));
                    }
                    self.attachment_worker = Some(std::thread::spawn(move || {
                        let _ = send.send(gearth_rust::attachment::Attachment::start_auto_detect(
                            &candidates,
                            options,
                            &path,
                        ));
                    }));
                } else {
                    self.attachment_worker = Some(std::thread::spawn(move || {
                        let _ = send.send(gearth_rust::attachment::Attachment::start(
                            &host, port, options, &path,
                        ));
                    }));
                }
            }
            Err(e) => {
                let msg = e.to_string();
                self.connection_error = Some(msg.clone());
                self.status = msg;
            }
        }
    }
    fn connection(&mut self, ui: &mut egui::Ui) {
        let idle = self.relay.is_none() && self.attachment_pending.is_none();
        let palette = self.theme.palette_with_accent(self.custom_accent);
        let avail_w = ui.available_width().max(600.0);
        let top_left_w = (avail_w * 0.58).floor();
        let top_right_w = (avail_w - top_left_w - 14.0).max(210.0);

        // Row 1 (exact Connection.fxml top grid):
        // Left: bordered card with Client type radios (Flash/Origins/Unity/Nitro) + Hotel version
        // Right: Port, Host, Connect/Abort + Auto-detect
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(top_left_w, 114.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    group_box(ui, self.theme, egui::Margin::same(0.0), |ui| {
                        ui.set_width(top_left_w - 2.0);
                        ui.add_space(6.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.add_space(8.0);
                            ui.label(self.i18n.text("tab.connection.client"));
                            ui.add_enabled_ui(idle, |ui| {
                                let is_flash = !self.origins && !self.nitro;
                                let is_origins = self.origins && !self.nitro;
                                let is_unity = self.nitro && self.unity;
                                let is_nitro = self.nitro && !self.unity && !self.city;
                                let is_city = self.nitro && !self.unity && self.city;
                                let mut switched = false;
                                if ui
                                    .radio(is_flash, self.i18n.text("tab.connection.client.flash"))
                                    .clicked()
                                {
                                    self.origins = false;
                                    self.nitro = false;
                                    self.unity = false;
                                    self.city = false;
                                    self.connection_port = "30000".into();
                                    if gearth_rust::attachment::ORIGINS_HOTELS
                                        .contains(&self.attachment_host.as_str())
                                        || self.attachment_host == "habbocity.fr"
                                    {
                                        self.attachment_host = "game-fr.habbo.com".into();
                                    }
                                    switched = true;
                                }
                                if ui
                                    .radio(
                                        is_origins,
                                        self.i18n.text("tab.connection.client.origins"),
                                    )
                                    .clicked()
                                {
                                    self.origins = true;
                                    self.nitro = false;
                                    self.unity = false;
                                    self.city = false;
                                    self.connection_port = "40001".into();
                                    if gearth_rust::attachment::FLASH_HOTELS
                                        .contains(&self.attachment_host.as_str())
                                        || self.attachment_host == "habbocity.fr"
                                    {
                                        self.attachment_host = "game-od.habbo.com".into();
                                    }
                                    switched = true;
                                }
                                if ui
                                    .radio(is_unity, self.i18n.text("tab.connection.client.unity"))
                                    .clicked()
                                {
                                    self.origins = false;
                                    self.nitro = true;
                                    self.unity = true;
                                    self.city = false;
                                    switched = true;
                                }
                                if ui
                                    .radio(is_nitro, self.i18n.text("tab.connection.client.nitro"))
                                    .clicked()
                                {
                                    self.origins = false;
                                    self.nitro = true;
                                    self.unity = false;
                                    self.city = false;
                                    switched = true;
                                }
                                if ui
                                    .radio(is_city, self.i18n.text("rust.connection.client.city"))
                                    .on_hover_text("https://habbocity.fr/hotel")
                                    .clicked()
                                {
                                    self.origins = false;
                                    self.nitro = true;
                                    self.unity = false;
                                    self.city = true;
                                    self.attachment_host = "habbocity.fr".into();
                                    self.allow_city_helper = true;
                                    let _ = self.prepare_certificate();
                                    switched = true;
                                }
                                if switched {
                                    self.update_rules();
                                    self.start_doctor_check();
                                }
                            });
                        });
                        ui.add_space(6.0);
                        let rect = ui.available_rect_before_wrap();
                        ui.painter().line_segment(
                            [
                                egui::pos2(rect.left(), rect.top()),
                                egui::pos2(rect.right(), rect.top()),
                            ],
                            egui::Stroke::new(1.0_f32, palette.group_border),
                        );
                        ui.add_space(7.0);
                        ui.horizontal(|ui| {
                            ui.add_space(10.0);
                            ui.vertical(|ui| {
                                ui.label(self.i18n.text("tab.connection.version"));
                                ui.add_space(3.0);
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.hotel_version)
                                        .desired_width((top_left_w - 28.0).max(160.0)),
                                );
                            });
                        });
                        ui.add_space(10.0);
                    });
                },
            );

            ui.add_space(10.0);

            ui.allocate_ui_with_layout(
                egui::vec2(top_right_w, 114.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.add_space(4.0);
                    let input_w = (top_right_w - 64.0).max(120.0);
                    egui::Grid::new("classic-conn-inputs")
                        .num_columns(2)
                        .spacing([8.0, 8.0])
                        .show(ui, |ui| {
                            ui.label(self.i18n.text("tab.connection.port"));
                            if self.nitro {
                                ui.add_enabled(
                                    idle,
                                    egui::TextEdit::singleline(&mut self.listen)
                                        .desired_width(input_w),
                                );
                            } else {
                                ui.add_enabled(
                                    idle && !self.auto_detect,
                                    egui::TextEdit::singleline(&mut self.connection_port)
                                        .desired_width(input_w),
                                );
                            }
                            ui.end_row();

                            ui.label(self.i18n.text("tab.connection.host"));
                            if self.nitro {
                                ui.add_enabled(
                                    false,
                                    egui::TextEdit::singleline(&mut self.attachment_host)
                                        .desired_width(input_w),
                                );
                            } else {
                                let hotels = if self.origins {
                                    gearth_rust::attachment::ORIGINS_HOTELS
                                } else {
                                    gearth_rust::attachment::FLASH_HOTELS
                                };
                                ui.horizontal(|ui| {
                                    ui.add_enabled(
                                        idle && !self.auto_detect,
                                        egui::TextEdit::singleline(&mut self.attachment_host)
                                            .desired_width((input_w - 28.0).max(90.0)),
                                    );
                                    ui.add_enabled_ui(idle && !self.auto_detect, |ui| {
                                        egui::ComboBox::from_id_salt("attach-hotel")
                                            .width(18.0)
                                            .selected_text("")
                                            .show_ui(ui, |ui| {
                                                for host in hotels {
                                                    ui.selectable_value(
                                                        &mut self.attachment_host,
                                                        (*host).into(),
                                                        *host,
                                                    );
                                                }
                                                for host in &self.custom_hotels {
                                                    if !hotels
                                                        .iter()
                                                        .any(|h| h.eq_ignore_ascii_case(host))
                                                    {
                                                        ui.selectable_value(
                                                            &mut self.attachment_host,
                                                            host.clone(),
                                                            host.as_str(),
                                                        );
                                                    }
                                                }
                                            });
                                    });
                                });
                            }
                            ui.end_row();
                        });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        let btn_w = (top_right_w - 104.0).max(96.0);
                        if idle {
                            let enabled = !self.nitro || self.certificate_task.is_none();
                            if ui
                                .add_enabled(
                                    enabled,
                                    egui::Button::new(
                                        self.i18n.text("tab.connection.button.connect"),
                                    )
                                    .min_size(egui::vec2(btn_w, 28.0)),
                                )
                                .clicked()
                            {
                                if self.nitro {
                                    if let Err(e) = self.start_nitro() {
                                        self.status = e.to_string();
                                    }
                                } else {
                                    self.start_flash_or_origins_attach();
                                }
                            }
                        } else if ui
                            .add(
                                egui::Button::new(self.i18n.text("tab.connection.button.abort"))
                                    .min_size(egui::vec2(btn_w, 28.0)),
                            )
                            .clicked()
                        {
                            self.stop_connection();
                        }
                        ui.add_enabled(
                            idle && !self.nitro,
                            egui::Checkbox::new(
                                &mut self.auto_detect,
                                self.i18n.text("tab.connection.autodetect"),
                            ),
                        );
                    });
                },
            );
        });

        ui.add_space(10.0);

        // Row 2 (exact Connection.fxml bottom grid):
        // Left: Connection state label + tall centered bordered box
        // Right: Bordered Host / Port read-only card
        let bot_left_w = (avail_w * 0.36).floor();
        let bot_right_w = (avail_w - bot_left_w - 14.0).max(260.0);
        let (state_text, state_color) = self.connection_state_display();
        let (mut connected_host, mut connected_port) =
            if self.relay.as_ref().is_some_and(Connection::connected) {
                if let Some(endpoint) = &self.connected_endpoint {
                    endpoint
                        .rsplit_once(':')
                        .map(|(h, p)| (h.to_owned(), p.to_owned()))
                        .unwrap_or_else(|| (endpoint.clone(), String::new()))
                } else if self.nitro {
                    self.listen
                        .rsplit_once(':')
                        .map(|(h, p)| (h.to_owned(), p.to_owned()))
                        .unwrap_or_else(|| (self.listen.clone(), String::new()))
                } else {
                    self.remote
                        .rsplit_once(':')
                        .map(|(h, p)| (h.to_owned(), p.to_owned()))
                        .unwrap_or_else(|| {
                            (self.attachment_host.clone(), self.connection_port.clone())
                        })
                }
            } else {
                (String::new(), String::new())
            };

        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(bot_left_w, 92.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.label(self.i18n.text("tab.connection.state"));
                    ui.add_space(4.0);
                    group_box(ui, self.theme, egui::Margin::same(8.0), |ui| {
                        ui.set_min_size(egui::vec2(bot_left_w - 18.0, 56.0));
                        ui.centered_and_justified(|ui| {
                            ui.label(egui::RichText::new(&state_text).color(state_color).strong());
                        });
                    });
                },
            );

            ui.add_space(10.0);

            ui.allocate_ui_with_layout(
                egui::vec2(bot_right_w, 92.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.add_space(6.0);
                    group_box(ui, self.theme, egui::Margin::symmetric(10.0, 10.0), |ui| {
                        ui.set_width(bot_right_w - 22.0);
                        let field_w = (bot_right_w - 100.0).max(150.0);
                        egui::Grid::new("classic-conn-output")
                            .num_columns(2)
                            .spacing([12.0, 8.0])
                            .show(ui, |ui| {
                                ui.label(self.i18n.text("tab.connection.host"));
                                ui.add_enabled(
                                    false,
                                    egui::TextEdit::singleline(&mut connected_host)
                                        .desired_width(field_w),
                                );
                                ui.end_row();
                                ui.label(self.i18n.text("tab.connection.port"));
                                ui.add_enabled(
                                    false,
                                    egui::TextEdit::singleline(&mut connected_port)
                                        .desired_width(field_w),
                                );
                                ui.end_row();
                            });
                    });
                },
            );
        });

        ui.add_space(6.0);
        if let Some(error) = &self.connection_error {
            ui.colored_label(egui::Color32::from_rgb(0xc9, 0x30, 0x2c), error);
            ui.add_space(4.0);
        }

        self.show_connection_profiles_bar(ui, idle, palette);
        ui.add_space(6.0);
        self.show_connection_doctor(ui, idle, palette);
        ui.add_space(6.0);

        // Expandable mode-specific details below the iconic 2x2 Connection.fxml grid
        if self.nitro {
            egui::ScrollArea::vertical()
                .id_salt("nitro_connection_panel")
                .show(ui, |ui| {
                    self.nitro_connection(ui);
                });
            return;
        }

        egui::CollapsingHeader::new(self.i18n.text("rust.connection.options"))
            .id_salt("connection-advanced-drawer")
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("connection_options_scroll")
                    .max_height(260.0)
                    .show(ui, |ui| {
                        let hotels = if self.origins {
                            gearth_rust::attachment::ORIGINS_HOTELS
                        } else {
                            gearth_rust::attachment::FLASH_HOTELS
                        };
                        ui.horizontal(|ui| {
                            let trimmed = self.attachment_host.trim().to_owned();
                            let is_saved = !trimmed.is_empty()
                                && self
                                    .custom_hotels
                                    .iter()
                                    .any(|h| h.eq_ignore_ascii_case(&trimmed));
                            let is_builtin =
                                hotels.iter().any(|h| h.eq_ignore_ascii_case(&trimmed));
                            if !trimmed.is_empty()
                                && !is_builtin
                                && !is_saved
                                && ui
                                    .button(self.i18n.text("rust.connection.save_hotel"))
                                    .clicked()
                            {
                                self.custom_hotels.push(trimmed);
                                self.save_settings();
                            } else if is_saved
                                && ui
                                    .button(self.i18n.text("rust.connection.remove_hotel"))
                                    .clicked()
                            {
                                self.custom_hotels
                                    .retain(|h| !h.eq_ignore_ascii_case(&trimmed));
                                self.save_settings();
                            }
                            if ui
                                .add_enabled(
                                    idle,
                                    egui::Button::new(
                                        self.i18n.text("rust.connection.recover_redirects"),
                                    ),
                                )
                                .clicked()
                            {
                                self.status =
                                    match gearth_rust::attachment::HostsRedirect::recover_stale(
                                        &gearth_rust::attachment::HostsRedirect::system_path(),
                                    ) {
                                        Ok(()) => {
                                            self.i18n.text("rust.connection.redirects_removed")
                                        }
                                        Err(e) => e.to_string(),
                                    };
                            }
                        });
                        #[cfg(target_os = "macos")]
                        if !self.origins
                            && ui
                                .add_enabled(
                                    idle,
                                    egui::Button::new(self.i18n.text("alert.macosflash.title")),
                                )
                                .on_hover_text(self.i18n.text("alert.macosflash.content"))
                                .clicked()
                        {
                            self.status = match gearth_platform::prepare_macos_flash_client() {
                                Ok(backup) => format!(
                                    "{} (backup: {})",
                                    self.i18n.text("alert.macosflash.title"),
                                    backup.display()
                                ),
                                Err(e) => {
                                    format!("{}: {e}", self.i18n.text("alert.macosflash.failed"))
                                }
                            };
                        }
                        ui.checkbox(
                            &mut self.flash_auto,
                            self.i18n.text("rust.connection.flash_crypto"),
                        );
                        ui.horizontal(|ui| {
                            if ui
                                .button(self.i18n.text("rust.connection.refresh"))
                                .clicked()
                            {
                                match gearth_platform::habbo_processes() {
                                    Ok(processes) => self.client_processes = processes,
                                    Err(e) => self.status = e.to_string(),
                                }
                            }
                            egui::ComboBox::from_id_salt("flash-process")
                                .selected_text(if self.flash_pid == 0 {
                                    self.i18n.text("rust.connection.automatic")
                                } else {
                                    format!("PID {}", self.flash_pid)
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut self.flash_pid,
                                        0,
                                        self.i18n.text("rust.connection.automatic"),
                                    );
                                    for p in &self.client_processes {
                                        ui.selectable_value(
                                            &mut self.flash_pid,
                                            p.pid,
                                            format!("{} - PID {}", p.executable, p.pid),
                                        );
                                    }
                                });
                        });
                        ui.separator();
                        egui::Grid::new("connection-manual-options")
                            .spacing([12.0, 6.0])
                            .show(ui, |ui| {
                                ui.label(self.i18n.text("rust.connection.local"));
                                ui.add_enabled(
                                    idle,
                                    egui::TextEdit::singleline(&mut self.listen)
                                        .desired_width(280.0),
                                );
                                ui.end_row();
                                ui.label(self.i18n.text("rust.connection.remote"));
                                ui.add_enabled(
                                    idle,
                                    egui::TextEdit::singleline(&mut self.remote)
                                        .desired_width(280.0),
                                );
                                ui.end_row();
                                ui.label(self.i18n.text("rust.connection.client_identifier"));
                                ui.text_edit_singleline(&mut self.client_identifier);
                                ui.end_row();
                                ui.label(self.i18n.text("rust.connection.packet_identifiers"));
                                ui.text_edit_singleline(&mut self.packet_database);
                                ui.end_row();
                                ui.label(self.i18n.text("rust.connection.outgoing_key"));
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.outgoing_key)
                                        .password(true),
                                );
                                ui.end_row();
                                ui.label(self.i18n.text("rust.connection.incoming_key"));
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.incoming_key)
                                        .password(true),
                                );
                                ui.end_row();
                            });
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(
                                    idle && self.packet_download.is_none(),
                                    egui::Button::new(self.i18n.text("rust.connection.load_sulek")),
                                )
                                .clicked()
                            {
                                let version = self.hotel_version.clone();
                                let origins = self.origins;
                                let socks = match configured_socks(
                                    self.socks_enabled,
                                    &self.socks_proxy,
                                    &self.socks_user,
                                    &self.socks_password,
                                ) {
                                    Ok(socks) => socks,
                                    Err(error) => {
                                        self.status = error.to_string();
                                        return;
                                    }
                                };
                                let (send, receive) = std::sync::mpsc::channel();
                                self.packet_download = Some(receive);
                                self.status = self.i18n.text("rust.connection.loading_identifiers");
                                std::thread::spawn(move || {
                                    let _ = send.send(PacketInfoManager::fetch_sulek_for_proxy(
                                        &version, origins, socks,
                                    ));
                                });
                            }
                            ui.label(format!(
                                "{} {}",
                                self.packet_info.entries().len(),
                                self.i18n.text("rust.connection.identifier_count")
                            ));
                            if idle
                                && ui
                                    .button(self.i18n.text("rust.connection.listen"))
                                    .clicked()
                            {
                                match self.listen.parse() {
                                    Ok(listen) => match self.relay_options().and_then(|options| {
                                        Relay::start_with_options(
                                            Config {
                                                listen,
                                                remote: self.remote.trim().to_owned(),
                                            },
                                            options,
                                        )
                                    }) {
                                        Ok((relay, events)) => {
                                            self.relay = Some(Connection::Tcp(relay));
                                            self.events = Some(events);
                                            self.update_rules();
                                        }
                                        Err(e) => self.status = e.to_string(),
                                    },
                                    Err(e) => self.status = format!("Invalid local address: {e}"),
                                }
                            }
                        });
                    });
            });
    }
    fn stop_connection(&mut self) {
        if self.logger_connection_active || self.relay.as_ref().is_some_and(Connection::connected) {
            self.logger_window.on_disconnect();
        }
        if self.logger_clear_on_disconnect
            && (self.logger_connection_active
                || self.relay.as_ref().is_some_and(Connection::connected))
        {
            clear_log_contents(&mut self.logs, &mut self.logs_bytes);
        }
        self.logger_connection_active = false;
        self.connected_endpoint = None;
        self.connection_error = None;
        self.status = "Disconnected".into();
        if let Some(guard) = &mut self.proxy_guard {
            match guard.restore() {
                Ok(()) => self.proxy_guard = None,
                Err(e) => self.status = format!("Proxy restoration failed: {e}"),
            }
        }
        if let Some(redirect) = &mut self.redirect {
            match redirect.restore() {
                Ok(()) => self.redirect = None,
                Err(e) => self.status = format!("Hosts restoration failed: {e}"),
            }
        }
        self.relay.take();
        self.events = None;
        self.scheduler.jobs.clear();
        self.active_schedule_edit = None;
        self.start_doctor_check();
    }
    fn start_doctor_check(&mut self) {
        let mode = doctor::DoctorMode::from_flags(self.origins, self.nitro, self.unity, self.city);
        let req = doctor::DoctorRequest {
            mode,
            active: self.relay.is_some() || self.attachment_pending.is_some(),
            listen: self.listen.clone(),
            connection_port: self.connection_port.clone(),
            auto_detect: self.auto_detect,
            system_proxy: self.system_proxy,
            system_proxy_pac: self.system_proxy_pac,
            allow_city_helper: self.allow_city_helper,
            city_key_path: self.city_key_path.clone(),
            identity_dir: self.identity_directory(),
            hosts_path: gearth_rust::attachment::HostsRedirect::system_path(),
        };
        let (send, receive) = std::sync::mpsc::channel();
        self.doctor_task = Some(receive);
        std::thread::spawn(move || {
            let _ = send.send(doctor::run_diagnostics(req));
        });
    }
    fn apply_doctor_fix(&mut self, action: doctor::FixAction) {
        match action {
            doctor::FixAction::InstallCertificate => {
                if let Err(e) = self.prepare_certificate() {
                    self.status = e.to_string();
                    self.start_doctor_check();
                    return;
                }
                if let Some((path, _)) = self.public_certificate.clone() {
                    let (send, receive) = std::sync::mpsc::channel();
                    self.certificate_task = Some(receive);
                    self.status = "Waiting for certificate operation...".into();
                    std::thread::spawn(move || {
                        let result = gearth_platform::install_root_certificate(&path)
                            .map(|()| "Certificate installed".into());
                        let _ = send.send(result);
                    });
                }
            }
            doctor::FixAction::PickFreePort => {
                if let Some(port) = doctor::find_free_loopback_port() {
                    if self.nitro {
                        self.listen = format!("127.0.0.1:{port}");
                    } else {
                        self.connection_port = port.to_string();
                    }
                    self.status = format!("Selected free local port {port}");
                    self.start_doctor_check();
                } else {
                    self.status = "Could not find a free local port".into();
                }
            }
            doctor::FixAction::EnablePacProxy => {
                self.system_proxy = true;
                if !self.unity {
                    self.system_proxy_pac = true;
                }
                self.save_settings();
                self.start_doctor_check();
            }
            doctor::FixAction::RestoreProxy => {
                self.status = match gearth_platform::recover_system_proxy() {
                    Ok(()) => self.i18n.text("rust.browser.proxy_restored"),
                    Err(e) => e.to_string(),
                };
                self.start_doctor_check();
            }
            doctor::FixAction::CleanHosts => {
                self.status = match gearth_rust::attachment::HostsRedirect::recover_stale(
                    &gearth_rust::attachment::HostsRedirect::system_path(),
                ) {
                    Ok(()) => self.i18n.text("rust.connection.redirects_removed"),
                    Err(e) => e.to_string(),
                };
                self.start_doctor_check();
            }
            doctor::FixAction::EnableCityHelper => {
                self.allow_city_helper = true;
                self.save_settings();
                self.start_doctor_check();
            }
            doctor::FixAction::ClearCityKey => {
                self.city_key_path.clear();
                self.save_settings();
                self.start_doctor_check();
            }
            #[cfg(target_os = "macos")]
            doctor::FixAction::RelaunchAsAdmin => {
                self.start_macos_admin_relaunch(None);
            }
            #[cfg(target_os = "macos")]
            doctor::FixAction::PrepareMacosFlash => {
                self.status = match gearth_platform::prepare_macos_flash_client() {
                    Ok(backup) => format!(
                        "{} (backup: {})",
                        self.i18n.text("alert.macosflash.title"),
                        backup.display()
                    ),
                    Err(e) => format!("{}: {e}", self.i18n.text("alert.macosflash.failed")),
                };
                self.start_doctor_check();
            }
        }
    }
    #[cfg(target_os = "macos")]
    fn start_macos_admin_relaunch(&mut self, auto_connect_mode: Option<&str>) {
        if self.relaunch_admin_task.is_some() {
            return;
        }
        self.save_settings_internal(true);
        let Ok(exe) = std::env::current_exe() else {
            self.status = "Could not locate current executable for admin relaunch".into();
            return;
        };
        let config_path = self.settings_path.clone();
        let user_home = std::env::var_os("HOME").map(PathBuf::from);
        let mut extra_args = Vec::new();
        if let Some(mode) = auto_connect_mode {
            extra_args.push("--connect".into());
            extra_args.push(mode.to_owned());
            if !self.auto_detect {
                let host = self.attachment_host.trim();
                if !host.is_empty() {
                    extra_args.push("--host".into());
                    extra_args.push(host.to_owned());
                }
                let port = self.connection_port.trim();
                if !port.is_empty() {
                    extra_args.push("--port".into());
                    extra_args.push(port.to_owned());
                }
            }
        }
        let (send, receive) = std::sync::mpsc::channel();
        self.relaunch_admin_task = Some(receive);
        self.status = self.i18n.text("rust.doctor.fix.relaunch_admin");
        std::thread::spawn(move || {
            let result = gearth_platform::relaunch_macos_as_admin(
                &exe,
                &config_path,
                user_home.as_deref(),
                &extra_args,
            );
            let _ = send.send(result);
        });
    }
    fn show_connection_doctor(
        &mut self,
        ui: &mut egui::Ui,
        idle: bool,
        palette: theme_ui::ThemePalette,
    ) {
        let current_mode =
            doctor::DoctorMode::from_flags(self.origins, self.nitro, self.unity, self.city);
        if self.doctor_task.is_none()
            && self
                .doctor_report
                .as_ref()
                .is_none_or(|report| report.mode != current_mode)
        {
            self.start_doctor_check();
        }
        let ok_color = egui::Color32::from_rgb(0x2e, 0xa0, 0x43);
        let warn_color = egui::Color32::from_rgb(0xd9, 0x82, 0x2b);
        let err_color = egui::Color32::from_rgb(0xd9, 0x3b, 0x3b);
        let mut pending_fix: Option<doctor::FixAction> = None;
        let mut trigger_refresh = false;

        group_box(ui, self.theme, egui::Margin::symmetric(8.0, 5.0), |ui| {
            ui.horizontal(|ui| {
                let (dot_color, summary_text) =
                    if self.doctor_task.is_some() && self.doctor_report.is_none() {
                        (palette.text_muted, self.i18n.text("rust.doctor.checking"))
                    } else if let Some(report) = &self.doctor_report {
                        let errors = report.error_count();
                        let warns = report.warn_count();
                        if errors > 0 {
                            (
                                err_color,
                                self.i18n
                                    .text("rust.doctor.issues")
                                    .replace("{count}", &errors.to_string()),
                            )
                        } else if warns > 0 {
                            (
                                warn_color,
                                self.i18n
                                    .text("rust.doctor.warnings")
                                    .replace("{count}", &warns.to_string()),
                            )
                        } else {
                            (ok_color, self.i18n.text("rust.doctor.ready"))
                        }
                    } else {
                        (palette.text_muted, self.i18n.text("rust.doctor.checking"))
                    };

                let (dot_rect, _) =
                    ui.allocate_exact_size(egui::vec2(10.0, 14.0), egui::Sense::hover());
                ui.painter()
                    .circle_filled(dot_rect.center(), 4.5, dot_color);

                let (chev_rect, chev_resp) =
                    ui.allocate_exact_size(egui::vec2(10.0, 14.0), egui::Sense::click());
                if ui.is_rect_visible(chev_rect) {
                    let c = chev_rect.center();
                    let pts = if self.doctor_expanded {
                        vec![
                            egui::pos2(c.x - 4.0, c.y - 2.0),
                            egui::pos2(c.x + 4.0, c.y - 2.0),
                            egui::pos2(c.x, c.y + 3.0),
                        ]
                    } else {
                        vec![
                            egui::pos2(c.x - 2.0, c.y - 4.0),
                            egui::pos2(c.x + 3.0, c.y),
                            egui::pos2(c.x - 2.0, c.y + 4.0),
                        ]
                    };
                    ui.painter().add(egui::Shape::convex_polygon(
                        pts,
                        ui.visuals().text_color(),
                        egui::Stroke::NONE,
                    ));
                }
                let title_resp = ui
                    .add(
                        egui::Label::new(
                            egui::RichText::new(self.i18n.text("rust.doctor.title")).strong(),
                        )
                        .sense(egui::Sense::click()),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                if chev_resp
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .clicked()
                    || title_resp.clicked()
                {
                    self.doctor_expanded = !self.doctor_expanded;
                }
                ui.label(egui::RichText::new("·").color(palette.text_muted));
                ui.label(egui::RichText::new(summary_text).color(dot_color).small());

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let checking = self.doctor_task.is_some();
                    let refresh_label = if checking {
                        self.i18n.text("rust.doctor.checking")
                    } else {
                        self.i18n.text("rust.doctor.refresh")
                    };
                    if ui
                        .add_enabled(!checking, egui::Button::new(refresh_label).small())
                        .clicked()
                    {
                        trigger_refresh = true;
                    }
                });
            });

            if self.doctor_expanded {
                if let Some(report) = &self.doctor_report {
                    ui.add_space(4.0);
                    for item in &report.items {
                        let color = match item.severity {
                            doctor::CheckSeverity::Ok => ok_color,
                            doctor::CheckSeverity::Warn => warn_color,
                            doctor::CheckSeverity::Error => err_color,
                        };
                        let mut detail = self.i18n.text(item.detail_key);
                        if let Some(arg) = &item.detail_arg {
                            detail = detail.replace("{detail}", arg);
                        }
                        ui.horizontal(|ui| {
                            let (r, _) = ui
                                .allocate_exact_size(egui::vec2(10.0, 14.0), egui::Sense::hover());
                            ui.painter().circle_filled(r.center(), 3.5, color);
                            ui.label(
                                egui::RichText::new(self.i18n.text(item.label_key))
                                    .small()
                                    .strong(),
                            );
                            ui.label(egui::RichText::new(detail).small().color(
                                if item.severity == doctor::CheckSeverity::Ok {
                                    palette.text_muted
                                } else {
                                    color
                                },
                            ));
                            if let Some(fix) = item.fix {
                                let can_fix = idle && self.certificate_task.is_none();
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui
                                            .add_enabled(
                                                can_fix,
                                                egui::Button::new(
                                                    egui::RichText::new(
                                                        self.i18n.text(fix.label_key()),
                                                    )
                                                    .small(),
                                                )
                                                .small(),
                                            )
                                            .clicked()
                                        {
                                            pending_fix = Some(fix);
                                        }
                                    },
                                );
                            }
                        });
                    }
                    if report.mode.is_browser() && report.cert_trusted {
                        ui.add_space(2.0);
                        ui.label(
                            egui::RichText::new(self.i18n.text("rust.doctor.firefox_tip"))
                                .small()
                                .color(palette.text_muted),
                        );
                    }
                }
            }
        });

        if let Some(fix) = pending_fix {
            self.apply_doctor_fix(fix);
        } else if trigger_refresh {
            self.start_doctor_check();
        }
    }
    fn apply_connection_profile(&mut self, profile: &doctor::ConnectionProfile) {
        self.origins = profile.mode == doctor::DoctorMode::Origins;
        self.nitro = profile.mode.is_browser();
        self.unity = profile.mode == doctor::DoctorMode::Unity;
        self.city = profile.mode == doctor::DoctorMode::City;
        if !profile.host.is_empty() {
            self.attachment_host = profile.host.clone();
        }
        if !profile.port.is_empty() {
            self.connection_port = profile.port.clone();
        }
        if !profile.listen.is_empty() {
            self.listen = profile.listen.clone();
        }
        self.auto_detect = profile.auto_detect;
        self.system_proxy = profile.system_proxy;
        self.system_proxy_pac = profile.system_proxy_pac;
        self.nitro_urls = profile.nitro_urls.clone();
        self.allow_city_helper = profile.allow_city_helper;
        self.city_key_path = profile.city_key_path.clone();
        self.active_profile_name = profile.name.clone();
        if self.city {
            let _ = self.prepare_certificate();
        }
        self.update_rules();
        self.start_doctor_check();
        self.status = self
            .i18n
            .text("rust.profiles.loaded")
            .replace("{name}", &profile.name);
    }
    fn show_connection_profiles_bar(
        &mut self,
        ui: &mut egui::Ui,
        idle: bool,
        palette: theme_ui::ThemePalette,
    ) {
        let builtins = doctor::builtin_profiles();
        let mut apply_profile: Option<doctor::ConnectionProfile> = None;
        let mut save_profile_name: Option<String> = None;
        let mut delete_profile_name: Option<String> = None;

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 5.0;
            ui.label(
                egui::RichText::new(self.i18n.text("rust.profiles.label"))
                    .small()
                    .strong(),
            );
            let selected_label = if self.active_profile_name.is_empty() {
                self.i18n.text("rust.profiles.select")
            } else {
                self.active_profile_name.clone()
            };
            ui.add_enabled_ui(idle, |ui| {
                egui::ComboBox::from_id_salt("connection-profiles-combo")
                    .width(155.0)
                    .selected_text(selected_label)
                    .show_ui(ui, |ui| {
                        ui.label(
                            egui::RichText::new(self.i18n.text("rust.profiles.builtin"))
                                .small()
                                .color(palette.text_muted),
                        );
                        for p in &builtins {
                            if ui
                                .selectable_label(self.active_profile_name == p.name, &p.name)
                                .clicked()
                            {
                                apply_profile = Some(p.clone());
                            }
                        }
                        if !self.connection_profiles.is_empty() {
                            ui.separator();
                            ui.label(
                                egui::RichText::new(self.i18n.text("rust.profiles.saved"))
                                    .small()
                                    .color(palette.text_muted),
                            );
                            for p in &self.connection_profiles {
                                if ui
                                    .selectable_label(self.active_profile_name == p.name, &p.name)
                                    .clicked()
                                {
                                    apply_profile = Some(p.clone());
                                }
                            }
                        }
                    });
            });

            let is_custom_active = !self.active_profile_name.is_empty()
                && self
                    .connection_profiles
                    .iter()
                    .any(|p| p.name.eq_ignore_ascii_case(&self.active_profile_name));
            if is_custom_active
                && ui
                    .add_enabled(idle, egui::Button::new("×").small())
                    .on_hover_text(self.i18n.text("rust.profiles.delete"))
                    .clicked()
            {
                delete_profile_name = Some(self.active_profile_name.clone());
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let can_save = !self.new_profile_name.trim().is_empty();
                if ui
                    .add_enabled(
                        can_save,
                        egui::Button::new(self.i18n.text("rust.profiles.save")).small(),
                    )
                    .clicked()
                {
                    save_profile_name = Some(self.new_profile_name.trim().to_owned());
                }
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut self.new_profile_name)
                        .desired_width(120.0)
                        .hint_text(self.i18n.text("rust.profiles.name_hint")),
                );
                if can_save && edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    save_profile_name = Some(self.new_profile_name.trim().to_owned());
                }
            });
        });

        if let Some(profile) = apply_profile {
            self.apply_connection_profile(&profile);
        }
        if let Some(name) = save_profile_name {
            let mode =
                doctor::DoctorMode::from_flags(self.origins, self.nitro, self.unity, self.city);
            let profile = doctor::ConnectionProfile {
                name: name.clone(),
                mode,
                host: self.attachment_host.clone(),
                port: self.connection_port.clone(),
                listen: self.listen.clone(),
                auto_detect: self.auto_detect,
                system_proxy: self.system_proxy,
                system_proxy_pac: self.system_proxy_pac,
                nitro_urls: self.nitro_urls.clone(),
                allow_city_helper: self.allow_city_helper,
                city_key_path: self.city_key_path.clone(),
            };
            self.connection_profiles
                .retain(|p| !p.name.eq_ignore_ascii_case(&name));
            self.connection_profiles.push(profile);
            self.active_profile_name = name.clone();
            self.new_profile_name.clear();
            self.save_settings_internal(true);
            self.status = self
                .i18n
                .text("rust.profiles.saved_status")
                .replace("{name}", &name);
        }
        if let Some(name) = delete_profile_name {
            self.connection_profiles
                .retain(|p| !p.name.eq_ignore_ascii_case(&name));
            self.active_profile_name.clear();
            self.save_settings_internal(true);
            self.status = self
                .i18n
                .text("rust.profiles.deleted_status")
                .replace("{name}", &name);
        }
    }
    fn identity_directory(&self) -> PathBuf {
        self.settings_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("certificate-authority")
    }
    fn prepare_certificate(&mut self) -> std::io::Result<()> {
        let identity = ProxyIdentity::ensure(&self.identity_directory())?;
        self.public_certificate = Some((identity.certificate_path, identity.certificate_der));
        Ok(())
    }
    fn resolve_browser_listen_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        let configured: std::net::SocketAddr =
            self.listen.trim().parse().map_err(std::io::Error::other)?;
        if configured.port() == 0 {
            return Ok(configured);
        }
        match std::net::TcpListener::bind(configured) {
            Ok(listener) => {
                drop(listener);
                Ok(configured)
            }
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
                for offset in 1..=16u16 {
                    let Some(candidate_port) = configured.port().checked_add(offset) else {
                        break;
                    };
                    let candidate = std::net::SocketAddr::new(configured.ip(), candidate_port);
                    if let Ok(listener) = std::net::TcpListener::bind(candidate) {
                        drop(listener);
                        return Ok(candidate);
                    }
                }
                Ok(std::net::SocketAddr::new(configured.ip(), 0))
            }
            Err(err) => Err(err),
        }
    }
    fn start_unity(&mut self) -> std::io::Result<()> {
        let socks = configured_socks(
            self.socks_enabled,
            &self.socks_proxy,
            &self.socks_user,
            &self.socks_password,
        )?;
        self.prepare_certificate()?;
        if self.system_proxy
            && !gearth_platform::certificate_trusted(&self.public_certificate.as_ref().unwrap().1)?
        {
            return Err(std::io::Error::other(
                "Install the displayed public certificate before enabling the system proxy",
            ));
        }
        self.hotel_version.clear();
        self.client_identifier.clear();
        self.load_packet_database()?;
        if self.packet_info.entries().is_empty() {
            self.packet_info = PacketInfoManager::from_json(
                "",
                include_bytes!("../resources/unity/messages.json"),
            )
            .map_err(std::io::Error::other)?;
            invalidate_log_expressions(&mut self.logs);
            self.logger_search_cache = None;
        }
        let mut http = WebOptions::new(
            self.resolve_browser_listen_addr()?,
            self.identity_directory(),
        );
        http.upstream_socks = socks;
        let mut communicator = gearth_rust::unity_server::UnityOptions::new(
            "127.0.0.1:0".parse().unwrap(),
            self.identity_directory(),
        );
        communicator.extensions = self.extension_host.clone();
        communicator.packet_info = self.packet_info.clone();
        communicator.packet_safety = Some(self.packet_safety.clone());
        communicator.admin_service = Some(self.admin_service.clone());
        let cache = self
            .settings_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("unity-cache");
        let (connection, events) =
            gearth_rust::unity_connection::UnityConnection::start(http, communicator, cache)?;
        if self.system_proxy {
            self.proxy_guard = Some(gearth_platform::SystemProxyGuard::activate(
                connection.address,
            )?);
        }
        self.status = format!(
            "Unity asset proxy listening on {}; reload the WebGL client",
            connection.address
        );
        self.relay = Some(Connection::Unity(Box::new(connection)));
        self.events = Some(events);
        self.update_rules();
        Ok(())
    }
    fn start_nitro(&mut self) -> std::io::Result<()> {
        if self.unity {
            return self.start_unity();
        }
        let socks = configured_socks(
            self.socks_enabled,
            &self.socks_proxy,
            &self.socks_user,
            &self.socks_password,
        )?;
        self.prepare_certificate()?;
        self.hotel_version = NITRO_REVISION.into();
        self.client_identifier = "HTML5".into();
        self.load_packet_database()?;
        if self.system_proxy
            && !gearth_platform::certificate_trusted(&self.public_certificate.as_ref().unwrap().1)?
        {
            return Err(std::io::Error::other(
                "Install the displayed public certificate before enabling the system proxy",
            ));
        }
        let mut options = WebOptions::new(
            self.resolve_browser_listen_addr()?,
            self.identity_directory(),
        );
        options.packet_info = self.packet_info.clone();
        options.upstream_socks = socks;
        options.packet_safety = Some(self.packet_safety.clone());
        options.admin_service = Some(self.admin_service.clone());
        options.extensions = self.extension_host.clone();
        options.hotels = gearth_rust::nitro::Hotels::load(
            &self
                .settings_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("nitro.json"),
        )?
        .with_defaults();
        options.websocket_urls = self
            .nitro_urls
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        options.city_mode = self.city;
        if self.city {
            for default_url in [
                "wss://habblet.habbocity.fr/*",
                "wss://habblet.habbocity.fr",
                "wss://websocket.habbocity.fr/*",
            ] {
                if !options.websocket_urls.iter().any(|u| u == default_url) {
                    options.websocket_urls.push(default_url.to_owned());
                }
            }
        }
        options.allow_city_helper = self.allow_city_helper;
        options.pac_hosts = gearth_rust::web_proxy::pac_hosts_for_options(
            self.city,
            &options.hotels,
            &options.websocket_urls,
        );
        let pac_label = if self.city {
            "*.habbocity.fr".to_owned()
        } else if options.pac_hosts.len() == 1 {
            format!("*.{}", options.pac_hosts[0])
        } else {
            format!("{} hosts", options.pac_hosts.len())
        };
        let use_pac = self.system_proxy_pac && !options.pac_hosts.is_empty();
        if !self.city_key_path.trim().is_empty() {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(&self.city_key_path)?
                .take(65537)
                .read_to_end(&mut bytes)?;
            options.city_keys = Some(gearth_rust::nitro_city::CityKeys::from_json(&bytes)?);
        }
        let (proxy, events) = WebProxy::start(options)?;
        if self.system_proxy {
            self.proxy_guard = Some(if use_pac {
                gearth_platform::SystemProxyGuard::activate_pac(
                    proxy.address,
                    &proxy.pac_url,
                    pac_label,
                )?
            } else {
                gearth_platform::SystemProxyGuard::activate(proxy.address)?
            });
        }
        self.status = if self.city {
            format!(
                "City proxy listening on {}; open or reload (Ctrl+F5) https://habbocity.fr/hotel",
                proxy.address
            )
        } else {
            format!(
                "Browser proxy listening on {}; reload the Nitro client",
                proxy.address
            )
        };
        self.relay = Some(Connection::Web(proxy));
        self.events = Some(events);
        self.update_rules();
        Ok(())
    }
    fn browser_socks_options(&mut self, ui: &mut egui::Ui, grid_id: &'static str) {
        ui.add_enabled_ui(self.relay.is_none(), |ui| {
            ui.checkbox(
                &mut self.socks_enabled,
                self.i18n.text("tab.extra.options.advanced.socks"),
            );
            egui::Grid::new(grid_id).show(ui, |ui| {
                for (key, value) in [
                    ("rust.connection.socks_proxy", &mut self.socks_proxy),
                    ("rust.connection.socks_user", &mut self.socks_user),
                ] {
                    let label = ui.label(self.i18n.text(key));
                    ui.text_edit_singleline(value).labelled_by(label.id);
                    ui.end_row();
                }
                let label = ui.label(self.i18n.text("rust.connection.socks_password"));
                ui.add(egui::TextEdit::singleline(&mut self.socks_password).password(true))
                    .labelled_by(label.id);
                ui.end_row();
            });
        });
    }

    fn nitro_connection(&mut self, ui: &mut egui::Ui) {
        ui.label(self.i18n.text(if self.unity {
            "rust.browser.unity_connection"
        } else if self.city {
            "rust.browser.city_connection"
        } else {
            "rust.browser.nitro_connection"
        }));
        if self.city {
            ui.hyperlink_to(
                self.i18n.text("rust.browser.open_habbocity"),
                "https://habbocity.fr/hotel",
            );
        }
        ui.horizontal(|ui| {
            ui.label(self.i18n.text("rust.browser.local_address"));
            ui.add_enabled(
                self.relay.is_none(),
                egui::TextEdit::singleline(&mut self.listen),
            );
        });
        ui.add_enabled(
            self.relay.is_none(),
            egui::Checkbox::new(
                &mut self.system_proxy,
                self.i18n.text("rust.browser.configure_proxy"),
            ),
        );
        if !self.unity {
            ui.indent("pac-proxy-indent", |ui| {
                ui.add_enabled(
                    self.relay.is_none() && self.system_proxy,
                    egui::Checkbox::new(
                        &mut self.system_proxy_pac,
                        self.i18n.text("rust.browser.pac_proxy"),
                    ),
                );
            });
        }
        ui.label(self.i18n.text("rust.browser.proxy_hint"));
        if ui
            .add_enabled(
                self.relay.is_none(),
                egui::Button::new(self.i18n.text("rust.browser.restore_proxy")),
            )
            .clicked()
        {
            self.status = match gearth_platform::recover_system_proxy() {
                Ok(()) => self.i18n.text("rust.browser.proxy_restored"),
                Err(e) => e.to_string(),
            };
        }
        if ui
            .add_enabled(
                self.relay.is_none() && self.certificate_task.is_none(),
                egui::Button::new(self.i18n.text("rust.browser.prepare_certificate")),
            )
            .clicked()
        {
            self.status = match self.prepare_certificate() {
                Ok(()) => self.i18n.text("rust.browser.certificate_ready"),
                Err(e) => e.to_string(),
            };
        }
        if let Some((path, der)) = self.public_certificate.clone() {
            ui.label(format!(
                "{}: {}",
                self.i18n.text("rust.browser.public_certificate"),
                path.display()
            ));
            ui.label(self.i18n.text("rust.browser.certificate_hint"));
            ui.horizontal(|ui| {
                let available = self.relay.is_none() && self.certificate_task.is_none();
                let action = if ui
                    .add_enabled(
                        available,
                        egui::Button::new(self.i18n.text("rust.browser.install_certificate")),
                    )
                    .clicked()
                {
                    Some(true)
                } else if ui
                    .add_enabled(
                        available,
                        egui::Button::new(self.i18n.text("rust.browser.remove_certificate")),
                    )
                    .clicked()
                {
                    Some(false)
                } else {
                    None
                };
                if let Some(install) = action {
                    let (send, receive) = std::sync::mpsc::channel();
                    self.certificate_task = Some(receive);
                    self.status = "Waiting for certificate operation...".into();
                    std::thread::spawn(move || {
                        let result = if install {
                            gearth_platform::install_root_certificate(&path)
                        } else {
                            gearth_platform::remove_root_certificate(&der)
                        }
                        .map(|()| {
                            if install {
                                "Certificate installed".into()
                            } else {
                                "Certificate removed".into()
                            }
                        });
                        let _ = send.send(result);
                    });
                }
            });
        }
        if self.unity {
            ui.label(self.i18n.text("rust.browser.unity_identifiers"));
            ui.add_enabled(
                self.relay.is_none(),
                egui::TextEdit::singleline(&mut self.packet_database),
            );
            ui.label(self.i18n.text("rust.browser.unity_hint"));
            self.browser_socks_options(ui, "unity-socks-options");
            ui.label(self.i18n.text("rust.browser.manual_proxy_hint"));
        } else {
            egui::CollapsingHeader::new(self.i18n.text("rust.browser.nitro_options")).show(
                ui,
                |ui| {
                    ui.label(self.i18n.text("rust.connection.packet_identifiers"));
                    ui.text_edit_singleline(&mut self.packet_database);
                    ui.label(self.i18n.text("rust.browser.websocket_hint"));
                    ui.add(egui::TextEdit::multiline(&mut self.nitro_urls).desired_rows(3));
                    ui.label(self.i18n.text("rust.browser.city_keys"));
                    ui.text_edit_singleline(&mut self.city_key_path);
                    ui.add_enabled(
                        self.relay.is_none(),
                        egui::Checkbox::new(
                            &mut self.allow_city_helper,
                            self.i18n.text("rust.browser.city_helper"),
                        ),
                    );
                    self.browser_socks_options(ui, "nitro-socks-options");
                    ui.label(self.i18n.text("rust.browser.manual_proxy_hint"));
                },
            );
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        self.relay.is_none() && self.packet_download.is_none(),
                        egui::Button::new(self.i18n.text("rust.browser.load_nitro_identifiers")),
                    )
                    .clicked()
                {
                    let socks = match configured_socks(
                        self.socks_enabled,
                        &self.socks_proxy,
                        &self.socks_user,
                        &self.socks_password,
                    ) {
                        Ok(socks) => socks,
                        Err(error) => {
                            self.status = error.to_string();
                            return;
                        }
                    };
                    let (send, receive) = std::sync::mpsc::channel();
                    self.packet_download = Some(receive);
                    self.status = self.i18n.text("rust.connection.loading_identifiers");
                    std::thread::spawn(move || {
                        let _ = send.send(fetch_nitro_metadata(socks));
                    });
                }
                ui.label(format!(
                    "{} {}",
                    self.packet_info.entries().len(),
                    self.i18n.text("rust.connection.identifier_count")
                ));
            });
        }
        if self.relay.is_none() {
            if ui
                .add_enabled(
                    self.certificate_task.is_none(),
                    egui::Button::new(self.i18n.text("rust.browser.start_proxy")),
                )
                .clicked()
            {
                if let Err(e) = self.start_nitro() {
                    self.status = e.to_string();
                }
            }
        } else if ui.button(self.i18n.text("rust.connection.stop")).clicked() {
            self.stop_connection();
        }
        ui.separator();
        ui.label(if self.unity {"Unity WebGL hooks and communicator are validated on controlled fixtures; official client sessions still need regression testing."}else{"Nitro transport and beta-29 hotel adapters are implemented with finite fixture tests. Real hotel sessions and Chrome TLS emulation still need validation and work."});
    }
    fn logger(&mut self, ui: &mut egui::Ui) {
        // Exact UiLogger.fxml keyboard accelerators: Ctrl+I, Ctrl+O, Ctrl+L, Ctrl+E
        if ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::I)) {
            self.incoming = !self.incoming;
        }
        if ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::O)) {
            self.outgoing = !self.outgoing;
        }
        if ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::L)) {
            self.logger_autoscroll = !self.logger_autoscroll;
        }
        if ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::E)) {
            clear_log_contents(&mut self.logs, &mut self.logs_bytes);
        }

        let mut chosen_export: Option<String> = None;

        // Exact UiLogger.fxml MenuBar: Window | View | Packets + inline Filter
        egui::menu::bar(ui, |ui| {
            ui.menu_button(self.i18n.text("ext.logger.menu.window"), |ui| {
                if ui
                    .checkbox(
                        &mut self.logger_window.always_on_top,
                        self.i18n.text("ext.logger.menu.window.alwaysontop"),
                    )
                    .changed()
                {
                    ui.ctx().request_repaint_of(egui::ViewportId::ROOT);
                }
                if !self.logger_window.open
                    && ui
                        .button(self.i18n.text("rust.logger.open_panel"))
                        .clicked()
                {
                    self.logger_window.open = true;
                    ui.close_menu();
                }
                ui.menu_button(self.i18n.text("ext.logger.menu.window.onconnect"), |ui| {
                    ui.checkbox(
                        &mut self.logger_window.open_on_connect,
                        self.i18n
                            .text("ext.logger.menu.window.onconnect.openwindow"),
                    );
                    ui.checkbox(
                        &mut self.logger_clear_on_connect,
                        self.i18n.text("ext.logger.menu.window.onconnect.reset"),
                    );
                });
                ui.menu_button(
                    self.i18n.text("ext.logger.menu.window.ondisconnect"),
                    |ui| {
                        ui.checkbox(
                            &mut self.logger_window.hide_on_disconnect,
                            self.i18n
                                .text("ext.logger.menu.window.ondisconnect.hidewindow"),
                        );
                        ui.checkbox(
                            &mut self.logger_clear_on_disconnect,
                            self.i18n.text("ext.logger.menu.window.ondisconnect.reset"),
                        );
                    },
                );
            });

            ui.menu_button(self.i18n.text("ext.logger.menu.view"), |ui| {
                ui.checkbox(
                    &mut self.incoming,
                    format!(
                        "{}  (Ctrl+I)",
                        self.i18n.text("ext.logger.menu.view.incoming")
                    ),
                );
                ui.checkbox(
                    &mut self.outgoing,
                    format!(
                        "{}  (Ctrl+O)",
                        self.i18n.text("ext.logger.menu.view.outgoing")
                    ),
                );
                ui.checkbox(
                    &mut self.logger_autoscroll,
                    format!(
                        "{}  (Ctrl+L)",
                        self.i18n.text("ext.logger.menu.view.autoscroll")
                    ),
                );
                ui.separator();
                ui.checkbox(
                    &mut self.logger_friendly,
                    self.i18n.text("rust.logger.friendly_mode"),
                );
                ui.checkbox(&mut self.paused, self.i18n.text("rust.logger.pause"));
                ui.checkbox(
                    &mut self.logger_capture_selected_only,
                    self.i18n.text("rust.logger.capture_selected_only"),
                )
                .on_hover_text(self.i18n.text("rust.logger.capture_selected_hint"));
                ui.separator();
                if ui
                    .button(format!(
                        "{}  (Ctrl+E)",
                        self.i18n.text("ext.logger.menu.view.cleartext")
                    ))
                    .clicked()
                {
                    clear_log_contents(&mut self.logs, &mut self.logs_bytes);
                    ui.close_menu();
                }
            });

            ui.menu_button(self.i18n.text("ext.logger.menu.packets"), |ui| {
                ui.menu_button(
                    self.i18n.text("ext.logger.menu.packets.displaydetails"),
                    |ui| {
                        ui.menu_button(
                            self.i18n
                                .text("ext.logger.menu.packets.displaydetails.byterep"),
                            |ui| {
                                for mode in [
                                    PacketRepresentation::Legacy,
                                    PacketRepresentation::HexDump,
                                    PacketRepresentation::RawHex,
                                    PacketRepresentation::Expression,
                                    PacketRepresentation::NoBytes,
                                ] {
                                    ui.selectable_value(
                                        &mut self.logger_representation,
                                        mode,
                                        self.i18n.text(mode.translation_key()),
                                    );
                                }
                                ui.separator();
                                ui.label(self.i18n.text("rust.logger.extra"));
                                ui.checkbox(
                                    &mut self.logger_extra_legacy,
                                    self.i18n
                                        .text(PacketRepresentation::Legacy.translation_key()),
                                );
                                ui.checkbox(
                                    &mut self.logger_extra_raw_hex,
                                    self.i18n
                                        .text(PacketRepresentation::RawHex.translation_key()),
                                );
                                ui.checkbox(
                                    &mut self.logger_extra_hex_dump,
                                    self.i18n
                                        .text(PacketRepresentation::HexDump.translation_key()),
                                );
                            },
                        );
                        ui.menu_button(
                            self.i18n
                                .text("ext.logger.menu.packets.displaydetails.message"),
                            |ui| {
                                ui.checkbox(
                                    &mut self.logger_names,
                                    self.i18n.text(
                                        "ext.logger.menu.packets.displaydetails.message.name",
                                    ),
                                );
                                ui.checkbox(
                                    &mut self.logger_hashes,
                                    self.i18n.text(
                                        "ext.logger.menu.packets.displaydetails.message.hash",
                                    ),
                                );
                                ui.checkbox(
                                    &mut self.logger_message_id,
                                    self.i18n
                                        .text("ext.logger.menu.packets.displaydetails.message.id"),
                                );
                            },
                        );
                        ui.checkbox(
                            &mut self.logger_structure,
                            self.i18n
                                .text("ext.logger.menu.packets.displaydetails.structure"),
                        );
                        ui.checkbox(
                            &mut self.logger_timestamp,
                            self.i18n
                                .text("ext.logger.menu.packets.displaydetails.timestamp"),
                        );
                        ui.separator();
                        ui.checkbox(
                            &mut self.logger_additional,
                            self.i18n.text("rust.logger.additional"),
                        );
                        ui.checkbox(&mut self.logger_split, self.i18n.text("rust.logger.split"));
                        ui.checkbox(
                            &mut self.logger_java_structure_limit,
                            self.i18n.text("rust.logger.java_structure_limit"),
                        );
                        ui.checkbox(
                            &mut self.logger_java_structure_clean,
                            self.i18n.text("rust.logger.java_structure_clean"),
                        );
                        ui.checkbox(
                            &mut self.logger_export_separators,
                            self.i18n.text("rust.logger.export_separators"),
                        );
                        ui.checkbox(
                            &mut self.logger_export_hide_empty_header,
                            self.i18n.text("rust.logger.export_hide_empty_header"),
                        );
                        ui.checkbox(
                            &mut self.logger_display_hide_empty_header,
                            self.i18n.text("rust.logger.display_hide_empty_header"),
                        );
                    },
                );
                ui.menu_button(self.i18n.text("ext.logger.menu.packets.antispam"), |ui| {
                    let old = self.logger_antispam;
                    for mode in [
                        AntiSpam::None,
                        AntiSpam::Low,
                        AntiSpam::Medium,
                        AntiSpam::High,
                        AntiSpam::Ultra,
                    ] {
                        ui.radio_value(
                            &mut self.logger_antispam,
                            mode,
                            self.i18n.text(mode.translation_key()),
                        );
                    }
                    if old != self.logger_antispam {
                        self.logger_filter.set_mode(self.logger_antispam);
                    }
                    ui.separator();
                    if ui
                        .button(self.i18n.text("rust.logger.reset_filtered"))
                        .clicked()
                    {
                        self.logger_filtered = 0;
                        ui.close_menu();
                    }
                });
                ui.checkbox(
                    &mut self.logger_skip_big,
                    self.i18n.text("ext.logger.menu.packets.skipbig"),
                );
                ui.horizontal(|ui| {
                    ui.label(self.i18n.text("rust.logger.packet_limit"));
                    ui.add(
                        egui::DragValue::new(&mut self.packet_limit).range(0..=16 * 1024 * 1024),
                    );
                });
                ui.separator();
                if ui
                    .button(self.i18n.text("ext.logger.menu.packets.exportall"))
                    .clicked()
                {
                    match gearth_platform::choose_file(gearth_platform::FileKind::Text, true) {
                        Ok(Some(selected)) => match selected.into_os_string().into_string() {
                            Ok(path) => {
                                self.export_path = path.clone();
                                chosen_export = Some(path);
                            }
                            Err(_) => self.status = self.i18n.text("rust.dialog.invalid_path"),
                        },
                        Ok(None) => {}
                        Err(error) => {
                            self.status =
                                format!("{}: {error}", self.i18n.text("rust.dialog.failed"));
                        }
                    }
                    ui.close_menu();
                }
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !self.logger_window.open
                    && ui
                        .small_button(self.i18n.text("rust.logger.open_panel"))
                        .clicked()
                {
                    self.logger_window.open = true;
                }
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .desired_width(160.0)
                        .hint_text(self.i18n.text("rust.logger.filter")),
                );
            });
        });

        let skipped_label = format!("<{}>", self.i18n.text("ext.logger.element.skipped"));
        let timestamp_label = self.i18n.text("ext.logger.element.timestamp");
        let blocked_label = self.i18n.text("ext.logger.element.blocked");
        let replaced_label = self.i18n.text("ext.logger.element.replaced");
        let incoming_label = self.i18n.text("ext.logger.element.direction.incoming");
        let outgoing_label = self.i18n.text("ext.logger.element.direction.outgoing");
        let display_options = LogDisplayOptions {
            additional: self.logger_additional,
            names: self.logger_names,
            hashes: self.logger_hashes,
            message_id: self.logger_message_id,
            representation: self.logger_representation,
            extra_legacy: self.logger_extra_legacy,
            extra_raw_hex: self.logger_extra_raw_hex,
            extra_hex_dump: self.logger_extra_hex_dump,
            skip_big: self.logger_skip_big,
            skipped_label: &skipped_label,
            timestamp: self.logger_timestamp,
            timestamp_label: &timestamp_label,
            blocked_label: &blocked_label,
            replaced_label: &replaced_label,
            incoming_label: &incoming_label,
            outgoing_label: &outgoing_label,
            structure: self.logger_structure,
            java_structure_limit: self.logger_java_structure_limit,
            java_structure_clean: self.logger_java_structure_clean,
            export_hide_empty_header: self.logger_export_hide_empty_header,
        };
        let (display_incoming, display_outgoing) = logger_display::displayed_directions(
            self.incoming,
            self.outgoing,
            self.logger_capture_selected_only,
        );
        if let Some(target_path) = chosen_export {
            let export_filter = self.filter.to_lowercase();
            if self
                .logger_search_cache
                .as_ref()
                .is_none_or(|(cached, _)| cached != &export_filter)
            {
                self.logger_search_cache = Some((
                    export_filter.clone(),
                    matching_packet_metadata(&self.packet_info, &export_filter),
                ));
            }
            let matching_metadata = &self
                .logger_search_cache
                .as_ref()
                .expect("search cache initialized")
                .1;
            let hide_noisy = self.logger_hide_noisy;
            let hidden_headers = &self.logger_hidden_headers;
            let packet_info = &self.packet_info;
            let visible = self.logs.iter().filter(|row| {
                if !log_row_matches(
                    row,
                    &export_filter,
                    matching_metadata,
                    display_outgoing,
                    display_incoming,
                ) {
                    return false;
                }
                let dir = row.message.direction;
                let hdr = row.message.packet.header();
                if hidden_headers.contains(&(dir, hdr)) {
                    return false;
                }
                if hide_noisy {
                    let (names, _) = row
                        .packet_metadata
                        .get_or_init(|| log_packet_metadata(packet_info, dir, hdr));
                    if logger_ui::is_noisy_packet(dir, hdr, names) {
                        return false;
                    }
                }
                true
            });
            let result = logger_display::write_atomic(Path::new(&target_path), |file| {
                write_log_capture(
                    std::io::BufWriter::new(file),
                    visible,
                    &self.packet_info,
                    display_options,
                    logger_display::export_separators(
                        self.logger_split,
                        self.logger_export_separators,
                    ),
                )
            });
            self.status = match result {
                Ok(()) => format!("Capture saved to {target_path}"),
                Err(e) => e.to_string(),
            };
        }
        let (rate_total, rate_in, rate_out) = self.logger_stats.rates(Instant::now());
        // Quick beginner-friendly toolbar right below the classic MenuBar
        ui.add_space(2.0);
        ui.horizontal_wrapped(|ui| {
            let dark = ui.visuals().dark_mode;
            let in_bg = if self.incoming {
                if dark {
                    egui::Color32::from_rgb(130, 35, 35)
                } else {
                    egui::Color32::from_rgb(248, 215, 218)
                }
            } else {
                egui::Color32::TRANSPARENT
            };
            let in_fg = if self.incoming {
                if dark {
                    egui::Color32::WHITE
                } else {
                    egui::Color32::from_rgb(132, 32, 41)
                }
            } else {
                self.theme
                    .palette_with_accent(self.custom_accent)
                    .text_muted
            };
            if vector_text_button(
                ui,
                VectorIcon::ArrowLeft,
                in_fg,
                &self.i18n.text("ext.logger.element.direction.incoming"),
                Some(in_fg),
                Some(in_bg),
                true,
            )
            .clicked()
            {
                self.incoming = !self.incoming;
            }
            let out_bg = if self.outgoing {
                if dark {
                    egui::Color32::from_rgb(25, 80, 145)
                } else {
                    egui::Color32::from_rgb(207, 226, 255)
                }
            } else {
                egui::Color32::TRANSPARENT
            };
            let out_fg = if self.outgoing {
                if dark {
                    egui::Color32::WHITE
                } else {
                    egui::Color32::from_rgb(8, 66, 152)
                }
            } else {
                self.theme
                    .palette_with_accent(self.custom_accent)
                    .text_muted
            };
            if vector_text_button(
                ui,
                VectorIcon::ArrowRight,
                out_fg,
                &self.i18n.text("ext.logger.element.direction.outgoing"),
                Some(out_fg),
                Some(out_bg),
                true,
            )
            .clicked()
            {
                self.outgoing = !self.outgoing;
            }
            let ui_fg = ui.visuals().text_color();
            if vector_text_button(
                ui,
                if self.paused {
                    VectorIcon::Play
                } else {
                    VectorIcon::Pause
                },
                ui_fg,
                &self.i18n.text(if self.paused {
                    "rust.scheduler.resume"
                } else {
                    "rust.logger.pause"
                }),
                None,
                None,
                true,
            )
            .clicked()
            {
                self.paused = !self.paused;
            }
            if vector_text_button(
                ui,
                VectorIcon::Trash,
                ui_fg,
                &self.i18n.text("rust.logger.clear"),
                None,
                None,
                true,
            )
            .clicked()
            {
                clear_log_contents(&mut self.logs, &mut self.logs_bytes);
                self.logger_stats.reset();
                self.selected_log_index = None;
            }
            // 1-click noisy/ping packet suppressor toggle
            let noisy_bg = if self.logger_hide_noisy {
                if dark {
                    egui::Color32::from_rgb(138, 88, 16)
                } else {
                    egui::Color32::from_rgb(255, 240, 204)
                }
            } else {
                egui::Color32::TRANSPARENT
            };
            let noisy_fg = if self.logger_hide_noisy {
                if dark {
                    egui::Color32::WHITE
                } else {
                    egui::Color32::from_rgb(130, 78, 8)
                }
            } else {
                self.theme
                    .palette_with_accent(self.custom_accent)
                    .text_muted
            };
            if vector_text_button(
                ui,
                VectorIcon::Block,
                noisy_fg,
                &self.i18n.text("rust.logger.hide_noisy"),
                Some(noisy_fg),
                Some(noisy_bg),
                true,
            )
            .clicked()
            {
                self.logger_hide_noisy = !self.logger_hide_noisy;
            }
            if !self.logger_hidden_headers.is_empty() {
                let mut remove_hidden = None;
                let mut clear_all_hidden = false;
                ui.menu_button(
                    format!(
                        "{} ({})",
                        self.i18n.text("rust.logger.hidden_headers"),
                        self.logger_hidden_headers.len()
                    ),
                    |ui| {
                        let mut sorted: Vec<_> =
                            self.logger_hidden_headers.iter().copied().collect();
                        sorted.sort_by(|a, b| (a.0.name(), a.1).cmp(&(b.0.name(), b.1)));
                        for (dir, hdr) in sorted {
                            let (names, _) = log_packet_metadata(&self.packet_info, dir, hdr);
                            let label = if names.is_empty() {
                                format!("{} #{hdr}", dir.name())
                            } else {
                                format!("{} {} (#{hdr})", dir.name(), names.replace("][", " / "))
                            };
                            ui.horizontal(|ui| {
                                ui.label(label);
                                if ui.small_button("x").clicked() {
                                    remove_hidden = Some((dir, hdr));
                                }
                            });
                        }
                        ui.separator();
                        if ui
                            .button(self.i18n.text("rust.logger.clear_hidden"))
                            .clicked()
                        {
                            clear_all_hidden = true;
                            ui.close_menu();
                        }
                    },
                );
                if let Some(pair) = remove_hidden {
                    self.logger_hidden_headers.remove(&pair);
                }
                if clear_all_hidden {
                    self.logger_hidden_headers.clear();
                }
            }
            // Filter Presets menu (apply / save / delete)
            let mut apply_preset_idx = None;
            let mut delete_preset_idx = None;
            let mut save_new_preset = false;
            ui.menu_button(self.i18n.text("rust.logger.presets"), |ui| {
                ui.set_min_width(220.0);
                if self.logger_presets.is_empty() {
                    ui.small(
                        egui::RichText::new(self.i18n.text("rust.logger.no_presets"))
                            .italics()
                            .color(
                                self.theme
                                    .palette_with_accent(self.custom_accent)
                                    .text_muted,
                            ),
                    );
                } else {
                    for (idx, preset) in self.logger_presets.iter().enumerate() {
                        ui.horizontal(|ui| {
                            if ui.button(&preset.name).clicked() {
                                apply_preset_idx = Some(idx);
                                ui.close_menu();
                            }
                            if ui
                                .small_button(self.i18n.text("rust.action.remove"))
                                .clicked()
                            {
                                delete_preset_idx = Some(idx);
                            }
                        });
                    }
                }
                ui.separator();
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.logger_preset_name)
                            .desired_width(130.0)
                            .hint_text(self.i18n.text("rust.logger.preset_name")),
                    );
                    if ui
                        .add_enabled(
                            !self.logger_preset_name.trim().is_empty(),
                            egui::Button::new(self.i18n.text("rust.logger.save_preset")),
                        )
                        .clicked()
                    {
                        save_new_preset = true;
                    }
                });
            });
            if let Some(idx) = apply_preset_idx {
                if let Some(preset) = self.logger_presets.get(idx).cloned() {
                    self.filter = preset.query;
                    self.logger_hide_noisy = preset.hide_noisy;
                    self.incoming = preset.incoming;
                    self.outgoing = preset.outgoing;
                    self.logger_hidden_headers = preset.hidden_headers.into_iter().collect();
                    self.status = format!("Applied logger preset: {}", preset.name);
                }
            }
            if let Some(idx) = delete_preset_idx {
                if idx < self.logger_presets.len() {
                    self.logger_presets.remove(idx);
                    self.save_settings();
                }
            }
            if save_new_preset {
                let name = self.logger_preset_name.trim().to_owned();
                if !name.is_empty() {
                    let mut hidden: Vec<_> = self.logger_hidden_headers.iter().copied().collect();
                    hidden.sort_by(|a, b| (a.0.name(), a.1).cmp(&(b.0.name(), b.1)));
                    let preset = logger_ui::LoggerFilterPreset {
                        name: name.clone(),
                        query: self.filter.clone(),
                        hide_noisy: self.logger_hide_noisy,
                        incoming: self.incoming,
                        outgoing: self.outgoing,
                        hidden_headers: hidden,
                    };
                    if let Some(existing) = self
                        .logger_presets
                        .iter_mut()
                        .find(|p| p.name.eq_ignore_ascii_case(&name))
                    {
                        *existing = preset;
                    } else {
                        self.logger_presets.push(preset);
                    }
                    self.logger_preset_name.clear();
                    self.save_settings();
                }
            }
            // Stats toggle + live rate
            let stats_label = format!(
                "{} ({rate_total:.1} {})",
                self.i18n.text("rust.logger.stats"),
                self.i18n.text("rust.logger.pkt_per_sec")
            );
            let stats_bg = if self.logger_show_stats {
                if dark {
                    egui::Color32::from_rgb(35, 86, 62)
                } else {
                    egui::Color32::from_rgb(212, 237, 224)
                }
            } else {
                egui::Color32::TRANSPARENT
            };
            let stats_fg = if self.logger_show_stats {
                if dark {
                    egui::Color32::WHITE
                } else {
                    egui::Color32::from_rgb(20, 90, 50)
                }
            } else {
                ui_fg
            };
            if vector_text_button(
                ui,
                VectorIcon::Star,
                stats_fg,
                &stats_label,
                Some(stats_fg),
                Some(stats_bg),
                true,
            )
            .clicked()
            {
                self.logger_show_stats = !self.logger_show_stats;
            }
            // Custom packet names manager button (HabboCity / custom headers)
            let custom_label = if self.custom_packet_names.is_empty() {
                self.i18n.text("rust.logger.custom_names")
            } else {
                format!(
                    "{} ({})",
                    self.i18n.text("rust.logger.custom_names"),
                    self.custom_packet_names.len()
                )
            };
            if vector_text_button(ui, VectorIcon::Gear, ui_fg, &custom_label, None, None, true)
                .clicked()
            {
                self.custom_names_window_open = true;
            }
            if self.logger_friendly {
                if vector_text_button(
                    ui,
                    VectorIcon::Sparkle,
                    self.theme
                        .palette_with_accent(self.custom_accent)
                        .primary_accent,
                    &self.i18n.text("rust.logger.friendly_mode"),
                    None,
                    None,
                    true,
                )
                .clicked()
                {
                    self.logger_friendly = false;
                }
            } else if ui
                .small_button(self.i18n.text("rust.logger.classic_mode"))
                .clicked()
            {
                self.logger_friendly = true;
            }
        });
        if self.logger_show_stats {
            let palette = self.theme.palette_with_accent(self.custom_accent);
            let top = self.logger_stats.top_headers(8);
            let mut stats_filter_req = None;
            let mut stats_hide_req = None;
            group_box(ui, self.theme, egui::Margin::symmetric(8.0, 4.0), |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.strong(format!(
                        "{rate_total:.1} {}",
                        self.i18n.text("rust.logger.pkt_per_sec")
                    ));
                    ui.small(
                        egui::RichText::new(format!(
                            "(← {rate_in:.1} · → {rate_out:.1} | Total: ← {} · → {})",
                            self.logger_stats.total_in, self.logger_stats.total_out
                        ))
                        .color(palette.text_muted),
                    );
                    if !top.is_empty() {
                        ui.separator();
                        ui.small(
                            egui::RichText::new(format!(
                                "{}:",
                                self.i18n.text("rust.logger.top_headers")
                            ))
                            .color(palette.text_muted),
                        );
                        for (dir, hdr, count) in &top {
                            let (names, _) = log_packet_metadata(&self.packet_info, *dir, *hdr);
                            let arrow = if *dir == Direction::ToServer {
                                "→"
                            } else {
                                "←"
                            };
                            let chip = if names.is_empty() {
                                format!("{arrow} #{hdr} ({count})")
                            } else {
                                let short = names.split("][").next().unwrap_or(&names);
                                format!("{arrow} {short} #{hdr} ({count})")
                            };
                            let resp = ui.small_button(&chip).on_hover_text(format!(
                                "{} · {}",
                                self.i18n.text("rust.logger.filter"),
                                self.i18n.text("rust.logger.hide_header")
                            ));
                            if resp.clicked() {
                                stats_filter_req = Some(hdr.to_string());
                            } else if resp.secondary_clicked() {
                                stats_hide_req = Some((*dir, *hdr));
                            }
                        }
                    }
                });
            });
            if let Some(q) = stats_filter_req {
                self.filter = q;
            }
            if let Some(pair) = stats_hide_req {
                self.logger_hidden_headers.insert(pair);
            }
        }
        ui.separator();
        let (display_incoming, display_outgoing) = logger_display::displayed_directions(
            self.incoming,
            self.outgoing,
            self.logger_capture_selected_only,
        );
        let filter = self.filter.to_lowercase();
        if self
            .logger_search_cache
            .as_ref()
            .is_none_or(|(cached, _)| cached != &filter)
        {
            self.logger_search_cache = Some((
                filter.clone(),
                matching_packet_metadata(&self.packet_info, &filter),
            ));
        }
        let matching_metadata = &self
            .logger_search_cache
            .as_ref()
            .expect("search cache initialized")
            .1;
        let hide_noisy = self.logger_hide_noisy;
        let hidden_headers = &self.logger_hidden_headers;
        let packet_info_ref = &self.packet_info;
        let filtered: Vec<_> = self
            .logs
            .iter()
            .filter(|row| {
                if !log_row_matches(
                    row,
                    &filter,
                    matching_metadata,
                    display_outgoing,
                    display_incoming,
                ) {
                    return false;
                }
                let dir = row.message.direction;
                let hdr = row.message.packet.header();
                if hidden_headers.contains(&(dir, hdr)) {
                    return false;
                }
                if hide_noisy {
                    let (names, _) = row
                        .packet_metadata
                        .get_or_init(|| log_packet_metadata(packet_info_ref, dir, hdr));
                    if logger_ui::is_noisy_packet(dir, hdr, names) {
                        return false;
                    }
                }
                true
            })
            .collect();
        let mut inspection = None;
        let mut open_injection_req: Option<(Direction, String)> = None;
        let mut replay_req: Option<(Direction, gearth_rust::packet::Packet)> = None;
        let mut diff_base_req: Option<logger_ui::PacketSnapshot> = None;
        let mut diff_compare_req: Option<logger_ui::PacketSnapshot> = None;
        let mut block_header_req: Option<(Direction, u16)> = None;
        let mut hide_header_req: Option<(Direction, u16)> = None;
        let mut rename_header_req: Option<(Direction, u16, String)> = None;
        let mut copy_status_req: Option<String> = None;
        let logger_connected = self.relay.as_ref().is_some_and(Connection::connected);
        let has_diff_base = self.diff_base.is_some();
        let hide_empty_header = logger_display::hide_empty_byte_header(
            self.logger_display_hide_empty_header,
            self.logger_representation,
            self.logger_extra_legacy,
            self.logger_extra_hex_dump,
            self.logger_extra_raw_hex,
        );
        let has_selected = self.logger_friendly
            && self
                .selected_log_index
                .is_some_and(|sel| self.logs.iter().any(|row| row.message.index == sel));
        let inspector_reserve = if has_selected { 164.0 } else { 0.0 };
        let log_height = (ui.available_height() - 28.0 - inspector_reserve).max(96.0);
        if self.logger_friendly {
            let palette = self.theme.palette_with_accent(self.custom_accent);
            let dark = ui.visuals().dark_mode;
            let empty_payload = self.i18n.text("rust.logger.empty_payload");
            let friendly_row_h = 46.0;
            egui::ScrollArea::vertical()
                .id_salt("friendly_logger_scroll")
                .max_height(log_height)
                .stick_to_bottom(self.logger_autoscroll)
                .show_rows(ui, friendly_row_h, filtered.len(), |ui, range| {
                    for i in range {
                        let row = filtered[i];
                        let m = &row.message;
                        let selected = self.selected_log_index == Some(m.index);
                        let (accent, badge_bg, badge_fg) = if m.blocked || m.packet.edited {
                            (
                                egui::Color32::from_rgb(217, 130, 15),
                                egui::Color32::from_rgb(217, 130, 15),
                                egui::Color32::WHITE,
                            )
                        } else if m.direction == Direction::ToServer {
                            (
                                egui::Color32::from_rgb(0, 114, 214),
                                if dark {
                                    egui::Color32::from_rgb(26, 94, 170)
                                } else {
                                    egui::Color32::from_rgb(214, 233, 255)
                                },
                                if dark {
                                    egui::Color32::WHITE
                                } else {
                                    egui::Color32::from_rgb(10, 74, 158)
                                },
                            )
                        } else {
                            (
                                egui::Color32::from_rgb(198, 40, 40),
                                if dark {
                                    egui::Color32::from_rgb(150, 38, 38)
                                } else {
                                    egui::Color32::from_rgb(253, 224, 227)
                                },
                                if dark {
                                    egui::Color32::WHITE
                                } else {
                                    egui::Color32::from_rgb(148, 24, 34)
                                },
                            )
                        };
                        let row_bg = if selected {
                            ui.visuals().selection.bg_fill
                        } else if i % 2 == 1 {
                            palette.table_row_alt_bg
                        } else {
                            palette.content_bg
                        };
                        let (names, _) = row.packet_metadata.get_or_init(|| {
                            log_packet_metadata(&self.packet_info, m.direction, m.packet.header())
                        });
                        let title = if !names.is_empty() {
                            names.replace("][", " / ")
                        } else {
                            format!("Packet #{}", m.packet.header())
                        };
                        let payload_len = if m.packet.format() == PacketFormat::EvaWire {
                            m.packet.bytes().len().saturating_sub(4)
                        } else {
                            m.packet.bytes().len()
                        };
                        let summary = if row.skipped {
                            row.expression.clone()
                        } else {
                            let (expr, _, _) = row.packet_expression.get_or_init(|| {
                                let (expression, known) =
                                    gearth_rust::structure_prediction::expression_with_metadata(
                                        &m.packet,
                                        m.direction,
                                        &self.packet_info,
                                        row.unity,
                                    )
                                    .unwrap_or_default();
                                let clean = logger_display::java_structure_is_clean(&expression);
                                (bounded_log_prediction(expression), known, clean)
                            });
                            let source = if expr.is_empty() {
                                &row.expression
                            } else {
                                expr
                            };
                            let fields = logger_ui::parse_expression_fields(source);
                            logger_ui::summarize_fields(&fields, &empty_payload, 140)
                        };

                        let card = egui::Frame::none()
                            .fill(row_bg)
                            .inner_margin(egui::Margin {
                                left: 8.0,
                                right: 8.0,
                                top: 4.0,
                                bottom: 4.0,
                            })
                            .show(ui, |ui| {
                                ui.set_min_size(egui::vec2(
                                    (ui.available_width() - 4.0).max(200.0),
                                    friendly_row_h - 8.0,
                                ));
                                ui.horizontal(|ui| {
                                    let dir_badge = if m.direction == Direction::ToServer {
                                        format!("→ {outgoing_label}")
                                    } else {
                                        format!("← {incoming_label}")
                                    };
                                    logger_ui::badge_pill(ui, &dir_badge, badge_bg, badge_fg);
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(&title).strong().size(12.5),
                                        )
                                        .truncate(),
                                    );
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "ID {} · {} B",
                                            m.packet.header(),
                                            payload_len
                                        ))
                                        .small()
                                        .color(palette.text_muted),
                                    );
                                    if m.blocked {
                                        logger_ui::badge_pill(
                                            ui,
                                            &blocked_label,
                                            egui::Color32::from_rgb(198, 40, 40),
                                            egui::Color32::WHITE,
                                        );
                                    } else if m.packet.edited {
                                        logger_ui::badge_pill(
                                            ui,
                                            &replaced_label,
                                            egui::Color32::from_rgb(217, 130, 15),
                                            egui::Color32::WHITE,
                                        );
                                    }
                                    if let Some(ts) = row.timestamp_ms {
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                ui.label(
                                                    egui::RichText::new(
                                                        logger_ui::format_clock_time(ts),
                                                    )
                                                    .small()
                                                    .monospace()
                                                    .color(palette.text_muted),
                                                );
                                            },
                                        );
                                    }
                                });
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(&summary)
                                            .small()
                                            .color(palette.text_muted),
                                    )
                                    .truncate(),
                                );
                            });
                        let rect = card.response.rect;
                        ui.painter().rect_filled(
                            egui::Rect::from_min_size(
                                rect.left_top(),
                                egui::vec2(3.0, rect.height()),
                            ),
                            0.0,
                            accent,
                        );
                        if self.logger_split {
                            let y = rect.bottom() - 0.5;
                            ui.painter().line_segment(
                                [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
                                egui::Stroke::new(0.5_f32, palette.tab_active_border),
                            );
                        }
                        let response = card.response.interact(egui::Sense::click());
                        let editable_expr = row
                            .packet_expression
                            .get()
                            .and_then(|(e, _, clean)| (!e.is_empty() && *clean).then(|| e.clone()))
                            .unwrap_or_else(|| row.expression.clone());
                        response.context_menu(|ui| {
                            if ui
                                .add_enabled(
                                    !row.skipped && logger_connected,
                                    egui::Button::new(self.i18n.text("rust.logger.replay_now")),
                                )
                                .clicked()
                            {
                                replay_req = Some((m.direction, m.packet.clone()));
                                ui.close_menu();
                            }
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.open_injection")),
                                )
                                .clicked()
                            {
                                open_injection_req = Some((m.direction, editable_expr.clone()));
                                ui.close_menu();
                            }
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.diff_set_base")),
                                )
                                .clicked()
                            {
                                let fields = logger_ui::parse_expression_fields(&editable_expr);
                                diff_base_req = Some(logger_ui::PacketSnapshot {
                                    direction: m.direction,
                                    header: m.packet.header(),
                                    title: title.clone(),
                                    expression: editable_expr.clone(),
                                    fields,
                                    bytes: m.packet.bytes().to_vec(),
                                });
                                ui.close_menu();
                            }
                            if has_diff_base
                                && ui
                                    .add_enabled(
                                        !row.skipped,
                                        egui::Button::new(
                                            self.i18n.text("rust.logger.diff_compare"),
                                        ),
                                    )
                                    .clicked()
                            {
                                let fields = logger_ui::parse_expression_fields(&editable_expr);
                                diff_compare_req = Some(logger_ui::PacketSnapshot {
                                    direction: m.direction,
                                    header: m.packet.header(),
                                    title: title.clone(),
                                    expression: editable_expr.clone(),
                                    fields,
                                    bytes: m.packet.bytes().to_vec(),
                                });
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.copy_packet")),
                                )
                                .clicked()
                            {
                                ui.ctx().copy_text(row.expression.clone());
                                ui.close_menu();
                            }
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.copy_python")),
                                )
                                .clicked()
                            {
                                let fields = logger_ui::parse_expression_fields(
                                    row.packet_expression
                                        .get()
                                        .map(|(e, _, _)| e.as_str())
                                        .filter(|s| !s.is_empty())
                                        .unwrap_or(&row.expression),
                                );
                                let name_opt = (!names.is_empty()).then_some(title.as_str());
                                let snippet = logger_ui::to_gpython_snippet(
                                    m.direction,
                                    m.packet.header(),
                                    name_opt,
                                    &row.expression,
                                    &fields,
                                );
                                ui.ctx().copy_text(snippet);
                                copy_status_req = Some(format!(
                                    "Copied G-Python snippet for header {}",
                                    m.packet.header()
                                ));
                                ui.close_menu();
                            }
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.copy_java")),
                                )
                                .clicked()
                            {
                                let fields = logger_ui::parse_expression_fields(
                                    row.packet_expression
                                        .get()
                                        .map(|(e, _, _)| e.as_str())
                                        .filter(|s| !s.is_empty())
                                        .unwrap_or(&row.expression),
                                );
                                let name_opt = (!names.is_empty()).then_some(title.as_str());
                                let snippet = logger_ui::to_java_snippet(
                                    m.direction,
                                    m.packet.header(),
                                    name_opt,
                                    &row.expression,
                                    &fields,
                                );
                                ui.ctx().copy_text(snippet);
                                copy_status_req = Some(format!(
                                    "Copied Java snippet for header {}",
                                    m.packet.header()
                                ));
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui
                                .button(self.i18n.text("rust.logger.hide_header"))
                                .clicked()
                            {
                                hide_header_req = Some((m.direction, m.packet.header()));
                                ui.close_menu();
                            }
                            if ui
                                .button(self.i18n.text("rust.logger.rename_header"))
                                .clicked()
                            {
                                let existing = if !names.is_empty() {
                                    names.split("][").next().unwrap_or("").to_owned()
                                } else {
                                    String::new()
                                };
                                rename_header_req =
                                    Some((m.direction, m.packet.header(), existing));
                                ui.close_menu();
                            }
                            if ui
                                .button(self.i18n.text("rust.logger.block_header"))
                                .clicked()
                            {
                                block_header_req = Some((m.direction, m.packet.header()));
                                ui.close_menu();
                            }
                            if ui
                                .button(self.i18n.text("rust.logger.inspect_bytes"))
                                .clicked()
                            {
                                inspection = Some(logger_display::hex_dump(m.packet.bytes(), 4096));
                                ui.close_menu();
                            }
                        });
                        if response.double_clicked() && !row.skipped {
                            open_injection_req = Some((m.direction, editable_expr));
                        } else if response.clicked() {
                            self.selected_log_index = Some(m.index);
                        }
                    }
                });

            // Beginner-friendly Packet Details Inspector panel
            if let Some(sel_idx) = self.selected_log_index {
                if let Some(row) = self.logs.iter().find(|r| r.message.index == sel_idx) {
                    let m = &row.message;
                    let (names, hashes) = row.packet_metadata.get_or_init(|| {
                        log_packet_metadata(&self.packet_info, m.direction, m.packet.header())
                    });
                    let title = if !names.is_empty() {
                        names.replace("][", " / ")
                    } else {
                        format!("Packet #{}", m.packet.header())
                    };
                    let expr_source = if !row.skipped {
                        let (expr, _, _) = row.packet_expression.get_or_init(|| {
                            let (expression, known) =
                                gearth_rust::structure_prediction::expression_with_metadata(
                                    &m.packet,
                                    m.direction,
                                    &self.packet_info,
                                    row.unity,
                                )
                                .unwrap_or_default();
                            let clean = logger_display::java_structure_is_clean(&expression);
                            (bounded_log_prediction(expression), known, clean)
                        });
                        if expr.is_empty() {
                            row.expression.as_str()
                        } else {
                            expr.as_str()
                        }
                    } else {
                        row.expression.as_str()
                    };
                    let fields = logger_ui::parse_expression_fields(expr_source);
                    ui.add_space(4.0);
                    group_box(ui, self.theme, egui::Margin::symmetric(8.0, 6.0), |ui| {
                        ui.set_min_width((ui.available_width() - 4.0).max(200.0));
                        ui.horizontal(|ui| {
                            ui.strong(format!(
                                "{} — {title} (ID {})",
                                self.i18n.text("rust.logger.inspector"),
                                m.packet.header()
                            ));
                            ui.label(
                                egui::RichText::new(self.i18n.text(
                                    if m.direction == Direction::ToServer {
                                        "rust.logger.direction_out_desc"
                                    } else {
                                        "rust.logger.direction_in_desc"
                                    },
                                ))
                                .small()
                                .color(palette.text_muted),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if vector_icon_button(
                                        ui,
                                        VectorIcon::Close,
                                        egui::vec2(20.0, 20.0),
                                        10.0,
                                        None,
                                        ui.visuals().text_color(),
                                    )
                                    .clicked()
                                    {
                                        self.selected_log_index = None;
                                    }
                                },
                            );
                        });
                        if !hashes.is_empty() {
                            ui.small(
                                egui::RichText::new(format!("Hash: {hashes}"))
                                    .color(palette.text_muted),
                            );
                        }
                        ui.add_space(3.0);
                        egui::ScrollArea::vertical()
                            .id_salt("logger_inspector_fields")
                            .max_height(52.0)
                            .show(ui, |ui| {
                                if fields.is_empty() {
                                    ui.small(
                                        egui::RichText::new(&empty_payload)
                                            .italics()
                                            .color(palette.text_muted),
                                    );
                                } else {
                                    ui.horizontal_wrapped(|ui| {
                                        for field in &fields {
                                            let bg = if field.is_string {
                                                if dark {
                                                    egui::Color32::from_rgb(45, 78, 52)
                                                } else {
                                                    egui::Color32::from_rgb(225, 244, 229)
                                                }
                                            } else if dark {
                                                egui::Color32::from_rgb(56, 56, 64)
                                            } else {
                                                egui::Color32::from_rgb(236, 238, 242)
                                            };
                                            egui::Frame::none()
                                                .fill(bg)
                                                .rounding(egui::Rounding::same(3.0))
                                                .inner_margin(egui::Margin::symmetric(5.0, 2.0))
                                                .show(ui, |ui| {
                                                    ui.horizontal(|ui| {
                                                        ui.spacing_mut().item_spacing.x = 3.0;
                                                        ui.label(
                                                            egui::RichText::new(format!(
                                                                "{}:",
                                                                field.kind
                                                            ))
                                                            .small()
                                                            .color(palette.text_muted),
                                                        );
                                                        ui.label(
                                                            egui::RichText::new(&field.value)
                                                                .small()
                                                                .monospace(),
                                                        );
                                                    });
                                                });
                                        }
                                    });
                                }
                            });
                        ui.add_space(4.0);
                        ui.horizontal_wrapped(|ui| {
                            let ui_fg = ui.visuals().text_color();
                            if ui
                                .add_enabled(
                                    !row.skipped && logger_connected,
                                    egui::Button::new(self.i18n.text("rust.logger.replay_now")),
                                )
                                .clicked()
                            {
                                replay_req = Some((m.direction, m.packet.clone()));
                            }
                            let send_clicked = ui
                                .add_enabled_ui(!row.skipped, |ui| {
                                    vector_text_button(
                                        ui,
                                        VectorIcon::ArrowRight,
                                        palette.primary_accent,
                                        &self.i18n.text("rust.logger.open_injection"),
                                        None,
                                        None,
                                        false,
                                    )
                                    .clicked()
                                })
                                .inner;
                            if send_clicked {
                                let best_expr = row
                                    .packet_expression
                                    .get()
                                    .and_then(|(e, _, clean)| {
                                        (!e.is_empty() && *clean).then(|| e.clone())
                                    })
                                    .unwrap_or_else(|| row.expression.clone());
                                open_injection_req = Some((m.direction, best_expr));
                            }
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.diff_set_base")),
                                )
                                .clicked()
                            {
                                diff_base_req = Some(logger_ui::PacketSnapshot {
                                    direction: m.direction,
                                    header: m.packet.header(),
                                    title: title.clone(),
                                    expression: expr_source.to_owned(),
                                    fields: fields.clone(),
                                    bytes: m.packet.bytes().to_vec(),
                                });
                            }
                            if has_diff_base
                                && ui
                                    .add_enabled(
                                        !row.skipped,
                                        egui::Button::new(
                                            self.i18n.text("rust.logger.diff_compare"),
                                        ),
                                    )
                                    .clicked()
                            {
                                diff_compare_req = Some(logger_ui::PacketSnapshot {
                                    direction: m.direction,
                                    header: m.packet.header(),
                                    title: title.clone(),
                                    expression: expr_source.to_owned(),
                                    fields: fields.clone(),
                                    bytes: m.packet.bytes().to_vec(),
                                });
                            }
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.copy_packet")),
                                )
                                .clicked()
                            {
                                ui.ctx().copy_text(row.expression.clone());
                            }
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.copy_python")),
                                )
                                .clicked()
                            {
                                let name_opt = (!names.is_empty()).then_some(title.as_str());
                                let snippet = logger_ui::to_gpython_snippet(
                                    m.direction,
                                    m.packet.header(),
                                    name_opt,
                                    &row.expression,
                                    &fields,
                                );
                                ui.ctx().copy_text(snippet);
                                copy_status_req = Some(format!(
                                    "Copied G-Python snippet for header {}",
                                    m.packet.header()
                                ));
                            }
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.copy_java")),
                                )
                                .clicked()
                            {
                                let name_opt = (!names.is_empty()).then_some(title.as_str());
                                let snippet = logger_ui::to_java_snippet(
                                    m.direction,
                                    m.packet.header(),
                                    name_opt,
                                    &row.expression,
                                    &fields,
                                );
                                ui.ctx().copy_text(snippet);
                                copy_status_req = Some(format!(
                                    "Copied Java snippet for header {}",
                                    m.packet.header()
                                ));
                            }
                            if ui
                                .button(self.i18n.text("rust.logger.hide_header"))
                                .clicked()
                            {
                                hide_header_req = Some((m.direction, m.packet.header()));
                            }
                            if ui
                                .button(self.i18n.text("rust.logger.rename_header"))
                                .clicked()
                            {
                                let existing = if !names.is_empty() {
                                    names.split("][").next().unwrap_or("").to_owned()
                                } else {
                                    String::new()
                                };
                                rename_header_req =
                                    Some((m.direction, m.packet.header(), existing));
                            }
                            if vector_text_button(
                                ui,
                                VectorIcon::Block,
                                egui::Color32::from_rgb(200, 65, 65),
                                &self.i18n.text("rust.logger.block_header"),
                                Some(ui_fg),
                                None,
                                false,
                            )
                            .clicked()
                            {
                                block_header_req = Some((m.direction, m.packet.header()));
                            }
                            if ui
                                .button(self.i18n.text("rust.logger.inspect_bytes"))
                                .clicked()
                            {
                                inspection = Some(logger_display::hex_dump(m.packet.bytes(), 4096));
                            }
                        });
                    });
                }
            }
        } else {
            let extra_lines = usize::from(
                self.logger_extra_legacy
                    && self.logger_representation != PacketRepresentation::Legacy,
            ) + usize::from(
                self.logger_extra_raw_hex
                    && self.logger_representation != PacketRepresentation::RawHex,
            );
            let row_height = if self.logger_representation == PacketRepresentation::HexDump
                || self.logger_extra_hex_dump
            {
                // Eight 16-byte lines, an offset/truncation footer, and the header.
                ui.text_style_height(&egui::TextStyle::Monospace) * 13.0
                    + if self.logger_structure { 24.0 } else { 0.0 }
            } else if self.logger_structure {
                44.0
            } else {
                24.0
            } + extra_lines as f32
                * (ui.text_style_height(&egui::TextStyle::Monospace) + ui.spacing().item_spacing.y)
                + if self.logger_timestamp {
                    ui.text_style_height(&egui::TextStyle::Monospace) + ui.spacing().item_spacing.y
                } else {
                    0.0
                }
                + if self.logger_names || self.logger_hashes || self.logger_message_id {
                    ui.text_style_height(&egui::TextStyle::Monospace) + ui.spacing().item_spacing.y
                } else {
                    0.0
                }
                + if filtered
                    .iter()
                    .any(|row| row.message.blocked || row.message.packet.edited)
                {
                    ui.text_style_height(&egui::TextStyle::Monospace) + ui.spacing().item_spacing.y
                } else {
                    0.0
                };
            egui::ScrollArea::vertical()
                .max_height(log_height)
                .stick_to_bottom(self.logger_autoscroll)
                .show_rows(ui, row_height, filtered.len(), |ui, range| {
                    for i in range {
                        let row = filtered[i];
                        let m = &row.message;
                        let (color, hex_color, marker_color) =
                            log_colors(m.direction, ui.visuals().dark_mode);
                        let rendered = render_log_row(row, &self.packet_info, display_options);
                        let row_output = ui.allocate_ui_with_layout(
                            egui::vec2(ui.available_width(), row_height),
                            egui::Layout::top_down(egui::Align::Min),
                            |ui| {
                                if let Some(timestamp) = &rendered.timestamp {
                                    ui.monospace(timestamp);
                                }
                                if let Some(metadata) = &rendered.metadata {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(metadata).monospace().color(color),
                                        )
                                        .truncate(),
                                    );
                                }
                                if let Some(marker) = &rendered.marker {
                                    ui.label(
                                        egui::RichText::new(marker).monospace().color(marker_color),
                                    );
                                }
                                let response = if hide_empty_header {
                                    ui.allocate_response(
                                        egui::vec2(ui.available_width(), 2.0),
                                        egui::Sense::click(),
                                    )
                                } else {
                                    ui.add(
                                        egui::Label::new(log_header_layout(
                                            &rendered.header,
                                            None,
                                            color,
                                            marker_color,
                                            ui.text_style_height(&egui::TextStyle::Monospace),
                                        ))
                                        .truncate()
                                        .sense(egui::Sense::click()),
                                    )
                                };
                                for representation in &rendered.extra_representations {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(representation)
                                                .monospace()
                                                .color(color),
                                        )
                                        .truncate(),
                                    );
                                }
                                if let Some(dump) = &rendered.dump {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(dump).monospace().color(hex_color),
                                        )
                                        .wrap_mode(egui::TextWrapMode::Extend),
                                    );
                                }
                                if let Some(raw_hex) = &rendered.extra_raw_hex {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(raw_hex)
                                                .monospace()
                                                .color(hex_color),
                                        )
                                        .truncate(),
                                    );
                                }
                                if let Some(structure) = &rendered.structure {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(structure).monospace().small(),
                                        )
                                        .truncate(),
                                    );
                                }
                                response
                            },
                        );
                        let response = logger_row_response(
                            row_output.inner,
                            row_output.response.clone(),
                            hide_empty_header,
                        );
                        response.context_menu(|ui| {
                            if ui
                                .add_enabled(
                                    !row.skipped && logger_connected,
                                    egui::Button::new(self.i18n.text("rust.logger.replay_now")),
                                )
                                .clicked()
                            {
                                replay_req = Some((m.direction, m.packet.clone()));
                                ui.close_menu();
                            }
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.open_injection")),
                                )
                                .clicked()
                            {
                                let expr = row
                                    .packet_expression
                                    .get()
                                    .and_then(|(e, _, clean)| {
                                        (!e.is_empty() && *clean).then(|| e.clone())
                                    })
                                    .unwrap_or_else(|| row.expression.clone());
                                open_injection_req = Some((m.direction, expr));
                                ui.close_menu();
                            }
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.diff_set_base")),
                                )
                                .clicked()
                            {
                                let (names, _) = row.packet_metadata.get_or_init(|| {
                                    log_packet_metadata(
                                        &self.packet_info,
                                        m.direction,
                                        m.packet.header(),
                                    )
                                });
                                let expr_src = row
                                    .packet_expression
                                    .get()
                                    .map(|(e, _, _)| e.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&row.expression);
                                let title = if !names.is_empty() {
                                    names.replace("][", " / ")
                                } else {
                                    format!("Packet #{}", m.packet.header())
                                };
                                diff_base_req = Some(logger_ui::PacketSnapshot {
                                    direction: m.direction,
                                    header: m.packet.header(),
                                    title,
                                    expression: expr_src.to_owned(),
                                    fields: logger_ui::parse_expression_fields(expr_src),
                                    bytes: m.packet.bytes().to_vec(),
                                });
                                ui.close_menu();
                            }
                            if has_diff_base
                                && ui
                                    .add_enabled(
                                        !row.skipped,
                                        egui::Button::new(
                                            self.i18n.text("rust.logger.diff_compare"),
                                        ),
                                    )
                                    .clicked()
                            {
                                let (names, _) = row.packet_metadata.get_or_init(|| {
                                    log_packet_metadata(
                                        &self.packet_info,
                                        m.direction,
                                        m.packet.header(),
                                    )
                                });
                                let expr_src = row
                                    .packet_expression
                                    .get()
                                    .map(|(e, _, _)| e.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&row.expression);
                                let title = if !names.is_empty() {
                                    names.replace("][", " / ")
                                } else {
                                    format!("Packet #{}", m.packet.header())
                                };
                                diff_compare_req = Some(logger_ui::PacketSnapshot {
                                    direction: m.direction,
                                    header: m.packet.header(),
                                    title,
                                    expression: expr_src.to_owned(),
                                    fields: logger_ui::parse_expression_fields(expr_src),
                                    bytes: m.packet.bytes().to_vec(),
                                });
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui
                                .button(self.i18n.text("rust.logger.copy_displayed"))
                                .clicked()
                            {
                                let mut text = Vec::new();
                                if write_log_capture(
                                    &mut text,
                                    std::iter::once(row),
                                    &self.packet_info,
                                    LogDisplayOptions {
                                        export_hide_empty_header: hide_empty_header,
                                        ..display_options
                                    },
                                    false,
                                )
                                .is_ok()
                                {
                                    ui.ctx().copy_text(
                                        String::from_utf8_lossy(&text)
                                            .trim_end_matches('\n')
                                            .to_owned(),
                                    );
                                }
                                ui.close_menu();
                            }
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.copy_packet")),
                                )
                                .clicked()
                            {
                                ui.ctx().copy_text(row.expression.clone());
                                ui.close_menu();
                            }
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.copy_hex")),
                                )
                                .clicked()
                            {
                                ui.ctx().copy_text(expression::hex(m.packet.bytes()));
                                ui.close_menu();
                            }
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.copy_python")),
                                )
                                .clicked()
                            {
                                let (names, _) = row.packet_metadata.get_or_init(|| {
                                    log_packet_metadata(
                                        &self.packet_info,
                                        m.direction,
                                        m.packet.header(),
                                    )
                                });
                                let expr_src = row
                                    .packet_expression
                                    .get()
                                    .map(|(e, _, _)| e.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&row.expression);
                                let fields = logger_ui::parse_expression_fields(expr_src);
                                let title = names.replace("][", " / ");
                                let name_opt = (!title.is_empty()).then_some(title.as_str());
                                let snippet = logger_ui::to_gpython_snippet(
                                    m.direction,
                                    m.packet.header(),
                                    name_opt,
                                    &row.expression,
                                    &fields,
                                );
                                ui.ctx().copy_text(snippet);
                                copy_status_req = Some(format!(
                                    "Copied G-Python snippet for header {}",
                                    m.packet.header()
                                ));
                                ui.close_menu();
                            }
                            if ui
                                .add_enabled(
                                    !row.skipped,
                                    egui::Button::new(self.i18n.text("rust.logger.copy_java")),
                                )
                                .clicked()
                            {
                                let (names, _) = row.packet_metadata.get_or_init(|| {
                                    log_packet_metadata(
                                        &self.packet_info,
                                        m.direction,
                                        m.packet.header(),
                                    )
                                });
                                let expr_src = row
                                    .packet_expression
                                    .get()
                                    .map(|(e, _, _)| e.as_str())
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(&row.expression);
                                let fields = logger_ui::parse_expression_fields(expr_src);
                                let title = names.replace("][", " / ");
                                let name_opt = (!title.is_empty()).then_some(title.as_str());
                                let snippet = logger_ui::to_java_snippet(
                                    m.direction,
                                    m.packet.header(),
                                    name_opt,
                                    &row.expression,
                                    &fields,
                                );
                                ui.ctx().copy_text(snippet);
                                copy_status_req = Some(format!(
                                    "Copied Java snippet for header {}",
                                    m.packet.header()
                                ));
                                ui.close_menu();
                            }
                            ui.separator();
                            if ui
                                .button(self.i18n.text("rust.logger.hide_header"))
                                .clicked()
                            {
                                hide_header_req = Some((m.direction, m.packet.header()));
                                ui.close_menu();
                            }
                            if ui
                                .button(self.i18n.text("rust.logger.rename_header"))
                                .clicked()
                            {
                                let (names, _) = row.packet_metadata.get_or_init(|| {
                                    log_packet_metadata(
                                        &self.packet_info,
                                        m.direction,
                                        m.packet.header(),
                                    )
                                });
                                let existing = if !names.is_empty() {
                                    names.split("][").next().unwrap_or("").to_owned()
                                } else {
                                    String::new()
                                };
                                rename_header_req =
                                    Some((m.direction, m.packet.header(), existing));
                                ui.close_menu();
                            }
                            if ui
                                .button(self.i18n.text("rust.logger.inspect_bytes"))
                                .clicked()
                            {
                                inspection = Some(logger_display::hex_dump(m.packet.bytes(), 4096));
                                ui.close_menu();
                            }
                        });
                        if self.logger_split {
                            let rect = row_output.response.rect;
                            let y = rect.bottom() - 1.0;
                            ui.painter().line_segment(
                                [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
                                ui.visuals().widgets.noninteractive.bg_stroke,
                            );
                        }
                        if response.hovered() && !row.skipped {
                            let structure = row.predicted_structure.get_or_init(|| {
                                bounded_log_prediction(
                                    gearth_rust::structure_prediction::predict(
                                        &m.packet, row.unity,
                                    )
                                    .unwrap_or_else(|_| "unavailable".into()),
                                )
                            });
                            response
                                .clone()
                                .on_hover_text(format!("Predicted structure: {structure}"));
                        }
                        if response.clicked() && !row.skipped {
                            open_injection_req = Some((m.direction, row.expression.clone()));
                        }
                    }
                });
        }
        if let Some((dir, packet)) = replay_req {
            self.replay_logged_packet(dir, packet);
        }
        if let Some(base) = diff_base_req {
            self.status = self
                .i18n
                .text("rust.logger.diff_base_pinned")
                .replace("{header}", &base.header.to_string());
            self.diff_base = Some(base);
        }
        if let Some(target) = diff_compare_req {
            if let Some(base) = self.diff_base.clone() {
                self.diff_pair = Some((base, target));
            }
        }
        if let Some((dir, expr)) = open_injection_req {
            self.expression = expr;
            self.direction = dir;
            self.tab = Tab::Injection;
        }
        if let Some((dir, header)) = block_header_req {
            let already = self.settings.rules.iter().any(|(enabled, d, h, repl)| {
                *enabled && *d == dir && *h == header && repl.is_none()
            });
            if !already {
                self.settings.rules.push((true, dir, header, None));
                self.update_rules();
                let _ = Settings::save_rules(&self.settings_path, &self.settings.rules);
                self.status = format!("Blocked {} packet ID {header}", dir.name());
            }
        }
        if let Some((dir, header)) = hide_header_req {
            self.logger_hidden_headers.insert((dir, header));
            self.status = format!("Hidden {} header {header} in logger", dir.name());
        }
        if let Some((dir, header, existing)) = rename_header_req {
            self.rename_header_dialog = Some((dir, header, existing));
        }
        if let Some(msg) = copy_status_req {
            self.status = msg;
        }
        // Quick Rename Header modal
        if let Some((dir, header, mut name_buf)) = self.rename_header_dialog.clone() {
            let mut open = true;
            let mut save_it = false;
            let mut cancel_it = false;
            egui::Window::new(format!(
                "{} — {} #{header}",
                self.i18n.text("rust.logger.rename_header"),
                dir.name()
            ))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ui.ctx(), |ui| {
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut name_buf)
                        .desired_width(260.0)
                        .hint_text(self.i18n.text("rust.logger.custom_name_hint")),
                );
                if edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    save_it = true;
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button(self.i18n.text("rust.rule.save")).clicked() {
                        save_it = true;
                    }
                    if ui.button(self.i18n.text("rust.rule.cancel")).clicked() {
                        cancel_it = true;
                    }
                });
            });
            if save_it {
                self.upsert_custom_packet_name(dir, header, name_buf);
                self.rename_header_dialog = None;
            } else if cancel_it || !open {
                self.rename_header_dialog = None;
            } else {
                self.rename_header_dialog = Some((dir, header, name_buf));
            }
        }
        // Side-by-side Packet Diff window (A <-> B)
        if let Some((left, right)) = self.diff_pair.clone() {
            let mut open = true;
            let mut swap = false;
            let mut clear_base = false;
            let palette = self.theme.palette_with_accent(self.custom_accent);
            let field_diff = logger_ui::diff_packet_fields(&left.fields, &right.fields);
            let byte_diff = logger_ui::diff_packet_bytes(&left.bytes, &right.bytes, 512);
            let changed_fields = field_diff
                .iter()
                .filter(|r| r.kind != logger_ui::FieldDiffKind::Same)
                .count();
            let changed_bytes = byte_diff.iter().filter(|b| b.changed).count();
            egui::Window::new(self.i18n.text("rust.logger.diff_title"))
                .open(&mut open)
                .resizable(true)
                .default_size([560.0, 380.0])
                .show(ui.ctx(), |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(format!(
                            "A: {} (#{}, {} B)",
                            left.title,
                            left.header,
                            left.bytes.len()
                        ));
                        ui.label(
                            egui::RichText::new("vs")
                                .color(palette.primary_accent)
                                .strong(),
                        );
                        ui.strong(format!(
                            "B: {} (#{}, {} B)",
                            right.title,
                            right.header,
                            right.bytes.len()
                        ));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .small_button(self.i18n.text("rust.logger.diff_clear"))
                                .clicked()
                            {
                                clear_base = true;
                            }
                            if ui
                                .small_button(self.i18n.text("rust.logger.diff_swap"))
                                .clicked()
                            {
                                swap = true;
                            }
                        });
                    });
                    ui.small(
                        egui::RichText::new(
                            self.i18n
                                .text("rust.logger.diff_summary")
                                .replace("{fields}", &changed_fields.to_string())
                                .replace("{bytes}", &changed_bytes.to_string()),
                        )
                        .color(palette.text_muted),
                    );
                    ui.separator();
                    ui.label(
                        egui::RichText::new(self.i18n.text("rust.logger.diff_fields"))
                            .small()
                            .strong(),
                    );
                    egui::ScrollArea::vertical()
                        .id_salt("packet_diff_fields_scroll")
                        .max_height(155.0)
                        .show(ui, |ui| {
                            if field_diff.is_empty() {
                                ui.small(
                                    egui::RichText::new(
                                        self.i18n.text("rust.logger.empty_payload"),
                                    )
                                    .italics()
                                    .color(palette.text_muted),
                                );
                            } else {
                                egui::Grid::new("packet_diff_fields_grid")
                                    .striped(true)
                                    .spacing([10.0, 3.0])
                                    .show(ui, |ui| {
                                        ui.strong("#");
                                        ui.strong("Diff");
                                        ui.strong("Packet A");
                                        ui.strong("Packet B");
                                        ui.end_row();
                                        for row in &field_diff {
                                            let (badge, color) = match row.kind {
                                                logger_ui::FieldDiffKind::Same => {
                                                    ("=", palette.text_muted)
                                                }
                                                logger_ui::FieldDiffKind::Changed => {
                                                    ("~", egui::Color32::from_rgb(0xd9, 0x82, 0x2b))
                                                }
                                                logger_ui::FieldDiffKind::Added => {
                                                    ("+", egui::Color32::from_rgb(0x2e, 0xa0, 0x43))
                                                }
                                                logger_ui::FieldDiffKind::Removed => {
                                                    ("-", egui::Color32::from_rgb(0xd9, 0x3b, 0x3b))
                                                }
                                            };
                                            ui.monospace(format!("{}", row.index));
                                            ui.label(
                                                egui::RichText::new(badge)
                                                    .monospace()
                                                    .strong()
                                                    .color(color),
                                            );
                                            let fmt_side =
                                                |f: &Option<logger_ui::DecodedField>| match f {
                                                    Some(d) => format!("{}: {}", d.kind, d.value),
                                                    None => "—".into(),
                                                };
                                            ui.label(
                                                egui::RichText::new(fmt_side(&row.left))
                                                    .monospace()
                                                    .small()
                                                    .color(color),
                                            );
                                            ui.label(
                                                egui::RichText::new(fmt_side(&row.right))
                                                    .monospace()
                                                    .small()
                                                    .color(color),
                                            );
                                            ui.end_row();
                                        }
                                    });
                            }
                        });
                    ui.separator();
                    ui.label(
                        egui::RichText::new(self.i18n.text("rust.logger.diff_bytes"))
                            .small()
                            .strong(),
                    );
                    egui::ScrollArea::vertical()
                        .id_salt("packet_diff_bytes_scroll")
                        .max_height(110.0)
                        .show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.spacing_mut().item_spacing = egui::vec2(4.0, 2.0);
                                for chunk in &byte_diff {
                                    let l_hex = chunk
                                        .left
                                        .map(|b| format!("{b:02X}"))
                                        .unwrap_or_else(|| "--".into());
                                    let r_hex = chunk
                                        .right
                                        .map(|b| format!("{b:02X}"))
                                        .unwrap_or_else(|| "--".into());
                                    let text = if chunk.changed {
                                        format!("{:02X}:{l_hex}→{r_hex}", chunk.offset)
                                    } else {
                                        l_hex
                                    };
                                    let color = if chunk.changed {
                                        egui::Color32::from_rgb(0xd9, 0x82, 0x2b)
                                    } else {
                                        palette.text_muted
                                    };
                                    ui.label(
                                        egui::RichText::new(text).monospace().small().color(color),
                                    );
                                }
                            });
                        });
                });
            if clear_base {
                self.diff_base = None;
                self.diff_pair = None;
            } else if swap {
                self.diff_pair = Some((right, left));
            } else if !open {
                self.diff_pair = None;
            }
        }
        // Custom Packet Names Manager window (HabboCity / custom Nitro headers)
        if self.custom_names_window_open {
            let mut open = self.custom_names_window_open;
            let mut remove_custom: Option<(Direction, u16)> = None;
            let mut add_custom = false;
            let mut import_custom = false;
            let mut export_custom = false;
            egui::Window::new(self.i18n.text("rust.logger.custom_names"))
                .open(&mut open)
                .resizable(true)
                .default_width(480.0)
                .show(ui.ctx(), |ui| {
                    ui.small(format!("{}", self.custom_packet_names_path().display()));
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        direction_selector(ui, &mut self.custom_name_direction, &self.i18n);
                        ui.add(
                            egui::DragValue::new(&mut self.custom_name_header)
                                .prefix("#")
                                .range(0..=u16::MAX),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.custom_name_input)
                                .desired_width(180.0)
                                .hint_text(self.i18n.text("rust.logger.custom_name_hint")),
                        );
                        if ui
                            .add_enabled(
                                !self.custom_name_input.trim().is_empty(),
                                egui::Button::new(self.i18n.text("rust.rule.save")),
                            )
                            .clicked()
                        {
                            add_custom = true;
                        }
                    });
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui
                            .button(self.i18n.text("rust.logger.import_custom_names"))
                            .clicked()
                        {
                            import_custom = true;
                        }
                        if ui
                            .button(self.i18n.text("rust.logger.export_custom_names"))
                            .clicked()
                        {
                            export_custom = true;
                        }
                    });
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .id_salt("custom_packet_names_scroll")
                        .max_height(260.0)
                        .show(ui, |ui| {
                            if self.custom_packet_names.is_empty() {
                                ui.small(
                                    egui::RichText::new(
                                        self.i18n.text("rust.logger.no_custom_names"),
                                    )
                                    .italics()
                                    .color(
                                        self.theme
                                            .palette_with_accent(self.custom_accent)
                                            .text_muted,
                                    ),
                                );
                            } else {
                                for (dir, hdr, name) in &self.custom_packet_names {
                                    ui.horizontal(|ui| {
                                        ui.monospace(format!("{} #{hdr:<5}", dir.name()));
                                        ui.strong(name);
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                if ui
                                                    .small_button(
                                                        self.i18n.text("rust.action.remove"),
                                                    )
                                                    .clicked()
                                                {
                                                    remove_custom = Some((*dir, *hdr));
                                                }
                                            },
                                        );
                                    });
                                }
                            }
                        });
                });
            self.custom_names_window_open = open;
            if add_custom {
                let name = std::mem::take(&mut self.custom_name_input);
                self.upsert_custom_packet_name(
                    self.custom_name_direction,
                    self.custom_name_header,
                    name,
                );
            }
            if let Some((dir, hdr)) = remove_custom {
                self.remove_custom_packet_name(dir, hdr);
            }
            if import_custom {
                match gearth_platform::choose_file(gearth_platform::FileKind::Json, false) {
                    Ok(Some(selected)) => match PacketInfoManager::load_custom_names(&selected) {
                        Ok(imported) => {
                            let count = imported.len();
                            for (dir, hdr, name) in imported {
                                if let Some(existing) = self
                                    .custom_packet_names
                                    .iter_mut()
                                    .find(|(d, h, _)| *d == dir && *h == hdr)
                                {
                                    existing.2 = name;
                                } else {
                                    self.custom_packet_names.push((dir, hdr, name));
                                }
                            }
                            self.custom_packet_names
                                .sort_by(|a, b| (a.0.name(), a.1).cmp(&(b.0.name(), b.1)));
                            self.apply_custom_packet_names();
                            let _ = PacketInfoManager::save_custom_names(
                                &self.custom_packet_names_path(),
                                &self.custom_packet_names,
                            );
                            self.status = format!("Imported {count} custom packet names");
                        }
                        Err(e) => self.status = format!("Import failed: {e}"),
                    },
                    Ok(None) => {}
                    Err(e) => {
                        self.status = format!("{}: {e}", self.i18n.text("rust.dialog.failed"))
                    }
                }
            }
            if export_custom {
                match gearth_platform::choose_file(gearth_platform::FileKind::Json, true) {
                    Ok(Some(selected)) => {
                        match PacketInfoManager::save_custom_names(
                            &selected,
                            &self.custom_packet_names,
                        ) {
                            Ok(()) => {
                                self.status = format!(
                                    "Exported custom packet names to {}",
                                    selected.display()
                                )
                            }
                            Err(e) => self.status = format!("Export failed: {e}"),
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        self.status = format!("{}: {e}", self.i18n.text("rust.dialog.failed"))
                    }
                }
            }
        }
        if let Some(dump) = inspection {
            self.packet_dump = Some(dump);
        }
        let mut open = self.packet_dump.is_some();
        if let Some(dump) = &self.packet_dump {
            egui::Window::new(self.i18n.text("rust.logger.packet_bytes"))
                .open(&mut open)
                .resizable(true)
                .default_width(720.0)
                .show(ui.ctx(), |ui| {
                    if ui.button(self.i18n.text("rust.logger.copy_dump")).clicked() {
                        ui.ctx().copy_text(dump.clone());
                    }
                    egui::ScrollArea::both().max_height(500.0).show(ui, |ui| {
                        ui.monospace(dump);
                    });
                });
        }
        if !open {
            self.packet_dump = None;
        }
        // Exact UiLogger.fxml bottom status strip
        ui.separator();
        let yes = self.i18n.text("ext.logger.state.true");
        let no = self.i18n.text("ext.logger.state.false");
        ui.horizontal_wrapped(|ui| {
            ui.small(format!(
                "{}: {}  |  {}: {}  |  {}: {}  |  {}: {}  |  {}: {}",
                self.i18n.text("ext.logger.menu.view.incoming"),
                if self.incoming { &yes } else { &no },
                self.i18n.text("ext.logger.menu.view.outgoing"),
                if self.outgoing { &yes } else { &no },
                self.i18n.text("ext.logger.menu.view.autoscroll"),
                if self.logger_autoscroll { &yes } else { &no },
                self.i18n.text("ext.logger.state.packetinfo"),
                if !self.packet_info.entries().is_empty() {
                    &yes
                } else {
                    &no
                },
                self.i18n.text("ext.logger.state.filtered"),
                self.logger_filtered,
            ));
        });
    }
    fn developer_mode_dialog(&mut self, ctx: &egui::Context) {
        if !self.developer_mode_confirmation {
            return;
        }
        let mut open = true;
        let mut decision = None;
        egui::Window::new(self.i18n.text("tab.extra.options.developmode.alert.title"))
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(
                    self.i18n
                        .text("tab.extra.options.developmode.alert.content"),
                );
                ui.horizontal(|ui| {
                    if ui.button(self.i18n.text("rust.confirmation.no")).clicked() {
                        decision = Some(false);
                    }
                    if ui.button(self.i18n.text("rust.confirmation.yes")).clicked() {
                        decision = Some(true);
                    }
                });
            });
        if let Some(enable) = decision {
            self.developer_mode_confirmation = false;
            if enable {
                if let Ok(mut safety) = self.packet_safety.lock() {
                    safety.set_developer_mode(true);
                    self.developer_mode = true;
                } else {
                    self.status = "Packet safety state unavailable".into();
                }
            }
        } else if !open {
            self.developer_mode_confirmation = false;
        }
    }
    fn developer_mode_control(&mut self, ui: &mut egui::Ui) {
        let developer_changed = ui
            .checkbox(
                &mut self.developer_mode,
                egui::RichText::new(self.i18n.text("tab.extra.options.developmode")).strong(),
            )
            .on_hover_text(
                self.i18n
                    .text("tab.extra.options.developmode.alert.content"),
            )
            .changed();
        if developer_changed {
            if self.developer_mode {
                self.developer_mode = false;
                self.developer_mode_confirmation = true;
            } else if let Ok(mut safety) = self.packet_safety.lock() {
                safety.set_developer_mode(false);
            } else {
                self.developer_mode = true;
                self.status = "Packet safety state unavailable".into();
            }
        }
    }
    fn injection(&mut self, ui: &mut egui::Ui) {
        // Compute live packet validation & description matching Injection.fxml header bar
        let (corrupted, corrupted_indices, info_text, server_valid, client_valid) =
            if self.expression.len() <= 64 * 1024 {
                let parsed_server = injection::parse_packets(
                    &self.expression,
                    self.packet_format(Direction::ToServer),
                    Direction::ToServer,
                    &self.packet_info,
                );
                let parsed_client = injection::parse_packets(
                    &self.expression,
                    self.packet_format(Direction::ToClient),
                    Direction::ToClient,
                    &self.packet_info,
                );
                let is_safe = |packets: &[gearth_rust::packet::Packet], direction| {
                    self.packet_safety.lock().is_ok_and(|safety| {
                        injection::first_unsafe_packet(
                            packets,
                            direction,
                            Some(&self.hotel_version),
                            &safety,
                            self.developer_mode,
                        )
                        .is_none()
                    })
                };
                let s_ok = parsed_server
                    .as_ref()
                    .is_ok_and(|packets| is_safe(packets, Direction::ToServer));
                let c_ok = parsed_client
                    .as_ref()
                    .is_ok_and(|packets| is_safe(packets, Direction::ToClient));
                match parsed_server.as_ref().or(parsed_client.as_ref()) {
                    Ok(packets) if packets.len() == 1 => {
                        let p = &packets[0];
                        let unsafe_tag = if !s_ok && !c_ok {
                            format!(" [{}]", self.i18n.text("tab.injection.description.unsafe"))
                        } else {
                            String::new()
                        };
                        (
                            false,
                            Vec::new(),
                            format!(
                                "{} ({}={}, {}={}){}",
                                self.i18n.text("tab.injection.description.header"),
                                self.i18n.text("tab.injection.description.id"),
                                p.header(),
                                self.i18n.text("tab.injection.description.length"),
                                p.bytes().len(),
                                unsafe_tag
                            ),
                            s_ok,
                            c_ok,
                        )
                    }
                    Ok(packets) => (
                        false,
                        Vec::new(),
                        format!(
                            "{} {}",
                            packets.len(),
                            self.i18n.text("tab.injection.description.packets")
                        ),
                        s_ok,
                        c_ok,
                    ),
                    Err(_) => {
                        let bad = injection::corrupted_packet_indices(
                            &self.expression,
                            self.packet_format(Direction::ToServer),
                            Direction::ToServer,
                            &self.packet_info,
                        );
                        (
                            true,
                            bad,
                            format!(
                                "{} ({}=NULL, {}=0)",
                                self.i18n.text("tab.injection.description.header"),
                                self.i18n.text("tab.injection.description.id"),
                                self.i18n.text("tab.injection.description.length")
                            ),
                            false,
                            false,
                        )
                    }
                }
            } else {
                (false, Vec::new(), "Large input".into(), true, true)
            };

        let avail_w = ui.available_width().max(580.0);
        let history_w = 182.0;
        let left_w = (avail_w - history_w - 14.0).max(320.0);
        let editor_h = (ui.available_height() - 140.0).clamp(96.0, 360.0);

        // Exact Injection.fxml 2-column layout: Left editor (+ Visual Field Builder) + Right History/Favorites card
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(left_w, editor_h + 88.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.horizontal(|ui| {
                        let multi_line = self.expression.contains('\n');
                        let corrupt_label =
                            if corrupted && multi_line && !corrupted_indices.is_empty() {
                                let list = corrupted_indices
                                    .iter()
                                    .map(usize::to_string)
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                format!(
                                    "{}: {} -> {list}",
                                    self.i18n.text("tab.injection.corrupted"),
                                    self.i18n.text("tab.injection.corrupted.true")
                                )
                            } else {
                                format!(
                                    "{}: {}",
                                    self.i18n.text("tab.injection.corrupted"),
                                    self.i18n.text(if corrupted {
                                        "tab.injection.corrupted.true"
                                    } else {
                                        "tab.injection.corrupted.false"
                                    })
                                )
                            };
                        let corrupt_color = if corrupted {
                            egui::Color32::from_rgb(0xc9, 0x30, 0x2c)
                        } else {
                            egui::Color32::from_rgb(0x39, 0x84, 0x39)
                        };
                        ui.label(
                            egui::RichText::new(corrupt_label)
                                .italics()
                                .small()
                                .color(corrupt_color),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                egui::RichText::new(&info_text).italics().small().color(
                                    self.theme
                                        .palette_with_accent(self.custom_accent)
                                        .text_muted,
                                ),
                            );
                        });
                    });
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        egui::ComboBox::from_id_salt("injection-builder-kind")
                            .width(68.0)
                            .selected_text(&self.builder_field_kind)
                            .show_ui(ui, |ui| {
                                for kind in logger_ui::BUILDER_FIELD_KINDS {
                                    ui.selectable_value(
                                        &mut self.builder_field_kind,
                                        (*kind).to_owned(),
                                        *kind,
                                    );
                                }
                            });
                        let val_w = (left_w - 150.0).max(80.0);
                        let val_resp = ui.add(
                            egui::TextEdit::singleline(&mut self.builder_field_value)
                                .desired_width(val_w)
                                .hint_text(self.i18n.text("rust.injection.builder_value_hint")),
                        );
                        let insert_enter =
                            val_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if insert_enter
                            || ui
                                .add(
                                    egui::Button::new(
                                        self.i18n.text("rust.injection.builder_insert"),
                                    )
                                    .small(),
                                )
                                .clicked()
                        {
                            let token = logger_ui::format_builder_token(
                                &self.builder_field_kind,
                                &self.builder_field_value,
                            );
                            self.expression.push_str(&token);
                            self.builder_field_value.clear();
                        }
                    });
                    ui.add_space(3.0);
                    egui::ScrollArea::vertical()
                        .id_salt("injection_input_scroll")
                        .max_height(editor_h)
                        .show(ui, |ui| {
                            ui.add_sized(
                                egui::vec2(left_w, editor_h),
                                egui::TextEdit::multiline(&mut self.expression)
                                    .font(egui::TextStyle::Monospace),
                            );
                        });
                    ui.add_space(6.0);
                    let connected = self.relay.as_ref().is_some_and(Connection::connected);
                    let btn_w = ((left_w - 10.0) * 0.5).max(120.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                connected && server_valid,
                                egui::Button::new(self.i18n.text("tab.injection.send.toserver"))
                                    .min_size(egui::vec2(btn_w, 28.0)),
                            )
                            .on_disabled_hover_text(self.i18n.text(if connected {
                                "rust.injection.invalid"
                            } else {
                                "rust.injection.connect"
                            }))
                            .clicked()
                        {
                            self.send_injection(Direction::ToServer);
                        }
                        if ui
                            .add_enabled(
                                connected && client_valid,
                                egui::Button::new(self.i18n.text("tab.injection.send.toclient"))
                                    .min_size(egui::vec2(btn_w, 28.0)),
                            )
                            .on_disabled_hover_text(self.i18n.text(if connected {
                                "rust.injection.invalid"
                            } else {
                                "rust.injection.connect"
                            }))
                            .clicked()
                        {
                            self.send_injection(Direction::ToClient);
                        }
                    });
                },
            );

            ui.add_space(10.0);

            ui.allocate_ui_with_layout(
                egui::vec2(history_w, editor_h + 88.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.horizontal(|ui| {
                        ui.selectable_value(
                            &mut self.injection_right_tab_favorites,
                            false,
                            self.i18n.text("tab.injection.history"),
                        );
                        ui.selectable_value(
                            &mut self.injection_right_tab_favorites,
                            true,
                            self.i18n.text("rust.injection.favorites"),
                        );
                        if !self.injection_right_tab_favorites {
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui
                                        .link(self.i18n.text("tab.injection.history.clear"))
                                        .clicked()
                                    {
                                        self.injection_history.clear();
                                        self.status = match self
                                            .injection_history
                                            .save_to_settings(&self.settings_path)
                                        {
                                            Ok(()) => "Injection history cleared".into(),
                                            Err(error) => {
                                                format!(
                                                    "History cleared in memory; could not save: {error}"
                                                )
                                            }
                                        };
                                    }
                                },
                            );
                        }
                    });
                    ui.add_space(3.0);
                    group_box(ui, self.theme, egui::Margin::same(4.0), |ui| {
                        ui.set_min_size(egui::vec2(history_w - 10.0, editor_h + 52.0));
                        if !self.injection_right_tab_favorites {
                            egui::ScrollArea::vertical()
                                .id_salt("injection_history")
                                .max_height(editor_h + 52.0)
                                .show(ui, |ui| {
                                    for entry in self.injection_history.entries() {
                                        let label = if entry.direction.is_empty() {
                                            entry.expression.replace('\n', " ")
                                        } else {
                                            format!(
                                                "{}: {}",
                                                entry.direction,
                                                entry.expression.replace('\n', " ")
                                            )
                                        };
                                        let resp = ui
                                            .add(
                                                egui::Label::new(
                                                    egui::RichText::new(label).monospace().small(),
                                                )
                                                .truncate()
                                                .sense(egui::Sense::click()),
                                            )
                                            .on_hover_text(
                                                self.i18n.text("tab.injection.history.tooltip"),
                                            );
                                        if resp.double_clicked() {
                                            self.expression = entry.expression.clone();
                                            if let Ok(direction) =
                                                Direction::parse(&entry.direction)
                                            {
                                                self.direction = direction;
                                            }
                                        }
                                    }
                                });
                        } else {
                            let connected =
                                self.relay.as_ref().is_some_and(Connection::connected);
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 3.0;
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.injection_fav_name)
                                        .desired_width((history_w - 64.0).max(80.0))
                                        .hint_text(self.i18n.text("rust.injection.favorite_name")),
                                );
                                let can_save = !self.expression.trim().is_empty();
                                let fav_accent = self
                                    .theme
                                    .palette_with_accent(self.custom_accent)
                                    .primary_accent;
                                let save_clicked = ui
                                    .add_enabled_ui(can_save, |ui| {
                                        vector_icon_button(
                                            ui,
                                            VectorIcon::Star,
                                            egui::vec2(22.0, 20.0),
                                            11.0,
                                            None,
                                            fav_accent,
                                        )
                                        .on_hover_text(
                                            self.i18n.text("rust.injection.favorite_save"),
                                        )
                                        .clicked()
                                    })
                                    .inner;
                                if save_clicked {
                                    let name = if self.injection_fav_name.trim().is_empty() {
                                        self.expression
                                            .trim()
                                            .chars()
                                            .take(24)
                                            .collect::<String>()
                                    } else {
                                        self.injection_fav_name.trim().to_owned()
                                    };
                                    self.injection_favorites
                                        .retain(|f| !f.name.eq_ignore_ascii_case(&name));
                                    self.injection_favorites.push(logger_ui::InjectionFavorite {
                                        name,
                                        direction: self.direction,
                                        expression: self.expression.clone(),
                                    });
                                    self.injection_fav_name.clear();
                                    self.save_settings();
                                }
                            });
                            ui.separator();
                            let mut load_fav: Option<(Direction, String)> = None;
                            let mut send_fav: Option<(Direction, String)> = None;
                            let mut delete_fav: Option<usize> = None;
                            let fav_accent = self
                                .theme
                                .palette_with_accent(self.custom_accent)
                                .primary_accent;
                            egui::ScrollArea::vertical()
                                .id_salt("injection_favorites_scroll")
                                .max_height(editor_h + 18.0)
                                .show(ui, |ui| {
                                    if self.injection_favorites.is_empty() {
                                        ui.small(
                                            egui::RichText::new(
                                                self.i18n.text("rust.injection.favorites_empty"),
                                            )
                                            .italics()
                                            .color(
                                                self.theme
                                                    .palette_with_accent(self.custom_accent)
                                                    .text_muted,
                                            ),
                                        );
                                    }
                                    for (idx, fav) in self.injection_favorites.iter().enumerate() {
                                        ui.horizontal(|ui| {
                                            ui.spacing_mut().item_spacing.x = 3.0;
                                            let dir_tag = if fav.direction == Direction::ToServer {
                                                "→"
                                            } else {
                                                "←"
                                            };
                                            let resp = ui
                                                .add(
                                                    egui::Label::new(
                                                        egui::RichText::new(format!(
                                                            "{dir_tag} {}",
                                                            fav.name
                                                        ))
                                                        .small(),
                                                    )
                                                    .truncate()
                                                    .sense(egui::Sense::click()),
                                                )
                                                .on_hover_text(&fav.expression);
                                            if resp.double_clicked() {
                                                load_fav =
                                                    Some((fav.direction, fav.expression.clone()));
                                            }
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    if vector_icon_button(
                                                        ui,
                                                        VectorIcon::Close,
                                                        egui::vec2(18.0, 18.0),
                                                        8.0,
                                                        None,
                                                        ui.visuals().text_color(),
                                                    )
                                                    .clicked()
                                                    {
                                                        delete_fav = Some(idx);
                                                    }
                                                    let play_clicked = ui
                                                        .add_enabled_ui(connected, |ui| {
                                                            vector_icon_button(
                                                                ui,
                                                                VectorIcon::Play,
                                                                egui::vec2(20.0, 18.0),
                                                                9.0,
                                                                None,
                                                                fav_accent,
                                                            )
                                                            .on_hover_text(
                                                                self.i18n
                                                                    .text("rust.logger.replay_now"),
                                                            )
                                                            .clicked()
                                                        })
                                                        .inner;
                                                    if play_clicked {
                                                        send_fav = Some((
                                                            fav.direction,
                                                            fav.expression.clone(),
                                                        ));
                                                    }
                                                },
                                            );
                                        });
                                    }
                                });
                            if let Some((dir, expr)) = load_fav {
                                self.direction = dir;
                                self.expression = expr;
                            }
                            if let Some((dir, expr)) = send_fav {
                                self.expression = expr;
                                self.send_injection(dir);
                            }
                            if let Some(idx) = delete_fav {
                                self.injection_favorites.remove(idx);
                                self.save_settings();
                            }
                        }
                    });
                },
            );
        });

        ui.add_space(6.0);
        egui::CollapsingHeader::new(self.i18n.text("rust.rule.title"))
            .id_salt("injection-rules-drawer")
            .show(ui, |ui| {
                self.injection_rules_panel(ui);
            });
    }
    fn injection_rules_panel(&mut self, ui: &mut egui::Ui) {
        let mut saved_rules_changed = false;
        let changed = ui
            .add_enabled(
                self.editing_saved_rule.is_none(),
                egui::Checkbox::new(&mut self.block_enabled, self.i18n.text("rust.rule.enabled")),
            )
            .changed();
        let changed = ui
            .add(
                egui::DragValue::new(&mut self.block_header)
                    .prefix(format!("{} ", self.i18n.text("rust.rule.header"))),
            )
            .changed()
            || changed;
        let before = self.block_direction;
        direction_selector(ui, &mut self.block_direction, &self.i18n);
        if changed || before != self.block_direction {
            self.update_rules();
        }
        ui.label(self.i18n.text("rust.rule.replacement"));
        if ui
            .text_edit_singleline(&mut self.replacement_expression)
            .changed()
        {
            self.update_rules();
        }
        if let Some(index) = self.editing_saved_rule {
            ui.label(format!("Editing saved rule {}", index + 1));
        }
        if ui
            .button(self.i18n.text(if self.editing_saved_rule.is_some() {
                "rust.rule.save"
            } else {
                "rust.rule.add"
            }))
            .clicked()
        {
            let replacement = Rules::editor_rule(
                true,
                self.block_direction,
                self.block_header,
                &self.replacement_expression,
                self.packet_format(self.block_direction),
                &self.packet_info,
            )
            .map(|rule| match rule.expect("enabled rule is present").action {
                Action::Block => None,
                Action::Replace(packet) => Some(expression::to_lossless_expression(&packet)),
            });
            match replacement {
                Ok(replacement) => {
                    let result = if let Some(index) = self.editing_saved_rule {
                        self.settings.replace_saved_rule(
                            index,
                            self.block_direction,
                            self.block_header,
                            replacement,
                        )
                    } else {
                        self.settings.rules.push((
                            true,
                            self.block_direction,
                            self.block_header,
                            replacement,
                        ));
                        Ok(())
                    };
                    match result {
                        Ok(()) => {
                            self.editing_saved_rule = None;
                            self.block_enabled = false;
                            self.status = "Rule updated".into();
                            saved_rules_changed = true;
                            self.update_rules();
                        }
                        Err(error) => self.status = error.to_string(),
                    }
                }
                Err(error) => self.status = error.to_string(),
            }
        }
        if self.editing_saved_rule.is_some()
            && ui.button(self.i18n.text("rust.rule.cancel")).clicked()
        {
            self.editing_saved_rule = None;
        }
        let mut remove = None;
        let mut edit = None;
        let mut move_rule = None;
        let mut changed = false;
        let rule_count = self.settings.rules.len();
        for (index, (enabled, direction, header, replacement)) in
            self.settings.rules.iter_mut().enumerate()
        {
            ui.horizontal(|ui| {
                let toggled = ui
                    .checkbox(
                        enabled,
                        format!(
                            "{} header {} · {}",
                            direction.name(),
                            header,
                            if replacement.is_some() {
                                "replace"
                            } else {
                                "block"
                            }
                        ),
                    )
                    .changed();
                changed |= toggled;
                saved_rules_changed |= toggled;
                if ui
                    .small_button(self.i18n.text("rust.action.remove"))
                    .clicked()
                {
                    remove = Some(index);
                }
                if ui
                    .small_button(self.i18n.text("rust.action.edit"))
                    .clicked()
                {
                    edit = Some(index);
                }
                if ui
                    .add_enabled(
                        self.editing_saved_rule.is_none() && index > 0,
                        egui::Button::new(self.i18n.text("rust.action.up")),
                    )
                    .clicked()
                {
                    move_rule = Some((index, index - 1));
                }
                if ui
                    .add_enabled(
                        self.editing_saved_rule.is_none() && index + 1 < rule_count,
                        egui::Button::new(self.i18n.text("rust.action.down")),
                    )
                    .clicked()
                {
                    move_rule = Some((index, index + 1));
                }
                if let Some((_, error)) = self.rule_errors.iter().find(|(i, _)| *i == index) {
                    ui.colored_label(
                        egui::Color32::from_rgb(180, 60, 60),
                        format!("Not active: {error}"),
                    );
                }
            });
        }
        if let Some(index) = remove {
            self.settings.rules.remove(index);
            self.editing_saved_rule = match self.editing_saved_rule {
                Some(editing) if editing == index => None,
                Some(editing) if editing > index => Some(editing - 1),
                other => other,
            };
            changed = true;
            saved_rules_changed = true;
        }
        if let Some((from, to)) = move_rule {
            if let Err(error) = self.settings.move_saved_rule(from, to) {
                self.status = error.to_string();
            } else {
                changed = true;
                saved_rules_changed = true;
            }
        }
        if let Some(index) = edit {
            if let Some((_, direction, header, replacement)) = self.settings.rules.get(index) {
                self.block_direction = *direction;
                self.block_header = *header;
                self.replacement_expression = replacement.clone().unwrap_or_default();
                self.block_enabled = false;
                self.editing_saved_rule = Some(index);
                changed = true;
            }
        }
        if changed {
            self.update_rules();
        }
        if saved_rules_changed {
            if let Err(error) = Settings::save_rules(&self.settings_path, &self.settings.rules) {
                self.status = format!("Rules changed in memory; could not save: {error}");
            }
        }
    }
    fn replay_logged_packet(&mut self, direction: Direction, packet: gearth_rust::packet::Packet) {
        let header = packet.header();
        let Some(relay) = self.relay.as_ref() else {
            self.status = "Not connected".into();
            return;
        };
        let allowed = match self.packet_safety.lock() {
            Ok(safety) => safety.may_send(
                Some(&self.hotel_version),
                direction,
                header,
                self.developer_mode,
            ),
            Err(_) => {
                self.status = "Packet safety state unavailable".into();
                return;
            }
        };
        if !allowed {
            self.status = format!(
                "Packet {header} has not been observed in this direction for this hotel version"
            );
            return;
        }
        self.status = match relay.inject(direction, packet) {
            Ok(()) => self
                .i18n
                .text("rust.logger.replayed")
                .replace("{dir}", direction.name())
                .replace("{header}", &header.to_string()),
            Err(error) => error.to_string(),
        };
    }
    fn send_injection(&mut self, direction: Direction) {
        self.direction = direction;
        let Some(relay) = self.relay.as_ref() else {
            self.status = "Not connected".into();
            return;
        };
        self.status = match injection::parse_packets(
            &self.expression,
            self.packet_format(direction),
            direction,
            &self.packet_info,
        ) {
            Ok(packets) => {
                let unsafe_id = match self.packet_safety.lock() {
                    Ok(safety) => injection::first_unsafe_packet(
                        &packets,
                        direction,
                        Some(&self.hotel_version),
                        &safety,
                        self.developer_mode,
                    ),
                    Err(_) => {
                        self.status = "Packet safety state unavailable".into();
                        return;
                    }
                };
                if let Some(header) = unsafe_id {
                    self.status = format!("Packet {header} has not been observed in this direction for this hotel version");
                    return;
                }
                let total = packets.len();
                match injection::enqueue_packets(packets, |packet| relay.inject(direction, packet)) {
                    Err((accepted, error)) => format!("{accepted} of {total} packets queued; remaining packets not queued: {error}"),
                    Ok(accepted) => {
                        if self.injection_history.record(&self.expression, direction) {
                            match self.injection_history.save_to_settings(&self.settings_path) {
                                Ok(()) => format!("{accepted} packets queued"),
                                Err(error) => format!("{accepted} packets queued; could not save history: {error}"),
                            }
                        } else { format!("{accepted} packets queued; expression too large for history") }
                    }
                }
            }
            Err(error) => error.to_string(),
        };
    }
    fn reset_active_schedule_editor(&mut self) {
        self.schedule_draft.expression.clear();
        self.schedule_draft.direction = Direction::ToClient;
        self.interval_ms = 500;
        self.align_schedule = true;
        self.schedule_offset_ms = 0;
        self.schedule_interval_input = "500+0".into();
        self.repeat_forever = true;
        self.repeat = 1;
    }
    fn schedule(&mut self, ui: &mut egui::Ui) {
        let mut templates_changed = false;
        let palette = self.theme.palette_with_accent(self.custom_accent);
        let avail_w = ui.available_width().max(580.0);
        let table_h = (ui.available_height() - 130.0).clamp(96.0, 380.0);

        // Exact Scheduler.fxml top table: Index (10%) | Packet (39%) | Interval (16%) | Destination (18%) | Edit (15%)
        let mut remove = None;
        let mut pause_change = None;
        let mut edit_active = None;
        group_box(ui, self.theme, egui::Margin::same(0.0), |ui| {
            let box_w = (avail_w - 2.0).max(560.0);
            ui.set_width(box_w);
            let inner_w = (box_w - 2.0).max(540.0);
            let col_idx = (inner_w * 0.10).floor();
            let col_pkt = (inner_w * 0.39).floor();
            let col_int = (inner_w * 0.16).floor();
            let col_dst = (inner_w * 0.18).floor();
            let col_edt = (inner_w - col_idx - col_pkt - col_int - col_dst).max(80.0);
            let col_xs = [
                col_idx,
                col_idx + col_pkt,
                col_idx + col_pkt + col_int,
                col_idx + col_pkt + col_int + col_dst,
            ];
            let grid_stroke = egui::Stroke::new(1.0_f32, palette.table_grid_line);

            let header_resp = egui::Frame::none()
                .fill(palette.table_header_bg)
                .inner_margin(egui::Margin::symmetric(0.0, 5.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        for (w, key) in [
                            (col_idx, "tab.scheduler.table.index"),
                            (col_pkt, "tab.scheduler.table.packet"),
                            (col_int, "tab.scheduler.table.interval"),
                            (col_dst, "tab.scheduler.table.destination"),
                            (col_edt, "tab.scheduler.table.edit"),
                        ] {
                            ui.allocate_ui_with_layout(
                                egui::vec2(w, 18.0),
                                egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                                |ui| {
                                    ui.set_min_width(w);
                                    ui.set_max_width(w);
                                    ui.label(
                                        egui::RichText::new(self.i18n.text(key))
                                            .color(palette.table_header_text),
                                    );
                                },
                            );
                        }
                    });
                });
            let hrect = header_resp.response.rect;
            for dx in col_xs {
                ui.painter().line_segment(
                    [
                        egui::pos2(hrect.left() + dx, hrect.top()),
                        egui::pos2(hrect.left() + dx, hrect.bottom()),
                    ],
                    grid_stroke,
                );
            }
            ui.painter()
                .line_segment([hrect.left_bottom(), hrect.right_bottom()], grid_stroke);
            egui::ScrollArea::vertical()
                .id_salt("scheduler_active_table")
                .max_height(table_h)
                .show(ui, |ui| {
                    ui.set_min_height(table_h);
                    ui.spacing_mut().item_spacing.y = 0.0;
                    for (i, job) in self.scheduler.jobs.iter().enumerate() {
                        let bg = if self.active_schedule_edit == Some(job.id) {
                            palette.table_row_blue
                        } else {
                            palette.table_row_active
                        };
                        let row_resp = egui::Frame::none()
                            .fill(bg)
                            .inner_margin(egui::Margin::symmetric(0.0, 3.0))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 0.0;
                                    ui.allocate_ui_with_layout(
                                        egui::vec2(col_idx, 20.0),
                                        egui::Layout::centered_and_justified(
                                            egui::Direction::LeftToRight,
                                        ),
                                        |ui| {
                                            ui.set_min_width(col_idx);
                                            ui.set_max_width(col_idx);
                                            ui.label(format!("{}", i + 1));
                                        },
                                    );
                                    let expr = job.source_expression.clone().unwrap_or_else(|| {
                                        expression::to_lossless_expression(&job.packet)
                                    });
                                    ui.allocate_ui_with_layout(
                                        egui::vec2(col_pkt, 20.0),
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            ui.set_min_width(col_pkt);
                                            ui.set_max_width(col_pkt);
                                            ui.add_space(6.0);
                                            ui.add(
                                                egui::Label::new(
                                                    egui::RichText::new(expr).monospace().small(),
                                                )
                                                .truncate(),
                                            );
                                        },
                                    );
                                    let interval_text = match job.alignment_offset_ms {
                                        Some(offset) => {
                                            format!("{}+{offset}", job.interval.as_millis())
                                        }
                                        None => format!("{}", job.interval.as_millis()),
                                    };
                                    ui.allocate_ui_with_layout(
                                        egui::vec2(col_int, 20.0),
                                        egui::Layout::centered_and_justified(
                                            egui::Direction::LeftToRight,
                                        ),
                                        |ui| {
                                            ui.set_min_width(col_int);
                                            ui.set_max_width(col_int);
                                            ui.label(interval_text);
                                        },
                                    );
                                    let dest_label = match job.direction {
                                        Direction::ToServer => {
                                            self.i18n.text("rust.direction.server")
                                        }
                                        Direction::ToClient => {
                                            self.i18n.text("rust.direction.client")
                                        }
                                    };
                                    ui.allocate_ui_with_layout(
                                        egui::vec2(col_dst, 20.0),
                                        egui::Layout::centered_and_justified(
                                            egui::Direction::LeftToRight,
                                        ),
                                        |ui| {
                                            ui.set_min_width(col_dst);
                                            ui.set_max_width(col_dst);
                                            ui.label(dest_label);
                                        },
                                    );
                                    ui.allocate_ui_with_layout(
                                        egui::vec2(col_edt, 20.0),
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            ui.set_min_width(col_edt);
                                            ui.set_max_width(col_edt);
                                            ui.add_space(8.0);
                                            ui.spacing_mut().item_spacing.x = 6.0;
                                            let pause_tex = self.logos.as_ref().and_then(|l| {
                                                if job.paused {
                                                    l.btn_resume.as_ref()
                                                } else {
                                                    l.btn_pause.as_ref()
                                                }
                                            });
                                            if icon_action(
                                                ui,
                                                pause_tex,
                                                if job.paused { ">" } else { "||" },
                                                14.0,
                                            )
                                            .on_hover_text(self.i18n.text(if job.paused {
                                                "rust.scheduler.resume"
                                            } else {
                                                "rust.scheduler.pause"
                                            }))
                                            .clicked()
                                            {
                                                pause_change = Some((i, !job.paused));
                                            }
                                            let edit_tex = self
                                                .logos
                                                .as_ref()
                                                .and_then(|l| l.btn_edit.as_ref());
                                            if icon_action(ui, edit_tex, "E", 14.0)
                                                .on_hover_text(self.i18n.text("rust.action.edit"))
                                                .clicked()
                                            {
                                                edit_active = Some(job.id);
                                            }
                                            let del_tex = self
                                                .logos
                                                .as_ref()
                                                .and_then(|l| l.btn_delete.as_ref());
                                            if icon_action(ui, del_tex, "X", 14.0)
                                                .on_hover_text(self.i18n.text("rust.action.remove"))
                                                .clicked()
                                            {
                                                remove = Some(i);
                                            }
                                        },
                                    );
                                });
                            });
                        let r = row_resp.response.rect;
                        for dx in col_xs {
                            ui.painter().line_segment(
                                [
                                    egui::pos2(r.left() + dx, r.top()),
                                    egui::pos2(r.left() + dx, r.bottom()),
                                ],
                                grid_stroke,
                            );
                        }
                        ui.painter()
                            .line_segment([r.left_bottom(), r.right_bottom()], grid_stroke);
                    }
                });
        });

        ui.add_space(6.0);

        // Exact Scheduler.fxml bottom Row 1: Packet: [input] [Clear] [S] [L]
        ui.horizontal(|ui| {
            ui.label(format!("{}:", self.i18n.text("tab.scheduler.setup.packet")));
            let pkt_w = (avail_w - 224.0).max(180.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.schedule_draft.expression)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(pkt_w),
            );
            if ui
                .button(self.i18n.text("tab.scheduler.button.clear"))
                .on_hover_text(self.i18n.text("tab.scheduler.button.clear.tooltip"))
                .clicked()
            {
                self.scheduler.jobs.clear();
                if self.active_schedule_edit.take().is_some() {
                    self.reset_active_schedule_editor();
                }
            }
            if ui
                .add(
                    egui::Button::new(self.i18n.text("tab.scheduler.button.save"))
                        .min_size(egui::vec2(28.0, 24.0)),
                )
                .on_hover_text(self.i18n.text("tab.scheduler.button.save.tooltip"))
                .clicked()
            {
                match gearth_platform::choose_file(gearth_platform::FileKind::Schedule, true) {
                    Ok(Some(path)) => {
                        if let Ok(path_str) = path.into_os_string().into_string() {
                            self.schedule_path = path_str;
                            let formatted = if !self.scheduler.jobs.is_empty() {
                                schedule_file::format_active(&self.scheduler.jobs)
                            } else {
                                schedule_file::format(&self.settings.schedules)
                            };
                            self.status = match formatted.and_then(|text| {
                                schedule_file::write_atomic(Path::new(&self.schedule_path), &text)
                            }) {
                                Ok(()) => format!(
                                    "{}: {}",
                                    self.i18n.text("rust.scheduler.exported_active"),
                                    self.schedule_path
                                ),
                                Err(error) => format!(
                                    "{}: {error}",
                                    self.i18n.text("rust.scheduler.export_failed")
                                ),
                            };
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        self.status = format!("{}: {e}", self.i18n.text("rust.dialog.failed"))
                    }
                }
            }
            if ui
                .add(
                    egui::Button::new(self.i18n.text("tab.scheduler.button.load"))
                        .min_size(egui::vec2(28.0, 24.0)),
                )
                .on_hover_text(self.i18n.text("tab.scheduler.button.load.tooltip"))
                .clicked()
            {
                match gearth_platform::choose_file(gearth_platform::FileKind::Schedule, false) {
                    Ok(Some(path)) => {
                        if let Ok(path_str) = path.into_os_string().into_string() {
                            self.schedule_path = path_str;
                            let result = self.read_schedule_file().and_then(|templates| {
                                let specs = self
                                    .compile_schedules(&templates, true)
                                    .map_err(std::io::Error::other)?;
                                self.scheduler
                                    .replace_batch_deferred(
                                        specs,
                                        (Instant::now(), SystemTime::now()),
                                    )
                                    .map_err(std::io::Error::other)?;
                                Ok(templates)
                            });
                            self.status = match result {
                                Ok(templates) => {
                                    let count = templates.len();
                                    if self.active_schedule_edit.take().is_some() {
                                        self.reset_active_schedule_editor();
                                    }
                                    format!(
                                        "{}: {count} ({})",
                                        self.i18n.text("rust.scheduler.loaded_active"),
                                        self.schedule_path
                                    )
                                }
                                Err(error) => format!(
                                    "{}: {error}",
                                    self.i18n.text("rust.scheduler.load_failed")
                                ),
                            };
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        self.status = format!("{}: {e}", self.i18n.text("rust.dialog.failed"))
                    }
                }
            }
        });

        // Exact Scheduler.fxml bottom Row 2: Interval: [500+0] (In) (Out) [Add/Edit] [x] Enable hotkeys
        let editing = self.schedule_edit.is_some() || self.active_schedule_edit.is_some();
        ui.horizontal(|ui| {
            ui.label(format!(
                "{}:",
                self.i18n.text("tab.scheduler.setup.interval")
            ));
            if ui
                .add(
                    egui::TextEdit::singleline(&mut self.schedule_interval_input)
                        .desired_width(74.0),
                )
                .changed()
            {
                if let Ok((delay, offset)) = parse_interval_spec(&self.schedule_interval_input) {
                    self.interval_ms = delay;
                    self.align_schedule = offset.is_some();
                    self.schedule_offset_ms = offset.unwrap_or(0);
                }
            }
            ui.radio_value(
                &mut self.schedule_draft.direction,
                Direction::ToClient,
                self.i18n.text("tab.scheduler.direction.in"),
            );
            ui.radio_value(
                &mut self.schedule_draft.direction,
                Direction::ToServer,
                self.i18n.text("tab.scheduler.direction.out"),
            );
            let add_label = if editing {
                self.i18n.text("tab.scheduler.button.edit")
            } else {
                self.i18n.text("tab.scheduler.button.add")
            };
            if ui
                .add_enabled(
                    editing || self.relay.as_ref().is_some_and(Connection::connected),
                    egui::Button::new(add_label).min_size(egui::vec2(52.0, 24.0)),
                )
                .clicked()
            {
                let mut reset_active_editor = false;
                match parse_interval_spec(&self.schedule_interval_input) {
                    Err(err) => self.status = err,
                    Ok((delay, offset)) => {
                        self.interval_ms = delay;
                        self.align_schedule = offset.is_some();
                        self.schedule_offset_ms = offset.unwrap_or(0);
                        let parsed = expression::parse_with_format(
                            &self.schedule_draft.expression,
                            self.packet_format(self.schedule_draft.direction),
                            Some((self.schedule_draft.direction, &self.packet_info)),
                        );
                        self.status = match parsed.and_then(|packet| {
                            if let Some(id) = self.active_schedule_edit {
                                self.scheduler.update_configured(
                                    id,
                                    ScheduleSpec {
                                        packet,
                                        source_expression: Some(
                                            self.schedule_draft.expression.clone(),
                                        ),
                                        direction: self.schedule_draft.direction,
                                        interval_ms: self.interval_ms,
                                        offset_ms: offset,
                                        repeat: (!self.repeat_forever).then_some(self.repeat),
                                    },
                                    (Instant::now(), SystemTime::now()),
                                )
                            } else if editing {
                                Ok(())
                            } else {
                                self.scheduler.add_configured(
                                    packet,
                                    self.schedule_draft.direction,
                                    self.interval_ms,
                                    offset,
                                    (!self.repeat_forever).then_some(self.repeat),
                                    (Instant::now(), SystemTime::now()),
                                )?;
                                self.scheduler
                                    .jobs
                                    .last_mut()
                                    .expect("newly added schedule")
                                    .source_expression =
                                    Some(self.schedule_draft.expression.clone());
                                Ok(())
                            }
                        }) {
                            Ok(()) => {
                                if self.active_schedule_edit.take().is_some() {
                                    reset_active_editor = true;
                                    "Active schedule updated; saved templates are unchanged".into()
                                } else {
                                    let template = ScheduleTemplate {
                                        expression: self.schedule_draft.expression.clone(),
                                        direction: self.schedule_draft.direction,
                                        interval_ms: self.interval_ms,
                                        offset_ms: offset,
                                        paused: self
                                            .schedule_edit
                                            .and_then(|i| self.settings.schedules.get(i))
                                            .is_some_and(|old| old.paused),
                                        repeat: if self.repeat_forever { 0 } else { self.repeat },
                                    };
                                    if let Some(index) = self.schedule_edit.take() {
                                        if let Some(existing) =
                                            self.settings.schedules.get_mut(index)
                                        {
                                            *existing = template;
                                            templates_changed = true;
                                            "Template updated; active schedules are unchanged"
                                                .into()
                                        } else {
                                            "Template no longer exists".into()
                                        }
                                    } else {
                                        self.settings.schedules.push(template);
                                        templates_changed = true;
                                        "Schedule added".into()
                                    }
                                }
                            }
                            Err(e) => e.to_string(),
                        };
                    }
                }
                if reset_active_editor {
                    self.reset_active_schedule_editor();
                }
            }
            if editing
                && vector_icon_button(
                    ui,
                    VectorIcon::Close,
                    egui::vec2(22.0, 22.0),
                    10.5,
                    None,
                    ui.visuals().text_color(),
                )
                .on_hover_text(self.i18n.text("rust.scheduler.cancel_edit"))
                .clicked()
            {
                let reset_active_editor = self.active_schedule_edit.is_some();
                self.schedule_edit = None;
                self.active_schedule_edit = None;
                if reset_active_editor {
                    self.reset_active_schedule_editor();
                }
            }
            let mut hotkeys_enabled = self.scheduler_hotkeys.is_some();
            if ui
                .checkbox(
                    &mut hotkeys_enabled,
                    self.i18n.text("tab.scheduler.hotkeys"),
                )
                .changed()
            {
                if hotkeys_enabled {
                    let context = ui.ctx().clone();
                    match gearth_platform::GlobalHotkeys::start(move || context.request_repaint()) {
                        Ok(hotkeys) => {
                            let unavailable: Vec<_> = hotkeys
                                .available()
                                .iter()
                                .enumerate()
                                .filter_map(|(index, available)| {
                                    (!available).then_some(index.to_string())
                                })
                                .collect();
                            self.status = if unavailable.is_empty() {
                                "Global scheduler shortcuts enabled".into()
                            } else {
                                format!("Shortcuts unavailable for: {}", unavailable.join(", "))
                            };
                            self.scheduler_hotkeys = Some(hotkeys);
                        }
                        Err(error) => self.status = format!("Could not enable shortcuts: {error}"),
                    }
                } else {
                    self.scheduler_hotkeys.take();
                    self.status = "Global scheduler shortcuts disabled".into();
                }
            }
        });

        ui.add_space(4.0);
        egui::CollapsingHeader::new(self.i18n.text("rust.scheduler.saved_hint"))
            .id_salt("scheduler-templates-drawer")
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::DragValue::new(&mut self.repeat)
                            .range(1..=1_000_000)
                            .prefix(format!("{} ", self.i18n.text("rust.scheduler.count"))),
                    );
                    ui.checkbox(
                        &mut self.repeat_forever,
                        self.i18n.text("rust.scheduler.forever"),
                    );
                    ui.checkbox(
                        &mut self.scheduler_auto_start,
                        self.i18n.text("rust.scheduler.auto_start"),
                    );
                });
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            self.relay.as_ref().is_some_and(Connection::connected),
                            egui::Button::new(self.i18n.text("rust.scheduler.run_saved")),
                        )
                        .clicked()
                    {
                        let specs = self.compile_schedules(&self.settings.schedules, false);
                        self.status = match specs.and_then(|specs| {
                            self.scheduler
                                .add_batch_deferred(specs, (Instant::now(), SystemTime::now()))
                        }) {
                            Ok(()) => self.i18n.text("rust.scheduler.started"),
                            Err(e) => {
                                format!("{}: {e}", self.i18n.text("rust.scheduler.start_failed"))
                            }
                        };
                    }
                    if ui
                        .button(self.i18n.text("rust.scheduler.clear_saved"))
                        .clicked()
                    {
                        self.settings.schedules.clear();
                        templates_changed = true;
                        self.schedule_edit = None;
                    }
                    if ui.button(self.i18n.text("rust.scheduler.import")).clicked() {
                        let result = self.read_schedule_file();
                        self.status = match result {
                            Ok(templates) => {
                                let count = templates.len();
                                self.settings.schedules = templates;
                                templates_changed = true;
                                self.schedule_edit = None;
                                format!("{}: {count}", self.i18n.text("rust.scheduler.imported"))
                            }
                            Err(error) => format!(
                                "{}: {error}",
                                self.i18n.text("rust.scheduler.import_failed")
                            ),
                        };
                    }
                    if ui
                        .button(self.i18n.text("rust.scheduler.export_templates"))
                        .clicked()
                    {
                        self.status = match schedule_file::format(&self.settings.schedules)
                            .and_then(|text| {
                                schedule_file::write_atomic(Path::new(&self.schedule_path), &text)
                            }) {
                            Ok(()) => format!(
                                "{}: {}",
                                self.i18n.text("rust.scheduler.exported_templates"),
                                self.schedule_path
                            ),
                            Err(error) => format!(
                                "{}: {error}",
                                self.i18n.text("rust.scheduler.export_failed")
                            ),
                        };
                    }
                });
                let mut edit_template = None;
                let mut remove_template = None;
                for (i, template) in self.settings.schedules.iter_mut().enumerate() {
                    ui.horizontal(|ui| {
                        if ui
                            .small_button(self.i18n.text("rust.action.edit"))
                            .clicked()
                        {
                            edit_template = Some(i);
                        }
                        if ui
                            .small_button(self.i18n.text("rust.action.remove"))
                            .clicked()
                        {
                            remove_template = Some(i);
                        }
                        if ui
                            .checkbox(
                                &mut template.paused,
                                self.i18n.text("rust.scheduler.paused_start"),
                            )
                            .changed()
                        {
                            templates_changed = true;
                        }
                        ui.label(format!(
                            "{}: {} every {} ms",
                            i + 1,
                            template.direction.name(),
                            template.interval_ms
                        ));
                        ui.add(egui::Label::new(&template.expression).truncate());
                    });
                }
                if let Some(index) = edit_template {
                    let template = &self.settings.schedules[index];
                    self.schedule_draft.expression = template.expression.clone();
                    self.schedule_draft.direction = template.direction;
                    self.interval_ms = template.interval_ms;
                    self.align_schedule = template.offset_ms.is_some();
                    self.schedule_offset_ms = template.offset_ms.unwrap_or(0);
                    self.schedule_interval_input = match template.offset_ms {
                        Some(offset) => format!("{}+{offset}", template.interval_ms),
                        None => template.interval_ms.to_string(),
                    };
                    self.repeat_forever = template.repeat == 0;
                    self.repeat = template.repeat.max(1);
                    self.schedule_edit = Some(index);
                    self.active_schedule_edit = None;
                }
                if let Some(index) = remove_template {
                    self.settings.schedules.remove(index);
                    templates_changed = true;
                    self.schedule_edit = match self.schedule_edit {
                        Some(editing) if editing == index => None,
                        Some(editing) if editing > index => Some(editing - 1),
                        other => other,
                    };
                }
            });

        if let Some((i, paused)) = pause_change {
            if let Err(error) = self.scheduler.set_paused(i, paused, Instant::now()) {
                self.status = error.to_string();
            }
        }
        if let Some(id) = edit_active {
            if self.active_schedule_edit == Some(id) {
                self.active_schedule_edit = None;
                self.reset_active_schedule_editor();
            } else if let Some(job) = self.scheduler.jobs.iter().find(|job| job.id == id) {
                self.schedule_draft.expression = job
                    .source_expression
                    .clone()
                    .unwrap_or_else(|| expression::to_lossless_expression(&job.packet));
                self.schedule_draft.direction = job.direction;
                self.interval_ms = job.interval.as_millis() as u64;
                self.align_schedule = job.alignment_offset_ms.is_some();
                self.schedule_offset_ms = job.alignment_offset_ms.unwrap_or(0);
                self.schedule_interval_input = match job.alignment_offset_ms {
                    Some(offset) => format!("{}+{offset}", self.interval_ms),
                    None => self.interval_ms.to_string(),
                };
                self.repeat_forever = job.remaining.is_none();
                self.repeat = job.remaining.unwrap_or(1);
                self.active_schedule_edit = Some(id);
                self.schedule_edit = None;
            }
        }
        if let Some(i) = remove {
            if self.active_schedule_edit == Some(self.scheduler.jobs[i].id) {
                self.active_schedule_edit = None;
                self.reset_active_schedule_editor();
            }
            self.scheduler.jobs.remove(i);
        }
        if templates_changed {
            if let Err(error) =
                Settings::save_schedules(&self.settings_path, &self.settings.schedules)
            {
                self.status =
                    format!("Schedule templates changed in memory; could not save: {error}");
            }
        }
    }

    fn set_admin_enabled(&mut self, enabled: bool) {
        let packet = match self.admin_service.lock() {
            Ok(mut service) => service.set_enabled(enabled),
            Err(_) => {
                self.status = "Client permissions state unavailable".into();
                return;
            }
        };
        self.always_admin = enabled;
        if let (Some(relay), Some(packet)) = (&self.relay, packet) {
            if let Err(error) = relay.inject(Direction::ToClient, packet) {
                self.status = format!("Could not update client permissions: {error}");
            }
        }
    }
    fn extra(&mut self, ui: &mut egui::Ui) {
        let avail_w = ui.available_width().max(580.0);
        let left_w = (avail_w * 0.50).floor();
        let right_w = (avail_w - left_w - 14.0).max(250.0);
        let notepad_h = (ui.available_height() - 72.0).clamp(140.0, 380.0);

        // Exact Extra.fxml 2-column split:
        // Left: Notepad + bottom row (Always on top + Troubleshooting link)
        // Right: Developer mode (bold), Staff permissions, G-Python, Advanced + bordered SOCKS/decrypt/debug box
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(left_w, notepad_h + 52.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.label(format!("{}:", self.i18n.text("tab.extra.notepad")));
                    ui.add_space(3.0);
                    egui::ScrollArea::vertical()
                        .id_salt("extra_notepad_scroll")
                        .max_height(notepad_h)
                        .show(ui, |ui| {
                            ui.add_sized(
                                egui::vec2(left_w - 4.0, notepad_h),
                                egui::TextEdit::multiline(&mut self.notepad),
                            );
                        });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui
                            .checkbox(
                                &mut self.always_on_top,
                                self.i18n.text("tab.extra.options.alwaysontop"),
                            )
                            .changed()
                        {
                            ui.ctx()
                                .send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                                    if self.always_on_top {
                                        egui::WindowLevel::AlwaysOnTop
                                    } else {
                                        egui::WindowLevel::Normal
                                    },
                                ));
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.hyperlink_to(
                                self.i18n.text("tab.extra.troubleshooting"),
                                "https://github.com/sirjonasxx/G-Earth/wiki/Troubleshooting",
                            );
                        });
                    });
                },
            );

            ui.add_space(12.0);

            ui.allocate_ui_with_layout(
                egui::vec2(right_w, notepad_h + 52.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.add_space(4.0);
                    self.developer_mode_control(ui);
                    ui.add_space(4.0);
                    if ui
                        .checkbox(
                            &mut self.always_admin,
                            self.i18n.text("tab.extra.options.staffpermissions"),
                        )
                        .on_hover_text(self.i18n.text("rust.extra.staff_hint"))
                        .changed()
                    {
                        self.set_admin_enabled(self.always_admin);
                    }
                    ui.add_space(4.0);
                    ui.checkbox(
                        &mut self.python_enabled,
                        self.i18n.text("tab.extra.options.pythonscripting"),
                    );
                    ui.add_space(4.0);
                    if ui
                        .checkbox(
                            &mut self.advanced_options,
                            self.i18n.text("tab.extra.options.advanced"),
                        )
                        .changed()
                        && !self.advanced_options
                    {
                        self.debug_stdout = false;
                        self.socks_enabled = false;
                        if self.relay.is_none() && self.attachment_pending.is_none() {
                            self.disable_decryption = false;
                        }
                    }
                    ui.add_space(4.0);
                    ui.add_enabled_ui(self.advanced_options, |ui| {
                        group_box(ui, self.theme, egui::Margin::symmetric(8.0, 6.0), |ui| {
                            ui.set_width((right_w - 18.0).max(220.0));
                            ui.checkbox(
                                &mut self.socks_enabled,
                                self.i18n.text("tab.extra.options.advanced.socks"),
                            );
                            ui.add_enabled_ui(self.socks_enabled, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(format!(
                                        "{}:",
                                        self.i18n.text("tab.extra.options.advanced.proxy.ip")
                                    ));
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.socks_proxy)
                                            .hint_text("ip:port")
                                            .desired_width((right_w - 102.0).max(120.0)),
                                    );
                                });
                                ui.horizontal(|ui| {
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.socks_user)
                                            .hint_text(self.i18n.text("rust.connection.socks_user"))
                                            .desired_width(((right_w - 36.0) * 0.5).max(80.0)),
                                    );
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.socks_password)
                                            .password(true)
                                            .hint_text(
                                                self.i18n.text("rust.connection.socks_password"),
                                            )
                                            .desired_width(((right_w - 36.0) * 0.5).max(80.0)),
                                    );
                                });
                            });
                            ui.add_space(2.0);
                            ui.add_enabled(
                                self.relay.is_none() && self.attachment_pending.is_none(),
                                egui::Checkbox::new(
                                    &mut self.disable_decryption,
                                    self.i18n
                                        .text("tab.extra.options.advanced.disabledecryption"),
                                ),
                            );
                            ui.checkbox(
                                &mut self.debug_stdout,
                                self.i18n.text("tab.extra.options.advanced.debugstdout"),
                            );
                        });
                    });
                },
            );
        });
    }
    fn tools(&mut self, ui: &mut egui::Ui) {
        let avail_w = ui.available_width().max(580.0);
        let palette = self.theme.palette_with_accent(self.custom_accent);

        // Exact Tools.fxml Section 1: Encoding/Decoding
        ui.label(
            egui::RichText::new(format!(
                "{}/{}",
                self.i18n.text("tab.tools.encoding"),
                self.i18n.text("tab.tools.decoding")
            ))
            .italics()
            .color(palette.text_muted),
        );
        ui.add_space(3.0);
        group_box(ui, self.theme, egui::Margin::symmetric(10.0, 8.0), |ui| {
            ui.set_width((avail_w - 22.0).max(540.0));
            let field_w = ((avail_w - 280.0) * 0.5).max(115.0);
            egui::Grid::new("tools-enc-dec-grid")
                .num_columns(5)
                .spacing([8.0, 8.0])
                .show(ui, |ui| {
                    ui.label(format!("{}:", self.i18n.text("tab.tools.type.integer")));
                    let decoded = ui
                        .add(egui::TextEdit::singleline(&mut self.tool_int).desired_width(field_w));
                    let encoded_value = packet_tools::encode_i32(&self.tool_int).ok();
                    let encode = ui
                        .add_enabled(
                            encoded_value.is_some(),
                            egui::Button::new(self.i18n.text("tab.tools.button.encode"))
                                .min_size(egui::vec2(72.0, 26.0)),
                        )
                        .clicked()
                        || (decoded.lost_focus()
                            && ui.input(|input| input.key_pressed(egui::Key::Enter)));
                    if encode {
                        if let Some(value) = encoded_value {
                            self.tool_int_encoded = value;
                        }
                    }
                    let decoded_value = packet_tools::decode_i32(&self.tool_int_encoded).ok();
                    let decode = ui
                        .add_enabled(
                            decoded_value.is_some(),
                            egui::Button::new(self.i18n.text("tab.tools.button.decode"))
                                .min_size(egui::vec2(72.0, 26.0)),
                        )
                        .clicked();
                    let encoded = ui.add(
                        egui::TextEdit::singleline(&mut self.tool_int_encoded)
                            .desired_width(field_w),
                    );
                    if decode
                        || (encoded.lost_focus()
                            && ui.input(|input| input.key_pressed(egui::Key::Enter)))
                    {
                        if let Ok(value) = packet_tools::decode_i32(&self.tool_int_encoded) {
                            self.tool_int = value.to_string();
                        }
                    }
                    ui.end_row();

                    ui.label(format!("{}:", self.i18n.text("tab.tools.type.ushort")));
                    let decoded = ui.add(
                        egui::TextEdit::singleline(&mut self.tool_ushort).desired_width(field_w),
                    );
                    let encoded_value = packet_tools::encode_u16(&self.tool_ushort).ok();
                    let encode = ui
                        .add_enabled(
                            encoded_value.is_some(),
                            egui::Button::new(self.i18n.text("tab.tools.button.encode"))
                                .min_size(egui::vec2(72.0, 26.0)),
                        )
                        .clicked()
                        || (decoded.lost_focus()
                            && ui.input(|input| input.key_pressed(egui::Key::Enter)));
                    if encode {
                        if let Some(value) = encoded_value {
                            self.tool_ushort_encoded = value;
                        }
                    }
                    let decoded_value = packet_tools::decode_u16(&self.tool_ushort_encoded).ok();
                    let decode = ui
                        .add_enabled(
                            decoded_value.is_some(),
                            egui::Button::new(self.i18n.text("tab.tools.button.decode"))
                                .min_size(egui::vec2(72.0, 26.0)),
                        )
                        .clicked();
                    let encoded = ui.add(
                        egui::TextEdit::singleline(&mut self.tool_ushort_encoded)
                            .desired_width(field_w),
                    );
                    if decode
                        || (encoded.lost_focus()
                            && ui.input(|input| input.key_pressed(egui::Key::Enter)))
                    {
                        if let Ok(value) = packet_tools::decode_u16(&self.tool_ushort_encoded) {
                            self.tool_ushort = value.to_string();
                        }
                    }
                    ui.end_row();
                });
        });

        ui.add_space(10.0);

        // Exact Tools.fxml Section 2: Packet <-> Expression side-by-side
        ui.label(
            egui::RichText::new(format!(
                "{} <-> {}",
                self.i18n.text("tab.tools.packet"),
                self.i18n.text("tab.tools.expression")
            ))
            .italics()
            .color(palette.text_muted),
        );
        ui.add_space(3.0);
        group_box(ui, self.theme, egui::Margin::symmetric(8.0, 8.0), |ui| {
            ui.set_width((avail_w - 18.0).max(540.0));
            let area_h = 84.0;
            let arrow_w = 72.0;
            let box_w = ((avail_w - 46.0 - arrow_w * 2.0) * 0.5).max(150.0);
            let pkt_format = self.packet_format(self.direction);
            let can_to_expr = !self.tool_input.trim().is_empty()
                && packet_tools::wire_to_expression(
                    &self.tool_input,
                    pkt_format,
                    self.direction,
                    &self.packet_info,
                    self.nitro && self.unity,
                )
                .is_ok();
            let can_to_pkt = !self.tool_output.trim().is_empty()
                && packet_tools::expression_to_wire(
                    &self.tool_output,
                    pkt_format,
                    self.direction,
                    &self.packet_info,
                )
                .is_ok();
            ui.horizontal_top(|ui| {
                let pkt_resp = egui::ScrollArea::vertical()
                    .id_salt("tools_packet_area")
                    .max_height(area_h)
                    .show(ui, |ui| {
                        ui.add_sized(
                            egui::vec2(box_w, area_h),
                            egui::TextEdit::multiline(&mut self.tool_input)
                                .font(egui::TextStyle::Monospace)
                                .hint_text(self.i18n.text("tab.tools.packet")),
                        )
                    })
                    .inner;
                let trigger_to_expr = ui
                    .add_enabled(
                        can_to_expr,
                        egui::Button::new("------>").min_size(egui::vec2(arrow_w, area_h)),
                    )
                    .on_hover_text(self.i18n.text("rust.tools.packet_to_expression"))
                    .clicked()
                    || (can_to_expr
                        && pkt_resp.has_focus()
                        && ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::Enter)));
                if trigger_to_expr {
                    match packet_tools::wire_to_expression(
                        &self.tool_input,
                        pkt_format,
                        self.direction,
                        &self.packet_info,
                        self.nitro && self.unity,
                    ) {
                        Ok((output, structured)) => {
                            self.tool_output = output;
                            self.status = if structured {
                                self.i18n.text("rust.tools.converted")
                            } else {
                                self.i18n.text("rust.tools.structure_unavailable")
                            };
                        }
                        Err(error) => self.status = error.to_string(),
                    }
                }
                let trigger_to_pkt_btn = ui
                    .add_enabled(
                        can_to_pkt,
                        egui::Button::new("<------").min_size(egui::vec2(arrow_w, area_h)),
                    )
                    .on_hover_text(self.i18n.text("rust.tools.expression_to_packet"))
                    .clicked();
                let expr_resp = egui::ScrollArea::vertical()
                    .id_salt("tools_expr_area")
                    .max_height(area_h)
                    .show(ui, |ui| {
                        ui.add_sized(
                            egui::vec2(box_w, area_h),
                            egui::TextEdit::multiline(&mut self.tool_output)
                                .font(egui::TextStyle::Monospace)
                                .hint_text(self.i18n.text("tab.tools.expression")),
                        )
                    })
                    .inner;
                if trigger_to_pkt_btn
                    || (can_to_pkt
                        && expr_resp.has_focus()
                        && ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::Enter)))
                {
                    self.tool_input = packet_tools::expression_to_wire(
                        &self.tool_output,
                        pkt_format,
                        self.direction,
                        &self.packet_info,
                    )
                    .unwrap_or_else(|error| error.to_string());
                }
            });
        });

        ui.add_space(6.0);
        egui::CollapsingHeader::new(self.i18n.text("rust.tools.packet_format"))
            .id_salt("tools-extra-drawer")
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    direction_selector(ui, &mut self.direction, &self.i18n);
                    ui.label(format!("{:?}", self.packet_format(self.direction)));
                    if ui
                        .button(self.i18n.text("rust.tools.expression_to_hex"))
                        .clicked()
                    {
                        self.tool_output = packet_tools::expression_to_hex(
                            &self.tool_input,
                            self.packet_format(self.direction),
                            self.direction,
                            &self.packet_info,
                        )
                        .unwrap_or_else(|e| e.to_string());
                    }
                    if ui
                        .button(self.i18n.text("rust.tools.hex_to_expression"))
                        .clicked()
                    {
                        self.tool_output = packet_tools::hex_to_expression(
                            &self.tool_input,
                            self.packet_format(self.direction),
                        )
                        .unwrap_or_else(|e| e.to_string());
                    }
                    if ui
                        .button(self.i18n.text("rust.tools.copy_output"))
                        .clicked()
                    {
                        ui.ctx().copy_text(self.tool_output.clone());
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Import Cache/cache.json");
                    ui.text_edit_singleline(&mut self.legacy_cache_path);
                    browse_path(
                        ui,
                        &mut self.legacy_cache_path,
                        gearth_platform::FileKind::Json,
                        false,
                        &self.i18n,
                        &mut self.status,
                    );
                    if ui.button("Import").clicked() {
                        let result = std::fs::read(&self.legacy_cache_path)
                            .and_then(|bytes| {
                                serde_json::from_slice(&bytes).map_err(std::io::Error::other)
                            })
                            .and_then(|value| self.settings.import_java_cache(value));
                        match result {
                            Ok(()) => {
                                self.apply_settings();
                                self.status =
                                    "Original cache imported; use Save settings to keep it".into();
                            }
                            Err(e) => self.status = e.to_string(),
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.add(
                        egui::DragValue::new(&mut self.settings.log_limit)
                            .range(16..=50000)
                            .prefix("Log rows "),
                    );
                    ui.add(
                        egui::DragValue::new(&mut self.settings.log_bytes)
                            .range(4096..=512 * 1024 * 1024)
                            .prefix("Log memory bytes "),
                    );
                });
            });
    }
}
fn direction_selector(ui: &mut egui::Ui, direction: &mut Direction, i18n: &I18n) {
    ui.horizontal(|ui| {
        ui.selectable_value(
            direction,
            Direction::ToServer,
            i18n.text("rust.direction.server"),
        );
        ui.selectable_value(
            direction,
            Direction::ToClient,
            i18n.text("rust.direction.client"),
        );
    });
}
impl eframe::App for Desktop {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        if !self.tray_initialized {
            self.tray_initialized = true;
            let wake_ctx = ctx.clone();
            if let Ok(tray) = gearth_platform::SystemTray::start("G-Earth Rust", move || {
                wake_ctx.request_repaint()
            }) {
                self.system_tray = Some(tray);
            }
        }
        if let Some(tray) = &self.system_tray {
            while let Some(event) = tray.try_recv() {
                match event {
                    gearth_platform::TrayEvent::Show => {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    }
                    gearth_platform::TrayEvent::Quit => {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
        }
        if !self.always_on_top_applied {
            self.always_on_top_applied = true;
            if self.always_on_top {
                ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                    egui::WindowLevel::AlwaysOnTop,
                ));
            }
        }
        if self.logos.is_none() {
            self.logos = Some(ThemeLogos::load(ctx));
        }
        if !self.startup_update_checked {
            self.startup_update_checked = true;
            if self.auto_update {
                self.start_update_check();
            }
        }
        if !self.extensions_autostarted {
            self.extensions_autostarted = true;
            self.start_installed_extensions();
        }
        self.poll_auto_save_settings();
        if self.launch_args_auto_connect {
            self.launch_args_auto_connect = false;
            if self.relay.is_none() && self.attachment_pending.is_none() {
                if self.nitro {
                    if let Err(e) = self.start_nitro() {
                        self.connection_error = Some(e.to_string());
                        self.status = e.to_string();
                    }
                } else {
                    self.start_flash_or_origins_attach();
                }
            }
        }
        ctx.set_visuals(self.theme.visuals_with_accent(self.custom_accent));
        self.poll();
        if self.update_close_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        let palette = self.theme.palette_with_accent(self.custom_accent);
        let desired_title = format!(
            "{} 1.5.4-beta-29 (G-Earth-Rust · {})",
            self.theme.title(),
            gearth_rust::update_checker::current_build_tag()
        );
        if self.last_window_title != desired_title {
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(desired_title.clone()));
            self.last_window_title = desired_title;
        }
        egui::TopBottomPanel::top("tabs")
            .frame(
                egui::Frame::none()
                    .fill(palette.titlebar_bg)
                    .inner_margin(egui::Margin {
                        left: 8.0,
                        right: 8.0,
                        top: 6.0,
                        bottom: 0.0,
                    }),
            )
            .show(ctx, |ui| {
                if self.developer_mode_confirmation {
                    ui.disable();
                }
                // Single compact top strip: Bootstrap TabPane left + Fluxer/Flag/Theme/Gear right
                let mut active_tab_rect = None;
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 2.0;
                    for (tab, key) in [
                        (Tab::Connection, "tab.connection"),
                        (Tab::Injection, "tab.injection"),
                        (Tab::Tools, "tab.tools"),
                        (Tab::Scheduler, "tab.scheduler"),
                        (Tab::Extensions, "tab.extensions"),
                        (Tab::Extra, "tab.extra"),
                        (Tab::Info, "tab.info"),
                        (Tab::Logger, "rust.logger.tab"),
                    ] {
                        let label = self.i18n.text(key);
                        let resp = tab_button(ui, self.tab == tab, &label, palette);
                        if self.tab == tab {
                            active_tab_rect = Some(resp.rect);
                        }
                        if resp.clicked() {
                            self.tab = tab;
                        }
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let theme_before = self.theme;
                        let gear_popup_id = ui.make_persistent_id("settings_gear_popup");
                        let gear_resp = vector_icon_button(
                            ui,
                            VectorIcon::Gear,
                            egui::vec2(24.0, 22.0),
                            13.0,
                            None,
                            ui.visuals().text_color(),
                        );
                        if gear_resp.clicked() {
                            self.accent_picker_open = false;
                            ui.memory_mut(|m| m.toggle_popup(gear_popup_id));
                        }
                        egui::popup::popup_below_widget(
                            ui,
                            gear_popup_id,
                            &gear_resp,
                            egui::popup::PopupCloseBehavior::CloseOnClickOutside,
                            |ui| {
                                ui.set_min_width(190.0);
                                if ui.button(self.i18n.text("rust.settings.save")).clicked() {
                                    self.save_settings();
                                    self.accent_picker_open = false;
                                    ui.memory_mut(|m| m.close_popup());
                                }
                                if ui.button(self.i18n.text("rust.settings.reload")).clicked() {
                                    self.load_settings();
                                    self.accent_picker_open = false;
                                    ui.memory_mut(|m| m.close_popup());
                                }
                                ui.separator();
                                for theme in AppTheme::ALL {
                                    if ui
                                        .selectable_value(&mut self.theme, theme, theme.name())
                                        .clicked()
                                    {
                                        self.accent_picker_open = false;
                                        ui.memory_mut(|m| m.close_popup());
                                    }
                                }
                                ui.separator();
                                ui.label(
                                    egui::RichText::new(self.i18n.text("rust.theme.accent"))
                                        .small()
                                        .strong(),
                                );
                                ui.add_space(2.0);
                                ui.horizontal_wrapped(|ui| {
                                    ui.spacing_mut().item_spacing = egui::vec2(5.0, 5.0);
                                    for (preset_name, preset_color) in ACCENT_PRESETS {
                                        let is_selected = self.custom_accent == Some(*preset_color);
                                        let (rect, resp) = ui.allocate_exact_size(
                                            egui::vec2(16.0, 16.0),
                                            egui::Sense::click(),
                                        );
                                        if ui.is_rect_visible(rect) {
                                            ui.painter().circle_filled(
                                                rect.center(),
                                                7.0,
                                                *preset_color,
                                            );
                                            if is_selected || resp.hovered() {
                                                let stroke_color = if is_selected {
                                                    egui::Color32::WHITE
                                                } else {
                                                    ui.visuals().text_color()
                                                };
                                                ui.painter().circle_stroke(
                                                    rect.center(),
                                                    7.5,
                                                    egui::Stroke::new(1.5_f32, stroke_color),
                                                );
                                            }
                                        }
                                        if resp
                                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                                            .on_hover_text(*preset_name)
                                            .clicked()
                                        {
                                            self.custom_accent = Some(*preset_color);
                                        }
                                    }
                                });
                                ui.add_space(4.0);
                                let active_accent = self
                                    .custom_accent
                                    .unwrap_or_else(|| self.theme.palette().primary_accent);
                                ui.horizontal(|ui| {
                                    let (swatch_rect, swatch_resp) = ui.allocate_exact_size(
                                        egui::vec2(22.0, 18.0),
                                        egui::Sense::click(),
                                    );
                                    if ui.is_rect_visible(swatch_rect) {
                                        ui.painter().rect(
                                            swatch_rect,
                                            egui::Rounding::same(3.0),
                                            active_accent,
                                            egui::Stroke::new(
                                                1.0_f32,
                                                ui.visuals().widgets.inactive.bg_stroke.color,
                                            ),
                                        );
                                    }
                                    if swatch_resp
                                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                                        .on_hover_text(format_hex_color(active_accent))
                                        .clicked()
                                    {
                                        self.accent_picker_open = !self.accent_picker_open;
                                    }
                                    if ui
                                        .add(
                                            egui::Button::new(
                                                egui::RichText::new(format_hex_color(
                                                    active_accent,
                                                ))
                                                .monospace()
                                                .small(),
                                            )
                                            .small(),
                                        )
                                        .clicked()
                                    {
                                        self.accent_picker_open = !self.accent_picker_open;
                                    }
                                    if ui
                                        .add_enabled(
                                            self.custom_accent.is_some(),
                                            egui::Button::new(
                                                self.i18n.text("rust.theme.accent_default"),
                                            )
                                            .small(),
                                        )
                                        .clicked()
                                    {
                                        self.custom_accent = None;
                                    }
                                });
                                if self.accent_picker_open {
                                    ui.add_space(4.0);
                                    let mut picker_color = active_accent;
                                    if egui::color_picker::color_picker_color32(
                                        ui,
                                        &mut picker_color,
                                        egui::color_picker::Alpha::Opaque,
                                    ) {
                                        self.custom_accent = Some(picker_color);
                                    }
                                }
                            },
                        );
                        ui.add_space(4.0);
                        dark_mode_pill_switch(ui, &mut self.theme, self.custom_accent)
                            .on_hover_text(self.i18n.text("rust.theme.toggle_hint"));
                        if self.theme != theme_before {
                            if let Some(host) = &self.extension_host {
                                if let Err(e) = host.set_theme(self.theme.extension_theme_name()) {
                                    self.status = e.to_string();
                                }
                            }
                        }
                        ui.add_space(6.0);
                        let before = self.language.clone();
                        let flag_tex = self
                            .logos
                            .as_ref()
                            .and_then(|l| l.flag(&self.language))
                            .cloned();
                        let lang_popup_id = ui.make_persistent_id("lang_flag_popup");
                        let flag_resp = if let Some(tex) = &flag_tex {
                            let (rect, resp) = ui
                                .allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::click());
                            if ui.is_rect_visible(rect) {
                                ui.painter().image(
                                    tex.id(),
                                    egui::Rect::from_center_size(
                                        rect.center(),
                                        egui::vec2(18.0, 18.0),
                                    ),
                                    egui::Rect::from_min_max(
                                        egui::pos2(0.0, 0.0),
                                        egui::pos2(1.0, 1.0),
                                    ),
                                    egui::Color32::WHITE,
                                );
                            }
                            resp
                        } else {
                            ui.small_button(self.language.to_uppercase())
                        };
                        if flag_resp.clicked() {
                            ui.memory_mut(|m| m.toggle_popup(lang_popup_id));
                        }
                        egui::popup::popup_below_widget(
                            ui,
                            lang_popup_id,
                            &flag_resp,
                            egui::popup::PopupCloseBehavior::CloseOnClick,
                            |ui| {
                                ui.set_min_width(120.0);
                                for (code, name) in LANGUAGES {
                                    ui.horizontal(|ui| {
                                        if let Some(tex) =
                                            self.logos.as_ref().and_then(|l| l.flag(code))
                                        {
                                            ui.add(egui::Image::new((
                                                tex.id(),
                                                egui::vec2(16.0, 16.0),
                                            )));
                                        }
                                        ui.selectable_value(
                                            &mut self.language,
                                            (*code).into(),
                                            *name,
                                        );
                                    });
                                }
                            },
                        );
                        if before != self.language {
                            self.i18n = I18n::new(&self.language);
                            if let Some(host) = &self.extension_host {
                                if let Err(e) = host.set_language(&self.language) {
                                    self.status = e.to_string();
                                }
                            }
                        }
                        ui.add_space(6.0);
                        if let Some(tex) = self.logos.as_ref().and_then(|l| l.fluxer.as_ref()) {
                            let fluxer_resp = ui
                                .add(
                                    egui::Image::new((tex.id(), egui::vec2(18.0, 18.0)))
                                        .rounding(egui::Rounding::same(4.0))
                                        .sense(egui::Sense::click()),
                                )
                                .on_hover_cursor(egui::CursorIcon::PointingHand)
                                .on_hover_text("Fluxer Community — https://fluxer.gg/OqH9tI3d");
                            if fluxer_resp.clicked() {
                                ui.ctx()
                                    .open_url(egui::OpenUrl::new_tab("https://fluxer.gg/OqH9tI3d"));
                            }
                        }
                        if let Some(Ok(info)) = self.update_result.clone() {
                            if info.outdated && self.update_apply_task.is_none() {
                                ui.add_space(6.0);
                                if vector_text_button(
                                    ui,
                                    VectorIcon::UpdateArrow,
                                    egui::Color32::from_rgb(210, 120, 15),
                                    &info.latest_version,
                                    Some(egui::Color32::from_rgb(210, 120, 15)),
                                    None,
                                    true,
                                )
                                .on_hover_text(self.i18n.text("rust.info.update_now"))
                                .clicked()
                                {
                                    self.start_update_apply(info);
                                }
                            }
                        }
                    });
                });
                let bottom_rect = ui.available_rect_before_wrap();
                ui.painter().line_segment(
                    [
                        egui::pos2(bottom_rect.left() - 8.0, bottom_rect.top()),
                        egui::pos2(bottom_rect.right() + 8.0, bottom_rect.top()),
                    ],
                    egui::Stroke::new(1.0_f32, palette.tab_active_border),
                );
                if let Some(active_rect) = active_tab_rect {
                    // Seamlessly merge active Bootstrap tab into content pane
                    ui.painter().line_segment(
                        [
                            egui::pos2(active_rect.left() + 1.0, bottom_rect.top()),
                            egui::pos2(active_rect.right() - 1.0, bottom_rect.top()),
                        ],
                        egui::Stroke::new(2.0_f32, palette.tab_active_bg),
                    );
                }
            });
        let mut disable_proxy_clicked = false;
        egui::TopBottomPanel::bottom("status")
            .frame(
                egui::Frame::none()
                    .fill(palette.titlebar_bg)
                    .stroke(egui::Stroke::new(1.0_f32, palette.tab_active_border))
                    .inner_margin(egui::Margin::symmetric(8.0, 2.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if let Some(guard) = &self.proxy_guard {
                        let dark = ui.visuals().dark_mode;
                        let (badge_bg, badge_fg, label_key) = if guard.is_pac() {
                            (
                                if dark {
                                    egui::Color32::from_rgb(28, 92, 62)
                                } else {
                                    egui::Color32::from_rgb(209, 240, 224)
                                },
                                if dark {
                                    egui::Color32::WHITE
                                } else {
                                    egui::Color32::from_rgb(16, 86, 48)
                                },
                                "rust.browser.proxy_active_pac",
                            )
                        } else {
                            (
                                if dark {
                                    egui::Color32::from_rgb(154, 96, 16)
                                } else {
                                    egui::Color32::from_rgb(255, 238, 200)
                                },
                                if dark {
                                    egui::Color32::WHITE
                                } else {
                                    egui::Color32::from_rgb(122, 70, 6)
                                },
                                "rust.browser.proxy_active_global",
                            )
                        };
                        let badge_text =
                            format!("{}: {}", self.i18n.text(label_key), guard.target());
                        logger_ui::badge_pill(ui, &badge_text, badge_bg, badge_fg);
                        if ui
                            .small_button(self.i18n.text("rust.browser.disable_proxy"))
                            .clicked()
                        {
                            disable_proxy_clicked = true;
                        }
                        ui.separator();
                    }
                    ui.add(egui::Label::new(egui::RichText::new(&self.status).small()).truncate());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.small(
                            egui::RichText::new(format!(
                                "{} observed · {} retained",
                                self.total,
                                self.logs.len()
                            ))
                            .color(palette.text_muted),
                        );
                    });
                });
            });
        if disable_proxy_clicked {
            if let Some(guard) = &mut self.proxy_guard {
                match guard.restore() {
                    Ok(()) => {
                        self.proxy_guard = None;
                        self.status = self.i18n.text("rust.browser.proxy_restored");
                    }
                    Err(e) => {
                        self.status = format!("Proxy restoration failed: {e}");
                    }
                }
            }
        }
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(palette.content_bg)
                    .inner_margin(egui::Margin::symmetric(12.0, 10.0)),
            )
            .show(ctx, |ui| {
                if self.developer_mode_confirmation {
                    ui.disable();
                }
                match self.tab {
                    Tab::Connection => {
                        egui::ScrollArea::vertical()
                            .id_salt("connection_panel")
                            .show(ui, |ui| self.connection(ui));
                    }
                    Tab::Logger if self.logger_window.open => {
                        ui.centered_and_justified(|ui| {
                            ui.label(self.i18n.text("rust.logger.panel_open"));
                        });
                    }
                    Tab::Logger => self.logger(ui),
                    Tab::Injection => {
                        egui::ScrollArea::vertical()
                            .id_salt("injection_panel")
                            .show(ui, |ui| self.injection(ui));
                    }
                    Tab::Scheduler => {
                        egui::ScrollArea::vertical()
                            .id_salt("scheduler_panel")
                            .show(ui, |ui| self.schedule(ui));
                    }
                    Tab::Tools => {
                        egui::ScrollArea::vertical()
                            .id_salt("tools_panel")
                            .show(ui, |ui| self.tools(ui));
                    }
                    Tab::Extensions => self.extensions(ui),
                    Tab::Extra => {
                        egui::ScrollArea::vertical()
                            .id_salt("extra_panel")
                            .show(ui, |ui| self.extra(ui));
                    }
                    Tab::Info => {
                        egui::ScrollArea::vertical()
                            .id_salt("info_panel")
                            .show(ui, |ui| {
                                // Exact Info.fxml 2-column layout: large theme logo left, version/credits/links right
                                let logo_tex = self
                                    .logos
                                    .as_ref()
                                    .and_then(|l| l.large(self.theme))
                                    .cloned();
                                ui.horizontal_top(|ui| {
                                    ui.allocate_ui_with_layout(
                                        egui::vec2(204.0, 224.0),
                                        egui::Layout::centered_and_justified(
                                            egui::Direction::TopDown,
                                        ),
                                        |ui| {
                                            if let Some(tex) = &logo_tex {
                                                ui.add(egui::Image::new((
                                                    tex.id(),
                                                    egui::vec2(192.0, 192.0),
                                                )));
                                            }
                                        },
                                    );
                                    ui.add_space(12.0);
                                    ui.vertical(|ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(
                                                egui::RichText::new(format!(
                                                    "{} 1.5.4-beta-29",
                                                    self.theme.title()
                                                ))
                                                .size(18.0)
                                                .strong(),
                                            );
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    if ui
                                                        .button(self.i18n.text("tab.info.donate"))
                                                        .clicked()
                                                    {
                                                        self.donate_dialog_open = true;
                                                    }
                                                    let checking = self.update_task.is_some()
                                                        || self.update_apply_task.is_some();
                                                    if ui
                                                        .add_enabled(
                                                            !checking,
                                                            egui::Button::new(
                                                                self.i18n.text(
                                                                    "rust.info.check_updates",
                                                                ),
                                                            ),
                                                        )
                                                        .clicked()
                                                    {
                                                        self.start_update_check();
                                                    }
                                                },
                                            );
                                        });
                                        ui.add_space(2.0);
                                        ui.label(
                                            egui::RichText::new(
                                                self.i18n.text("tab.info.description"),
                                            )
                                            .color(palette.text_muted),
                                        );
                                        if ui
                                            .checkbox(
                                                &mut self.auto_update,
                                                self.i18n.text("rust.info.auto_update"),
                                            )
                                            .changed()
                                        {
                                            self.save_settings();
                                        }
                                        if self.update_apply_task.is_some() {
                                            ui.colored_label(
                                                egui::Color32::from_rgb(210, 120, 15),
                                                self.i18n.text("rust.info.updating"),
                                            );
                                        } else if self.update_task.is_some() {
                                            ui.small(self.i18n.text("rust.info.checking_updates"));
                                        } else if let Some(result) = self.update_result.clone() {
                                            match result {
                                                Ok(info) if info.outdated => {
                                                    ui.horizontal_wrapped(|ui| {
                                                        ui.colored_label(
                                                            egui::Color32::from_rgb(210, 120, 15),
                                                            format!(
                                                                "{} ({})",
                                                                self.i18n
                                                                    .text("alert.outdated.title"),
                                                                info.latest_version
                                                            ),
                                                        );
                                                        let can_apply = info
                                                            .checksums_url
                                                            .is_some()
                                                            && (info.asset_download_url.is_some()
                                                                || info
                                                                    .setup_download_url
                                                                    .is_some());
                                                        if can_apply
                                                            && ui
                                                                .button(
                                                                    self.i18n.text(
                                                                        "rust.info.update_now",
                                                                    ),
                                                                )
                                                                .clicked()
                                                        {
                                                            self.start_update_apply(info.clone());
                                                        }
                                                        ui.hyperlink_to(
                                                            self.i18n.text(
                                                                "alert.outdated.content.update",
                                                            ),
                                                            &info.release_url,
                                                        );
                                                    });
                                                }
                                                Ok(info) => {
                                                    ui.small(format!(
                                                        "{} ({})",
                                                        self.i18n.text("rust.info.up_to_date"),
                                                        info.latest_version
                                                    ));
                                                }
                                                Err(error) => {
                                                    ui.small(error);
                                                }
                                            }
                                        }
                                        if let Some(error) = &self.update_apply_error {
                                            ui.colored_label(
                                                egui::Color32::from_rgb(0xc9, 0x30, 0x2c),
                                                error,
                                            );
                                        }
                                        ui.add_space(6.0);
                                        ui.horizontal(|ui| {
                                    ui.strong(format!("{}:", self.i18n.text("tab.info.createdby")));
                                    ui.label("sirjonasxx  ·  Rust port: 1desirable1337 / Tear1338");
                                });
                                        ui.add_space(6.0);
                                        ui.vertical(|ui| {
                                            ui.strong(format!(
                                                "{}:",
                                                self.i18n.text("tab.info.links")
                                            ));
                                            ui.hyperlink_to(
                                                "Github - G-Earth",
                                                "https://github.com/G-Realm/G-Earth",
                                            );
                                            ui.hyperlink_to(
                                                "Github - G-Earth-Rust",
                                                "https://github.com/Tear1338/G-Earth-Rust",
                                            );
                                            ui.horizontal(|ui| {
                                                ui.spacing_mut().item_spacing.x = 5.0;
                                                if let Some(tex) = self
                                                    .logos
                                                    .as_ref()
                                                    .and_then(|l| l.fluxer.as_ref())
                                                {
                                                    let img_resp = ui
                                                        .add(
                                                            egui::Image::new((
                                                                tex.id(),
                                                                egui::vec2(16.0, 16.0),
                                                            ))
                                                            .rounding(egui::Rounding::same(3.0))
                                                            .sense(egui::Sense::click()),
                                                        )
                                                        .on_hover_cursor(
                                                            egui::CursorIcon::PointingHand,
                                                        )
                                                        .on_hover_text(
                                                            "https://fluxer.gg/OqH9tI3d",
                                                        );
                                                    if img_resp.clicked() {
                                                        ui.ctx().open_url(egui::OpenUrl::new_tab(
                                                            "https://fluxer.gg/OqH9tI3d",
                                                        ));
                                                    }
                                                }
                                                ui.hyperlink_to(
                                                    "Fluxer - Community",
                                                    "https://fluxer.gg/OqH9tI3d",
                                                );
                                            });
                                            ui.hyperlink_to(
                                                "G-ExtensionStore",
                                                "https://github.com/Tear1338/G-ExtensionStore",
                                            );
                                        });
                                    });
                                });
                            });
                    }
                }
            });
        // Independent native OS windows matching beta-29 separate windows
        if self.ext_store_open {
            let mut open = true;
            let theme_visuals = self.theme.visuals_with_accent(self.custom_accent);
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("extension_store_window"),
                with_gearth_icon(
                    egui::ViewportBuilder::default()
                        .with_title("G-ExtensionStore")
                        .with_inner_size([680.0, 680.0])
                        .with_min_inner_size([520.0, 460.0]),
                ),
                |store_ctx, class| {
                    store_ctx.set_visuals(theme_visuals.clone());
                    if class == egui::ViewportClass::Embedded {
                        egui::Window::new("G-ExtensionStore")
                            .id(egui::Id::new("floating_extension_store"))
                            .open(&mut open)
                            .resizable(true)
                            .default_size([560.0, 560.0])
                            .min_size([480.0, 420.0])
                            .frame(
                                egui::Frame::window(&store_ctx.style())
                                    .inner_margin(egui::Margin::same(0.0)),
                            )
                            .show(store_ctx, |ui| {
                                self.store.show(
                                    ui,
                                    self.extension_host.as_ref(),
                                    Path::new(&self.extension_runtime),
                                    &self.i18n,
                                    &mut self.status,
                                    &mut self.extension_processes,
                                );
                            });
                    } else {
                        if store_ctx.input(|i| i.viewport().close_requested()) {
                            open = false;
                        }
                        egui::CentralPanel::default()
                            .frame(egui::Frame::none().fill(palette.content_bg))
                            .show(store_ctx, |ui| {
                                self.store.show(
                                    ui,
                                    self.extension_host.as_ref(),
                                    Path::new(&self.extension_runtime),
                                    &self.i18n,
                                    &mut self.status,
                                    &mut self.extension_processes,
                                );
                            });
                    }
                },
            );
            if !open {
                ctx.request_repaint_of(egui::ViewportId::ROOT);
            }
            self.ext_store_open = open;
        }
        if self.ext_gpython_open {
            let mut open = true;
            let title = self
                .i18n
                .text("tab.extensions.button.pythonshell.windowtitle");
            let theme_visuals = self.theme.visuals_with_accent(self.custom_accent);
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("gpython_shell_window"),
                with_gearth_icon(
                    egui::ViewportBuilder::default()
                        .with_title(&title)
                        .with_inner_size([580.0, 360.0])
                        .with_min_inner_size([420.0, 260.0]),
                ),
                |py_ctx, class| {
                    py_ctx.set_visuals(theme_visuals.clone());
                    if class == egui::ViewportClass::Embedded {
                        egui::Window::new(&title)
                            .id(egui::Id::new("floating_gpython_shell"))
                            .open(&mut open)
                            .resizable(true)
                            .default_size([560.0, 340.0])
                            .show(py_ctx, |ui| {
                                self.python_console.show(
                                    ui,
                                    self.extension_host.as_ref(),
                                    self.python_enabled,
                                    &self.i18n,
                                    &mut self.status,
                                );
                            });
                    } else {
                        if py_ctx.input(|i| i.viewport().close_requested()) {
                            open = false;
                        }
                        egui::CentralPanel::default().show(py_ctx, |ui| {
                            self.python_console.show(
                                ui,
                                self.extension_host.as_ref(),
                                self.python_enabled,
                                &self.i18n,
                                &mut self.status,
                            );
                        });
                        if self.python_console.is_pending() {
                            py_ctx.request_repaint_after(Duration::from_millis(80));
                        }
                    }
                },
            );
            if !open {
                ctx.request_repaint_of(egui::ViewportId::ROOT);
            }
            self.ext_gpython_open = open;
        }
        if self.ext_console_open {
            let mut open = true;
            let title = self.i18n.text("tab.extensions.button.logs.windowtitle");
            let dark = ui_is_dark(self.theme);
            let theme_visuals = self.theme.visuals_with_accent(self.custom_accent);
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("extension_console_window"),
                with_gearth_icon(
                    egui::ViewportBuilder::default()
                        .with_title(&title)
                        .with_inner_size([620.0, 360.0])
                        .with_min_inner_size([400.0, 240.0]),
                ),
                |console_ctx, class| {
                    console_ctx.set_visuals(theme_visuals.clone());
                    let render_console = |ui: &mut egui::Ui,
                                          console: &mut VecDeque<String>,
                                          i18n: &I18n| {
                        ui.horizontal(|ui| {
                            if ui.button(i18n.text("rust.logger.clear")).clicked() {
                                console.clear();
                            }
                            if ui.button(i18n.text("rust.tools.copy_output")).clicked() {
                                let joined = console.iter().cloned().collect::<Vec<_>>().join("\n");
                                ui.ctx().copy_text(joined);
                            }
                        });
                        ui.separator();
                        egui::ScrollArea::vertical()
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                for line in console.iter() {
                                    let (prefix, color_name, body) =
                                        parse_extension_console_line(line);
                                    let body_color = color_name
                                        .and_then(|name| extension_console_color(name, dark));
                                    ui.horizontal_wrapped(|ui| {
                                        ui.spacing_mut().item_spacing.x = 0.0;
                                        if !prefix.is_empty() {
                                            ui.monospace(prefix);
                                        }
                                        if let Some(color) = body_color {
                                            ui.label(
                                                egui::RichText::new(body).monospace().color(color),
                                            );
                                        } else {
                                            ui.monospace(body);
                                        }
                                    });
                                }
                            });
                    };
                    if class == egui::ViewportClass::Embedded {
                        egui::Window::new(&title)
                            .id(egui::Id::new("floating_extension_console"))
                            .open(&mut open)
                            .resizable(true)
                            .default_size([620.0, 340.0])
                            .show(console_ctx, |ui| {
                                render_console(ui, &mut self.extension_console, &self.i18n);
                            });
                    } else {
                        if console_ctx.input(|i| i.viewport().close_requested()) {
                            open = false;
                        }
                        egui::CentralPanel::default().show(console_ctx, |ui| {
                            render_console(ui, &mut self.extension_console, &self.i18n);
                        });
                        if self.extension_host.is_some() {
                            console_ctx.request_repaint_after(Duration::from_millis(100));
                        }
                    }
                },
            );
            if !open {
                ctx.request_repaint_of(egui::ViewportId::ROOT);
            }
            self.ext_console_open = open;
        }
        if self.ext_install_open {
            let mut open = self.ext_install_open;
            egui::Window::new(self.i18n.text("tab.extensions.button.install.windowtitle"))
                .open(&mut open)
                .resizable(true)
                .default_size([520.0, 160.0])
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(self.i18n.text("rust.extensions.runtime"));
                        ui.text_edit_singleline(&mut self.extension_runtime);
                    });
                    ui.horizontal(|ui| {
                        ui.label(self.i18n.text("rust.extensions.file"));
                        ui.text_edit_singleline(&mut self.extension_path);
                        browse_path(
                            ui,
                            &mut self.extension_path,
                            gearth_platform::FileKind::Extension,
                            false,
                            &self.i18n,
                            &mut self.status,
                        );
                    });
                    ui.checkbox(
                        &mut self.extension_install_permanent,
                        self.i18n.text("rust.extensions.install_permanent"),
                    );
                    if let Some(host) = &self.extension_host {
                        let launching = self.extension_launch_task.is_some();
                        if ui
                            .add_enabled(
                                !launching,
                                egui::Button::new(self.i18n.text("rust.extensions.launch")),
                            )
                            .clicked()
                        {
                            let host = host.clone();
                            let runtime = PathBuf::from(&self.extension_runtime);
                            let ext_path = PathBuf::from(&self.extension_path);
                            let permanent = self.extension_install_permanent;
                            let ext_dir = self.extensions_dir();
                            let (tx, rx) = std::sync::mpsc::channel();
                            self.extension_launch_task = Some(rx);
                            self.status = "Preparing runtime & launching extension...".into();
                            std::thread::spawn(move || {
                                let launch_path = if permanent {
                                    match gearth_rust::extension_host::install_extension_file(
                                        &ext_dir, &ext_path,
                                    ) {
                                        Ok(installed) => installed,
                                        Err(e) => {
                                            let _ = tx.send(Err(e));
                                            return;
                                        }
                                    }
                                } else {
                                    ext_path
                                };
                                let _ = tx.send(host.launch(&runtime, &launch_path));
                            });
                        }
                    }
                });
            self.ext_install_open = open;
        }
        if self.donate_dialog_open {
            let mut open = self.donate_dialog_open;
            egui::Window::new(self.i18n.text("tab.info.donate.alert.title"))
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(self.i18n.text("tab.info.donate.alert.content"));
                    let mut btc = "bc1q9cpejyx57tzlzzmtqu0tsjjw8pdg0rsx67crh4".to_owned();
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut btc).desired_width(340.0));
                        if ui.button("Copy").clicked() {
                            ui.ctx().copy_text(btc);
                        }
                    });
                });
            self.donate_dialog_open = open;
        }
        if self.logger_window.open {
            let mut open = true;
            let title = self.i18n.text("rust.logger.title");
            let previous_tab = self.tab;
            let level = if self.logger_window.always_on_top {
                egui::WindowLevel::AlwaysOnTop
            } else {
                egui::WindowLevel::Normal
            };
            let theme_visuals = self.theme.visuals_with_accent(self.custom_accent);
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("logger_window"),
                with_gearth_icon(
                    egui::ViewportBuilder::default()
                        .with_title(&title)
                        .with_window_level(level)
                        .with_inner_size([850.0, 600.0])
                        .with_min_inner_size([480.0, 320.0]),
                ),
                |logger_ctx, class| {
                    logger_ctx.set_visuals(theme_visuals.clone());
                    if class == egui::ViewportClass::Embedded {
                        egui::Window::new(&title)
                            .id(egui::Id::new("floating_logger"))
                            .open(&mut open)
                            .default_width(850.0)
                            .default_height(600.0)
                            .show(logger_ctx, |ui| {
                                if self.developer_mode_confirmation {
                                    ui.disable();
                                }
                                self.logger(ui);
                            });
                    } else {
                        if logger_ctx.input(|i| i.viewport().close_requested()) {
                            open = false;
                        }
                        egui::CentralPanel::default().show(logger_ctx, |ui| {
                            if self.developer_mode_confirmation {
                                ui.disable();
                            }
                            self.logger(ui);
                        });
                        if self.relay.is_some() {
                            logger_ctx.request_repaint_after(Duration::from_millis(50));
                        }
                    }
                },
            );
            if !open || previous_tab != self.tab {
                ctx.request_repaint_of(egui::ViewportId::ROOT);
            }
            self.logger_window.open = open;
        }
        if self.admin_warning_open {
            let mut open = self.admin_warning_open;
            let mut dismiss = false;
            egui::Window::new(self.i18n.text("alert.confirmation.windowtitle"))
                .id(egui::Id::new("admin_validator_dialog"))
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(self.i18n.text("alert.adminvalidator.content"));
                    ui.add_space(6.0);
                    if ui.button("OK").clicked() {
                        dismiss = true;
                    }
                });
            self.admin_warning_open = open && !dismiss;
        }
        self.developer_mode_dialog(ctx);
        self.extension_confirmation_dialogs(ctx);
        #[cfg(target_os = "macos")]
        let relaunching = self.relaunch_admin_task.is_some();
        #[cfg(not(target_os = "macos"))]
        let relaunching = false;
        let needs_repaint = self.relay.is_some()
            || self.attachment_pending.is_some()
            || self.extension_host.is_some()
            || self.python_console.is_pending()
            || self.scheduler_hotkeys.is_some()
            || self.update_task.is_some()
            || self.update_apply_task.is_some()
            || self.extension_launch_task.is_some()
            || self.extension_autostart_rx.is_some()
            || self.doctor_task.is_some()
            || relaunching;
        if needs_repaint {
            let mut delay = Duration::from_millis(50);
            if self.relay.as_ref().is_some_and(Connection::connected) {
                if let Some(next) = self.scheduler.next_wake_in(Instant::now()) {
                    delay = delay.min(next);
                }
            }
            ctx.request_repaint_after(delay);
        }
    }
}
fn ui_is_dark(theme: AppTheme) -> bool {
    theme.is_dark()
}

/// Parse beta-29 Extension Console lines of the form `#id [color]Title --> body` or `[color]body`.
fn parse_extension_console_line(line: &str) -> (String, Option<&str>, &str) {
    let (id_prefix, rest) = if line.starts_with('#') {
        if let Some(sp) = line.find(' ') {
            (&line[..=sp], &line[sp + 1..])
        } else {
            ("", line)
        }
    } else {
        ("", line)
    };
    let (color, after_tag) = if let Some(inner) = rest.strip_prefix('[') {
        if let Some(close) = inner.find(']') {
            let tag = &inner[..close];
            if !tag.is_empty() && tag.bytes().all(|b| b.is_ascii_alphabetic()) {
                (Some(tag), &inner[close + 1..])
            } else {
                (None, rest)
            }
        } else {
            (None, rest)
        }
    } else {
        (None, rest)
    };
    if let Some(arrow) = after_tag.find(" --> ") {
        let split = arrow + 5;
        (
            format!("{id_prefix}{}", &after_tag[..split]),
            color,
            &after_tag[split..],
        )
    } else {
        (id_prefix.to_owned(), color, after_tag)
    }
}

/// Official beta-29 `ExtensionLoggerController` / `logger.css` palette, adjusted for readability.
fn extension_console_color(name: &str, dark: bool) -> Option<egui::Color32> {
    match name.to_ascii_lowercase().as_str() {
        "grey" | "gray" => Some(egui::Color32::from_rgb(0xa9, 0xa9, 0xa9)),
        "lightgrey" | "lightgray" => Some(if dark {
            egui::Color32::from_rgb(0xd0, 0xd3, 0xd4)
        } else {
            egui::Color32::from_rgb(0x6e, 0x73, 0x78)
        }),
        "yellow" => Some(if dark {
            egui::Color32::from_rgb(0xff, 0xe8, 0x38)
        } else {
            egui::Color32::from_rgb(0xb5, 0x89, 0x00)
        }),
        "orange" => Some(egui::Color32::from_rgb(0xf0, 0x93, 0x2b)),
        "white" => Some(if dark {
            egui::Color32::WHITE
        } else {
            egui::Color32::from_rgb(0x44, 0x44, 0x44)
        }),
        "purple" => Some(if dark {
            egui::Color32::from_rgb(0xc5, 0x86, 0xc0)
        } else {
            egui::Color32::from_rgb(0x80, 0x00, 0x80)
        }),
        "brown" => Some(egui::Color32::from_rgb(0xa5, 0x52, 0x2a)),
        "pink" => Some(egui::Color32::from_rgb(0xff, 0x85, 0xa2)),
        "red" => Some(if dark {
            egui::Color32::from_rgb(0xf4, 0x60, 0x60)
        } else {
            egui::Color32::from_rgb(0xd9, 0x2b, 0x2b)
        }),
        "black" => Some(if dark {
            egui::Color32::from_rgb(0xd8, 0xd8, 0xd8)
        } else {
            egui::Color32::BLACK
        }),
        "blue" => Some(if dark {
            egui::Color32::from_rgb(0x6e, 0xa8, 0xfe)
        } else {
            egui::Color32::from_rgb(0x1f, 0x5f, 0xc4)
        }),
        "cyan" => Some(if dark {
            egui::Color32::from_rgb(0x4d, 0xd0, 0xe1)
        } else {
            egui::Color32::from_rgb(0x00, 0x83, 0x8f)
        }),
        "green" => Some(egui::Color32::from_rgb(0x73, 0xb5, 0x04)),
        "darkergreen" => Some(egui::Color32::from_rgb(0x2e, 0x8b, 0x57)),
        _ => None,
    }
}

fn find_java() -> PathBuf {
    let name = if cfg!(windows) { "java.exe" } else { "java" };
    if let Ok(exe) = std::env::current_exe() {
        for dir in exe.ancestors().skip(1).take(5) {
            let candidate = dir.join("jre").join("bin").join(name);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    if let Some(home) = std::env::var_os("JAVA_HOME") {
        let candidate = PathBuf::from(home).join("bin").join(name);
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from("java")
}
impl Desktop {
    fn extensions_dir(&self) -> PathBuf {
        self.settings_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("extensions")
    }
    fn apply_launch_args(&mut self, args: &LaunchArgs) {
        if let Some(theme) = args.theme {
            self.theme = theme;
            if let Some(host) = &self.extension_host {
                if let Err(e) = host.set_theme(self.theme.extension_theme_name()) {
                    self.status = e.to_string();
                }
            }
        }
        if args.debug_stdout {
            self.debug_stdout = true;
            self.advanced_options = true;
        }
        if let Some(mode) = args.connect_client {
            match mode {
                CliClientMode::Flash => {
                    self.origins = false;
                    self.nitro = false;
                    self.unity = false;
                    self.city = false;
                    self.connection_port = "30000".into();
                }
                CliClientMode::Origins => {
                    self.origins = true;
                    self.nitro = false;
                    self.unity = false;
                    self.city = false;
                    self.connection_port = "40001".into();
                }
                CliClientMode::Unity => {
                    self.origins = false;
                    self.nitro = true;
                    self.unity = true;
                    self.city = false;
                }
                CliClientMode::Nitro => {
                    self.origins = false;
                    self.nitro = true;
                    self.unity = false;
                    self.city = false;
                }
                CliClientMode::City => {
                    self.origins = false;
                    self.nitro = true;
                    self.unity = false;
                    self.city = true;
                    self.attachment_host = "habbocity.fr".into();
                    self.allow_city_helper = true;
                }
            }
            self.launch_args_auto_connect = true;
        }
        if let Some(host) = &args.host {
            self.attachment_host = host.clone();
            self.auto_detect = false;
        }
        if let Some(port) = args.port {
            self.connection_port = port.to_string();
            self.auto_detect = false;
        }
    }
    fn start_installed_extensions(&mut self) {
        let ext_dir = self.extensions_dir();
        for file in gearth_rust::extension_host::discover_installed_files(&ext_dir) {
            if let Some(fname) = file.file_name().and_then(|s| s.to_str()) {
                let stem = file
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or(fname)
                    .to_owned();
                self.known_installed_extensions
                    .entry(fname.to_owned())
                    .or_insert_with(|| gearth_rust::extension::ExtensionInfo {
                        title: stem,
                        author: String::new(),
                        version: String::new(),
                        description: fname.to_owned(),
                        on_click: false,
                        file: Some(fname.to_owned()),
                        cookie: String::new(),
                        can_leave: true,
                        can_delete: true,
                    });
            }
        }
        if let Ok(records) = gearth_rust::extension_store::installed(&ext_dir) {
            for record in records {
                if let Some(fname) = record.directory.file_name().and_then(|s| s.to_str()) {
                    self.known_installed_extensions
                        .entry(fname.to_owned())
                        .or_insert_with(|| gearth_rust::extension::ExtensionInfo {
                            title: record.title.clone(),
                            author: String::new(),
                            version: record.version.clone(),
                            description: String::new(),
                            on_click: false,
                            file: Some(fname.to_owned()),
                            cookie: String::new(),
                            can_leave: true,
                            can_delete: true,
                        });
                }
            }
        }
        let Some(host) = self.extension_host.clone() else {
            return;
        };
        let runtime = PathBuf::from(&self.extension_runtime);
        let (tx, rx) = std::sync::mpsc::channel();
        self.extension_autostart_rx = Some(rx);
        std::thread::spawn(move || {
            for file in gearth_rust::extension_host::discover_installed_files(&ext_dir) {
                let _ = tx.send(host.launch(&runtime, &file));
            }
            if let Ok(records) = gearth_rust::extension_store::installed(&ext_dir) {
                for record in records {
                    let filename = record
                        .directory
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("");
                    let _ = tx.send(host.launch_command(
                        &record.command,
                        &record.directory.join("extension"),
                        filename,
                        &record.title,
                        &runtime,
                    ));
                }
            }
        });
    }
    fn execute_extension_uninstall(&mut self, id: Option<u64>, fname: String, title: String) {
        if let Some(ext_id) = id {
            if let Some(host) = &self.extension_host {
                let _ = host.disconnect(ext_id);
            }
        }
        self.known_installed_extensions.remove(&fname);
        let dir = self.extensions_dir();
        let store_removed = fname.starts_with("extension-");
        match gearth_rust::extension_host::uninstall_installed(&dir, &fname) {
            Ok(true) => {
                if store_removed {
                    self.store.invalidate();
                }
                self.status = format!("Uninstalled {title}");
            }
            Ok(false) => {}
            Err(_) => {
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        std::thread::sleep(Duration::from_millis(150));
                        if gearth_rust::extension_host::uninstall_installed(&dir, &fname).is_ok() {
                            break;
                        }
                    }
                });
                if store_removed {
                    self.store.invalidate();
                }
                self.status = format!("Uninstalling {title}...");
            }
        }
    }
    fn restart_installed_extension(&mut self, fname: &str) {
        let Some(host) = self.extension_host.clone() else {
            return;
        };
        let ext_dir = self.extensions_dir();
        let runtime = PathBuf::from(&self.extension_runtime);
        let fname_owned = fname.to_owned();
        let (tx, rx) = std::sync::mpsc::channel();
        self.extension_launch_task = Some(rx);
        self.status = format!("Restarting {fname_owned}...");
        std::thread::spawn(move || {
            let target = ext_dir.join(&fname_owned);
            if target.is_file() {
                let _ = tx.send(host.launch(&runtime, &target));
            } else if fname_owned.starts_with("extension-") {
                let result =
                    gearth_rust::extension_store::installed(&ext_dir).and_then(|records| {
                        let record = records
                            .into_iter()
                            .find(|r| {
                                r.directory.file_name().and_then(|n| n.to_str())
                                    == Some(fname_owned.as_str())
                            })
                            .ok_or_else(|| {
                                std::io::Error::new(
                                    std::io::ErrorKind::NotFound,
                                    "installed store extension not found",
                                )
                            })?;
                        host.launch_command(
                            &record.command,
                            &record.directory.join("extension"),
                            &fname_owned,
                            &record.title,
                            &runtime,
                        )
                    });
                let _ = tx.send(result);
            } else {
                let _ = tx.send(Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "installed extension file not found",
                )));
            }
        });
    }
    fn extension_confirmation_dialogs(&mut self, ctx: &egui::Context) {
        if let Some((ext_id, fname, title)) = self.confirm_uninstall_ext.clone() {
            let mut open = true;
            let mut decision = None;
            egui::Window::new(self.i18n.text("alert.confirmation.windowtitle"))
                .id(egui::Id::new("confirm_uninstall_ext_dialog"))
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "{}\n({title})",
                        self.i18n
                            .text("tab.extensions.table.edit.uninstall.confirmation")
                    ));
                    ui.add_space(6.0);
                    ui.checkbox(
                        &mut self.confirm_uninstall_dont_ask,
                        self.i18n.text("alert.confirmation.button.donotaskagain"),
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button(self.i18n.text("rust.confirmation.yes")).clicked() {
                            decision = Some(true);
                        }
                        if ui.button(self.i18n.text("rust.confirmation.no")).clicked() {
                            decision = Some(false);
                        }
                    });
                });
            if let Some(confirmed) = decision {
                self.confirm_uninstall_ext = None;
                if self.confirm_uninstall_dont_ask {
                    self.confirm_uninstall_extension = false;
                    self.confirm_uninstall_dont_ask = false;
                    self.save_settings();
                }
                if confirmed {
                    self.execute_extension_uninstall(ext_id, fname, title);
                }
            } else if !open {
                self.confirm_uninstall_ext = None;
            }
        }
        if let Some((pending_id, pending_info)) = self.pending_ext_approvals.front().cloned() {
            let mut open = true;
            let mut decision = None;
            egui::Window::new(self.i18n.text("alert.confirmation.windowtitle"))
                .id(egui::Id::new("confirm_ext_connection_dialog"))
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    let msg = self
                        .i18n
                        .text("alert.extconnection.content")
                        .replace("%s", &pending_info.title);
                    ui.label(msg);
                    ui.add_space(6.0);
                    ui.checkbox(
                        &mut self.remember_ext_approval_box,
                        self.i18n.text("alert.confirmation.button.remember"),
                    );
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button(self.i18n.text("rust.confirmation.yes")).clicked() {
                            decision = Some(true);
                        }
                        if ui.button(self.i18n.text("rust.confirmation.no")).clicked() {
                            decision = Some(false);
                        }
                    });
                });
            if let Some(allow) = decision {
                self.pending_ext_approvals.pop_front();
                if self.remember_ext_approval_box {
                    self.remember_ext_approval = Some(allow);
                    self.remember_ext_approval_box = false;
                }
                if let Some(host) = &self.extension_host {
                    let res = if allow {
                        host.approve(pending_id)
                    } else {
                        host.disconnect(pending_id)
                    };
                    if let Err(e) = res {
                        self.status = e.to_string();
                    }
                }
            } else if !open {
                self.pending_ext_approvals.pop_front();
                if let Some(host) = &self.extension_host {
                    let _ = host.disconnect(pending_id);
                }
            }
        }
    }
    fn start_update_check(&mut self) {
        if self.update_task.is_some() || self.update_apply_task.is_some() {
            return;
        }
        let (send, receive) = std::sync::mpsc::channel();
        self.update_task = Some(receive);
        self.update_result = None;
        self.update_apply_error = None;
        std::thread::spawn(move || {
            let _ = send.send(gearth_rust::update_checker::check_github_updates(
                gearth_rust::update_checker::DEFAULT_REPOSITORY,
                gearth_rust::update_checker::current_build_tag(),
            ));
        });
    }
    fn start_update_apply(&mut self, info: gearth_rust::update_checker::UpdateInfo) {
        if self.update_apply_task.is_some() {
            return;
        }
        let (send, receive) = std::sync::mpsc::channel();
        self.update_apply_task = Some(receive);
        self.update_apply_error = None;
        self.status = format!(
            "{} ({})",
            self.i18n.text("rust.info.updating"),
            info.latest_version
        );
        std::thread::spawn(move || {
            let _ = send.send(gearth_rust::update_checker::download_and_apply_update(
                &info,
            ));
        });
    }
    fn load_settings(&mut self) {
        match Settings::read(&self.settings_path) {
            Ok(settings) => {
                self.settings = settings;
                self.settings_loaded = true;
                self.apply_settings();
                self.status = "Settings loaded".into();
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.settings_loaded = true;
            }
            Err(e) => {
                self.settings_loaded = false;
                self.status = format!("Could not load settings: {e}");
            }
        }
    }
    fn apply_settings(&mut self) {
        self.python_enabled = self
            .settings
            .booleans
            .get("python_enabled")
            .copied()
            .unwrap_or(true);
        self.scheduler_auto_start = self
            .settings
            .booleans
            .get("scheduler_auto_start")
            .copied()
            .unwrap_or(false);
        self.auto_update = self
            .settings
            .booleans
            .get("auto_update")
            .copied()
            .unwrap_or(true);
        self.confirm_uninstall_extension = self
            .settings
            .booleans
            .get("confirm_uninstall_extension")
            .copied()
            .unwrap_or(true);
        self.always_on_top = self
            .settings
            .booleans
            .get("always_on_top")
            .copied()
            .unwrap_or(false);
        self.auto_detect = self
            .settings
            .booleans
            .get("auto_detect")
            .copied()
            .unwrap_or(true);
        self.custom_hotels = self
            .settings
            .values
            .get("custom_hotels")
            .map(|value| parse_custom_hotels(value))
            .unwrap_or_default();
        let enabled = self
            .settings
            .booleans
            .get("always_admin")
            .copied()
            .unwrap_or(false);
        self.set_admin_enabled(enabled);
        self.editing_saved_rule = None;
        self.python_console.restore_settings(&self.settings);
        self.injection_history =
            InjectionHistory::from_json(self.settings.get("injection_history"));
        self.injection_favorites =
            logger_ui::parse_injection_favorites(self.settings.get("injection_favorites"));
        self.connection_profiles =
            doctor::parse_connection_profiles(self.settings.get("connection_profiles"));
        self.logger_representation =
            PacketRepresentation::from_setting(self.settings.get("logger_representation"));
        self.logger_extra_legacy = self
            .settings
            .booleans
            .get("logger_extra_legacy")
            .copied()
            .unwrap_or(false);
        self.logger_extra_raw_hex = self
            .settings
            .booleans
            .get("logger_extra_raw_hex")
            .copied()
            .unwrap_or(false);
        self.logger_extra_hex_dump = self
            .settings
            .booleans
            .get("logger_extra_hex_dump")
            .copied()
            .unwrap_or(false);
        self.logger_skip_big = self
            .settings
            .booleans
            .get("logger_skip_big")
            .copied()
            .unwrap_or(false);
        self.logger_timestamp = self
            .settings
            .booleans
            .get("logger_timestamp")
            .copied()
            .unwrap_or(false);
        self.logger_autoscroll = self
            .settings
            .booleans
            .get("logger_autoscroll")
            .copied()
            .unwrap_or(true);
        self.logger_capture_selected_only = self
            .settings
            .booleans
            .get("logger_capture_selected_only")
            .copied()
            .unwrap_or(false);
        self.logger_clear_on_connect = self
            .settings
            .booleans
            .get("logger_clear_on_connect")
            .copied()
            .unwrap_or(false);
        self.logger_clear_on_disconnect = self
            .settings
            .booleans
            .get("logger_clear_on_disconnect")
            .copied()
            .unwrap_or(false);
        self.logger_window.open_on_connect = self
            .settings
            .booleans
            .get("logger_open_on_connect")
            .copied()
            .unwrap_or(false);
        self.logger_window.hide_on_disconnect = self
            .settings
            .booleans
            .get("logger_hide_on_disconnect")
            .copied()
            .unwrap_or(false);
        self.logger_window.always_on_top = self
            .settings
            .booleans
            .get("logger_always_on_top")
            .copied()
            .unwrap_or(false);
        self.logger_antispam = AntiSpam::from_setting(self.settings.get("logger_antispam"));
        self.logger_filter.set_mode(self.logger_antispam);
        self.logger_hide_noisy = self
            .settings
            .booleans
            .get("logger_hide_noisy")
            .copied()
            .unwrap_or(false);
        self.logger_show_stats = self
            .settings
            .booleans
            .get("logger_show_stats")
            .copied()
            .unwrap_or(false);
        self.logger_hidden_headers =
            logger_ui::parse_hidden_headers_setting(self.settings.get("logger_hidden_headers"));
        self.logger_presets =
            logger_ui::parse_filter_presets(self.settings.get("logger_filter_presets"));
        if let Ok(custom) = PacketInfoManager::load_custom_names(&self.custom_packet_names_path()) {
            self.custom_packet_names = custom;
            if !self.custom_packet_names.is_empty() {
                self.packet_info = self
                    .packet_info
                    .with_custom_names(&self.custom_packet_names);
                invalidate_log_expressions(&mut self.logs);
                self.logger_search_cache = None;
            }
        }
        self.packet_limit = self
            .settings
            .values
            .get("logger_packet_limit")
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value <= 16 * 1024 * 1024)
            .unwrap_or(8000);
        self.logger_additional = self
            .settings
            .booleans
            .get("logger_additional")
            .copied()
            .unwrap_or(true);
        self.logger_structure = self
            .settings
            .booleans
            .get("logger_structure")
            .copied()
            .unwrap_or(true);
        self.logger_java_structure_limit = self
            .settings
            .booleans
            .get("logger_java_structure_limit")
            .copied()
            .unwrap_or(false);
        self.logger_java_structure_clean = self
            .settings
            .booleans
            .get("logger_java_structure_clean")
            .copied()
            .unwrap_or(false);
        self.logger_split = self
            .settings
            .booleans
            .get("logger_split")
            .copied()
            .unwrap_or(true);
        self.logger_export_separators = self
            .settings
            .booleans
            .get("logger_export_separators")
            .copied()
            .unwrap_or(false);
        self.logger_export_hide_empty_header = self
            .settings
            .booleans
            .get("logger_export_hide_empty_header")
            .copied()
            .unwrap_or(false);
        self.logger_display_hide_empty_header = self
            .settings
            .booleans
            .get("logger_display_hide_empty_header")
            .copied()
            .unwrap_or(false);
        self.logger_names = self
            .settings
            .booleans
            .get("logger_names")
            .copied()
            .unwrap_or(true);
        self.logger_hashes = self
            .settings
            .booleans
            .get("logger_hashes")
            .copied()
            .unwrap_or(false);
        self.logger_message_id = self
            .settings
            .booleans
            .get("logger_message_id")
            .copied()
            .unwrap_or(false);
        self.logger_friendly = self
            .settings
            .booleans
            .get("logger_friendly")
            .copied()
            .unwrap_or(true);
        self.developer_mode = self
            .settings
            .booleans
            .get("developer_mode")
            .copied()
            .unwrap_or(false);
        self.disable_decryption = self
            .settings
            .booleans
            .get("disable_decryption")
            .copied()
            .unwrap_or(false);
        self.debug_stdout = self
            .settings
            .booleans
            .get("debug_stdout")
            .copied()
            .unwrap_or(false);
        if self.disable_decryption || self.debug_stdout {
            self.advanced_options = true;
        }
        self.developer_mode_confirmation = false;
        if let Ok(mut safety) = self.packet_safety.lock() {
            safety.set_developer_mode(self.developer_mode);
        }
        for (key, target) in [
            ("listen", &mut self.listen),
            ("remote", &mut self.remote),
            ("attachment_host", &mut self.attachment_host),
            ("connection_port", &mut self.connection_port),
            ("hotel_version", &mut self.hotel_version),
            ("client_identifier", &mut self.client_identifier),
            ("packet_database", &mut self.packet_database),
            ("socks_proxy", &mut self.socks_proxy),
            ("socks_user", &mut self.socks_user),
            ("extension_runtime", &mut self.extension_runtime),
            ("notepad", &mut self.notepad),
            ("language", &mut self.language),
        ] {
            if let Some(value) = self.settings.values.get(key) {
                *target = value.clone();
            }
        }
        self.socks_enabled = self.settings.socks_enabled();
        self.origins = self
            .settings
            .booleans
            .get("origins")
            .copied()
            .unwrap_or_else(|| self.settings.get("client_type") == "SHOCKWAVE");
        self.nitro = self
            .settings
            .booleans
            .get("nitro")
            .copied()
            .unwrap_or(false);
        self.unity = self
            .settings
            .booleans
            .get("unity")
            .copied()
            .unwrap_or(false);
        self.city = self.settings.booleans.get("city").copied().unwrap_or(false);
        self.system_proxy = self
            .settings
            .booleans
            .get("system_proxy")
            .copied()
            .unwrap_or(cfg!(windows));
        self.system_proxy_pac = self
            .settings
            .booleans
            .get("system_proxy_pac")
            .copied()
            .unwrap_or(cfg!(windows));
        self.allow_city_helper = self
            .settings
            .booleans
            .get("allow_city_helper")
            .copied()
            .unwrap_or(false);
        self.nitro_urls = self.settings.get("nitro_urls").to_owned();
        self.city_key_path = self.settings.get("city_key_path").to_owned();
        if self.city {
            self.nitro = true;
            self.unity = false;
            self.allow_city_helper = true;
        }
        if self.nitro {
            self.origins = false;
        }
        let legacy_dark = self
            .settings
            .booleans
            .get("dark_mode")
            .copied()
            .unwrap_or(false);
        self.theme = AppTheme::from_settings(
            self.settings.values.get("theme").map(String::as_str),
            legacy_dark,
        );
        self.custom_accent = self
            .settings
            .values
            .get("theme_accent")
            .and_then(|value| parse_hex_color(value));
        self.outgoing = self
            .settings
            .booleans
            .get("outgoing")
            .copied()
            .unwrap_or(true);
        self.incoming = self
            .settings
            .booleans
            .get("incoming")
            .copied()
            .unwrap_or(true);
        self.i18n = I18n::new(&self.language);
        if let Some(host) = &self.extension_host {
            if let Err(e) = host.set_language(&self.language) {
                self.status = e.to_string();
            }
            if let Err(e) = host.set_theme(self.theme.extension_theme_name()) {
                self.status = e.to_string();
            }
        }
        self.update_rules();
        self.start_doctor_check();
        self.last_saved_settings_hash = Some(self.settings_fingerprint());
        self.settings_dirty_since = None;
    }
    fn settings_fingerprint(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.theme.name().hash(&mut h);
        self.custom_accent.map(format_hex_color).hash(&mut h);
        self.language.hash(&mut h);
        self.listen.hash(&mut h);
        self.remote.hash(&mut h);
        self.attachment_host.hash(&mut h);
        self.connection_port.hash(&mut h);
        self.nitro_urls.hash(&mut h);
        self.city_key_path.hash(&mut h);
        self.notepad.hash(&mut h);
        self.origins.hash(&mut h);
        self.nitro.hash(&mut h);
        self.unity.hash(&mut h);
        self.city.hash(&mut h);
        self.auto_detect.hash(&mut h);
        self.system_proxy.hash(&mut h);
        self.system_proxy_pac.hash(&mut h);
        self.allow_city_helper.hash(&mut h);
        self.auto_update.hash(&mut h);
        self.always_on_top.hash(&mut h);
        self.scheduler_auto_start.hash(&mut h);
        self.socks_enabled.hash(&mut h);
        self.socks_proxy.hash(&mut h);
        self.outgoing.hash(&mut h);
        self.incoming.hash(&mut h);
        self.logger_friendly.hash(&mut h);
        self.logger_hide_noisy.hash(&mut h);
        self.logger_show_stats.hash(&mut h);
        self.logger_autoscroll.hash(&mut h);
        self.logger_timestamp.hash(&mut h);
        self.logger_names.hash(&mut h);
        self.logger_hashes.hash(&mut h);
        self.logger_structure.hash(&mut h);
        self.logger_split.hash(&mut h);
        self.logger_hidden_headers.len().hash(&mut h);
        self.logger_presets.len().hash(&mut h);
        self.injection_favorites.len().hash(&mut h);
        self.connection_profiles.len().hash(&mut h);
        self.custom_hotels.hash(&mut h);
        self.developer_mode.hash(&mut h);
        self.disable_decryption.hash(&mut h);
        self.debug_stdout.hash(&mut h);
        self.python_enabled.hash(&mut h);
        h.finish()
    }
    fn poll_auto_save_settings(&mut self) {
        let fp = self.settings_fingerprint();
        match self.last_saved_settings_hash {
            None => {
                self.last_saved_settings_hash = Some(fp);
            }
            Some(saved) if saved == fp => {
                self.settings_dirty_since = None;
            }
            Some(_) => {
                let now = Instant::now();
                let since = *self.settings_dirty_since.get_or_insert(now);
                if now.duration_since(since) >= Duration::from_millis(800) {
                    self.save_settings_internal(true);
                }
            }
        }
    }
    fn save_settings(&mut self) {
        self.save_settings_internal(false);
    }
    fn save_settings_internal(&mut self, quiet: bool) {
        self.python_console.save_settings(&mut self.settings);
        self.settings
            .values
            .insert("injection_history".into(), self.injection_history.to_json());
        if self.injection_favorites.is_empty() {
            self.settings.values.remove("injection_favorites");
        } else {
            self.settings.values.insert(
                "injection_favorites".into(),
                logger_ui::serialize_injection_favorites(&self.injection_favorites),
            );
        }
        if self.connection_profiles.is_empty() {
            self.settings.values.remove("connection_profiles");
        } else {
            self.settings.values.insert(
                "connection_profiles".into(),
                doctor::serialize_connection_profiles(&self.connection_profiles),
            );
        }
        self.settings.values.insert(
            "logger_representation".into(),
            self.logger_representation.name().into(),
        );
        self.settings
            .values
            .insert("logger_antispam".into(), self.logger_antispam.name().into());
        self.settings
            .values
            .insert("logger_packet_limit".into(), self.packet_limit.to_string());
        if self.logger_hidden_headers.is_empty() {
            self.settings.values.remove("logger_hidden_headers");
        } else {
            self.settings.values.insert(
                "logger_hidden_headers".into(),
                logger_ui::format_hidden_headers_setting(&self.logger_hidden_headers),
            );
        }
        if self.logger_presets.is_empty() {
            self.settings.values.remove("logger_filter_presets");
        } else {
            self.settings.values.insert(
                "logger_filter_presets".into(),
                logger_ui::serialize_filter_presets(&self.logger_presets),
            );
        }
        for (key, value) in [
            ("listen", &self.listen),
            ("remote", &self.remote),
            ("attachment_host", &self.attachment_host),
            ("connection_port", &self.connection_port),
            ("hotel_version", &self.hotel_version),
            ("client_identifier", &self.client_identifier),
            ("packet_database", &self.packet_database),
            ("socks_proxy", &self.socks_proxy),
            ("socks_user", &self.socks_user),
            ("extension_runtime", &self.extension_runtime),
            ("nitro_urls", &self.nitro_urls),
            ("city_key_path", &self.city_key_path),
            ("notepad", &self.notepad),
            ("language", &self.language),
        ] {
            self.settings.values.insert(key.into(), value.clone());
        }
        self.settings
            .values
            .insert("theme".into(), self.theme.name().into());
        if let Some(accent) = self.custom_accent {
            self.settings
                .values
                .insert("theme_accent".into(), format_hex_color(accent));
        } else {
            self.settings.values.remove("theme_accent");
        }
        if self.custom_hotels.is_empty() {
            self.settings.values.remove("custom_hotels");
        } else {
            self.settings
                .values
                .insert("custom_hotels".into(), self.custom_hotels.join("\n"));
        }
        self.settings.booleans.extend([
            ("auto_update".into(), self.auto_update),
            (
                "confirm_uninstall_extension".into(),
                self.confirm_uninstall_extension,
            ),
            ("always_on_top".into(), self.always_on_top),
            ("auto_detect".into(), self.auto_detect),
            ("scheduler_auto_start".into(), self.scheduler_auto_start),
            ("socks_enabled".into(), self.socks_enabled),
            ("origins".into(), self.origins),
            ("nitro".into(), self.nitro),
            ("unity".into(), self.unity),
            ("city".into(), self.city),
            ("system_proxy".into(), self.system_proxy),
            ("system_proxy_pac".into(), self.system_proxy_pac),
            ("allow_city_helper".into(), self.allow_city_helper),
            ("dark_mode".into(), self.theme.is_dark()),
            ("outgoing".into(), self.outgoing),
            ("incoming".into(), self.incoming),
            ("logger_additional".into(), self.logger_additional),
            ("logger_structure".into(), self.logger_structure),
            (
                "logger_java_structure_limit".into(),
                self.logger_java_structure_limit,
            ),
            (
                "logger_java_structure_clean".into(),
                self.logger_java_structure_clean,
            ),
            ("logger_split".into(), self.logger_split),
            (
                "logger_export_separators".into(),
                self.logger_export_separators,
            ),
            (
                "logger_export_hide_empty_header".into(),
                self.logger_export_hide_empty_header,
            ),
            (
                "logger_display_hide_empty_header".into(),
                self.logger_display_hide_empty_header,
            ),
            ("logger_names".into(), self.logger_names),
            ("logger_hashes".into(), self.logger_hashes),
            ("logger_message_id".into(), self.logger_message_id),
            ("logger_friendly".into(), self.logger_friendly),
            ("developer_mode".into(), self.developer_mode),
            ("disable_decryption".into(), self.disable_decryption),
            ("debug_stdout".into(), self.debug_stdout),
            ("always_admin".into(), self.always_admin),
            ("python_enabled".into(), self.python_enabled),
            ("logger_extra_legacy".into(), self.logger_extra_legacy),
            ("logger_extra_raw_hex".into(), self.logger_extra_raw_hex),
            ("logger_extra_hex_dump".into(), self.logger_extra_hex_dump),
            ("logger_skip_big".into(), self.logger_skip_big),
            ("logger_timestamp".into(), self.logger_timestamp),
            ("logger_autoscroll".into(), self.logger_autoscroll),
            (
                "logger_capture_selected_only".into(),
                self.logger_capture_selected_only,
            ),
            (
                "logger_open_on_connect".into(),
                self.logger_window.open_on_connect,
            ),
            (
                "logger_hide_on_disconnect".into(),
                self.logger_window.hide_on_disconnect,
            ),
            (
                "logger_always_on_top".into(),
                self.logger_window.always_on_top,
            ),
            (
                "logger_clear_on_connect".into(),
                self.logger_clear_on_connect,
            ),
            (
                "logger_clear_on_disconnect".into(),
                self.logger_clear_on_disconnect,
            ),
            ("logger_hide_noisy".into(), self.logger_hide_noisy),
            ("logger_show_stats".into(), self.logger_show_stats),
        ]);
        match self.settings.save(&self.settings_path) {
            Ok(()) => {
                self.settings_loaded = true;
                self.last_saved_settings_hash = Some(self.settings_fingerprint());
                self.settings_dirty_since = None;
                if !quiet {
                    self.status = "Settings saved".into();
                }
            }
            Err(e) => {
                if !quiet {
                    self.status = e.to_string();
                }
            }
        }
    }
    fn custom_packet_names_path(&self) -> PathBuf {
        self.settings_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("custom-packets.json")
    }
    fn apply_custom_packet_names(&mut self) {
        self.packet_info = self
            .packet_info
            .with_custom_names(&self.custom_packet_names);
        invalidate_log_expressions(&mut self.logs);
        self.logger_search_cache = None;
    }
    fn upsert_custom_packet_name(&mut self, direction: Direction, header: u16, name: String) {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            self.remove_custom_packet_name(direction, header);
            return;
        }
        if let Some(existing) = self
            .custom_packet_names
            .iter_mut()
            .find(|(d, h, _)| *d == direction && *h == header)
        {
            existing.2 = trimmed.to_owned();
        } else {
            self.custom_packet_names
                .push((direction, header, trimmed.to_owned()));
            self.custom_packet_names
                .sort_by(|a, b| (a.0.name(), a.1).cmp(&(b.0.name(), b.1)));
        }
        self.apply_custom_packet_names();
        match PacketInfoManager::save_custom_names(
            &self.custom_packet_names_path(),
            &self.custom_packet_names,
        ) {
            Ok(()) => {
                self.status = format!("Named {} header {header} as {trimmed}", direction.name());
            }
            Err(e) => self.status = format!("Custom name updated in memory; save failed: {e}"),
        }
    }
    fn remove_custom_packet_name(&mut self, direction: Direction, header: u16) {
        self.custom_packet_names
            .retain(|(d, h, _)| !(*d == direction && *h == header));
        self.apply_custom_packet_names();
        let _ = PacketInfoManager::save_custom_names(
            &self.custom_packet_names_path(),
            &self.custom_packet_names,
        );
    }
    fn packet_format(&self, direction: Direction) -> PacketFormat {
        if self.origins && !self.nitro {
            if direction == Direction::ToServer {
                PacketFormat::WedgieOutgoing
            } else {
                PacketFormat::WedgieIncoming
            }
        } else {
            PacketFormat::EvaWire
        }
    }
    fn load_packet_database(&mut self) -> std::io::Result<()> {
        if !self.packet_database.trim().is_empty() {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::fs::File::open(&self.packet_database)?
                .take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 8 * 1024 * 1024 {
                return Err(std::io::Error::other("packet database exceeds 8 MiB"));
            }
            self.packet_info = if Path::new(&self.packet_database)
                .extension()
                .is_some_and(|s| s.eq_ignore_ascii_case("json"))
            {
                PacketInfoManager::from_json(&self.hotel_version, &bytes)
            } else {
                PacketInfoManager::from_tsv(
                    &self.hotel_version,
                    std::str::from_utf8(&bytes).map_err(std::io::Error::other)?,
                )
            }
            .map_err(std::io::Error::other)?;
        } else if self.packet_info.version != self.hotel_version {
            self.packet_info = PacketInfoManager::default();
        }
        self.apply_custom_packet_names();
        Ok(())
    }
    fn relay_options(&mut self) -> std::io::Result<RelayOptions> {
        self.load_packet_database()?;
        let cipher = |key: &str| -> std::io::Result<Option<Rc4>> {
            if key.trim().is_empty() {
                Ok(None)
            } else {
                Rc4::new(&expression::parse_hex(key).map_err(std::io::Error::other)?)
                    .map(Some)
                    .map_err(std::io::Error::other)
            }
        };
        let (host, port) = self
            .remote
            .rsplit_once(':')
            .ok_or_else(|| std::io::Error::other("Remote address requires host:port"))?;
        let connection = ConnectionDetails {
            host: host.trim_start_matches('[').trim_end_matches(']').into(),
            port: port.parse().map_err(std::io::Error::other)?,
            version: self.hotel_version.clone(),
            identifier: self.client_identifier.clone(),
            client_type: if self.origins {
                "SHOCKWAVE".into()
            } else {
                "FLASH".into()
            },
            packets: self.packet_info.clone(),
        };
        Ok(RelayOptions {
            packet_safety: Some(self.packet_safety.clone()),
            admin_service: Some(self.admin_service.clone()),
            flash_process: if self.flash_auto && !self.origins && !self.disable_decryption {
                if self.flash_pid != 0
                    && !gearth_platform::habbo_processes()?
                        .iter()
                        .any(|p| p.pid == self.flash_pid)
                {
                    return Err(std::io::Error::other(
                        "Selected Habbo process is no longer running",
                    ));
                }
                Some(self.flash_pid)
            } else {
                None
            },
            shockwave: self.origins,
            disable_origins_metadata: false,
            extensions: self.extension_host.clone(),
            connection: Some(connection),
            socks: configured_socks(
                self.socks_enabled,
                &self.socks_proxy,
                &self.socks_user,
                &self.socks_password,
            )?,
            outgoing_rc4: cipher(&self.outgoing_key)?,
            incoming_rc4: cipher(&self.incoming_key)?,
            single_session: false,
        })
    }
    fn extensions(&mut self, ui: &mut egui::Ui) {
        let palette = self.theme.palette_with_accent(self.custom_accent);
        let avail_w = ui.available_width().max(580.0);
        let table_h = (ui.available_height() - 80.0).clamp(110.0, 460.0);
        let fire_tex = self
            .logos
            .as_ref()
            .and_then(|l| l.btn_fire.as_ref())
            .cloned();
        let exit_tex = self
            .logos
            .as_ref()
            .and_then(|l| l.btn_exit.as_ref())
            .cloned();
        let delete_tex = self
            .logos
            .as_ref()
            .and_then(|l| l.btn_delete.as_ref())
            .cloned();
        let reload_tex = self
            .logos
            .as_ref()
            .and_then(|l| l.btn_reload.as_ref())
            .cloned();
        let ext_dir = self.extensions_dir();

        let mut pending_restart: Option<String> = None;
        let mut pending_uninstall: Option<(Option<u64>, String, String)> = None;

        // Pixel-faithful Extensions.fxml 5-column bordered table with vertical dividers
        group_box(ui, self.theme, egui::Margin::same(0.0), |ui| {
            let box_w = (avail_w - 2.0).max(560.0);
            ui.set_width(box_w);
            let inner_w = (box_w - 2.0).max(540.0);
            let col_title = (inner_w * 0.21).floor();
            let col_desc = (inner_w * 0.36).floor();
            let col_author = (inner_w * 0.17).floor();
            let col_ver = (inner_w * 0.12).floor();
            let col_edit = (inner_w - col_title - col_desc - col_author - col_ver).max(76.0);
            let col_xs = [
                col_title,
                col_title + col_desc,
                col_title + col_desc + col_author,
                col_title + col_desc + col_author + col_ver,
            ];
            let grid_stroke = egui::Stroke::new(1.0_f32, palette.table_grid_line);

            // Header row (centered labels, dark #282828 / light #f7f7f7, vertical dividers)
            let header_resp = egui::Frame::none()
                .fill(palette.table_header_bg)
                .inner_margin(egui::Margin::symmetric(0.0, 5.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        for (w, key) in [
                            (col_title, "tab.extensions.table.title"),
                            (col_desc, "tab.extensions.table.description"),
                            (col_author, "tab.extensions.table.author"),
                            (col_ver, "tab.extensions.table.version"),
                            (col_edit, "tab.extensions.table.edit"),
                        ] {
                            ui.allocate_ui_with_layout(
                                egui::vec2(w, 18.0),
                                egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                                |ui| {
                                    ui.set_min_width(w);
                                    ui.set_max_width(w);
                                    ui.label(
                                        egui::RichText::new(self.i18n.text(key))
                                            .color(palette.table_header_text),
                                    );
                                },
                            );
                        }
                    });
                });
            let hrect = header_resp.response.rect;
            for dx in col_xs {
                ui.painter().line_segment(
                    [
                        egui::pos2(hrect.left() + dx, hrect.top()),
                        egui::pos2(hrect.left() + dx, hrect.bottom()),
                    ],
                    grid_stroke,
                );
            }
            ui.painter()
                .line_segment([hrect.left_bottom(), hrect.right_bottom()], grid_stroke);

            egui::ScrollArea::vertical()
                .id_salt("extensions_table_scroll")
                .max_height(table_h)
                .show(ui, |ui| {
                    ui.set_min_height(table_h);
                    ui.spacing_mut().item_spacing.y = 0.0;
                    let draw_row =
                        |ui: &mut egui::Ui,
                         bg: egui::Color32,
                         title: &str,
                         desc: &str,
                         author: &str,
                         ver: &str,
                         render_actions: &mut dyn FnMut(&mut egui::Ui)| {
                            let row_resp = egui::Frame::none()
                                .fill(bg)
                                .inner_margin(egui::Margin::symmetric(0.0, 3.0))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 0.0;
                                        for (w, text) in [
                                            (col_title, title),
                                            (col_desc, desc),
                                            (col_author, author),
                                            (col_ver, ver),
                                        ] {
                                            ui.allocate_ui_with_layout(
                                                egui::vec2(w, 20.0),
                                                egui::Layout::left_to_right(egui::Align::Center),
                                                |ui| {
                                                    ui.set_min_width(w);
                                                    ui.set_max_width(w);
                                                    ui.add_space(6.0);
                                                    ui.add(egui::Label::new(text).truncate());
                                                },
                                            );
                                        }
                                        ui.allocate_ui_with_layout(
                                            egui::vec2(col_edit, 20.0),
                                            egui::Layout::left_to_right(egui::Align::Center),
                                            |ui| {
                                                ui.set_min_width(col_edit);
                                                ui.set_max_width(col_edit);
                                                ui.add_space(8.0);
                                                ui.spacing_mut().item_spacing.x = 6.0;
                                                render_actions(ui);
                                            },
                                        );
                                    });
                                });
                            let r = row_resp.response.rect;
                            for dx in col_xs {
                                ui.painter().line_segment(
                                    [
                                        egui::pos2(r.left() + dx, r.top()),
                                        egui::pos2(r.left() + dx, r.bottom()),
                                    ],
                                    grid_stroke,
                                );
                            }
                            ui.painter()
                                .line_segment([r.left_bottom(), r.right_bottom()], grid_stroke);
                        };

                    // Built-in internal rows (exact .tableRowBlue #3d5b69 dark / #f0ffff light / #fff0e3 Tanji)
                    let mut open_logger = false;
                    let mut open_store = false;
                    for (title, desc, author, ver, action) in [
                        (
                            "G-ExtensionStore",
                            "Get your extensions here",
                            "1desirable1337",
                            "1.0",
                            1u8,
                        ),
                        ("Packet Logger", "", "1desirable1337", "1.0", 0u8),
                    ] {
                        let open_tip = self.i18n.text("rust.extensions.open");
                        draw_row(
                            ui,
                            palette.table_row_blue,
                            title,
                            desc,
                            author,
                            ver,
                            &mut |ui| {
                                if icon_action(ui, fire_tex.as_ref(), ">", 14.0)
                                    .on_hover_text(&open_tip)
                                    .clicked()
                                {
                                    if action == 0 {
                                        open_logger = true;
                                    } else {
                                        open_store = true;
                                    }
                                }
                            },
                        );
                    }
                    if open_logger {
                        if self.logger_window.open {
                            ui.ctx().send_viewport_cmd_to(
                                egui::ViewportId::from_hash_of("logger_window"),
                                egui::ViewportCommand::Focus,
                            );
                        }
                        self.logger_window.open = true;
                    }
                    if open_store {
                        if self.ext_store_open {
                            ui.ctx().send_viewport_cmd_to(
                                egui::ViewportId::from_hash_of("extension_store_window"),
                                egui::ViewportCommand::Focus,
                            );
                        }
                        self.ext_store_open = true;
                    }

                    // External extensions (exact .tableRowActive #525252 / .tableRowInactive #5e5e5e)
                    if let Some(host) = &self.extension_host {
                        let open_tip = self.i18n.text("rust.extensions.open");
                        let allow_tip = self.i18n.text("rust.extensions.allow");
                        let disconnect_tip =
                            self.i18n.text("tab.extensions.table.edit.delete.tooltip");
                        let uninstall_tip = self
                            .i18n
                            .text("tab.extensions.table.edit.uninstall.tooltip");
                        let restart_tip =
                            self.i18n.text("tab.extensions.table.edit.restart.tooltip");
                        let mut status_update: Option<String> = None;
                        let connected = host.extensions();
                        let active_files: HashSet<String> = connected
                            .iter()
                            .filter_map(|e| e.info.file.clone())
                            .collect();
                        for extension in &connected {
                            let bg = if extension.approved {
                                palette.table_row_active
                            } else {
                                palette.table_row_inactive
                            };
                            let installed_file = extension.info.file.as_ref().filter(|fname| {
                                extension.info.can_delete
                                    && gearth_rust::extension_host::is_installed_file(
                                        &ext_dir, fname,
                                    )
                            });
                            draw_row(
                                ui,
                                bg,
                                &extension.info.title,
                                &extension.info.description,
                                &extension.info.author,
                                &extension.info.version,
                                &mut |ui| {
                                    if !extension.approved {
                                        if icon_action(ui, fire_tex.as_ref(), ">", 14.0)
                                            .on_hover_text(&allow_tip)
                                            .clicked()
                                        {
                                            if let Err(e) = host.approve(extension.id) {
                                                status_update = Some(e.to_string());
                                            }
                                        }
                                    } else if extension.info.on_click
                                        && icon_action(ui, fire_tex.as_ref(), ">", 14.0)
                                            .on_hover_text(&open_tip)
                                            .clicked()
                                    {
                                        if let Err(e) = host.click(extension.id) {
                                            status_update = Some(e.to_string());
                                        }
                                    }
                                    if extension.info.can_leave
                                        && icon_action(ui, exit_tex.as_ref(), "X", 14.0)
                                            .on_hover_text(&disconnect_tip)
                                            .clicked()
                                    {
                                        if let Err(e) = host.disconnect(extension.id) {
                                            status_update = Some(e.to_string());
                                        }
                                    }
                                    if let Some(fname) = installed_file {
                                        if icon_action(ui, delete_tex.as_ref(), "Del", 14.0)
                                            .on_hover_text(&uninstall_tip)
                                            .clicked()
                                        {
                                            pending_uninstall = Some((
                                                Some(extension.id),
                                                fname.clone(),
                                                extension.info.title.clone(),
                                            ));
                                        }
                                    }
                                },
                            );
                        }
                        // Disconnected installed extensions stay visible in .tableRowInactive with Reload + Delete
                        for (fname, info) in &self.known_installed_extensions {
                            if active_files.contains(fname)
                                || !gearth_rust::extension_host::is_installed_file(&ext_dir, fname)
                            {
                                continue;
                            }
                            draw_row(
                                ui,
                                palette.table_row_inactive,
                                &info.title,
                                &info.description,
                                &info.author,
                                &info.version,
                                &mut |ui| {
                                    if icon_action(ui, reload_tex.as_ref(), "R", 14.0)
                                        .on_hover_text(&restart_tip)
                                        .clicked()
                                    {
                                        pending_restart = Some(fname.clone());
                                    }
                                    if info.can_delete
                                        && icon_action(ui, delete_tex.as_ref(), "Del", 14.0)
                                            .on_hover_text(&uninstall_tip)
                                            .clicked()
                                    {
                                        pending_uninstall =
                                            Some((None, fname.clone(), info.title.clone()));
                                    }
                                },
                            );
                        }
                        if let Some(err) = status_update {
                            self.status = err;
                        }
                    } else {
                        ui.add_space(8.0);
                        ui.label(self.i18n.text("rust.extensions.server_unavailable"));
                    }
                });
        });

        if let Some(fname) = pending_restart {
            self.restart_installed_extension(&fname);
        }
        if let Some((id, fname, title)) = pending_uninstall {
            if self.confirm_uninstall_extension {
                self.confirm_uninstall_ext = Some((id, fname, title));
            } else {
                self.execute_extension_uninstall(id, fname, title);
            }
        }

        ui.add_space(8.0);

        // Exact Extensions.fxml bottom bar: Port: [9092] ... [G-Python shell] [Logs] [Installer]
        ui.horizontal(|ui| {
            ui.label(format!("{}:", self.i18n.text("tab.extensions.port")));
            ui.add_space(6.0);
            let mut port_text = self
                .extension_host
                .as_ref()
                .map(|host| host.address.port().to_string())
                .unwrap_or_else(|| "-".into());
            ui.add_enabled(
                false,
                egui::TextEdit::singleline(&mut port_text).desired_width(88.0),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                if ui
                    .add_enabled(
                        self.extension_host.is_some(),
                        egui::Button::new(self.i18n.text("tab.extensions.button.install"))
                            .min_size(egui::vec2(124.0, 28.0)),
                    )
                    .clicked()
                {
                    self.ext_install_open = true;
                }
                if ui
                    .add(
                        egui::Button::new(self.i18n.text("tab.extensions.button.logs"))
                            .min_size(egui::vec2(124.0, 28.0)),
                    )
                    .clicked()
                {
                    if self.ext_console_open {
                        ui.ctx().send_viewport_cmd_to(
                            egui::ViewportId::from_hash_of("extension_console_window"),
                            egui::ViewportCommand::Focus,
                        );
                    }
                    self.ext_console_open = true;
                }
                if ui
                    .add_enabled(
                        self.python_enabled,
                        egui::Button::new(self.i18n.text("tab.extensions.button.pythonshell"))
                            .min_size(egui::vec2(124.0, 28.0)),
                    )
                    .clicked()
                {
                    if self.ext_gpython_open {
                        ui.ctx().send_viewport_cmd_to(
                            egui::ViewportId::from_hash_of("gpython_shell_window"),
                            egui::ViewportCommand::Focus,
                        );
                    }
                    self.ext_gpython_open = true;
                }
            });
        });
    }
}
impl Drop for Desktop {
    fn drop(&mut self) {
        if let Some(worker) = self.attachment_worker.take() {
            let _ = worker.join();
        }
        if let Some(redirect) = &mut self.redirect {
            let _ = redirect.restore();
        }
        if self.settings_loaded
            || self
                .last_saved_settings_hash
                .is_some_and(|saved| saved != self.settings_fingerprint())
        {
            self.save_settings_internal(true);
        }
        if let Some(guard) = &mut self.proxy_guard {
            let _ = guard.restore();
        }
        self.relay.take();
        if let Some(host) = self.extension_host.take() {
            host.stop();
        }
        for child in &mut self.extension_processes {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod rule_editor_tests {
    use super::combine_rules;
    use gearth_rust::{
        packet::{Direction, Message, Packet, PacketFormat},
        packet_info::PacketInfoManager,
        rules::{Action, Rule, Rules},
    };

    fn message(header: u16) -> Message {
        Message {
            packet: Packet::new(header),
            direction: Direction::ToServer,
            index: 0,
            blocked: false,
        }
    }

    #[test]
    fn invalid_or_disabled_editor_does_not_retain_previous_rule_or_discard_saved_rules() {
        let info = PacketInfoManager::default();
        let saved = || {
            vec![Rule {
                enabled: true,
                direction: Direction::ToServer,
                header: 10,
                action: Action::Block,
            }]
        };
        let draft = |enabled, text| {
            Rules::editor_rule(
                enabled,
                Direction::ToServer,
                20,
                text,
                PacketFormat::EvaWire,
                &info,
            )
        };
        let (initial, error) = combine_rules(saved(), draft(true, "{h:21}"));
        assert!(error.is_none());
        let mut before = message(20);
        initial.apply(&mut before);
        assert_eq!(before.packet.header(), 21);

        for (enabled, expect_error) in [(true, true), (false, false)] {
            let (rules, error) = combine_rules(saved(), draft(enabled, "{h:bad}"));
            assert_eq!(error.is_some(), expect_error);
            let mut stale = message(20);
            rules.apply(&mut stale);
            assert_eq!(stale.packet.header(), 20);
            assert!(!stale.blocked);
            let mut still_saved = message(10);
            rules.apply(&mut still_saved);
            assert!(still_saved.blocked);
        }
        let (block, error) = combine_rules(vec![], draft(true, "  "));
        assert!(error.is_none());
        let mut blocked = message(20);
        block.apply(&mut blocked);
        assert!(blocked.blocked);
    }
}

#[cfg(test)]
mod logger_prediction_tests {
    use super::{
        bounded_log_prediction, clear_log_contents, invalidate_log_expressions, log_colors,
        log_header_layout, log_packet_metadata, log_row_matches, matching_packet_metadata,
        write_log_capture, write_log_metadata, LogDisplayOptions, LogRow, PacketRepresentation,
        LOG_PREDICTION_LIMIT,
    };
    use eframe::egui;
    use gearth_rust::packet::{Direction, Message, Packet, PacketFormat};
    use gearth_rust::packet_info::{PacketInfo, PacketInfoManager};
    use std::{collections::VecDeque, sync::OnceLock};

    #[test]
    fn hidden_header_row_accepts_primary_and_secondary_clicks() {
        let context = egui::Context::default();
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(400.0, 300.0));
        let mut row_rect = egui::Rect::NOTHING;
        let mut clicked = false;
        let mut secondary = false;
        for button in [egui::PointerButton::Primary, egui::PointerButton::Secondary] {
            for phase in 0..3 {
                let position = if phase == 0 {
                    egui::pos2(30.0, 30.0)
                } else {
                    row_rect.center()
                };
                let mut events = vec![egui::Event::PointerMoved(position)];
                if phase > 0 {
                    events.push(egui::Event::PointerButton {
                        pos: position,
                        button,
                        pressed: phase == 1,
                        modifiers: egui::Modifiers::default(),
                    });
                }
                let input = egui::RawInput {
                    screen_rect: Some(screen),
                    events,
                    ..Default::default()
                };
                let _ = context.run(input, |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let row = ui.allocate_ui(egui::vec2(200.0, 40.0), |ui| {
                            ui.allocate_response(
                                egui::vec2(ui.available_width(), 2.0),
                                egui::Sense::click(),
                            )
                        });
                        row_rect = row.response.rect;
                        let response = super::logger_row_response(row.inner, row.response, true);
                        clicked |= response.clicked();
                        secondary |= response.secondary_clicked();
                    });
                });
            }
        }
        assert!(clicked, "primary click should target hidden-header row");
        assert!(secondary, "secondary click should open its context menu");
    }

    #[test]
    fn logger_colors_distinguish_direction_and_highlight_markers() {
        for dark in [true, false] {
            let (incoming, _, highlight) = log_colors(Direction::ToClient, dark);
            let (outgoing, _, _) = log_colors(Direction::ToServer, dark);
            assert_ne!(incoming, outgoing);
            let header = "entrée BLOCKED {h:42}";
            let job = log_header_layout(header, Some("BLOCKED"), incoming, highlight, 14.0);
            assert_eq!(job.text, header);
            assert_eq!(job.sections[1].format.color, highlight);
            assert_eq!(&job.text[job.sections[1].byte_range.clone()], "BLOCKED");
            let normal = log_header_layout(header, None, incoming, highlight, 14.0);
            assert_eq!(normal.sections.len(), 1);
            assert_eq!(normal.sections[0].format.color, incoming);
        }
    }

    #[test]
    fn large_packet_option_hides_bytes_without_hiding_packet_expression() {
        let mut packet = Packet::new(42);
        packet.append(&vec![b'a'; 1000]).unwrap();
        let row = LogRow {
            message: Message {
                packet,
                direction: Direction::ToClient,
                index: 1,
                blocked: false,
            },
            timestamp_ms: None,
            expression: "{h:42}".into(),
            search: String::new(),
            bytes: 0,
            skipped: false,
            unity: false,
            predicted_structure: OnceLock::new(),
            packet_expression: OnceLock::new(),
            packet_metadata: OnceLock::new(),
        };
        let mut options = LogDisplayOptions {
            additional: false,
            names: false,
            hashes: false,
            message_id: false,
            representation: PacketRepresentation::Expression,
            extra_legacy: true,
            extra_raw_hex: false,
            extra_hex_dump: true,
            skip_big: true,
            skipped_label: "<paquet ignoré>",
            timestamp: false,
            timestamp_label: "timestamp",
            blocked_label: "Blocked",
            replaced_label: "Replaced",
            incoming_label: "Incoming",
            outgoing_label: "Outgoing",
            structure: false,
            java_structure_limit: false,
            java_structure_clean: false,
            export_hide_empty_header: false,
        };
        let info = PacketInfoManager::default();
        for payload_len in [1998, 1999] {
            let mut packet = Packet::new(42);
            packet.append(&vec![b'a'; payload_len]).unwrap();
            let mut long_row = LogRow {
                message: Message {
                    packet,
                    direction: Direction::ToClient,
                    index: 2,
                    blocked: false,
                },
                timestamp_ms: None,
                expression: String::new(),
                search: String::new(),
                bytes: 0,
                skipped: false,
                unity: false,
                predicted_structure: OnceLock::new(),
                packet_expression: OnceLock::from(("fixture structure".into(), true, true)),
                packet_metadata: OnceLock::new(),
            };
            options.structure = true;
            options.java_structure_limit = true;
            let mut output = Vec::new();
            write_log_capture(&mut output, [&long_row], &info, options, false).unwrap();
            assert_eq!(
                String::from_utf8(output)
                    .unwrap()
                    .contains("fixture structure"),
                payload_len == 1998
            );
            options.java_structure_limit = false;
            let mut output = Vec::new();
            write_log_capture(&mut output, [&long_row], &info, options, false).unwrap();
            assert!(String::from_utf8(output)
                .unwrap()
                .contains("fixture structure"));
            long_row.packet_expression.take();
            long_row
                .packet_expression
                .set(("unsafe\rtext".into(), true, false))
                .unwrap();
            options.java_structure_clean = true;
            let mut output = Vec::new();
            write_log_capture(&mut output, [&long_row], &info, options, false).unwrap();
            assert!(!String::from_utf8(output).unwrap().contains("unsafe"));
            options.java_structure_clean = false;
            let mut output = Vec::new();
            write_log_capture(&mut output, [&long_row], &info, options, false).unwrap();
            assert!(String::from_utf8(output).unwrap().contains("unsafe"));
        }
        options.structure = false;
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, false).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("{h:42}"));
        assert!(text.contains("<paquet ignoré>"));
        assert!(!text.contains("00000000  "));
        assert!(!text.contains("Legacy:"));
        options.representation = PacketRepresentation::RawHex;
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, false).unwrap();
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("<paquet ignoré>"));
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, true).unwrap();
        let skipped = String::from_utf8(output).unwrap();
        assert!(skipped.ends_with("<paquet ignoré>--------------------\n"));
        assert!(!skipped.contains("Incoming[42] ->"));
        for format in [PacketFormat::WedgieIncoming, PacketFormat::WedgieOutgoing] {
            for length in [1000, 1001] {
                let mut bytes = vec![b'x'; length];
                bytes[0] = 64;
                bytes[1] = 64;
                let wedgie = LogRow {
                    message: Message {
                        packet: Packet::from_bytes_with_format(format, bytes).unwrap(),
                        direction: Direction::ToClient,
                        index: 1,
                        blocked: false,
                    },
                    timestamp_ms: None,
                    expression: String::new(),
                    search: String::new(),
                    bytes: 0,
                    skipped: false,
                    unity: false,
                    predicted_structure: OnceLock::new(),
                    packet_expression: OnceLock::new(),
                    packet_metadata: OnceLock::new(),
                };
                let mut output = Vec::new();
                write_log_capture(&mut output, [&wedgie], &info, options, true).unwrap();
                let text = String::from_utf8(output).unwrap();
                if length == 1001 {
                    assert_eq!(text, "<paquet ignoré>--------------------\n");
                } else {
                    assert!(text.starts_with("Incoming[0] -> "));
                }
            }
        }
        options.representation = PacketRepresentation::Expression;
        options.skip_big = false;
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, false).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("Legacy:"));
        assert!(text.contains("00000000  "));
    }

    #[test]
    fn exported_capture_uses_display_options_and_reports_write_errors() {
        let mut row = LogRow {
            message: Message {
                packet: Packet::new(42),
                direction: Direction::ToClient,
                index: 7,
                blocked: true,
            },
            timestamp_ms: Some(123),
            expression: "{h:42}".into(),
            search: String::new(),
            bytes: 0,
            skipped: false,
            unity: false,
            predicted_structure: OnceLock::new(),
            packet_expression: OnceLock::new(),
            packet_metadata: OnceLock::new(),
        };
        let info = PacketInfoManager::new(
            "test",
            vec![
                PacketInfo {
                    header: 42,
                    direction: Direction::ToClient,
                    name: Some("Example".into()),
                    hash: Some("abc".into()),
                    structure: None,
                    source: "test".into(),
                },
                PacketInfo {
                    header: 42,
                    direction: Direction::ToClient,
                    name: Some("Another".into()),
                    hash: Some("def".into()),
                    structure: None,
                    source: "test".into(),
                },
            ],
        );
        let mut options = LogDisplayOptions {
            additional: false,
            names: true,
            hashes: true,
            message_id: true,
            representation: PacketRepresentation::RawHex,
            extra_legacy: false,
            extra_raw_hex: false,
            extra_hex_dump: false,
            skip_big: false,
            skipped_label: "<packet skipped>",
            timestamp: true,
            timestamp_label: "timestamp",
            blocked_label: "Blocked",
            replaced_label: "Replaced",
            incoming_label: "Incoming",
            outgoing_label: "Outgoing",
            structure: false,
            java_structure_limit: false,
            java_structure_clean: false,
            export_hide_empty_header: false,
        };
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, true).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text, "(timestamp: 123)\n[Example][Another][abc][def][42]\n[Blocked]\nIncoming[42] -> 00000002002a\n--------------------\n");
        assert!(text.contains("Incoming"));
        assert!(text.contains("[Blocked]\n"));
        assert!(text.contains("[Example][Another][abc][def][42]\n[Blocked]\n"));
        assert!(text.contains("00000002002a"));
        assert!(text.ends_with("--------------------\n"));
        let long_name = "é".repeat(700);
        let long_hash = "f".repeat(1100);
        let metadata = PacketInfoManager::new(
            "test",
            vec![
                PacketInfo {
                    header: 42,
                    direction: Direction::ToClient,
                    name: Some(long_name.clone()),
                    hash: Some(long_hash.clone()),
                    structure: None,
                    source: "test".into(),
                },
                PacketInfo {
                    header: 42,
                    direction: Direction::ToClient,
                    name: Some("".into()),
                    hash: Some(long_hash.clone()),
                    structure: None,
                    source: "test".into(),
                },
                PacketInfo {
                    header: 42,
                    direction: Direction::ToClient,
                    name: Some(long_name.clone()),
                    hash: Some("second".into()),
                    structure: None,
                    source: "test".into(),
                },
                PacketInfo {
                    header: 42,
                    direction: Direction::ToServer,
                    name: Some("wrong direction".into()),
                    hash: None,
                    structure: None,
                    source: "test".into(),
                },
            ],
        );
        let mut full_metadata = Vec::new();
        write_log_metadata(&mut full_metadata, &row, &metadata, options).unwrap();
        assert_eq!(
            String::from_utf8(full_metadata).unwrap(),
            format!("[{long_name}][][{long_hash}][second][42]\n")
        );
        let original_options = options;
        options.names = false;
        options.hashes = false;
        options.message_id = false;
        options.timestamp = false;
        row.message.blocked = false;
        row.message.direction = Direction::ToServer;
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, true).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "Outgoing[42] -> 00000002002a\n--------------------\n"
        );
        row.message.packet.put_string(&"x".repeat(1500)).unwrap();
        row.message.packet.edited = false;
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, false).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(
            text.trim_end().len(),
            "Outgoing[42] -> ".len() + row.message.packet.bytes().len() * 2
        );
        assert!(!text.contains('…'));
        // A display-limited row still retains the complete packet for export.
        row.skipped = true;
        options.structure = true;
        options.java_structure_limit = true;
        let structured_info = PacketInfoManager::new(
            "test",
            vec![PacketInfo {
                header: 42,
                direction: Direction::ToServer,
                name: Some("LongText".into()),
                hash: None,
                structure: Some("s".into()),
                source: "test".into(),
            }],
        );
        let (expected_structure, _) = gearth_rust::structure_prediction::expression_with_metadata(
            &row.message.packet,
            Direction::ToServer,
            &structured_info,
            false,
        )
        .unwrap();
        assert!(expected_structure.len() > LOG_PREDICTION_LIMIT);
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &structured_info, options, true).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains(&expected_structure));
        assert!(!text.contains("packet too large to display"));
        row.skipped = false;
        row.message.packet = Packet::new(42);
        row.message.direction = Direction::ToClient;
        row.message.blocked = true;
        options = original_options;
        for (visible, forced, expected) in [
            (false, false, false),
            (false, true, true),
            (true, false, true),
        ] {
            let mut output = Vec::new();
            write_log_capture(
                &mut output,
                [&row, &row],
                &info,
                options,
                gearth_rust::logger_display::export_separators(visible, forced),
            )
            .unwrap();
            assert_eq!(
                String::from_utf8(output)
                    .unwrap()
                    .matches("--------------------\n")
                    .count(),
                if expected { 2 } else { 0 }
            );
        }
        options.extra_legacy = true;
        options.extra_raw_hex = true;
        options.extra_hex_dump = true;
        options.timestamp_label = "heure";
        options.incoming_label = "Entrant";
        options.blocked_label = "Bloqué";
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, false).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with("(heure: 123)\n"));
        assert!(text.contains("Entrant"));
        assert!(text.contains("[Bloqué]\n"));
        assert!(text.contains("Entrant[42] -> "));
        assert!(!text.contains("Legacy:"));
        assert!(text.contains("00000002002a"));
        assert!(text.contains("00000000  00 00 00 02 00 2a"));
        assert!(!text.contains("Raw hex:")); // Already used by the main representation.
        options.extra_legacy = false;
        options.extra_raw_hex = false;
        options.extra_hex_dump = false;
        options.representation = PacketRepresentation::NoBytes;
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, false).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("00000002002a"));
        assert!(!text.contains("{h:42}"));
        assert!(text.contains("#000007"));
        options.export_hide_empty_header = true;
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, true).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("#000007"));
        assert!(text.contains(&format!("[{}]", options.blocked_label)));
        assert!(text.ends_with("--------------------\n"));
        options.extra_raw_hex = true;
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, false).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("Entrant[42] -> 00000002002a"));
        assert!(!text.contains("#000007"));
        options.extra_legacy = true;
        options.extra_hex_dump = true;
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, false).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.find("Entrant[42] -> ").unwrap() < text.find("00000000  ").unwrap());
        assert!(text.find("00000000  ").unwrap() < text.rfind("00000002002a").unwrap());
        options.extra_raw_hex = false;
        options.representation = PacketRepresentation::HexDump;
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, false).unwrap();
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("00000000  00 00 00 02 00 2a"));
        row.message.blocked = false;
        row.message.packet.edited = true;
        options.replaced_label = "Remplacé";
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, false).unwrap();
        assert!(String::from_utf8(output).unwrap().contains("[Remplacé]\n"));
        struct Fails;
        impl std::io::Write for Fails {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("write failed"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(write_log_capture(Fails, [&row], &info, options, false).is_err());
    }

    #[test]
    fn limits_predictions_without_splitting_unicode() {
        let short = "abc".to_owned();
        assert_eq!(bounded_log_prediction(short.clone()), short);
        let long = bounded_log_prediction("é".repeat(1000));
        assert!(long.len() <= LOG_PREDICTION_LIMIT);
        assert!(long.ends_with('…'));
    }

    #[test]
    fn packet_metadata_refresh_invalidates_cached_expressions() {
        let cached = OnceLock::new();
        cached
            .set(("old expression".to_owned(), true, true))
            .unwrap();
        let metadata = OnceLock::new();
        metadata
            .set(("old name".into(), "old hash".into()))
            .unwrap();
        let mut rows = VecDeque::from([LogRow {
            message: Message {
                packet: Packet::new(1),
                direction: Direction::ToClient,
                index: 1,
                blocked: false,
            },
            timestamp_ms: None,
            expression: String::new(),
            search: String::new(),
            bytes: 0,
            skipped: false,
            unity: false,
            predicted_structure: OnceLock::new(),
            packet_expression: cached,
            packet_metadata: metadata,
        }]);
        invalidate_log_expressions(&mut rows);
        assert!(rows[0].packet_expression.get().is_none());
        assert!(rows[0].packet_metadata.get().is_none());
        let mut accounted_bytes = 500;
        let filtered = 7;
        clear_log_contents(&mut rows, &mut accounted_bytes);
        assert!(rows.is_empty());
        assert_eq!((accounted_bytes, filtered), (0, 7));
    }

    #[test]
    fn packet_metadata_respects_direction_and_removes_duplicates() {
        let entry = |direction, name: &str, hash: &str| PacketInfo {
            header: 42,
            direction,
            name: Some(name.into()),
            hash: Some(hash.into()),
            structure: None,
            source: "fixture".into(),
        };
        let info = PacketInfoManager::new(
            "fixture",
            vec![
                entry(Direction::ToClient, "Room", "abc"),
                entry(Direction::ToClient, "Room", "abc"),
                entry(Direction::ToClient, "Other", "def"),
                entry(Direction::ToServer, "Outgoing", "xyz"),
            ],
        );
        assert_eq!(
            log_packet_metadata(&info, Direction::ToClient, 42),
            ("Room][Other".into(), "abc][def".into())
        );
        assert_eq!(
            log_packet_metadata(&info, Direction::ToServer, 42),
            ("Outgoing".into(), "xyz".into())
        );
        assert_eq!(
            log_packet_metadata(&info, Direction::ToClient, 43),
            (String::new(), String::new())
        );
    }

    #[test]
    fn logger_search_matches_names_and_hashes_without_crossing_directions() {
        let info = PacketInfoManager::new(
            "v",
            vec![PacketInfo {
                header: 42,
                direction: Direction::ToClient,
                name: Some("RoomInfo".into()),
                hash: Some("AB12".into()),
                structure: None,
                source: "fixture".into(),
            }],
        );
        let incoming = LogRow {
            message: Message {
                packet: Packet::new(42),
                direction: Direction::ToClient,
                index: 1,
                blocked: false,
            },
            timestamp_ms: None,
            expression: "{h:42}".into(),
            search: "42 {h:42}".into(),
            bytes: 0,
            skipped: false,
            unity: false,
            predicted_structure: OnceLock::new(),
            packet_expression: OnceLock::new(),
            packet_metadata: OnceLock::new(),
        };
        let matches = matching_packet_metadata(&info, "roominfo");
        assert!(log_row_matches(&incoming, "roominfo", &matches, true, true));
        assert!(!log_row_matches(
            &incoming, "roominfo", &matches, true, false
        ));
        assert!(log_row_matches(
            &incoming,
            "ab12",
            &matching_packet_metadata(&info, "ab12"),
            true,
            true
        ));
        let mut outgoing = incoming;
        outgoing.message.direction = Direction::ToServer;
        assert!(!log_row_matches(
            &outgoing, "roominfo", &matches, true, true
        ));
        assert!(log_row_matches(&outgoing, "42", &matches, true, true));
    }

    #[test]
    fn custom_hotels_parse_trims_and_deduplicates_case_insensitively() {
        let parsed = super::parse_custom_hotels(
            "  game-test.example \n\nGAME-TEST.EXAMPLE\ngame-2.example\n",
        );
        assert_eq!(parsed, vec!["game-test.example", "game-2.example"]);
    }

    #[test]
    fn cli_launch_args_parse_beta29_flags_and_equals_syntax() {
        let args: Vec<String> = [
            "-c",
            "origins",
            "--host",
            "game-od.habbo.com",
            "--port=40001",
            "--debug",
            "-t",
            "tanji",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let parsed = super::parse_cli_args(&args);
        assert_eq!(parsed.connect_client, Some(super::CliClientMode::Origins));
        assert_eq!(parsed.host.as_deref(), Some("game-od.habbo.com"));
        assert_eq!(parsed.port, Some(40001));
        assert!(parsed.debug_stdout);
        assert_eq!(parsed.theme, Some(super::AppTheme::Tanji));

        let nitro_args: Vec<String> = ["--connect=nitro", "--theme=dark", "--port", "0"]
            .into_iter()
            .map(String::from)
            .collect();
        let nitro = super::parse_cli_args(&nitro_args);
        assert_eq!(nitro.connect_client, Some(super::CliClientMode::Nitro));
        assert_eq!(nitro.theme, Some(super::AppTheme::GEarthDark));
        assert_eq!(nitro.port, None);
    }

    #[test]
    fn extension_console_parses_beta29_color_tags_and_announcement_prefix() {
        let (prefix, color, body) =
            super::parse_extension_console_line("#3 [green]G-Presets --> Ready!");
        assert_eq!(prefix, "#3 G-Presets --> ");
        assert_eq!(color, Some("green"));
        assert_eq!(body, "Ready!");
        assert!(super::extension_console_color("green", true).is_some());
        assert!(super::extension_console_color("darkergreen", false).is_some());
        assert!(super::extension_console_color("unknown", true).is_none());

        let (prefix2, color2, body2) = super::parse_extension_console_line("#1 plain message");
        assert_eq!(prefix2, "#1 ");
        assert_eq!(color2, None);
        assert_eq!(body2, "plain message");
    }
}
