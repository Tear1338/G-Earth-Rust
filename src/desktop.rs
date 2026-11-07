#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;
mod gpython_ui;
mod store_ui;
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
    web_proxy::{WebOptions, WebProxy, NITRO_REVISION},
};
use std::{
    collections::{HashSet, VecDeque},
    io::Read,
    path::{Path, PathBuf},
    process::Child,
    sync::mpsc::Receiver,
    sync::{Arc, OnceLock},
    time::{Duration, Instant, SystemTime},
};

// Both lazy prediction caches count against the capture byte budget.
const LOG_PREDICTION_LIMIT: usize = 1024;

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

fn main() -> eframe::Result<()> {
    eframe::run_native(
        "G-Earth Rust — development",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1060.0, 720.0])
                .with_min_inner_size([780.0, 540.0]),
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
    logger_split: bool,
    logger_names: bool,
    logger_hashes: bool,
    logger_message_id: bool,
    logger_representation: PacketRepresentation,
    logger_extra_legacy: bool,
    logger_extra_raw_hex: bool,
    logger_extra_hex_dump: bool,
    logger_skip_big: bool,
    logger_timestamp: bool,
    logger_autoscroll: bool,
    logger_clear_on_connect: bool,
    logger_clear_on_disconnect: bool,
    logger_window: logger_display::LoggerWindow,
    logger_connection_active: bool,
    logger_antispam: AntiSpam,
    logger_filter: LoggerFilter,
    logger_filtered: u64,
    packet_dump: Option<String>,
    expression: String,
    direction: Direction,
    injection_history: InjectionHistory,
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
    scheduler_hotkeys: Option<gearth_platform::GlobalHotkeys>,
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
    extension_processes: Vec<Child>,
    extension_console: VecDeque<String>,
    hotel_version: String,
    client_identifier: String,
    packet_database: String,
    packet_info: PacketInfoManager,
    packet_safety: Arc<std::sync::Mutex<gearth_rust::packet_safety::PacketSafety>>,
    developer_mode: bool,
    developer_mode_confirmation: bool,
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
    dark_mode: bool,
    language: String,
    i18n: I18n,
    notepad: String,
    logs_bytes: usize,
    replacement_expression: String,
    origins: bool,
    nitro: bool,
    unity: bool,
    system_proxy: bool,
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
    packet_expression: OnceLock<(String, bool)>,
    packet_metadata: OnceLock<(String, String)>,
}
fn invalidate_log_expressions(logs: &mut VecDeque<LogRow>) {
    for row in logs {
        row.packet_expression.take();
        row.packet_metadata.take();
    }
}
fn clear_log_contents(logs: &mut VecDeque<LogRow>, bytes: &mut usize, filtered: &mut u64) {
    logs.clear();
    *bytes = 0;
    *filtered = 0;
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
        bounded_log_prediction(names.join(", ")),
        bounded_log_prediction(hashes.join(", ")),
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
    structure: bool,
}

struct RenderedLogRow {
    header: String,
    extra_representations: Vec<String>,
    dump: Option<String>,
    structure: Option<String>,
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
            metadata.push_str(&format!("[{names}] "));
        }
        if options.hashes && !hashes.is_empty() {
            metadata.push_str(&format!("[{hashes}] "));
        }
    }
    if options.message_id {
        metadata.push_str(&format!("[{}] ", packet.header()));
    }
    let has_byte_representation = options.representation != PacketRepresentation::Expression
        || options.extra_legacy
        || options.extra_raw_hex
        || options.extra_hex_dump;
    let omit_representations = options.skip_big
        && has_byte_representation
        && packet.format() == PacketFormat::EvaWire
        && logger_display::skip_large_eva_representations(
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
    let timestamp = if options.timestamp {
        row.timestamp_ms
            .map(|ms| format!("({ms} ms) "))
            .unwrap_or_default()
    } else {
        String::new()
    };
    let header = format!(
        "{}#{:06}  {:8}  {}{}{}{}",
        timestamp,
        message.index,
        if message.direction == Direction::ToServer {
            "→ SERVER"
        } else {
            "← CLIENT"
        },
        if message.blocked {
            "BLOCKED  "
        } else if packet.edited {
            "REPLACED  "
        } else {
            ""
        },
        additional,
        metadata,
        representation
    );
    let dump = inline_dump.then(|| logger_display::hex_dump(packet.bytes(), 128));
    let mut extra_representations = Vec::new();
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
                extra_representations.push(format!(
                    "{}: {}",
                    mode.name(),
                    logger_display::represent(packet.bytes(), mode, 1024)
                ));
            }
        }
    }
    let structure = if options.structure && !row.skipped {
        let (expression, known) = row.packet_expression.get_or_init(|| {
            let (expression, known) = gearth_rust::structure_prediction::expression_with_metadata(
                packet,
                message.direction,
                info,
                row.unity,
            )
            .unwrap_or_default();
            (bounded_log_prediction(expression), known)
        });
        (!expression.is_empty()).then(|| {
            format!(
                "{}: {expression}",
                if *known { "Structure" } else { "Predicted" }
            )
        })
    } else {
        None
    };
    RenderedLogRow {
        header,
        extra_representations,
        dump,
        structure,
    }
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
        writeln!(output, "{}", rendered.header)?;
        for representation in rendered.extra_representations {
            writeln!(output, "{representation}")?;
        }
        if let Some(dump) = rendered.dump {
            writeln!(output, "{dump}")?;
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
            logger_split: true,
            logger_names: true,
            logger_hashes: false,
            logger_message_id: false,
            logger_representation: PacketRepresentation::Expression,
            logger_extra_legacy: false,
            logger_extra_raw_hex: false,
            logger_extra_hex_dump: false,
            logger_skip_big: false,
            logger_timestamp: false,
            logger_autoscroll: true,
            logger_clear_on_connect: false,
            logger_clear_on_disconnect: false,
            logger_window: logger_display::LoggerWindow::default(),
            logger_connection_active: false,
            logger_antispam: AntiSpam::None,
            logger_filter: LoggerFilter::default(),
            logger_filtered: 0,
            packet_dump: None,
            expression: "{h:123}{i:42}{s:\"hello\"}".into(),
            direction: Direction::ToServer,
            injection_history: InjectionHistory::default(),
            schedule_draft: ScheduleDraft::default(),
            interval_ms: 500,
            align_schedule: true,
            schedule_offset_ms: 0,
            repeat: 1,
            repeat_forever: true,
            schedule_edit: None,
            active_schedule_edit: None,
            schedule_path: "gearth.sched".into(),
            scheduler: Scheduler::default(),
            scheduler_hotkeys: None,
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
            extension_processes: Vec::new(),
            extension_console: VecDeque::new(),
            hotel_version: String::new(),
            client_identifier: String::new(),
            packet_database: String::new(),
            packet_info: PacketInfoManager::default(),
            packet_safety: Arc::new(std::sync::Mutex::new(
                gearth_rust::packet_safety::PacketSafety::default(),
            )),
            developer_mode: false,
            developer_mode_confirmation: false,
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
            dark_mode: false,
            language: "en".into(),
            i18n: I18n::new("en"),
            notepad: String::new(),
            logs_bytes: 0,
            replacement_expression: String::new(),
            origins: false,
            nitro: false,
            unity: false,
            system_proxy: cfg!(windows),
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
        };
        if let Some(host) = &desktop.extension_host {
            if let Err(error) = host.set_packet_safety(desktop.packet_safety.clone()) {
                desktop.status = format!("Extension packet safety unavailable: {error}");
            }
        }
        desktop.load_settings();
        desktop
    }
}
impl Desktop {
    fn compile_schedules(
        &self,
        templates: &[ScheduleTemplate],
    ) -> gearth_rust::packet::Result<Vec<(ScheduleSpec, bool)>> {
        templates
            .iter()
            .map(|template| {
                expression::parse_with_format(
                    &template.expression,
                    self.packet_format(template.direction),
                    Some((template.direction, &self.packet_info)),
                )
                .map(|packet| {
                    (
                        ScheduleSpec {
                            packet,
                            source_expression: Some(template.expression.clone()),
                            direction: template.direction,
                            interval_ms: template.interval_ms,
                            offset_ms: template.offset_ms,
                            repeat: (template.repeat != 0).then_some(template.repeat),
                        },
                        template.paused,
                    )
                })
            })
            .collect()
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
        if let Some(task) = &self.certificate_task {
            match task.try_recv() {
                Ok(result) => {
                    self.status = result.unwrap_or_else(|e| e.to_string());
                    self.certificate_task = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.status = "Certificate operation stopped".into();
                    self.certificate_task = None;
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
                            self.status =
                                "Waiting for the official client; reconnect Habbo now".into();
                            self.update_rules();
                        }
                        Err(e) => self.status = format!("Attachment failed: {e}"),
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
                            self.packet_info = database;
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
        if let Some(events) = &self.extension_events {
            for event in events.try_iter().take(256) {
                let line = match event {
                    HostEvent::Console { id, text } => format!("#{id} {text}"),
                    HostEvent::Error { id, text } => format!("#{id} ERROR: {text}"),
                    HostEvent::Pending { id, info } => {
                        format!("#{id} {} is waiting for approval", info.title)
                    }
                    HostEvent::Connected { id, info } => format!("#{id} {} connected", info.title),
                    HostEvent::Disconnected(id) => format!("#{id} disconnected"),
                };
                if self.extension_console.len() == 512 {
                    self.extension_console.pop_front();
                }
                self.extension_console.push_back(line);
            }
        }
        self.extension_processes
            .retain_mut(|p| !matches!(p.try_wait(), Ok(Some(_))));
        if let Some(events) = &self.events {
            for event in events.try_iter().take(512) {
                match event {
                    Event::Status(status) => self.status = status,
                    Event::PacketIdentifiers(database) => {
                        self.packet_info = database;
                        invalidate_log_expressions(&mut self.logs);
                        self.logger_search_cache = None;
                    }
                    Event::Packet(message) => {
                        self.total += 1;
                        if !self.paused {
                            if self.logger_filter.suppress(&message, Instant::now()) {
                                self.logger_filtered = self.logger_filtered.saturating_add(1);
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
                        self.logger_connection_active = true;
                        self.logger_window.on_connect();
                        if self.logger_clear_on_connect {
                            clear_log_contents(
                                &mut self.logs,
                                &mut self.logs_bytes,
                                &mut self.logger_filtered,
                            );
                        }
                        self.status = format!("Connected to {a}");
                        if let Some(guard) = &mut self.proxy_guard {
                            match guard.restore() {
                                Ok(()) => self.proxy_guard = None,
                                Err(e) => {
                                    self.status =
                                        format!("Connected; proxy restoration failed: {e}")
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
                        self.logger_window.on_disconnect();
                        if self.logger_clear_on_disconnect {
                            clear_log_contents(
                                &mut self.logs,
                                &mut self.logs_bytes,
                                &mut self.logger_filtered,
                            );
                        }
                        self.status = "Client disconnected; listening".into();
                    }
                    Event::Error(e) => self.status = e,
                }
            }
        }
        if let Some(relay) = &self.relay {
            if relay.connected() {
                let mut blocked = None;
                let result: std::io::Result<()> = self.scheduler.dispatch_filtered_with_wall_clock(
                    Instant::now(),
                    SystemTime::now(),
                    |direction, packet| {
                        let allowed = self
                            .packet_safety
                            .lock()
                            .map_err(|_| std::io::Error::other("Packet safety state unavailable"))?
                            .may_send(
                                Some(&self.hotel_version),
                                direction,
                                packet.header(),
                                self.developer_mode,
                            );
                        if !allowed {
                            blocked.get_or_insert(packet.header());
                            return Ok(false);
                        }
                        relay.inject(direction, packet.clone())?;
                        Ok(true)
                    },
                );
                if let Err(e) = result {
                    self.status = e.to_string();
                } else if let Some(header) = blocked {
                    self.status = format!("Scheduled packet {header} was not sent: ID not observed for this hotel version and direction");
                }
            }
        }
    }
    fn connection(&mut self, ui: &mut egui::Ui) {
        ui.heading(self.i18n.text("tab.connection"));
        if ui
            .add_enabled(
                self.relay.is_none() && self.attachment_pending.is_none(),
                egui::Checkbox::new(&mut self.nitro, self.i18n.text("rust.connection.browser")),
            )
            .changed()
        {
            if self.nitro {
                self.origins = false;
            }
            self.update_rules();
        }
        if self.nitro {
            ui.add_enabled_ui(self.relay.is_none(), |ui| {
                egui::ComboBox::from_id_salt("browser-client")
                    .selected_text(if self.unity {
                        "Unity WebGL"
                    } else {
                        "Nitro / HTML5"
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.unity, false, "Nitro / HTML5");
                        ui.selectable_value(&mut self.unity, true, "Unity WebGL");
                    });
            });
            self.nitro_connection(ui);
            return;
        }
        ui.label(if self.origins {
            "Origins TCP · negotiated Bobba encryption"
        } else {
            "EVA_WIRE TCP relay"
        });
        if ui
            .add_enabled(
                self.relay.is_none() && self.attachment_pending.is_none(),
                egui::Checkbox::new(&mut self.origins, "Origins / Shockwave"),
            )
            .changed()
        {
            let known = gearth_rust::attachment::FLASH_HOTELS
                .contains(&self.attachment_host.as_str())
                || gearth_rust::attachment::ORIGINS_HOTELS.contains(&self.attachment_host.as_str());
            if known {
                self.attachment_host = if self.origins {
                    "game-od.habbo.com".into()
                } else {
                    "game-fr.habbo.com".into()
                };
            }
            self.update_rules();
        }
        egui::CollapsingHeader::new(self.i18n.text("rust.connection.attachment")).default_open(true).show(ui,|ui|{
            let hotels=if self.origins{gearth_rust::attachment::ORIGINS_HOTELS}else{gearth_rust::attachment::FLASH_HOTELS};
            egui::ComboBox::from_id_salt("attach-hotel").selected_text(&self.attachment_host).show_ui(ui,|ui|{for host in hotels{ui.selectable_value(&mut self.attachment_host,(*host).into(),*host);}});
            ui.text_edit_singleline(&mut self.attachment_host);
            ui.checkbox(&mut self.flash_auto,"Negotiate Flash encryption and discover client RC4 state (Windows)");
            ui.horizontal(|ui|{
                if ui.button(self.i18n.text("rust.connection.refresh")).clicked(){match gearth_platform::habbo_processes(){Ok(processes)=>self.client_processes=processes,Err(e)=>self.status=e.to_string()}}
                egui::ComboBox::from_id_salt("flash-process").selected_text(if self.flash_pid==0{self.i18n.text("rust.connection.automatic")}else{format!("PID {}",self.flash_pid)}).show_ui(ui,|ui|{ui.selectable_value(&mut self.flash_pid,0,self.i18n.text("rust.connection.automatic"));for p in &self.client_processes{ui.selectable_value(&mut self.flash_pid,p.pid,format!("{} - PID {}",p.executable,p.pid));}});
            });
            if ui.add_enabled(self.relay.is_none()&&self.attachment_pending.is_none(),egui::Button::new(self.i18n.text("rust.connection.attach"))).clicked(){
                let port=if self.origins{40001}else{30000};self.remote=format!("{}:{port}",self.attachment_host);self.flash_auto = !self.origins;
                match self.relay_options(){Ok(options)=>{let host=self.attachment_host.clone();let path=gearth_rust::attachment::HostsRedirect::system_path();let (send,receive)=std::sync::mpsc::channel();self.attachment_pending=Some(receive);self.status="Resolving hotel and preparing the local listener...".into();self.attachment_worker=Some(std::thread::spawn(move||{let _=send.send(gearth_rust::attachment::Attachment::start(&host,port,options,&path));}));},Err(e)=>self.status=e.to_string()}
            }
            ui.label("Enter a hotel hostname for hosts attachment or its IPv4 address for Raw IP. Both require administrator/root privileges; Raw IP is Flash-only and preconnects three direct upstream sockets.");
            if ui.add_enabled(self.relay.is_none()&&self.attachment_pending.is_none(),egui::Button::new("Recover redirects after closing other G-Earth Rust instances")).clicked(){self.status=match gearth_rust::attachment::HostsRedirect::recover_stale(&gearth_rust::attachment::HostsRedirect::system_path()){Ok(())=>"Owned redirects removed".into(),Err(e)=>e.to_string()};}
        });
        ui.add_space(12.0);
        egui::Grid::new("connection-grid")
            .spacing([18.0, 12.0])
            .show(ui, |ui| {
                ui.label(self.i18n.text("rust.connection.local"));
                ui.add_enabled(
                    self.relay.is_none(),
                    egui::TextEdit::singleline(&mut self.listen).desired_width(400.0),
                );
                ui.end_row();
                ui.label(self.i18n.text("rust.connection.remote"));
                ui.add_enabled(
                    self.relay.is_none(),
                    egui::TextEdit::singleline(&mut self.remote).desired_width(400.0),
                );
                ui.end_row();
            });
        egui::CollapsingHeader::new(self.i18n.text("rust.connection.options")).show(ui,|ui|{
            ui.checkbox(&mut self.socks_enabled, self.i18n.text("tab.extra.options.advanced.socks"));
            egui::Grid::new("connection-options").show(ui,|ui|{
                for (label,value) in [("Hotel version",&mut self.hotel_version),("Client identifier",&mut self.client_identifier),("Packet identifiers (.tsv / .json)",&mut self.packet_database),("SOCKS5 proxy",&mut self.socks_proxy),("SOCKS username",&mut self.socks_user)] {ui.label(label);ui.text_edit_singleline(value);ui.end_row();}
                ui.label("SOCKS password");ui.add(egui::TextEdit::singleline(&mut self.socks_password).password(true));ui.end_row();
                ui.label("Outgoing RC4 key (hex)");ui.add(egui::TextEdit::singleline(&mut self.outgoing_key).password(true));ui.end_row();
                ui.label("Incoming RC4 key (hex)");ui.add(egui::TextEdit::singleline(&mut self.incoming_key).password(true));ui.end_row();
            });
            ui.label("Leave keys blank for plaintext. Explicit keys apply from the first byte of the TCP stream.");
        });
        ui.add_space(14.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.relay.is_none() && self.packet_download.is_none(),
                    egui::Button::new("Load packet names from Sulek"),
                )
                .clicked()
            {
                let version = self.hotel_version.clone();
                let origins = self.origins;
                let (send, receive) = std::sync::mpsc::channel();
                self.packet_download = Some(receive);
                self.status = "Loading packet identifiers...".into();
                std::thread::spawn(move || {
                    let _ = send.send(PacketInfoManager::fetch_sulek(&version, origins));
                });
            }
            ui.label(format!(
                "{} packet identifiers",
                self.packet_info.entries().len()
            ));
        });
        if self.relay.is_none() && self.attachment_pending.is_none() {
            if ui
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
        } else if self.relay.is_some()
            && ui.button(self.i18n.text("rust.connection.stop")).clicked()
        {
            self.stop_connection();
        }
        ui.add_space(20.0);
        ui.group(|ui| {
            ui.label(self.i18n.text("rust.connection.test_client_hint"));
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
            clear_log_contents(
                &mut self.logs,
                &mut self.logs_bytes,
                &mut self.logger_filtered,
            );
        }
        self.logger_connection_active = false;
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
    fn start_unity(&mut self) -> std::io::Result<()> {
        if self.socks_enabled {
            return Err(std::io::Error::other("Unity upstream SOCKS5 routing is not ported yet; disable the SOCKS proxy before using a direct connection"));
        }
        self.prepare_certificate()?;
        if self.system_proxy
            && !gearth_platform::certificate_trusted(&self.public_certificate.as_ref().unwrap().1)?
        {
            return Err(std::io::Error::other(
                "Install the displayed public certificate before enabling the Windows proxy",
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
        let http = WebOptions::new(
            self.listen.parse().map_err(std::io::Error::other)?,
            self.identity_directory(),
        );
        let mut communicator = gearth_rust::unity_server::UnityOptions::new(
            "127.0.0.1:0".parse().unwrap(),
            self.identity_directory(),
        );
        communicator.extensions = self.extension_host.clone();
        communicator.packet_info = self.packet_info.clone();
        communicator.packet_safety = Some(self.packet_safety.clone());
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
        if self.socks_enabled {
            return Err(std::io::Error::other("Nitro upstream SOCKS5 support is not implemented; disable the SOCKS proxy to use a direct connection"));
        }
        self.prepare_certificate()?;
        self.hotel_version = NITRO_REVISION.into();
        self.client_identifier = "HTML5".into();
        self.load_packet_database()?;
        if self.system_proxy
            && !gearth_platform::certificate_trusted(&self.public_certificate.as_ref().unwrap().1)?
        {
            return Err(std::io::Error::other(
                "Install the displayed public certificate before enabling the Windows proxy",
            ));
        }
        let mut options = WebOptions::new(
            self.listen.parse().map_err(std::io::Error::other)?,
            self.identity_directory(),
        );
        options.packet_info = self.packet_info.clone();
        options.packet_safety = Some(self.packet_safety.clone());
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
        options.allow_city_helper = self.allow_city_helper;
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
            self.proxy_guard = Some(gearth_platform::SystemProxyGuard::activate(proxy.address)?);
        }
        self.status = format!(
            "Browser proxy listening on {}; reload the Nitro client",
            proxy.address
        );
        self.relay = Some(Connection::Web(proxy));
        self.events = Some(events);
        self.update_rules();
        Ok(())
    }
    fn nitro_connection(&mut self, ui: &mut egui::Ui) {
        ui.label(if self.unity {
            "Unity WebGL browser connection"
        } else {
            "Nitro browser connection"
        });
        ui.horizontal(|ui| {
            ui.label("Local address");
            ui.add_enabled(
                self.relay.is_none(),
                egui::TextEdit::singleline(&mut self.listen),
            );
        });
        ui.add_enabled(
            self.relay.is_none(),
            egui::Checkbox::new(
                &mut self.system_proxy,
                "Configure Windows browser proxy while waiting for the game",
            ),
        );
        ui.label("Start the proxy, then reload your hotel. The previous Windows proxy is restored when the game connects or when you stop.");
        if ui
            .add_enabled(
                self.relay.is_none(),
                egui::Button::new("Restore saved Windows proxy after an interrupted session"),
            )
            .clicked()
        {
            self.status = match gearth_platform::recover_system_proxy() {
                Ok(()) => "Saved proxy settings restored; later user changes preserved".into(),
                Err(e) => e.to_string(),
            };
        }
        if ui
            .add_enabled(
                self.relay.is_none() && self.certificate_task.is_none(),
                egui::Button::new("Prepare public certificate"),
            )
            .clicked()
        {
            self.status = match self.prepare_certificate() {
                Ok(()) => "Public certificate ready".into(),
                Err(e) => e.to_string(),
            };
        }
        if let Some((path, der)) = self.public_certificate.clone() {
            ui.label(format!("Public certificate: {}", path.display()));
            ui.label("Installing this certificate allows this local proxy to inspect HTTPS while it is running. Only the public certificate belongs in the Windows certificate store.");
            ui.horizontal(|ui| {
                let available = self.relay.is_none() && self.certificate_task.is_none();
                let action = if ui
                    .add_enabled(
                        available,
                        egui::Button::new("Install certificate for my Windows account"),
                    )
                    .clicked()
                {
                    Some(true)
                } else if ui
                    .add_enabled(
                        available,
                        egui::Button::new("Remove certificate from my Windows account"),
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
            ui.label(
                "Unity packet identifiers (.json / .tsv); leave blank to use beta-29 messages.json",
            );
            ui.add_enabled(
                self.relay.is_none(),
                egui::TextEdit::singleline(&mut self.packet_database),
            );
            ui.label("Reload the official WebGL client with the browser proxy enabled. Its framework, loader and WebAssembly hooks are patched for this session. Unsupported client layouts stop with a patch error.");
            ui.label("With automatic Windows setup disabled, configure your test browser to use the local address and trust the displayed public certificate.");
        } else {
            egui::CollapsingHeader::new("Nitro options").show(ui,|ui|{
            ui.label("Packet identifiers (.tsv / .json)");ui.text_edit_singleline(&mut self.packet_database);
            ui.label("Optional game WebSocket URLs (final * accepts a prefix), one per line. Otherwise the game is recognized by its first outgoing packet (4000).");ui.add(egui::TextEdit::multiline(&mut self.nitro_urls).desired_rows(3));
            ui.label("HabboCity key data file (optional Nitro Helper JSON response)");ui.text_edit_singleline(&mut self.city_key_path);
            ui.add_enabled(self.relay.is_none(),egui::Checkbox::new(&mut self.allow_city_helper,"For this session, allow sending HabboCity's crypto WASM file to https://nitro.sulek.dev/habbocity to obtain its protocol keys"));
            ui.label("With the Windows proxy disabled, configure your test browser to use the local address and trust the public certificate in that browser.");
        });
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        self.relay.is_none() && self.packet_download.is_none(),
                        egui::Button::new("Load Nitro packet identifiers"),
                    )
                    .clicked()
                {
                    let (send, receive) = std::sync::mpsc::channel();
                    self.packet_download = Some(receive);
                    self.status = "Loading Nitro packet identifiers...".into();
                    std::thread::spawn(move || {
                        let _ = send.send(PacketInfoManager::fetch_sulek(NITRO_REVISION, false));
                    });
                }
                ui.label(format!(
                    "{} packet identifiers",
                    self.packet_info.entries().len()
                ));
            });
        }
        if self.relay.is_none() {
            if ui
                .add_enabled(
                    self.certificate_task.is_none(),
                    egui::Button::new("Start browser proxy"),
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
        ui.heading(self.i18n.text("rust.logger.title"));
        if !self.logger_window.open
            && ui
                .button(self.i18n.text("rust.logger.open_panel"))
                .clicked()
        {
            self.logger_window.open = true;
        }
        if ui
            .checkbox(
                &mut self.logger_window.always_on_top,
                self.i18n.text("ext.logger.menu.window.alwaysontop"),
            )
            .changed()
        {
            ui.ctx().request_repaint_of(egui::ViewportId::ROOT);
        }
        ui.horizontal(|ui| {
            ui.checkbox(
                &mut self.outgoing,
                self.i18n.text("ext.logger.menu.view.outgoing"),
            );
            ui.checkbox(
                &mut self.incoming,
                self.i18n.text("ext.logger.menu.view.incoming"),
            );
            ui.checkbox(&mut self.paused, self.i18n.text("rust.logger.pause"));
            if ui
                .button(self.i18n.text("ext.logger.menu.view.cleartext"))
                .clicked()
            {
                clear_log_contents(
                    &mut self.logs,
                    &mut self.logs_bytes,
                    &mut self.logger_filtered,
                );
            }
        });
        ui.horizontal(|ui| {
            ui.label(self.i18n.text("rust.logger.filter"));
            ui.text_edit_singleline(&mut self.filter);
            ui.label(self.i18n.text("rust.logger.packet_limit"));
            ui.add(egui::DragValue::new(&mut self.packet_limit).range(0..=16 * 1024 * 1024));
        });
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(
                &mut self.logger_additional,
                self.i18n.text("rust.logger.additional"),
            );
            ui.checkbox(
                &mut self.logger_structure,
                self.i18n
                    .text("ext.logger.menu.packets.displaydetails.structure"),
            );
            ui.checkbox(&mut self.logger_split, self.i18n.text("rust.logger.split"));
            ui.checkbox(
                &mut self.logger_names,
                self.i18n
                    .text("ext.logger.menu.packets.displaydetails.message.name"),
            );
            ui.checkbox(
                &mut self.logger_hashes,
                self.i18n
                    .text("ext.logger.menu.packets.displaydetails.message.hash"),
            );
            ui.checkbox(
                &mut self.logger_message_id,
                self.i18n
                    .text("ext.logger.menu.packets.displaydetails.message.id"),
            );
            let old = self.logger_antispam;
            egui::ComboBox::from_id_salt("logger_antispam")
                .selected_text(format!(
                    "{}: {}",
                    self.i18n.text("ext.logger.menu.packets.antispam"),
                    self.i18n.text(old.translation_key())
                ))
                .show_ui(ui, |ui| {
                    for mode in [
                        AntiSpam::None,
                        AntiSpam::Low,
                        AntiSpam::Medium,
                        AntiSpam::High,
                        AntiSpam::Ultra,
                    ] {
                        ui.selectable_value(
                            &mut self.logger_antispam,
                            mode,
                            self.i18n.text(mode.translation_key()),
                        );
                    }
                });
            if old != self.logger_antispam {
                self.logger_filter.set_mode(self.logger_antispam);
            }
            ui.label(format!(
                "{}: {}",
                self.i18n.text("ext.logger.state.filtered"),
                self.logger_filtered
            ));
        });
        ui.horizontal(|ui| {
            ui.checkbox(
                &mut self.logger_timestamp,
                self.i18n
                    .text("ext.logger.menu.packets.displaydetails.timestamp"),
            );
            ui.checkbox(
                &mut self.logger_autoscroll,
                self.i18n.text("ext.logger.menu.view.autoscroll"),
            );
            egui::ComboBox::from_id_salt("logger_representation")
                .selected_text(format!(
                    "{}: {}",
                    self.i18n
                        .text("ext.logger.menu.packets.displaydetails.byterep"),
                    self.i18n.text(self.logger_representation.translation_key())
                ))
                .show_ui(ui, |ui| {
                    for mode in [
                        PacketRepresentation::Expression,
                        PacketRepresentation::Legacy,
                        PacketRepresentation::RawHex,
                        PacketRepresentation::HexDump,
                    ] {
                        ui.selectable_value(
                            &mut self.logger_representation,
                            mode,
                            self.i18n.text(mode.translation_key()),
                        );
                    }
                });
        });
        ui.horizontal_wrapped(|ui| {
            ui.label(self.i18n.text("rust.logger.extra"));
            ui.checkbox(
                &mut self.logger_skip_big,
                self.i18n.text("ext.logger.menu.packets.skipbig"),
            );
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
        });
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(
                &mut self.logger_window.open_on_connect,
                format!(
                    "{}: {}",
                    self.i18n.text("ext.logger.menu.window.onconnect"),
                    self.i18n
                        .text("ext.logger.menu.window.onconnect.openwindow")
                ),
            );
            ui.checkbox(
                &mut self.logger_window.hide_on_disconnect,
                format!(
                    "{}: {}",
                    self.i18n.text("ext.logger.menu.window.ondisconnect"),
                    self.i18n
                        .text("ext.logger.menu.window.ondisconnect.hidewindow")
                ),
            );
            ui.checkbox(
                &mut self.logger_clear_on_connect,
                format!(
                    "{}: {}",
                    self.i18n.text("ext.logger.menu.window.onconnect"),
                    self.i18n.text("ext.logger.menu.window.onconnect.reset")
                ),
            );
            ui.checkbox(
                &mut self.logger_clear_on_disconnect,
                format!(
                    "{}: {}",
                    self.i18n.text("ext.logger.menu.window.ondisconnect"),
                    self.i18n.text("ext.logger.menu.window.ondisconnect.reset")
                ),
            );
        });
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
        let skipped_label = format!("<{}>", self.i18n.text("ext.logger.element.skipped"));
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
            structure: self.logger_structure,
        };
        ui.horizontal(|ui| {
            ui.label(self.i18n.text("rust.logger.export_path"));
            ui.text_edit_singleline(&mut self.export_path);
            if ui.button(self.i18n.text("rust.logger.export")).clicked() {
                let visible = self.logs.iter().filter(|row| {
                    log_row_matches(
                        row,
                        &filter,
                        matching_metadata,
                        self.outgoing,
                        self.incoming,
                    )
                });
                let result = logger_display::write_atomic(Path::new(&self.export_path), |file| {
                    write_log_capture(
                        std::io::BufWriter::new(file),
                        visible,
                        &self.packet_info,
                        display_options,
                        self.logger_split,
                    )
                });
                self.status = match result {
                    Ok(()) => format!("Capture saved to {}", self.export_path),
                    Err(e) => e.to_string(),
                };
            }
        });
        ui.separator();
        let filtered: Vec<_> = self
            .logs
            .iter()
            .filter(|row| {
                log_row_matches(
                    row,
                    &filter,
                    matching_metadata,
                    self.outgoing,
                    self.incoming,
                )
            })
            .collect();
        let extra_lines = usize::from(
            self.logger_extra_legacy && self.logger_representation != PacketRepresentation::Legacy,
        ) + usize::from(
            self.logger_extra_raw_hex && self.logger_representation != PacketRepresentation::RawHex,
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
            * (ui.text_style_height(&egui::TextStyle::Monospace) + ui.spacing().item_spacing.y);
        let mut inspection = None;
        egui::ScrollArea::vertical()
            .stick_to_bottom(self.logger_autoscroll)
            .show_rows(ui, row_height, filtered.len(), |ui, range| {
                for i in range {
                    let row = filtered[i];
                    let m = &row.message;
                    let (color, hex_color, marker_color) =
                        log_colors(m.direction, ui.visuals().dark_mode);
                    let marker = if m.blocked {
                        Some("BLOCKED")
                    } else if m.packet.edited {
                        Some("REPLACED")
                    } else {
                        None
                    };
                    let rendered = render_log_row(row, &self.packet_info, display_options);
                    let row_output = ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), row_height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            let response = ui.add(
                                egui::Label::new(log_header_layout(
                                    &rendered.header,
                                    marker,
                                    color,
                                    marker_color,
                                    ui.text_style_height(&egui::TextStyle::Monospace),
                                ))
                                .truncate()
                                .sense(egui::Sense::click()),
                            );
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
                    let response = row_output.inner;
                    response.context_menu(|ui| {
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
                        if ui.button("Inspect packet bytes").clicked() {
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
                                gearth_rust::structure_prediction::predict(&m.packet, row.unity)
                                    .unwrap_or_else(|_| "unavailable".into()),
                            )
                        });
                        response
                            .clone()
                            .on_hover_text(format!("Predicted structure: {structure}"));
                    }
                    if response.clicked() && !row.skipped {
                        self.expression = row.expression.clone();
                        self.direction = m.direction;
                        self.tab = Tab::Injection;
                    }
                }
            });
        if let Some(dump) = inspection {
            self.packet_dump = Some(dump);
        }
        let mut open = self.packet_dump.is_some();
        if let Some(dump) = &self.packet_dump {
            egui::Window::new("Packet bytes")
                .open(&mut open)
                .resizable(true)
                .default_width(720.0)
                .show(ui.ctx(), |ui| {
                    if ui.button("Copy hex dump").clicked() {
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
    }
    fn editor(&mut self, ui: &mut egui::Ui, allow_batch: bool) {
        let (draft, direction) = if allow_batch {
            (&mut self.expression, &mut self.direction)
        } else {
            (
                &mut self.schedule_draft.expression,
                &mut self.schedule_draft.direction,
            )
        };
        direction_selector(ui, direction, &self.i18n);
        ui.add(
            egui::TextEdit::multiline(draft)
                .font(egui::TextStyle::Monospace)
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
        let (draft, direction) = if allow_batch {
            (&self.expression, self.direction)
        } else {
            (
                &self.schedule_draft.expression,
                self.schedule_draft.direction,
            )
        };
        if draft.len() > 64 * 1024 {
            ui.label("Preview disabled for large input; it will be validated when submitted.");
            return;
        }
        let parsed = if allow_batch {
            injection::parse_packets(
                draft,
                self.packet_format(direction),
                direction,
                &self.packet_info,
            )
        } else {
            expression::parse_with_format(
                draft,
                self.packet_format(direction),
                Some((direction, &self.packet_info)),
            )
            .map(|packet| vec![packet])
        };
        match parsed {
            Ok(packets) if packets.len() == 1 => {
                let p = &packets[0];
                ui.label(format!("Header {} · {} bytes", p.header(), p.bytes().len()));
                ui.monospace(packet_tools::hex_preview(p, 1024));
            }
            Ok(packets) => {
                ui.label(format!("{} packets ready", packets.len()));
            }
            Err(e) => {
                ui.colored_label(egui::Color32::from_rgb(180, 60, 60), e.to_string());
            }
        }
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
                self.i18n.text("tab.extra.options.developmode"),
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
        ui.heading(self.i18n.text("tab.injection"));
        self.developer_mode_control(ui);
        self.editor(ui, true);
        // Large inputs are checked on submission to keep the editor responsive.
        let (server_valid, client_valid) = if self.expression.len() <= 64 * 1024 {
            let validate = |direction| {
                injection::parse_packets(
                    &self.expression,
                    self.packet_format(direction),
                    direction,
                    &self.packet_info,
                )
                .is_ok_and(|packets| {
                    self.packet_safety.lock().is_ok_and(|safety| {
                        injection::first_unsafe_packet(
                            &packets,
                            direction,
                            Some(&self.hotel_version),
                            &safety,
                            self.developer_mode,
                        )
                        .is_none()
                    })
                })
            };
            (validate(Direction::ToServer), validate(Direction::ToClient))
        } else {
            (true, true)
        };
        ui.horizontal(|ui| {
            let connected = self.relay.as_ref().is_some_and(Connection::connected);
            if ui
                .add_enabled(
                    connected && server_valid,
                    egui::Button::new(self.i18n.text("tab.injection.send.toserver")),
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
                    egui::Button::new(self.i18n.text("tab.injection.send.toclient")),
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
        ui.horizontal(|ui| {
            ui.label(self.i18n.text("tab.injection.history"));
            if ui
                .button(self.i18n.text("tab.injection.history.clear"))
                .clicked()
            {
                self.injection_history.clear();
                self.status = match self.injection_history.save_to_settings(&self.settings_path) {
                    Ok(()) => "Injection history cleared".into(),
                    Err(error) => format!("History cleared in memory; could not save: {error}"),
                };
            }
        });
        egui::ScrollArea::vertical()
            .id_salt("injection_history")
            .max_height(120.0)
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
                    if ui
                        .add(
                            egui::Label::new(label)
                                .truncate()
                                .sense(egui::Sense::click()),
                        )
                        .double_clicked()
                    {
                        self.expression = entry.expression.clone();
                        if let Ok(direction) = Direction::parse(&entry.direction) {
                            self.direction = direction;
                        }
                    }
                }
            });
        ui.add_space(20.0);
        ui.separator();
        ui.heading(self.i18n.text("rust.rule.title"));
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
                            self.status = "Rule updated; save settings to keep it".into();
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
                changed |= ui
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
        }
        if let Some((from, to)) = move_rule {
            if let Err(error) = self.settings.move_saved_rule(from, to) {
                self.status = error.to_string();
            } else {
                changed = true;
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
        self.repeat_forever = true;
        self.repeat = 1;
    }
    fn schedule(&mut self, ui: &mut egui::Ui) {
        ui.heading(self.i18n.text("tab.scheduler"));
        let mut enabled = self.scheduler_hotkeys.is_some();
        if ui
            .add_enabled(
                cfg!(windows),
                egui::Checkbox::new(&mut enabled, self.i18n.text("tab.scheduler.hotkeys")),
            )
            .changed()
        {
            if enabled {
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
        self.editor(ui, false);
        ui.horizontal(|ui| {
            ui.add(
                egui::DragValue::new(&mut self.interval_ms)
                    .range(1..=86_400_000)
                    .prefix(format!(
                        "{} (ms) ",
                        self.i18n.text("tab.scheduler.setup.interval")
                    )),
            );
            ui.add(
                egui::DragValue::new(&mut self.repeat)
                    .range(1..=1_000_000)
                    .prefix(format!("{} ", self.i18n.text("rust.scheduler.count"))),
            );
            ui.checkbox(
                &mut self.repeat_forever,
                self.i18n.text("rust.scheduler.forever"),
            );
        });
        ui.horizontal(|ui| {
            ui.checkbox(
                &mut self.align_schedule,
                self.i18n.text("rust.scheduler.align"),
            );
            ui.add_enabled(
                self.align_schedule,
                egui::DragValue::new(&mut self.schedule_offset_ms)
                    .range(0..=self.interval_ms.saturating_sub(1))
                    .prefix(format!("{} ", self.i18n.text("rust.scheduler.offset"))),
            );
        });
        let editing = self.schedule_edit.is_some() || self.active_schedule_edit.is_some();
        if ui
            .add_enabled(
                editing || self.relay.as_ref().is_some_and(Connection::connected),
                egui::Button::new(self.i18n.text(if self.active_schedule_edit.is_some() {
                    "rust.scheduler.active_save"
                } else if editing {
                    "rust.scheduler.template_save"
                } else {
                    "rust.scheduler.add"
                })),
            )
            .clicked()
        {
            let mut reset_active_editor = false;
            let valid_offset = !self.align_schedule || self.schedule_offset_ms < self.interval_ms;
            let parsed = expression::parse_with_format(
                &self.schedule_draft.expression,
                self.packet_format(self.schedule_draft.direction),
                Some((self.schedule_draft.direction, &self.packet_info)),
            );
            if !valid_offset {
                self.status = "Offset must be smaller than the interval".into();
            } else {
                self.status = match parsed.and_then(|packet| {
                    if let Some(id) = self.active_schedule_edit {
                        self.scheduler.update_configured(
                            id,
                            ScheduleSpec {
                                packet,
                                source_expression: Some(self.schedule_draft.expression.clone()),
                                direction: self.schedule_draft.direction,
                                interval_ms: self.interval_ms,
                                offset_ms: self.align_schedule.then_some(self.schedule_offset_ms),
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
                            self.align_schedule.then_some(self.schedule_offset_ms),
                            (!self.repeat_forever).then_some(self.repeat),
                            (Instant::now(), SystemTime::now()),
                        )?;
                        self.scheduler
                            .jobs
                            .last_mut()
                            .expect("newly added schedule")
                            .source_expression = Some(self.schedule_draft.expression.clone());
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
                                offset_ms: self.align_schedule.then_some(self.schedule_offset_ms),
                                paused: self
                                    .schedule_edit
                                    .and_then(|i| self.settings.schedules.get(i))
                                    .is_some_and(|old| old.paused),
                                repeat: if self.repeat_forever { 0 } else { self.repeat },
                            };
                            if let Some(index) = self.schedule_edit.take() {
                                if let Some(existing) = self.settings.schedules.get_mut(index) {
                                    *existing = template;
                                    "Template updated; active schedules are unchanged".into()
                                } else {
                                    "Template no longer exists".into()
                                }
                            } else {
                                self.settings.schedules.push(template);
                                "Schedule added".into()
                            }
                        }
                    }
                    Err(e) => e.to_string(),
                };
            }
            if reset_active_editor {
                self.reset_active_schedule_editor();
            }
        }
        if editing
            && ui
                .button(self.i18n.text("rust.scheduler.cancel_edit"))
                .clicked()
        {
            let reset_active_editor = self.active_schedule_edit.is_some();
            self.schedule_edit = None;
            self.active_schedule_edit = None;
            if reset_active_editor {
                self.reset_active_schedule_editor();
            }
        }
        if ui
            .button(self.i18n.text("rust.scheduler.cancel_all"))
            .clicked()
        {
            self.scheduler.jobs.clear();
            if self.active_schedule_edit.take().is_some() {
                self.reset_active_schedule_editor();
            }
        }
        ui.label(format!("{} active schedules", self.scheduler.jobs.len()));
        if ui
            .add_enabled(
                self.relay.as_ref().is_some_and(Connection::connected),
                egui::Button::new(self.i18n.text("rust.scheduler.run_saved")),
            )
            .clicked()
        {
            let specs = self.compile_schedules(&self.settings.schedules);
            self.status = match specs.and_then(|specs| {
                self.scheduler
                    .add_batch_configured(specs, (Instant::now(), SystemTime::now()))
            }) {
                Ok(()) => "Saved schedules started".into(),
                Err(e) => format!("No saved schedules started: {e}"),
            };
        }
        if ui
            .button(self.i18n.text("rust.scheduler.clear_saved"))
            .clicked()
        {
            self.settings.schedules.clear();
            self.schedule_edit = None;
        }
        ui.horizontal(|ui| {
            ui.label(".sched file");
            ui.text_edit_singleline(&mut self.schedule_path);
            if ui.button("Import").clicked() {
                let result = self.read_schedule_file();
                self.status = match result {
                    Ok(templates) => {
                        let count = templates.len();
                        self.settings.schedules = templates;
                        self.schedule_edit = None;
                        format!("Imported {count} templates; save settings to keep them")
                    }
                    Err(error) => format!("Import failed: {error}"),
                };
            }
            if ui
                .add_enabled(
                    self.relay.as_ref().is_some_and(Connection::connected),
                    egui::Button::new("Load and replace active"),
                )
                .on_hover_text(
                    "Replace active schedules with the .sched file; an empty file clears them",
                )
                .clicked()
            {
                let result = self.read_schedule_file().and_then(|templates| {
                    let specs = self
                        .compile_schedules(&templates)
                        .map_err(std::io::Error::other)?;
                    self.scheduler
                        .replace_batch_configured(specs, (Instant::now(), SystemTime::now()))
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
                            "Loaded {count} active schedules from {}",
                            self.schedule_path
                        )
                    }
                    Err(error) => format!("Load failed; active schedules unchanged: {error}"),
                };
            }
            if ui.button("Export templates").clicked() {
                self.status =
                    match schedule_file::format(&self.settings.schedules).and_then(|text| {
                        schedule_file::write_atomic(Path::new(&self.schedule_path), &text)
                    }) {
                        Ok(()) => format!("Exported templates to {}", self.schedule_path),
                        Err(error) => format!("Export failed: {error}"),
                    };
            }
            if ui
                .button("Export active")
                .on_hover_text("Export active, indefinitely repeating clock-aligned schedules")
                .clicked()
            {
                self.status =
                    match schedule_file::format_active(&self.scheduler.jobs).and_then(|text| {
                        schedule_file::write_atomic(Path::new(&self.schedule_path), &text)
                    }) {
                        Ok(()) => format!(
                            "Exported {} active schedules to {}",
                            self.scheduler.jobs.len(),
                            self.schedule_path
                        ),
                        Err(error) => format!("Export failed: {error}"),
                    };
            }
        });
        if !self.settings.schedules.is_empty() {
            ui.label("Saved templates (save settings to keep changes)");
        }
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
                ui.checkbox(
                    &mut template.paused,
                    self.i18n.text("rust.scheduler.paused_start"),
                );
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
            self.repeat_forever = template.repeat == 0;
            self.repeat = template.repeat.max(1);
            self.schedule_edit = Some(index);
            self.active_schedule_edit = None;
        }
        if let Some(index) = remove_template {
            self.settings.schedules.remove(index);
            self.schedule_edit = match self.schedule_edit {
                Some(editing) if editing == index => None,
                Some(editing) if editing > index => Some(editing - 1),
                other => other,
            };
        }
        let mut remove = None;
        let mut pause_change = None;
        let mut edit_active = None;
        for (i, job) in self.scheduler.jobs.iter().enumerate() {
            ui.horizontal(|ui| {
                if ui
                    .small_button(self.i18n.text(if job.paused {
                        "rust.scheduler.resume"
                    } else {
                        "rust.scheduler.pause"
                    }))
                    .clicked()
                {
                    pause_change = Some((i, !job.paused));
                }
                if ui
                    .small_button(self.i18n.text("rust.action.remove"))
                    .clicked()
                {
                    remove = Some(i);
                }
                if ui
                    .small_button(self.i18n.text("rust.action.edit"))
                    .clicked()
                {
                    edit_active = Some(job.id);
                }
                let remaining = job
                    .remaining
                    .map_or_else(|| "until cancelled".to_owned(), |n| n.to_string());
                ui.monospace(format!(
                    "{}: {} header {} every {} ms{} - remaining {}",
                    i + 1,
                    job.direction.name(),
                    job.packet.header(),
                    job.interval.as_millis(),
                    job.alignment_offset_ms
                        .map_or_else(String::new, |offset| format!(" + {offset} ms")),
                    remaining
                ));
                if i < 10 {
                    if let Some(hotkeys) = &self.scheduler_hotkeys {
                        ui.label(if hotkeys.available()[i] {
                            format!("Ctrl+Shift+{i}")
                        } else {
                            format!("Ctrl+Shift+{i} unavailable")
                        });
                    }
                }
            });
        }
        if let Some((i, paused)) = pause_change {
            if let Err(error) = self.scheduler.set_paused(i, paused, Instant::now()) {
                self.status = error.to_string();
            }
        }
        if let Some(id) = edit_active {
            if let Some(job) = self.scheduler.jobs.iter().find(|job| job.id == id) {
                self.schedule_draft.expression = job
                    .source_expression
                    .clone()
                    .unwrap_or_else(|| expression::to_lossless_expression(&job.packet));
                self.schedule_draft.direction = job.direction;
                self.interval_ms = job.interval.as_millis() as u64;
                self.align_schedule = job.alignment_offset_ms.is_some();
                self.schedule_offset_ms = job.alignment_offset_ms.unwrap_or(0);
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
    }

    fn extra(&mut self, ui: &mut egui::Ui) {
        ui.heading(self.i18n.text("tab.extra"));
        if ui
            .checkbox(
                &mut self.always_on_top,
                self.i18n.text("tab.extra.options.alwaysontop"),
            )
            .changed()
        {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::WindowLevel(if self.always_on_top {
                    egui::WindowLevel::AlwaysOnTop
                } else {
                    egui::WindowLevel::Normal
                }));
        }
        self.developer_mode_control(ui);
        ui.separator();
        ui.label(self.i18n.text("tab.extra.notepad"));
        ui.add(
            egui::TextEdit::multiline(&mut self.notepad)
                .desired_rows(12)
                .desired_width(f32::INFINITY),
        );
    }
    fn tools(&mut self, ui: &mut egui::Ui) {
        ui.heading(self.i18n.text("tab.tools"));
        ui.horizontal(|ui| {
            ui.label(self.i18n.text("tab.tools.type.integer"));
            let decoded =
                ui.add(egui::TextEdit::singleline(&mut self.tool_int).desired_width(110.0));
            let encoded_value = packet_tools::encode_i32(&self.tool_int).ok();
            let encode = ui
                .add_enabled(
                    encoded_value.is_some(),
                    egui::Button::new(self.i18n.text("tab.tools.button.encode")),
                )
                .clicked()
                || (decoded.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)));
            if encode {
                if let Some(value) = encoded_value {
                    self.tool_int_encoded = value;
                }
            }
            let decoded_value = packet_tools::decode_i32(&self.tool_int_encoded).ok();
            let decode = ui
                .add_enabled(
                    decoded_value.is_some(),
                    egui::Button::new(self.i18n.text("tab.tools.button.decode")),
                )
                .clicked();
            let encoded =
                ui.add(egui::TextEdit::singleline(&mut self.tool_int_encoded).desired_width(240.0));
            if decode
                || (encoded.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)))
            {
                if let Ok(value) = packet_tools::decode_i32(&self.tool_int_encoded) {
                    self.tool_int = value.to_string();
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label(self.i18n.text("tab.tools.type.ushort"));
            let decoded =
                ui.add(egui::TextEdit::singleline(&mut self.tool_ushort).desired_width(110.0));
            let encoded_value = packet_tools::encode_u16(&self.tool_ushort).ok();
            let encode = ui
                .add_enabled(
                    encoded_value.is_some(),
                    egui::Button::new(self.i18n.text("tab.tools.button.encode")),
                )
                .clicked()
                || (decoded.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)));
            if encode {
                if let Some(value) = encoded_value {
                    self.tool_ushort_encoded = value;
                }
            }
            let decoded_value = packet_tools::decode_u16(&self.tool_ushort_encoded).ok();
            let decode = ui
                .add_enabled(
                    decoded_value.is_some(),
                    egui::Button::new(self.i18n.text("tab.tools.button.decode")),
                )
                .clicked();
            let encoded = ui.add(
                egui::TextEdit::singleline(&mut self.tool_ushort_encoded).desired_width(240.0),
            );
            if decode
                || (encoded.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)))
            {
                if let Ok(value) = packet_tools::decode_u16(&self.tool_ushort_encoded) {
                    self.tool_ushort = value.to_string();
                }
            }
        });
        ui.separator();
        direction_selector(ui, &mut self.direction, &self.i18n);
        ui.label(format!(
            "Packet format: {:?}",
            self.packet_format(self.direction)
        ));
        ui.add(
            egui::TextEdit::multiline(&mut self.tool_input)
                .desired_rows(5)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );
        ui.horizontal(|ui| {
            if ui.button("Expression → wire hex").clicked() {
                self.tool_output = packet_tools::expression_to_hex(
                    &self.tool_input,
                    self.packet_format(self.direction),
                    self.direction,
                    &self.packet_info,
                )
                .unwrap_or_else(|e| e.to_string());
            }
            if ui.button("Wire hex → lossless expression").clicked() {
                self.tool_output = packet_tools::hex_to_expression(
                    &self.tool_input,
                    self.packet_format(self.direction),
                )
                .unwrap_or_else(|e| e.to_string());
            }
        });
        ui.horizontal(|ui| {
            if ui.button("Expression -> G-Earth packet").clicked() {
                self.tool_output = packet_tools::expression_to_wire(
                    &self.tool_input,
                    self.packet_format(self.direction),
                    self.direction,
                    &self.packet_info,
                )
                .unwrap_or_else(|error| error.to_string());
            }
            if ui.button("G-Earth packet -> expression").clicked() {
                match packet_tools::wire_to_expression(
                    &self.tool_input,
                    self.packet_format(self.direction),
                    self.direction,
                    &self.packet_info,
                    self.nitro && self.unity,
                ) {
                    Ok((output, structured)) => {
                        self.tool_output = output;
                        self.status = if structured {
                            "Packet converted to a verified expression".into()
                        } else {
                            "Structure unavailable; kept the original packet bytes".into()
                        };
                    }
                    Err(error) => self.status = error.to_string(),
                }
            }
        });
        ui.add(
            egui::TextEdit::multiline(&mut self.tool_output)
                .desired_rows(5)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );
        if ui.button("Copy output").clicked() {
            ui.ctx().copy_text(self.tool_output.clone());
        }
        if ui.button("Use output as input").clicked() {
            self.tool_input.clone_from(&self.tool_output);
        }
        ui.separator();
        ui.label(self.i18n.text("tab.extra.notepad"));
        ui.add(
            egui::TextEdit::multiline(&mut self.notepad)
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
        ui.horizontal(|ui| {
            ui.label("Import original Cache/cache.json");
            ui.text_edit_singleline(&mut self.legacy_cache_path);
            if ui.button("Import").clicked() {
                let result = std::fs::read(&self.legacy_cache_path)
                    .and_then(|bytes| serde_json::from_slice(&bytes).map_err(std::io::Error::other))
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
        ui.label(format!("Settings: {}", self.settings_path.display()));
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
        ctx.set_visuals(if self.dark_mode {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        });
        self.poll();
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            if self.developer_mode_confirmation {
                ui.disable();
            }
            ui.horizontal(|ui| {
                ui.strong("G-Earth Rust");
                ui.label("0.1.0 · development");
                if ui.button(self.i18n.text("rust.settings.save")).clicked() {
                    self.save_settings();
                }
                if ui.button(self.i18n.text("rust.settings.reload")).clicked() {
                    self.load_settings();
                }
                ui.checkbox(&mut self.dark_mode, self.i18n.text("rust.settings.dark"));
                let before = self.language.clone();
                egui::ComboBox::from_id_salt("language")
                    .selected_text(&self.language)
                    .show_ui(ui, |ui| {
                        for (code, name) in LANGUAGES {
                            ui.selectable_value(&mut self.language, (*code).into(), *name);
                        }
                    });
                if before != self.language {
                    self.i18n = I18n::new(&self.language);
                    if let Some(host) = &self.extension_host {
                        if let Err(e) = host.set_language(&self.language) {
                            self.status = e.to_string();
                        }
                    }
                }
            });
            ui.horizontal_wrapped(|ui| {
                for (tab, name) in [
                    (Tab::Connection, "tab.connection"),
                    (Tab::Logger, "rust.logger.tab"),
                    (Tab::Injection, "tab.injection"),
                    (Tab::Scheduler, "tab.scheduler"),
                    (Tab::Tools, "tab.tools"),
                    (Tab::Extensions, "tab.extensions"),
                    (Tab::Extra, "tab.extra"),
                    (Tab::Info, "tab.info"),
                ] {
                    let label = if name.starts_with("tab.") || name.starts_with("rust.") {
                        self.i18n.text(name)
                    } else {
                        name.to_owned()
                    };
                    ui.selectable_value(&mut self.tab, tab, label);
                }
                if ui
                    .checkbox(
                        &mut self.always_on_top,
                        self.i18n.text("tab.extra.options.alwaysontop"),
                    )
                    .changed()
                {
                    ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(
                        if self.always_on_top {
                            egui::WindowLevel::AlwaysOnTop
                        } else {
                            egui::WindowLevel::Normal
                        },
                    ));
                }
            });
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status);
                ui.separator();
                ui.label(format!(
                    "{} observed · {} retained · {} evicted",
                    self.total,
                    self.logs.len(),
                    self.display_dropped
                ));
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.developer_mode_confirmation {
                ui.disable();
            }
            match self.tab {
                Tab::Connection => self.connection(ui),
                Tab::Logger if self.logger_window.open => {
                    ui.label(self.i18n.text("rust.logger.panel_open"));
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
                    ui.heading("G-Earth Rust");
                    ui.label("Rust port in progress, based on G-Realm/G-Earth 1.5.4-beta-29.");
                    ui.hyperlink_to(
                        "Original project · sirjonasxx & contributors",
                        "https://github.com/G-Realm/G-Earth",
                    );
                    ui.hyperlink_to(
                        "Rust project · 1desirable1337",
                        "https://github.com/Tear1338/G-Earth-Rust",
                    );
                    ui.label(
                    "MIT licensed. Read docs/PARITY.md for implemented and missing functionality.",
                );
                    ui.label(
                    "Performance improvements have not been measured against the Java application.",
                );
                }
            }
        });
        if self.logger_window.open {
            let mut open = true;
            let title = self.i18n.text("rust.logger.title");
            let previous_tab = self.tab;
            let level = if self.logger_window.always_on_top {
                egui::WindowLevel::AlwaysOnTop
            } else {
                egui::WindowLevel::Normal
            };
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("logger_window"),
                egui::ViewportBuilder::default()
                    .with_title(&title)
                    .with_window_level(level)
                    .with_inner_size([850.0, 600.0])
                    .with_min_inner_size([480.0, 320.0]),
                |logger_ctx, class| {
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
        self.developer_mode_dialog(ctx);
        if self.relay.is_some()
            || self.attachment_pending.is_some()
            || self.extension_host.is_some()
            || self.python_console.is_pending()
            || self.scheduler_hotkeys.is_some()
        {
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
        self.editing_saved_rule = None;
        self.python_console.restore_settings(&self.settings);
        self.injection_history =
            InjectionHistory::from_json(self.settings.get("injection_history"));
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
        self.logger_split = self
            .settings
            .booleans
            .get("logger_split")
            .copied()
            .unwrap_or(true);
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
        self.developer_mode = self
            .settings
            .booleans
            .get("developer_mode")
            .copied()
            .unwrap_or(false);
        self.developer_mode_confirmation = false;
        if let Ok(mut safety) = self.packet_safety.lock() {
            safety.set_developer_mode(self.developer_mode);
        }
        for (key, target) in [
            ("listen", &mut self.listen),
            ("remote", &mut self.remote),
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
        if self.nitro {
            self.origins = false;
        }
        self.dark_mode = self
            .settings
            .booleans
            .get("dark_mode")
            .copied()
            .unwrap_or(false);
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
        }
        self.update_rules();
    }
    fn save_settings(&mut self) {
        self.python_console.save_settings(&mut self.settings);
        self.settings
            .values
            .insert("injection_history".into(), self.injection_history.to_json());
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
        for (key, value) in [
            ("listen", &self.listen),
            ("remote", &self.remote),
            ("hotel_version", &self.hotel_version),
            ("client_identifier", &self.client_identifier),
            ("packet_database", &self.packet_database),
            ("socks_proxy", &self.socks_proxy),
            ("socks_user", &self.socks_user),
            ("extension_runtime", &self.extension_runtime),
            ("notepad", &self.notepad),
            ("language", &self.language),
        ] {
            self.settings.values.insert(key.into(), value.clone());
        }
        self.settings.booleans.extend([
            ("socks_enabled".into(), self.socks_enabled),
            ("origins".into(), self.origins),
            ("nitro".into(), self.nitro),
            ("unity".into(), self.unity),
            ("dark_mode".into(), self.dark_mode),
            ("outgoing".into(), self.outgoing),
            ("incoming".into(), self.incoming),
            ("logger_additional".into(), self.logger_additional),
            ("logger_structure".into(), self.logger_structure),
            ("logger_split".into(), self.logger_split),
            ("logger_names".into(), self.logger_names),
            ("logger_hashes".into(), self.logger_hashes),
            ("logger_message_id".into(), self.logger_message_id),
            ("developer_mode".into(), self.developer_mode),
            ("logger_extra_legacy".into(), self.logger_extra_legacy),
            ("logger_extra_raw_hex".into(), self.logger_extra_raw_hex),
            ("logger_extra_hex_dump".into(), self.logger_extra_hex_dump),
            ("logger_skip_big".into(), self.logger_skip_big),
            ("logger_timestamp".into(), self.logger_timestamp),
            ("logger_autoscroll".into(), self.logger_autoscroll),
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
        ]);
        match self.settings.save(&self.settings_path) {
            Ok(()) => {
                self.settings_loaded = true;
                self.status = "Settings saved".into();
            }
            Err(e) => self.status = e.to_string(),
        }
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
        invalidate_log_expressions(&mut self.logs);
        self.logger_search_cache = None;
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
            flash_process: if self.flash_auto && !self.origins {
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
            extensions: self.extension_host.clone(),
            connection: Some(connection),
            socks: if !self.socks_enabled {
                None
            } else {
                if self.socks_proxy.trim().is_empty() {
                    return Err(std::io::Error::other(
                        "SOCKS5 proxy address is required when enabled",
                    ));
                }
                Some(SocksConfig {
                    proxy: self.socks_proxy.clone(),
                    credentials: if self.socks_user.is_empty() {
                        None
                    } else {
                        Some((self.socks_user.clone(), self.socks_password.clone()))
                    },
                })
            },
            outgoing_rc4: cipher(&self.outgoing_key)?,
            incoming_rc4: cipher(&self.incoming_key)?,
        })
    }
    fn extensions(&mut self, ui: &mut egui::Ui) {
        self.python_console
            .show(ui, self.extension_host.as_ref(), &mut self.status);
        self.store.show(
            ui,
            self.extension_host.as_ref(),
            Path::new(&self.extension_runtime),
            &mut self.status,
            &mut self.extension_processes,
        );
        ui.heading(self.i18n.text("tab.extensions"));
        let Some(host) = &self.extension_host else {
            ui.label("Unable to bind the extension server on ports 9092–9107.");
            return;
        };
        ui.label(format!("Extension server: {}", host.address));
        ui.horizontal(|ui| {
            ui.label("Runtime (Java / Python / Node)");
            ui.text_edit_singleline(&mut self.extension_runtime);
        });
        ui.horizontal(|ui| {
            ui.label("Extension file");
            ui.text_edit_singleline(&mut self.extension_path);
        });
        if ui.button("Launch extension").clicked() {
            match host.launch(
                Path::new(&self.extension_runtime),
                Path::new(&self.extension_path),
            ) {
                Ok(child) => {
                    self.extension_processes.push(child);
                    self.status = "Extension process launched".into();
                }
                Err(e) => self.status = e.to_string(),
            }
        }
        ui.separator();
        for extension in host.extensions() {
            ui.horizontal(|ui| {
                ui.label(format!(
                    "{} {} · {}",
                    extension.info.title, extension.info.version, extension.info.author
                ));
                if !extension.approved && ui.button("Allow connection").clicked() {
                    if let Err(e) = host.approve(extension.id) {
                        self.status = e.to_string();
                    }
                }
                if extension.approved && extension.info.on_click && ui.button("Open").clicked() {
                    if let Err(e) = host.click(extension.id) {
                        self.status = e.to_string();
                    }
                }
                if ui.button("Disconnect").clicked() {
                    if let Err(e) = host.disconnect(extension.id) {
                        self.status = e.to_string();
                    }
                }
            });
        }
        ui.separator();
        ui.label("Extension console");
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in &self.extension_console {
                    ui.monospace(line);
                }
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
        if self.settings_loaded {
            self.save_settings();
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
        write_log_capture, LogDisplayOptions, LogRow, PacketRepresentation, LOG_PREDICTION_LIMIT,
    };
    use gearth_rust::packet::{Direction, Message, Packet};
    use gearth_rust::packet_info::{PacketInfo, PacketInfoManager};
    use std::{collections::VecDeque, sync::OnceLock};

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
            structure: false,
        };
        let info = PacketInfoManager::default();
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
        let row = LogRow {
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
            vec![PacketInfo {
                header: 42,
                direction: Direction::ToClient,
                name: Some("Example".into()),
                hash: Some("abc".into()),
                structure: None,
                source: "test".into(),
            }],
        );
        let mut options = LogDisplayOptions {
            additional: false,
            names: true,
            hashes: false,
            message_id: true,
            representation: PacketRepresentation::RawHex,
            extra_legacy: false,
            extra_raw_hex: false,
            extra_hex_dump: false,
            skip_big: false,
            skipped_label: "<packet skipped>",
            timestamp: true,
            structure: false,
        };
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, true).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("(123 ms)"));
        assert!(text.contains("BLOCKED"));
        assert!(text.contains("[Example] [42]"));
        assert!(text.contains("00000002002a"));
        assert!(text.ends_with("--------------------\n"));
        options.extra_legacy = true;
        options.extra_raw_hex = true;
        options.extra_hex_dump = true;
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, false).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("Legacy:"));
        assert!(text.contains("00000002002a"));
        assert!(text.contains("00000000  00 00 00 02 00 2a"));
        assert!(!text.contains("Raw hex:")); // Already used by the main representation.
        options.extra_legacy = false;
        options.extra_raw_hex = false;
        options.extra_hex_dump = false;
        options.representation = PacketRepresentation::HexDump;
        let mut output = Vec::new();
        write_log_capture(&mut output, [&row], &info, options, false).unwrap();
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("00000000  00 00 00 02 00 2a"));
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
        cached.set(("old expression".to_owned(), true)).unwrap();
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
        let mut filtered = 7;
        clear_log_contents(&mut rows, &mut accounted_bytes, &mut filtered);
        assert!(rows.is_empty());
        assert_eq!((accounted_bytes, filtered), (0, 0));
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
            ("Room, Other".into(), "abc, def".into())
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
}
