#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;
use gearth_rust::{
    crypto::Rc4,
    expression,
    extension_host::{ConnectionDetails, ExtensionHost, HostEvent},
    i18n::{I18n, LANGUAGES},
    packet::{Direction, Message, PacketFormat},
    packet_info::PacketInfoManager,
    relay::RelayOptions,
    relay::{Config, Event, Relay},
    rules::{Action, Rule, Rules},
    scheduler::Scheduler,
    settings::{ScheduleTemplate, Settings},
    socks::SocksConfig,
};
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    process::Child,
    sync::mpsc::Receiver,
    sync::Arc,
    time::{Duration, Instant},
};

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
    Info,
}
struct Desktop {
    tab: Tab,
    listen: String,
    remote: String,
    status: String,
    relay: Option<Relay>,
    events: Option<Receiver<Event>>,
    logs: VecDeque<LogRow>,
    filter: String,
    outgoing: bool,
    incoming: bool,
    paused: bool,
    expression: String,
    direction: Direction,
    interval_ms: u64,
    repeat: u32,
    scheduler: Scheduler,
    block_header: u16,
    block_enabled: bool,
    block_direction: Direction,
    tool_input: String,
    tool_output: String,
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
    socks_proxy: String,
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
    packet_download: Option<Receiver<std::io::Result<PacketInfoManager>>>,
}
struct LogRow {
    message: Message,
    expression: String,
    search: String,
    bytes: usize,
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
            listen: "127.0.0.1:1234".into(),
            remote: "".into(),
            status: "Disconnected".into(),
            relay: None,
            events: None,
            logs: VecDeque::new(),
            filter: String::new(),
            outgoing: true,
            incoming: true,
            paused: false,
            expression: "{h:123}{i:42}{s:\"hello\"}".into(),
            direction: Direction::ToServer,
            interval_ms: 1000,
            repeat: 1,
            scheduler: Scheduler::default(),
            block_header: 0,
            block_enabled: false,
            block_direction: Direction::ToServer,
            tool_input: String::new(),
            tool_output: String::new(),
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
            socks_proxy: String::new(),
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
            packet_download: None,
        };
        desktop.load_settings();
        desktop
    }
}
impl Desktop {
    fn update_rules(&mut self) {
        let mut entries = match self.settings.compiled_rules_for(self.origins) {
            Ok(entries) => entries,
            Err(e) => {
                self.status = e.to_string();
                return;
            }
        };
        let action = if self.replacement_expression.trim().is_empty() {
            Action::Block
        } else {
            match expression::parse_with_format(
                &self.replacement_expression,
                self.packet_format(self.block_direction),
                Some((self.block_direction, &self.packet_info)),
            ) {
                Ok(p) => Action::Replace(p),
                Err(e) => {
                    self.status = e.to_string();
                    return;
                }
            }
        };
        entries.push(Rule {
            enabled: self.block_enabled,
            direction: self.block_direction,
            header: self.block_header,
            action,
        });
        if let Some(relay) = &self.relay {
            if let Err(e) = relay.set_rules(Rules { entries }) {
                self.status = e.to_string();
            }
        }
    }
    fn poll(&mut self) {
        if let Some(download) = &self.packet_download {
            match download.try_recv() {
                Ok(result) => {
                    match result {
                        Ok(database) => {
                            self.hotel_version = database.version.clone();
                            self.status =
                                format!("Loaded {} packet identifiers", database.entries().len());
                            self.packet_info = database;
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
                    Event::Packet(message) => {
                        self.total += 1;
                        if !self.paused {
                            let expression = expression::to_lossless_expression(&message.packet);
                            let search = format!(
                                "{} {}",
                                message.packet.header(),
                                expression.to_lowercase()
                            );
                            let bytes =
                                message.packet.bytes().len() + expression.len() + search.len();
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
                                expression,
                                search,
                                bytes,
                            });
                        }
                    }
                    Event::Listening(a) => self.status = format!("Listening on {a}"),
                    Event::Connected(a) => self.status = format!("Connected to {a}"),
                    Event::Disconnected => {
                        self.status = "Client disconnected; listening".into();
                        self.scheduler.jobs.clear();
                    }
                    Event::Error(e) => self.status = e,
                }
            }
        }
        if let Some(relay) = &self.relay {
            for (direction, packet) in self.scheduler.tick(Instant::now()) {
                if let Err(e) = relay.inject(direction, packet) {
                    self.status = e.to_string();
                    self.scheduler.jobs.clear();
                    break;
                }
            }
        }
    }
    fn connection(&mut self, ui: &mut egui::Ui) {
        ui.heading("Connection");
        ui.label(if self.origins {
            "Origins TCP · negotiated Bobba encryption"
        } else {
            "EVA_WIRE TCP relay"
        });
        ui.add_enabled(
            self.relay.is_none(),
            egui::Checkbox::new(&mut self.origins, "Origins / Shockwave"),
        );
        ui.add_space(12.0);
        egui::Grid::new("connection-grid")
            .spacing([18.0, 12.0])
            .show(ui, |ui| {
                ui.label("Local address");
                ui.add_enabled(
                    self.relay.is_none(),
                    egui::TextEdit::singleline(&mut self.listen).desired_width(400.0),
                );
                ui.end_row();
                ui.label("Remote host:port");
                ui.add_enabled(
                    self.relay.is_none(),
                    egui::TextEdit::singleline(&mut self.remote).desired_width(400.0),
                );
                ui.end_row();
            });
        egui::CollapsingHeader::new("Connection options").show(ui,|ui|{
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
        if self.relay.is_none() {
            if ui.button("Start listening").clicked() {
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
                            self.relay = Some(relay);
                            self.events = Some(events);
                            self.update_rules();
                        }
                        Err(e) => self.status = e.to_string(),
                    },
                    Err(e) => self.status = format!("Invalid local address: {e}"),
                }
            }
        } else if ui.button("Stop").clicked() {
            self.relay.take();
            self.events = None;
            self.scheduler.jobs.clear();
            self.status = "Disconnected".into();
        }
        ui.add_space(20.0);
        ui.group(|ui|{
            ui.label("Development scope");
            ui.label("Point a compatible test client at the local address. The relay forwards framed packets to the explicit remote address.");
            ui.label("Automatic Flash/Origins attachment, RC4 key discovery, Nitro TLS/WebSocket and Unity integration are not implemented yet.");
        });
    }
    fn logger(&mut self, ui: &mut egui::Ui) {
        ui.heading("Packet logger");
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.outgoing, "To server");
            ui.checkbox(&mut self.incoming, "To client");
            ui.checkbox(&mut self.paused, "Pause display");
            if ui.button("Clear").clicked() {
                self.logs.clear();
                self.logs_bytes = 0;
            }
        });
        ui.horizontal(|ui| {
            ui.label("Filter");
            ui.text_edit_singleline(&mut self.filter);
        });
        ui.horizontal(|ui| {
            ui.label("Export path");
            ui.text_edit_singleline(&mut self.export_path);
            if ui.button("Export displayed capture").clicked() {
                let mut text =
                    String::from("# G-Earth Rust capture: direction index blocked expression\n");
                for row in &self.logs {
                    let m = &row.message;
                    text.push_str(&format!(
                        "{}\t{}\t{}\t{}\n",
                        m.direction.name(),
                        m.index,
                        m.blocked,
                        row.expression
                    ));
                }
                self.status = match std::fs::write(&self.export_path, text) {
                    Ok(()) => format!("Capture saved to {}", self.export_path),
                    Err(e) => e.to_string(),
                };
            }
        });
        ui.separator();
        let filter = self.filter.to_lowercase();
        let filtered: Vec<_> = self
            .logs
            .iter()
            .filter(|row| {
                let m = &row.message;
                (if m.direction == Direction::ToServer {
                    self.outgoing
                } else {
                    self.incoming
                }) && (filter.is_empty() || row.search.contains(&filter))
            })
            .collect();
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show_rows(ui, 24.0, filtered.len(), |ui, range| {
                for i in range {
                    let row = filtered[i];
                    let m = &row.message;
                    let color = if m.blocked {
                        egui::Color32::from_rgb(180, 60, 60)
                    } else if m.direction == Direction::ToServer {
                        egui::Color32::from_rgb(30, 90, 170)
                    } else {
                        egui::Color32::from_rgb(20, 130, 70)
                    };
                    let label = format!(
                        "#{:06}  {:8}  {}{}",
                        m.index,
                        if m.direction == Direction::ToServer {
                            "→ SERVER"
                        } else {
                            "← CLIENT"
                        },
                        if m.blocked { "BLOCKED  " } else { "" },
                        row.expression
                    );
                    let response = ui.add(
                        egui::Label::new(egui::RichText::new(label).monospace().color(color))
                            .sense(egui::Sense::click()),
                    );
                    if response.clicked() {
                        self.expression = row.expression.clone();
                        self.direction = m.direction;
                        self.tab = Tab::Injection;
                    }
                }
            });
    }
    fn editor(&mut self, ui: &mut egui::Ui) {
        direction_selector(ui, &mut self.direction);
        ui.add(
            egui::TextEdit::multiline(&mut self.expression)
                .font(egui::TextStyle::Monospace)
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
        match expression::parse_with_format(
            &self.expression,
            self.packet_format(self.direction),
            Some((self.direction, &self.packet_info)),
        ) {
            Ok(p) => {
                ui.label(format!("Header {} · {} bytes", p.header(), p.bytes().len()));
                ui.monospace(expression::hex(p.bytes()));
            }
            Err(e) => {
                ui.colored_label(egui::Color32::from_rgb(180, 60, 60), e.to_string());
            }
        }
    }
    fn injection(&mut self, ui: &mut egui::Ui) {
        ui.heading("Packet injection");
        self.editor(ui);
        if ui
            .add_enabled(
                self.relay.as_ref().is_some_and(Relay::connected),
                egui::Button::new("Send packet"),
            )
            .clicked()
        {
            self.status = match expression::parse_with_format(
                &self.expression,
                self.packet_format(self.direction),
                Some((self.direction, &self.packet_info)),
            ) {
                Ok(packet) => match self.relay.as_ref().unwrap().inject(self.direction, packet) {
                    Ok(()) => "Packet queued".into(),
                    Err(e) => e.to_string(),
                },
                Err(e) => e.to_string(),
            };
        }
        ui.add_space(20.0);
        ui.separator();
        ui.heading("Block rule");
        let changed = ui
            .checkbox(&mut self.block_enabled, "Enable rule")
            .changed();
        let changed = ui
            .add(egui::DragValue::new(&mut self.block_header).prefix("Header "))
            .changed()
            || changed;
        let before = self.block_direction;
        direction_selector(ui, &mut self.block_direction);
        if changed || before != self.block_direction {
            self.update_rules();
        }
        ui.label("Replacement expression (empty = block)");
        if ui
            .text_edit_singleline(&mut self.replacement_expression)
            .changed()
        {
            self.update_rules();
        }
        if ui.button("Add saved rule").clicked() {
            let replacement = if self.replacement_expression.trim().is_empty() {
                Ok(None)
            } else {
                expression::parse_with_format(
                    &self.replacement_expression,
                    self.packet_format(self.block_direction),
                    Some((self.block_direction, &self.packet_info)),
                )
                .map(|p| Some(expression::to_lossless_expression(&p)))
            };
            match replacement {
                Ok(replacement) => {
                    self.settings.rules.push((
                        true,
                        self.block_direction,
                        self.block_header,
                        replacement,
                    ));
                    self.block_enabled = false;
                    self.update_rules();
                }
                Err(e) => self.status = e.to_string(),
            }
        }
        let mut remove = None;
        let mut changed = false;
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
                if ui.small_button("Remove").clicked() {
                    remove = Some(index);
                }
            });
        }
        if let Some(index) = remove {
            self.settings.rules.remove(index);
            changed = true;
        }
        if changed {
            self.update_rules();
        }
    }
    fn schedule(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scheduler");
        self.editor(ui);
        ui.horizontal(|ui| {
            ui.add(
                egui::DragValue::new(&mut self.interval_ms)
                    .range(1..=86_400_000)
                    .prefix("Interval ms "),
            );
            ui.add(
                egui::DragValue::new(&mut self.repeat)
                    .range(1..=1_000_000)
                    .prefix("Count "),
            );
        });
        if ui
            .add_enabled(
                self.relay.as_ref().is_some_and(Relay::connected),
                egui::Button::new("Add schedule"),
            )
            .clicked()
        {
            self.status = match expression::parse_with_format(
                &self.expression,
                self.packet_format(self.direction),
                Some((self.direction, &self.packet_info)),
            )
            .and_then(|p| {
                self.scheduler.add(
                    p,
                    self.direction,
                    Duration::from_millis(self.interval_ms),
                    Some(self.repeat),
                    Instant::now(),
                )
            }) {
                Ok(()) => {
                    self.settings.schedules.push(ScheduleTemplate {
                        expression: self.expression.clone(),
                        direction: self.direction,
                        interval_ms: self.interval_ms,
                        repeat: self.repeat,
                    });
                    "Schedule added".into()
                }
                Err(e) => e.to_string(),
            };
        }
        if ui.button("Cancel all schedules").clicked() {
            self.scheduler.jobs.clear();
        }
        ui.label(format!("{} active schedules", self.scheduler.jobs.len()));
        if ui
            .add_enabled(
                self.relay.as_ref().is_some_and(Relay::connected),
                egui::Button::new("Run saved schedules"),
            )
            .clicked()
        {
            for template in &self.settings.schedules {
                match expression::parse_with_format(
                    &template.expression,
                    self.packet_format(template.direction),
                    Some((template.direction, &self.packet_info)),
                )
                .and_then(|p| {
                    self.scheduler.add(
                        p,
                        template.direction,
                        Duration::from_millis(template.interval_ms),
                        Some(template.repeat),
                        Instant::now(),
                    )
                }) {
                    Ok(()) => {}
                    Err(e) => {
                        self.status = e.to_string();
                        break;
                    }
                }
            }
        }
        if ui.button("Clear saved schedules").clicked() {
            self.settings.schedules.clear();
        }
        for (i, job) in self.scheduler.jobs.iter().enumerate() {
            ui.monospace(format!(
                "{}: {} header {} every {} ms · remaining {}",
                i + 1,
                job.direction.name(),
                job.packet.header(),
                job.interval.as_millis(),
                job.remaining.unwrap_or(0)
            ));
        }
    }
    fn tools(&mut self, ui: &mut egui::Ui) {
        ui.heading("Packet tools");
        ui.add(
            egui::TextEdit::multiline(&mut self.tool_input)
                .desired_rows(5)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );
        ui.horizontal(|ui| {
            if ui.button("Expression → wire hex").clicked() {
                self.tool_output = expression::parse(&self.tool_input)
                    .map(|p| expression::hex(p.bytes()))
                    .unwrap_or_else(|e| e.to_string());
            }
            if ui.button("Wire hex → lossless expression").clicked() {
                self.tool_output = expression::parse_hex(&self.tool_input)
                    .and_then(gearth_rust::packet::Packet::from_bytes)
                    .map(|p| expression::to_lossless_expression(&p))
                    .unwrap_or_else(|e| e.to_string());
            }
        });
        ui.add(
            egui::TextEdit::multiline(&mut self.tool_output)
                .desired_rows(5)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );
        ui.separator();
        ui.label("Notepad");
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
fn direction_selector(ui: &mut egui::Ui, direction: &mut Direction) {
    ui.horizontal(|ui| {
        ui.selectable_value(direction, Direction::ToServer, "To server");
        ui.selectable_value(direction, Direction::ToClient, "To client");
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
            ui.horizontal(|ui| {
                ui.strong("G-Earth Rust");
                ui.label("0.1.0 · development");
                if ui.button("Save settings").clicked() {
                    self.save_settings();
                }
                if ui.button("Reload settings").clicked() {
                    self.load_settings();
                }
                ui.checkbox(&mut self.dark_mode, "Dark theme");
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
                    (Tab::Logger, "Logger"),
                    (Tab::Injection, "tab.injection"),
                    (Tab::Scheduler, "tab.scheduler"),
                    (Tab::Tools, "tab.tools"),
                    (Tab::Extensions, "tab.extensions"),
                    (Tab::Info, "Info"),
                ] {
                    let label = if name.starts_with("tab.") {
                        self.i18n.text(name)
                    } else {
                        name.to_owned()
                    };
                    ui.selectable_value(&mut self.tab, tab, label);
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
        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Connection => self.connection(ui),
            Tab::Logger => self.logger(ui),
            Tab::Injection => self.injection(ui),
            Tab::Scheduler => self.schedule(ui),
            Tab::Tools => self.tools(ui),
            Tab::Extensions => self.extensions(ui),
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
        });
        if self.relay.is_some() || self.extension_host.is_some() {
            ctx.request_repaint_after(Duration::from_millis(50));
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
        self.origins = self
            .settings
            .booleans
            .get("origins")
            .copied()
            .unwrap_or_else(|| self.settings.get("client_type") == "SHOCKWAVE");
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
            ("origins".into(), self.origins),
            ("dark_mode".into(), self.dark_mode),
            ("outgoing".into(), self.outgoing),
            ("incoming".into(), self.incoming),
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
        if self.origins {
            if direction == Direction::ToServer {
                PacketFormat::WedgieOutgoing
            } else {
                PacketFormat::WedgieIncoming
            }
        } else {
            PacketFormat::EvaWire
        }
    }
    fn relay_options(&mut self) -> std::io::Result<RelayOptions> {
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
            shockwave: self.origins,
            extensions: self.extension_host.clone(),
            connection: Some(connection),
            socks: if self.socks_proxy.trim().is_empty() {
                None
            } else {
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
        ui.heading("Extensions");
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
        if self.settings_loaded {
            self.save_settings();
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
