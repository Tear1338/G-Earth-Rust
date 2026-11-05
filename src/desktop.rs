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
    packet::{Direction, Message, PacketFormat},
    packet_info::PacketInfoManager,
    relay::RelayOptions,
    relay::{Config, Event, Relay},
    rules::{Action, Rule, Rules},
    schedule_file,
    scheduler::Scheduler,
    settings::{ScheduleTemplate, Settings},
    socks::SocksConfig,
    web_ca::ProxyIdentity,
    web_proxy::{WebOptions, WebProxy, NITRO_REVISION},
};
use std::{
    collections::VecDeque,
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
    Info,
}
struct Desktop {
    tab: Tab,
    listen: String,
    remote: String,
    status: String,
    relay: Option<Connection>,
    events: Option<Receiver<Event>>,
    logs: VecDeque<LogRow>,
    filter: String,
    outgoing: bool,
    incoming: bool,
    paused: bool,
    packet_limit: usize,
    logger_additional: bool,
    logger_structure: bool,
    logger_split: bool,
    expression: String,
    direction: Direction,
    interval_ms: u64,
    align_schedule: bool,
    schedule_offset_ms: u64,
    repeat: u32,
    repeat_forever: bool,
    schedule_edit: Option<usize>,
    schedule_path: String,
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
    expression: String,
    search: String,
    bytes: usize,
    skipped: bool,
    unity: bool,
    predicted_structure: OnceLock<String>,
    packet_expression: OnceLock<(String, bool)>,
}
fn invalidate_log_expressions(logs: &mut VecDeque<LogRow>) {
    for row in logs {
        row.packet_expression.take();
    }
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
            python_console: gpython_ui::PythonUi::default(),
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
            packet_limit: 8000,
            logger_additional: true,
            logger_structure: true,
            logger_split: true,
            expression: "{h:123}{i:42}{s:\"hello\"}".into(),
            direction: Direction::ToServer,
            interval_ms: 1000,
            align_schedule: false,
            schedule_offset_ms: 0,
            repeat: 1,
            repeat_forever: false,
            schedule_edit: None,
            schedule_path: "gearth.sched".into(),
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
                    }
                    Event::Packet(message) => {
                        self.total += 1;
                        if !self.paused {
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
                                + 2 * LOG_PREDICTION_LIMIT;
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
                                skipped,
                                unity: matches!(self.relay.as_ref(), Some(Connection::Unity(_))),
                                predicted_structure: OnceLock::new(),
                                packet_expression: OnceLock::new(),
                            });
                        }
                    }
                    Event::Listening(a) => self.status = format!("Listening on {a}"),
                    Event::Connected(a) => {
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
                        self.status = "Client disconnected; listening".into();
                        self.scheduler.jobs.clear();
                    }
                    Event::Error(e) => self.status = e,
                }
            }
        }
        if let Some(relay) = &self.relay {
            for (direction, packet) in self
                .scheduler
                .tick_with_wall_clock(Instant::now(), SystemTime::now())
            {
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
        if ui
            .add_enabled(
                self.relay.is_none() && self.attachment_pending.is_none(),
                egui::Checkbox::new(&mut self.nitro, "Browser client (Nitro / Unity)"),
            )
            .changed()
            && self.nitro
        {
            self.origins = false;
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
        }
        egui::CollapsingHeader::new("Official client attachment").default_open(true).show(ui,|ui|{
            let hotels=if self.origins{gearth_rust::attachment::ORIGINS_HOTELS}else{gearth_rust::attachment::FLASH_HOTELS};
            egui::ComboBox::from_id_salt("attach-hotel").selected_text(&self.attachment_host).show_ui(ui,|ui|{for host in hotels{ui.selectable_value(&mut self.attachment_host,(*host).into(),*host);}});
            ui.text_edit_singleline(&mut self.attachment_host);
            ui.checkbox(&mut self.flash_auto,"Negotiate Flash encryption and discover client RC4 state (Windows)");
            ui.horizontal(|ui|{
                if ui.button("Refresh Habbo processes").clicked(){match gearth_platform::habbo_processes(){Ok(processes)=>self.client_processes=processes,Err(e)=>self.status=e.to_string()}}
                egui::ComboBox::from_id_salt("flash-process").selected_text(if self.flash_pid==0{"Automatic (detect connecting client)".into()}else{format!("PID {}",self.flash_pid)}).show_ui(ui,|ui|{ui.selectable_value(&mut self.flash_pid,0,"Automatic (detect connecting client)");for p in &self.client_processes{ui.selectable_value(&mut self.flash_pid,p.pid,format!("{} - PID {}",p.executable,p.pid));}});
            });
            if ui.add_enabled(self.relay.is_none()&&self.attachment_pending.is_none(),egui::Button::new("Attach official client")).clicked(){
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
        if self.relay.is_none() && self.attachment_pending.is_none() {
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
                            self.relay = Some(Connection::Tcp(relay));
                            self.events = Some(events);
                            self.update_rules();
                        }
                        Err(e) => self.status = e.to_string(),
                    },
                    Err(e) => self.status = format!("Invalid local address: {e}"),
                }
            }
        } else if self.relay.is_some() && ui.button("Stop").clicked() {
            self.stop_connection();
        }
        ui.add_space(20.0);
        ui.group(|ui|{
            ui.label("Development scope");
            ui.label("Point a compatible test client at the local address. The relay forwards framed packets to the explicit remote address.");
            ui.label("Hosts-based Flash/Origins attachment is implemented. Raw-IP attachment and Unity integration are still outstanding. Nitro has a separate browser connection mode.");
        });
    }
    fn stop_connection(&mut self) {
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
        if !self.socks_proxy.trim().is_empty() {
            return Err(std::io::Error::other("Unity upstream SOCKS5 routing is not ported yet; clear the SOCKS setting before using a direct connection"));
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
        if !self.socks_proxy.trim().is_empty() {
            return Err(std::io::Error::other("Nitro upstream SOCKS5 support is not implemented; clear the SOCKS setting to use a direct connection"));
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
        } else if ui.button("Stop").clicked() {
            self.stop_connection();
        }
        ui.separator();
        ui.label(if self.unity {"Unity WebGL hooks and communicator are validated on controlled fixtures; official client sessions still need regression testing."}else{"Nitro transport and beta-29 hotel adapters are implemented with finite fixture tests. Real hotel sessions and Chrome TLS emulation still need validation and work."});
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
            ui.label("Packet display limit (bytes)");
            ui.add(egui::DragValue::new(&mut self.packet_limit).range(0..=16 * 1024 * 1024));
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.logger_additional, "Show additional data");
            ui.checkbox(&mut self.logger_structure, "Show packet structure");
            ui.checkbox(&mut self.logger_split, "Split packets");
        });
        let filter = self.filter.to_lowercase();
        ui.horizontal(|ui| {
            ui.label("Export path");
            ui.text_edit_singleline(&mut self.export_path);
            if ui.button("Export displayed capture").clicked() {
                let mut text =
                    String::from("# G-Earth Rust capture: direction index blocked expression\n");
                for row in &self.logs {
                    let m = &row.message;
                    let direction_visible = if m.direction == Direction::ToServer {
                        self.outgoing
                    } else {
                        self.incoming
                    };
                    if !direction_visible || (!filter.is_empty() && !row.search.contains(&filter)) {
                        continue;
                    }
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
        let row_height = if self.logger_structure { 44.0 } else { 24.0 };
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show_rows(ui, row_height, filtered.len(), |ui, range| {
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
                    let additional = if self.logger_additional {
                        format!(
                            "(h: {}, l: {})  ",
                            m.packet.header(),
                            if m.packet.format() == PacketFormat::EvaWire {
                                m.packet.bytes().len().saturating_sub(4)
                            } else {
                                m.packet.bytes().len()
                            }
                        )
                    } else {
                        String::new()
                    };
                    let label = format!(
                        "#{:06}  {:8}  {}{}{}",
                        m.index,
                        if m.direction == Direction::ToServer {
                            "→ SERVER"
                        } else {
                            "← CLIENT"
                        },
                        if m.blocked { "BLOCKED  " } else { "" },
                        additional,
                        row.expression
                    );
                    let row_output = ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), row_height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            let response = ui.add(
                                egui::Label::new(
                                    egui::RichText::new(label).monospace().color(color),
                                )
                                .truncate()
                                .sense(egui::Sense::click()),
                            );
                            if self.logger_structure && !row.skipped {
                                let (expression, known) = row.packet_expression.get_or_init(|| {
                                    let (expression, known) =
                                        gearth_rust::structure_prediction::expression_with_metadata(
                                            &m.packet, m.direction, &self.packet_info, row.unity,
                                        )
                                        .unwrap_or_default();
                                    (bounded_log_prediction(expression), known)
                                });
                                if !expression.is_empty() {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(format!(
                                                "{}: {expression}",
                                                if *known { "Structure" } else { "Predicted" }
                                            ))
                                            .monospace()
                                            .small(),
                                        )
                                        .truncate(),
                                    );
                                }
                            }
                            response
                        },
                    );
                    let response = row_output.inner;
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
                self.relay.as_ref().is_some_and(Connection::connected),
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
            ui.checkbox(&mut self.repeat_forever, "Repeat until cancelled");
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.align_schedule, "Align interval to clock");
            ui.add_enabled(
                self.align_schedule,
                egui::DragValue::new(&mut self.schedule_offset_ms)
                    .range(0..=self.interval_ms.saturating_sub(1))
                    .prefix("Offset ms "),
            );
        });
        let editing = self.schedule_edit.is_some();
        if ui
            .add_enabled(
                editing || self.relay.as_ref().is_some_and(Connection::connected),
                egui::Button::new(if editing {
                    "Save template changes"
                } else {
                    "Add schedule"
                }),
            )
            .clicked()
        {
            let valid_offset = !self.align_schedule || self.schedule_offset_ms < self.interval_ms;
            let parsed = expression::parse_with_format(
                &self.expression,
                self.packet_format(self.direction),
                Some((self.direction, &self.packet_info)),
            );
            if !valid_offset {
                self.status = "Offset must be smaller than the interval".into();
            } else {
                self.status = match parsed.and_then(|packet| {
                    if editing {
                        Ok(())
                    } else {
                        self.scheduler.add_configured(
                            packet,
                            self.direction,
                            self.interval_ms,
                            self.align_schedule.then_some(self.schedule_offset_ms),
                            (!self.repeat_forever).then_some(self.repeat),
                            (Instant::now(), SystemTime::now()),
                        )
                    }
                }) {
                    Ok(()) => {
                        let template = ScheduleTemplate {
                            expression: self.expression.clone(),
                            direction: self.direction,
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
                    Err(e) => e.to_string(),
                };
            }
        }
        if editing && ui.button("Cancel template editing").clicked() {
            self.schedule_edit = None;
        }
        if ui.button("Cancel all schedules").clicked() {
            self.scheduler.jobs.clear();
        }
        ui.label(format!("{} active schedules", self.scheduler.jobs.len()));
        if ui
            .add_enabled(
                self.relay.as_ref().is_some_and(Connection::connected),
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
                    self.scheduler.add_configured(
                        p,
                        template.direction,
                        template.interval_ms,
                        template.offset_ms,
                        (template.repeat != 0).then_some(template.repeat),
                        (Instant::now(), SystemTime::now()),
                    )
                }) {
                    Ok(()) => {
                        if template.paused {
                            if let Some(job) = self.scheduler.jobs.last_mut() {
                                job.paused = true;
                            }
                        }
                    }
                    Err(e) => {
                        self.status = e.to_string();
                        break;
                    }
                }
            }
        }
        if ui.button("Clear saved schedules").clicked() {
            self.settings.schedules.clear();
            self.schedule_edit = None;
        }
        ui.horizontal(|ui| {
            ui.label(".sched file");
            ui.text_edit_singleline(&mut self.schedule_path);
            if ui.button("Import").clicked() {
                let result = (|| -> std::io::Result<Vec<ScheduleTemplate>> {
                    let file = std::fs::File::open(&self.schedule_path)?;
                    let mut bytes = Vec::new();
                    file.take((schedule_file::MAX_SCHEDULE_FILE_BYTES + 1) as u64)
                        .read_to_end(&mut bytes)?;
                    let text = String::from_utf8(bytes).map_err(std::io::Error::other)?;
                    schedule_file::parse(&text)
                })();
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
            if ui.button("Export").clicked() {
                self.status = match schedule_file::format(&self.settings.schedules)
                    .and_then(|text| std::fs::write(&self.schedule_path, text))
                {
                    Ok(()) => format!("Exported templates to {}", self.schedule_path),
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
                if ui.small_button("Edit").clicked() {
                    edit_template = Some(i);
                }
                if ui.small_button("Remove").clicked() {
                    remove_template = Some(i);
                }
                ui.checkbox(&mut template.paused, "Paused on start");
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
            self.expression = template.expression.clone();
            self.direction = template.direction;
            self.interval_ms = template.interval_ms;
            self.align_schedule = template.offset_ms.is_some();
            self.schedule_offset_ms = template.offset_ms.unwrap_or(0);
            self.repeat_forever = template.repeat == 0;
            self.repeat = template.repeat.max(1);
            self.schedule_edit = Some(index);
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
        for (i, job) in self.scheduler.jobs.iter().enumerate() {
            ui.horizontal(|ui| {
                if ui
                    .small_button(if job.paused { "Resume" } else { "Pause" })
                    .clicked()
                {
                    pause_change = Some((i, !job.paused));
                }
                if ui.small_button("Remove").clicked() {
                    remove = Some(i);
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
            });
        }
        if let Some((i, paused)) = pause_change {
            if let Err(error) = self.scheduler.set_paused(i, paused, Instant::now()) {
                self.status = error.to_string();
            }
        }
        if let Some(i) = remove {
            self.scheduler.jobs.remove(i);
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
        if self.relay.is_some()
            || self.attachment_pending.is_some()
            || self.extension_host.is_some()
            || self.python_console.is_pending()
        {
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
        self.python_console.restore_settings(&self.settings);
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
            ("origins".into(), self.origins),
            ("nitro".into(), self.nitro),
            ("unity".into(), self.unity),
            ("dark_mode".into(), self.dark_mode),
            ("outgoing".into(), self.outgoing),
            ("incoming".into(), self.incoming),
            ("logger_additional".into(), self.logger_additional),
            ("logger_structure".into(), self.logger_structure),
            ("logger_split".into(), self.logger_split),
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
        self.python_console
            .show(ui, self.extension_host.as_ref(), &mut self.status);
        self.store.show(
            ui,
            self.extension_host.as_ref(),
            Path::new(&self.extension_runtime),
            &mut self.status,
            &mut self.extension_processes,
        );
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
mod logger_prediction_tests {
    use super::{bounded_log_prediction, invalidate_log_expressions, LogRow, LOG_PREDICTION_LIMIT};
    use gearth_rust::packet::{Direction, Message, Packet};
    use std::{collections::VecDeque, sync::OnceLock};

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
        let mut rows = VecDeque::from([LogRow {
            message: Message {
                packet: Packet::new(1),
                direction: Direction::ToClient,
                index: 1,
                blocked: false,
            },
            expression: String::new(),
            search: String::new(),
            bytes: 0,
            skipped: false,
            unity: false,
            predicted_structure: OnceLock::new(),
            packet_expression: cached,
        }]);
        invalidate_log_expressions(&mut rows);
        assert!(rows[0].packet_expression.get().is_none());
    }
}
