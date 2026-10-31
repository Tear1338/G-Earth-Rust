#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;
use gearth_rust::{
    expression,
    packet::{Direction, Message},
    relay::{Config, Event, Relay},
    rules::{Action, Rule, Rules},
    scheduler::Scheduler,
};
use std::{
    collections::VecDeque,
    sync::mpsc::Receiver,
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
    logs: VecDeque<Message>,
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
}
impl Default for Desktop {
    fn default() -> Self {
        Self {
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
        }
    }
}
impl Desktop {
    fn update_rules(&mut self) {
        if let Some(relay) = &self.relay {
            if let Err(e) = relay.set_rules(Rules {
                entries: vec![Rule {
                    enabled: self.block_enabled,
                    direction: self.block_direction,
                    header: self.block_header,
                    action: Action::Block,
                }],
            }) {
                self.status = e.to_string();
            }
        }
    }
    fn poll(&mut self) {
        if let Some(events) = &self.events {
            for event in events.try_iter().take(512) {
                match event {
                    Event::Packet(message) => {
                        self.total += 1;
                        if !self.paused {
                            if self.logs.len() == 5000 {
                                self.logs.pop_front();
                                self.display_dropped += 1;
                            }
                            self.logs.push_back(message);
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
        ui.label("Explicit TCP relay · unencrypted EVA_WIRE");
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
        ui.add_space(14.0);
        if self.relay.is_none() {
            if ui.button("Start listening").clicked() {
                match self.listen.parse() {
                    Ok(listen) => match Relay::start(Config {
                        listen,
                        remote: self.remote.trim().to_owned(),
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
                for m in &self.logs {
                    text.push_str(&format!(
                        "{}\t{}\t{}\t{}\n",
                        m.direction.name(),
                        m.index,
                        m.blocked,
                        expression::to_lossless_expression(&m.packet)
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
            .filter(|m| {
                (if m.direction == Direction::ToServer {
                    self.outgoing
                } else {
                    self.incoming
                }) && (filter.is_empty()
                    || m.packet.header().to_string().contains(&filter)
                    || expression::to_lossless_expression(&m.packet)
                        .to_lowercase()
                        .contains(&filter))
            })
            .collect();
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show_rows(ui, 24.0, filtered.len(), |ui, range| {
                for i in range {
                    let m = filtered[i];
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
                        expression::to_lossless_expression(&m.packet)
                    );
                    let response = ui.add(
                        egui::Label::new(egui::RichText::new(label).monospace().color(color))
                            .sense(egui::Sense::click()),
                    );
                    if response.clicked() {
                        self.expression = expression::to_lossless_expression(&m.packet);
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
        match expression::parse(&self.expression) {
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
            self.status = match expression::parse(&self.expression) {
                Ok(packet) => match self.relay.as_ref().unwrap().inject(self.direction, packet) {
                    Ok(()) => "Packet sent".into(),
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
            self.status = match expression::parse(&self.expression).and_then(|p| {
                self.scheduler.add(
                    p,
                    self.direction,
                    Duration::from_millis(self.interval_ms),
                    Some(self.repeat),
                    Instant::now(),
                )
            }) {
                Ok(()) => "Schedule added".into(),
                Err(e) => e.to_string(),
            };
        }
        if ui.button("Cancel all schedules").clicked() {
            self.scheduler.jobs.clear();
        }
        ui.label(format!("{} active schedules", self.scheduler.jobs.len()));
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
        ctx.set_visuals(egui::Visuals::light());
        self.poll();
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.strong("G-Earth Rust");
                ui.label("0.1.0 · development");
            });
            ui.horizontal_wrapped(|ui| {
                for (tab, name) in [
                    (Tab::Connection, "Connection"),
                    (Tab::Logger, "Logger"),
                    (Tab::Injection, "Injection"),
                    (Tab::Scheduler, "Scheduler"),
                    (Tab::Tools, "Tools"),
                    (Tab::Extensions, "Extensions"),
                    (Tab::Info, "Info"),
                ] {
                    ui.selectable_value(&mut self.tab, tab, name);
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
        egui::CentralPanel::default().show(ctx,|ui|match self.tab {
            Tab::Connection=>self.connection(ui),Tab::Logger=>self.logger(ui),Tab::Injection=>self.injection(ui),Tab::Scheduler=>self.schedule(ui),Tab::Tools=>self.tools(ui),
            Tab::Extensions=>{ui.heading("Extensions");ui.label("The beta-29 EVA_WIRE network message codec is implemented in the Rust library.");ui.label("The extension host, store, Python console and Java JAR launcher are not implemented yet.");ui.label("G-Presets compatibility has not been validated. Continue using the original G-Earth for existing extensions.");},
            Tab::Info=>{ui.heading("G-Earth Rust");ui.label("Rust port in progress, based on G-Realm/G-Earth 1.5.4-beta-29.");ui.hyperlink_to("Original project · sirjonasxx & contributors","https://github.com/G-Realm/G-Earth");ui.hyperlink_to("Rust project · 1desirable1337","https://github.com/Tear1338/G-Earth-Rust");ui.label("MIT licensed. Read docs/PARITY.md for implemented and missing functionality.");ui.label("Performance improvements have not been measured against the Java application.");}
        });
        if self.relay.is_some() {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }
}
