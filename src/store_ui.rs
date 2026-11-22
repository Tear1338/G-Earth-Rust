use eframe::egui;
use gearth_rust::{
    extension_host::ExtensionHost,
    extension_store::{self, Catalog, InstallStatus, Installed, Query, Sort, StoreExtension},
    i18n::I18n,
};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    process::Child,
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

const PAGE_SIZE: usize = 7;

enum Outcome {
    Catalog(Catalog),
    Installed(Box<Installed>),
    Changed(String),
}

enum Action {
    Install(Box<StoreExtension>),
    Remove(Box<Installed>),
    Launch(Box<Installed>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StoreView {
    Recent,
    Popular,
    NewReleases,
    Categories,
    Category(String),
    Installed,
    Search,
    Details(String),
}

struct OverviewIcons {
    clock: Option<egui::TextureHandle>,
    star: Option<egui::TextureHandle>,
    idea: Option<egui::TextureHandle>,
    success: Option<egui::TextureHandle>,
    search: Option<egui::TextureHandle>,
}

impl OverviewIcons {
    fn load(ctx: &egui::Context) -> Self {
        Self {
            clock: decode_png_texture(
                ctx,
                "store_overview_clock",
                include_bytes!("../resources/ui/store/clock.png"),
            ),
            star: decode_png_texture(
                ctx,
                "store_overview_star",
                include_bytes!("../resources/ui/store/star.png"),
            ),
            idea: decode_png_texture(
                ctx,
                "store_overview_idea",
                include_bytes!("../resources/ui/store/idea.png"),
            ),
            success: decode_png_texture(
                ctx,
                "store_overview_success",
                include_bytes!("../resources/ui/store/success.png"),
            ),
            search: decode_png_texture(
                ctx,
                "store_overview_search",
                include_bytes!("../resources/ui/store/search.png"),
            ),
        }
    }
}

fn decode_png_texture(
    ctx: &egui::Context,
    name: &str,
    bytes: &[u8],
) -> Option<egui::TextureHandle> {
    let icon = eframe::icon_data::from_png_bytes(bytes).ok()?;
    let image = egui::ColorImage::from_rgba_unmultiplied(
        [icon.width as usize, icon.height as usize],
        &icon.rgba,
    );
    Some(ctx.load_texture(name, image, egui::TextureOptions::LINEAR))
}

struct ImageDecodeResult {
    key: String,
    rgba: Option<(Vec<u8>, u32, u32)>,
}

fn sort_key(sort: Sort) -> &'static str {
    match sort {
        Sort::Rating => "rust.store.sort_rating",
        Sort::Alphabetical => "rust.store.sort_alphabetical",
        Sort::LastUpdated => "rust.store.sort_updated",
        Sort::NewReleases => "rust.store.sort_new",
    }
}

fn format_elapsed(date_str: &str, i18n: &I18n) -> Option<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let (amount, unit) = extension_store::elapsed_since(date_str, now)?;
    let suffix = if amount == 1 { "single" } else { "multiple" };
    let unit_label = i18n.text(&format!("ext.store.elapsedtime.{unit}.{suffix}"));
    Some(format!("{amount} {unit_label}"))
}

fn current_os_name() -> &'static str {
    if cfg!(windows) {
        "Windows"
    } else if cfg!(target_os = "macos") {
        "Mac"
    } else {
        "Linux"
    }
}

pub struct StoreUi {
    root: PathBuf,
    catalog: Option<Catalog>,
    installed: Vec<Installed>,
    worker: Option<Receiver<Result<Outcome, String>>>,
    initialized: bool,
    catalog_auto_requested: bool,
    view: StoreView,
    previous_view: StoreView,
    page: usize,
    search: String,
    sort: Sort,
    outdated: bool,
    reverse: bool,
    os: String,
    client: String,
    framework: String,
    category: String,
    overview_icons: Option<OverviewIcons>,
    remote_textures: HashMap<String, Option<egui::TextureHandle>>,
    requested_images: HashSet<String>,
    image_tx: Option<Sender<(String, String)>>,
    image_rx: Option<Receiver<ImageDecodeResult>>,
}

impl StoreUi {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            catalog: None,
            installed: Vec::new(),
            worker: None,
            initialized: false,
            catalog_auto_requested: false,
            view: StoreView::Recent,
            previous_view: StoreView::Recent,
            page: 0,
            search: String::new(),
            sort: Sort::LastUpdated,
            outdated: false,
            reverse: false,
            os: current_os_name().into(),
            client: String::new(),
            framework: String::new(),
            category: String::new(),
            overview_icons: None,
            remote_textures: HashMap::new(),
            requested_images: HashSet::new(),
            image_tx: None,
            image_rx: None,
        }
    }

    pub fn invalidate(&mut self) {
        self.initialized = false;
    }

    fn refresh(&mut self, status: &mut String) {
        match extension_store::installed(&self.root) {
            Ok(entries) => self.installed = entries,
            Err(error) => *status = error.to_string(),
        }
    }

    fn start_fetch_catalog(&mut self, status: &mut String) {
        if self.worker.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        self.worker = Some(receiver);
        *status = "Loading extension catalogue...".into();
        std::thread::spawn(move || {
            let result = Catalog::fetch(
                extension_store::STORE_SOURCE,
                extension_store::STORE_VERSION,
            )
            .map(Outcome::Catalog)
            .map_err(|error| error.to_string());
            let _ = sender.send(result);
        });
    }

    fn ensure_image_worker(&mut self) {
        if self.image_tx.is_some() {
            return;
        }
        let (req_tx, req_rx) = mpsc::channel::<(String, String)>();
        let (res_tx, res_rx) = mpsc::channel::<ImageDecodeResult>();
        std::thread::spawn(move || {
            while let Ok((key, url)) = req_rx.recv() {
                let rgba = extension_store::fetch_image_bytes(&url)
                    .ok()
                    .and_then(|bytes| eframe::icon_data::from_png_bytes(&bytes).ok())
                    .map(|icon| (icon.rgba, icon.width, icon.height));
                if res_tx.send(ImageDecodeResult { key, rgba }).is_err() {
                    break;
                }
            }
        });
        self.image_tx = Some(req_tx);
        self.image_rx = Some(res_rx);
    }

    fn poll_images(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.image_rx {
            let mut received_any = false;
            for item in rx.try_iter().take(16) {
                received_any = true;
                let tex = item.rgba.map(|(rgba, width, height)| {
                    let image = egui::ColorImage::from_rgba_unmultiplied(
                        [width as usize, height as usize],
                        &rgba,
                    );
                    ctx.load_texture(&item.key, image, egui::TextureOptions::LINEAR)
                });
                self.remote_textures.insert(item.key, tex);
            }
            if received_any || self.remote_textures.len() < self.requested_images.len() {
                ctx.request_repaint_after(std::time::Duration::from_millis(80));
            }
        }
    }

    fn request_image(&mut self, key: String, url: String) -> Option<egui::TextureHandle> {
        if let Some(existing) = self.remote_textures.get(&key) {
            return existing.clone();
        }
        if self.requested_images.insert(key.clone()) {
            self.ensure_image_worker();
            if let Some(tx) = &self.image_tx {
                let _ = tx.send((key, url));
            }
        }
        None
    }

    fn navigate(&mut self, next: StoreView) {
        if !matches!(self.view, StoreView::Details(_)) {
            self.previous_view = self.view.clone();
        }
        self.view = next;
        self.page = 0;
    }

    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        host: Option<&Arc<ExtensionHost>>,
        java: &Path,
        i18n: &I18n,
        status: &mut String,
        processes: &mut Vec<Child>,
    ) {
        if self.overview_icons.is_none() {
            self.overview_icons = Some(OverviewIcons::load(ui.ctx()));
        }
        if !self.initialized {
            self.refresh(status);
            self.initialized = true;
        }
        if !self.catalog_auto_requested && self.catalog.is_none() && self.worker.is_none() {
            self.catalog_auto_requested = true;
            self.start_fetch_catalog(status);
        }
        self.poll_images(ui.ctx());

        if let Some(worker) = &self.worker {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(80));
            match worker.try_recv() {
                Ok(result) => {
                    match result {
                        Ok(Outcome::Catalog(catalog)) => {
                            *status =
                                format!("Loaded {} store extensions", catalog.extensions.len());
                            self.catalog = Some(catalog);
                        }
                        Ok(Outcome::Installed(record)) => {
                            self.refresh(status);
                            if let Some(host) = host {
                                let filename = record
                                    .directory
                                    .file_name()
                                    .and_then(|name| name.to_str())
                                    .unwrap_or("");
                                match host.launch_command(
                                    &record.command,
                                    &record.directory.join("extension"),
                                    filename,
                                    &record.title,
                                    java,
                                ) {
                                    Ok(process) => {
                                        processes.push(process);
                                        *status = format!(
                                            "Installed & launched {} {}",
                                            record.title, record.version
                                        );
                                    }
                                    Err(error) => {
                                        *status = format!(
                                            "Installed {} {} (launch failed: {error})",
                                            record.title, record.version
                                        );
                                    }
                                }
                            } else {
                                *status = format!("Installed {} {}", record.title, record.version);
                            }
                        }
                        Ok(Outcome::Changed(message)) => {
                            *status = message;
                            self.refresh(status);
                        }
                        Err(error) => *status = error,
                    }
                    self.worker = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    *status = "Extension store worker stopped".into();
                    self.worker = None;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }

        let dark = ui.visuals().dark_mode;
        let ready = self.worker.is_none();
        let mut action: Option<Action> = None;
        let mut next_view: Option<StoreView> = None;
        let mut refresh_requested = false;
        let mut open_folder_requested = false;

        // Pre-fetch icon if we are on Details view so the header can show it
        let detail_icon_key =
            if let (StoreView::Details(title), Some(catalog)) = (&self.view, &self.catalog) {
                catalog
                    .extensions
                    .iter()
                    .find(|e| e.title == *title)
                    .map(|ext| (format!("icon:{}", ext.title), catalog.icon_url(ext)))
            } else {
                None
            };
        if let Some((key, url)) = &detail_icon_key {
            let _ = self.request_image(key.clone(), url.clone());
        }

        // 1. Iconic Dark-Teal Header Banner (#143b4b + black left 72x72 icon box)
        let (header_title, header_subtitle, section_title) = match &self.view {
            StoreView::Recent => (
                i18n.text("ext.store.search.ordering.byupdate.title"),
                i18n.text("ext.store.search.ordering.byupdate.description"),
                i18n.text("ext.store.search.ordering.byupdate.contenttitle"),
            ),
            StoreView::Popular => (
                i18n.text("ext.store.search.ordering.byrating.title"),
                i18n.text("ext.store.search.ordering.byrating.description"),
                i18n.text("ext.store.search.ordering.byrating.contenttitle"),
            ),
            StoreView::NewReleases => (
                i18n.text("ext.store.search.ordering.bydate.title"),
                i18n.text("ext.store.search.ordering.bydate.description"),
                i18n.text("ext.store.search.ordering.bydate.contenttitle"),
            ),
            StoreView::Categories => (
                i18n.text("ext.store.categories.title"),
                i18n.text("ext.store.categories.description"),
                i18n.text("ext.store.categories.contenttitle"),
            ),
            StoreView::Category(name) => {
                let desc = self
                    .catalog
                    .as_ref()
                    .and_then(|c| c.config.categories.iter().find(|cat| cat.name == *name))
                    .map(|cat| cat.description.clone())
                    .unwrap_or_default();
                (name.clone(), desc, name.clone())
            }
            StoreView::Installed => (
                i18n.text("ext.store.overview.title"),
                i18n.text("ext.store.overview.description"),
                i18n.text("ext.store.overview.contenttitle"),
            ),
            StoreView::Search => (
                i18n.text("ext.store.search.title"),
                i18n.text("ext.store.search.description"),
                i18n.text("ext.store.search.results"),
            ),
            StoreView::Details(title) => {
                let sub = self
                    .catalog
                    .as_ref()
                    .and_then(|c| c.extensions.iter().find(|e| e.title == *title))
                    .map(|e| {
                        let author = e
                            .authors
                            .first()
                            .map(|a| a.name.as_str())
                            .unwrap_or("Unknown");
                        format!(
                            "{}  ·  v{}",
                            i18n.text("ext.store.extension.madeby")
                                .replace("%s", author),
                            e.version
                        )
                    })
                    .unwrap_or_default();
                (title.clone(), sub, title.clone())
            }
        };

        let header_bg = egui::Color32::from_rgb(0x14, 0x3b, 0x4b);
        let icon_box_bg = egui::Color32::from_rgb(0x06, 0x0d, 0x11);
        let banner_h = 72.0;

        egui::Frame::none()
            .fill(header_bg)
            .inner_margin(egui::Margin::same(0.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    // Left 72x72 dark icon block
                    egui::Frame::none().fill(icon_box_bg).show(ui, |ui| {
                        ui.allocate_ui_with_layout(
                            egui::vec2(banner_h, banner_h),
                            egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                            |ui| {
                                let custom_tex = detail_icon_key
                                    .as_ref()
                                    .and_then(|(k, _)| self.remote_textures.get(k))
                                    .and_then(|t| t.as_ref());
                                let overview_tex =
                                    self.overview_icons
                                        .as_ref()
                                        .and_then(|ic| match &self.view {
                                            StoreView::Recent => ic.clock.as_ref(),
                                            StoreView::Popular | StoreView::NewReleases => {
                                                ic.star.as_ref()
                                            }
                                            StoreView::Categories | StoreView::Category(_) => {
                                                ic.idea.as_ref()
                                            }
                                            StoreView::Installed => ic.success.as_ref(),
                                            StoreView::Search => ic.search.as_ref(),
                                            StoreView::Details(_) => ic.star.as_ref(),
                                        });
                                if let Some(tex) = custom_tex.or(overview_tex) {
                                    ui.add(egui::Image::new((tex.id(), egui::vec2(50.0, 50.0))));
                                }
                            },
                        );
                    });

                    ui.add_space(14.0);
                    ui.vertical(|ui| {
                        ui.add_space(12.0);
                        ui.label(
                            egui::RichText::new(&header_title)
                                .size(20.0)
                                .strong()
                                .color(egui::Color32::WHITE),
                        );
                        ui.add_space(2.0);
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&header_subtitle)
                                    .size(12.0)
                                    .color(egui::Color32::from_rgb(0xd4, 0xe7, 0xef)),
                            )
                            .truncate(),
                        );
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(12.0);
                        if !ready {
                            ui.spinner();
                            ui.add_space(6.0);
                        }
                        match &self.view {
                            StoreView::Details(_) => {
                                if ui
                                    .add(
                                        egui::Button::new(
                                            egui::RichText::new("← Back")
                                                .color(egui::Color32::WHITE),
                                        )
                                        .fill(egui::Color32::from_rgb(0x1f, 0x55, 0x6b)),
                                    )
                                    .clicked()
                                {
                                    next_view = Some(self.previous_view.clone());
                                }
                            }
                            StoreView::Installed => {
                                if ui
                                    .add(
                                        egui::Button::new(
                                            egui::RichText::new(
                                                i18n.text("ext.store.overview.folder"),
                                            )
                                            .color(egui::Color32::WHITE),
                                        )
                                        .fill(egui::Color32::from_rgb(0x1f, 0x55, 0x6b)),
                                    )
                                    .clicked()
                                {
                                    open_folder_requested = true;
                                }
                            }
                            _ => {
                                if ui
                                    .add_enabled(
                                        ready,
                                        egui::Button::new(
                                            egui::RichText::new("↻").color(egui::Color32::WHITE),
                                        )
                                        .fill(egui::Color32::from_rgb(0x1f, 0x55, 0x6b)),
                                    )
                                    .on_hover_text(i18n.text("rust.store.load"))
                                    .clicked()
                                {
                                    refresh_requested = true;
                                }
                            }
                        }
                    });
                });
            });

        // 2. Quick Links Navigation Bar (exact beta-29 strip + Installed badge + Search)
        let nav_bg = if dark {
            egui::Color32::from_rgb(0x24, 0x24, 0x24)
        } else {
            egui::Color32::WHITE
        };
        let link_color = if dark {
            egui::Color32::from_rgb(0x63, 0xb3, 0xed)
        } else {
            egui::Color32::from_rgb(0x1e, 0x7e, 0xb8)
        };
        let active_link_color = if dark {
            egui::Color32::WHITE
        } else {
            egui::Color32::from_rgb(0x0c, 0x3b, 0x57)
        };

        egui::Frame::none()
            .fill(nav_bg)
            .inner_margin(egui::Margin::symmetric(12.0, 7.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.strong("Quick Links:");
                    ui.add_space(6.0);
                    let installed_count = self.installed.len();
                    let nav_items: [(&str, StoreView); 5] = [
                        ("Recent", StoreView::Recent),
                        ("Popular", StoreView::Popular),
                        ("New", StoreView::NewReleases),
                        ("Categories", StoreView::Categories),
                        ("Installed", StoreView::Installed),
                    ];
                    for (label, target) in nav_items {
                        let is_active = self.view == target
                            || (target == StoreView::Categories
                                && matches!(self.view, StoreView::Category(_)));
                        let display = if target == StoreView::Installed && installed_count > 0 {
                            format!("{label} ({installed_count})")
                        } else {
                            label.to_owned()
                        };
                        let text = if is_active {
                            egui::RichText::new(display)
                                .strong()
                                .underline()
                                .color(active_link_color)
                        } else {
                            egui::RichText::new(display).underline().color(link_color)
                        };
                        if ui
                            .add(egui::Label::new(text).sense(egui::Sense::click()))
                            .clicked()
                        {
                            next_view = Some(target);
                        }
                        ui.add_space(8.0);
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let is_search = self.view == StoreView::Search;
                        let s_text = if is_search {
                            egui::RichText::new(i18n.text("ext.store.button.search"))
                                .strong()
                                .underline()
                                .color(active_link_color)
                        } else {
                            egui::RichText::new(i18n.text("ext.store.button.search"))
                                .underline()
                                .color(link_color)
                        };
                        if ui
                            .add(egui::Label::new(s_text).sense(egui::Sense::click()))
                            .clicked()
                        {
                            next_view = Some(StoreView::Search);
                        }
                    });
                });
            });

        // Subtle divider below Quick Links
        let sep_rect = ui.available_rect_before_wrap();
        ui.painter().line_segment(
            [
                egui::pos2(sep_rect.left(), sep_rect.top()),
                egui::pos2(sep_rect.right(), sep_rect.top()),
            ],
            egui::Stroke::new(
                1.0_f32,
                if dark {
                    egui::Color32::from_rgb(0x3e, 0x3e, 0x3e)
                } else {
                    egui::Color32::from_rgb(0xdc, 0xdc, 0xdc)
                },
            ),
        );

        // 3. Body Container (Section Title + Inline Filter + Bordered List/Detail Box + Pagination)
        let body_bg = if dark {
            egui::Color32::from_rgb(0x2b, 0x2b, 0x2b)
        } else {
            egui::Color32::from_rgb(0xf7, 0xf7, 0xf7)
        };
        let frame_border = if dark {
            egui::Color32::from_rgb(0x55, 0x62, 0x69)
        } else {
            egui::Color32::from_rgb(0x4a, 0x4a, 0x4a)
        };
        let row_divider = if dark {
            egui::Color32::from_rgb(0x45, 0x55, 0x5e)
        } else {
            egui::Color32::from_rgb(0xa3, 0xc3, 0xd4)
        };
        let row_even = if dark {
            egui::Color32::from_rgb(0x26, 0x33, 0x3a)
        } else {
            egui::Color32::from_rgb(0xee, 0xfb, 0xff)
        };
        let row_odd = if dark {
            egui::Color32::from_rgb(0x2e, 0x3f, 0x48)
        } else {
            egui::Color32::from_rgb(0xc7, 0xeb, 0xfc)
        };
        let muted_fg = if dark {
            egui::Color32::from_rgb(0xa8, 0xb6, 0xbe)
        } else {
            egui::Color32::from_rgb(0x4a, 0x55, 0x5c)
        };

        let mut total_pages: usize = 1;
        let mut total_items: usize = 0;
        let mut show_pagination = false;

        egui::Frame::none()
            .fill(body_bg)
            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
            .show(ui, |ui| {
                // Section title + quick live search bar (instant filter on list views!)
                let is_list_view = matches!(
                    self.view,
                    StoreView::Recent
                        | StoreView::Popular
                        | StoreView::NewReleases
                        | StoreView::Category(_)
                        | StoreView::Search
                );
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(&section_title)
                            .size(16.0)
                            .strong()
                            .color(if dark {
                                egui::Color32::from_rgb(0xc8, 0xd4, 0xda)
                            } else {
                                egui::Color32::from_rgb(0x90, 0x96, 0x9b)
                            }),
                    );
                    if is_list_view {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if !self.search.is_empty() && ui.small_button("✕").clicked() {
                                self.search.clear();
                                self.page = 0;
                            }
                            let search_resp = ui.add(
                                egui::TextEdit::singleline(&mut self.search)
                                    .desired_width(170.0)
                                    .hint_text(format!("🔍 {}", i18n.text("rust.store.search"))),
                            );
                            if search_resp.changed() {
                                self.page = 0;
                            }
                        });
                    }
                });

                // Extra filter controls on Search view
                if self.view == StoreView::Search {
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        let prev = (
                            self.os.clone(),
                            self.client.clone(),
                            self.framework.clone(),
                            self.category.clone(),
                            self.sort,
                            self.reverse,
                            self.outdated,
                        );
                        egui::ComboBox::from_id_salt("store-sort-v2")
                            .width(120.0)
                            .selected_text(i18n.text(sort_key(self.sort)))
                            .show_ui(ui, |ui| {
                                for order in [
                                    Sort::LastUpdated,
                                    Sort::Rating,
                                    Sort::NewReleases,
                                    Sort::Alphabetical,
                                ] {
                                    ui.selectable_value(
                                        &mut self.sort,
                                        order,
                                        i18n.text(sort_key(order)),
                                    );
                                }
                            });
                        egui::ComboBox::from_id_salt("store-os-v2")
                            .width(96.0)
                            .selected_text(if self.os.is_empty() {
                                i18n.text("rust.store.all_systems")
                            } else {
                                self.os.clone()
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.os,
                                    String::new(),
                                    i18n.text("rust.store.all_systems"),
                                );
                                for name in ["Windows", "Linux", "Mac"] {
                                    ui.selectable_value(&mut self.os, name.into(), name);
                                }
                            });
                        egui::ComboBox::from_id_salt("store-client-v2")
                            .width(96.0)
                            .selected_text(if self.client.is_empty() {
                                i18n.text("rust.store.all_clients")
                            } else {
                                self.client.clone()
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.client,
                                    String::new(),
                                    i18n.text("rust.store.all_clients"),
                                );
                                for name in ["Flash", "Nitro", "Unity", "Shockwave"] {
                                    ui.selectable_value(&mut self.client, name.into(), name);
                                }
                            });
                        if let Some(catalog) = &self.catalog {
                            egui::ComboBox::from_id_salt("store-fw-v2")
                                .width(110.0)
                                .selected_text(if self.framework.is_empty() {
                                    i18n.text("rust.store.all_frameworks")
                                } else {
                                    self.framework.clone()
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut self.framework,
                                        String::new(),
                                        i18n.text("rust.store.all_frameworks"),
                                    );
                                    for fw in &catalog.config.frameworks {
                                        ui.selectable_value(
                                            &mut self.framework,
                                            fw.name.clone(),
                                            &fw.name,
                                        );
                                    }
                                });
                            egui::ComboBox::from_id_salt("store-cat-v2")
                                .width(110.0)
                                .selected_text(if self.category.is_empty() {
                                    i18n.text("rust.store.all_categories")
                                } else {
                                    self.category.clone()
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut self.category,
                                        String::new(),
                                        i18n.text("rust.store.all_categories"),
                                    );
                                    for cat in &catalog.config.categories {
                                        ui.selectable_value(
                                            &mut self.category,
                                            cat.name.clone(),
                                            &cat.name,
                                        );
                                    }
                                });
                        }
                        ui.checkbox(&mut self.outdated, i18n.text("rust.store.outdated"));
                        ui.checkbox(&mut self.reverse, i18n.text("rust.store.reverse"));
                        if prev
                            != (
                                self.os.clone(),
                                self.client.clone(),
                                self.framework.clone(),
                                self.category.clone(),
                                self.sort,
                                self.reverse,
                                self.outdated,
                            )
                        {
                            self.page = 0;
                        }
                    });
                }

                ui.add_space(6.0);

                // Reserve space for pagination footer
                let list_h = (ui.available_height() - 42.0).max(200.0);

                // Rounded bordered content box (exact screenshot style)
                egui::Frame::none()
                    .fill(if dark {
                        egui::Color32::from_rgb(0x21, 0x2b, 0x31)
                    } else {
                        egui::Color32::WHITE
                    })
                    .stroke(egui::Stroke::new(1.2_f32, frame_border))
                    .rounding(egui::Rounding::same(5.0))
                    .inner_margin(egui::Margin::same(1.0))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        egui::ScrollArea::vertical()
                            .id_salt("store_main_box")
                            .max_height(list_h)
                            .show(ui, |ui| {
                                ui.set_min_height(list_h);
                                ui.spacing_mut().item_spacing.y = 0.0;

                                match self.view.clone() {
                                    StoreView::Installed => {
                                        if self.installed.is_empty() {
                                            ui.add_space(28.0);
                                            ui.vertical_centered(|ui| {
                                                ui.label(
                                                    egui::RichText::new(
                                                        i18n.text("ext.store.overview.description"),
                                                    )
                                                    .color(muted_fg),
                                                );
                                            });
                                        } else {
                                            let installed_clone = self.installed.clone();
                                            let catalog_clone = self.catalog.clone();
                                            for (idx, record) in
                                                installed_clone.iter().enumerate()
                                            {
                                                let bg = if idx % 2 == 0 {
                                                    row_even
                                                } else {
                                                    row_odd
                                                };
                                                let catalog_ext = catalog_clone.as_ref().and_then(
                                                    |c| {
                                                        c.extensions
                                                            .iter()
                                                            .find(|e| e.title == record.title)
                                                    },
                                                );
                                                let update_available =
                                                    catalog_ext.is_some_and(|e| {
                                                        extension_store::compare_versions(
                                                            &e.version,
                                                            &record.version,
                                                        )
                                                        .is_gt()
                                                    });
                                                    let icon_tex = if let (Some(cat), Some(ext)) =
                                                        (&catalog_clone, catalog_ext)
                                                    {
                                                        self.request_image(
                                                            format!("icon:{}", ext.title),
                                                            cat.icon_url(ext),
                                                        )
                                                    } else {
                                                        None
                                                    };
                                                let row_resp = egui::Frame::none()
                                                    .fill(bg)
                                                    .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                                                    .show(ui, |ui| {
                                                        ui.horizontal(|ui| {
                                                            draw_ext_icon(
                                                                ui,
                                                                icon_tex.as_ref(),
                                                                &record.title,
                                                                38.0,
                                                            );
                                                            ui.add_space(8.0);
                                                            ui.vertical(|ui| {
                                                                ui.horizontal(|ui| {
                                                                    let title_resp = ui.add(
                                                                        egui::Label::new(
                                                                            egui::RichText::new(
                                                                                &record.title,
                                                                            )
                                                                            .size(14.0)
                                                                            .strong(),
                                                                        )
                                                                        .sense(egui::Sense::click()),
                                                                    );
                                                                    if catalog_ext.is_some()
                                                                        && title_resp.clicked()
                                                                    {
                                                                        next_view = Some(
                                                                            StoreView::Details(
                                                                                record
                                                                                    .title
                                                                                    .clone(),
                                                                            ),
                                                                        );
                                                                    }
                                                                    if update_available {
                                                                        ui.colored_label(
                                                                            egui::Color32::from_rgb(
                                                                                210, 120, 15,
                                                                            ),
                                                                            "⬆ Update",
                                                                        );
                                                                    }
                                                                });
                                                                ui.label(
                                                                    egui::RichText::new(format!(
                                                                        "{}: {}",
                                                                        i18n.text(
                                                                            "ext.store.extension.version"
                                                                        ),
                                                                        record.version
                                                                    ))
                                                                    .small()
                                                                    .color(muted_fg),
                                                                );
                                                            });
                                                            ui.with_layout(
                                                                egui::Layout::right_to_left(
                                                                    egui::Align::Center,
                                                                ),
                                                                |ui| {
                                                                    if ui
                                                                        .add_enabled(
                                                                            ready,
                                                                            egui::Button::new(
                                                                                i18n.text(
                                                                                    "rust.store.uninstall",
                                                                                ),
                                                                            ),
                                                                        )
                                                                        .clicked()
                                                                    {
                                                                        action =
                                                                            Some(Action::Remove(
                                                                                Box::new(
                                                                                    record.clone(),
                                                                                ),
                                                                            ));
                                                                    }
                                                                    if let Some(ext) = catalog_ext {
                                                                        if update_available
                                                                            && ui
                                                                                .add_enabled(
                                                                                    ready,
                                                                                    egui::Button::new(
                                                                                        i18n.text(
                                                                                            "ext.store.button.update",
                                                                                        ),
                                                                                    ),
                                                                                )
                                                                                .clicked()
                                                                        {
                                                                            action = Some(
                                                                                Action::Install(
                                                                                    Box::new(
                                                                                        ext.clone(),
                                                                                    ),
                                                                                ),
                                                                            );
                                                                        }
                                                                    }
                                                                    if ui
                                                                        .add_enabled(
                                                                            host.is_some(),
                                                                            egui::Button::new(
                                                                                i18n.text(
                                                                                    "rust.store.launch",
                                                                                ),
                                                                            ),
                                                                        )
                                                                        .clicked()
                                                                    {
                                                                        action =
                                                                            Some(Action::Launch(
                                                                                Box::new(
                                                                                    record.clone(),
                                                                                ),
                                                                            ));
                                                                    }
                                                                },
                                                            );
                                                        });
                                                    });
                                                let r = row_resp.response.rect;
                                                ui.painter().line_segment(
                                                    [r.left_bottom(), r.right_bottom()],
                                                    egui::Stroke::new(1.0_f32, row_divider),
                                                );
                                            }
                                        }
                                    }
                                    StoreView::Categories => {
                                        if let Some(catalog) = self.catalog.clone() {
                                            for (idx, cat) in
                                                catalog.config.categories.iter().enumerate()
                                            {
                                                let bg = if idx % 2 == 0 {
                                                    row_even
                                                } else {
                                                    row_odd
                                                };
                                                let count = catalog
                                                    .extensions
                                                    .iter()
                                                    .filter(|e| {
                                                        !e.outdated
                                                            && e.categories
                                                                .iter()
                                                                .any(|c| c == &cat.name)
                                                    })
                                                    .count();
                                                let row_resp = egui::Frame::none()
                                                    .fill(bg)
                                                    .inner_margin(egui::Margin::symmetric(
                                                        10.0, 8.0,
                                                    ))
                                                    .show(ui, |ui| {
                                                        ui.set_width(ui.available_width());
                                                        ui.horizontal(|ui| {
                                                            ui.vertical(|ui| {
                                                                ui.label(
                                                                    egui::RichText::new(&cat.name)
                                                                        .size(14.0)
                                                                        .strong(),
                                                                );
                                                                ui.label(
                                                                    egui::RichText::new(
                                                                        &cat.description,
                                                                    )
                                                                    .small()
                                                                    .color(muted_fg),
                                                                );
                                                            });
                                                            ui.with_layout(
                                                                egui::Layout::right_to_left(
                                                                    egui::Align::Center,
                                                                ),
                                                                |ui| {
                                                                    ui.label(
                                                                        egui::RichText::new(
                                                                            format!(
                                                                                "{count} →"
                                                                            ),
                                                                        )
                                                                        .strong()
                                                                        .color(link_color),
                                                                    );
                                                                },
                                                            );
                                                        });
                                                    });
                                                let r = row_resp.response.rect;
                                                ui.painter().line_segment(
                                                    [r.left_bottom(), r.right_bottom()],
                                                    egui::Stroke::new(1.0_f32, row_divider),
                                                );
                                                if ui
                                                    .interact(
                                                        r,
                                                        ui.id().with(("cat_row", idx)),
                                                        egui::Sense::click(),
                                                    )
                                                    .clicked()
                                                {
                                                    next_view =
                                                        Some(StoreView::Category(cat.name.clone()));
                                                }
                                            }
                                        } else {
                                            ui.add_space(36.0);
                                            ui.vertical_centered(|ui| {
                                                ui.spinner();
                                                ui.label("Loading extension catalogue...");
                                            });
                                        }
                                    }
                                    StoreView::Details(title) => {
                                        if let Some(catalog) = self.catalog.clone() {
                                            if let Some(ext) = catalog
                                                .extensions
                                                .iter()
                                                .find(|e| e.title == title)
                                                .cloned()
                                            {
                                                let screenshot_key =
                                                    format!("screenshot:{}", ext.title);
                                                let screenshot_tex = self.request_image(
                                                    screenshot_key,
                                                    catalog.screenshot_url(&ext),
                                                );
                                                let install_status =
                                                    extension_store::install_status(
                                                        &catalog,
                                                        &ext,
                                                        &self.installed,
                                                    );
                                                let installed_record = self
                                                    .installed
                                                    .iter()
                                                    .find(|r| {
                                                        r.source == catalog.source
                                                            && r.title == ext.title
                                                    })
                                                    .cloned();
                                                egui::Frame::none()
                                                    .inner_margin(egui::Margin::same(12.0))
                                                    .show(ui, |ui| {
                                                        // Top action bar: Rating + Elapsed + Install/Launch/Uninstall
                                                        ui.horizontal_wrapped(|ui| {
                                                            ui.label(
                                                                egui::RichText::new(format!(
                                                                    "★ {} {}",
                                                                    ext.rating,
                                                                    i18n.text(
                                                                        "ext.store.extension.rating"
                                                                    )
                                                                ))
                                                                .strong(),
                                                            );
                                                            if let Some(rel) = format_elapsed(
                                                                &ext.update_date,
                                                                i18n,
                                                            ) {
                                                                ui.label(
                                                                    egui::RichText::new(format!(
                                                                        "· {}",
                                                                        i18n.text(
                                                                            "ext.store.extension.lastupdated"
                                                                        )
                                                                        .replace("%s", &rel)
                                                                    ))
                                                                    .color(muted_fg),
                                                                );
                                                            }
                                                            ui.with_layout(
                                                                egui::Layout::right_to_left(
                                                                    egui::Align::Center,
                                                                ),
                                                                |ui| {
                                                                    let btn_label = match install_status
                                                                    {
                                                                        InstallStatus::Installed => {
                                                                            i18n.text(
                                                                                "ext.store.button.installed",
                                                                            )
                                                                        }
                                                                        InstallStatus::UpdateAvailable => {
                                                                            i18n.text(
                                                                                "ext.store.button.update",
                                                                            )
                                                                        }
                                                                        InstallStatus::OlderVersion => {
                                                                            i18n.text(
                                                                                "rust.store.install_older",
                                                                            )
                                                                        }
                                                                        InstallStatus::NotInstalled => {
                                                                            i18n.text(
                                                                                "ext.store.button.install",
                                                                            )
                                                                        }
                                                                    };
                                                                    let btn_fill = match install_status
                                                                    {
                                                                        InstallStatus::Installed => {
                                                                            egui::Color32::from_rgb(
                                                                                0x39, 0x84, 0x39,
                                                                            )
                                                                        }
                                                                        InstallStatus::UpdateAvailable => {
                                                                            egui::Color32::from_rgb(
                                                                                0xd5, 0x85, 0x12,
                                                                            )
                                                                        }
                                                                        _ => egui::Color32::from_rgb(
                                                                            0x1e, 0x7e, 0xb8,
                                                                        ),
                                                                    };
                                                                    if ui
                                                                        .add_enabled(
                                                                            ready
                                                                                && install_status
                                                                                    != InstallStatus::Installed,
                                                                            egui::Button::new(
                                                                                egui::RichText::new(
                                                                                    btn_label,
                                                                                )
                                                                                .color(
                                                                                    egui::Color32::WHITE,
                                                                                )
                                                                                .strong(),
                                                                            )
                                                                            .fill(btn_fill)
                                                                            .min_size(egui::vec2(
                                                                                104.0, 28.0,
                                                                            )),
                                                                        )
                                                                        .clicked()
                                                                    {
                                                                        action =
                                                                            Some(Action::Install(
                                                                                Box::new(
                                                                                    ext.clone(),
                                                                                ),
                                                                            ));
                                                                    }
                                                                    if let Some(rec) =
                                                                        installed_record
                                                                    {
                                                                        if ui
                                                                            .add_enabled(
                                                                                host.is_some(),
                                                                                egui::Button::new(
                                                                                    i18n.text(
                                                                                        "rust.store.launch",
                                                                                    ),
                                                                                )
                                                                                .min_size(
                                                                                    egui::vec2(
                                                                                        76.0, 28.0,
                                                                                    ),
                                                                                ),
                                                                            )
                                                                            .clicked()
                                                                        {
                                                                            action = Some(
                                                                                Action::Launch(
                                                                                    Box::new(
                                                                                        rec.clone(),
                                                                                    ),
                                                                                ),
                                                                            );
                                                                        }
                                                                        if ui
                                                                            .add_enabled(
                                                                                ready,
                                                                                egui::Button::new(
                                                                                    i18n.text(
                                                                                        "rust.store.uninstall",
                                                                                    ),
                                                                                )
                                                                                .min_size(
                                                                                    egui::vec2(
                                                                                        82.0, 28.0,
                                                                                    ),
                                                                                ),
                                                                            )
                                                                            .clicked()
                                                                        {
                                                                            action = Some(
                                                                                Action::Remove(
                                                                                    Box::new(rec),
                                                                                ),
                                                                            );
                                                                        }
                                                                    }
                                                                },
                                                            );
                                                        });
                                                        ui.add_space(6.0);
                                                        ui.separator();
                                                        ui.add_space(6.0);

                                                        // Warnings
                                                        if !ext.stable {
                                                            ui.colored_label(
                                                                egui::Color32::from_rgb(
                                                                    210, 120, 15,
                                                                ),
                                                                format!(
                                                                    "⚠ {}",
                                                                    i18n.text(
                                                                        "ext.store.extension.warning.unstable"
                                                                    )
                                                                ),
                                                            );
                                                            ui.add_space(4.0);
                                                        }
                                                        if let Some(fw) = catalog
                                                            .config
                                                            .frameworks
                                                            .iter()
                                                            .find(|f| f.name == ext.framework.name)
                                                        {
                                                            if fw.installation.required {
                                                                if let Some(url) = fw
                                                                    .installation
                                                                    .instructions
                                                                    .as_ref()
                                                                    .filter(|u| {
                                                                        u.starts_with("https://")
                                                                    })
                                                                {
                                                                    ui.horizontal_wrapped(|ui| {
                                                                        ui.colored_label(
                                                                            egui::Color32::from_rgb(
                                                                                210, 120, 15,
                                                                            ),
                                                                            format!(
                                                                                "⚠ {} requires runtime setup:",
                                                                                fw.name
                                                                            ),
                                                                        );
                                                                        ui.hyperlink_to(
                                                                            i18n.text(
                                                                                "ext.store.extension.details.click_here",
                                                                            ),
                                                                            url,
                                                                        );
                                                                    });
                                                                    ui.add_space(4.0);
                                                                }
                                                            }
                                                        }

                                                        // Description
                                                        ui.strong(format!(
                                                            "{}:",
                                                            i18n.text(
                                                                "ext.store.extension.details.description"
                                                            )
                                                        ));
                                                        ui.add_space(2.0);
                                                        ui.label(&ext.description);
                                                        ui.add_space(8.0);

                                                        // Technical info grid
                                                        ui.strong(i18n.text(
                                                            "ext.store.extension.details.technical_information",
                                                        ));
                                                        ui.add_space(4.0);
                                                        egui::Grid::new("store_detail_tech_grid")
                                                            .num_columns(2)
                                                            .spacing([12.0, 4.0])
                                                            .show(ui, |ui| {
                                                                ui.label(
                                                                    egui::RichText::new(format!(
                                                                        "{}:",
                                                                        i18n.text(
                                                                            "ext.store.extension.details.authors"
                                                                        )
                                                                    ))
                                                                    .color(muted_fg),
                                                                );
                                                                let authors = ext
                                                                    .authors
                                                                    .iter()
                                                                    .map(|a| {
                                                                        format!(
                                                                            "{} ({} {})",
                                                                            a.name,
                                                                            a.reputation,
                                                                            i18n.text(
                                                                                "ext.store.extension.author.reputation"
                                                                            )
                                                                        )
                                                                    })
                                                                    .collect::<Vec<_>>()
                                                                    .join(", ");
                                                                ui.label(authors);
                                                                ui.end_row();

                                                                ui.label(
                                                                    egui::RichText::new(format!(
                                                                        "{}:",
                                                                        i18n.text(
                                                                            "ext.store.extension.details.framework"
                                                                        )
                                                                    ))
                                                                    .color(muted_fg),
                                                                );
                                                                ui.label(format!(
                                                                    "{} v{} ({})",
                                                                    ext.framework.name,
                                                                    ext.framework.version,
                                                                    ext.language
                                                                ));
                                                                ui.end_row();

                                                                ui.label(
                                                                    egui::RichText::new(format!(
                                                                        "{}:",
                                                                        i18n.text(
                                                                            "ext.store.extension.details.systems"
                                                                        )
                                                                    ))
                                                                    .color(muted_fg),
                                                                );
                                                                ui.label(
                                                                    ext.compatibility
                                                                        .systems
                                                                        .join(", "),
                                                                );
                                                                ui.end_row();

                                                                ui.label(
                                                                    egui::RichText::new(format!(
                                                                        "{}:",
                                                                        i18n.text(
                                                                            "ext.store.extension.details.clients"
                                                                        )
                                                                    ))
                                                                    .color(muted_fg),
                                                                );
                                                                ui.label(
                                                                    ext.compatibility
                                                                        .clients
                                                                        .join(", "),
                                                                );
                                                                ui.end_row();

                                                                ui.label(
                                                                    egui::RichText::new(format!(
                                                                        "{}:",
                                                                        i18n.text(
                                                                            "ext.store.extension.details.categories"
                                                                        )
                                                                    ))
                                                                    .color(muted_fg),
                                                                );
                                                                ui.label(
                                                                    ext.categories.join(", "),
                                                                );
                                                                ui.end_row();
                                                            });

                                                        ui.add_space(6.0);
                                                        ui.horizontal(|ui| {
                                                            for (label, url) in [
                                                                (
                                                                    i18n.text(
                                                                        "ext.store.extension.details.source",
                                                                    ),
                                                                    Some(&ext.source),
                                                                ),
                                                                (
                                                                    "README".into(),
                                                                    ext.readme.as_ref(),
                                                                ),
                                                                (
                                                                    i18n.text(
                                                                        "ext.store.extension.details.releases",
                                                                    ),
                                                                    ext.releases.as_ref(),
                                                                ),
                                                            ] {
                                                                if let Some(url) = url.filter(|u| {
                                                                    u.starts_with("https://")
                                                                }) {
                                                                    ui.hyperlink_to(label, url);
                                                                    ui.add_space(8.0);
                                                                }
                                                            }
                                                        });

                                                        // Lazy-loaded Screenshot
                                                        if let Some(tex) = &screenshot_tex {
                                                            ui.add_space(10.0);
                                                            ui.strong(format!(
                                                                "{}:",
                                                                i18n.text(
                                                                    "ext.store.extension.details.screenshot"
                                                                )
                                                            ));
                                                            ui.add_space(4.0);
                                                            let orig = tex.size_vec2();
                                                            let max_w =
                                                                (ui.available_width() - 8.0)
                                                                    .max(120.0);
                                                            let scale = (max_w / orig.x.max(1.0))
                                                                .min(1.0);
                                                            ui.add(egui::Image::new((
                                                                tex.id(),
                                                                orig * scale,
                                                            )));
                                                        }
                                                    });
                                            }
                                        }
                                    }
                                    // Paginated list views: Recent, Popular, NewReleases, Category, Search
                                    list_view => {
                                        if let Some(catalog) = self.catalog.clone() {
                                            let (sort, cat_filter, os_filter, cli_filter, fw_filter, inc_outdated, rev) =
                                                match &list_view {
                                                    StoreView::Recent => (
                                                        Sort::LastUpdated,
                                                        None,
                                                        Some(current_os_name()),
                                                        None,
                                                        None,
                                                        false,
                                                        false,
                                                    ),
                                                    StoreView::Popular => (
                                                        Sort::Rating,
                                                        None,
                                                        Some(current_os_name()),
                                                        None,
                                                        None,
                                                        false,
                                                        false,
                                                    ),
                                                    StoreView::NewReleases => (
                                                        Sort::NewReleases,
                                                        None,
                                                        Some(current_os_name()),
                                                        None,
                                                        None,
                                                        false,
                                                        false,
                                                    ),
                                                    StoreView::Category(name) => (
                                                        Sort::Rating,
                                                        Some(name.as_str()),
                                                        Some(current_os_name()),
                                                        None,
                                                        None,
                                                        false,
                                                        false,
                                                    ),
                                                    StoreView::Search => (
                                                        self.sort,
                                                        (!self.category.is_empty())
                                                            .then_some(self.category.as_str()),
                                                        (!self.os.is_empty())
                                                            .then_some(self.os.as_str()),
                                                        (!self.client.is_empty())
                                                            .then_some(self.client.as_str()),
                                                        (!self.framework.is_empty())
                                                            .then_some(self.framework.as_str()),
                                                        self.outdated,
                                                        self.reverse,
                                                    ),
                                                    _ => unreachable!(),
                                                };
                                            let query = Query {
                                                text: &self.search,
                                                os: os_filter,
                                                client: cli_filter,
                                                framework: fw_filter,
                                                category: cat_filter,
                                                include_outdated: inc_outdated,
                                                sort,
                                                reverse: rev,
                                            };
                                            let matches: Vec<StoreExtension> = catalog
                                                .query(&query)
                                                .into_iter()
                                                .cloned()
                                                .collect();
                                            total_items = matches.len();
                                            total_pages = total_items.div_ceil(PAGE_SIZE).max(1);
                                            if self.page >= total_pages {
                                                self.page = total_pages - 1;
                                            }
                                            show_pagination = true;

                                            if matches.is_empty() {
                                                ui.add_space(36.0);
                                                ui.vertical_centered(|ui| {
                                                    ui.label(
                                                        egui::RichText::new(
                                                            i18n.text("ext.store.extension.notinstore"),
                                                        )
                                                        .color(muted_fg),
                                                    );
                                                });
                                            } else {
                                                let start = self.page * PAGE_SIZE;
                                                let end = (start + PAGE_SIZE).min(matches.len());
                                                let total_w = ui.available_width();
                                                let meta_w = 136.0;
                                                let left_w = (total_w - meta_w - 2.0).max(200.0);

                                                for (row_idx, ext) in
                                                    matches[start..end].iter().enumerate()
                                                {
                                                    let bg = if row_idx % 2 == 0 {
                                                        row_even
                                                    } else {
                                                        row_odd
                                                    };
                                                    let icon_tex = self.request_image(
                                                        format!("icon:{}", ext.title),
                                                        catalog.icon_url(ext),
                                                    );
                                                    let install_status =
                                                        extension_store::install_status(
                                                            &catalog,
                                                            ext,
                                                            &self.installed,
                                                        );
                                                    let author = ext
                                                        .authors
                                                        .first()
                                                        .map(|a| a.name.as_str())
                                                        .unwrap_or("Unknown");
                                                    let made_by = i18n
                                                        .text("ext.store.extension.madeby")
                                                        .replace("%s", author);
                                                    let subline = match format_elapsed(
                                                        &ext.update_date,
                                                        i18n,
                                                    ) {
                                                        Some(rel) => format!(
                                                            "{made_by}, {}",
                                                            i18n.text(
                                                                "ext.store.extension.lastupdated"
                                                            )
                                                            .replace("%s", &rel)
                                                        ),
                                                        None => made_by,
                                                    };

                                                    let row_resp = egui::Frame::none()
                                                        .fill(bg)
                                                        .inner_margin(egui::Margin::symmetric(
                                                            0.0, 0.0,
                                                        ))
                                                        .show(ui, |ui| {
                                                            ui.horizontal(|ui| {
                                                                ui.spacing_mut().item_spacing.x =
                                                                    0.0;
                                                                // Left area: Icon + Title + Author/Updated
                                                                ui.allocate_ui_with_layout(
                                                                    egui::vec2(left_w, 50.0),
                                                                    egui::Layout::left_to_right(
                                                                        egui::Align::Center,
                                                                    ),
                                                                    |ui| {
                                                                        ui.set_min_width(left_w);
                                                                        ui.set_max_width(left_w);
                                                                        ui.add_space(7.0);
                                                                        draw_ext_icon(
                                                                            ui,
                                                                            icon_tex.as_ref(),
                                                                            &ext.title,
                                                                            38.0,
                                                                        );
                                                                        ui.add_space(8.0);
                                                                        ui.vertical(|ui| {
                                                                            ui.add_space(5.0);
                                                                            ui.horizontal(|ui| {
                                                                                let t_resp = ui.add(
                                                                                    egui::Label::new(
                                                                                        egui::RichText::new(
                                                                                            &ext.title,
                                                                                        )
                                                                                        .size(14.0)
                                                                                        .strong(),
                                                                                    )
                                                                                    .truncate()
                                                                                    .sense(
                                                                                        egui::Sense::click(),
                                                                                    ),
                                                                                );
                                                                                if t_resp.clicked()
                                                                                {
                                                                                    next_view = Some(
                                                                                        StoreView::Details(
                                                                                            ext.title
                                                                                                .clone(),
                                                                                        ),
                                                                                    );
                                                                                }
                                                                                match install_status
                                                                                {
                                                                                    InstallStatus::Installed => {
                                                                                        ui.colored_label(
                                                                                            egui::Color32::from_rgb(
                                                                                                0x2e, 0x8b, 0x57,
                                                                                            ),
                                                                                            "✓",
                                                                                        );
                                                                                    }
                                                                                    InstallStatus::UpdateAvailable => {
                                                                                        ui.colored_label(
                                                                                            egui::Color32::from_rgb(
                                                                                                210, 120, 15,
                                                                                            ),
                                                                                            "⬆",
                                                                                        );
                                                                                    }
                                                                                    _ => {}
                                                                                }
                                                                            });
                                                                            ui.add(
                                                                                egui::Label::new(
                                                                                    egui::RichText::new(
                                                                                        &subline,
                                                                                    )
                                                                                    .size(11.5)
                                                                                    .color(muted_fg),
                                                                                )
                                                                                .truncate(),
                                                                            );
                                                                        });
                                                                    },
                                                                );
                                                                // Right metadata column: Version + Rating (exact screenshot column)
                                                                ui.allocate_ui_with_layout(
                                                                    egui::vec2(meta_w, 50.0),
                                                                    egui::Layout::left_to_right(
                                                                        egui::Align::Center,
                                                                    ),
                                                                    |ui| {
                                                                        ui.set_min_width(meta_w);
                                                                        ui.set_max_width(meta_w);
                                                                        ui.add_space(8.0);
                                                                        ui.vertical(|ui| {
                                                                            ui.add_space(7.0);
                                                                            ui.add(
                                                                                egui::Label::new(
                                                                                    egui::RichText::new(
                                                                                        format!(
                                                                                            "{}: {}",
                                                                                            i18n.text(
                                                                                                "ext.store.extension.version"
                                                                                            ),
                                                                                            ext.version
                                                                                        ),
                                                                                    )
                                                                                    .size(12.0),
                                                                                )
                                                                                .truncate(),
                                                                            );
                                                                            ui.add(
                                                                                egui::Label::new(
                                                                                    egui::RichText::new(
                                                                                        format!(
                                                                                            "{}: {}",
                                                                                            i18n.text(
                                                                                                "ext.store.extension.rating"
                                                                                            ),
                                                                                            ext.rating
                                                                                        ),
                                                                                    )
                                                                                    .size(12.0),
                                                                                )
                                                                                .truncate(),
                                                                            );
                                                                        });
                                                                    },
                                                                );
                                                            });
                                                        });
                                                    let r = row_resp.response.rect;
                                                    // Vertical column divider before Version/Rating (exact screenshot!)
                                                    ui.painter().line_segment(
                                                        [
                                                            egui::pos2(r.left() + left_w, r.top()),
                                                            egui::pos2(
                                                                r.left() + left_w,
                                                                r.bottom(),
                                                            ),
                                                        ],
                                                        egui::Stroke::new(1.0_f32, row_divider),
                                                    );
                                                    // Horizontal row divider
                                                    ui.painter().line_segment(
                                                        [r.left_bottom(), r.right_bottom()],
                                                        egui::Stroke::new(1.0_f32, row_divider),
                                                    );
                                                    // Full-row click opens Details view + subtle hover highlight
                                                    let row_click = ui.interact(
                                                        r,
                                                        ui.id().with(("ext_row", start + row_idx)),
                                                        egui::Sense::click(),
                                                    );
                                                    if row_click.hovered() {
                                                        ui.painter().rect_filled(
                                                            r,
                                                            egui::Rounding::ZERO,
                                                            egui::Color32::from_rgba_unmultiplied(
                                                                255, 255, 255, 18,
                                                            ),
                                                        );
                                                    }
                                                    if row_click.clicked() {
                                                        next_view = Some(StoreView::Details(
                                                            ext.title.clone(),
                                                        ));
                                                    }
                                                }
                                            }
                                        } else {
                                            ui.add_space(36.0);
                                            ui.vertical_centered(|ui| {
                                                ui.spinner();
                                                ui.label("Loading extension catalogue...");
                                            });
                                        }
                                    }
                                }
                            });
                    });

                // 4. Exact beta-29 Pagination Footer: [<<] [<]  1 / 5  [>] [>>]
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if show_pagination {
                        ui.label(
                            egui::RichText::new(format!(
                                "{total_items} {}",
                                i18n.text("rust.store.matches")
                            ))
                            .small()
                            .color(muted_fg),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.spacing_mut().item_spacing.x = 5.0;
                            let can_next = self.page + 1 < total_pages;
                            let can_prev = self.page > 0;
                            let page_btn = |ui: &mut egui::Ui, label: &str, enabled: bool| {
                                ui.add_enabled(
                                    enabled,
                                    egui::Button::new(egui::RichText::new(label).strong())
                                        .min_size(egui::vec2(28.0, 26.0)),
                                )
                                .clicked()
                            };
                            if page_btn(ui, ">>", can_next) {
                                self.page = total_pages - 1;
                            }
                            if page_btn(ui, ">", can_next) {
                                self.page += 1;
                            }
                            ui.add_space(6.0);
                            ui.label(
                                egui::RichText::new(format!("{} / {total_pages}", self.page + 1))
                                    .color(muted_fg),
                            );
                            ui.add_space(6.0);
                            if page_btn(ui, "<", can_prev) {
                                self.page -= 1;
                            }
                            if page_btn(ui, "<<", can_prev) {
                                self.page = 0;
                            }
                        });
                    }
                });
            });

        if refresh_requested {
            self.start_fetch_catalog(status);
        }
        if open_folder_requested {
            if let Err(error) = gearth_platform::open_folder(&self.root) {
                *status = error.to_string();
            }
        }
        if let Some(view) = next_view {
            self.navigate(view);
        }

        match action {
            Some(Action::Install(extension)) => {
                if let Some(catalog) = self.catalog.clone() {
                    let root = self.root.clone();
                    let (sender, receiver) = mpsc::channel();
                    self.worker = Some(receiver);
                    *status = format!("Installing {} {}...", extension.title, extension.version);
                    std::thread::spawn(move || {
                        let result = extension_store::install(&catalog, &extension, &root)
                            .map(|record| Outcome::Installed(Box::new(record)))
                            .map_err(|error| error.to_string());
                        let _ = sender.send(result);
                    });
                }
            }
            Some(Action::Remove(record)) => {
                let root = self.root.clone();
                let (sender, receiver) = mpsc::channel();
                self.worker = Some(receiver);
                std::thread::spawn(move || {
                    let result = extension_store::uninstall(&root, &record)
                        .map(|()| {
                            Outcome::Changed(format!(
                                "Uninstalled {} {}",
                                record.title, record.version
                            ))
                        })
                        .map_err(|error| error.to_string());
                    let _ = sender.send(result);
                });
            }
            Some(Action::Launch(record)) => {
                if let Some(host) = host {
                    let filename = record
                        .directory
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("");
                    match host.launch_command(
                        &record.command,
                        &record.directory.join("extension"),
                        filename,
                        &record.title,
                        java,
                    ) {
                        Ok(process) => {
                            processes.push(process);
                            *status = format!("Launched {} {}", record.title, record.version);
                        }
                        Err(error) => *status = error.to_string(),
                    }
                }
            }
            None => {}
        }
    }
}

fn draw_ext_icon(ui: &mut egui::Ui, tex: Option<&egui::TextureHandle>, title: &str, size: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    if !ui.is_rect_visible(rect) {
        return;
    }
    if let Some(tex) = tex {
        ui.painter().image(
            tex.id(),
            rect,
            egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
            egui::Color32::WHITE,
        );
    } else {
        // Clean monogram placeholder while icon.png loads lazily
        let initial: String = title
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(2)
            .collect::<String>()
            .to_uppercase();
        ui.painter().rect_filled(
            rect,
            egui::Rounding::same(5.0),
            egui::Color32::from_rgb(0x1f, 0x55, 0x6b),
        );
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            if initial.is_empty() { "?" } else { &initial },
            egui::FontId::proportional(size * 0.42),
            egui::Color32::WHITE,
        );
    }
}
