use crate::theme_ui::{vector_icon, vector_icon_button, vector_text_button, VectorIcon};
use eframe::egui;
use gearth_rust::{
    extension_host::ExtensionHost,
    extension_store::{
        self, Catalog, InstallStatus, Installed, MultiCatalog, Query, Sort, StoreExtension,
        StoreSource,
    },
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
    Catalog(MultiCatalog),
    Installed(Box<Installed>),
    Changed(String),
}

enum Action {
    Install(Box<(Catalog, StoreExtension)>),
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
    Sources,
    Details { source: String, title: String },
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
    catalog: Option<MultiCatalog>,
    sources: Vec<StoreSource>,
    source_filter: String,
    new_source_repo: String,
    new_source_version: String,
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
    zoomed_screenshot: Option<(String, String)>,
    notice: Option<(String, bool)>,
}

impl StoreUi {
    pub fn new(root: PathBuf) -> Self {
        let sources = extension_store::load_sources(&root);
        Self {
            root,
            catalog: None,
            sources,
            source_filter: String::new(),
            new_source_repo: String::new(),
            new_source_version: extension_store::STORE_VERSION.into(),
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
            zoomed_screenshot: None,
            notice: None,
        }
    }

    pub fn invalidate(&mut self) {
        self.initialized = false;
    }

    fn refresh(&mut self, status: &mut String) {
        self.sources = extension_store::load_sources(&self.root);
        match extension_store::installed(&self.root) {
            Ok(entries) => self.installed = entries,
            Err(error) => *status = error.to_string(),
        }
    }

    fn start_fetch_catalog(&mut self, status: &mut String) {
        if self.worker.is_some() {
            return;
        }
        let sources = self.sources.clone();
        let (sender, receiver) = mpsc::channel();
        self.worker = Some(receiver);
        *status = "Loading extension catalogues...".into();
        std::thread::spawn(move || {
            let result = MultiCatalog::fetch_many(&sources)
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
        if !matches!(self.view, StoreView::Details { .. } | StoreView::Sources) {
            self.previous_view = self.view.clone();
        }
        self.view = next;
        self.page = 0;
        self.zoomed_screenshot = None;
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
                            let loaded_count = catalog.catalogs.len();
                            let total_ext = catalog.total_extensions();
                            *status = format!(
                                "Loaded {total_ext} store extensions from {loaded_count} source(s)"
                            );
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
                                        let msg = format!(
                                            "Installed & launched {} {}",
                                            record.title, record.version
                                        );
                                        *status = msg.clone();
                                        self.notice = Some((msg, false));
                                    }
                                    Err(error) => {
                                        let msg = format!(
                                            "Installed {} {} (launch failed: {error})",
                                            record.title, record.version
                                        );
                                        *status = msg.clone();
                                        self.notice = Some((msg, true));
                                    }
                                }
                            } else {
                                let msg = format!("Installed {} {}", record.title, record.version);
                                *status = msg.clone();
                                self.notice = Some((msg, false));
                            }
                        }
                        Ok(Outcome::Changed(message)) => {
                            self.notice = Some((message.clone(), false));
                            *status = message;
                            self.refresh(status);
                        }
                        Err(error) => {
                            self.notice = Some((error.clone(), true));
                            *status = error;
                        }
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
        let detail_icon_key = if let (StoreView::Details { source, title }, Some(catalog)) =
            (&self.view, &self.catalog)
        {
            catalog.find(source, title).map(|(cat, ext)| {
                (
                    format!("icon:{}:{}", cat.source, ext.title),
                    cat.icon_url(ext),
                )
            })
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
                    .and_then(|c| {
                        c.merged_categories()
                            .into_iter()
                            .find(|cat| cat.name == *name)
                    })
                    .map(|cat| cat.description)
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
            StoreView::Sources => (
                i18n.text("rust.store.sources_title"),
                i18n.text("rust.store.sources_subtitle"),
                i18n.text("rust.store.sources_section"),
            ),
            StoreView::Details { source, title } => {
                let sub = self
                    .catalog
                    .as_ref()
                    .and_then(|c| c.find(source, title))
                    .map(|(_, e)| {
                        e.description
                            .lines()
                            .next()
                            .unwrap_or(&e.description)
                            .trim()
                            .to_owned()
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
                                            StoreView::Sources => ic.idea.as_ref(),
                                            StoreView::Details { .. } => ic.star.as_ref(),
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
                            StoreView::Details { .. } => {}
                            StoreView::Sources => {
                                if vector_text_button(
                                    ui,
                                    VectorIcon::ArrowLeft,
                                    egui::Color32::WHITE,
                                    &i18n.text("rust.store.back"),
                                    Some(egui::Color32::WHITE),
                                    Some(egui::Color32::from_rgb(0x1f, 0x55, 0x6b)),
                                    false,
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
                                let refresh_clicked = ui
                                    .add_enabled_ui(ready, |ui| {
                                        vector_icon_button(
                                            ui,
                                            VectorIcon::Refresh,
                                            egui::vec2(26.0, 24.0),
                                            13.0,
                                            Some(egui::Color32::from_rgb(0x1f, 0x55, 0x6b)),
                                            egui::Color32::WHITE,
                                        )
                                        .on_hover_text(i18n.text("rust.store.load"))
                                        .clicked()
                                    })
                                    .inner;
                                if refresh_clicked {
                                    refresh_requested = true;
                                }
                                ui.add_space(4.0);
                                if ui
                                    .add(
                                        egui::Button::new(
                                            egui::RichText::new(i18n.text("rust.store.sources"))
                                                .color(egui::Color32::WHITE),
                                        )
                                        .fill(egui::Color32::from_rgb(0x1f, 0x55, 0x6b)),
                                    )
                                    .on_hover_text(i18n.text("rust.store.sources_tooltip"))
                                    .clicked()
                                {
                                    next_view = Some(StoreView::Sources);
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

        let viewport_w = ui.available_width();
        egui::Frame::none()
            .fill(body_bg)
            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
            .show(ui, |ui| {
                let body_w = (viewport_w - 24.0).max(200.0);
                ui.set_min_width(body_w);
                ui.set_max_width(body_w);
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
                            if !self.search.is_empty()
                                && vector_icon_button(
                                    ui,
                                    VectorIcon::Close,
                                    egui::vec2(20.0, 20.0),
                                    9.5,
                                    None,
                                    muted_fg,
                                )
                                .clicked()
                            {
                                self.search.clear();
                                self.page = 0;
                            }
                            let search_resp = ui.add(
                                egui::TextEdit::singleline(&mut self.search)
                                    .desired_width(146.0)
                                    .hint_text(i18n.text("rust.store.search")),
                            );
                            if search_resp.changed() {
                                self.page = 0;
                            }
                            vector_icon(ui, VectorIcon::Search, 13.0, muted_fg);
                            if self.sources.len() > 1 {
                                let prev_src = self.source_filter.clone();
                                let selected_label = if self.source_filter.is_empty() {
                                    i18n.text("rust.store.all_stores")
                                } else {
                                    self.source_filter
                                        .split('/')
                                        .next()
                                        .unwrap_or(&self.source_filter)
                                        .to_owned()
                                };
                                egui::ComboBox::from_id_salt("store-source-filter")
                                    .width(104.0)
                                    .selected_text(selected_label)
                                    .show_ui(ui, |ui| {
                                        ui.selectable_value(
                                            &mut self.source_filter,
                                            String::new(),
                                            i18n.text("rust.store.all_stores"),
                                        );
                                        for src in self.sources.iter().filter(|s| s.enabled) {
                                            ui.selectable_value(
                                                &mut self.source_filter,
                                                src.repo.clone(),
                                                src.display_tag(),
                                            );
                                        }
                                    });
                                if prev_src != self.source_filter {
                                    self.page = 0;
                                }
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
                            let frameworks = catalog.merged_frameworks();
                            let categories = catalog.merged_categories();
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
                                    for fw in &frameworks {
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
                                    for cat in &categories {
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
                if let Some((msg, is_error)) = self.notice.clone() {
                    let (bg, fg) = if is_error {
                        (
                            if dark {
                                egui::Color32::from_rgb(0x4a, 0x1d, 0x1d)
                            } else {
                                egui::Color32::from_rgb(0xfd, 0xe8, 0xe8)
                            },
                            if dark {
                                egui::Color32::from_rgb(0xff, 0xb4, 0xb4)
                            } else {
                                egui::Color32::from_rgb(0x9b, 0x1c, 0x1c)
                            },
                        )
                    } else {
                        (
                            if dark {
                                egui::Color32::from_rgb(0x1b, 0x3b, 0x26)
                            } else {
                                egui::Color32::from_rgb(0xe6, 0xf7, 0xec)
                            },
                            if dark {
                                egui::Color32::from_rgb(0x9f, 0xe6, 0xb8)
                            } else {
                                egui::Color32::from_rgb(0x1b, 0x6b, 0x34)
                            },
                        )
                    };
                    let mut dismiss_notice = false;
                    egui::Frame::none()
                        .fill(bg)
                        .rounding(egui::Rounding::same(4.0))
                        .inner_margin(egui::Margin::symmetric(8.0, 4.0))
                        .show(ui, |ui| {
                            ui.set_min_width((body_w - 16.0).max(160.0));
                            ui.set_max_width((body_w - 16.0).max(160.0));
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::Label::new(egui::RichText::new(&msg).small().color(fg))
                                        .wrap(),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if vector_icon_button(
                                            ui,
                                            VectorIcon::Close,
                                            egui::vec2(18.0, 18.0),
                                            8.5,
                                            None,
                                            fg,
                                        )
                                        .clicked()
                                        {
                                            dismiss_notice = true;
                                        }
                                    },
                                );
                            });
                        });
                    if dismiss_notice {
                        self.notice = None;
                    }
                    ui.add_space(4.0);
                }

                // Reserve space for pagination / action footer
                let notice_h = if self.notice.is_some() { 32.0 } else { 0.0 };
                let list_h = (ui.available_height() - 44.0 - notice_h).max(180.0);
                let is_details_view = matches!(self.view, StoreView::Details { .. });
                let mut detail_footer: Option<(
                    Catalog,
                    StoreExtension,
                    InstallStatus,
                    Option<Installed>,
                )> = None;

                // Rounded bordered content box (exact beta-29 style; grey forum backdrop on Details)
                let box_fill = if is_details_view {
                    if dark {
                        egui::Color32::from_rgb(0x1b, 0x20, 0x24)
                    } else {
                        egui::Color32::from_rgb(0xb8, 0xb6, 0xb2)
                    }
                } else if dark {
                    egui::Color32::from_rgb(0x21, 0x2b, 0x31)
                } else {
                    egui::Color32::WHITE
                };
                egui::Frame::none()
                    .fill(box_fill)
                    .stroke(egui::Stroke::new(1.2_f32, frame_border))
                    .rounding(egui::Rounding::same(5.0))
                    .inner_margin(egui::Margin::same(1.0))
                    .show(ui, |ui| {
                        let inner_box_w = (body_w - 4.0).max(200.0);
                        ui.set_min_width(inner_box_w);
                        ui.set_max_width(inner_box_w);
                        egui::ScrollArea::vertical()
                            .id_salt("store_main_box")
                            .max_height(list_h)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.set_min_height(list_h);
                                ui.set_max_width(inner_box_w);
                                ui.spacing_mut().item_spacing.y = 0.0;

                                match self.view.clone() {
                                    StoreView::Sources => {
                                        let mut sources_changed = false;
                                        let mut remove_idx: Option<usize> = None;
                                        let statuses = self
                                            .catalog
                                            .as_ref()
                                            .map(|c| c.statuses.clone())
                                            .unwrap_or_default();
                                        egui::Frame::none()
                                            .inner_margin(egui::Margin::same(12.0))
                                            .show(ui, |ui| {
                                                for (idx, src) in
                                                    self.sources.iter_mut().enumerate()
                                                {
                                                    let bg = if idx % 2 == 0 {
                                                        row_even
                                                    } else {
                                                        row_odd
                                                    };
                                                    let st = statuses
                                                        .iter()
                                                        .find(|s| s.repo == src.repo);
                                                    let is_builtin = src.repo
                                                        == extension_store::STORE_SOURCE
                                                        || src.repo
                                                            == extension_store::CUSTOM_STORE_SOURCE;
                                                    egui::Frame::none()
                                                        .fill(bg)
                                                        .inner_margin(egui::Margin::symmetric(
                                                            8.0, 6.0,
                                                        ))
                                                        .show(ui, |ui| {
                                                            ui.horizontal(|ui| {
                                                                if ui
                                                                    .checkbox(&mut src.enabled, "")
                                                                    .changed()
                                                                {
                                                                    sources_changed = true;
                                                                }
                                                                ui.vertical(|ui| {
                                                                    ui.horizontal(|ui| {
                                                                        ui.strong(&src.repo);
                                                                        ui.label(
                                                                            egui::RichText::new(
                                                                                format!(
                                                                                    "({})",
                                                                                    src.version
                                                                                ),
                                                                            )
                                                                            .small()
                                                                            .color(muted_fg),
                                                                        );
                                                                    });
                                                                    if !src.enabled {
                                                                        ui.label(
                                                                            egui::RichText::new(
                                                                                i18n.text(
                                                                                    "rust.store.disabled",
                                                                                ),
                                                                            )
                                                                            .small()
                                                                            .color(muted_fg),
                                                                        );
                                                                    } else if let Some(s) = st {
                                                                        if let Some(err) = &s.error
                                                                        {
                                                                            let warn_col =
                                                                                egui::Color32::from_rgb(
                                                                                    210, 120, 15,
                                                                                );
                                                                            ui.horizontal(|ui| {
                                                                                ui.spacing_mut()
                                                                                    .item_spacing
                                                                                    .x = 5.0;
                                                                                vector_icon(
                                                                                    ui,
                                                                                    VectorIcon::Warning,
                                                                                    12.0,
                                                                                    warn_col,
                                                                                );
                                                                                ui.colored_label(
                                                                                    warn_col,
                                                                                    i18n.text(
                                                                                        "rust.store.unavailable",
                                                                                    ),
                                                                                )
                                                                                .on_hover_text(err);
                                                                            });
                                                                        } else {
                                                                            let r = s
                                                                                .loaded_ref
                                                                                .as_deref()
                                                                                .unwrap_or(
                                                                                    &s.version,
                                                                                );
                                                                            let ok_col =
                                                                                egui::Color32::from_rgb(
                                                                                    0x2e, 0x8b, 0x57,
                                                                                );
                                                                            ui.horizontal(|ui| {
                                                                                ui.spacing_mut()
                                                                                    .item_spacing
                                                                                    .x = 5.0;
                                                                                vector_icon(
                                                                                    ui,
                                                                                    VectorIcon::Check,
                                                                                    12.0,
                                                                                    ok_col,
                                                                                );
                                                                                ui.colored_label(
                                                                                    ok_col,
                                                                                    format!(
                                                                                        "{} extension(s) via {r}",
                                                                                        s.extension_count
                                                                                    ),
                                                                                );
                                                                            });
                                                                        }
                                                                    }
                                                                });
                                                                if !is_builtin {
                                                                    ui.with_layout(
                                                                        egui::Layout::right_to_left(
                                                                            egui::Align::Center,
                                                                        ),
                                                                        |ui| {
                                                                            if vector_icon_button(
                                                                                ui,
                                                                                VectorIcon::Close,
                                                                                egui::vec2(
                                                                                    20.0, 20.0,
                                                                                ),
                                                                                9.5,
                                                                                None,
                                                                                muted_fg,
                                                                            )
                                                                            .clicked()
                                                                            {
                                                                                remove_idx =
                                                                                    Some(idx);
                                                                            }
                                                                        },
                                                                    );
                                                                }
                                                            });
                                                        });
                                                    ui.add_space(4.0);
                                                }
                                                if let Some(idx) = remove_idx {
                                                    let removed = self.sources.remove(idx);
                                                    if self.source_filter == removed.repo {
                                                        self.source_filter.clear();
                                                    }
                                                    sources_changed = true;
                                                }
                                                ui.add_space(8.0);
                                                ui.separator();
                                                ui.add_space(8.0);
                                                ui.strong(i18n.text("rust.store.add_repo_title"));
                                                ui.add_space(4.0);
                                                ui.horizontal(|ui| {
                                                    ui.add(
                                                        egui::TextEdit::singleline(
                                                            &mut self.new_source_repo,
                                                        )
                                                        .desired_width(210.0)
                                                        .hint_text("owner/G-ExtensionStore"),
                                                    );
                                                    ui.add(
                                                        egui::TextEdit::singleline(
                                                            &mut self.new_source_version,
                                                        )
                                                        .desired_width(80.0)
                                                        .hint_text("1.5.3 / main"),
                                                    );
                                                    if ui
                                                        .button(i18n.text("rust.store.add"))
                                                        .clicked()
                                                    {
                                                        let repo =
                                                            self.new_source_repo.trim().to_owned();
                                                        let version = if self
                                                            .new_source_version
                                                            .trim()
                                                            .is_empty()
                                                        {
                                                            extension_store::STORE_VERSION
                                                                .to_owned()
                                                        } else {
                                                            self.new_source_version
                                                                .trim()
                                                                .to_owned()
                                                        };
                                                        match extension_store::validate_source(
                                                            &repo, &version,
                                                        ) {
                                                            Ok(()) => {
                                                                if !self.sources.iter().any(|s| {
                                                                    s.repo
                                                                        .eq_ignore_ascii_case(&repo)
                                                                }) {
                                                                    self.sources.push(
                                                                        StoreSource::new(
                                                                            repo, version,
                                                                        ),
                                                                    );
                                                                    self.new_source_repo.clear();
                                                                    sources_changed = true;
                                                                }
                                                            }
                                                            Err(err) => {
                                                                *status = err.to_string();
                                                            }
                                                        }
                                                    }
                                                    if ui
                                                        .button(
                                                            i18n.text("rust.store.reset_defaults"),
                                                        )
                                                        .clicked()
                                                    {
                                                        self.sources =
                                                            extension_store::default_sources();
                                                        self.source_filter.clear();
                                                        sources_changed = true;
                                                    }
                                                });
                                                ui.add_space(10.0);
                                                ui.label(
                                                    egui::RichText::new(
                                                        i18n.text("rust.store.repo_layout_hint"),
                                                    )
                                                    .small()
                                                    .color(muted_fg),
                                                );
                                            });
                                        if sources_changed {
                                            if let Err(err) = extension_store::save_sources(
                                                &self.root,
                                                &self.sources,
                                            ) {
                                                *status = err.to_string();
                                            }
                                            refresh_requested = true;
                                        }
                                    }
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
                                                let matched = catalog_clone
                                                    .as_ref()
                                                    .and_then(|c| {
                                                        c.find(&record.source, &record.title)
                                                    })
                                                    .map(|(cat, ext)| (cat.clone(), ext.clone()));
                                                let update_available =
                                                    matched.as_ref().is_some_and(|(_, e)| {
                                                        extension_store::compare_versions(
                                                            &e.version,
                                                            &record.version,
                                                        )
                                                        .is_gt()
                                                    });
                                                let icon_tex = matched.as_ref().and_then(
                                                    |(cat, ext)| {
                                                        self.request_image(
                                                            format!(
                                                                "icon:{}:{}",
                                                                cat.source, ext.title
                                                            ),
                                                            cat.icon_url(ext),
                                                        )
                                                    },
                                                );
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
                                                                    if matched.is_some()
                                                                        && title_resp.clicked()
                                                                    {
                                                                        next_view = Some(
                                                                            StoreView::Details {
                                                                                source: record
                                                                                    .source
                                                                                    .clone(),
                                                                                title: record
                                                                                    .title
                                                                                    .clone(),
                                                                            },
                                                                        );
                                                                    }
                                                                    if record.source
                                                                        != extension_store::STORE_SOURCE
                                                                    {
                                                                        draw_source_badge(
                                                                            ui,
                                                                            &record.source,
                                                                        );
                                                                    }
                                                                    if update_available {
                                                                        let up_col = egui::Color32::from_rgb(
                                                                            210, 120, 15,
                                                                        );
                                                                        vector_icon(
                                                                            ui,
                                                                            VectorIcon::UpdateArrow,
                                                                            12.0,
                                                                            up_col,
                                                                        );
                                                                        ui.colored_label(
                                                                            up_col,
                                                                            i18n.text(
                                                                                "ext.store.button.update",
                                                                            ),
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
                                                                    if let Some((cat, ext)) =
                                                                        &matched
                                                                    {
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
                                                                                    Box::new((
                                                                                        cat.clone(),
                                                                                        ext.clone(),
                                                                                    )),
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
                                            let categories = catalog.merged_categories();
                                            for (idx, cat) in categories.iter().enumerate() {
                                                let bg = if idx % 2 == 0 {
                                                    row_even
                                                } else {
                                                    row_odd
                                                };
                                                let count: usize = catalog
                                                    .catalogs
                                                    .iter()
                                                    .filter(|c| {
                                                        self.source_filter.is_empty()
                                                            || c.source == self.source_filter
                                                    })
                                                    .flat_map(|c| c.extensions.iter())
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
                                                                    vector_icon(
                                                                        ui,
                                                                        VectorIcon::ArrowRight,
                                                                        12.0,
                                                                        link_color,
                                                                    );
                                                                    ui.add_space(4.0);
                                                                    ui.label(
                                                                        egui::RichText::new(
                                                                            format!("{count}"),
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
                                                ui.label(i18n.text("rust.store.loading"));
                                            });
                                        }
                                    }
                                    StoreView::Details { source, title } => {
                                        if let Some(multi) = self.catalog.clone() {
                                            if let Some((catalog, ext)) = multi
                                                .find(&source, &title)
                                                .map(|(c, e)| (c.clone(), e.clone()))
                                            {
                                                let screenshot_key = format!(
                                                    "screenshot:{}:{}",
                                                    catalog.source, ext.title
                                                );
                                                let screenshot_tex = self.request_image(
                                                    screenshot_key.clone(),
                                                    catalog.screenshot_url(&ext),
                                                );
                                                let main_author = ext.authors.first().cloned();
                                                let avatar_tex = main_author
                                                    .as_ref()
                                                    .and_then(|a| {
                                                        a.avatar_url().map(|url| {
                                                            (
                                                                format!(
                                                                    "avatar:{}:{}",
                                                                    a.hotel
                                                                        .as_deref()
                                                                        .unwrap_or(""),
                                                                    a.username
                                                                        .as_deref()
                                                                        .unwrap_or(&a.name)
                                                                ),
                                                                url,
                                                            )
                                                        })
                                                    })
                                                    .and_then(|(k, url)| self.request_image(k, url));
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
                                                detail_footer = Some((
                                                    catalog.clone(),
                                                    ext.clone(),
                                                    install_status,
                                                    installed_record,
                                                ));

                                                let post_header_bg = if dark {
                                                    egui::Color32::from_rgb(0x23, 0x5c, 0x85)
                                                } else {
                                                    egui::Color32::from_rgb(0x31, 0x79, 0xac)
                                                };
                                                let author_col_bg = if dark {
                                                    egui::Color32::from_rgb(0x1b, 0x38, 0x45)
                                                } else {
                                                    egui::Color32::from_rgb(0xc8, 0xef, 0xf8)
                                                };
                                                let content_col_bg = if dark {
                                                    egui::Color32::from_rgb(0x22, 0x29, 0x2e)
                                                } else {
                                                    egui::Color32::WHITE
                                                };
                                                let quote_bg = if dark {
                                                    egui::Color32::from_rgb(0x31, 0x39, 0x40)
                                                } else {
                                                    egui::Color32::from_rgb(0xcc, 0xcc, 0xcc)
                                                };
                                                let author_muted = if dark {
                                                    egui::Color32::from_rgb(0xb2, 0xcb, 0xd6)
                                                } else {
                                                    egui::Color32::from_rgb(0x44, 0x44, 0x44)
                                                };
                                                let time_label =
                                                    format_elapsed(&ext.update_date, i18n)
                                                        .map(|rel| {
                                                            i18n.text("rust.store.time_ago")
                                                                .replace("%s", &rel)
                                                        })
                                                        .unwrap_or_else(|| ext.update_date.clone());

                                                // 1) Classic Habbo forum blue header bar (#3179ac)
                                                let detail_w = (inner_box_w - 12.0).max(240.0);
                                                egui::Frame::none()
                                                    .fill(post_header_bg)
                                                    .inner_margin(egui::Margin::symmetric(8.0, 5.0))
                                                    .show(ui, |ui| {
                                                        ui.set_min_width((detail_w - 16.0).max(200.0));
                                                        ui.set_max_width((detail_w - 16.0).max(200.0));
                                                        ui.horizontal(|ui| {
                                                            ui.label(
                                                                egui::RichText::new(&time_label)
                                                                    .size(12.5)
                                                                    .color(egui::Color32::WHITE),
                                                            );
                                                            ui.with_layout(
                                                                egui::Layout::right_to_left(
                                                                    egui::Align::Center,
                                                                ),
                                                                |ui| {
                                                                    let star_col =
                                                                        egui::Color32::from_rgb(
                                                                            0xff, 0xf3, 0xb0,
                                                                        );
                                                                    ui.label(
                                                                        egui::RichText::new(
                                                                            format!(
                                                                                "{} {}",
                                                                                ext.rating,
                                                                                i18n.text(
                                                                                    "ext.store.extension.rating"
                                                                                )
                                                                            ),
                                                                        )
                                                                        .size(12.0)
                                                                        .strong()
                                                                        .color(star_col),
                                                                    );
                                                                    vector_icon(
                                                                        ui,
                                                                        VectorIcon::Star,
                                                                        12.0,
                                                                        star_col,
                                                                    );
                                                                    if catalog.source
                                                                        != extension_store::STORE_SOURCE
                                                                    {
                                                                        ui.add_space(6.0);
                                                                        draw_source_badge(
                                                                            ui,
                                                                            &catalog.source,
                                                                        );
                                                                    }
                                                                },
                                                            );
                                                        });
                                                    });

                                                // 2) Forum post two-column body:
                                                //    Left 136px light-blue author sidebar + Right white content area
                                                let total_w = detail_w;
                                                let author_w = 136.0_f32;
                                                let right_w = (total_w - author_w).max(200.0);
                                                let bg_content_idx =
                                                    ui.painter().add(egui::Shape::Noop);
                                                let bg_author_idx =
                                                    ui.painter().add(egui::Shape::Noop);
                                                let body_resp = ui.horizontal_top(|ui| {
                                                    ui.spacing_mut().item_spacing.x = 0.0;
                                                    // Left author sidebar (.cb_author)
                                                    ui.allocate_ui_with_layout(
                                                        egui::vec2(author_w, 0.0),
                                                        egui::Layout::top_down(egui::Align::LEFT),
                                                        |ui| {
                                                            ui.set_min_width(author_w);
                                                            ui.set_max_width(author_w);
                                                            egui::Frame::none()
                                                                .inner_margin(egui::Margin::same(
                                                                    8.0,
                                                                ))
                                                                .show(ui, |ui| {
                                                                    if let Some(author) =
                                                                        &main_author
                                                                    {
                                                                        ui.label(
                                                                            egui::RichText::new(
                                                                                &author.name,
                                                                            )
                                                                            .size(13.0)
                                                                            .strong(),
                                                                        );
                                                                        ui.add_space(2.0);
                                                                        ui.label(
                                                                            egui::RichText::new(
                                                                                format!(
                                                                                    "{} {}",
                                                                                    author.reputation,
                                                                                    i18n.text(
                                                                                        "ext.store.extension.author.reputation"
                                                                                    )
                                                                                ),
                                                                            )
                                                                            .size(12.0)
                                                                            .color(author_muted),
                                                                        );
                                                                        ui.label(
                                                                            egui::RichText::new(
                                                                                format!(
                                                                                    "{} {}",
                                                                                    author
                                                                                        .extensions_count,
                                                                                    i18n.text(
                                                                                        "ext.store.extension.author.releases"
                                                                                    )
                                                                                ),
                                                                            )
                                                                            .size(12.0)
                                                                            .color(author_muted),
                                                                        );
                                                                        ui.add_space(4.0);
                                                                        if let Some(tex) =
                                                                            &avatar_tex
                                                                        {
                                                                            let sz = tex.size_vec2();
                                                                            let scale = (110.0_f32
                                                                                / sz.x.max(1.0))
                                                                                .min(1.0);
                                                                            ui.add(
                                                                                egui::Image::new((
                                                                                    tex.id(),
                                                                                    sz * scale,
                                                                                )),
                                                                            );
                                                                        }
                                                                        if let Some(discord) = author
                                                                            .discord
                                                                            .as_deref()
                                                                            .filter(|s| {
                                                                                !s.trim().is_empty()
                                                                            })
                                                                        {
                                                                            ui.add_space(4.0);
                                                                            ui.label(
                                                                                egui::RichText::new(
                                                                                    discord,
                                                                                )
                                                                                .size(10.5)
                                                                                .color(author_muted),
                                                                            );
                                                                        }
                                                                    }
                                                                });
                                                        },
                                                    );

                                                    // Right post content (.cb_content)
                                                    ui.allocate_ui_with_layout(
                                                        egui::vec2(right_w, 0.0),
                                                        egui::Layout::top_down(egui::Align::LEFT),
                                                        |ui| {
                                                            ui.set_min_width(right_w);
                                                            ui.set_max_width(right_w);
                                                            egui::Frame::none()
                                                                .inner_margin(egui::Margin::symmetric(
                                                                    12.0, 8.0,
                                                                ))
                                                                .show(ui, |ui| {
                                                                    ui.spacing_mut()
                                                                        .item_spacing
                                                                        .y = 4.0;
                                                                    // Title - vX.Y.Z
                                                                    ui.horizontal_wrapped(|ui| {
                                                                        ui.spacing_mut()
                                                                            .item_spacing
                                                                            .x = 0.0;
                                                                        ui.label(
                                                                            egui::RichText::new(
                                                                                &ext.title,
                                                                            )
                                                                            .size(13.5)
                                                                            .strong(),
                                                                        );
                                                                        ui.label(
                                                                            egui::RichText::new(
                                                                                format!(
                                                                                    " - v{}",
                                                                                    ext.version
                                                                                ),
                                                                            )
                                                                            .size(13.5),
                                                                        );
                                                                    });
                                                                    ui.add_space(4.0);

                                                                    // Description + grey quote box (.cbc_quote)
                                                                    ui.label(
                                                                        egui::RichText::new(
                                                                            format!(
                                                                                "{}:",
                                                                                i18n.text(
                                                                                    "ext.store.extension.details.description"
                                                                                )
                                                                            ),
                                                                        )
                                                                        .size(12.5)
                                                                        .strong(),
                                                                    );
                                                                    let quote_w = (right_w - 52.0).max(140.0);
                                                                    ui.indent("ext_desc_quote", |ui| {
                                                                        egui::Frame::none()
                                                                            .fill(quote_bg)
                                                                            .rounding(
                                                                                egui::Rounding::same(
                                                                                    2.0,
                                                                                ),
                                                                            )
                                                                            .inner_margin(
                                                                                egui::Margin::same(
                                                                                    7.0,
                                                                                ),
                                                                            )
                                                                            .show(ui, |ui| {
                                                                                ui.set_min_width(quote_w);
                                                                                ui.set_max_width(quote_w);
                                                                                ui.add(
                                                                                    egui::Label::new(
                                                                                        egui::RichText::new(
                                                                                            &ext.description,
                                                                                        )
                                                                                        .size(12.5),
                                                                                    )
                                                                                    .wrap(),
                                                                                );
                                                                                if let Some(url) = ext
                                                                                    .readme
                                                                                    .as_deref()
                                                                                    .filter(|u| {
                                                                                        u.starts_with(
                                                                                            "https://",
                                                                                        )
                                                                                    })
                                                                                {
                                                                                    ui.add_space(
                                                                                        6.0,
                                                                                    );
                                                                                    ui.hyperlink_to(
                                                                                        "README",
                                                                                        url,
                                                                                    );
                                                                                }
                                                                            });
                                                                    });
                                                                    ui.add_space(6.0);

                                                                    // Auteur(s):
                                                                    ui.horizontal_wrapped(|ui| {
                                                                        ui.label(
                                                                            egui::RichText::new(
                                                                                format!(
                                                                                    "{}: ",
                                                                                    i18n.text(
                                                                                        "ext.store.extension.details.authors"
                                                                                    )
                                                                                ),
                                                                            )
                                                                            .size(12.5)
                                                                            .strong(),
                                                                        );
                                                                        let names = ext
                                                                            .authors
                                                                            .iter()
                                                                            .map(|a| {
                                                                                a.name.as_str()
                                                                            })
                                                                            .collect::<Vec<_>>()
                                                                            .join(", ");
                                                                        ui.label(
                                                                            egui::RichText::new(
                                                                                names,
                                                                            )
                                                                            .size(12.5),
                                                                        );
                                                                    });
                                                                    ui.add_space(2.0);

                                                                    // Catégories: (clickable links!)
                                                                    ui.horizontal_wrapped(|ui| {
                                                                        ui.label(
                                                                            egui::RichText::new(
                                                                                format!(
                                                                                    "{}: ",
                                                                                    i18n.text(
                                                                                        "ext.store.extension.details.categories"
                                                                                    )
                                                                                ),
                                                                            )
                                                                            .size(12.5)
                                                                            .strong(),
                                                                        );
                                                                        for (ci, cat_name) in ext
                                                                            .categories
                                                                            .iter()
                                                                            .enumerate()
                                                                        {
                                                                            if ci > 0 {
                                                                                ui.label(",");
                                                                            }
                                                                            if ui
                                                                                .add(
                                                                                    egui::Label::new(
                                                                                        egui::RichText::new(
                                                                                            cat_name,
                                                                                        )
                                                                                        .size(12.5)
                                                                                        .underline()
                                                                                        .color(
                                                                                            link_color,
                                                                                        ),
                                                                                    )
                                                                                    .sense(
                                                                                        egui::Sense::click(),
                                                                                    ),
                                                                                )
                                                                                .clicked()
                                                                            {
                                                                                next_view = Some(
                                                                                    StoreView::Category(
                                                                                        cat_name
                                                                                            .clone(),
                                                                                    ),
                                                                                );
                                                                            }
                                                                        }
                                                                    });
                                                                    ui.add_space(6.0);

                                                                    // Information technique + second grey quote box
                                                                    ui.label(
                                                                        egui::RichText::new(
                                                                            i18n.text(
                                                                                "ext.store.extension.details.technical_information",
                                                                            ),
                                                                        )
                                                                        .size(12.5)
                                                                        .strong(),
                                                                    );
                                                                    let click_here = i18n.text(
                                                                        "ext.store.extension.details.click_here",
                                                                    );
                                                                    ui.indent("ext_tech_quote", |ui| {
                                                                        egui::Frame::none()
                                                                            .fill(quote_bg)
                                                                            .rounding(
                                                                                egui::Rounding::same(
                                                                                    2.0,
                                                                                ),
                                                                            )
                                                                            .inner_margin(
                                                                                egui::Margin::same(
                                                                                    7.0,
                                                                                ),
                                                                            )
                                                                            .show(ui, |ui| {
                                                                                ui.set_min_width(quote_w);
                                                                                ui.set_max_width(quote_w);
                                                                                ui.spacing_mut()
                                                                                    .item_spacing
                                                                                    .y = 3.0;
                                                                                if let Some(url) = ext
                                                                                    .releases
                                                                                    .as_deref()
                                                                                    .filter(|u| {
                                                                                        u.starts_with(
                                                                                            "https://",
                                                                                        )
                                                                                    })
                                                                                {
                                                                                    ui.horizontal_wrapped(
                                                                                        |ui| {
                                                                                            ui.label(
                                                                                                egui::RichText::new(
                                                                                                    format!(
                                                                                                        "{}: ",
                                                                                                        i18n.text(
                                                                                                            "ext.store.extension.details.releases"
                                                                                                        )
                                                                                                    ),
                                                                                                )
                                                                                                .size(12.5),
                                                                                            );
                                                                                            ui.hyperlink_to(
                                                                                                &click_here,
                                                                                                url,
                                                                                            );
                                                                                        },
                                                                                    );
                                                                                }
                                                                                ui.add(
                                                                                    egui::Label::new(
                                                                                        egui::RichText::new(
                                                                                            format!(
                                                                                                "{}: {}",
                                                                                                i18n.text(
                                                                                                    "ext.store.extension.details.language"
                                                                                                ),
                                                                                                ext.language
                                                                                            ),
                                                                                        )
                                                                                        .size(12.5),
                                                                                    )
                                                                                    .wrap(),
                                                                                );
                                                                                if ext
                                                                                    .source
                                                                                    .starts_with(
                                                                                        "https://",
                                                                                    )
                                                                                {
                                                                                    ui.horizontal_wrapped(
                                                                                        |ui| {
                                                                                            ui.label(
                                                                                                egui::RichText::new(
                                                                                                    format!(
                                                                                                        "{}: ",
                                                                                                        i18n.text(
                                                                                                            "ext.store.extension.details.source"
                                                                                                        )
                                                                                                    ),
                                                                                                )
                                                                                                .size(12.5),
                                                                                            );
                                                                                            ui.hyperlink_to(
                                                                                                &click_here,
                                                                                                &ext.source,
                                                                                            );
                                                                                        },
                                                                                    );
                                                                                }
                                                                                ui.add(
                                                                                    egui::Label::new(
                                                                                        egui::RichText::new(
                                                                                            format!(
                                                                                                "{}: {} - v{}",
                                                                                                i18n.text(
                                                                                                    "ext.store.extension.details.framework"
                                                                                                ),
                                                                                                ext.framework.name,
                                                                                                ext.framework.version
                                                                                            ),
                                                                                        )
                                                                                        .size(12.5),
                                                                                    )
                                                                                    .wrap(),
                                                                                );
                                                                                ui.add(
                                                                                    egui::Label::new(
                                                                                        egui::RichText::new(
                                                                                            format!(
                                                                                                "{}: {}",
                                                                                                i18n.text(
                                                                                                    "ext.store.extension.details.systems"
                                                                                                ),
                                                                                                ext.compatibility
                                                                                                    .systems
                                                                                                    .join(", ")
                                                                                            ),
                                                                                        )
                                                                                        .size(12.5),
                                                                                    )
                                                                                    .wrap(),
                                                                                );
                                                                                if catalog.source
                                                                                    != extension_store::STORE_SOURCE
                                                                                {
                                                                                    ui.add(
                                                                                        egui::Label::new(
                                                                                            egui::RichText::new(
                                                                                                format!(
                                                                                                    "Store: {}",
                                                                                                    catalog.source
                                                                                                ),
                                                                                            )
                                                                                            .size(12.5),
                                                                                        )
                                                                                        .wrap(),
                                                                                    );
                                                                                }
                                                                            });
                                                                    });
                                                                    ui.add_space(6.0);

                                                                    // Clients compatibles:
                                                                    ui.horizontal_wrapped(|ui| {
                                                                        ui.label(
                                                                            egui::RichText::new(
                                                                                format!(
                                                                                    "{}: ",
                                                                                    i18n.text(
                                                                                        "ext.store.extension.details.clients"
                                                                                    )
                                                                                ),
                                                                            )
                                                                            .size(12.5)
                                                                            .strong(),
                                                                        );
                                                                        ui.label(
                                                                            egui::RichText::new(
                                                                                ext.compatibility
                                                                                    .clients
                                                                                    .join(", "),
                                                                            )
                                                                            .size(12.5),
                                                                        );
                                                                    });

                                                                    // Warnings (framework requirement + unstable)
                                                                    if let Some(fw) = catalog
                                                                        .config
                                                                        .frameworks
                                                                        .iter()
                                                                        .find(|f| {
                                                                            f.name
                                                                                == ext
                                                                                    .framework
                                                                                    .name
                                                                        })
                                                                    {
                                                                        if fw.installation.required
                                                                        {
                                                                            if let Some(url) = fw
                                                                                .installation
                                                                                .instructions
                                                                                .as_deref()
                                                                                .filter(|u| {
                                                                                    u.starts_with(
                                                                                        "https://",
                                                                                    )
                                                                                })
                                                                            {
                                                                                ui.add_space(4.0);
                                                                                let warn_col = egui::Color32::from_rgb(
                                                                                    210, 120, 15,
                                                                                );
                                                                                ui.horizontal_wrapped(
                                                                                    |ui| {
                                                                                        vector_icon(
                                                                                            ui,
                                                                                            VectorIcon::Warning,
                                                                                            12.5,
                                                                                            warn_col,
                                                                                        );
                                                                                        ui.colored_label(
                                                                                            warn_col,
                                                                                            format!(
                                                                                                "{}:",
                                                                                                fw.name
                                                                                            ),
                                                                                        );
                                                                                        ui.hyperlink_to(
                                                                                            &click_here,
                                                                                            url,
                                                                                        );
                                                                                    },
                                                                                );
                                                                            }
                                                                        }
                                                                    }
                                                                    if !ext.stable {
                                                                        ui.add_space(4.0);
                                                                        let warn_col = egui::Color32::from_rgb(
                                                                            210, 120, 15,
                                                                        );
                                                                        ui.horizontal_wrapped(
                                                                            |ui| {
                                                                                vector_icon(
                                                                                    ui,
                                                                                    VectorIcon::Warning,
                                                                                    12.5,
                                                                                    warn_col,
                                                                                );
                                                                                ui.colored_label(
                                                                                    warn_col,
                                                                                    i18n.text(
                                                                                        "ext.store.extension.warning.unstable",
                                                                                    ),
                                                                                );
                                                                            },
                                                                        );
                                                                    }

                                                                    // Screenshot with crisp 1px black border + click-to-zoom
                                                                    if let Some(tex) =
                                                                        &screenshot_tex
                                                                    {
                                                                        ui.add_space(8.0);
                                                                        ui.label(
                                                                            egui::RichText::new(
                                                                                format!(
                                                                                    "{}:",
                                                                                    i18n.text(
                                                                                        "ext.store.extension.details.screenshot"
                                                                                    )
                                                                                ),
                                                                            )
                                                                            .size(12.5)
                                                                            .strong(),
                                                                        );
                                                                        ui.add_space(2.0);
                                                                        let orig = tex.size_vec2();
                                                                        let max_w = (ui
                                                                            .available_width()
                                                                            - 12.0)
                                                                            .clamp(120.0, 450.0);
                                                                        let scale = (max_w
                                                                            / orig.x.max(1.0))
                                                                            .min(1.0);
                                                                        let img_resp =
                                                                            egui::Frame::none()
                                                                                .stroke(
                                                                                    egui::Stroke::new(
                                                                                        1.0_f32,
                                                                                        egui::Color32::BLACK,
                                                                                    ),
                                                                                )
                                                                                .show(ui, |ui| {
                                                                                    ui.add(
                                                                                        egui::Image::new((
                                                                                            tex.id(),
                                                                                            orig * scale,
                                                                                        ))
                                                                                        .sense(
                                                                                            egui::Sense::click(),
                                                                                        ),
                                                                                    )
                                                                                })
                                                                                .inner;
                                                                        if img_resp
                                                                            .on_hover_text(
                                                                                i18n.text(
                                                                                    "rust.store.click_enlarge",
                                                                                ),
                                                                            )
                                                                            .clicked()
                                                                        {
                                                                            self.zoomed_screenshot =
                                                                                Some((
                                                                                    ext.title
                                                                                        .clone(),
                                                                                    screenshot_key,
                                                                                ));
                                                                        }
                                                                    }
                                                                    ui.add_space(6.0);
                                                                });
                                                        },
                                                    );
                                                });
                                                let post_rect = body_resp.response.rect;
                                                let author_rect = egui::Rect::from_min_max(
                                                    post_rect.min,
                                                    egui::pos2(
                                                        (post_rect.left() + author_w)
                                                            .min(post_rect.right()),
                                                        post_rect.bottom(),
                                                    ),
                                                );
                                                ui.painter().set(
                                                    bg_content_idx,
                                                    egui::Shape::rect_filled(
                                                        post_rect,
                                                        egui::Rounding::ZERO,
                                                        content_col_bg,
                                                    ),
                                                );
                                                ui.painter().set(
                                                    bg_author_idx,
                                                    egui::Shape::rect_filled(
                                                        author_rect,
                                                        egui::Rounding::ZERO,
                                                        author_col_bg,
                                                    ),
                                                );
                                            }
                                        }
                                    }
                                    // Paginated list views: Recent, Popular, NewReleases, Category, Search
                                    list_view => {
                                        if let Some(multi) = self.catalog.clone() {
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
                                            let source_filter = (!self.source_filter.is_empty())
                                                .then_some(self.source_filter.as_str());
                                            let matches: Vec<(Catalog, StoreExtension)> = multi
                                                .query(&query, source_filter)
                                                .into_iter()
                                                .map(|(cat, ext)| (cat.clone(), ext.clone()))
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

                                                for (row_idx, (catalog, ext)) in
                                                    matches[start..end].iter().enumerate()
                                                {
                                                    let bg = if row_idx % 2 == 0 {
                                                        row_even
                                                    } else {
                                                        row_odd
                                                    };
                                                    let icon_tex = self.request_image(
                                                        format!(
                                                            "icon:{}:{}",
                                                            catalog.source, ext.title
                                                        ),
                                                        catalog.icon_url(ext),
                                                    );
                                                    let install_status =
                                                        extension_store::install_status(
                                                            catalog,
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
                                                                                        StoreView::Details {
                                                                                            source: catalog
                                                                                                .source
                                                                                                .clone(),
                                                                                            title: ext
                                                                                                .title
                                                                                                .clone(),
                                                                                        },
                                                                                    );
                                                                                }
                                                                                if catalog.source
                                                                                    != extension_store::STORE_SOURCE
                                                                                {
                                                                                    ui.add_space(4.0);
                                                                                    draw_source_badge(
                                                                                        ui,
                                                                                        &catalog.source,
                                                                                    );
                                                                                }
                                                                                match install_status
                                                                                {
                                                                                    InstallStatus::Installed => {
                                                                                        ui.add_space(
                                                                                            4.0,
                                                                                        );
                                                                                        vector_icon(
                                                                                            ui,
                                                                                            VectorIcon::Check,
                                                                                            12.0,
                                                                                            egui::Color32::from_rgb(
                                                                                                0x2e, 0x8b, 0x57,
                                                                                            ),
                                                                                        )
                                                                                        .on_hover_text(
                                                                                            i18n.text(
                                                                                                "rust.store.installed",
                                                                                            ),
                                                                                        );
                                                                                    }
                                                                                    InstallStatus::UpdateAvailable => {
                                                                                        ui.add_space(
                                                                                            4.0,
                                                                                        );
                                                                                        vector_icon(
                                                                                            ui,
                                                                                            VectorIcon::UpdateArrow,
                                                                                            12.0,
                                                                                            egui::Color32::from_rgb(
                                                                                                210, 120, 15,
                                                                                            ),
                                                                                        )
                                                                                        .on_hover_text(
                                                                                            i18n.text(
                                                                                                "ext.store.button.update",
                                                                                            ),
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
                                                        next_view = Some(StoreView::Details {
                                                            source: catalog.source.clone(),
                                                            title: ext.title.clone(),
                                                        });
                                                    }
                                                }
                                            }
                                        } else {
                                            ui.add_space(36.0);
                                            ui.vertical_centered(|ui| {
                                                ui.spinner();
                                                ui.label(i18n.text("rust.store.loading"));
                                            });
                                        }
                                    }
                                }
                            });
                    });

                // 4. Exact beta-29 Chunky Habbo Footer: [Return] ... [Launch][Uninstall][Install]
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.set_min_width(body_w);
                    ui.set_max_width(body_w);
                    if let Some((catalog, ext, install_status, installed_record)) = detail_footer {
                        if habbo_forum_button(
                            ui,
                            &i18n.text("rust.store.return"),
                            egui::vec2(98.0, 27.0),
                            true,
                            HabboBtnStyle::Grey,
                            dark,
                        ) {
                            next_view = Some(self.previous_view.clone());
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            let (btn_label, btn_style) = match install_status {
                                InstallStatus::Installed => (
                                    i18n.text("ext.store.button.installed"),
                                    HabboBtnStyle::Green,
                                ),
                                InstallStatus::UpdateAvailable => (
                                    i18n.text("ext.store.button.update"),
                                    HabboBtnStyle::Amber,
                                ),
                                InstallStatus::OlderVersion => (
                                    i18n.text("rust.store.install_older"),
                                    HabboBtnStyle::Blue,
                                ),
                                InstallStatus::NotInstalled => {
                                    (i18n.text("ext.store.button.install"), HabboBtnStyle::Blue)
                                }
                            };
                            if habbo_forum_button(
                                ui,
                                &btn_label,
                                egui::vec2(108.0, 27.0),
                                ready && install_status != InstallStatus::Installed,
                                btn_style,
                                dark,
                            ) {
                                action = Some(Action::Install(Box::new((catalog, ext))));
                            }
                            if let Some(rec) = installed_record {
                                if habbo_forum_button(
                                    ui,
                                    &i18n.text("rust.store.launch"),
                                    egui::vec2(78.0, 27.0),
                                    host.is_some(),
                                    HabboBtnStyle::Grey,
                                    dark,
                                ) {
                                    action = Some(Action::Launch(Box::new(rec.clone())));
                                }
                                if habbo_forum_button(
                                    ui,
                                    &i18n.text("rust.store.uninstall"),
                                    egui::vec2(88.0, 27.0),
                                    ready,
                                    HabboBtnStyle::Grey,
                                    dark,
                                ) {
                                    action = Some(Action::Remove(Box::new(rec)));
                                }
                            }
                        });
                    } else if show_pagination {
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
                            if habbo_forum_button(
                                ui,
                                ">>",
                                egui::vec2(28.0, 27.0),
                                can_next,
                                HabboBtnStyle::White,
                                dark,
                            ) {
                                self.page = total_pages - 1;
                            }
                            if habbo_forum_button(
                                ui,
                                ">",
                                egui::vec2(28.0, 27.0),
                                can_next,
                                HabboBtnStyle::White,
                                dark,
                            ) {
                                self.page += 1;
                            }
                            ui.add_space(6.0);
                            ui.label(
                                egui::RichText::new(format!("{} / {total_pages}", self.page + 1))
                                    .color(muted_fg),
                            );
                            ui.add_space(6.0);
                            if habbo_forum_button(
                                ui,
                                "<",
                                egui::vec2(28.0, 27.0),
                                can_prev,
                                HabboBtnStyle::White,
                                dark,
                            ) {
                                self.page -= 1;
                            }
                            if habbo_forum_button(
                                ui,
                                "<<",
                                egui::vec2(28.0, 27.0),
                                can_prev,
                                HabboBtnStyle::White,
                                dark,
                            ) {
                                self.page = 0;
                            }
                        });
                    }
                });
            });

        // Full-size screenshot zoom modal ("voir mieux")
        if let Some((zoom_title, zoom_key)) = self.zoomed_screenshot.clone() {
            if let Some(Some(tex)) = self.remote_textures.get(&zoom_key).cloned() {
                let mut open = true;
                egui::Window::new(format!("Screenshot — {zoom_title}"))
                    .id(egui::Id::new("store_screenshot_zoom"))
                    .open(&mut open)
                    .collapsible(false)
                    .resizable(true)
                    .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                    .show(ui.ctx(), |ui| {
                        let screen = ui.ctx().screen_rect().size() - egui::vec2(60.0, 90.0);
                        let orig = tex.size_vec2();
                        let scale = (screen.x / orig.x.max(1.0))
                            .min(screen.y / orig.y.max(1.0))
                            .min(1.0);
                        ui.add(egui::Image::new((tex.id(), orig * scale)));
                    });
                if !open {
                    self.zoomed_screenshot = None;
                }
            }
        }

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
            Some(Action::Install(pair)) => {
                let (catalog, extension) = *pair;
                if let Some(host) = host {
                    for ext in host.extensions() {
                        if ext.info.title.eq_ignore_ascii_case(&extension.title) {
                            let _ = host.disconnect(ext.id);
                        }
                    }
                }
                let root = self.root.clone();
                let (sender, receiver) = mpsc::channel();
                self.worker = Some(receiver);
                self.notice = None;
                *status = format!("Installing {} {}...", extension.title, extension.version);
                std::thread::spawn(move || {
                    let result = extension_store::install(&catalog, &extension, &root)
                        .map(|record| Outcome::Installed(Box::new(record)))
                        .map_err(|error| error.to_string());
                    let _ = sender.send(result);
                });
            }
            Some(Action::Remove(record)) => {
                if let Some(host) = host {
                    let dir_name = record
                        .directory
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");
                    for ext in host.extensions() {
                        let matches_file =
                            !dir_name.is_empty() && ext.info.file.as_deref() == Some(dir_name);
                        let matches_title = ext.info.title.eq_ignore_ascii_case(&record.title);
                        if matches_file || matches_title {
                            let _ = host.disconnect(ext.id);
                        }
                    }
                }
                let root = self.root.clone();
                let (sender, receiver) = mpsc::channel();
                self.worker = Some(receiver);
                self.notice = None;
                *status = format!("Uninstalling {} {}...", record.title, record.version);
                std::thread::spawn(move || {
                    let mut last_err = None;
                    for attempt in 0..16 {
                        if attempt > 0 {
                            std::thread::sleep(std::time::Duration::from_millis(150));
                        }
                        match extension_store::uninstall(&root, &record) {
                            Ok(()) => {
                                last_err = None;
                                break;
                            }
                            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                                last_err = None;
                                break;
                            }
                            Err(err) => {
                                last_err = Some(err);
                            }
                        }
                    }
                    let result = match last_err {
                        None => Ok(Outcome::Changed(format!(
                            "Uninstalled {} {}",
                            record.title, record.version
                        ))),
                        Some(error) => Err(format!(
                            "Could not uninstall {} (close the extension first if still running): {error}",
                            record.title
                        )),
                    };
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
                            let msg = format!("Launched {} {}", record.title, record.version);
                            *status = msg.clone();
                            self.notice = Some((msg, false));
                        }
                        Err(error) => {
                            let msg = error.to_string();
                            *status = msg.clone();
                            self.notice = Some((msg, true));
                        }
                    }
                }
            }
            None => {}
        }
    }
}

#[derive(Clone, Copy)]
enum HabboBtnStyle {
    Grey,
    Blue,
    Green,
    Amber,
    White,
}

/// Chunky Habbo forum button matching beta-29 `buttons.css` (`.forumbtn` + inner lower bevel).
fn habbo_forum_button(
    ui: &mut egui::Ui,
    label: &str,
    size: egui::Vec2,
    enabled: bool,
    style: HabboBtnStyle,
    dark: bool,
) -> bool {
    let sense = if enabled {
        egui::Sense::click()
    } else {
        egui::Sense::hover()
    };
    let (rect, resp) = ui.allocate_exact_size(size, sense);
    if ui.is_rect_visible(rect) {
        let hovered = enabled && resp.hovered();
        let active = enabled && resp.is_pointer_button_down_on();
        let (top_fill, bot_fill, border_col, text_col) = match (style, enabled, dark) {
            (HabboBtnStyle::Blue, true, _) => (
                if active {
                    egui::Color32::from_rgb(0x24, 0x87, 0xac)
                } else if hovered {
                    egui::Color32::from_rgb(0x2d, 0xa3, 0xce)
                } else {
                    egui::Color32::from_rgb(0x27, 0x92, 0xb9)
                },
                egui::Color32::from_rgb(0x22, 0x82, 0xa5),
                egui::Color32::BLACK,
                egui::Color32::WHITE,
            ),
            (HabboBtnStyle::Blue, false, _) => (
                egui::Color32::from_rgb(0x3d, 0x88, 0x9d),
                egui::Color32::from_rgb(0x35, 0x77, 0x8a),
                egui::Color32::from_rgb(0x35, 0x5b, 0x64),
                egui::Color32::from_rgb(0xee, 0xf7, 0xfa),
            ),
            (HabboBtnStyle::Green, _, _) => (
                egui::Color32::from_rgb(0x39, 0x84, 0x39),
                egui::Color32::from_rgb(0x2f, 0x6f, 0x2f),
                egui::Color32::from_rgb(0x1f, 0x45, 0x1f),
                egui::Color32::WHITE,
            ),
            (HabboBtnStyle::Amber, _, _) => (
                if hovered {
                    egui::Color32::from_rgb(0xe3, 0x92, 0x1c)
                } else {
                    egui::Color32::from_rgb(0xd5, 0x85, 0x12)
                },
                egui::Color32::from_rgb(0xb8, 0x71, 0x0d),
                egui::Color32::BLACK,
                egui::Color32::WHITE,
            ),
            (HabboBtnStyle::Grey, true, false) => (
                if hovered {
                    egui::Color32::from_rgb(0xdc, 0xdc, 0xdc)
                } else {
                    egui::Color32::from_rgb(0xd1, 0xd1, 0xd1)
                },
                egui::Color32::from_rgb(0xbb, 0xbb, 0xbb),
                egui::Color32::BLACK,
                egui::Color32::from_rgb(0x14, 0x14, 0x14),
            ),
            (HabboBtnStyle::Grey, true, true) => (
                if hovered {
                    egui::Color32::from_rgb(0x4b, 0x52, 0x57)
                } else {
                    egui::Color32::from_rgb(0x3e, 0x45, 0x4a)
                },
                egui::Color32::from_rgb(0x31, 0x37, 0x3b),
                egui::Color32::from_rgb(0x12, 0x15, 0x17),
                egui::Color32::WHITE,
            ),
            (HabboBtnStyle::Grey, false, _) => (
                egui::Color32::from_rgb(0x9a, 0x9a, 0x9a),
                egui::Color32::from_rgb(0x88, 0x88, 0x88),
                egui::Color32::from_rgb(0x55, 0x55, 0x55),
                egui::Color32::from_rgb(0xd8, 0xd8, 0xd8),
            ),
            (HabboBtnStyle::White, true, false) => (
                if hovered {
                    egui::Color32::WHITE
                } else {
                    egui::Color32::from_rgb(0xf3, 0xf3, 0xf3)
                },
                egui::Color32::from_rgb(0xd9, 0xd9, 0xd9),
                egui::Color32::BLACK,
                egui::Color32::from_rgb(0x14, 0x14, 0x14),
            ),
            (HabboBtnStyle::White, true, true) => (
                if hovered {
                    egui::Color32::from_rgb(0x4a, 0x51, 0x56)
                } else {
                    egui::Color32::from_rgb(0x3c, 0x43, 0x48)
                },
                egui::Color32::from_rgb(0x2f, 0x35, 0x39),
                egui::Color32::from_rgb(0x12, 0x15, 0x17),
                egui::Color32::WHITE,
            ),
            (HabboBtnStyle::White, false, false) => (
                egui::Color32::from_rgb(0xc3, 0xc3, 0xc1),
                egui::Color32::from_rgb(0xb8, 0xb8, 0xb6),
                egui::Color32::from_rgb(0x7a, 0x7a, 0x7a),
                egui::Color32::from_rgb(0x50, 0x50, 0x50),
            ),
            (HabboBtnStyle::White, false, true) => (
                egui::Color32::from_rgb(0x2b, 0x30, 0x34),
                egui::Color32::from_rgb(0x25, 0x2a, 0x2d),
                egui::Color32::from_rgb(0x45, 0x4c, 0x52),
                egui::Color32::from_rgb(0x72, 0x7a, 0x80),
            ),
        };
        let painter = ui.painter();
        let rounding = egui::Rounding::same(4.0);
        // Outer crisp Habbo frame + subtle bottom drop bevel
        painter.rect_filled(rect, rounding, border_col);
        let inner = rect.shrink2(egui::vec2(1.8, 1.8));
        painter.rect_filled(inner, egui::Rounding::same(2.5), bot_fill);
        let top_half = egui::Rect::from_min_max(
            inner.min,
            egui::pos2(inner.right(), inner.top() + inner.height() * 0.52),
        );
        painter.rect_filled(top_half, egui::Rounding::same(2.0), top_fill);
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            label,
            egui::FontId::proportional(12.5),
            text_col,
        );
    }
    enabled && resp.clicked()
}

fn draw_source_badge(ui: &mut egui::Ui, source: &str) {
    let tag = source.split('/').next().unwrap_or(source);
    egui::Frame::none()
        .fill(egui::Color32::from_rgb(0x1f, 0x55, 0x6b))
        .rounding(egui::Rounding::same(3.0))
        .inner_margin(egui::Margin::symmetric(4.0, 1.0))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(tag)
                    .size(10.0)
                    .strong()
                    .color(egui::Color32::WHITE),
            );
        });
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
