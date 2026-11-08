use eframe::egui;
use gearth_rust::{
    extension_host::ExtensionHost,
    extension_store::{self, Catalog, InstallStatus, Installed, Query, Sort, StoreExtension},
    i18n::I18n,
};
use std::{
    path::{Path, PathBuf},
    process::Child,
    sync::{
        mpsc::{self, Receiver},
        Arc,
    },
};
enum Outcome {
    Catalog(Catalog),
    Changed(String),
}
enum Action {
    Install(Box<StoreExtension>),
    Remove(Box<Installed>),
    Launch(Box<Installed>),
}
fn sort_key(sort: Sort) -> &'static str {
    match sort {
        Sort::Rating => "rust.store.sort_rating",
        Sort::Alphabetical => "rust.store.sort_alphabetical",
        Sort::LastUpdated => "rust.store.sort_updated",
        Sort::NewReleases => "rust.store.sort_new",
    }
}
pub struct StoreUi {
    root: PathBuf,
    catalog: Option<Catalog>,
    installed: Vec<Installed>,
    worker: Option<Receiver<Result<Outcome, String>>>,
    initialized: bool,
    search: String,
    sort: Sort,
    outdated: bool,
    reverse: bool,
    os: String,
    client: String,
    framework: String,
    category: String,
}
impl StoreUi {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            catalog: None,
            installed: Vec::new(),
            worker: None,
            initialized: false,
            search: String::new(),
            sort: Sort::Rating,
            outdated: false,
            reverse: false,
            os: String::new(),
            client: String::new(),
            framework: String::new(),
            category: String::new(),
        }
    }
    fn refresh(&mut self, status: &mut String) {
        match extension_store::installed(&self.root) {
            Ok(entries) => self.installed = entries,
            Err(error) => *status = error.to_string(),
        }
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
        if !self.initialized {
            self.refresh(status);
            self.initialized = true;
        }
        if let Some(worker) = &self.worker {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(100));
            match worker.try_recv() {
                Ok(result) => {
                    match result {
                        Ok(Outcome::Catalog(catalog)) => {
                            *status =
                                format!("Loaded {} store extensions", catalog.extensions.len());
                            self.catalog = Some(catalog);
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
        egui::CollapsingHeader::new(i18n.text("rust.store.title"))
            .default_open(true)
            .show(ui, |ui| {
                let ready = self.worker.is_none();
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(ready, egui::Button::new(i18n.text("rust.store.load")))
                        .clicked()
                    {
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
                    ui.label(i18n.text("rust.store.search"));
                    ui.text_edit_singleline(&mut self.search);
                    egui::ComboBox::from_id_salt("store-sort")
                        .selected_text(i18n.text(sort_key(self.sort)))
                        .show_ui(ui, |ui| {
                            for order in [
                                Sort::Rating,
                                Sort::Alphabetical,
                                Sort::LastUpdated,
                                Sort::NewReleases,
                            ] {
                                ui.selectable_value(
                                    &mut self.sort,
                                    order,
                                    i18n.text(sort_key(order)),
                                );
                            }
                        });
                    ui.checkbox(&mut self.reverse, i18n.text("rust.store.reverse"));
                    ui.checkbox(&mut self.outdated, i18n.text("rust.store.outdated"));
                    if !ready {
                        ui.spinner();
                    }
                });
                let mut action = None;
                if let Some(catalog) = &self.catalog {
                    ui.horizontal(|ui| {
                        egui::ComboBox::from_id_salt("store-os")
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
                        egui::ComboBox::from_id_salt("store-client")
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
                        egui::ComboBox::from_id_salt("store-framework")
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
                                for framework in &catalog.config.frameworks {
                                    ui.selectable_value(
                                        &mut self.framework,
                                        framework.name.clone(),
                                        &framework.name,
                                    );
                                }
                            });
                        egui::ComboBox::from_id_salt("store-category")
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
                                for category in &catalog.config.categories {
                                    ui.selectable_value(
                                        &mut self.category,
                                        category.name.clone(),
                                        &category.name,
                                    );
                                }
                            });
                    });
                    let query = Query {
                        text: &self.search,
                        os: (!self.os.is_empty()).then_some(self.os.as_str()),
                        client: (!self.client.is_empty()).then_some(self.client.as_str()),
                        framework: (!self.framework.is_empty()).then_some(self.framework.as_str()),
                        category: (!self.category.is_empty()).then_some(self.category.as_str()),
                        include_outdated: self.outdated,
                        sort: self.sort,
                        reverse: self.reverse,
                    };
                    let matches = catalog.query(&query);
                    ui.label(format!(
                        "{} {}",
                        matches.len(),
                        i18n.text("rust.store.matches")
                    ));
                    egui::ScrollArea::vertical()
                        .id_salt("store-catalogue")
                        .max_height(250.0)
                        .show(ui, |ui| {
                            for extension in matches {
                                ui.group(|ui| {
                                    let install_status = extension_store::install_status(
                                        catalog,
                                        extension,
                                        &self.installed,
                                    );
                                    let label = i18n.text(match install_status {
                                        InstallStatus::Installed => "rust.store.installed",
                                        InstallStatus::UpdateAvailable => {
                                            "rust.store.install_update"
                                        }
                                        InstallStatus::OlderVersion => "rust.store.install_older",
                                        InstallStatus::NotInstalled => "rust.store.install",
                                    });
                                    ui.horizontal(|ui| {
                                        ui.strong(format!(
                                            "{} {}",
                                            extension.title, extension.version
                                        ));
                                        ui.label(format!(
                                            "{} · {} · rating {}",
                                            extension.framework.name,
                                            extension.language,
                                            extension.rating
                                        ));
                                        if ui
                                            .add_enabled(
                                                ready && install_status != InstallStatus::Installed,
                                                egui::Button::new(label),
                                            )
                                            .clicked()
                                        {
                                            action =
                                                Some(Action::Install(Box::new(extension.clone())));
                                        }
                                    });
                                    ui.label(&extension.description);
                                    ui.label(format!(
                                        "By {} · {}",
                                        extension
                                            .authors
                                            .iter()
                                            .map(|author| author.name.as_str())
                                            .collect::<Vec<_>>()
                                            .join(", "),
                                        extension.compatibility.clients.join(", ")
                                    ));
                                    ui.horizontal(|ui| {
                                        for (label, url) in [
                                            ("Source", Some(&extension.source)),
                                            ("Readme", extension.readme.as_ref()),
                                            ("Releases", extension.releases.as_ref()),
                                        ] {
                                            if let Some(url) =
                                                url.filter(|url| url.starts_with("https://"))
                                            {
                                                ui.hyperlink_to(label, url);
                                            }
                                        }
                                    });
                                    if let Some(framework) =
                                        catalog.config.frameworks.iter().find(|framework| {
                                            framework.name == extension.framework.name
                                        })
                                    {
                                        if framework.installation.required {
                                            if let Some(instructions) = framework
                                                .installation
                                                .instructions
                                                .as_ref()
                                                .filter(|url| url.starts_with("https://"))
                                            {
                                                ui.hyperlink_to(
                                                    format!("{} runtime setup", framework.name),
                                                    instructions,
                                                );
                                            }
                                        }
                                    }
                                });
                            }
                        });
                }
                ui.separator();
                ui.strong(i18n.text("rust.store.installed_versions"));
                ui.label(i18n.text("rust.store.installed_hint"));
                egui::ScrollArea::vertical()
                    .id_salt("store-installed")
                    .max_height(150.0)
                    .show(ui, |ui| {
                        for record in &self.installed {
                            ui.horizontal(|ui| {
                                ui.label(format!("{} {}", record.title, record.version));
                                if ui
                                    .add_enabled(
                                        host.is_some(),
                                        egui::Button::new(i18n.text("rust.store.launch")),
                                    )
                                    .clicked()
                                {
                                    action = Some(Action::Launch(Box::new(record.clone())));
                                }
                                if ui
                                    .add_enabled(
                                        ready,
                                        egui::Button::new(i18n.text("rust.store.uninstall")),
                                    )
                                    .clicked()
                                {
                                    action = Some(Action::Remove(Box::new(record.clone())));
                                }
                            });
                        }
                    });
                match action {
                    Some(Action::Install(extension)) => {
                        if let Some(catalog) = self.catalog.clone() {
                            let root = self.root.clone();
                            let (sender, receiver) = mpsc::channel();
                            self.worker = Some(receiver);
                            *status =
                                format!("Installing {} {}...", extension.title, extension.version);
                            std::thread::spawn(move || {
                                let result = extension_store::install(&catalog, &extension, &root)
                                    .map(|record| {
                                        Outcome::Changed(format!(
                                            "Installed {} {}",
                                            record.title, record.version
                                        ))
                                    })
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
                                    *status =
                                        format!("Launched {} {}", record.title, record.version);
                                }
                                Err(error) => *status = error.to_string(),
                            }
                        }
                    }
                    None => {}
                }
            });
    }
}
