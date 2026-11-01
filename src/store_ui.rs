use eframe::egui;
use gearth_rust::{
    extension_host::ExtensionHost,
    extension_store::{self, Catalog, Installed, Query, Sort, StoreExtension},
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
    Install(StoreExtension),
    Remove(Installed),
    Launch(Installed),
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
        status: &mut String,
        processes: &mut Vec<Child>,
    ) {
        if !self.initialized {
            self.refresh(status);
            self.initialized = true;
        }
        if let Some(worker) = &self.worker {
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
        egui::CollapsingHeader::new("Extension store").default_open(true).show(ui,|ui|{
            let ready=self.worker.is_none();ui.horizontal(|ui|{
                if ui.add_enabled(ready,egui::Button::new("Load / refresh catalogue")).clicked(){let (sender,receiver)=mpsc::channel();self.worker=Some(receiver);*status="Loading extension catalogue...".into();std::thread::spawn(move||{let result=Catalog::fetch(extension_store::STORE_SOURCE,extension_store::STORE_VERSION).map(Outcome::Catalog).map_err(|error|error.to_string());let _=sender.send(result);});}
                ui.label("Search");ui.text_edit_singleline(&mut self.search);
                egui::ComboBox::from_id_salt("store-sort").selected_text(format!("{:?}",self.sort)).show_ui(ui,|ui|{for order in [Sort::Rating,Sort::Alphabetical,Sort::LastUpdated,Sort::NewReleases]{ui.selectable_value(&mut self.sort,order,format!("{order:?}"));}});
                ui.checkbox(&mut self.reverse,"Reverse");ui.checkbox(&mut self.outdated,"Include outdated");
                if !ready{ui.spinner();}
            });
            let mut action=None;
            if let Some(catalog)=&self.catalog{
                ui.horizontal(|ui|{
                    egui::ComboBox::from_id_salt("store-os").selected_text(if self.os.is_empty(){"All systems"}else{&self.os}).show_ui(ui,|ui|{ui.selectable_value(&mut self.os,String::new(),"All systems");for name in ["Windows","Linux","Mac"]{ui.selectable_value(&mut self.os,name.into(),name);}});
                    egui::ComboBox::from_id_salt("store-client").selected_text(if self.client.is_empty(){"All clients"}else{&self.client}).show_ui(ui,|ui|{ui.selectable_value(&mut self.client,String::new(),"All clients");for name in ["Flash","Nitro","Unity","Shockwave"]{ui.selectable_value(&mut self.client,name.into(),name);}});
                    egui::ComboBox::from_id_salt("store-framework").selected_text(if self.framework.is_empty(){"All frameworks"}else{&self.framework}).show_ui(ui,|ui|{ui.selectable_value(&mut self.framework,String::new(),"All frameworks");for framework in &catalog.config.frameworks{ui.selectable_value(&mut self.framework,framework.name.clone(),&framework.name);}});
                    egui::ComboBox::from_id_salt("store-category").selected_text(if self.category.is_empty(){"All categories"}else{&self.category}).show_ui(ui,|ui|{ui.selectable_value(&mut self.category,String::new(),"All categories");for category in &catalog.config.categories{ui.selectable_value(&mut self.category,category.name.clone(),&category.name);}});
                });
                let query=Query {text:&self.search,os:(!self.os.is_empty()).then_some(self.os.as_str()),client:(!self.client.is_empty()).then_some(self.client.as_str()),framework:(!self.framework.is_empty()).then_some(self.framework.as_str()),category:(!self.category.is_empty()).then_some(self.category.as_str()),include_outdated:self.outdated,sort:self.sort,reverse:self.reverse};
                let matches=catalog.query(&query);ui.label(format!("{} matching extensions",matches.len()));
                egui::ScrollArea::vertical().id_salt("store-catalogue").max_height(250.0).show(ui,|ui|{
                    for extension in matches {ui.group(|ui|{
                        let exact=self.installed.iter().any(|record|record.title==extension.title&&record.version==extension.version);let older=self.installed.iter().any(|record|record.title==extension.title&&extension_store::compare_versions(&record.version,&extension.version).is_lt());
                        ui.horizontal(|ui|{ui.strong(format!("{} {}",extension.title,extension.version));ui.label(format!("{} · {} · rating {}",extension.framework.name,extension.language,extension.rating));if ui.add_enabled(ready&&!exact,egui::Button::new(if exact{"Installed"}else if older{"Install update"}else{"Install"})).clicked(){action=Some(Action::Install(extension.clone()));}});
                        ui.label(&extension.description);ui.label(format!("By {} · {}",extension.authors.iter().map(|author|author.name.as_str()).collect::<Vec<_>>().join(", "),extension.compatibility.clients.join(", ")));
                        ui.horizontal(|ui|{for (label,url) in [("Source",Some(&extension.source)),("Readme",extension.readme.as_ref()),("Releases",extension.releases.as_ref())]{if let Some(url)=url.filter(|url|url.starts_with("https://")){ui.hyperlink_to(label,url);}}});
                        if let Some(framework)=catalog.config.frameworks.iter().find(|framework|framework.name==extension.framework.name){if framework.installation.required{if let Some(instructions)=framework.installation.instructions.as_ref().filter(|url|url.starts_with("https://")){ui.hyperlink_to(format!("{} runtime setup",framework.name),instructions);}}}
                    });}
                });
            }
            ui.separator();ui.strong("Installed versions");ui.label("Updates keep older versions available. Launch and uninstall apply to the selected version.");
            egui::ScrollArea::vertical().id_salt("store-installed").max_height(150.0).show(ui,|ui|{for record in &self.installed{ui.horizontal(|ui|{ui.label(format!("{} {}",record.title,record.version));if ui.add_enabled(host.is_some(),egui::Button::new("Launch")).clicked(){action=Some(Action::Launch(record.clone()));}if ui.add_enabled(ready,egui::Button::new("Uninstall")).clicked(){action=Some(Action::Remove(record.clone()));}});}});
            match action {
                Some(Action::Install(extension))=>{if let Some(catalog)=self.catalog.clone(){let root=self.root.clone();let (sender,receiver)=mpsc::channel();self.worker=Some(receiver);*status=format!("Installing {} {}...",extension.title,extension.version);std::thread::spawn(move||{let result=extension_store::install(&catalog,&extension,&root).map(|record|Outcome::Changed(format!("Installed {} {}",record.title,record.version))).map_err(|error|error.to_string());let _=sender.send(result);});}},
                Some(Action::Remove(record))=>{let root=self.root.clone();let (sender,receiver)=mpsc::channel();self.worker=Some(receiver);std::thread::spawn(move||{let result=extension_store::uninstall(&root,&record).map(|()|Outcome::Changed(format!("Uninstalled {} {}",record.title,record.version))).map_err(|error|error.to_string());let _=sender.send(result);});},
                Some(Action::Launch(record))=>{if let Some(host)=host{let filename=record.directory.file_name().and_then(|name|name.to_str()).unwrap_or("");match host.launch_command(&record.command,&record.directory.join("extension"),filename,&record.title,java){Ok(process)=>{processes.push(process);*status=format!("Launched {} {}",record.title,record.version);},Err(error)=>*status=error.to_string()}}},
                None=>{},
            }
        });
    }
}
