use eframe::egui;
use gearth_rust::{
    extension_host::ExtensionHost,
    gpython::{self, Dependencies, PythonConsole},
    i18n::I18n,
};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
};
pub struct PythonUi {
    runtime: String,
    title: String,
    report: Option<Dependencies>,
    pending: Option<Receiver<Result<Dependencies, String>>>,
    install_cancel: Option<Arc<AtomicBool>>,
    consoles: Vec<PythonConsole>,
}
impl Default for PythonUi {
    fn default() -> Self {
        Self {
            runtime: "python".into(),
            title: "G-Python console".into(),
            report: None,
            pending: None,
            install_cancel: None,
            consoles: Vec::new(),
        }
    }
}
impl PythonUi {
    fn cancel_install(&mut self) {
        if let Some(cancel) = self.install_cancel.take() {
            cancel.store(true, Ordering::Relaxed);
        }
    }
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }
    pub fn restore_settings(&mut self, settings: &gearth_rust::settings::Settings) {
        self.cancel_install();
        if let Some(runtime) = settings.values.get("python_runtime") {
            self.runtime = runtime.clone();
        }
        if let Some(title) = settings.values.get("python_title") {
            self.title = title.clone();
        }
        self.report = None;
        self.pending = None;
    }
    pub fn save_settings(&self, settings: &mut gearth_rust::settings::Settings) {
        settings.values.extend([
            ("python_runtime".into(), self.runtime.clone()),
            ("python_title".into(), self.title.clone()),
        ]);
    }
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        host: Option<&Arc<ExtensionHost>>,
        python_enabled: bool,
        i18n: &I18n,
        status: &mut String,
    ) {
        if let Some(pending) = &self.pending {
            match pending.try_recv() {
                Ok(result) => {
                    match result {
                        Ok(report) => {
                            let missing = report.missing();
                            *status = if missing.is_empty() {
                                "G-Python dependencies ready".into()
                            } else {
                                format!("Missing: {}", missing.join(", "))
                            };
                            self.report = Some(report);
                        }
                        Err(error) => *status = error,
                    }
                    self.install_cancel = None;
                    self.pending = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.install_cancel = None;
                    self.pending = None;
                    *status = "Python check stopped".into();
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        self.consoles.retain_mut(|console| {
            for line in console.poll() {
                if line.starts_with("GEARTH_PYTHON_ERROR") {
                    *status = line;
                } else if line == "GEARTH_PYTHON_READY" {
                    *status = "G-Python console connected".into();
                }
            }
            !matches!(console.exited(), Ok(Some(_)))
        });
        egui::CollapsingHeader::new("G-Python live console").show(ui,|ui|{
            if !python_enabled { ui.label(i18n.text("rust.python.disabled_hint")); }
            ui.horizontal(|ui|{ui.label("Python executable");if ui.add_enabled(self.pending.is_none(),egui::TextEdit::singleline(&mut self.runtime)).changed(){self.report=None;}ui.label("Console title");ui.text_edit_singleline(&mut self.title);});
            ui.horizontal(|ui|{if ui.add_enabled(self.pending.is_none(),egui::Button::new("Check Python dependencies")).clicked(){let runtime=self.runtime.clone();let (send,receive)=mpsc::channel();self.pending=Some(receive);*status="Checking Python modules...".into();std::thread::spawn(move||{let _=send.send(gpython::probe(Path::new(&runtime)).map_err(|error|error.to_string()));});}
                if ui.add_enabled(self.pending.is_none()&&self.consoles.is_empty(),egui::Button::new("Install/repair Python packages")).clicked(){let runtime=self.runtime.clone();let cancel=Arc::new(AtomicBool::new(false));let worker_cancel=cancel.clone();let (send,receive)=mpsc::channel();self.install_cancel=Some(cancel);self.pending=Some(receive);self.report=None;*status="Installing validated Python packages in the selected environment...".into();std::thread::spawn(move||{let _=send.send(gpython::install_dependencies(Path::new(&runtime),&worker_cancel).map_err(|error|error.to_string()));});}
                if self.install_cancel.is_some()&&ui.button("Cancel installation").clicked(){self.cancel_install();*status="Cancelling Python package installation...".into();}
                if self.pending.is_some(){ui.spinner();}
                let enabled=python_enabled&&host.is_some()&&self.pending.is_none()&&self.report.as_ref().is_some_and(|report|report.missing().is_empty())&&self.consoles.len()<4;
                if ui.add_enabled(enabled,egui::Button::new("Open G-Python QtConsole")).clicked(){match PythonConsole::launch(Path::new(&self.runtime),host.unwrap(),&self.title){Ok(console)=>{self.consoles.push(console);*status="Starting G-Python kernel and QtConsole...".into();},Err(error)=>*status=error.to_string()}}
                if ui.add_enabled(!self.consoles.is_empty(),egui::Button::new("Stop Python consoles")).clicked(){self.consoles.clear();*status="Python consoles stopped".into();}
            });
            ui.label("Python 3.11+, g-python, qtconsole, PyQt5, jupyter-console, jupyter-client and ipykernel are required.");ui.label("Install/repair pins G-Python 0.1.6 and modifies the selected environment; an interrupted pip run can leave partial changes.");ui.monospace("python -m pip install g-python==0.1.6 qtconsole PyQt5 jupyter-console jupyter-client ipykernel");ui.hyperlink_to("G-Python documentation","https://github.com/sirjonasxx/G-Python");
            for (index,console) in self.consoles.iter().enumerate(){ui.label(format!("Console {}: {}",index+1,if console.ready{"connected"}else{"starting"}));}
        });
    }
}
impl Drop for PythonUi {
    fn drop(&mut self) {
        self.cancel_install();
    }
}
