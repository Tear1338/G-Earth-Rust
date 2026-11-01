use eframe::egui;
use gearth_rust::{
    extension_host::ExtensionHost,
    gpython::{self, Dependencies, PythonConsole},
};
use std::{
    path::Path,
    sync::{
        mpsc::{self, Receiver},
        Arc,
    },
};
pub struct PythonUi {
    runtime: String,
    title: String,
    report: Option<Dependencies>,
    pending: Option<Receiver<Result<Dependencies, String>>>,
    consoles: Vec<PythonConsole>,
}
impl Default for PythonUi {
    fn default() -> Self {
        Self {
            runtime: "python".into(),
            title: "G-Python console".into(),
            report: None,
            pending: None,
            consoles: Vec::new(),
        }
    }
}
impl PythonUi {
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        host: Option<&Arc<ExtensionHost>>,
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
                    self.pending = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
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
            ui.horizontal(|ui|{ui.label("Python executable");if ui.add_enabled(self.pending.is_none(),egui::TextEdit::singleline(&mut self.runtime)).changed(){self.report=None;}ui.label("Console title");ui.text_edit_singleline(&mut self.title);});
            ui.horizontal(|ui|{if ui.add_enabled(self.pending.is_none(),egui::Button::new("Check Python dependencies")).clicked(){let runtime=self.runtime.clone();let (send,receive)=mpsc::channel();self.pending=Some(receive);*status="Checking Python modules...".into();std::thread::spawn(move||{let _=send.send(gpython::probe(Path::new(&runtime)).map_err(|error|error.to_string()));});}
                if self.pending.is_some(){ui.spinner();}
                let enabled=host.is_some()&&self.report.as_ref().is_some_and(|report|report.missing().is_empty())&&self.consoles.len()<4;
                if ui.add_enabled(enabled,egui::Button::new("Open G-Python QtConsole")).clicked(){match PythonConsole::launch(Path::new(&self.runtime),host.unwrap(),&self.title){Ok(console)=>{self.consoles.push(console);*status="Starting G-Python kernel and QtConsole...".into();},Err(error)=>*status=error.to_string()}}
                if ui.add_enabled(!self.consoles.is_empty(),egui::Button::new("Stop Python consoles")).clicked(){self.consoles.clear();*status="Python consoles stopped".into();}
            });
            ui.label("Python 3.11+, g-python, qtconsole, PyQt5, jupyter-console, jupyter-client and ipykernel are required.");ui.monospace("python -m pip install g-python==0.1.6 qtconsole PyQt5 jupyter-console ipykernel");ui.hyperlink_to("G-Python documentation","https://github.com/sirjonasxx/G-Python");
            for (index,console) in self.consoles.iter().enumerate(){ui.label(format!("Console {}: {}",index+1,if console.ready{"connected"}else{"starting"}));}
        });
    }
}
