#![cfg(feature="web")]
use gearth_rust::unity_wasm::{patch,EXPORTS,IMPORTS};
#[test] fn patches_all_four_hooks_and_preserves_valid_indices(){
    let input=wat::parse_str(include_str!("fixtures/unity_hooks.wat")).unwrap();let output=patch(&input).unwrap();wasmparser::Validator::new().validate_all(&output.bytes).unwrap();let mut imports=Vec::new();let mut exports=Vec::new();for payload in wasmparser::Parser::new(0).parse_all(&output.bytes){match payload.unwrap(){wasmparser::Payload::ImportSection(section)=>for import in section{let import=import.unwrap();imports.push((import.module.to_owned(),import.name.to_owned()));},wasmparser::Payload::ExportSection(section)=>for export in section{exports.push(export.unwrap().name.to_owned());},_=>{}}}for name in IMPORTS{assert!(imports.iter().any(|(module,field)|module=="env"&&field==name));}for name in EXPORTS{assert!(exports.iter().any(|field|field==name));}assert!(patch(&output.bytes).is_err());
    if let Some(directory)=std::env::var_os("GEARTH_UNITY_FIXTURE_DIR"){let directory=std::path::PathBuf::from(directory);std::fs::create_dir_all(&directory).unwrap();std::fs::write(directory.join("original.wasm"),input).unwrap();std::fs::write(directory.join("rust-patched.wasm"),output.bytes).unwrap();}
}
#[test] fn refuses_missing_or_ambiguous_hook_patterns(){
    let fixture=include_str!("fixtures/unity_hooks.wat");let missing=fixture.replace("i32.load8_u offset=30","i32.load8_u offset=31");assert!(patch(&wat::parse_str(missing).unwrap()).unwrap_err().to_string().contains("g_outgoing_packet"));
    let ambiguous=fixture.replacen("  (func $incoming", "  (func (type $out) local.get 0 i32.load8_u offset=30 align=1 if nop end)\n  (func $incoming",1);assert!(patch(&wat::parse_str(ambiguous).unwrap()).unwrap_err().to_string().contains("ambiguous"));assert!(patch(b"not wasm").is_err());
}
