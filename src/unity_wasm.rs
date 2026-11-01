//! Beta-29 Unity WASM hooks. Every function index is re-encoded and output validated.
use std::{convert::Infallible,io};
use wasm_encoder::{reencode::{self,Reencode},CodeSection,ExportKind,ExportSection,FunctionSection,ImportSection,Instruction,Module};
use wasmparser::{FunctionBody,Operator,Parser,Payload,TypeRef,ValType};
pub const MAX_WASM:usize=100*1024*1024;
pub const IMPORTS:[&str;4]=["g_chacha_setkey","g_chacha_returnbyte","g_outgoing_packet","g_incoming_packet"];
pub const EXPORTS:[&str;3]=["_gearth_returnbyte_copy","_gearth_outgoing_copy","_gearth_incoming_copy"];
#[derive(Debug)] pub struct Patched {pub bytes:Vec<u8>,pub functions:[u32;4]}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] enum Kind {Get,Set,Const,Load,Load8,Eqz,If,Block,Call,Xor,Other}
#[derive(Clone,Debug)] struct Op {kind:Kind,index:u32,align:u8,offset:u64,calls:usize,tail_xor:bool}
impl Op {fn new(kind:Kind)->Self{Self {kind,index:0,align:0,offset:0,calls:0,tail_xor:false}}}
struct Level {container:Op,ops:Vec<Op>,in_else:bool}
fn shape(body:&FunctionBody<'_>)->io::Result<Vec<Op>> {
    let mut reader=body.get_operators_reader().map_err(io::Error::other)?;let mut levels=vec![Level {container:Op::new(Kind::Other),ops:Vec::new(),in_else:false}];let mut count=0;
    while !reader.eof(){count+=1;if count>65536{return Ok(Vec::new());}let operator=reader.read().map_err(io::Error::other)?;
        if matches!(operator,Operator::End){let mut level=levels.pop().ok_or_else(||io::Error::other("unbalanced WASM expression"))?;if levels.is_empty(){return Ok(level.ops);}level.container.tail_xor=level.ops.iter().rev().take(5).any(|op|op.kind==Kind::Xor);levels.last_mut().unwrap().ops.push(level.container);continue;}
        if matches!(operator,Operator::Else){let level=levels.last_mut().unwrap();level.in_else=true;continue;}
        let mut op=match operator {Operator::LocalGet {local_index}=>{let mut op=Op::new(Kind::Get);op.index=local_index;op},Operator::LocalSet {..}=>Op::new(Kind::Set),Operator::I32Const {..}=>Op::new(Kind::Const),Operator::I32Load {memarg}=>{let mut op=Op::new(Kind::Load);op.align=memarg.align;op.offset=memarg.offset;op},Operator::I32Load8U {memarg}=>{let mut op=Op::new(Kind::Load8);op.align=memarg.align;op.offset=memarg.offset;op},Operator::I32Eqz=>Op::new(Kind::Eqz),Operator::If {..}=>Op::new(Kind::If),Operator::Block {..}=>Op::new(Kind::Block),Operator::Call {..}=>Op::new(Kind::Call),Operator::I32Xor=>Op::new(Kind::Xor),_=>Op::new(Kind::Other)};
        if matches!(operator,Operator::If {..}|Operator::Block {..}|Operator::Loop {..}|Operator::TryTable {..}){if levels.len()>1024{return Err(io::Error::other("WASM control nesting exceeds limit"));}levels.push(Level {container:op,ops:Vec::new(),in_else:false});}else{let level=levels.last_mut().unwrap();if op.kind==Kind::Call&&!level.in_else{level.container.calls+=1;}op.calls=0;level.ops.push(op);}
    }Err(io::Error::other("unterminated WASM expression"))
}
fn matches_hook(hook:usize,locals:&[(u32,ValType)],ops:&[Op])->bool {
    let kinds=ops.iter().map(|op|op.kind).collect::<Vec<_>>();use Kind::*;
    match hook {
        0=>locals.is_empty()&&kinds==[Get,If,Get,Const,Get,Load,Const,Const,Const,Call],
        1=>locals==[(1,ValType::I32)]&&(ops.len()==21||ops.len()==22)&&ops[ops.len()-14].kind==Block&&ops[ops.len()-14].tail_xor,
        2=>locals.is_empty()&&kinds==[Get,Load8,If]&&ops[0].index==0&&ops[1].align==0&&ops[1].offset==30,
        3=>locals==[(5,ValType::I32)]&&kinds.starts_with(&[Const,Load8,Eqz,If,Const,Load,Set,Block,Set,Get,Get,Get,Get,Get,Load])&&ops[5].align==2&&ops[5].offset==0&&ops[3].calls==3,
        _=>false,
    }
}
pub fn patch(bytes:&[u8])->io::Result<Patched> {
    if bytes.len()>MAX_WASM{return Err(io::Error::other("Unity WASM exceeds 100 MiB"));}wasmparser::Validator::new().validate_all(bytes).map_err(io::Error::other)?;
    let mut types=Vec::new();let mut functions=Vec::new();let mut imports=0;let mut has_imports=false;let mut has_exports=false;let mut body_index=0;let mut found:[Option<(u32,u32)>;4]=[None;4];
    for payload in Parser::new(0).parse_all(bytes){match payload.map_err(io::Error::other)? {
        Payload::TypeSection(section)=>for ty in section.into_iter_err_on_gc_types(){types.push(ty.map_err(io::Error::other)?);},
        Payload::ImportSection(section)=>{has_imports=true;for item in section {let item=item.map_err(io::Error::other)?;if IMPORTS.contains(&item.name){return Err(io::Error::other("Unity WASM is already patched"));}if let TypeRef::Func(_)=item.ty{imports+=1;}}},
        Payload::FunctionSection(section)=>for ty in section{functions.push(ty.map_err(io::Error::other)?);},
        Payload::ExportSection(section)=>{has_exports=true;for item in section{if EXPORTS.contains(&item.map_err(io::Error::other)?.name){return Err(io::Error::other("Unity WASM already contains hook exports"));}}},
        Payload::CodeSectionEntry(body)=>{let type_id=*functions.get(body_index).ok_or_else(||io::Error::other("missing WASM function type"))?;let ty=&types[type_id as usize];let eligible=ty.params().iter().all(|p|*p==ValType::I32)&&((ty.params().len()==3&&(ty.results().is_empty()||ty.results()==[ValType::I32]))||((ty.params().len()==4||ty.params().len()==5)&&ty.results().is_empty()));
            if eligible&&body.range().len()<=1024*1024 {let locals=body.get_locals_reader().map_err(io::Error::other)?.into_iter().collect::<Result<Vec<_>,_>>().map_err(io::Error::other)?;let ops=shape(&body)?;for (hook,target) in found.iter_mut().enumerate(){let arity=[4,3,3,5][hook];let returns=if hook==1{&[ValType::I32][..]}else{&[][..]};if ty.params().len()==arity&&ty.results()==returns&&matches_hook(hook,&locals,&ops){if target.is_some(){return Err(io::Error::other(format!("ambiguous Unity hook {}",IMPORTS[hook])));}*target=Some((body_index as u32,type_id));}}}body_index+=1;},
        Payload::CustomSection(section) if section.name().starts_with("reloc.")||section.name()=="linking"=>return Err(io::Error::other("relocatable WASM is not a Unity client module")),
        _=>{},
    }}
    if !has_imports||!has_exports{return Err(io::Error::other("Unity WASM requires import and export sections"));}let mut targets=[(0,0);4];for (index,value) in found.into_iter().enumerate(){targets[index]=value.ok_or_else(||io::Error::other(format!("Unity hook {} was not found",IMPORTS[index])))?;}
    let mut encoder=Hooks {targets,imports,total:functions.len() as u32,body:0};let mut module=Module::new();encoder.parse_core_module(&mut module,Parser::new(0),bytes).map_err(io::Error::other)?;let patched=module.finish();if patched.len()>MAX_WASM{return Err(io::Error::other("patched Unity WASM exceeds limit"));}wasmparser::Validator::new().validate_all(&patched).map_err(io::Error::other)?;
    Ok(Patched {bytes:patched,functions:targets.map(|(function,_)|function+imports)})
}
struct Hooks {targets:[(u32,u32);4],imports:u32,total:u32,body:u32}
type EncodeResult=Result<(),reencode::Error<Infallible>>;
impl Reencode for Hooks {
    type Error=Infallible;
    fn function_index(&mut self,index:u32)->Result<u32,reencode::Error<Self::Error>> {Ok(if index>=self.imports{index+4}else{index})}
    fn parse_import_section(&mut self,section:&mut ImportSection,reader:wasmparser::ImportSectionReader<'_>)->EncodeResult {reencode::utils::parse_import_section(self,section,reader)?;for (index,name) in IMPORTS.iter().enumerate(){section.import("env",name,wasm_encoder::EntityType::Function(self.targets[index].1));}Ok(())}
    fn parse_function_section(&mut self,section:&mut FunctionSection,reader:wasmparser::FunctionSectionReader<'_>)->EncodeResult {reencode::utils::parse_function_section(self,section,reader)?;for (_,ty) in &self.targets[1..]{section.function(*ty);}Ok(())}
    fn parse_export_section(&mut self,section:&mut ExportSection,reader:wasmparser::ExportSectionReader<'_>)->EncodeResult {reencode::utils::parse_export_section(self,section,reader)?;for (index,name) in EXPORTS.iter().enumerate(){section.export(name,ExportKind::Func,self.imports+self.total+4+index as u32);}Ok(())}
    fn parse_code_section(&mut self,section:&mut CodeSection,reader:wasmparser::CodeSectionReader<'_>)->EncodeResult {
        let bodies=reader.into_iter().collect::<Result<Vec<_>,_>>()?;for body in &bodies{self.parse_function_body(section,body.clone())?;}let targets=self.targets;for (function,_) in targets[1..].iter().copied(){reencode::utils::parse_function_body(self,section,bodies[function as usize].clone())?;}Ok(())
    }
    fn parse_function_body(&mut self,section:&mut CodeSection,body:FunctionBody<'_>)->EncodeResult {
        let index=self.body;self.body+=1;let Some(hook)=self.targets.iter().position(|(function,_)|*function==index)else{return reencode::utils::parse_function_body(self,section,body);};
        let mut function=self.new_function_with_parsed_locals(&body)?;for parameter in 0..[4,3,3,5][hook]{function.instruction(&Instruction::LocalGet(parameter));}function.instruction(&Instruction::Call(self.imports+hook as u32));
        if hook==0 {let mut reader=body.get_operators_reader()?;while !reader.eof(){function.instruction(&self.parse_instruction(&mut reader)?);}}else{function.instruction(&Instruction::End);}section.function(&function);Ok(())
    }
}
