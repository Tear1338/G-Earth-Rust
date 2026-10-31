//! Packet identifiers shared with beta-29's extension IPC.
use crate::packet::{error, Direction, Packet, Result};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketInfo {
    pub header: u16,
    pub hash: Option<String>,
    pub name: Option<String>,
    pub structure: Option<String>,
    pub direction: Direction,
    pub source: String,
}
#[derive(Debug, Clone, Default)]
pub struct PacketInfoManager {
    pub version: String,
    entries: Vec<PacketInfo>,
    names: HashMap<(Direction,String),usize>,
}
impl PacketInfoManager {
    pub fn new(version: impl Into<String>, entries: Vec<PacketInfo>) -> Self {
        let mut names=HashMap::new();
        for (i,e) in entries.iter().enumerate() {
            for name in [&e.name,&e.hash].into_iter().flatten() {names.entry((e.direction,name.clone())).or_insert(i);}
        }
        Self {version:version.into(),entries,names}
    }
    pub fn entries(&self)->&[PacketInfo] {&self.entries}
    pub fn by_name(&self,direction:Direction,name:&str)->Option<&PacketInfo> {
        self.names.get(&(direction,name.to_owned())).map(|i|&self.entries[*i])
    }
    pub fn by_header(&self,direction:Direction,header:u16)->impl Iterator<Item=&PacketInfo> {
        self.entries.iter().filter(move |e|e.direction==direction&&e.header==header)
    }
    pub fn append_to(&self,p:&mut Packet)->Result<()> {
        p.put_i32(i32::try_from(self.entries.len()).map_err(|_|error("too many packet identifiers"))?)?;
        for e in &self.entries {
            p.put_i32(i32::from(e.header))?.put_string(e.hash.as_deref().unwrap_or("NULL"))?
                .put_string(e.name.as_deref().unwrap_or("NULL"))?.put_string(e.structure.as_deref().unwrap_or("NULL"))?
                .put_bool(e.direction==Direction::ToServer)?.put_string(&e.source)?;
        }
        Ok(())
    }
    pub fn read_from(version:impl Into<String>,p:&mut Packet)->Result<Self> {
        let count=p.read_i32()?;
        if count<0 || count as usize>p.remaining()/13 {return Err(error("invalid packet identifier count"));}
        let mut entries=Vec::with_capacity(count as usize);
        for _ in 0..count {
            let header=u16::try_from(p.read_i32()?).map_err(|_|error("invalid packet header"))?;
            let optional=|s:String|if s=="NULL" {None}else{Some(s)};
            let hash=optional(p.read_string()?);let name=optional(p.read_string()?);let structure=optional(p.read_string()?);
            let direction=if p.read_bool()? {Direction::ToServer}else{Direction::ToClient};let source=p.read_string()?;
            entries.push(PacketInfo {header,hash,name,structure,direction,source});
        }
        Ok(Self::new(version,entries))
    }
    /// Portable tab-separated database: direction, header, name, hash, structure, source.
    pub fn from_tsv(version:impl Into<String>,text:&str)->Result<Self> {
        let mut entries=Vec::new();
        for line in text.lines().filter(|l|!l.trim().is_empty()&&!l.starts_with('#')) {
            let fields:Vec<_>=line.split('\t').collect();
            if fields.len()!=6 {return Err(error("packet database requires six tab-separated fields"));}
            let optional=|s:&str|if s.is_empty()||s=="NULL" {None}else{Some(s.to_owned())};
            entries.push(PacketInfo {direction:Direction::parse(fields[0])?,header:fields[1].parse().map_err(|_|error("invalid database header"))?,name:optional(fields[2]),hash:optional(fields[3]),structure:optional(fields[4]),source:fields[5].to_owned()});
        }
        Ok(Self::new(version,entries))
    }
}
