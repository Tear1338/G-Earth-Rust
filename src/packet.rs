use std::fmt;
use std::io::{self, Read, Write};

pub const MAX_FRAME: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketError(pub String);
impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}
impl std::error::Error for PacketError {}
pub type Result<T> = std::result::Result<T, PacketError>;
pub fn error(message: &str) -> PacketError { PacketError(message.to_owned()) }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction { ToServer, ToClient }
impl Direction {
    pub fn name(self) -> &'static str { match self { Self::ToServer => "TOSERVER", Self::ToClient => "TOCLIENT" } }
    pub fn parse(s: &str) -> Result<Self> { match s { "TOSERVER" => Ok(Self::ToServer), "TOCLIENT" => Ok(Self::ToClient), _ => Err(error("invalid direction")) } }
}

/// Complete wire bytes: 32-bit big-endian payload length, 16-bit header, body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet { bytes: Vec<u8>, cursor: usize, pub edited: bool }
impl Packet {
    pub fn new(header: u16) -> Self {
        let mut bytes = vec![0,0,0,2]; bytes.extend_from_slice(&header.to_be_bytes());
        Self { bytes, cursor: 6, edited: false }
    }
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < 6 || bytes.len() > MAX_FRAME + 4 { return Err(error("invalid packet size")); }
        let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        if length != bytes.len() - 4 { return Err(error("packet length mismatch")); }
        Ok(Self { bytes, cursor: 6, edited: false })
    }
    pub fn bytes(&self) -> &[u8] { &self.bytes }
    pub fn body(&self) -> &[u8] { &self.bytes[6..] }
    pub fn header(&self) -> u16 { u16::from_be_bytes(self.bytes[4..6].try_into().unwrap()) }
    pub fn cursor(&self) -> usize { self.cursor }
    pub fn remaining(&self) -> usize { self.bytes.len() - self.cursor }
    pub fn reset(&mut self) { self.cursor = 6; }
    pub fn set_cursor(&mut self, cursor: usize) -> Result<()> {
        if !(6..=self.bytes.len()).contains(&cursor) { return Err(error("cursor outside body")); }
        self.cursor = cursor; Ok(())
    }
    pub fn set_header(&mut self, header: u16) { self.bytes[4..6].copy_from_slice(&header.to_be_bytes()); self.edited = true; }
    pub fn read_bytes(&mut self, count: usize) -> Result<&[u8]> {
        let end = self.cursor.checked_add(count).ok_or_else(|| error("length overflow"))?;
        if end > self.bytes.len() { return Err(error("truncated packet field")); }
        let start = self.cursor; self.cursor = end; Ok(&self.bytes[start..end])
    }
    pub fn read_u8(&mut self) -> Result<u8> { Ok(self.read_bytes(1)?[0]) }
    pub fn read_bool(&mut self) -> Result<bool> { Ok(self.read_u8()? != 0) }
    pub fn read_u16(&mut self) -> Result<u16> { Ok(u16::from_be_bytes(self.read_bytes(2)?.try_into().unwrap())) }
    pub fn read_i32(&mut self) -> Result<i32> { Ok(i32::from_be_bytes(self.read_bytes(4)?.try_into().unwrap())) }
    pub fn read_i64(&mut self) -> Result<i64> { Ok(i64::from_be_bytes(self.read_bytes(8)?.try_into().unwrap())) }
    pub fn read_f32(&mut self) -> Result<f32> { Ok(f32::from_be_bytes(self.read_bytes(4)?.try_into().unwrap())) }
    pub fn read_f64(&mut self) -> Result<f64> { Ok(f64::from_be_bytes(self.read_bytes(8)?.try_into().unwrap())) }
    /// G-Earth defaults to ISO-8859-1, including its extension IPC.
    pub fn read_string(&mut self) -> Result<String> {
        let start = self.cursor;
        let result = (|| { let n = self.read_u16()? as usize; Ok(latin1_decode(self.read_bytes(n)?)) })();
        if result.is_err() { self.cursor = start; } result
    }
    pub fn read_long_string(&mut self) -> Result<String> {
        let start = self.cursor;
        let result = (|| { let n = self.read_i32()?; if n < 0 { return Err(error("negative string length")); } Ok(latin1_decode(self.read_bytes(n as usize)?)) })();
        if result.is_err() { self.cursor = start; } result
    }
    pub fn read_utf8_long(&mut self) -> Result<String> {
        let start = self.cursor;
        let result = (|| { let n = self.read_i32()?; if n < 0 { return Err(error("negative string length")); }
            String::from_utf8(self.read_bytes(n as usize)?.to_vec()).map_err(|_| error("invalid UTF-8")) })();
        if result.is_err() { self.cursor = start; } result
    }
    pub fn append(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        let length = self.bytes.len().checked_add(bytes.len()).ok_or_else(|| error("length overflow"))?;
        if length > MAX_FRAME + 4 { return Err(error("packet too large")); }
        self.bytes.extend_from_slice(bytes); self.fix_length(); self.edited = true; Ok(self)
    }
    fn fix_length(&mut self) { let length = (self.bytes.len()-4) as u32; self.bytes[..4].copy_from_slice(&length.to_be_bytes()); }
    pub fn put_u8(&mut self, v: u8) -> Result<&mut Self> { self.append(&[v]) }
    pub fn put_bool(&mut self, v: bool) -> Result<&mut Self> { self.put_u8(u8::from(v)) }
    pub fn put_u16(&mut self, v: u16) -> Result<&mut Self> { self.append(&v.to_be_bytes()) }
    pub fn put_i32(&mut self, v: i32) -> Result<&mut Self> { self.append(&v.to_be_bytes()) }
    pub fn put_i64(&mut self, v: i64) -> Result<&mut Self> { self.append(&v.to_be_bytes()) }
    pub fn put_f32(&mut self, v: f32) -> Result<&mut Self> { self.append(&v.to_be_bytes()) }
    pub fn put_f64(&mut self, v: f64) -> Result<&mut Self> { self.append(&v.to_be_bytes()) }
    pub fn put_string(&mut self, s: &str) -> Result<&mut Self> {
        let bytes = latin1_encode(s)?; let n = u16::try_from(bytes.len()).map_err(|_| error("short string too long"))?;
        let mut field = n.to_be_bytes().to_vec(); field.extend(bytes); self.append(&field)
    }
    pub fn put_long_string(&mut self, s: &str) -> Result<&mut Self> {
        let bytes = latin1_encode(s)?; self.put_long_bytes(&bytes)
    }
    pub fn put_long_bytes(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        let n = i32::try_from(bytes.len()).map_err(|_| error("string too long"))?;
        let mut field = n.to_be_bytes().to_vec(); field.extend_from_slice(bytes); self.append(&field)
    }
    pub fn replace(&mut self, offset: usize, count: usize, replacement: &[u8]) -> Result<()> {
        let end = offset.checked_add(count).ok_or_else(|| error("offset overflow"))?;
        if offset < 6 || end > self.bytes.len() { return Err(error("replacement outside body")); }
        if self.bytes.len() - count + replacement.len() > MAX_FRAME + 4 { return Err(error("packet too large")); }
        self.bytes.splice(offset..end, replacement.iter().copied()); self.fix_length(); self.reset(); self.edited = true; Ok(())
    }
    pub fn stringify(&self) -> String { format!("{}{}", if self.edited {'1'} else {'0'}, latin1_decode(&self.bytes)) }
    pub fn from_stringified(s: &str) -> Result<Self> {
        let flag = s.as_bytes().first().ok_or_else(|| error("empty serialized packet"))?;
        if *flag != b'0' && *flag != b'1' { return Err(error("invalid edited flag")); }
        let mut p = Self::from_bytes(latin1_encode(&s[1..])?)?; p.edited = *flag == b'1'; Ok(p)
    }
}

#[derive(Debug, Clone)]
pub struct Message { pub packet: Packet, pub direction: Direction, pub index: i32, pub blocked: bool }
impl Message {
    pub fn stringify(&self) -> String { format!("{}\t{}\t{}\t{}", u8::from(self.blocked), self.index, self.direction.name(), self.packet.stringify()) }
    pub fn parse(s: &str) -> Result<Self> {
        let mut fields = s.splitn(4, '\t');
        let blocked = match fields.next() { Some("1") => true, Some("0") => false, _ => return Err(error("invalid blocked flag")) };
        let index = fields.next().ok_or_else(|| error("missing index"))?.parse().map_err(|_| error("invalid index"))?;
        let direction = Direction::parse(fields.next().ok_or_else(|| error("missing direction"))?)?;
        let packet = Packet::from_stringified(fields.next().ok_or_else(|| error("missing packet"))?)?;
        Ok(Self { packet, direction, index, blocked })
    }
}
pub fn latin1_decode(bytes: &[u8]) -> String { bytes.iter().map(|b| char::from(*b)).collect() }
pub fn latin1_encode(s: &str) -> Result<Vec<u8>> { s.chars().map(|c| u8::try_from(c as u32).map_err(|_| error("character outside ISO-8859-1"))).collect() }

/// Incremental decoder with bounded buffering and no drain/copy of retained frames.
#[derive(Default)]
pub struct FrameDecoder { bytes: Vec<u8>, start: usize }
impl FrameDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        if self.bytes.len()-self.start + bytes.len() > MAX_FRAME + 4 { return Err(error("frame buffer limit exceeded")); }
        if self.start != 0 { self.bytes.drain(..self.start); self.start = 0; }
        self.bytes.extend_from_slice(bytes); Ok(())
    }
    pub fn next_packet(&mut self) -> Result<Option<Packet>> {
        let available = &self.bytes[self.start..];
        if available.len() < 4 { return Ok(None); }
        let n = u32::from_be_bytes(available[..4].try_into().unwrap()) as usize;
        if !(2..=MAX_FRAME).contains(&n) { return Err(error("invalid frame length")); }
        if available.len() < n+4 { return Ok(None); }
        let p = Packet::from_bytes(available[..n+4].to_vec())?; self.start += n+4;
        if self.start == self.bytes.len() { self.bytes.clear(); self.start = 0; } Ok(Some(p))
    }
}
pub fn read_frame(reader: &mut impl Read) -> io::Result<Packet> {
    let mut prefix = [0;4]; reader.read_exact(&mut prefix)?;
    let n = u32::from_be_bytes(prefix) as usize;
    if !(2..=MAX_FRAME).contains(&n) { return Err(io::Error::new(io::ErrorKind::InvalidData,"invalid frame length")); }
    let mut bytes = vec![0;n+4]; bytes[..4].copy_from_slice(&prefix); reader.read_exact(&mut bytes[4..])?;
    Packet::from_bytes(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData,e))
}
pub fn write_frame(writer: &mut impl Write, packet: &Packet) -> io::Result<()> { writer.write_all(packet.bytes()) }
