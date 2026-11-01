//! Network-extension codec matching beta-29's NetworkExtensionCodec.java.
use crate::packet::{error, Direction, Message, Packet, PacketFormat, Result};

pub const EVA_WIRE: i32 = 0;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionInfo {
    pub title: String,
    pub author: String,
    pub version: String,
    pub description: String,
    pub on_click: bool,
    pub file: Option<String>,
    pub cookie: String,
    pub can_leave: bool,
    pub can_delete: bool,
}
#[derive(Debug, Clone)]
pub enum Incoming {
    Info(ExtensionInfo),
    Manipulated(Message),
    RequestFlags,
    Send {
        direction: Direction,
        packet: Packet,
    },
    PacketToString {
        text: String,
        format: PacketFormat,
    },
    StringToPacket {
        text: String,
        format: PacketFormat,
    },
    Console(String),
}
pub fn decode(mut p: Packet) -> Result<Incoming> {
    let message = match p.header() {
        1 => {
            let title = p.read_string()?;
            let author = p.read_string()?;
            let version = p.read_string()?;
            let description = p.read_string()?;
            let on_click = p.read_bool()?;
            let has_file = p.read_bool()?;
            let file = p.read_string()?;
            let cookie = p.read_string()?;
            let can_leave = p.read_bool()?;
            let can_delete = p.read_bool()?;
            Incoming::Info(ExtensionInfo {
                title,
                author,
                version,
                description,
                on_click,
                file: if has_file { Some(file) } else { None },
                cookie,
                can_leave,
                can_delete,
            })
        }
        2 => {
            let text = p.read_long_string()?;
            let format = read_format(&mut p)?;
            let message = Message::parse_with_format(&text, format)?;
            Incoming::Manipulated(message)
        }
        3 => Incoming::RequestFlags,
        4 => {
            let direction = match p.read_u8()? {
                0 => Direction::ToClient,
                1 => Direction::ToServer,
                _ => return Err(error("invalid send direction")),
            };
            let length = p.read_i32()?;
            if length < 2 {
                return Err(error("invalid injected packet size"));
            }
            let bytes = p.read_bytes(length as usize)?.to_vec();
            let format = read_format(&mut p)?;
            let packet = Packet::from_bytes_with_format(format, bytes)?;
            Incoming::Send { direction, packet }
        }
        20 => {
            let text = p.read_long_string()?;
            let format = read_format(&mut p)?;
            Incoming::PacketToString { text, format }
        }
        21 => {
            let text = p.read_utf8_long()?;
            let format = read_format(&mut p)?;
            Incoming::StringToPacket { text, format }
        }
        98 => Incoming::Console(p.read_string()?),
        _ => return Err(error("unsupported extension message header")),
    };
    if p.remaining() != 0 {
        return Err(error("trailing extension message data"));
    }
    Ok(message)
}
fn read_format(p: &mut Packet) -> Result<PacketFormat> {
    if p.remaining() == 0 {
        Ok(PacketFormat::EvaWire)
    } else {
        PacketFormat::from_id(p.read_i32()?)
    }
}
pub fn info_request() -> Packet {
    Packet::new(2)
}
pub fn info_response(info: &ExtensionInfo) -> Result<Packet> {
    let mut p = Packet::new(1);
    for s in [&info.title, &info.author, &info.version, &info.description] {
        p.put_string(s)?;
    }
    p.put_bool(info.on_click)?
        .put_bool(info.file.is_some())?
        .put_string(info.file.as_deref().unwrap_or(""))?
        .put_string(&info.cookie)?
        .put_bool(info.can_leave)?
        .put_bool(info.can_delete)?;
    Ok(p)
}
pub fn init(connected: bool) -> Result<Packet> {
    init_with_language(connected, "en")
}
pub fn init_with_language(connected: bool, language: &str) -> Result<Packet> {
    let mut p = Packet::new(7);
    p.put_bool(connected)?;
    append_host_info(&mut p, language)?;
    Ok(p)
}
fn append_host_info(p: &mut Packet, language: &str) -> Result<()> {
    p.put_string("G-Earth-Rust")?
        .put_string(env!("CARGO_PKG_VERSION"))?
        .put_i32(1)?
        .put_string("language")?
        .put_string(language)?;
    Ok(())
}
pub fn update_host_info(language: &str) -> Result<Packet> {
    let mut p = Packet::new(10);
    append_host_info(&mut p, language)?;
    Ok(p)
}
pub fn intercept(message: &Message) -> Result<Packet> {
    let mut p = Packet::new(3);
    p.put_long_string(&message.stringify())?
        .put_i32(message.packet.format().id())?;
    Ok(p)
}
pub fn manipulated(message: &Message) -> Result<Packet> {
    let mut p = intercept(message)?;
    p.set_header(2);
    Ok(p)
}
pub fn send(direction: Direction, packet: &Packet) -> Result<Packet> {
    let mut p = Packet::new(4);
    p.put_u8(if direction == Direction::ToClient {
        0
    } else {
        1
    })?
    .put_i32(packet.bytes().len() as i32)?
    .append(packet.bytes())?
    .put_i32(packet.format().id())?;
    Ok(p)
}
pub fn flags(values: &[String]) -> Result<Packet> {
    let mut p = Packet::new(4);
    p.put_i32(values.len() as i32)?;
    for value in values {
        p.put_string(value)?;
    }
    Ok(p)
}
pub fn connection_start(
    host: &str,
    port: u16,
    version: &str,
    identifier: &str,
    client_type: &str,
) -> Result<Packet> {
    let mut p = Packet::new(5);
    p.put_string(host)?
        .put_i32(i32::from(port))?
        .put_string(version)?
        .put_string(identifier)?
        .put_string(client_type)?
        .put_i32(0)?;
    Ok(p)
}
