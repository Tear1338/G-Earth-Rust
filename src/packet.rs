use std::fmt;
use std::io::{self, Read, Write};
pub const MAX_FRAME: usize = 16 * 1024 * 1024;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketError(pub String);
impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for PacketError {}
pub type Result<T> = std::result::Result<T, PacketError>;
pub fn error(message: &str) -> PacketError {
    PacketError(message.to_owned())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    ToServer,
    ToClient,
}
impl Direction {
    pub fn name(self) -> &'static str {
        match self {
            Self::ToServer => "TOSERVER",
            Self::ToClient => "TOCLIENT",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "TOSERVER" => Ok(Self::ToServer),
            "TOCLIENT" => Ok(Self::ToClient),
            _ => Err(error("invalid direction")),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PacketFormat {
    #[default]
    EvaWire,
    WedgieIncoming,
    WedgieOutgoing,
}
impl PacketFormat {
    pub fn id(self) -> i32 {
        match self {
            Self::EvaWire => 0,
            Self::WedgieIncoming => 1,
            Self::WedgieOutgoing => 2,
        }
    }
    pub fn from_id(id: i32) -> Result<Self> {
        match id {
            0 => Ok(Self::EvaWire),
            1 => Ok(Self::WedgieIncoming),
            2 => Ok(Self::WedgieOutgoing),
            _ => Err(error("unknown packet format")),
        }
    }
    pub fn body_offset(self) -> usize {
        if self == Self::EvaWire {
            6
        } else {
            2
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    format: PacketFormat,
    bytes: Vec<u8>,
    cursor: usize,
    pub edited: bool,
}
impl Packet {
    pub fn new(header: u16) -> Self {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[0, 0, 0, 2]);
        bytes.extend_from_slice(&header.to_be_bytes());
        Self {
            format: PacketFormat::EvaWire,
            bytes,
            cursor: 6,
            edited: false,
        }
    }
    pub fn new_with_format(format: PacketFormat, header: u16) -> Result<Self> {
        if format == PacketFormat::EvaWire {
            return Ok(Self::new(header));
        }
        Ok(Self {
            format,
            bytes: crate::encoding::encode_b64(u32::from(header), 2)?,
            cursor: 2,
            edited: false,
        })
    }
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Self::from_bytes_with_format(PacketFormat::EvaWire, bytes)
    }
    pub fn from_bytes_with_format(format: PacketFormat, bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < format.body_offset() || bytes.len() > MAX_FRAME + 4 {
            return Err(error("invalid packet size"));
        }
        if format == PacketFormat::EvaWire {
            if u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize != bytes.len() - 4 {
                return Err(error("packet length mismatch"));
            }
        } else {
            crate::encoding::decode_b64(&bytes[..2])?;
        }
        Ok(Self {
            format,
            bytes,
            cursor: format.body_offset(),
            edited: false,
        })
    }
    pub fn format(&self) -> PacketFormat {
        self.format
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn body(&self) -> &[u8] {
        &self.bytes[self.format.body_offset()..]
    }
    pub fn header(&self) -> u16 {
        if self.format == PacketFormat::EvaWire {
            u16::from_be_bytes(self.bytes[4..6].try_into().unwrap())
        } else {
            u16::from(self.bytes[0] - 64) * 64 + u16::from(self.bytes[1] - 64)
        }
    }
    pub fn cursor(&self) -> usize {
        self.cursor
    }
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.cursor
    }
    pub fn reset(&mut self) {
        self.cursor = self.format.body_offset();
    }
    pub fn set_cursor(&mut self, cursor: usize) -> Result<()> {
        if !(self.format.body_offset()..=self.bytes.len()).contains(&cursor) {
            return Err(error("cursor outside body"));
        }
        self.cursor = cursor;
        Ok(())
    }
    pub fn set_header(&mut self, header: u16) {
        if self.format == PacketFormat::EvaWire {
            self.bytes[4..6].copy_from_slice(&header.to_be_bytes());
        } else {
            self.bytes[0] = 64 + ((header >> 6) & 63) as u8;
            self.bytes[1] = 64 + (header & 63) as u8;
        }
        self.edited = true;
    }
    pub fn read_bytes(&mut self, n: usize) -> Result<&[u8]> {
        let end = self
            .cursor
            .checked_add(n)
            .ok_or_else(|| error("length overflow"))?;
        if end > self.bytes.len() {
            return Err(error("truncated packet field"));
        }
        let start = self.cursor;
        self.cursor = end;
        Ok(&self.bytes[start..end])
    }
    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }
    pub fn read_bool(&mut self) -> Result<bool> {
        if self.format == PacketFormat::EvaWire {
            Ok(self.read_u8()? != 0)
        } else {
            Ok(self.read_i32()? == 1)
        }
    }
    pub fn read_u16(&mut self) -> Result<u16> {
        let start = self.cursor;
        let result = (|| match self.format {
            PacketFormat::EvaWire => {
                Ok(u16::from_be_bytes(self.read_bytes(2)?.try_into().unwrap()))
            }
            PacketFormat::WedgieIncoming => {
                u16::try_from(self.read_i32()?).map_err(|_| error("WEDGIE ushort outside range"))
            }
            PacketFormat::WedgieOutgoing => {
                Ok(crate::encoding::decode_b64(self.read_bytes(2)?)? as u16)
            }
        })();
        if result.is_err() {
            self.cursor = start;
        }
        result
    }
    pub fn read_i32(&mut self) -> Result<i32> {
        if self.format == PacketFormat::EvaWire {
            Ok(i32::from_be_bytes(self.read_bytes(4)?.try_into().unwrap()))
        } else {
            let (value, n) = crate::encoding::decode_vl64(&self.bytes[self.cursor..])?;
            self.cursor += n;
            Ok(value)
        }
    }
    pub fn read_i64(&mut self) -> Result<i64> {
        self.ensure_eva()?;
        Ok(i64::from_be_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }
    pub fn read_f32(&mut self) -> Result<f32> {
        self.ensure_eva()?;
        Ok(f32::from_be_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }
    pub fn read_f64(&mut self) -> Result<f64> {
        self.ensure_eva()?;
        Ok(f64::from_be_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }
    pub fn read_string(&mut self) -> Result<String> {
        let start = self.cursor;
        let result = (|| {
            if self.format == PacketFormat::WedgieIncoming {
                let n = self.bytes[self.cursor..]
                    .iter()
                    .position(|b| *b == 2)
                    .ok_or_else(|| error("unterminated WEDGIE string"))?;
                let value = latin1_decode(self.read_bytes(n)?);
                self.cursor += 1;
                return Ok(value);
            }
            let n = self.read_u16()? as usize;
            Ok(latin1_decode(self.read_bytes(n)?))
        })();
        if result.is_err() {
            self.cursor = start;
        }
        result
    }
    /// Read an EVA two-byte-length-prefixed field without copying its bytes.
    /// Invalid or truncated fields leave the cursor unchanged.
    pub fn read_short_bytes(&mut self) -> Result<&[u8]> {
        self.ensure_eva()?;
        let start = self.cursor;
        let prefix_end = start
            .checked_add(2)
            .ok_or_else(|| error("length overflow"))?;
        let prefix = self
            .bytes
            .get(start..prefix_end)
            .ok_or_else(|| error("truncated packet field"))?;
        let len = u16::from_be_bytes(prefix.try_into().unwrap()) as usize;
        let end = prefix_end
            .checked_add(len)
            .ok_or_else(|| error("length overflow"))?;
        if end > self.bytes.len() {
            return Err(error("truncated packet field"));
        }
        self.cursor = end;
        Ok(&self.bytes[prefix_end..end])
    }
    /// Read an EVA short string encoded in UTF-8. Invalid text leaves the cursor unchanged.
    pub fn read_utf8(&mut self) -> Result<String> {
        self.ensure_eva()?;
        let start = self.cursor;
        let result = (|| {
            std::str::from_utf8(self.read_short_bytes()?)
                .map(str::to_owned)
                .map_err(|_| error("invalid UTF-8"))
        })();
        if result.is_err() {
            self.cursor = start;
        }
        result
    }
    /// Read an EVA four-byte-length-prefixed field without copying its bytes.
    /// Invalid or truncated fields leave the cursor unchanged.
    pub fn read_long_bytes(&mut self) -> Result<&[u8]> {
        self.ensure_eva()?;
        let start = self.cursor;
        let prefix_end = start
            .checked_add(4)
            .ok_or_else(|| error("length overflow"))?;
        let prefix = self
            .bytes
            .get(start..prefix_end)
            .ok_or_else(|| error("truncated packet field"))?;
        let len = i32::from_be_bytes(prefix.try_into().unwrap());
        if len < 0 {
            return Err(error("negative string length"));
        }
        let end = prefix_end
            .checked_add(len as usize)
            .ok_or_else(|| error("length overflow"))?;
        if end > self.bytes.len() {
            return Err(error("truncated packet field"));
        }
        self.cursor = end;
        Ok(&self.bytes[prefix_end..end])
    }
    pub fn read_long_string(&mut self) -> Result<String> {
        Ok(latin1_decode(self.read_long_bytes()?))
    }
    pub fn read_utf8_long(&mut self) -> Result<String> {
        self.ensure_eva()?;
        let start = self.cursor;
        let result = (|| {
            std::str::from_utf8(self.read_long_bytes()?)
                .map(str::to_owned)
                .map_err(|_| error("invalid UTF-8"))
        })();
        if result.is_err() {
            self.cursor = start;
        }
        result
    }
    pub fn append(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        let n = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| error("length overflow"))?;
        if n > MAX_FRAME + 4 {
            return Err(error("packet too large"));
        }
        self.bytes.extend_from_slice(bytes);
        self.fix_length();
        self.edited = true;
        Ok(self)
    }
    fn fix_length(&mut self) {
        if self.format == PacketFormat::EvaWire {
            let n = (self.bytes.len() - 4) as u32;
            self.bytes[..4].copy_from_slice(&n.to_be_bytes());
        }
    }
    pub fn put_u8(&mut self, v: u8) -> Result<&mut Self> {
        self.append(&[v])
    }
    pub fn put_bool(&mut self, v: bool) -> Result<&mut Self> {
        if self.format == PacketFormat::EvaWire {
            self.put_u8(u8::from(v))
        } else {
            self.put_i32(i32::from(v))
        }
    }
    pub fn put_u16(&mut self, v: u16) -> Result<&mut Self> {
        match self.format {
            PacketFormat::EvaWire => self.append(&v.to_be_bytes()),
            PacketFormat::WedgieIncoming => {
                self.append(&crate::encoding::encode_vl64(i32::from(v)))
            }
            PacketFormat::WedgieOutgoing => {
                self.append(&crate::encoding::encode_b64(u32::from(v), 2)?)
            }
        }
    }
    pub fn put_i32(&mut self, v: i32) -> Result<&mut Self> {
        if self.format == PacketFormat::EvaWire {
            self.append(&v.to_be_bytes())
        } else {
            self.append(&crate::encoding::encode_vl64(v))
        }
    }
    pub fn put_i64(&mut self, v: i64) -> Result<&mut Self> {
        self.ensure_eva()?;
        self.append(&v.to_be_bytes())
    }
    pub fn put_f32(&mut self, v: f32) -> Result<&mut Self> {
        self.ensure_eva()?;
        self.append(&v.to_be_bytes())
    }
    pub fn put_f64(&mut self, v: f64) -> Result<&mut Self> {
        self.ensure_eva()?;
        self.append(&v.to_be_bytes())
    }
    pub fn put_string(&mut self, s: &str) -> Result<&mut Self> {
        if self.format == PacketFormat::EvaWire && s.is_ascii() {
            let length = u16::try_from(s.len()).map_err(|_| error("short string too long"))?;
            if self.bytes.len() + 2 + s.len() > MAX_FRAME + 4 {
                return Err(error("packet too large"));
            }
            self.bytes.reserve(2 + s.len());
            self.bytes.extend_from_slice(&length.to_be_bytes());
            self.bytes.extend_from_slice(s.as_bytes());
            self.fix_length();
            self.edited = true;
            return Ok(self);
        }
        let bytes = latin1_encode(s)?;
        let mut field = match self.format {
            PacketFormat::EvaWire => u16::try_from(bytes.len())
                .map_err(|_| error("short string too long"))?
                .to_be_bytes()
                .to_vec(),
            PacketFormat::WedgieOutgoing => crate::encoding::encode_b64(
                u32::try_from(bytes.len()).map_err(|_| error("WEDGIE string too long"))?,
                2,
            )?,
            PacketFormat::WedgieIncoming => {
                if bytes.contains(&2) {
                    return Err(error("WEDGIE string contains terminator"));
                }
                Vec::new()
            }
        };
        field.extend(bytes);
        if self.format == PacketFormat::WedgieIncoming {
            field.push(2);
        }
        self.append(&field)
    }
    pub fn put_long_string(&mut self, s: &str) -> Result<&mut Self> {
        self.put_long_bytes(&latin1_encode(s)?)
    }
    /// Append bytes with an EVA two-byte byte-length prefix, for custom encodings.
    pub fn put_short_bytes(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        self.ensure_eva()?;
        let len = u16::try_from(bytes.len()).map_err(|_| error("short string too long"))?;
        let total = self
            .bytes
            .len()
            .checked_add(2)
            .and_then(|n| n.checked_add(bytes.len()))
            .ok_or_else(|| error("length overflow"))?;
        if total > MAX_FRAME + 4 {
            return Err(error("packet too large"));
        }
        self.bytes.reserve(2 + bytes.len());
        self.bytes.extend_from_slice(&len.to_be_bytes());
        self.bytes.extend_from_slice(bytes);
        self.fix_length();
        self.edited = true;
        Ok(self)
    }
    /// Append an EVA UTF-8 string with a two-byte byte-length prefix.
    pub fn put_utf8(&mut self, s: &str) -> Result<&mut Self> {
        self.put_short_bytes(s.as_bytes())
    }
    /// Append an EVA UTF-8 string with a four-byte byte-length prefix.
    pub fn put_utf8_long(&mut self, s: &str) -> Result<&mut Self> {
        self.put_long_bytes(s.as_bytes())
    }
    pub fn put_long_bytes(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        self.ensure_eva()?;
        let n = i32::try_from(bytes.len()).map_err(|_| error("string too long"))?;
        let total = self
            .bytes
            .len()
            .checked_add(4)
            .and_then(|n| n.checked_add(bytes.len()))
            .ok_or_else(|| error("length overflow"))?;
        if total > MAX_FRAME + 4 {
            return Err(error("packet too large"));
        }
        self.bytes.reserve(4 + bytes.len());
        self.bytes.extend_from_slice(&n.to_be_bytes());
        self.bytes.extend_from_slice(bytes);
        self.fix_length();
        self.edited = true;
        Ok(self)
    }
    pub fn replace(&mut self, offset: usize, count: usize, replacement: &[u8]) -> Result<()> {
        let end = offset
            .checked_add(count)
            .ok_or_else(|| error("offset overflow"))?;
        if offset < self.format.body_offset() || end > self.bytes.len() {
            return Err(error("replacement outside body"));
        }
        if self.bytes.len() - count + replacement.len() > MAX_FRAME + 4 {
            return Err(error("packet too large"));
        }
        self.bytes.splice(offset..end, replacement.iter().copied());
        self.fix_length();
        self.reset();
        self.edited = true;
        Ok(())
    }

    /// Replace a fixed-width EVA field at an absolute packet offset, preserving
    /// the read cursor. Header and length bytes are intentionally protected.
    fn replace_fixed(&mut self, offset: usize, replacement: &[u8]) -> Result<&mut Self> {
        self.ensure_eva()?;
        let end = offset
            .checked_add(replacement.len())
            .ok_or_else(|| error("offset overflow"))?;
        if offset < self.format.body_offset() || end > self.bytes.len() {
            return Err(error("replacement outside body"));
        }
        self.bytes[offset..end].copy_from_slice(replacement);
        self.edited = true;
        Ok(self)
    }

    pub fn replace_u8(&mut self, offset: usize, value: u8) -> Result<&mut Self> {
        self.replace_fixed(offset, &[value])
    }
    pub fn replace_bool(&mut self, offset: usize, value: bool) -> Result<&mut Self> {
        self.replace_u8(offset, u8::from(value))
    }
    pub fn replace_u16(&mut self, offset: usize, value: u16) -> Result<&mut Self> {
        self.replace_fixed(offset, &value.to_be_bytes())
    }
    pub fn replace_i32(&mut self, offset: usize, value: i32) -> Result<&mut Self> {
        self.replace_fixed(offset, &value.to_be_bytes())
    }
    pub fn replace_i64(&mut self, offset: usize, value: i64) -> Result<&mut Self> {
        self.replace_fixed(offset, &value.to_be_bytes())
    }
    pub fn replace_f32(&mut self, offset: usize, value: f32) -> Result<&mut Self> {
        self.replace_fixed(offset, &value.to_be_bytes())
    }
    pub fn replace_f64(&mut self, offset: usize, value: f64) -> Result<&mut Self> {
        self.replace_fixed(offset, &value.to_be_bytes())
    }

    /// Replace one length-prefixed Latin-1 string. A cursor past the new end
    /// is clamped so subsequent reads remain safe after a shrinking edit.
    pub fn replace_string(&mut self, offset: usize, value: &str) -> Result<&mut Self> {
        self.ensure_eva()?;
        if value.len() > usize::from(u16::MAX) * 2 {
            return Err(error("short string too long"));
        }
        self.replace_short_bytes(offset, &latin1_encode(value)?)
    }
    /// Replace a two-byte-length-prefixed UTF-8 string at an absolute offset.
    pub fn replace_utf8(&mut self, offset: usize, value: &str) -> Result<&mut Self> {
        self.replace_short_bytes(offset, value.as_bytes())
    }
    /// Replace an EVA two-byte-length-prefixed field with caller-encoded bytes.
    pub fn replace_short_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<&mut Self> {
        self.ensure_eva()?;
        let prefix_end = offset
            .checked_add(2)
            .ok_or_else(|| error("offset overflow"))?;
        if offset < self.format.body_offset() || prefix_end > self.bytes.len() {
            return Err(error("replacement outside body"));
        }
        let old_len =
            u16::from_be_bytes(self.bytes[offset..prefix_end].try_into().unwrap()) as usize;
        let old_end = prefix_end
            .checked_add(old_len)
            .ok_or_else(|| error("length overflow"))?;
        if old_end > self.bytes.len() {
            return Err(error("truncated packet field"));
        }
        let len = u16::try_from(bytes.len()).map_err(|_| error("short string too long"))?;
        let mut field = Vec::with_capacity(2 + bytes.len());
        field.extend_from_slice(&len.to_be_bytes());
        field.extend_from_slice(bytes);
        let cursor = self.cursor;
        self.replace(offset, old_end - offset, &field)?;
        self.cursor = cursor.min(self.bytes.len());
        Ok(self)
    }

    /// Replace non-overlapping occurrences of a big-endian integer in the body.
    pub fn replace_all_i32(&mut self, old: i32, new: i32) -> Result<usize> {
        self.ensure_eva()?;
        let old = old.to_be_bytes();
        let new = new.to_be_bytes();
        let mut offset = self.format.body_offset();
        let mut count = 0;
        while offset + 4 <= self.bytes.len() {
            if self.bytes[offset..offset + 4] == old {
                self.bytes[offset..offset + 4].copy_from_slice(&new);
                self.edited = true;
                count += 1;
                offset += 4;
            } else {
                offset += 1;
            }
        }
        Ok(count)
    }

    /// Replace up to `limit` exact, length-prefixed Latin-1 strings anywhere in
    /// the EVA body; `None` replaces all. The packet is unchanged on failure.
    pub fn replace_strings(&mut self, old: &str, new: &str, limit: Option<usize>) -> Result<usize> {
        self.ensure_eva()?;
        if limit == Some(0) {
            return Ok(0);
        }
        if old.len() > usize::from(u16::MAX) * 2 || new.len() > usize::from(u16::MAX) * 2 {
            return Err(error("short string too long"));
        }
        let old = latin1_encode(old)?;
        let new = latin1_encode(new)?;
        let old_len = u16::try_from(old.len()).map_err(|_| error("short string too long"))?;
        let new_len = u16::try_from(new.len()).map_err(|_| error("short string too long"))?;
        let mut result = Vec::new();
        let mut offset = self.format.body_offset();
        let mut copied = 0;
        let mut count = 0;
        while offset + 2 + old.len() <= self.bytes.len() {
            if self.bytes[offset..offset + 2] == old_len.to_be_bytes()
                && self.bytes[offset + 2..offset + 2 + old.len()] == old
            {
                let end = offset + 2 + old.len();
                let needed = result
                    .len()
                    .checked_add(offset - copied)
                    .and_then(|n| n.checked_add(2 + new.len()))
                    .and_then(|n| n.checked_add(self.bytes.len() - end))
                    .ok_or_else(|| error("length overflow"))?;
                if needed > MAX_FRAME + 4 {
                    return Err(error("packet too large"));
                }
                result.extend_from_slice(&self.bytes[copied..offset]);
                result.extend_from_slice(&new_len.to_be_bytes());
                result.extend_from_slice(&new);
                copied = end;
                offset = end;
                count += 1;
                if limit == Some(count) {
                    break;
                }
            } else {
                offset += 1;
            }
        }
        if count != 0 {
            result.extend_from_slice(&self.bytes[copied..]);
            self.bytes = result;
            self.fix_length();
            self.cursor = self.cursor.min(self.bytes.len());
            self.edited = true;
        }
        Ok(count)
    }

    /// Replace literal substrings in length-prefixed Latin-1 fields, scanning
    /// from the end as beta-29 does. Java regex patterns and replacement groups
    /// are deliberately rejected until their semantics are implemented.
    pub fn replace_substrings_literal(
        &mut self,
        old: &str,
        new: &str,
        limit: Option<usize>,
    ) -> Result<usize> {
        self.ensure_eva()?;
        if limit == Some(0) {
            return Ok(0);
        }
        if old.is_empty()
            || old.chars().any(|c| ".^$|?*+()[]{}\\".contains(c))
            || new.contains(['$', '\\'])
        {
            return Err(error(
                "empty or regex substring replacement is not supported",
            ));
        }
        if old.len() > usize::from(u16::MAX) * 2 || new.len() > usize::from(u16::MAX) * 2 {
            return Err(error("short string too long"));
        }
        let old_bytes = latin1_encode(old)?;
        let new_bytes = latin1_encode(new)?;
        let mut candidate = self.clone();
        let mut offset = candidate.bytes.len() as isize - 2 - old_bytes.len() as isize;
        let mut max = candidate.bytes.len();
        let mut count = 0;
        let mut scanned_bytes = 0usize;
        while offset >= candidate.format.body_offset() as isize {
            let i = offset as usize;
            if i + 2 <= candidate.bytes.len() {
                let length =
                    u16::from_be_bytes([candidate.bytes[i], candidate.bytes[i + 1]]) as usize;
                let end = i + 2 + length;
                if end <= candidate.bytes.len() && end <= max {
                    scanned_bytes = scanned_bytes
                        .checked_add(length)
                        .filter(|n| *n <= MAX_FRAME)
                        .ok_or_else(|| error("substring scan limit exceeded"))?;
                    let text = latin1_decode(&candidate.bytes[i + 2..end]);
                    if text.contains(old) {
                        let occurrences = text.matches(old).count();
                        let result_len = length
                            .checked_sub(occurrences * old_bytes.len())
                            .and_then(|n| {
                                occurrences
                                    .checked_mul(new_bytes.len())
                                    .and_then(|growth| n.checked_add(growth))
                            })
                            .filter(|n| *n <= usize::from(u16::MAX))
                            .ok_or_else(|| error("short string too long"))?;
                        if candidate.bytes.len() - length + result_len > MAX_FRAME + 4 {
                            return Err(error("packet too large"));
                        }
                        let replacement = text.replace(old, new);
                        candidate.replace_string(i, &replacement)?;
                        count += 1;
                        offset -= 1 + old_bytes.len() as isize;
                        if limit == Some(count) {
                            break;
                        }
                        if offset < 0 {
                            break;
                        }
                        max = offset as usize;
                    }
                }
            }
            offset -= 1;
        }
        *self = candidate;
        Ok(count)
    }
    pub fn stringify(&self) -> String {
        format!(
            "{}{}",
            if self.edited { '1' } else { '0' },
            latin1_decode(&self.bytes)
        )
    }
    pub fn from_stringified(s: &str) -> Result<Self> {
        Self::from_stringified_with_format(s, PacketFormat::EvaWire)
    }
    pub fn from_stringified_with_format(s: &str, format: PacketFormat) -> Result<Self> {
        let flag = *s
            .as_bytes()
            .first()
            .ok_or_else(|| error("empty serialized packet"))?;
        if flag != b'0' && flag != b'1' {
            return Err(error("invalid edited flag"));
        }
        let mut p = Self::from_bytes_with_format(format, latin1_encode(&s[1..])?)?;
        p.edited = flag == b'1';
        Ok(p)
    }
    fn ensure_eva(&self) -> Result<()> {
        if self.format == PacketFormat::EvaWire {
            Ok(())
        } else {
            Err(error("field is not supported by WEDGIE packets"))
        }
    }
}
#[derive(Debug, Clone)]
pub struct Message {
    pub packet: Packet,
    pub direction: Direction,
    pub index: i32,
    pub blocked: bool,
}
impl Message {
    pub fn stringify(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            u8::from(self.blocked),
            self.index,
            self.direction.name(),
            self.packet.stringify()
        )
    }
    pub fn parse(s: &str) -> Result<Self> {
        Self::parse_with_format(s, PacketFormat::EvaWire)
    }
    pub fn parse_with_format(s: &str, format: PacketFormat) -> Result<Self> {
        let mut fields = s.splitn(4, '\t');
        let blocked = match fields.next() {
            Some("1") => true,
            Some("0") => false,
            _ => return Err(error("invalid blocked flag")),
        };
        let index = fields
            .next()
            .ok_or_else(|| error("missing index"))?
            .parse()
            .map_err(|_| error("invalid index"))?;
        let direction = Direction::parse(fields.next().ok_or_else(|| error("missing direction"))?)?;
        let packet = Packet::from_stringified_with_format(
            fields.next().ok_or_else(|| error("missing packet"))?,
            format,
        )?;
        Ok(Self {
            packet,
            direction,
            index,
            blocked,
        })
    }
}
pub fn latin1_decode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| char::from(*b)).collect()
}
pub fn latin1_encode(s: &str) -> Result<Vec<u8>> {
    s.chars()
        .map(|c| u8::try_from(c as u32).map_err(|_| error("character outside ISO-8859-1")))
        .collect()
}

/// Incremental decoder with bounded buffering and no drain/copy of retained frames.
#[derive(Default)]
pub struct FrameDecoder {
    bytes: Vec<u8>,
    start: usize,
}
impl FrameDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        // Leave room for a transport read containing the tail of a maximum-size
        // frame followed by the start of the next frame.
        if self.bytes.len() - self.start + bytes.len() > MAX_FRAME + 4 + 65536 {
            return Err(error("frame buffer limit exceeded"));
        }
        if self.start != 0 {
            self.bytes.drain(..self.start);
            self.start = 0;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    pub fn next_packet(&mut self) -> Result<Option<Packet>> {
        let available = &self.bytes[self.start..];
        if available.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_be_bytes(available[..4].try_into().unwrap()) as usize;
        if !(2..=MAX_FRAME).contains(&n) {
            return Err(error("invalid frame length"));
        }
        if available.len() < n + 4 {
            return Ok(None);
        }
        let p = Packet::from_bytes(available[..n + 4].to_vec())?;
        self.start += n + 4;
        if self.start == self.bytes.len() {
            self.bytes.clear();
            self.start = 0;
        }
        Ok(Some(p))
    }
}
pub fn read_frame(reader: &mut impl Read) -> io::Result<Packet> {
    let mut prefix = [0; 4];
    reader.read_exact(&mut prefix)?;
    let n = u32::from_be_bytes(prefix) as usize;
    if !(2..=MAX_FRAME).contains(&n) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut bytes = vec![0; n + 4];
    bytes[..4].copy_from_slice(&prefix);
    reader.read_exact(&mut bytes[4..])?;
    Packet::from_bytes(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
pub fn write_frame(writer: &mut impl Write, packet: &Packet) -> io::Result<()> {
    writer.write_all(packet.bytes())
}
