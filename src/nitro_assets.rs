//! Hotel assets are decoded locally. No uploads or operating-system changes.
use std::io;
pub fn hartico_key(png_bytes: &[u8]) -> io::Result<[u8; 24]> {
    if png_bytes.len() > 16 * 1024 * 1024 {
        return Err(io::Error::other("Hartico PNG exceeds 16 MiB"));
    }
    let mut decoder = png::Decoder::new(std::io::Cursor::new(png_bytes));
    decoder.set_limits(png::Limits {
        bytes: 64 * 1024 * 1024,
    });
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().map_err(io::Error::other)?;
    let size = reader.output_buffer_size();
    if size > 64 * 1024 * 1024 {
        return Err(io::Error::other("decoded Hartico PNG exceeds 64 MiB"));
    }
    let mut pixels = vec![0; size];
    let info = reader.next_frame(&mut pixels).map_err(io::Error::other)?;
    let (stride, green) = match info.color_type {
        png::ColorType::Rgba => (4, 1),
        png::ColorType::Rgb => (3, 1),
        png::ColorType::GrayscaleAlpha => (2, 0),
        png::ColorType::Grayscale => (1, 0),
        _ => return Err(io::Error::other("unsupported Hartico PNG pixel format")),
    };
    if info.bit_depth != png::BitDepth::Eight || info.buffer_size() / stride < 128 {
        return Err(io::Error::other(
            "Hartico PNG must contain at least 128 pixels",
        ));
    }
    let mut key = [0; 24];
    for i in 0..128 {
        key[i / 8] = (key[i / 8] << 1) | (pixels[i * stride + green] & 1);
    }
    for i in 0..8 {
        key[16 + i] = key[i];
    }
    Ok(key)
}
pub struct Hartico {
    key: [u8; 24],
    authenticated: bool,
}
impl Hartico {
    pub fn new(key: [u8; 24]) -> Self {
        Self {
            key,
            authenticated: false,
        }
    }
    pub fn decode(
        &mut self,
        direction: crate::packet::Direction,
        bytes: &mut Vec<u8>,
    ) -> io::Result<()> {
        use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        if direction == crate::packet::Direction::ToServer && self.authenticated {
            if bytes.len() < 16 || !bytes.len().is_multiple_of(8) {
                return Err(io::Error::other("invalid Hartico encrypted frame"));
            }
            *bytes = cbc::Decryptor::<des::TdesEde3>::new((&self.key).into(), (&bytes[..8]).into())
                .decrypt_padded_vec_mut::<Pkcs7>(&bytes[8..])
                .map_err(|_| io::Error::other("invalid Hartico ciphertext padding"))?;
        }
        Ok(())
    }
    pub fn encode(
        &mut self,
        direction: crate::packet::Direction,
        bytes: &mut Vec<u8>,
    ) -> io::Result<()> {
        if direction == crate::packet::Direction::ToServer && self.authenticated {
            let mut iv = [0; 8];
            getrandom::fill(&mut iv).map_err(|e| io::Error::other(e.to_string()))?;
            *bytes = self.encrypt(bytes, iv);
        } else if direction == crate::packet::Direction::ToClient
            && bytes.as_slice() == [0, 0, 0, 2, 9, 187]
        {
            self.authenticated = true;
        }
        Ok(())
    }
    pub(crate) fn encrypt(&self, bytes: &[u8], iv: [u8; 8]) -> Vec<u8> {
        use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        let mut result = iv.to_vec();
        result.extend(
            cbc::Encryptor::<des::TdesEde3>::new((&self.key).into(), (&iv).into())
                .encrypt_padded_vec_mut::<Pkcs7>(bytes),
        );
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Direction, Packet};
    #[test]
    fn extracts_green_lsb_key_and_repeats_first_eight_bytes() {
        let expected: [u8; 16] = std::array::from_fn(|i| i as u8 * 13);
        let mut pixels = vec![0u8; 128 * 4];
        for i in 0..128 {
            pixels[i * 4] = 123;
            pixels[i * 4 + 1] = ((expected[i / 8] >> (7 - i % 8)) & 1) | 128;
            pixels[i * 4 + 2] = 25;
            pixels[i * 4 + 3] = 255;
        }
        let mut bytes = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut bytes, 128, 1);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            encoder
                .write_header()
                .unwrap()
                .write_image_data(&pixels)
                .unwrap();
        }
        let key = hartico_key(&bytes).unwrap();
        assert_eq!(&key[..16], &expected);
        assert_eq!(&key[16..], &expected[..8]);
        assert!(hartico_key(b"not a png").is_err());
    }
    #[test]
    fn switches_to_cbc_only_after_server_authentication() {
        let mut codec = Hartico::new([43; 24]);
        let original = Packet::new(77).bytes().to_vec();
        let mut plain = original.clone();
        codec.decode(Direction::ToServer, &mut plain).unwrap();
        assert_eq!(plain, original);
        codec
            .encode(Direction::ToClient, &mut vec![0, 0, 0, 2, 9, 187])
            .unwrap();
        let mut encrypted = codec.encrypt(&original, [9; 8]);
        assert_ne!(encrypted, original);
        codec.decode(Direction::ToServer, &mut encrypted).unwrap();
        assert_eq!(encrypted, original);
        codec.encode(Direction::ToServer, &mut encrypted).unwrap();
        codec.decode(Direction::ToServer, &mut encrypted).unwrap();
        assert_eq!(encrypted, original);
        assert!(codec.decode(Direction::ToServer, &mut vec![0; 7]).is_err());
    }
}
