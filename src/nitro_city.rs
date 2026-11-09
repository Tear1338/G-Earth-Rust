//! HabboCity beta-29 GCM handshake and independent CTR streams.
use crate::packet::{Direction, Packet};
use std::io;
#[derive(Clone)]
pub struct CityKeys {
    key: Vec<u8>,
    iv: Vec<u8>,
    salt_key: Vec<Vec<u8>>,
    salt_iv: Vec<Vec<u8>>,
}
impl CityKeys {
    pub fn from_json(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > 65536 {
            return Err(io::Error::other("Nitro helper response exceeds 64 KiB"));
        }
        let json: serde_json::Value = serde_json::from_slice(bytes).map_err(io::Error::other)?;
        if json.get("status").and_then(|s| s.as_str()) != Some("ok") {
            return Err(io::Error::other(
                "Nitro helper did not return successful key data",
            ));
        }
        let result = json
            .get("result")
            .ok_or_else(|| io::Error::other("missing Nitro helper result"))?;
        fn hex(value: &serde_json::Value) -> io::Result<Vec<u8>> {
            let value = value
                .as_str()
                .ok_or_else(|| io::Error::other("expected a hexadecimal key"))?;
            if value.len() > 8192 {
                return Err(io::Error::other("Nitro salt too large"));
            }
            crate::expression::parse_hex(value).map_err(io::Error::other)
        }
        fn salts(value: Option<&serde_json::Value>) -> io::Result<Vec<Vec<u8>>> {
            let values = value
                .and_then(|v| v.as_array())
                .filter(|v| !v.is_empty() && v.len() <= 64)
                .ok_or_else(|| io::Error::other("expected 1-64 Nitro salts"))?;
            values.iter().map(hex).collect()
        }
        let key = hex(result
            .get("aes_key")
            .ok_or_else(|| io::Error::other("missing AES key"))?)?;
        let iv = hex(result
            .get("aes_iv")
            .ok_or_else(|| io::Error::other("missing AES IV"))?)?;
        if ![16, 24, 32].contains(&key.len()) || ![12, 16].contains(&iv.len()) {
            return Err(io::Error::other(
                "unsupported HabboCity AES key or GCM nonce size",
            ));
        }
        Ok(Self {
            key,
            iv,
            salt_key: salts(result.get("salt_key"))?,
            salt_iv: salts(result.get("salt_iv"))?,
        })
    }
    fn handshake(&self, bytes: &[u8], encrypt: bool) -> io::Result<Vec<u8>> {
        use aes_gcm::{
            aead::{
                consts::{U12, U16},
                Aead, KeyInit,
            },
            AesGcm, Nonce,
        };
        macro_rules! cipher {
            ($aes:ty,$size:ty) => {{
                let cipher = AesGcm::<$aes, $size>::new_from_slice(&self.key)
                    .map_err(|_| io::Error::other("invalid AES key"))?;
                let nonce = Nonce::<$size>::from_slice(&self.iv);
                if encrypt {
                    cipher.encrypt(nonce, bytes)
                } else {
                    cipher.decrypt(nonce, bytes)
                }
                .map_err(|_| io::Error::other("HabboCity GCM authentication failed"))
            }};
        }
        match (self.key.len(), self.iv.len()) {
            (16, 12) => cipher!(aes::Aes128, U12),
            (24, 12) => cipher!(aes::Aes192, U12),
            (32, 12) => cipher!(aes::Aes256, U12),
            (16, 16) => cipher!(aes::Aes128, U16),
            (24, 16) => cipher!(aes::Aes192, U16),
            (32, 16) => cipher!(aes::Aes256, U16),
            _ => Err(io::Error::other("unsupported AES parameters")),
        }
    }
}
type Stream = ctr::Ctr128BE<aes::Aes128>;
pub struct HabboCity {
    keys: CityKeys,
    ciphers: Option<[Stream; 4]>,
    first_client: bool,
    first_server: bool,
}
impl HabboCity {
    pub fn new(keys: CityKeys) -> Self {
        Self {
            keys,
            ciphers: None,
            first_client: true,
            first_server: true,
        }
    }
    fn initialize(&mut self, bytes: &[u8]) -> io::Result<()> {
        use ctr::cipher::KeyIvInit;
        use sha2::{Digest, Sha256};
        let sso = Packet::from_bytes(bytes.to_vec())
            .map_err(io::Error::other)?
            .read_string()
            .map_err(io::Error::other)?;
        let digest = |salts: &[Vec<u8>]| {
            let mut hash = Sha256::new();
            if salts.len() == 1 {
                hash.update(sso.as_bytes());
                hash.update(&salts[0]);
            } else {
                for (index, salt) in salts.iter().enumerate() {
                    hash.update(salt);
                    if index + 1 < salts.len() {
                        hash.update(sso.as_bytes());
                    }
                }
            }
            hash.finalize()
        };
        let key = digest(&self.keys.salt_key);
        let iv = digest(&self.keys.salt_iv);
        let cipher = Stream::new_from_slices(&key[..16], &iv[..16]).map_err(io::Error::other)?;
        self.ciphers = Some(std::array::from_fn(|_| cipher.clone()));
        Ok(())
    }
    fn stream(&mut self, index: usize, bytes: &mut [u8]) -> io::Result<()> {
        use ctr::cipher::StreamCipher;
        self.ciphers
            .as_mut()
            .ok_or_else(|| io::Error::other("HabboCity handshake was not received"))?[index]
            .try_apply_keystream(bytes)
            .map_err(|_| io::Error::other("HabboCity CTR stream exhausted"))
    }
    pub fn decode(&mut self, direction: Direction, bytes: &mut Vec<u8>) -> io::Result<()> {
        if direction == Direction::ToServer && self.first_client {
            *bytes = self.keys.handshake(bytes, false)?;
            self.initialize(bytes)?;
            self.first_client = false;
            Ok(())
        } else {
            self.stream(
                if direction == Direction::ToServer {
                    0
                } else {
                    2
                },
                bytes,
            )
        }
    }
    pub fn encode(&mut self, direction: Direction, bytes: &mut Vec<u8>) -> io::Result<()> {
        if direction == Direction::ToServer && self.first_server {
            *bytes = self.keys.handshake(bytes, true)?;
            self.first_server = false;
            Ok(())
        } else {
            self.stream(
                if direction == Direction::ToServer {
                    3
                } else {
                    1
                },
                bytes,
            )
        }
    }
}
pub(crate) fn helper_multipart(wasm: &[u8]) -> io::Result<(String, Vec<u8>)> {
    if wasm.len() > 16 * 1024 * 1024 || !wasm.starts_with(b"\0asm\x01\0\0\0") {
        return Err(io::Error::other(
            "Nitro helper accepts only a bounded WebAssembly module",
        ));
    }
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
    let boundary = format!(
        "gearth-{}",
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let mut body=format!("--{boundary}\r\nContent-Disposition: form-data; name=\"wasm\"; filename=\"data.wasm\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    body.extend(wasm);
    body.extend(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok((format!("multipart/form-data; boundary={boundary}"), body))
}
/// This function must only be called after an explicit opt-in for the current session.
pub fn fetch_keys(wasm: &[u8]) -> io::Result<CityKeys> {
    use io::Read;
    let (content_type, body) = helper_multipart(wasm)?;
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(20))
        .redirects(0)
        .build();
    let response = agent
        .post("https://nitro.sulek.dev/habbocity")
        .set("Content-Type", &content_type)
        .send_bytes(&body)
        .map_err(io::Error::other)?;
    let mut response_bytes = Vec::new();
    response
        .into_reader()
        .take(65537)
        .read_to_end(&mut response_bytes)?;
    CityKeys::from_json(&response_bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn keys() -> CityKeys {
        CityKeys::from_json(br#"{"status":"ok","result":{"aes_key":"000102030405060708090a0b0c0d0e0f","aes_iv":"000102030405060708090a0b","salt_key":["11","22"],"salt_iv":["33"]}}"#).unwrap()
    }
    #[test]
    #[ignore = "requires the independent Java JCE oracle; run in java-compatibility CI"]
    fn java_crypto_matches_hotel_handshake_cbc_and_segmented_ctr() {
        let path = std::env::var("GEARTH_NITRO_CRYPTO_ORACLE")
            .expect("Java crypto oracle path is required");
        let data = std::fs::read_to_string(path).unwrap();
        let values: std::collections::BTreeMap<_, _> = data
            .lines()
            .map(|line| {
                let (name, hex) = line.split_once('=').unwrap();
                (name, crate::expression::parse_hex(hex).unwrap())
            })
            .collect();
        let mut keys = keys();
        let mut hello = Packet::new(2419);
        hello.put_string("fixture-sso").unwrap();
        assert_eq!(
            keys.handshake(hello.bytes(), true).unwrap(),
            values["gcm12"]
        );
        keys.iv = (0..16).collect();
        assert_eq!(
            keys.handshake(hello.bytes(), true).unwrap(),
            values["gcm16"]
        );
        assert_eq!(
            crate::nitro_assets::Hartico::new([43; 24]).encrypt(Packet::new(77).bytes(), [9; 8]),
            values["des"]
        );
        let mut city = HabboCity::new(keys);
        city.initialize(hello.bytes()).unwrap();
        for header in [77, 78] {
            let mut bytes = Packet::new(header).bytes().to_vec();
            city.stream(0, &mut bytes).unwrap();
            assert_eq!(bytes, values[format!("ctr{header}").as_str()]);
        }
        assert_eq!(values.len(), 5);
    }
    #[test]
    fn city_handshake_authenticates_and_streams_survive_dropped_and_injected_packets() {
        let keys = keys();
        let mut bridge = HabboCity::new(keys.clone());
        let mut client = HabboCity::new(keys.clone());
        let mut server = HabboCity::new(keys.clone());
        let mut handshake = Packet::new(2419);
        handshake.put_string("fixture-sso").unwrap();
        client.initialize(handshake.bytes()).unwrap();
        server.initialize(handshake.bytes()).unwrap();
        let encrypted = keys.handshake(handshake.bytes(), true).unwrap();
        let mut tampered = encrypted.clone();
        tampered[0] ^= 1;
        assert!(keys.handshake(&tampered, false).is_err());
        let mut bytes = encrypted;
        bridge.decode(Direction::ToServer, &mut bytes).unwrap();
        assert_eq!(bytes, handshake.bytes());
        bridge.encode(Direction::ToServer, &mut bytes).unwrap();
        assert_eq!(keys.handshake(&bytes, false).unwrap(), handshake.bytes());
        for header in [77, 78] {
            let mut bytes = Packet::new(header).bytes().to_vec();
            client.stream(0, &mut bytes).unwrap();
            bridge.decode(Direction::ToServer, &mut bytes).unwrap();
            assert_eq!(Packet::from_bytes(bytes.clone()).unwrap().header(), header);
            if header == 78 {
                bridge.encode(Direction::ToServer, &mut bytes).unwrap();
                server.stream(3, &mut bytes).unwrap();
                assert_eq!(Packet::from_bytes(bytes).unwrap().header(), 78);
            }
        }
        let mut bytes = Packet::new(79).bytes().to_vec();
        bridge.encode(Direction::ToServer, &mut bytes).unwrap();
        server.stream(3, &mut bytes).unwrap();
        assert_eq!(Packet::from_bytes(bytes).unwrap().header(), 79);
        let mut bytes = Packet::new(88).bytes().to_vec();
        server.stream(2, &mut bytes).unwrap();
        bridge.decode(Direction::ToClient, &mut bytes).unwrap();
        assert_eq!(Packet::from_bytes(bytes.clone()).unwrap().header(), 88);
        bridge.encode(Direction::ToClient, &mut bytes).unwrap();
        client.stream(1, &mut bytes).unwrap();
        assert_eq!(Packet::from_bytes(bytes).unwrap().header(), 88);
    }
    #[test]
    fn invalid_helper_inputs_fail_before_any_network_request() {
        assert!(CityKeys::from_json(br#"{"status":"error"}"#).is_err());
        assert!(fetch_keys(b"not wasm").is_err());
    }
}
