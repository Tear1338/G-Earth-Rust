//! Origins WEDGIE transport and beta-29 Bobba DH/HKDF/ChaCha7539 handshake.
use crate::{encoding::{encode_b64,decode_b64},packet::{Packet,PacketFormat,MAX_FRAME}};
use base64::{Engine,engine::general_purpose::STANDARD_NO_PAD};
use chacha20::{ChaCha20,cipher::{KeyIvInit,StreamCipher}};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::Sha256;
use std::io;
const G:&[u8]=b"23786635532332886537261431906453031264918297";
const P:&[u8]=b"632158881801130885249042417232212770524741295422564233061391190031954228421232913648184592218883487397503624904102572293826728806813079";
const MAX_CHUNK:usize=262143;
#[derive(Clone)]
pub struct ChaChaKey {pub key:[u8;32],pub nonce:[u8;12],counter:u64}
impl ChaChaKey {
    pub fn apply(&mut self,data:&mut [u8]) {
        let mut nonce=self.nonce;let base=u64::from_le_bytes(nonce[4..12].try_into().unwrap());nonce[4..12].copy_from_slice(&base.wrapping_add(self.counter).to_le_bytes());self.counter=self.counter.wrapping_add(1);
        ChaCha20::new((&self.key).into(),(&nonce).into()).apply_keystream(data);
    }
}
#[derive(Clone)]
pub struct BobbaKeys {pub c2s_data:ChaChaKey,pub c2s_header:ChaChaKey,pub s2c_data:ChaChaKey,pub s2c_header:ChaChaKey}
pub struct BobbaCrypto {private:BigUint,public:BigUint,keys:Option<BobbaKeys>}
impl BobbaCrypto {
    pub fn random()->io::Result<Self> {let mut bytes=[0;8];loop{getrandom::fill(&mut bytes).map_err(|e|io::Error::other(e.to_string()))?;let n=u64::from_be_bytes(bytes);if n!=0{return Self::with_private(n);}}}
    pub fn with_private(private:u64)->io::Result<Self> {if private==0{return Err(io::Error::other("zero DH private key"));}let private=BigUint::from(private);let modulus=BigUint::parse_bytes(P,10).unwrap();let public=BigUint::parse_bytes(G,10).unwrap().modpow(&private,&modulus);Ok(Self {private,public,keys:None})}
    pub fn public_key(&self)->String {self.public.to_str_radix(10)}
    pub fn set_peer(&mut self,public:&str)->io::Result<()> {
        if public.len()>512{return Err(io::Error::other("DH public key too large"));}
        let public=BigUint::parse_bytes(public.as_bytes(),10).ok_or_else(||io::Error::other("invalid DH public key"))?;let modulus=BigUint::parse_bytes(P,10).unwrap();
        if public<=BigUint::from(1u8)||public>=modulus{return Err(io::Error::other("DH public key outside group"));}
        let shared=public.modpow(&self.private,&modulus).to_bytes_be();
        fn derive(shared:&[u8],purpose:&str)->io::Result<ChaChaKey> {
            let mut output=[0;44];Hkdf::<Sha256>::new(Some(b"BobbaXtraHKDFSalt"),shared).expand(format!("BobbaXtra|{purpose}").as_bytes(),&mut output).map_err(|_|io::Error::other("HKDF expansion failed"))?;
            Ok(ChaChaKey {key:output[..32].try_into().unwrap(),nonce:output[32..].try_into().unwrap(),counter:0})
        }
        self.keys=Some(BobbaKeys {c2s_data:derive(&shared,"bobba-c2s-data")?,c2s_header:derive(&shared,"bobba-c2s-header")?,s2c_data:derive(&shared,"bobba-s2c-data")?,s2c_header:derive(&shared,"bobba-s2c-header")?});Ok(())
    }
    pub fn keys(&self)->io::Result<&BobbaKeys>{self.keys.as_ref().ok_or_else(||io::Error::other("DH exchange not completed"))}
    pub fn keys_mut(&mut self)->io::Result<&mut BobbaKeys>{self.keys.as_mut().ok_or_else(||io::Error::other("DH exchange not completed"))}
}
#[derive(Default)]
struct Buffer {bytes:Vec<u8>,start:usize,decoded_length:Option<usize>}
impl Buffer {
    fn push(&mut self,bytes:&[u8])->io::Result<()> {if self.bytes.len()-self.start+bytes.len()>MAX_FRAME+65536{return Err(io::Error::other("Origins buffer limit"));}if self.start>0{self.bytes.drain(..self.start);self.start=0;}self.bytes.extend_from_slice(bytes);Ok(())}
    fn delimiter(&mut self)->Option<Vec<u8>> {let tail=&self.bytes[self.start..];let n=tail.iter().position(|b|*b==1)?;let bytes=tail[..n].to_vec();self.start+=n+1;Some(bytes)}
    fn chunk(&mut self,header_key:Option<&mut ChaChaKey>)->io::Result<Option<Vec<u8>>> {
        let header_size=if header_key.is_some(){6}else{3};let tail=&self.bytes[self.start..];if tail.len()<header_size{return Ok(None);}
        let n=if let Some(n)=self.decoded_length{n}else{
            let bytes=if let Some(key)=header_key{let mut header=STANDARD_NO_PAD.decode(&tail[..6]).map_err(io::Error::other)?;if header.len()!=4{return Err(io::Error::other("invalid encrypted Origins header"));}key.apply(&mut header);header[1..].to_vec()}else{tail[..3].to_vec()};
            let n=decode_b64(&bytes).map_err(io::Error::other)? as usize;if !(2..=MAX_CHUNK).contains(&n){return Err(io::Error::other("invalid Origins chunk length"));}self.decoded_length=Some(n);n
        };
        if tail.len()<header_size+n{return Ok(None);}let data=tail[header_size..header_size+n].to_vec();self.start+=header_size+n;self.decoded_length=None;Ok(Some(data))
    }
    fn take_tail(&mut self)->Vec<u8>{let remaining=self.bytes[self.start..].to_vec();self.bytes.clear();self.start=0;remaining}
}
pub struct ShockwaveTransport {client:BobbaCrypto,server:BobbaCrypto,client_encrypted:bool,server_encrypted:bool,client_buffer:Buffer,server_buffer:Buffer,server_plain:Buffer}
impl ShockwaveTransport {
    pub fn new()->io::Result<Self>{Ok(Self {client:BobbaCrypto::random()?,server:BobbaCrypto::random()?,client_encrypted:false,server_encrypted:false,client_buffer:Buffer::default(),server_buffer:Buffer::default(),server_plain:Buffer::default()})}
    pub fn client_packets(&mut self,bytes:&[u8])->io::Result<Vec<Packet>> {
        self.client_buffer.push(bytes)?;let mut packets=Vec::new();
        loop {
            let header=if self.client_encrypted{Some(&mut self.client.keys_mut()?.c2s_header)}else{None};let Some(mut bytes)=self.client_buffer.chunk(header)? else{break;};
            if self.client_encrypted{bytes=STANDARD_NO_PAD.decode(&bytes).map_err(io::Error::other)?;self.client.keys_mut()?.c2s_data.apply(&mut bytes);}
            let mut packet=Packet::from_bytes_with_format(PacketFormat::WedgieOutgoing,bytes).map_err(io::Error::other)?;
            if !self.client_encrypted&&packet.header()==202{self.client.set_peer(&packet.read_string().map_err(io::Error::other)?)?;packet.reset();}
            packets.push(packet);
        }
        Ok(packets)
    }
    pub fn server_packets(&mut self,bytes:&[u8])->io::Result<Vec<Packet>> {
        let mut packets=Vec::new();
        if !self.server_encrypted{
            self.server_plain.push(bytes)?;
            while let Some(bytes)=self.server_plain.delimiter(){
                let mut packet=Packet::from_bytes_with_format(PacketFormat::WedgieIncoming,bytes).map_err(io::Error::other)?;
                if packet.header()==1{self.server.set_peer(&packet.read_string().map_err(io::Error::other)?)?;self.server_encrypted=true;packet.reset();packets.push(packet);let tail=self.server_plain.take_tail();self.server_buffer.push(&tail)?;break;}
                packets.push(packet);
            }
            if !self.server_encrypted{return Ok(packets);}
        }else{self.server_buffer.push(bytes)?;}
        while let Some(bytes)=self.server_buffer.chunk(Some(&mut self.server.keys_mut()?.s2c_header))?{
            let mut decoded=STANDARD_NO_PAD.decode(bytes).map_err(io::Error::other)?;self.server.keys_mut()?.s2c_data.apply(&mut decoded);self.server_plain.push(&decoded)?;
            while let Some(bytes)=self.server_plain.delimiter(){packets.push(Packet::from_bytes_with_format(PacketFormat::WedgieIncoming,bytes).map_err(io::Error::other)?);}
        }
        Ok(packets)
    }
    pub fn encode_to_server(&mut self,packet:&Packet)->io::Result<Vec<u8>> {
        if packet.format()!=PacketFormat::WedgieOutgoing{return Err(io::Error::other("Origins server packet has wrong format"));}
        if self.server_encrypted{let keys=self.server.keys_mut()?;return encrypt(packet.bytes(),&mut keys.c2s_header,&mut keys.c2s_data);}
        let bytes=if packet.header()==202{let mut replacement=Packet::new_with_format(PacketFormat::WedgieOutgoing,202).map_err(io::Error::other)?;replacement.put_string(&self.server.public_key()).map_err(io::Error::other)?;replacement.bytes().to_vec()}else{packet.bytes().to_vec()};
        let mut framed=encode_b64(bytes.len() as u32,3).map_err(io::Error::other)?;framed.extend(bytes);Ok(framed)
    }
    pub fn encode_to_client(&mut self,packet:&Packet)->io::Result<Vec<u8>> {
        if packet.format()!=PacketFormat::WedgieIncoming{return Err(io::Error::other("Origins client packet has wrong format"));}
        if self.client_encrypted{let mut bytes=packet.bytes().to_vec();bytes.push(1);let keys=self.client.keys_mut()?;return encrypt(&bytes,&mut keys.s2c_header,&mut keys.s2c_data);}
        let mut bytes=if packet.header()==1{self.client.keys()?;let mut replacement=Packet::new_with_format(PacketFormat::WedgieIncoming,1).map_err(io::Error::other)?;replacement.put_string(&self.client.public_key()).map_err(io::Error::other)?;self.client_encrypted=true;replacement.bytes().to_vec()}else{packet.bytes().to_vec()};bytes.push(1);Ok(bytes)
    }
}
fn encrypt(bytes:&[u8],header_key:&mut ChaChaKey,data_key:&mut ChaChaKey)->io::Result<Vec<u8>> {
    let mut data=bytes.to_vec();data_key.apply(&mut data);let encoded=STANDARD_NO_PAD.encode(data);if encoded.len()>MAX_CHUNK{return Err(io::Error::other("Origins encrypted chunk too large"));}
    let mut random=[0;1];getrandom::fill(&mut random).map_err(|e|io::Error::other(e.to_string()))?;
    let mut header=vec![1+random[0]%126];header.extend(encode_b64(encoded.len() as u32,3).map_err(io::Error::other)?);header_key.apply(&mut header);let mut result=STANDARD_NO_PAD.encode(header).into_bytes();result.extend_from_slice(encoded.as_bytes());Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn decode_wire(wire:&[u8],header:&mut ChaChaKey,data:&mut ChaChaKey)->Vec<u8>{let mut buffer=Buffer::default();buffer.push(wire).unwrap();let raw=buffer.chunk(Some(header)).unwrap().unwrap();let mut bytes=STANDARD_NO_PAD.decode(raw).unwrap();data.apply(&mut bytes);bytes}
    #[test]
    fn complete_origins_handshake_with_fragmented_encrypted_packets() {
        let mut proxy=ShockwaveTransport::new().unwrap();let mut client=BobbaCrypto::with_private(12345).unwrap();let mut server=BobbaCrypto::with_private(67890).unwrap();
        let mut key_request=Packet::new_with_format(PacketFormat::WedgieOutgoing,202).unwrap();key_request.put_string(&client.public_key()).unwrap();let mut wire=encode_b64(key_request.bytes().len() as u32,3).unwrap();wire.extend_from_slice(key_request.bytes());
        let mut received=Vec::new();for byte in wire{received.extend(proxy.client_packets(&[byte]).unwrap());}assert_eq!(received.len(),1);
        let forwarded=proxy.encode_to_server(&received[0]).unwrap();let mut request=Packet::from_bytes_with_format(PacketFormat::WedgieOutgoing,forwarded[3..].to_vec()).unwrap();server.set_peer(&request.read_string().unwrap()).unwrap();
        let mut reply=Packet::new_with_format(PacketFormat::WedgieIncoming,1).unwrap();reply.put_string(&server.public_key()).unwrap();let mut wire=reply.bytes().to_vec();wire.push(1);let packets=proxy.server_packets(&wire).unwrap();let forwarded=proxy.encode_to_client(&packets[0]).unwrap();let mut response=Packet::from_bytes_with_format(PacketFormat::WedgieIncoming,forwarded[..forwarded.len()-1].to_vec()).unwrap();client.set_peer(&response.read_string().unwrap()).unwrap();
        let mut outgoing=Packet::new_with_format(PacketFormat::WedgieOutgoing,77).unwrap();outgoing.put_i32(42).unwrap();let keys=client.keys_mut().unwrap();let wire=encrypt(outgoing.bytes(),&mut keys.c2s_header,&mut keys.c2s_data).unwrap();
        let mut packets=Vec::new();for byte in wire{packets.extend(proxy.client_packets(&[byte]).unwrap());}assert_eq!(packets.len(),1);assert_eq!(packets[0].bytes(),outgoing.bytes());
        let wire=proxy.encode_to_server(&packets[0]).unwrap();let keys=server.keys_mut().unwrap();assert_eq!(decode_wire(&wire,&mut keys.c2s_header,&mut keys.c2s_data),outgoing.bytes());
        let mut incoming=Packet::new_with_format(PacketFormat::WedgieIncoming,78).unwrap();incoming.put_string("hello").unwrap();let mut plain=incoming.bytes().to_vec();plain.push(1);let keys=server.keys_mut().unwrap();let wire=encrypt(&plain,&mut keys.s2c_header,&mut keys.s2c_data).unwrap();
        let mut packets=Vec::new();for byte in wire{packets.extend(proxy.server_packets(&[byte]).unwrap());}assert_eq!(packets.len(),1);assert_eq!(packets[0].bytes(),incoming.bytes());let wire=proxy.encode_to_client(&packets[0]).unwrap();let keys=client.keys_mut().unwrap();assert_eq!(decode_wire(&wire,&mut keys.s2c_header,&mut keys.s2c_data),plain);
    }
}
