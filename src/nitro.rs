//! Pinned beta-29 Nitro hotel selection and wire modifiers.
use crate::{crypto::Rc4,packet::{Direction,Packet}};
use std::{io,path::Path};
const CONFIG_LIMIT:u64=1024*1024;
#[derive(Clone,Debug,PartialEq,Eq)]
pub enum HotelKind {Plain,HubbeSt,HabboSk,Hartico,HabboCity}
#[derive(Clone,Debug)]
pub struct Hotel {pub name:String,pub websocket_urls:Vec<String>,pub kind:HotelKind}
impl Hotel {
    pub fn matches(&self,url:&str)->bool {let url=url.split('?').next().unwrap_or(url);self.websocket_urls.iter().any(|pattern|match pattern.strip_suffix('*'){Some(prefix)=>url.starts_with(prefix),None=>url==pattern})}
}
#[derive(Clone,Default)] pub struct Hotels {pub entries:Vec<Hotel>}
impl Hotels {
    pub fn beta29()->Self {let mut result=Self::default();for (name,urls,kind) in [
        ("habbocity.fr",vec!["wss://websocket.habbocity.fr/websocket/"],HotelKind::HabboCity),
        ("hartico.tv",vec!["wss://server.hartico.tv/"],HotelKind::Hartico),
        ("habbosk.us",vec!["wss://game-ws.habbosk.us/ws"],HotelKind::HabboSk),
        ("hubbe.st",vec!["wss://ws.hubbe.st:2053/"],HotelKind::HubbeSt),
        ("hubbe.biz",vec!["wss://socket.hubbe.biz/"],HotelKind::Plain),
        ("leet",vec!["wss://proxy.leet.city/*","wss://proxy.leethotel.biz/*","wss://game.habblet.city/*"],HotelKind::Plain),
    ]{result.entries.push(Hotel {name:name.into(),websocket_urls:urls.into_iter().map(str::to_owned).collect(),kind});}result}
    pub fn from_json(bytes:&[u8])->io::Result<Self> {
        if bytes.len()>CONFIG_LIMIT as usize{return Err(io::Error::other("nitro.json exceeds 1 MiB"));}
        let values:serde_json::Value=serde_json::from_slice(bytes).map_err(io::Error::other)?;let values=values.as_array().ok_or_else(||io::Error::other("nitro.json must contain an array"))?;
        if values.len()>256{return Err(io::Error::other("too many Nitro hotel configurations"));}
        let mut result=Self::default();for (index,value) in values.iter().enumerate(){
            let urls=value.get("websocketUrls").and_then(|v|v.as_array()).ok_or_else(||io::Error::other("websocketUrls must contain an array"))?;if urls.is_empty()||urls.len()>256{return Err(io::Error::other("websocketUrls must contain 1-256 URLs"));}
            let mut websocket_urls=Vec::new();for url in urls{let url=url.as_str().map(str::trim).filter(|s|!s.is_empty()&&s.len()<=8192).ok_or_else(||io::Error::other("invalid Nitro WebSocket URL"))?;websocket_urls.push(url.into());}
            let default=format!("nitro.json[{index}]");let name=value.get("name").and_then(|v|v.as_str()).map(str::trim).filter(|s|!s.is_empty()).unwrap_or(&default).into();result.entries.push(Hotel {name,websocket_urls,kind:HotelKind::Plain});
        }Ok(result)
    }
    pub fn load(path:&Path)->io::Result<Self> {use io::Read;let file=match std::fs::File::open(path){Ok(file)=>file,Err(e) if e.kind()==io::ErrorKind::NotFound=>return Ok(Self::default()),Err(e)=>return Err(e)};let mut bytes=Vec::new();file.take(CONFIG_LIMIT+1).read_to_end(&mut bytes)?;Self::from_json(&bytes)}
    /// Dynamic configurations precede the built-in list, matching beta-29.
    pub fn with_defaults(mut self)->Self {self.entries.extend(Self::beta29().entries);self}
    pub fn find(&self,url:&str)->Option<&Hotel>{self.entries.iter().find(|hotel|hotel.matches(url))}
}
pub enum Decoded {PacketBytes(Vec<u8>),Bypass(Vec<u8>)}
pub enum Modifier {Plain,HubbeSt {first:bool},HabboSk(Box<HabboSk>),Hartico(crate::nitro_assets::Hartico),HabboCity(Box<crate::nitro_city::HabboCity>)}
impl Modifier {
    pub fn new(kind:&HotelKind)->io::Result<Self>{match kind {HotelKind::Plain=>Ok(Self::Plain),HotelKind::HubbeSt=>Ok(Self::HubbeSt {first:true}),HotelKind::HabboSk=>Ok(Self::HabboSk(Box::new(HabboSk::new()?))),HotelKind::Hartico|HotelKind::HabboCity=>Err(io::Error::other("this hotel's asset-dependent encryption is not ported yet"))}}
    pub fn decode(&mut self,direction:Direction,mut bytes:Vec<u8>)->io::Result<Decoded>{match self {Self::Plain=>{},Self::HubbeSt {first}=>{if direction==Direction::ToServer&&*first{*first=false;return Ok(Decoded::Bypass(bytes));}},Self::HabboSk(codec)=>codec.decode(direction,&mut bytes)?,Self::Hartico(codec)=>codec.decode(direction,&mut bytes)?,Self::HabboCity(codec)=>codec.decode(direction,&mut bytes)?}Ok(Decoded::PacketBytes(bytes))}
    pub fn encode(&mut self,direction:Direction,mut bytes:Vec<u8>)->io::Result<Vec<u8>>{match self {Self::HabboSk(codec)=>codec.encode(direction,&mut bytes)?,Self::Hartico(codec)=>codec.encode(direction,&mut bytes)?,Self::HabboCity(codec)=>codec.encode(direction,&mut bytes)?,_=>{}}Ok(bytes)}
}
// Key bytes are the pinned upstream DEFAULT_KEY's hex decoding, not URL-decoded.
const SK_KEY_HEX:&str="253146253045402535442530436e25304152752531376342502530452d5f5169253542253136253144253142253742595825303342612531426655253146402532332531305357574a6f253131253141253139722535442531376d25303152362532336c5a6d58253038374225314425313342514d582530446252253031754e68472530302535452537425f2530416d544a4f2531397525354225304654253130664d6d51253144253142724d25303250502531432533422531344b4d73592531376d253032573476253345253545612535425862452531344025314455253132253046253036672530322530342537454b25334542562530432d253034253041672530462531452531444e732530442535455725313025363025313867253037253130253130742531452530352530322530384b6f253135253141492532302535434368565a322532326e25304625334325303525303937253130482531342531442530332531302530385062253036542f4963435025304671535f6a2530464e25314549752535432535435325314133253138622530372531302531422532364a2530302530322530362531386e253130253139253144253235253038496c2530435169776c2530426c25354325354330253136253139253135253145554d5a25304364253036557a2531432533452531352530355f253744253545";
pub struct HabboSk {out_read:Rc4,out_write:Rc4,in_read:Option<Rc4>,in_write:Option<Rc4>,client_random:Option<Vec<u8>>}
impl HabboSk {
    fn new()->io::Result<Self>{let key=crate::expression::parse_hex(SK_KEY_HEX).map_err(io::Error::other)?;let cipher=Rc4::new(&key).map_err(io::Error::other)?;Ok(Self {out_read:cipher.clone(),out_write:cipher,in_read:None,in_write:None,client_random:None})}
    fn decode(&mut self,direction:Direction,bytes:&mut [u8])->io::Result<()> {
        if direction==Direction::ToServer {self.out_read.apply(bytes);if self.client_random.is_none(){let mut packet=Packet::from_bytes(bytes.to_vec()).map_err(io::Error::other)?;if packet.header()==3792{let value=packet.read_string().map_err(io::Error::other)?;self.client_random=Some(value.chars().map(|c|if c.is_ascii(){c as u8}else{b'?'}).collect());}}}else if let Some(cipher)=&mut self.in_read{cipher.apply(bytes);}Ok(())
    }
    fn encode(&mut self,direction:Direction,bytes:&mut [u8])->io::Result<()> {
        if direction==Direction::ToServer{self.out_write.apply(bytes);}else if let Some(cipher)=&mut self.in_write{cipher.apply(bytes);}else{let mut packet=Packet::from_bytes(bytes.to_vec()).map_err(io::Error::other)?;if packet.header()==9384{let server=packet.read_string().map_err(io::Error::other)?;let mut key=self.client_random.clone().ok_or_else(||io::Error::other("HabboSK client key was not received"))?;key.extend(server.chars().map(|c|if c.is_ascii(){c as u8}else{b'?'}));use md5::{Digest,Md5};let out=Md5::digest(&key).iter().map(|b|format!("{b:02x}")).collect::<String>();self.out_read=Rc4::new(out.as_bytes()).map_err(io::Error::other)?;self.out_write=self.out_read.clone();self.in_read=Some(Rc4::new(&key).map_err(io::Error::other)?);self.in_write=self.in_read.clone();}}Ok(())
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn beta29_leet_and_habblet_prefixes_strip_only_the_query(){let hotels=Hotels::beta29();assert_eq!(hotels.find("wss://game.habblet.city/game?token=test").unwrap().name,"leet");assert!(hotels.find("wss://game.habblet.city.attacker.invalid/game").is_none());assert!(hotels.find("wss://socket.hubbe.biz/?x=1").is_some());assert!(hotels.find("wss://socket.hubbe.biz/other").is_none());}
    #[test] fn parses_original_dynamic_configuration_and_preserves_precedence(){let hotels=Hotels::from_json(br#"[{"name":" custom ","websocketUrls":[" wss://game.habblet.city/* "]}]"#).unwrap().with_defaults();assert_eq!(hotels.find("wss://game.habblet.city/game").unwrap().name,"custom");for invalid in [r#"{}"#,r#"[{"websocketUrls":[]}]"#,r#"[{"websocketUrls":[""]}]"#]{assert!(Hotels::from_json(invalid.as_bytes()).is_err());}}
    #[test] fn hubbe_st_bypasses_exactly_one_outgoing_frame(){let mut modifier=Modifier::new(&HotelKind::HubbeSt).unwrap();assert!(matches!(modifier.decode(Direction::ToClient,vec![1]).unwrap(),Decoded::PacketBytes(_)));assert!(matches!(modifier.decode(Direction::ToServer,vec![2]).unwrap(),Decoded::Bypass(_)));assert!(matches!(modifier.decode(Direction::ToServer,vec![3]).unwrap(),Decoded::PacketBytes(_)));}
    #[test] fn habbosk_keeps_independent_streams_when_packets_are_blocked_or_injected(){
        let mut codec=HabboSk::new().unwrap();let default=crate::expression::parse_hex(SK_KEY_HEX).unwrap();let mut client=Rc4::new(&default).unwrap();let mut server=client.clone();let mut hello=Packet::new(3792);hello.put_string("client").unwrap();let mut bytes=hello.bytes().to_vec();client.apply(&mut bytes);codec.decode(Direction::ToServer,&mut bytes).unwrap();assert_eq!(bytes,hello.bytes());codec.encode(Direction::ToServer,&mut bytes).unwrap();server.apply(&mut bytes);assert_eq!(bytes,hello.bytes());
        let mut reply=Packet::new(9384);reply.put_string("server").unwrap();let mut bytes=reply.bytes().to_vec();codec.encode(Direction::ToClient,&mut bytes).unwrap();assert_eq!(bytes,reply.bytes());
        use md5::{Digest,Md5};let key=Md5::digest(b"clientserver").iter().map(|b|format!("{b:02x}")).collect::<String>();let mut client=Rc4::new(key.as_bytes()).unwrap();let mut server=client.clone();
        for header in [77,78]{let mut bytes=Packet::new(header).bytes().to_vec();client.apply(&mut bytes);codec.decode(Direction::ToServer,&mut bytes).unwrap();assert_eq!(Packet::from_bytes(bytes.clone()).unwrap().header(),header);if header==78{codec.encode(Direction::ToServer,&mut bytes).unwrap();server.apply(&mut bytes);assert_eq!(Packet::from_bytes(bytes).unwrap().header(),78);}}
        let mut bytes=Packet::new(79).bytes().to_vec();codec.encode(Direction::ToServer,&mut bytes).unwrap();server.apply(&mut bytes);assert_eq!(Packet::from_bytes(bytes).unwrap().header(),79);
        let mut server=Rc4::new(b"clientserver").unwrap();let mut client=server.clone();let original=Packet::new(88);let mut bytes=original.bytes().to_vec();server.apply(&mut bytes);codec.decode(Direction::ToClient,&mut bytes).unwrap();assert_eq!(bytes,original.bytes());codec.encode(Direction::ToClient,&mut bytes).unwrap();client.apply(&mut bytes);assert_eq!(bytes,original.bytes());
    }
}
