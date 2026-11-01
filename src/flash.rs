//! Flash negotiation and bounded RC4 recovery from read-only client snapshots.
use crate::{crypto::Rc4,packet::{Direction,Packet,MAX_FRAME}};
use std::{io,sync::atomic::{AtomicBool,Ordering},time::{Duration,Instant}};
const BOOTSTRAP_LIMIT:usize=65536;
#[derive(Default)]
struct Side {buffer:Vec<u8>,encrypted:bool,reader:Option<Rc4>,writer:Option<Rc4>,waiting:Option<Instant>}
impl Side {
    fn feed(&mut self,bytes:&[u8])->io::Result<()> {
        if self.buffer.len()+bytes.len()>if self.encrypted&&self.reader.is_none(){BOOTSTRAP_LIMIT}else{MAX_FRAME+65536}{return Err(io::Error::other("Flash buffer limit exceeded"));}
        let start=self.buffer.len();self.buffer.extend_from_slice(bytes);if let Some(cipher)=&mut self.reader{cipher.apply(&mut self.buffer[start..]);}Ok(())
    }
    fn next(&mut self)->io::Result<Option<Packet>> {
        if self.encrypted&&self.reader.is_none()||self.buffer.len()<4{return Ok(None);}
        let n=u32::from_be_bytes(self.buffer[..4].try_into().unwrap()) as usize;
        if !(2..=MAX_FRAME).contains(&n){return Err(io::Error::other("invalid Flash frame length"));}
        if self.buffer.len()<n+4{return Ok(None);}
        let p=Packet::from_bytes(self.buffer.drain(..n+4).collect()).map_err(io::Error::other)?;Ok(Some(p))
    }
    fn negotiate(&mut self){self.encrypted=true;self.waiting=Some(Instant::now());}
    fn install(&mut self,cipher:Rc4){self.writer=Some(cipher.clone());let mut reader=cipher;reader.apply(&mut self.buffer);self.reader=Some(reader);self.waiting=None;}
}
pub struct DecodedPacket {pub packet:Packet,pub encrypted:bool}
#[derive(Clone,Debug)] pub struct Identity {pub version:String,pub identifier:String}
#[derive(Default)]
pub struct FlashSession {outgoing:Side,incoming:Side,identity:Option<Identity>,reported:bool,incoming_count:usize,negotiated:bool,last_scan:Option<Instant>,scan_stats:Option<(usize,usize,bool)>}
impl FlashSession {
    pub fn feed(&mut self,direction:Direction,bytes:&[u8])->io::Result<Vec<DecodedPacket>> {
        self.side(direction).feed(bytes)?;let mut packets=Vec::new();
        loop {
            let side=self.side(direction);let encrypted=side.encrypted;let Some(packet)=side.next()?else{break;};
            self.observe(direction,&packet);packets.push(DecodedPacket {packet,encrypted});
        }Ok(packets)
    }
    fn side(&mut self,direction:Direction)->&mut Side {if direction==Direction::ToServer{&mut self.outgoing}else{&mut self.incoming}}
    fn observe(&mut self,direction:Direction,p:&Packet) {
        if direction==Direction::ToServer&&self.identity.is_none()&&p.bytes().len()<104 {
            let mut hello=p.clone();if let (Ok(version),Ok(identifier))=(hello.read_string(),hello.read_string()) {if hello.remaining()==0&&!version.is_empty(){self.identity=Some(Identity {version,identifier});}}
        }
        if direction==Direction::ToClient {
            if !self.negotiated&&self.identity.is_some()&&self.incoming_count<2 {
                let mut packet=p.clone();if packet.read_string().is_ok(){let remaining=packet.remaining();
                    if p.bytes().len()>504&&remaining==1 {let incoming=packet.read_bool().unwrap_or(false);self.outgoing.negotiate();if incoming{self.incoming.negotiate();}self.negotiated=true;}
                    else if p.bytes().len()>204&&remaining==0{self.outgoing.negotiate();self.negotiated=true;}
                }
            }self.incoming_count+=1;
        }
    }
    pub fn take_identity(&mut self)->Option<Identity>{if self.reported{return None;}let identity=self.identity.clone()?;self.reported=true;Some(identity)}
    pub fn encrypted(&mut self,direction:Direction)->bool{self.side(direction).encrypted}
    pub fn encode(&mut self,direction:Direction,packet:&Packet,encrypted:bool)->io::Result<Vec<u8>> {
        let mut bytes=packet.bytes().to_vec();if encrypted{let cipher=self.side(direction).writer.as_mut().ok_or_else(||io::Error::new(io::ErrorKind::WouldBlock,"Flash key discovery is still pending"))?;cipher.apply(&mut bytes);}Ok(bytes)
    }
    pub fn recover_with(&mut self,states:&[[u8;256]],cancel:&AtomicBool)->io::Result<bool> {
        for direction in [Direction::ToServer,Direction::ToClient]{
            let side=self.side(direction);if side.encrypted&&side.reader.is_none()&&side.buffer.len()>=6 {
                if let Some(cipher)=recover_state(states,&side.buffer,direction,cancel)?{side.install(cipher);}
            }
        }Ok([&self.outgoing,&self.incoming].iter().all(|s|!s.encrypted||s.reader.is_some()))
    }
    pub fn discover(&mut self,pid:u32,cancel:&AtomicBool)->io::Result<()> {
        let now=Instant::now();
        for side in [&self.outgoing,&self.incoming]{if side.waiting.is_some_and(|t|now.duration_since(t)>Duration::from_secs(15)){return Err(io::Error::new(io::ErrorKind::TimedOut,format!("Flash RC4 discovery timed out; scan {:?}; pending outgoing {} bytes, incoming {} bytes",self.scan_stats,if self.outgoing.reader.is_none(){self.outgoing.buffer.len()}else{0},if self.incoming.reader.is_none(){self.incoming.buffer.len()}else{0})));}}
        let pending=[&self.outgoing,&self.incoming].iter().any(|s|s.encrypted&&s.reader.is_none()&&s.buffer.len()>=6);
        if pending&&self.last_scan.is_none_or(|t|now.duration_since(t)>=Duration::from_millis(100)) {
            self.last_scan=Some(now);let scan=gearth_platform::scan_habbo(pid,cancel)?;self.scan_stats=Some((scan.states.len(),scan.bytes_read,scan.complete));self.recover_with(&scan.states,cancel)?;
        }Ok(())
    }
}
fn valid_frames(encrypted:&[u8],candidate:&Rc4)->bool {
    let mut decoded=encrypted.to_vec();candidate.clone().apply(&mut decoded);let mut at=0;let mut count=0;
    while at+6<=decoded.len(){let n=u32::from_be_bytes(decoded[at..at+4].try_into().unwrap()) as usize;if !(2..=MAX_FRAME).contains(&n)||at+n+4>decoded.len(){break;}at+=n+4;count+=1;}
    at==decoded.len()&&count>0
}
pub fn recover_state(states:&[[u8;256]],encrypted:&[u8],direction:Direction,cancel:&AtomicBool)->io::Result<Option<Rc4>> {
    if cancel.load(Ordering::Acquire){return Err(io::Error::new(io::ErrorKind::Interrupted,"key discovery cancelled"));}
    if encrypted.len()<6||encrypted.len()>BOOTSTRAP_LIMIT{return Ok(None);}
    // Flash commonly retains the fresh shared-secret table for the opposite direction.
    // Prefer that exact table over reversing a snapshot with an unknown j counter.
    let mut fresh=None;
    for state in states.iter().take(64){let candidate=Rc4::from_state(*state,0,0).map_err(io::Error::other)?;
        if valid_frames(encrypted,&candidate){if fresh.as_ref().is_some_and(|c:&Rc4|c.state()!=candidate.state()){return Ok(None);}fresh=Some(candidate);}
    }
    if fresh.is_some()||direction==Direction::ToClient{return Ok(fresh);}
    let deadline=Instant::now()+Duration::from_secs(5);let mut found=None;
    for state in states.iter().take(64){for y in 0..256 {
        if cancel.load(Ordering::Acquire){return Err(io::Error::new(io::ErrorKind::Interrupted,"key discovery cancelled"));}if Instant::now()>deadline{return Ok(None);}
        let mut candidate=Rc4::from_state(*state,encrypted.len() as u8,y as u8).map_err(io::Error::other)?;candidate.rewind(encrypted.len());
        let (_,x,y)=candidate.state();if x!=0||y!=0||!valid_frames(encrypted,&candidate){continue;}
        // Different reverse states can reproduce frame lengths yet corrupt the final body byte.
        // Wait for additional evidence rather than silently selecting the first match.
        if found.as_ref().is_some_and(|c:&Rc4|c.state()!=candidate.state()){return Ok(None);}found=Some(candidate);
    }}Ok(found)
}
