//! Explicit plaintext EVA_WIRE relay. One cancellable nonblocking transport loop.
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}, mpsc::{self, Receiver, SyncSender}};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use crate::packet::{Direction, FrameDecoder, Message, Packet};
use crate::rules::Rules;

const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;
#[derive(Debug, Clone)]
pub enum Event { Listening(SocketAddr), Connected(String), Disconnected, Packet(Message), Error(String) }
pub struct Config { pub listen: SocketAddr, pub remote: String }
struct Session { injections: SyncSender<(Direction,Packet)>, closed: Arc<AtomicBool> }
pub struct Relay {
    stop: Arc<AtomicBool>, active: Arc<Mutex<Option<Arc<Session>>>>,
    worker: Option<JoinHandle<()>>, rules: Arc<Mutex<Rules>>, pub address: SocketAddr,
}
impl Relay {
    pub fn start(config: Config) -> io::Result<(Self, Receiver<Event>)> {
        if !config.listen.ip().is_loopback() { return Err(io::Error::new(io::ErrorKind::InvalidInput,"listen address must be loopback")); }
        let remote: Vec<SocketAddr> = config.remote.to_socket_addrs()?.collect();
        if remote.is_empty() { return Err(io::Error::new(io::ErrorKind::InvalidInput,"remote has no addresses")); }
        let listener = TcpListener::bind(config.listen)?; listener.set_nonblocking(true)?; let address = listener.local_addr()?;
        let (events,rx) = mpsc::sync_channel(2048);
        let stop = Arc::new(AtomicBool::new(false)); let active = Arc::new(Mutex::new(None)); let rules = Arc::new(Mutex::new(Rules::default()));
        let (worker_stop,worker_active,worker_rules) = (stop.clone(),active.clone(),rules.clone());
        let worker = thread::spawn(move || {
            let _ = events.try_send(Event::Listening(address)); let mut index = 0i32;
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((client,_)) => {
                        let server = remote.iter().find_map(|addr| {
                            if worker_stop.load(Ordering::Acquire) { return None; }
                            TcpStream::connect_timeout(addr,Duration::from_secs(2)).ok()
                        });
                        let Some(server) = server else { let _ = events.try_send(Event::Error("remote connection failed".into())); continue; };
                        let (injections,commands) = mpsc::sync_channel(256); let closed = Arc::new(AtomicBool::new(false));
                        let session = Arc::new(Session {injections,closed:closed.clone()});
                        if let Ok(mut slot) = worker_active.lock() {
                            if worker_stop.load(Ordering::Acquire) { break; }
                            *slot = Some(session);
                        } else { break; }
                        let _ = events.try_send(Event::Connected(server.peer_addr().map(|v|v.to_string()).unwrap_or_default()));
                        let result = run_session(client,server,&worker_stop,&closed,&worker_rules,&events,commands,&mut index);
                        closed.store(true,Ordering::Release);
                        if let Err(e)=result { let _=events.try_send(Event::Error(e.to_string())); }
                        if let Ok(mut slot)=worker_active.lock() { *slot=None; }
                        let _ = events.try_send(Event::Disconnected);
                    }
                    Err(e) if e.kind()==io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                    Err(e) => {let _=events.try_send(Event::Error(e.to_string()));break;}
                }
            }
        });
        Ok((Self {stop,active,worker:Some(worker),rules,address},rx))
    }
    pub fn set_rules(&self,rules:Rules)->io::Result<()> {
        *self.rules.lock().map_err(|_|io::Error::other("rules lock poisoned"))?=rules;Ok(())
    }
    pub fn connected(&self)->bool {self.active.lock().map(|s|s.as_ref().is_some_and(|s|!s.closed.load(Ordering::Acquire))).unwrap_or(false)}
    /// Queue an injection. Delivery errors are reported through Event::Error.
    pub fn inject(&self,direction:Direction,packet:Packet)->io::Result<()> {
        let active=self.active.lock().map_err(|_|io::Error::other("session lock poisoned"))?;
        let session=active.as_ref().filter(|s|!s.closed.load(Ordering::Acquire)).ok_or_else(||io::Error::new(io::ErrorKind::NotConnected,"no active client"))?;
        session.injections.try_send((direction,packet)).map_err(|e|match e {
            mpsc::TrySendError::Full(_)=>io::Error::new(io::ErrorKind::WouldBlock,"injection queue full"),
            mpsc::TrySendError::Disconnected(_)=>io::Error::new(io::ErrorKind::NotConnected,"session closed"),
        })
    }
    pub fn stop(&mut self) {
        self.stop.store(true,Ordering::Release);
        if let Ok(active)=self.active.lock() {if let Some(s)=active.as_ref(){s.closed.store(true,Ordering::Release);}}
        if let Some(worker)=self.worker.take(){let _=worker.join();}
    }
}
impl Drop for Relay {fn drop(&mut self){self.stop();}}
struct Pending {packet:Packet,offset:usize}
#[derive(Default)]
struct Output {queue:VecDeque<Pending>,bytes:usize}
impl Output {
    fn push(&mut self,packet:Packet)->io::Result<()> {
        if self.bytes+packet.bytes().len()>MAX_PENDING_BYTES {return Err(io::Error::other("peer output queue limit exceeded"));}
        self.bytes+=packet.bytes().len();self.queue.push_back(Pending {packet,offset:0});Ok(())
    }
    fn flush(&mut self,stream:&mut TcpStream)->io::Result<bool> {
        let mut progress=false;
        for _ in 0..64 {
            let Some(frame)=self.queue.front_mut() else {break;};
            match stream.write(&frame.packet.bytes()[frame.offset..]) {
                Ok(0)=>return Err(io::Error::new(io::ErrorKind::WriteZero,"peer stopped accepting data")),
                Ok(n)=>{frame.offset+=n;self.bytes-=n;progress=true;if frame.offset==frame.packet.bytes().len(){self.queue.pop_front();}},
                Err(e) if e.kind()==io::ErrorKind::WouldBlock=>break,
                Err(e) if e.kind()==io::ErrorKind::Interrupted=>continue,
                Err(e)=>return Err(e),
            }
        }
        Ok(progress)
    }
}
#[allow(clippy::too_many_arguments)]
fn run_session(mut client:TcpStream,mut server:TcpStream,stop:&AtomicBool,closed:&AtomicBool,rules:&Mutex<Rules>,events:&SyncSender<Event>,commands:Receiver<(Direction,Packet)>,index:&mut i32)->io::Result<()> {
    client.set_nonblocking(true)?;server.set_nonblocking(true)?;client.set_nodelay(true)?;server.set_nodelay(true)?;
    let mut to_server=Output::default();let mut to_client=Output::default();
    let mut from_client=FrameDecoder::default();let mut from_server=FrameDecoder::default();
    let mut buffer=[0u8;8192];
    while !stop.load(Ordering::Acquire)&&!closed.load(Ordering::Acquire) {
        let mut progress=false;
        for (direction,packet) in commands.try_iter().take(64) {
            let message=Message {packet,direction,index:*index,blocked:false};*index=index.wrapping_add(1);
            match direction {Direction::ToServer=>to_server.push(message.packet.clone())?,Direction::ToClient=>to_client.push(message.packet.clone())?,}
            let _=events.try_send(Event::Packet(message));progress=true;
        }
        for direction in [Direction::ToServer,Direction::ToClient] {
            let (input,decoder,output)=match direction {
                Direction::ToServer=>(&mut client,&mut from_client,&mut to_server),
                Direction::ToClient=>(&mut server,&mut from_server,&mut to_client),
            };
            match input.read(&mut buffer) {
                Ok(0)=>return Ok(()),
                Ok(n)=>{
                    progress=true;decoder.push(&buffer[..n]).map_err(io::Error::other)?;
                    while let Some(packet)=decoder.next_packet().map_err(io::Error::other)? {
                        let mut message=Message {packet,direction,index:*index,blocked:false};*index=index.wrapping_add(1);
                        rules.lock().map_err(|_|io::Error::other("rules lock poisoned"))?.apply(&mut message);
                        if !message.blocked {output.push(message.packet.clone())?;}
                        let _=events.try_send(Event::Packet(message));
                    }
                }
                Err(e) if matches!(e.kind(),io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted)=>{},
                Err(e) if matches!(e.kind(),io::ErrorKind::ConnectionReset|io::ErrorKind::ConnectionAborted)=>return Ok(()),
                Err(e)=>return Err(e),
            }
        }
        progress|=to_server.flush(&mut server)?;progress|=to_client.flush(&mut client)?;
        if !progress {thread::sleep(Duration::from_millis(1));}
    }
    Ok(())
}
