//! Explicit, unencrypted EVA_WIRE TCP relay. Does not alter OS proxy settings.
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicI32, Ordering}, mpsc::{self, Receiver, SyncSender}};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use crate::packet::{read_frame, write_frame, Direction, Message, Packet};
use crate::rules::Rules;

#[derive(Debug, Clone)]
pub enum Event { Listening(SocketAddr), Connected(String), Disconnected, Packet(Message), Error(String) }
pub struct Config { pub listen: SocketAddr, pub remote: String }
struct Session { client: Mutex<TcpStream>, server: Mutex<TcpStream>, cancel_client: TcpStream, cancel_server: TcpStream, closed: AtomicBool }
impl Session {
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let _ = self.cancel_client.shutdown(Shutdown::Both); let _ = self.cancel_server.shutdown(Shutdown::Both);
    }
    fn send(&self, direction: Direction, packet: &Packet) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) { return Err(io::Error::new(io::ErrorKind::NotConnected,"session closed")); }
        let output = match direction { Direction::ToServer => &self.server, Direction::ToClient => &self.client };
        let mut stream = output.lock().map_err(|_| io::Error::other("stream lock poisoned"))?;
        write_frame(&mut *stream,packet)
    }
}
pub struct Relay {
    stop: Arc<AtomicBool>, active: Arc<Mutex<Option<Arc<Session>>>>,
    worker: Option<JoinHandle<()>>, rules: Arc<Mutex<Rules>>, tx: SyncSender<Event>, index: Arc<AtomicI32>,
    pub address: SocketAddr,
}
impl Relay {
    pub fn start(config: Config) -> io::Result<(Self, Receiver<Event>)> {
        if !config.listen.ip().is_loopback() { return Err(io::Error::new(io::ErrorKind::InvalidInput,"listen address must be loopback")); }
        // Resolve once before starting: no hidden DNS work on the UI thread afterwards.
        let remote: Vec<SocketAddr> = config.remote.to_socket_addrs()?.collect();
        if remote.is_empty() { return Err(io::Error::new(io::ErrorKind::InvalidInput,"remote has no addresses")); }
        let listener = TcpListener::bind(config.listen)?; listener.set_nonblocking(true)?; let address = listener.local_addr()?;
        let (tx,rx) = mpsc::sync_channel(2048);
        let stop = Arc::new(AtomicBool::new(false)); let active = Arc::new(Mutex::new(None));
        let rules = Arc::new(Mutex::new(Rules::default())); let index = Arc::new(AtomicI32::new(0));
        let (s,a,r,t,i) = (stop.clone(),active.clone(),rules.clone(),tx.clone(),index.clone());
        let worker = thread::spawn(move || {
            let _ = t.try_send(Event::Listening(address));
            while !s.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((client,_)) => {
                        let server = remote.iter().find_map(|addr| {
                            if s.load(Ordering::Acquire) { return None; }
                            TcpStream::connect_timeout(addr,Duration::from_secs(2)).ok()
                        });
                        let Some(server) = server else { let _ = t.try_send(Event::Error("remote connection failed".into())); continue; };
                        if s.load(Ordering::Acquire) { break; }
                        let _ = client.set_nodelay(true); let _ = server.set_nodelay(true);
                        let _ = client.set_write_timeout(Some(Duration::from_secs(2))); let _ = server.set_write_timeout(Some(Duration::from_secs(2)));
                        let session = match make_session(&client,&server) { Ok(v)=>Arc::new(v),Err(e)=>{let _=t.try_send(Event::Error(e.to_string()));continue;} };
                        if let Ok(mut slot) = a.lock() { *slot = Some(session.clone()); }
                        let _ = t.try_send(Event::Connected(server.peer_addr().map(|v|v.to_string()).unwrap_or_default()));
                        let (ss,rr,tt,ii) = (session.clone(),r.clone(),t.clone(),i.clone());
                        let upstream = thread::spawn(move || pump(client,Direction::ToServer,ss,rr,tt,ii));
                        pump(server,Direction::ToClient,session.clone(),r.clone(),t.clone(),i.clone());
                        session.close(); let _ = upstream.join();
                        if let Ok(mut slot) = a.lock() { *slot = None; }
                        let _ = t.try_send(Event::Disconnected);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
                    Err(e) => { let _ = t.try_send(Event::Error(e.to_string())); break; }
                }
            }
        });
        Ok((Self { stop, active, worker:Some(worker), rules, tx, index, address },rx))
    }
    pub fn set_rules(&self, rules: Rules) -> io::Result<()> {
        *self.rules.lock().map_err(|_| io::Error::other("rules lock poisoned"))? = rules; Ok(())
    }
    pub fn connected(&self) -> bool { self.active.lock().map(|s|s.as_ref().is_some_and(|s|!s.closed.load(Ordering::Acquire))).unwrap_or(false) }
    pub fn inject(&self, direction: Direction, packet: Packet) -> io::Result<()> {
        let session = self.active.lock().map_err(|_|io::Error::other("session lock poisoned"))?.clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected,"no active client"))?;
        session.send(direction,&packet)?;
        let _ = self.tx.try_send(Event::Packet(Message {packet,direction,index:self.index.fetch_add(1,Ordering::Relaxed),blocked:false})); Ok(())
    }
    pub fn stop(&mut self) {
        self.stop.store(true,Ordering::Release);
        if let Ok(active) = self.active.lock() { if let Some(session) = active.as_ref() { session.close(); } }
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}
impl Drop for Relay { fn drop(&mut self) { self.stop(); } }
fn make_session(client: &TcpStream, server: &TcpStream) -> io::Result<Session> {
    Ok(Session {client:Mutex::new(client.try_clone()?),server:Mutex::new(server.try_clone()?),cancel_client:client.try_clone()?,cancel_server:server.try_clone()?,closed:AtomicBool::new(false)})
}
fn pump(mut input: TcpStream, direction: Direction, session: Arc<Session>, rules: Arc<Mutex<Rules>>, events: SyncSender<Event>, index: Arc<AtomicI32>) {
    while !session.closed.load(Ordering::Acquire) {
        let packet = match read_frame(&mut input) {
            Ok(p)=>p,
            Err(e)=>{if !session.closed.load(Ordering::Acquire) && !matches!(e.kind(),io::ErrorKind::UnexpectedEof|io::ErrorKind::ConnectionReset|io::ErrorKind::ConnectionAborted) {let _=events.try_send(Event::Error(e.to_string()));} break;}
        };
        let mut message = Message {packet,direction,index:index.fetch_add(1,Ordering::Relaxed),blocked:false};
        match rules.lock() { Ok(r)=>r.apply(&mut message),Err(_)=>break }
        if !message.blocked { if let Err(e)=session.send(direction,&message.packet) {let _=events.try_send(Event::Error(e.to_string()));break;} }
        // Logging cannot block packet delivery. UI keeps a second bounded ring buffer.
        let _ = events.try_send(Event::Packet(message));
    }
    session.close();
}
