//! One lifecycle for Unity's browser asset proxy and TLS communicator.
use crate::{
    packet::{Direction, Packet},
    relay::Event,
    rules::Rules,
    unity_assets::UnityAssets,
    unity_server::{UnityOptions, UnityServer},
    web_proxy::{WebOptions, WebProxy},
};
use std::{
    collections::VecDeque,
    io,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

// Keep lifecycle events when the desktop falls behind, while avoiding a
// blocking send on the network worker and unbounded memory during a flood.
const MAX_PENDING_CONTROL_EVENTS: usize = 64;
#[derive(Default)]
struct EventForwarder {
    pending: VecDeque<Event>,
}
impl EventForwarder {
    fn flush(&mut self, sender: &SyncSender<Event>) -> bool {
        while let Some(event) = self.pending.pop_front() {
            match sender.try_send(event) {
                Ok(()) => {}
                Err(TrySendError::Full(event)) => {
                    self.pending.push_front(event);
                    return true;
                }
                Err(TrySendError::Disconnected(_)) => return false,
            }
        }
        true
    }
    fn forward(&mut self, sender: &SyncSender<Event>, event: Event) -> bool {
        if self.pending.is_empty() {
            match sender.try_send(event) {
                Ok(()) => return true,
                Err(TrySendError::Disconnected(_)) => return false,
                Err(TrySendError::Full(event)) => return self.queue(event),
            }
        }
        self.queue(event)
    }
    fn queue(&mut self, event: Event) -> bool {
        if matches!(event, Event::Packet(_)) {
            return true;
        }
        if self.pending.len() == MAX_PENDING_CONTROL_EVENTS {
            if matches!(event, Event::Status(_)) {
                return true;
            }
            // Prefer connection lifecycle over less important status updates.
            if let Some(index) = self
                .pending
                .iter()
                .position(|event| matches!(event, Event::Status(_)))
            {
                self.pending.remove(index);
            } else {
                self.pending.pop_front();
            }
        }
        self.pending.push_back(event);
        true
    }
}
pub struct UnityConnection {
    http: WebProxy,
    communicator: UnityServer,
    forward_stop: Arc<AtomicBool>,
    forwarder: Option<JoinHandle<()>>,
    pub address: std::net::SocketAddr,
}
impl UnityConnection {
    pub fn start(
        mut http: WebOptions,
        communicator: UnityOptions,
        cache_directory: PathBuf,
    ) -> io::Result<(Self, Receiver<Event>)> {
        if http.identity_directory != communicator.identity_directory {
            return Err(io::Error::other(
                "Unity proxy and communicator must use the same public certificate",
            ));
        }
        let (server, unity_events) = UnityServer::start(communicator)?;
        http.unity = Some(UnityAssets {
            websocket_port: server.address.port(),
            token: server.token().into(),
            cache_directory,
        });
        http.detect_nitro = false;
        http.hotels = crate::nitro::Hotels::default();
        http.websocket_urls.clear();
        http.extensions = None;
        http.allow_city_helper = false;
        let (proxy, http_events) = WebProxy::start(http)?;
        let address = proxy.address;
        let (sender, events) = mpsc::sync_channel(2048);
        let forward_stop = Arc::new(AtomicBool::new(false));
        let stopping = forward_stop.clone();
        let forwarder = thread::spawn(move || {
            let mut forwarder = EventForwarder::default();
            while !stopping.load(Ordering::Acquire) {
                if !forwarder.flush(&sender) {
                    break;
                }
                for event in unity_events
                    .try_iter()
                    .take(512)
                    .chain(http_events.try_iter().take(128))
                {
                    if !forwarder.forward(&sender, event) {
                        return;
                    }
                }
                thread::park_timeout(Duration::from_millis(10));
            }
        });
        Ok((
            Self {
                http: proxy,
                communicator: server,
                forward_stop,
                forwarder: Some(forwarder),
                address,
            },
            events,
        ))
    }
    pub fn connected(&self) -> bool {
        self.communicator.connected()
    }
    pub fn inject(&self, direction: Direction, packet: Packet) -> io::Result<()> {
        self.communicator.inject(direction, packet)
    }
    pub fn set_rules(&self, rules: Rules) -> io::Result<()> {
        self.communicator.set_rules(rules)
    }
    pub fn stop(&mut self) {
        self.communicator.stop();
        self.http.stop();
        self.forward_stop.store(true, Ordering::Release);
        if let Some(forwarder) = self.forwarder.take() {
            forwarder.thread().unpark();
            let _ = forwarder.join();
        }
    }
}

impl Drop for UnityConnection {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Direction, Message, Packet};

    fn packet() -> Event {
        Event::Packet(Message {
            packet: Packet::new(42),
            direction: Direction::ToClient,
            index: 0,
            blocked: false,
        })
    }
    #[test]
    fn lifecycle_events_wait_in_order_when_display_is_full() {
        let (sender, receiver) = mpsc::sync_channel(1);
        sender.try_send(packet()).unwrap();
        let mut forwarder = EventForwarder::default();
        assert!(forwarder.forward(&sender, Event::Connected("fixture".into())));
        assert!(forwarder.forward(&sender, packet()));
        assert!(forwarder.forward(&sender, Event::Disconnected));
        assert_eq!(forwarder.pending.len(), 2);
        assert!(matches!(receiver.recv().unwrap(), Event::Packet(_)));
        assert!(forwarder.flush(&sender));
        assert!(matches!(receiver.recv().unwrap(), Event::Connected(_)));
        assert!(forwarder.flush(&sender));
        assert!(matches!(receiver.recv().unwrap(), Event::Disconnected));
        assert!(forwarder.pending.is_empty());
    }
    #[test]
    fn control_backlog_is_bounded_and_receiver_loss_is_reported() {
        let (sender, receiver) = mpsc::sync_channel(1);
        sender.try_send(packet()).unwrap();
        let mut forwarder = EventForwarder::default();
        assert!(forwarder.forward(&sender, Event::Connected("fixture".into())));
        for _ in 0..100 {
            assert!(forwarder.forward(&sender, Event::Status("busy".into())));
        }
        assert!(forwarder.forward(&sender, Event::Disconnected));
        assert_eq!(forwarder.pending.len(), MAX_PENDING_CONTROL_EVENTS);
        assert!(matches!(
            forwarder.pending.front(),
            Some(Event::Connected(_))
        ));
        assert!(matches!(
            forwarder.pending.back(),
            Some(Event::Disconnected)
        ));
        drop(receiver);
        assert!(!forwarder.flush(&sender));
    }
}
