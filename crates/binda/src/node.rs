//! The running node: owns the registration store and drives the gossip
//! and resolver UDP loops.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use binda_core::gossip::{is_well_formed, DigestEntry, GossipMessage, RegistrationRumor};
use binda_core::liveness::{SystemTimeSource, TimeSource};
use binda_core::resolver::{ResolveAnswer, ResolveQuery};
use binda_core::store::RegistryStore;
use binda_core::wire;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::interval;

use crate::peers::PeerBook;

/// How often a node pushes a gossip digest to one randomly-chosen peer.
const GOSSIP_INTERVAL: Duration = Duration::from_secs(1);

/// Shared node state, cheap to clone (everything behind `Arc`).
#[derive(Clone)]
pub struct Node {
    pub store: Arc<Mutex<RegistryStore>>,
    pub peers: Arc<PeerBook>,
    pub time: Arc<dyn TimeSource>,
}

impl Node {
    pub fn new(peers: Vec<SocketAddr>) -> Self {
        Self {
            store: Arc::new(Mutex::new(RegistryStore::new())),
            peers: Arc::new(PeerBook::new(peers)),
            time: Arc::new(SystemTimeSource),
        }
    }

    /// Bind the gossip UDP socket and run both the periodic digest-push
    /// loop and the inbound-message loop until the process exits.
    pub async fn run_gossip(&self, bind_addr: SocketAddr) -> std::io::Result<()> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        println!("binda: gossip listening on {bind_addr}");

        let push_socket = socket.clone();
        let push_node = self.clone();
        tokio::spawn(async move {
            push_node.gossip_push_loop(push_socket).await;
        });

        self.gossip_recv_loop(socket).await
    }

    async fn gossip_push_loop(&self, socket: Arc<UdpSocket>) {
        let mut ticker = interval(GOSSIP_INTERVAL);
        loop {
            ticker.tick().await;
            let Some(peer) = self.peers.random_peer().await else {
                continue;
            };
            let rumors: Vec<DigestEntry> = {
                let store = self.store.lock().await;
                store
                    .all_rumors()
                    .map(|(domain, _client_key, token)| DigestEntry {
                        domain: domain.clone(),
                        issued_at_millis: token.issued_at_millis,
                    })
                    .collect()
            };
            if rumors.is_empty() {
                continue;
            }
            let msg = GossipMessage::Digest { rumors };
            if let Ok(bytes) = wire::encode(&msg) {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    }

    async fn gossip_recv_loop(&self, socket: Arc<UdpSocket>) -> std::io::Result<()> {
        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        loop {
            let (len, from) = socket.recv_from(&mut buf).await?;
            let Ok(msg) = wire::decode::<GossipMessage>(&buf[..len]) else {
                // Not decodable as our protocol: for this exchange, treat
                // the sender as not-a-BINDA-node and drop it silently.
                continue;
            };
            if !is_well_formed(&msg) {
                continue;
            }
            self.peers.learn(from).await;
            self.handle_gossip_message(&socket, from, msg).await;
        }
    }

    async fn handle_gossip_message(&self, socket: &UdpSocket, from: SocketAddr, msg: GossipMessage) {
        match msg {
            GossipMessage::Digest { rumors } => {
                let missing: Vec<_> = {
                    let store = self.store.lock().await;
                    rumors
                        .into_iter()
                        .filter(|entry| match store.lookup(&entry.domain) {
                            Some(reg) => reg.token.issued_at_millis < entry.issued_at_millis,
                            None => true,
                        })
                        .map(|entry| entry.domain)
                        .collect()
                };
                if missing.is_empty() {
                    return;
                }
                let request = GossipMessage::Request { domains: missing };
                if let Ok(bytes) = wire::encode(&request) {
                    let _ = socket.send_to(&bytes, from).await;
                }
            }
            GossipMessage::Request { domains } => {
                let rumors: Vec<RegistrationRumor> = {
                    let store = self.store.lock().await;
                    domains
                        .into_iter()
                        .filter_map(|domain| {
                            store.lookup(&domain).map(|reg| RegistrationRumor {
                                domain,
                                token: reg.token,
                                client_key: reg.client_key.clone(),
                            })
                        })
                        .collect()
                };
                if rumors.is_empty() {
                    return;
                }
                let response = GossipMessage::Rumors { rumors };
                if let Ok(bytes) = wire::encode(&response) {
                    let _ = socket.send_to(&bytes, from).await;
                }
            }
            GossipMessage::Rumors { rumors } => {
                let mut store = self.store.lock().await;
                for rumor in rumors {
                    store.adopt_rumor(rumor.domain, rumor.client_key, rumor.token);
                }
            }
        }
    }

    /// Bind the resolver UDP socket and answer [`ResolveQuery`]s until the
    /// process exits.
    pub async fn run_resolver(&self, bind_addr: SocketAddr) -> std::io::Result<()> {
        let socket = UdpSocket::bind(bind_addr).await?;
        println!("binda: resolver listening on {bind_addr}");
        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        loop {
            let (len, from) = socket.recv_from(&mut buf).await?;
            let Ok(query) = wire::decode::<ResolveQuery>(&buf[..len]) else {
                continue;
            };
            let answer = {
                let store = self.store.lock().await;
                match store.lookup(&query.domain) {
                    Some(reg) => ResolveAnswer {
                        owner_client_key: Some(reg.client_key.clone()),
                        records: reg.records.clone(),
                    },
                    None => ResolveAnswer {
                        owner_client_key: None,
                        records: Vec::new(),
                    },
                }
            };
            if let Ok(bytes) = wire::encode(&answer) {
                let _ = socket.send_to(&bytes, from).await;
            }
        }
    }
}
