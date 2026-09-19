//! The running node: owns the registration store and drives the gossip
//! and resolver UDP loops.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use binda_core::api::handle_client_request;
use binda_core::client_api::ClientRequest;
use binda_core::dns;
use binda_core::fcrdns::{self, RdnsVerifier};
use binda_core::gossip::{is_well_formed, DigestEntry, GossipMessage, RegistrationRumor};
use binda_core::liveness::TimeSource;
use binda_core::ntp::NtpTimeSource;
use binda_core::rate_limit::RateLimiter;
use binda_core::resolver::{ResolveAnswer, ResolveQuery};
use binda_core::store::RegistryStore;
use binda_core::wire;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::interval;

use crate::peers::PeerBook;

/// How often a node pushes a gossip digest to one randomly-chosen peer.
const GOSSIP_INTERVAL: Duration = Duration::from_secs(1);

/// Burst size and steady-state rate for each listener's per-source-address
/// rate limiter. These throttle *volume from one sender*, which is the
/// actual abuse this project cares about, rather than capping the size of
/// any single message (see [`binda_core::rate_limit`]).
const RATE_LIMIT_BURST: u32 = 20;
const RATE_LIMIT_PER_SEC: f64 = 10.0;
/// Cap on distinct source addresses a limiter tracks at once, so spraying
/// spoofed source addresses can't grow the limiter's own memory without
/// bound (the least-recently-seen address is evicted to make room).
const RATE_LIMIT_MAX_TRACKED_KEYS: usize = 100_000;
/// How often the maintenance task prunes rate limiter entries that have
/// gone quiet, and how old an entry has to be to qualify.
const RATE_LIMIT_PRUNE_INTERVAL: Duration = Duration::from_secs(60);
const RATE_LIMIT_PRUNE_AGE: Duration = Duration::from_secs(300);

fn new_rate_limiter() -> Mutex<RateLimiter<SocketAddr>> {
    Mutex::new(RateLimiter::new(
        RATE_LIMIT_BURST,
        RATE_LIMIT_PER_SEC,
        RATE_LIMIT_MAX_TRACKED_KEYS,
    ))
}

/// Shared node state, cheap to clone (everything behind `Arc`).
#[derive(Clone)]
pub struct Node {
    pub store: Arc<Mutex<RegistryStore>>,
    pub peers: Arc<PeerBook>,
    pub time: Arc<dyn TimeSource>,
    gossip_limiter: Arc<Mutex<RateLimiter<SocketAddr>>>,
    resolver_limiter: Arc<Mutex<RateLimiter<SocketAddr>>>,
    api_limiter: Arc<Mutex<RateLimiter<SocketAddr>>>,
    dns_limiter: Arc<Mutex<RateLimiter<SocketAddr>>>,
}

impl Node {
    /// Construct a node whose clock is disciplined against public NTP
    /// servers. This blocks briefly (bounded by the per-server query
    /// timeout) to get an initial offset before the node starts trusting
    /// it for liveness decisions.
    pub fn new(peers: Vec<SocketAddr>) -> Self {
        let time: Arc<dyn TimeSource> = Arc::new(NtpTimeSource::spawn_default());
        Self {
            store: Arc::new(Mutex::new(RegistryStore::new())),
            peers: Arc::new(PeerBook::new(peers)),
            time,
            gossip_limiter: Arc::new(new_rate_limiter()),
            resolver_limiter: Arc::new(new_rate_limiter()),
            api_limiter: Arc::new(new_rate_limiter()),
            dns_limiter: Arc::new(new_rate_limiter()),
        }
    }

    /// Spawn a background task that periodically prunes every listener's
    /// rate limiter of addresses that have gone quiet. Not required for
    /// memory safety (each limiter already bounds its own size), just
    /// keeps the tracked set closer to "currently active."
    pub fn spawn_rate_limiter_maintenance(&self) {
        let limiters = [
            self.gossip_limiter.clone(),
            self.resolver_limiter.clone(),
            self.api_limiter.clone(),
            self.dns_limiter.clone(),
        ];
        tokio::spawn(async move {
            let mut ticker = interval(RATE_LIMIT_PRUNE_INTERVAL);
            loop {
                ticker.tick().await;
                let now = std::time::Instant::now();
                for limiter in &limiters {
                    limiter.lock().await.prune_older_than(RATE_LIMIT_PRUNE_AGE, now);
                }
            }
        });
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
            if !self.gossip_limiter.lock().await.allow(from) {
                continue;
            }
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
            if !self.resolver_limiter.lock().await.allow(from) {
                continue;
            }
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

    /// Bind the client-facing registration API UDP socket and serve
    /// [`ClientRequest`]s (probe / register / set-records) until the
    /// process exits.
    pub async fn run_client_api(&self, bind_addr: SocketAddr) -> std::io::Result<()> {
        let socket = UdpSocket::bind(bind_addr).await?;
        println!("binda: client API listening on {bind_addr}");
        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        loop {
            let (len, from) = socket.recv_from(&mut buf).await?;
            if !self.api_limiter.lock().await.allow(from) {
                continue;
            }
            let Ok(request) = wire::decode::<ClientRequest>(&buf[..len]) else {
                continue;
            };

            // Only a Register actually needs this (it's what the "5
            // domains per live socket" cap gates), and it's a real,
            // blocking network round-trip against the public DNS system,
            // so it runs off the async runtime's worker threads and
            // (crucially) before the store's lock is ever taken.
            let rdns_verified = match &request {
                ClientRequest::Register(envelope) => {
                    let source_ip = from.ip();
                    let claimed_rdns = envelope.rdns.clone();
                    tokio::task::spawn_blocking(move || {
                        fcrdns::FcrdnsVerifier.verify(source_ip, &claimed_rdns)
                    })
                    .await
                    .unwrap_or(false)
                }
                _ => true,
            };

            let response = {
                let mut store = self.store.lock().await;
                handle_client_request(&mut store, self.time.as_ref(), request, rdns_verified)
            };
            if let Ok(bytes) = wire::encode(&response) {
                let _ = socket.send_to(&bytes, from).await;
            }
        }
    }

    /// Bind a UDP socket speaking BINDA's own native name-lookup wire
    /// protocol (see [`dns`]): DNS-shaped framing, but every label is raw
    /// UTF-8 on the wire — never Punycode/ASCII. This is a deliberate
    /// break from RFC 1035 wire compatibility, not an oversight.
    pub async fn run_dns(&self, bind_addr: SocketAddr) -> std::io::Result<()> {
        let socket = UdpSocket::bind(bind_addr).await?;
        println!("binda: native name-lookup protocol listening on {bind_addr}");
        // Sized to match the other listeners' datagram cap, not DNS's
        // traditional 512-byte assumption: a name here has no length
        // limit, so the buffer shouldn't impose one either.
        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        loop {
            let (len, from) = socket.recv_from(&mut buf).await?;
            if !self.dns_limiter.lock().await.allow(from) {
                continue;
            }
            let query = match dns::parse_query(&buf[..len]) {
                Ok(query) => query,
                Err(_) => {
                    // Echo back a minimal error response when we can at
                    // least recover the message ID, so a malformed
                    // request gets an answer instead of silence.
                    if len >= 2 {
                        let id = u16::from_be_bytes([buf[0], buf[1]]);
                        let response = dns::build_error_response(id, dns::RCODE_FORMAT_ERROR);
                        let _ = socket.send_to(&response, from).await;
                    }
                    continue;
                }
            };
            let response = {
                let store = self.store.lock().await;
                match store.lookup(&query.domain) {
                    Some(reg) => {
                        let matching: Vec<_> = reg
                            .records
                            .iter()
                            .filter(|r| dns::record_matches_qtype(r, query.qtype))
                            .cloned()
                            .collect();
                        dns::build_response(&query, true, &matching)
                    }
                    None => dns::build_response(&query, false, &[]),
                }
            };
            let _ = socket.send_to(&response, from).await;
        }
    }
}
