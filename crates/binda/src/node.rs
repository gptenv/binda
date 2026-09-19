//! The running node: owns the registration store and drives the gossip
//! and resolver UDP loops.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use binda_core::api::handle_client_request;
use binda_core::client_api::ClientRequest;
use binda_core::dns;
use binda_core::domain::DomainName;
use binda_core::fcrdns::{self, RdnsVerifier};
use binda_core::gossip::{
    is_valid_rumor_response, is_well_formed, ConformanceChallenge, DigestEntry, GossipMessage,
    RegistrationRumor,
};
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

/// How long an outstanding [`ConformanceChallenge`] this node issued is
/// kept waiting for its answer before being dropped as abandoned.
const PENDING_CHALLENGE_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap on outstanding challenges tracked at once, mirroring the rate
/// limiters' own bound: a flood of `Digest` messages from spoofed source
/// addresses (each provoking us to issue a fresh challenge) can't grow
/// this map without bound.
const MAX_PENDING_CHALLENGES: usize = 10_000;

type PendingChallenge = (ConformanceChallenge, Vec<DomainName>, Instant);

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
    /// Conformance challenges this node has issued (via a
    /// [`GossipMessage::Request`]) and is waiting to see answered
    /// correctly in the matching [`GossipMessage::Rumors`] reply, keyed
    /// by the peer address the request was sent to.
    pending_challenges: Arc<Mutex<HashMap<SocketAddr, PendingChallenge>>>,
    /// What checks a `Register` request's claimed `rdns` hostname against
    /// its actual source address. Real deployments must use the default
    /// ([`fcrdns::FcrdnsVerifier`]); swapping in
    /// [`fcrdns::AllowAllVerifier`] (via
    /// [`Node::new_allowing_any_rdns`]) is for local demos and testing
    /// only, and is never the default.
    rdns_verifier: Arc<dyn RdnsVerifier>,
}

impl Node {
    /// Construct a node whose clock is disciplined against public NTP
    /// servers, and whose registrations are gated by real FCrDNS
    /// verification. This blocks briefly (bounded by the per-server
    /// query timeout) to get an initial NTP offset before the node
    /// starts trusting it for liveness decisions.
    pub fn new(peers: Vec<SocketAddr>) -> Self {
        Self::new_with_verifier(peers, Arc::new(fcrdns::FcrdnsVerifier))
    }

    /// Construct a node that accepts *any* claimed `rdns` hostname
    /// without checking it — see [`fcrdns::AllowAllVerifier`] for why
    /// this only ever belongs in a local demo or test, never a real
    /// deployment reachable by anyone else.
    pub fn new_allowing_any_rdns(peers: Vec<SocketAddr>) -> Self {
        Self::new_with_verifier(peers, Arc::new(fcrdns::AllowAllVerifier))
    }

    fn new_with_verifier(peers: Vec<SocketAddr>, rdns_verifier: Arc<dyn RdnsVerifier>) -> Self {
        let time: Arc<dyn TimeSource> = Arc::new(NtpTimeSource::spawn_default());
        Self {
            store: Arc::new(Mutex::new(RegistryStore::new())),
            peers: Arc::new(PeerBook::new(peers)),
            time,
            gossip_limiter: Arc::new(new_rate_limiter()),
            resolver_limiter: Arc::new(new_rate_limiter()),
            api_limiter: Arc::new(new_rate_limiter()),
            dns_limiter: Arc::new(new_rate_limiter()),
            pending_challenges: Arc::new(Mutex::new(HashMap::new())),
            rdns_verifier,
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
        let pending_challenges = self.pending_challenges.clone();
        tokio::spawn(async move {
            let mut ticker = interval(RATE_LIMIT_PRUNE_INTERVAL);
            loop {
                ticker.tick().await;
                let now = Instant::now();
                for limiter in &limiters {
                    limiter
                        .lock()
                        .await
                        .prune_older_than(RATE_LIMIT_PRUNE_AGE, now);
                }
                pending_challenges
                    .lock()
                    .await
                    .retain(|_, (_, _, issued_at)| {
                        now.duration_since(*issued_at) < PENDING_CHALLENGE_TIMEOUT
                    });
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
            // Send even an empty digest: a freshly-joined node with
            // nothing to announce yet still needs its peer to *learn its
            // address* (see gossip_recv_loop's peers.learn call), so that
            // peer's own next push has somewhere new to send data the
            // newcomer is missing. Skipping empty digests would strand a
            // one-directionally configured `--peer` pointing at a node
            // that doesn't yet know the newcomer exists.
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

    async fn handle_gossip_message(
        &self,
        socket: &UdpSocket,
        from: SocketAddr,
        msg: GossipMessage,
    ) {
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

                // Bundle a fresh behavioural test with the request: real
                // BINDA behaviour is a deterministic function of this
                // challenge (crate::collision::resolve), so a peer that
                // can't answer it correctly isn't proven to run BINDA's
                // protocol logic, whatever its rumors claim.
                let challenge = ConformanceChallenge::random(self.time.now_millis());
                {
                    let mut pending = self.pending_challenges.lock().await;
                    if !pending.contains_key(&from) && pending.len() >= MAX_PENDING_CHALLENGES {
                        if let Some(oldest) = pending
                            .iter()
                            .min_by_key(|(_, (_, _, issued_at))| *issued_at)
                            .map(|(addr, _)| *addr)
                        {
                            pending.remove(&oldest);
                        }
                    }
                    pending.insert(from, (challenge, missing.clone(), Instant::now()));
                }

                let request = GossipMessage::Request {
                    domains: missing,
                    challenge,
                };
                if let Ok(bytes) = wire::encode(&request) {
                    let _ = socket.send_to(&bytes, from).await;
                }
            }
            GossipMessage::Request { domains, challenge } => {
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
                // Always answer the challenge, even with zero rumors:
                // proving correct behaviour doesn't depend on having data
                // to share, and silently dropping an empty-but-correct
                // answer would just make legitimate peers with nothing
                // new look indistinguishable from incorrect ones.
                let response = GossipMessage::Rumors {
                    rumors,
                    challenge_answer: challenge.expected_answer(),
                };
                if let Ok(bytes) = wire::encode(&response) {
                    let _ = socket.send_to(&bytes, from).await;
                }
            }
            GossipMessage::Rumors {
                rumors,
                challenge_answer,
            } => {
                let expected = {
                    let mut pending = self.pending_challenges.lock().await;
                    pending.remove(&from)
                };
                let Some((challenge, requested, _)) = expected else {
                    // No outstanding challenge for this address: either
                    // we never asked, or it already timed out. Either
                    // way, there's nothing to verify this answer against,
                    // so it isn't trusted.
                    return;
                };
                if challenge_answer != challenge.expected_answer() {
                    // Wrong answer to a fully deterministic function of
                    // our own challenge: for this exchange, we assume
                    // we're not actually talking to a BINDA node, and
                    // ignore everything it sent, rumors included.
                    return;
                }

                if !is_valid_rumor_response(&requested, &rumors) {
                    // A correctly answered challenge proves only that the
                    // sender can perform the deterministic BINDA operation.
                    // It does not excuse violating the request/response
                    // contract: never adopt an unrequested or duplicate fact.
                    return;
                }

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
            // domains per live socket" cap gates), and (with the real
            // FcrdnsVerifier) it's a blocking network round-trip against
            // the public DNS system, so it runs off the async runtime's
            // worker threads and (crucially) before the store's lock is
            // ever taken.
            let rdns_verified = match &request {
                ClientRequest::Register(envelope) => {
                    let source_ip = from.ip();
                    let claimed_rdns = envelope.rdns.clone();
                    let verifier = self.rdns_verifier.clone();
                    tokio::task::spawn_blocking(move || verifier.verify(source_ip, &claimed_rdns))
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

#[cfg(test)]
mod tests {
    use super::*;
    use binda_core::client::ClientIdentity;
    use binda_core::domain::DomainName;
    use binda_core::liveness::SystemTimeSource;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::time::Duration as StdDuration;

    /// Build a `Node` for tests: same shape as `Node::new`, but backed by
    /// the plain system clock instead of `NtpTimeSource`, so constructing
    /// one doesn't block on (or depend on) real network access.
    fn test_node(peers: Vec<SocketAddr>) -> Node {
        Node {
            store: Arc::new(Mutex::new(RegistryStore::new())),
            peers: Arc::new(PeerBook::new(peers)),
            time: Arc::new(SystemTimeSource),
            gossip_limiter: Arc::new(new_rate_limiter()),
            resolver_limiter: Arc::new(new_rate_limiter()),
            api_limiter: Arc::new(new_rate_limiter()),
            dns_limiter: Arc::new(new_rate_limiter()),
            pending_challenges: Arc::new(Mutex::new(HashMap::new())),
            rdns_verifier: Arc::new(fcrdns::FcrdnsVerifier),
        }
    }

    /// Same as [`test_node`], but with FCrDNS verification switched off,
    /// so `Register` requests succeed without needing real reverse-DNS
    /// infrastructure. Used only to test the `Register` happy path
    /// itself; every other test uses the real verifier so a wrongly
    /// "always succeeds" verifier can't mask a real regression.
    fn test_node_allowing_any_rdns(peers: Vec<SocketAddr>) -> Node {
        Node {
            rdns_verifier: Arc::new(fcrdns::AllowAllVerifier),
            ..test_node(peers)
        }
    }

    // These four helpers all share one shape: spawn a listener loop that,
    // by design, never returns (it's a `loop { ... }` bound to a real UDP
    // socket) and run it in the background for a test to send traffic
    // at. Source-based coverage instrumentation can't mark a spawned
    // async block's own "completed" region as hit when it's an infinite
    // loop that gets torn down by the test process exiting rather than
    // by returning — that's a property of *how the test drives the
    // listener*, not of whether the listener's behavior is actually
    // exercised (every test using these asserts on real responses over a
    // real socket). `#[coverage(off)]` excludes exactly that
    // structurally-uncoverable line, the same way `main` is excluded for
    // an analogous reason.
    #[coverage(off)]
    fn spawn_gossip_task(node: &Node, addr: SocketAddr) {
        let n = node.clone();
        tokio::spawn(async move {
            let _ = n.run_gossip(addr).await;
        });
    }

    #[coverage(off)]
    fn spawn_resolver_task(node: &Node, addr: SocketAddr) {
        let n = node.clone();
        tokio::spawn(async move {
            let _ = n.run_resolver(addr).await;
        });
    }

    #[coverage(off)]
    fn spawn_client_api_task(node: &Node, addr: SocketAddr) {
        let n = node.clone();
        tokio::spawn(async move {
            let _ = n.run_client_api(addr).await;
        });
    }

    #[coverage(off)]
    fn spawn_dns_task(node: &Node, addr: SocketAddr) {
        let n = node.clone();
        tokio::spawn(async move {
            let _ = n.run_dns(addr).await;
        });
    }

    /// Receive datagrams on `socket` until one decodes as a
    /// `GossipMessage::Request`, ignoring anything else (e.g. the
    /// victim's own routine, unsolicited `Digest` pushes to this address,
    /// since it's also listed as one of the victim's peers).
    async fn recv_request(
        socket: &UdpSocket,
    ) -> (Vec<DomainName>, ConformanceChallenge, SocketAddr) {
        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        for _ in 0..20 {
            let (len, from) =
                tokio::time::timeout(StdDuration::from_secs(5), socket.recv_from(&mut buf))
                    .await
                    .expect("should receive a Request within the timeout")
                    .unwrap();
            if let Ok(GossipMessage::Request { domains, challenge }) = wire::decode(&buf[..len]) {
                return (domains, challenge, from);
            }
        }
        panic!("never received a Request message");
    }

    async fn seed_registration(node: &Node, domain: &DomainName) {
        seed_registration_with_records(node, domain, Vec::new()).await;
    }

    async fn seed_registration_with_records(
        node: &Node,
        domain: &DomainName,
        records: Vec<binda_core::zone::Record>,
    ) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let client = ClientIdentity::new(signing_key.verifying_key(), "seed.example.net");
        let mut store = node.store.lock().await;
        store.probe(&client, node.time.as_ref());
        store
            .register(domain.clone(), &client, node.time.as_ref())
            .unwrap();
        if !records.is_empty() {
            assert!(store.set_records(domain, &client, records));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn spawn_rate_limiter_maintenance_runs_without_panicking() {
        // The maintenance task's own prune interval is long (see
        // RATE_LIMIT_PRUNE_INTERVAL); this just confirms spawning it,
        // and the task actually starting up, doesn't panic or block.
        let node = test_node(Vec::new());
        node.spawn_rate_limiter_maintenance();
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn two_nodes_converge_via_gossip() {
        let a_addr: SocketAddr = "127.0.0.1:29530".parse().unwrap();
        let b_addr: SocketAddr = "127.0.0.1:29531".parse().unwrap();
        let domain = DomainName::new("gossip-test-a.binda").unwrap();

        let node_a = test_node(vec![b_addr]);
        seed_registration(&node_a, &domain).await;
        let node_b = test_node(vec![a_addr]);

        let a = node_a.clone();
        tokio::spawn(async move {
            let _ = a.run_gossip(a_addr).await;
        });
        let b = node_b.clone();
        tokio::spawn(async move {
            let _ = b.run_gossip(b_addr).await;
        });

        // Give the push loop (fires every GOSSIP_INTERVAL) a couple of
        // rounds to propagate: A pushes to B, B requests what it's
        // missing, A answers the conformance challenge correctly, B
        // adopts it.
        tokio::time::sleep(GOSSIP_INTERVAL * 3).await;

        let store = node_b.store.lock().await;
        assert!(
            store.lookup(&domain).is_some(),
            "node B should have learned node A's registration via gossip"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn incorrect_challenge_answer_is_rejected() {
        let victim_addr: SocketAddr = "127.0.0.1:29540".parse().unwrap();
        let rogue_addr: SocketAddr = "127.0.0.1:29541".parse().unwrap();
        let evil_domain = DomainName::new("evil.binda").unwrap();

        let victim = test_node(vec![rogue_addr]);
        let v = victim.clone();
        tokio::spawn(async move {
            let _ = v.run_gossip(victim_addr).await;
        });

        let rogue_socket = UdpSocket::bind(rogue_addr).await.unwrap();
        tokio::time::sleep(StdDuration::from_millis(200)).await;

        // Advertise a domain the victim doesn't have.
        let fake_digest = GossipMessage::Digest {
            rumors: vec![DigestEntry {
                domain: evil_domain.clone(),
                issued_at_millis: u64::MAX,
            }],
        };
        rogue_socket
            .send_to(&wire::encode(&fake_digest).unwrap(), victim_addr)
            .await
            .unwrap();

        // The victim should come back asking for it, bundling a
        // conformance challenge.
        let (_, challenge, from) = recv_request(&rogue_socket).await;

        // Answer with a deliberately wrong token.
        let correct = challenge.expected_answer();
        let wrong = if correct == challenge.token_a {
            challenge.token_b
        } else {
            challenge.token_a
        };
        let malicious_response = GossipMessage::Rumors {
            rumors: vec![RegistrationRumor {
                domain: evil_domain.clone(),
                token: binda_core::token::RegistrationToken::issue(0),
                client_key: "rogue".to_string(),
            }],
            challenge_answer: wrong,
        };
        rogue_socket
            .send_to(&wire::encode(&malicious_response).unwrap(), from)
            .await
            .unwrap();

        tokio::time::sleep(StdDuration::from_millis(500)).await;

        let store = victim.store.lock().await;
        assert!(
            store.lookup(&evil_domain).is_none(),
            "a wrong conformance answer must not be adopted, however plausible the rumor looks"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn correct_challenge_answer_is_accepted() {
        let victim_addr: SocketAddr = "127.0.0.1:29550".parse().unwrap();
        let honest_addr: SocketAddr = "127.0.0.1:29551".parse().unwrap();
        let domain = DomainName::new("honest.binda").unwrap();

        let victim = test_node(vec![honest_addr]);
        let v = victim.clone();
        tokio::spawn(async move {
            let _ = v.run_gossip(victim_addr).await;
        });

        let honest_socket = UdpSocket::bind(honest_addr).await.unwrap();
        tokio::time::sleep(StdDuration::from_millis(200)).await;
        let fake_digest = GossipMessage::Digest {
            rumors: vec![DigestEntry {
                domain: domain.clone(),
                issued_at_millis: u64::MAX,
            }],
        };
        honest_socket
            .send_to(&wire::encode(&fake_digest).unwrap(), victim_addr)
            .await
            .unwrap();

        let (_, challenge, from) = recv_request(&honest_socket).await;

        let token = binda_core::token::RegistrationToken::issue(0);
        let honest_response = GossipMessage::Rumors {
            rumors: vec![RegistrationRumor {
                domain: domain.clone(),
                token,
                client_key: "honest".to_string(),
            }],
            challenge_answer: challenge.expected_answer(),
        };
        honest_socket
            .send_to(&wire::encode(&honest_response).unwrap(), from)
            .await
            .unwrap();

        tokio::time::sleep(StdDuration::from_millis(500)).await;

        let store = victim.store.lock().await;
        let reg = store
            .lookup(&domain)
            .expect("a correctly-answered rumor should be adopted");
        assert_eq!(reg.client_key, "honest");
        assert_eq!(reg.token, token);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn correctly_challenged_but_request_invalid_rumors_are_rejected() {
        let victim_addr: SocketAddr = "127.0.0.1:29580".parse().unwrap();
        let rogue_addr: SocketAddr = "127.0.0.1:29581".parse().unwrap();
        let requested = DomainName::new("requested.binda").unwrap();
        let unrequested = DomainName::new("unrequested.binda").unwrap();

        let victim = test_node(vec![rogue_addr]);
        spawn_gossip_task(&victim, victim_addr);
        let rogue_socket = UdpSocket::bind(rogue_addr).await.unwrap();
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        rogue_socket
            .send_to(
                &wire::encode(&GossipMessage::Digest {
                    rumors: vec![DigestEntry {
                        domain: requested.clone(),
                        issued_at_millis: u64::MAX,
                    }],
                })
                .unwrap(),
                victim_addr,
            )
            .await
            .unwrap();
        let (_, challenge, from) = recv_request(&rogue_socket).await;
        let invalid_response = GossipMessage::Rumors {
            rumors: vec![RegistrationRumor {
                domain: unrequested.clone(),
                token: binda_core::token::RegistrationToken::issue(0),
                client_key: "rogue".into(),
            }],
            challenge_answer: challenge.expected_answer(),
        };
        rogue_socket
            .send_to(&wire::encode(&invalid_response).unwrap(), from)
            .await
            .unwrap();
        tokio::time::sleep(StdDuration::from_millis(200)).await;

        let store = victim.store.lock().await;
        assert!(store.lookup(&requested).is_none());
        assert!(store.lookup(&unrequested).is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolver_returns_registered_owner_and_records() {
        use binda_core::resolver::{ResolveAnswer, ResolveQuery};
        use binda_core::zone::{Record, RecordType};

        let resolver_addr: SocketAddr = "127.0.0.1:29570".parse().unwrap();
        let node = test_node(Vec::new());
        let domain = DomainName::new("resolver-test.binda").unwrap();
        seed_registration_with_records(
            &node,
            &domain,
            vec![Record {
                name: "@".into(),
                record_type: RecordType::A,
                ttl_secs: 300,
                value: "203.0.113.9".into(),
            }],
        )
        .await;

        let n = node.clone();
        tokio::spawn(async move {
            let _ = n.run_resolver(resolver_addr).await;
        });
        tokio::time::sleep(StdDuration::from_millis(150)).await;

        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket
            .set_read_timeout(Some(StdDuration::from_secs(3)))
            .unwrap();
        let query = ResolveQuery {
            domain: domain.clone(),
        };
        client_socket
            .send_to(&wire::encode(&query).unwrap(), resolver_addr)
            .unwrap();
        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        let (len, _) = client_socket.recv_from(&mut buf).unwrap();
        let answer: ResolveAnswer = wire::decode(&buf[..len]).unwrap();
        assert!(answer.owner_client_key.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolver_returns_empty_answer_for_unknown_domain() {
        use binda_core::resolver::{ResolveAnswer, ResolveQuery};

        let resolver_addr: SocketAddr = "127.0.0.1:29571".parse().unwrap();
        let node = test_node(Vec::new());
        let n = node.clone();
        tokio::spawn(async move {
            let _ = n.run_resolver(resolver_addr).await;
        });
        tokio::time::sleep(StdDuration::from_millis(150)).await;

        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket
            .set_read_timeout(Some(StdDuration::from_secs(3)))
            .unwrap();
        let query = ResolveQuery {
            domain: DomainName::new("nobody-has-this.binda").unwrap(),
        };
        client_socket
            .send_to(&wire::encode(&query).unwrap(), resolver_addr)
            .unwrap();
        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        let (len, _) = client_socket.recv_from(&mut buf).unwrap();
        let answer: ResolveAnswer = wire::decode(&buf[..len]).unwrap();
        assert_eq!(answer.owner_client_key, None);
        assert!(answer.records.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn native_dns_loop_resolves_a_registered_a_record() {
        use binda_core::zone::{Record, RecordType};

        let dns_addr: SocketAddr = "127.0.0.1:29572".parse().unwrap();
        let node = test_node(Vec::new());
        let domain = DomainName::new("native-dns-test.binda").unwrap();
        seed_registration_with_records(
            &node,
            &domain,
            vec![Record {
                name: "@".into(),
                record_type: RecordType::A,
                ttl_secs: 300,
                value: "203.0.113.20".into(),
            }],
        )
        .await;

        let n = node.clone();
        tokio::spawn(async move {
            let _ = n.run_dns(dns_addr).await;
        });
        tokio::time::sleep(StdDuration::from_millis(150)).await;

        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket
            .set_read_timeout(Some(StdDuration::from_secs(3)))
            .unwrap();
        let mut query = Vec::new();
        query.extend(0x1234u16.to_be_bytes());
        query.extend(0x0100u16.to_be_bytes());
        query.extend(1u16.to_be_bytes());
        query.extend([0u8; 6]);
        for label in domain.labels() {
            let bytes = label.as_bytes();
            query.extend((bytes.len() as u32).to_be_bytes());
            query.extend(bytes);
        }
        query.extend(0u32.to_be_bytes());
        query.extend(1u16.to_be_bytes()); // QTYPE A
        query.extend(1u16.to_be_bytes()); // QCLASS IN

        client_socket.send_to(&query, dns_addr).unwrap();
        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        let (len, _) = client_socket.recv_from(&mut buf).unwrap();
        let response = &buf[..len];
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1);
        assert!(response.ends_with(&[203, 0, 113, 20]));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn native_dns_loop_sends_formerr_for_unparseable_message() {
        let dns_addr: SocketAddr = "127.0.0.1:29573".parse().unwrap();
        let node = test_node(Vec::new());
        let n = node.clone();
        tokio::spawn(async move {
            let _ = n.run_dns(dns_addr).await;
        });
        tokio::time::sleep(StdDuration::from_millis(150)).await;

        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket
            .set_read_timeout(Some(StdDuration::from_secs(3)))
            .unwrap();
        // A 2-byte message can't possibly be a valid query, but it does
        // carry a recognizable ID for the error response to echo.
        client_socket.send_to(&[0x99, 0x88], dns_addr).unwrap();
        let mut buf = [0u8; 64];
        let (len, _) = client_socket.recv_from(&mut buf).unwrap();
        assert_eq!(len, 12);
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0x9988);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn probe_via_client_api_socket_returns_ack() {
        use binda_core::client_api::{
            probe_message, ClientRequest, ClientResponse, ProbeBody, SignedEnvelope,
        };
        use ed25519_dalek::Signer;

        let api_addr: SocketAddr = "127.0.0.1:29560".parse().unwrap();
        let node = test_node(Vec::new());
        let n = node.clone();
        tokio::spawn(async move {
            let _ = n.run_client_api(api_addr).await;
        });
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket
            .set_read_timeout(Some(StdDuration::from_secs(3)))
            .unwrap();
        let signing_key = SigningKey::generate(&mut OsRng);
        let timestamp = node.time.now_millis();
        let msg = probe_message(timestamp);
        let signature = signing_key.sign(&msg);
        let req = ClientRequest::Probe(SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns: "client.example.net".to_string(),
            timestamp_millis: timestamp,
            signature: signature.to_bytes().to_vec(),
            body: ProbeBody,
        });
        client_socket
            .send_to(&wire::encode(&req).unwrap(), api_addr)
            .unwrap();

        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        let (len, _) = client_socket.recv_from(&mut buf).unwrap();
        let response: ClientResponse = wire::decode(&buf[..len]).unwrap();
        assert_eq!(response, ClientResponse::ProbeAck);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn register_via_client_api_is_refused_without_real_fcrdns() {
        use binda_core::client_api::{
            probe_message, register_message, ClientRequest, ClientResponse, ProbeBody,
            RegisterBody, SignedEnvelope,
        };
        use ed25519_dalek::Signer;

        let api_addr: SocketAddr = "127.0.0.1:29561".parse().unwrap();
        let node = test_node(Vec::new());
        let n = node.clone();
        tokio::spawn(async move {
            let _ = n.run_client_api(api_addr).await;
        });
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket
            .set_read_timeout(Some(StdDuration::from_secs(15)))
            .unwrap();
        let signing_key = SigningKey::generate(&mut OsRng);
        let rdns = "definitely-not-a-real-reverse-dns-name.invalid".to_string();

        let t = node.time.now_millis();
        let probe_msg = probe_message(t);
        let probe_sig = signing_key.sign(&probe_msg);
        let probe_req = ClientRequest::Probe(SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns: rdns.clone(),
            timestamp_millis: t,
            signature: probe_sig.to_bytes().to_vec(),
            body: ProbeBody,
        });
        client_socket
            .send_to(&wire::encode(&probe_req).unwrap(), api_addr)
            .unwrap();
        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        let (len, _) = client_socket.recv_from(&mut buf).unwrap();
        let _: ClientResponse = wire::decode(&buf[..len]).unwrap();

        let domain = DomainName::new("wont-register.binda").unwrap();
        let t = node.time.now_millis();
        let register_msg = register_message(&domain, t);
        let register_sig = signing_key.sign(&register_msg);
        let register_req = ClientRequest::Register(SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns,
            timestamp_millis: t,
            signature: register_sig.to_bytes().to_vec(),
            body: RegisterBody { domain },
        });
        client_socket
            .send_to(&wire::encode(&register_req).unwrap(), api_addr)
            .unwrap();
        let (len, _) = client_socket.recv_from(&mut buf).unwrap();
        let response: ClientResponse = wire::decode(&buf[..len]).unwrap();
        match response {
            ClientResponse::Error { .. } => {}
            other => panic!("expected Error (no real host can forward-confirm this made-up rdns), got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn register_via_client_api_succeeds_with_rdns_verification_disabled() {
        use binda_core::client_api::{
            probe_message, register_message, ClientRequest, ClientResponse, ProbeBody,
            RegisterBody, SignedEnvelope,
        };
        use ed25519_dalek::Signer;

        let api_addr: SocketAddr = "127.0.0.1:29562".parse().unwrap();
        let node = test_node_allowing_any_rdns(Vec::new());
        spawn_client_api_task(&node, api_addr);
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket
            .set_read_timeout(Some(StdDuration::from_secs(3)))
            .unwrap();
        let signing_key = SigningKey::generate(&mut OsRng);
        let rdns = "this-would-never-forward-confirm.invalid".to_string();

        let t = node.time.now_millis();
        let probe_msg = probe_message(t);
        let probe_sig = signing_key.sign(&probe_msg);
        let probe_req = ClientRequest::Probe(SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns: rdns.clone(),
            timestamp_millis: t,
            signature: probe_sig.to_bytes().to_vec(),
            body: ProbeBody,
        });
        client_socket
            .send_to(&wire::encode(&probe_req).unwrap(), api_addr)
            .unwrap();
        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        let (len, _) = client_socket.recv_from(&mut buf).unwrap();
        let _: ClientResponse = wire::decode(&buf[..len]).unwrap();

        let domain = DomainName::new("demo-succeeds.binda").unwrap();
        let t = node.time.now_millis();
        let register_msg = register_message(&domain, t);
        let register_sig = signing_key.sign(&register_msg);
        let register_req = ClientRequest::Register(SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns,
            timestamp_millis: t,
            signature: register_sig.to_bytes().to_vec(),
            body: RegisterBody { domain },
        });
        client_socket
            .send_to(&wire::encode(&register_req).unwrap(), api_addr)
            .unwrap();
        let (len, _) = client_socket.recv_from(&mut buf).unwrap();
        let response: ClientResponse = wire::decode(&buf[..len]).unwrap();
        assert!(matches!(response, ClientResponse::Registered { .. }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_allowing_any_rdns_constructs_a_working_node() {
        // Exercises the public constructor directly (main() is the only
        // other caller, and it's excluded from coverage), rather than
        // going through the test-only struct-literal helper.
        let node = Node::new_allowing_any_rdns(Vec::new());
        assert!(node
            .store
            .lock()
            .await
            .lookup(&DomainName::new("nobody.binda").unwrap())
            .is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rate_limiter_maintenance_prunes_stale_pending_challenges_but_keeps_fresh_ones() {
        let node = test_node(Vec::new());
        let fresh_peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let stale_peer: SocketAddr = "127.0.0.1:2".parse().unwrap();
        {
            let mut pending = node.pending_challenges.lock().await;
            pending.insert(
                fresh_peer,
                (ConformanceChallenge::random(0), Vec::new(), Instant::now()),
            );
            let long_ago = Instant::now()
                .checked_sub(PENDING_CHALLENGE_TIMEOUT + Duration::from_secs(1))
                .expect("test process has been up long enough for this");
            pending.insert(
                stale_peer,
                (ConformanceChallenge::random(0), Vec::new(), long_ago),
            );
        }

        node.spawn_rate_limiter_maintenance();
        // The maintenance loop's first tick fires immediately (tokio
        // interval semantics), so a short wait is enough to observe it.
        tokio::time::sleep(StdDuration::from_millis(50)).await;

        let pending = node.pending_challenges.lock().await;
        assert!(pending.contains_key(&fresh_peer));
        assert!(!pending.contains_key(&stale_peer));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gossip_push_loop_idles_safely_with_no_known_peers() {
        let gossip_addr: SocketAddr = "127.0.0.1:29610".parse().unwrap();
        let node = test_node(Vec::new());
        seed_registration(
            &node,
            &DomainName::new("has-data-but-no-peers.binda").unwrap(),
        )
        .await;
        spawn_gossip_task(&node, gossip_addr);
        // Long enough for several push-loop ticks; nothing to assert on
        // directly (there's no peer to send to), this just proves the
        // loop doesn't panic or block when self.peers.random_peer()
        // returns None every time.
        tokio::time::sleep(GOSSIP_INTERVAL * 2 + StdDuration::from_millis(200)).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn gossip_recv_loop_ignores_garbage_bytes_and_keeps_working() {
        let gossip_addr: SocketAddr = "127.0.0.1:29611".parse().unwrap();
        let node = test_node(Vec::new());
        spawn_gossip_task(&node, gossip_addr);
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(b"not a gossip message", gossip_addr)
            .await
            .unwrap();
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        // The loop must have survived the garbage: a well-formed message
        // sent right after should still get a real reply.
        let digest = GossipMessage::Digest {
            rumors: vec![DigestEntry {
                domain: DomainName::new("after-garbage.binda").unwrap(),
                issued_at_millis: u64::MAX,
            }],
        };
        socket
            .send_to(&wire::encode(&digest).unwrap(), gossip_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        let (len, _) = tokio::time::timeout(StdDuration::from_secs(5), socket.recv_from(&mut buf))
            .await
            .expect("node should still respond after ignoring garbage")
            .unwrap();
        assert!(wire::decode::<GossipMessage>(&buf[..len]).is_ok());
    }

    // A dedicated "oversized Digest ignored by the running gossip loop"
    // integration test isn't practical: encoding MAX_DIGEST_ENTRIES + 1
    // entries (even with minimal one-character domain names) costs far
    // more than MAX_DATAGRAM_BYTES in JSON overhead alone, so
    // wire::decode's own size cap always rejects such a message before
    // is_well_formed ever gets to. That rejection (not is_well_formed)
    // is exactly what gossip_recv_loop_ignores_garbage_bytes_and_keeps_working
    // exercises. is_well_formed's own oversized-rejection logic is
    // covered directly in binda_core::gossip's unit tests instead, where
    // it doesn't have to survive a real wire encode/decode round trip.

    #[tokio::test(flavor = "multi_thread")]
    async fn gossip_rate_limiter_drops_traffic_past_the_burst() {
        let gossip_addr: SocketAddr = "127.0.0.1:29613".parse().unwrap();
        let node = test_node(Vec::new());
        seed_registration(&node, &DomainName::new("rate-limit-gossip.binda").unwrap()).await;
        spawn_gossip_task(&node, gossip_addr);
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = GossipMessage::Request {
            domains: vec![DomainName::new("rate-limit-gossip.binda").unwrap()],
            challenge: ConformanceChallenge::random(0),
        };
        let bytes = wire::encode(&request).unwrap();

        // Fire well past the burst size in a tight loop from the same
        // source address; some of these must be dropped outright.
        for _ in 0..40 {
            let _ = socket.send_to(&bytes, gossip_addr).await;
        }

        let mut received = 0;
        loop {
            let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
            match tokio::time::timeout(StdDuration::from_millis(300), socket.recv_from(&mut buf))
                .await
            {
                Ok(Ok(_)) => received += 1,
                _ => break,
            }
        }
        assert!(
            received < 40,
            "expected the rate limiter to drop some of 40 rapid requests, got {received} replies"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolver_rate_limiter_drops_traffic_past_the_burst() {
        use binda_core::resolver::ResolveQuery;

        let resolver_addr: SocketAddr = "127.0.0.1:29614".parse().unwrap();
        let node = test_node(Vec::new());
        spawn_resolver_task(&node, resolver_addr);
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = ResolveQuery {
            domain: DomainName::new("whatever.binda").unwrap(),
        };
        let bytes = wire::encode(&query).unwrap();
        for _ in 0..40 {
            let _ = socket.send_to(&bytes, resolver_addr).await;
        }

        let mut received = 0;
        loop {
            let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
            match tokio::time::timeout(StdDuration::from_millis(300), socket.recv_from(&mut buf))
                .await
            {
                Ok(Ok(_)) => received += 1,
                _ => break,
            }
        }
        assert!(
            received < 40,
            "expected the rate limiter to drop some of 40 rapid queries, got {received} replies"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolver_ignores_undecodable_bytes_and_keeps_working() {
        use binda_core::resolver::{ResolveAnswer, ResolveQuery};

        let resolver_addr: SocketAddr = "127.0.0.1:29615".parse().unwrap();
        let node = test_node(Vec::new());
        spawn_resolver_task(&node, resolver_addr);
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket
            .set_read_timeout(Some(StdDuration::from_secs(3)))
            .unwrap();
        client_socket.send_to(b"garbage", resolver_addr).unwrap();
        std::thread::sleep(StdDuration::from_millis(100));

        let query = ResolveQuery {
            domain: DomainName::new("after-garbage.binda").unwrap(),
        };
        client_socket
            .send_to(&wire::encode(&query).unwrap(), resolver_addr)
            .unwrap();
        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        let (len, _) = client_socket.recv_from(&mut buf).unwrap();
        let answer: ResolveAnswer = wire::decode(&buf[..len]).unwrap();
        assert_eq!(answer.owner_client_key, None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn client_api_rate_limiter_drops_traffic_past_the_burst() {
        use binda_core::client_api::{probe_message, ClientRequest, ProbeBody, SignedEnvelope};
        use ed25519_dalek::Signer;

        let api_addr: SocketAddr = "127.0.0.1:29616".parse().unwrap();
        let node = test_node(Vec::new());
        spawn_client_api_task(&node, api_addr);
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let signing_key = SigningKey::generate(&mut OsRng);
        let t = node.time.now_millis();
        let msg = probe_message(t);
        let sig = signing_key.sign(&msg);
        let req = ClientRequest::Probe(SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns: "host.example.net".into(),
            timestamp_millis: t,
            signature: sig.to_bytes().to_vec(),
            body: ProbeBody,
        });
        let bytes = wire::encode(&req).unwrap();
        for _ in 0..40 {
            let _ = socket.send_to(&bytes, api_addr).await;
        }

        let mut received = 0;
        loop {
            let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
            match tokio::time::timeout(StdDuration::from_millis(300), socket.recv_from(&mut buf))
                .await
            {
                Ok(Ok(_)) => received += 1,
                _ => break,
            }
        }
        assert!(
            received < 40,
            "expected the rate limiter to drop some of 40 rapid requests, got {received} replies"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn client_api_ignores_undecodable_bytes_and_keeps_working() {
        use binda_core::client_api::{
            probe_message, ClientRequest, ClientResponse, ProbeBody, SignedEnvelope,
        };
        use ed25519_dalek::Signer;

        let api_addr: SocketAddr = "127.0.0.1:29617".parse().unwrap();
        let node = test_node(Vec::new());
        spawn_client_api_task(&node, api_addr);
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket
            .set_read_timeout(Some(StdDuration::from_secs(3)))
            .unwrap();
        client_socket.send_to(b"garbage", api_addr).unwrap();
        std::thread::sleep(StdDuration::from_millis(100));

        let signing_key = SigningKey::generate(&mut OsRng);
        let t = node.time.now_millis();
        let msg = probe_message(t);
        let sig = signing_key.sign(&msg);
        let req = ClientRequest::Probe(SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns: "host.example.net".into(),
            timestamp_millis: t,
            signature: sig.to_bytes().to_vec(),
            body: ProbeBody,
        });
        client_socket
            .send_to(&wire::encode(&req).unwrap(), api_addr)
            .unwrap();
        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        let (len, _) = client_socket.recv_from(&mut buf).unwrap();
        let response: ClientResponse = wire::decode(&buf[..len]).unwrap();
        assert_eq!(response, ClientResponse::ProbeAck);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dns_rate_limiter_drops_traffic_past_the_burst() {
        let dns_addr: SocketAddr = "127.0.0.1:29618".parse().unwrap();
        let node = test_node(Vec::new());
        spawn_dns_task(&node, dns_addr);
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut query = Vec::new();
        query.extend(0x1234u16.to_be_bytes());
        query.extend(0x0100u16.to_be_bytes());
        query.extend(1u16.to_be_bytes());
        query.extend([0u8; 6]);
        query.extend(4u32.to_be_bytes());
        query.extend(b"test");
        query.extend(0u32.to_be_bytes());
        query.extend(1u16.to_be_bytes());
        query.extend(1u16.to_be_bytes());

        for _ in 0..40 {
            let _ = socket.send_to(&query, dns_addr).await;
        }

        let mut received = 0;
        loop {
            let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
            match tokio::time::timeout(StdDuration::from_millis(300), socket.recv_from(&mut buf))
                .await
            {
                Ok(Ok(_)) => received += 1,
                _ => break,
            }
        }
        assert!(
            received < 40,
            "expected the rate limiter to drop some of 40 rapid queries, got {received} replies"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn native_dns_loop_returns_nxdomain_for_unknown_domain() {
        let dns_addr: SocketAddr = "127.0.0.1:29619".parse().unwrap();
        let node = test_node(Vec::new());
        spawn_dns_task(&node, dns_addr);
        tokio::time::sleep(StdDuration::from_millis(100)).await;

        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client_socket
            .set_read_timeout(Some(StdDuration::from_secs(3)))
            .unwrap();
        let mut query = Vec::new();
        query.extend(0x4321u16.to_be_bytes());
        query.extend(0x0100u16.to_be_bytes());
        query.extend(1u16.to_be_bytes());
        query.extend([0u8; 6]);
        for label in "nobody-registered-this.binda".split('.') {
            let bytes = label.as_bytes();
            query.extend((bytes.len() as u32).to_be_bytes());
            query.extend(bytes);
        }
        query.extend(0u32.to_be_bytes());
        query.extend(1u16.to_be_bytes());
        query.extend(1u16.to_be_bytes());

        client_socket.send_to(&query, dns_addr).unwrap();
        let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
        let (len, _) = client_socket.recv_from(&mut buf).unwrap();
        let response = &buf[..len];
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x000F, 3); // RCODE_NXDOMAIN
    }
}
