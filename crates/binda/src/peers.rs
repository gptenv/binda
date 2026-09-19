//! The set of peers a node gossips with.
//!
//! Nothing here tracks trust or reputation — see [`binda_core::gossip`] for
//! why: every exchange is judged on the well-formedness of that exchange's
//! messages alone, never on a running score kept per peer.

use std::net::SocketAddr;

use rand::seq::SliceRandom;
use tokio::sync::RwLock;

/// A shared, mutable list of peer addresses to gossip with.
#[derive(Debug, Default)]
pub struct PeerBook {
    peers: RwLock<Vec<SocketAddr>>,
}

impl PeerBook {
    pub fn new(initial: Vec<SocketAddr>) -> Self {
        Self {
            peers: RwLock::new(initial),
        }
    }

    /// Pick one peer at random to gossip with this round, if any are known.
    pub async fn random_peer(&self) -> Option<SocketAddr> {
        let peers = self.peers.read().await;
        peers.choose(&mut rand::thread_rng()).copied()
    }

    /// Learn of a peer address not already known, e.g. because it gossiped
    /// to us first.
    pub async fn learn(&self, addr: SocketAddr) {
        let mut peers = self.peers.write().await;
        if !peers.contains(&addr) {
            peers.push(addr);
        }
    }

    pub async fn snapshot(&self) -> Vec<SocketAddr> {
        self.peers.read().await.clone()
    }
}
