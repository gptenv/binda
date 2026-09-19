//! The set of peers a node gossips with.
//!
//! Nothing here tracks trust or reputation — see [`binda_core::gossip`]
//! for why: every information pull is gated by a fresh behavioural
//! conformance test, not a running score kept per peer, so this book is
//! just an address list, never a reputation ledger.

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

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[tokio::test]
    async fn starts_empty_with_no_initial_peers() {
        let book = PeerBook::new(Vec::new());
        assert!(book.random_peer().await.is_none());
        assert!(book.snapshot().await.is_empty());
    }

    #[tokio::test]
    async fn random_peer_returns_the_only_known_peer() {
        let book = PeerBook::new(vec![addr(9000)]);
        assert_eq!(book.random_peer().await, Some(addr(9000)));
    }

    #[tokio::test]
    async fn learn_adds_a_new_address() {
        let book = PeerBook::new(Vec::new());
        book.learn(addr(9000)).await;
        assert_eq!(book.snapshot().await, vec![addr(9000)]);
    }

    #[tokio::test]
    async fn learn_does_not_duplicate_a_known_address() {
        let book = PeerBook::new(vec![addr(9000)]);
        book.learn(addr(9000)).await;
        assert_eq!(book.snapshot().await, vec![addr(9000)]);
    }

    #[tokio::test]
    async fn snapshot_reflects_multiple_learned_peers() {
        let book = PeerBook::new(Vec::new());
        book.learn(addr(9000)).await;
        book.learn(addr(9001)).await;
        let snapshot = book.snapshot().await;
        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.contains(&addr(9000)));
        assert!(snapshot.contains(&addr(9001)));
    }
}
