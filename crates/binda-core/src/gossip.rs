//! Gossip-based (epidemic anti-entropy) propagation between BINDA nodes.
//!
//! Nodes never mark a peer as "trusted" or "distrusted" — they simply
//! observe whether the peer's messages conform to the protocol on every
//! exchange. A peer that ever sends a malformed or out-of-protocol message
//! is treated, *for that exchange only*, as not-a-BINDA-node: its gossip is
//! dropped and no state is updated from it. A later, well-formed exchange
//! from the same address is judged entirely on its own merits.

use serde::{Deserialize, Serialize};

use crate::domain::DomainName;
use crate::token::RegistrationToken;

/// A single fact a node can gossip about: a domain's current registration
/// state, as of a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationRumor {
    pub domain: DomainName,
    pub token: RegistrationToken,
    pub client_key: String,
}

/// Messages exchanged between BINDA peers during anti-entropy gossip
/// rounds. This is deliberately a small, closed, easy-to-validate set:
/// well-formedness of the message *is* the behavioural test peers apply to
/// each other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GossipMessage {
    /// "Here is a digest of what I know" — a peer announces the rumors it
    /// holds so the recipient can request only what it's missing.
    Digest { rumors: Vec<DigestEntry> },
    /// "Send me the full rumor for these domains."
    Request { domains: Vec<DomainName> },
    /// The full rumor payload answering a [`GossipMessage::Request`].
    Rumors { rumors: Vec<RegistrationRumor> },
}

/// A lightweight summary of one rumor, exchanged before the full payload
/// so peers don't re-send data the recipient already has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestEntry {
    pub domain: DomainName,
    pub issued_at_millis: u64,
}

/// A minimal behavioural check a node runs against every message it
/// receives before acting on it, standing in for a trust decision.
///
/// This is intentionally structural, not reputation-based: a node that
/// gossips one malformed message isn't blacklisted, it's simply ignored
/// *for that message*.
pub fn is_well_formed(message: &GossipMessage) -> bool {
    match message {
        GossipMessage::Digest { rumors } => rumors.len() <= MAX_DIGEST_ENTRIES,
        GossipMessage::Request { domains } => domains.len() <= MAX_REQUEST_ENTRIES,
        GossipMessage::Rumors { rumors } => rumors.len() <= MAX_DIGEST_ENTRIES,
    }
}

/// Upper bound on how many entries a single digest or rumor batch may
/// carry, so a malformed/hostile peer can't force unbounded allocation.
pub const MAX_DIGEST_ENTRIES: usize = 4096;

/// Upper bound on how many domains may appear in a single request.
pub const MAX_REQUEST_ENTRIES: usize = 4096;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_digest_is_rejected() {
        let rumors = (0..MAX_DIGEST_ENTRIES + 1)
            .map(|i| DigestEntry {
                domain: DomainName::new(format!("d{i}.binda")).unwrap(),
                issued_at_millis: 0,
            })
            .collect();
        let msg = GossipMessage::Digest { rumors };
        assert!(!is_well_formed(&msg));
    }

    #[test]
    fn normal_digest_is_accepted() {
        let msg = GossipMessage::Digest {
            rumors: vec![DigestEntry {
                domain: DomainName::new("example.binda").unwrap(),
                issued_at_millis: 0,
            }],
        };
        assert!(is_well_formed(&msg));
    }
}
