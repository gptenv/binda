//! Wire encoding for messages exchanged over the network.
//!
//! Encoding is JSON: this is a young protocol under active change, and
//! human-readable frames make it far easier to debug with a packet dump
//! than a binary format would, at a bandwidth cost this project is happy
//! to pay for now. Datagrams are capped at [`MAX_DATAGRAM_BYTES`] so a
//! malformed or hostile peer can't force unbounded allocation on decode.

use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

/// Maximum size, in bytes, of a single encoded wire message. Chosen to sit
/// comfortably under the practical UDP datagram size most networks pass
/// without fragmentation.
pub const MAX_DATAGRAM_BYTES: usize = 60_000;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("failed to serialize message: {0}")]
    Encode(serde_json::Error),
    #[error("failed to deserialize message: {0}")]
    Decode(serde_json::Error),
    #[error("encoded message of {actual} bytes exceeds the {max} byte limit")]
    TooLarge { actual: usize, max: usize },
}

/// Encode `message` to bytes, refusing to produce a frame larger than
/// [`MAX_DATAGRAM_BYTES`].
pub fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>, WireError> {
    let bytes = serde_json::to_vec(message).map_err(WireError::Encode)?;
    if bytes.len() > MAX_DATAGRAM_BYTES {
        return Err(WireError::TooLarge {
            actual: bytes.len(),
            max: MAX_DATAGRAM_BYTES,
        });
    }
    Ok(bytes)
}

/// Decode `bytes` into a `T`, refusing input larger than
/// [`MAX_DATAGRAM_BYTES`] before even attempting to parse it.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WireError> {
    if bytes.len() > MAX_DATAGRAM_BYTES {
        return Err(WireError::TooLarge {
            actual: bytes.len(),
            max: MAX_DATAGRAM_BYTES,
        });
    }
    serde_json::from_slice(bytes).map_err(WireError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gossip::{DigestEntry, GossipMessage};
    use crate::domain::DomainName;

    #[test]
    fn round_trips_a_gossip_message() {
        let msg = GossipMessage::Digest {
            rumors: vec![DigestEntry {
                domain: DomainName::new("example.binda").unwrap(),
                issued_at_millis: 42,
            }],
        };
        let bytes = encode(&msg).unwrap();
        let decoded: GossipMessage = decode(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn rejects_oversized_input() {
        let huge = vec![0u8; MAX_DATAGRAM_BYTES + 1];
        let result: Result<GossipMessage, _> = decode(&huge);
        assert!(matches!(result, Err(WireError::TooLarge { .. })));
    }
}
