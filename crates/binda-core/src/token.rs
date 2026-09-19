//! Registration tokens: the timestamp + random nonce pair issued to a
//! client when it registers a domain, used to detect and order collisions.

use rand::RngCore;
use serde::{Deserialize, Serialize};

/// A unique-enough claim on a domain name: the issuing time plus 8
/// cryptographically random bytes.
///
/// Two clients racing to register the same name will each be issued a
/// distinct token; if a collision is detected (two live tokens for the
/// same [`crate::domain::DomainName`]), the tokens are handed to
/// [`crate::collision::resolve`] to pick a winner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationToken {
    pub issued_at_millis: u64,
    pub nonce: [u8; 8],
}

impl RegistrationToken {
    /// Issue a fresh token for the given timestamp, drawing its nonce from
    /// a cryptographically secure RNG.
    pub fn issue(issued_at_millis: u64) -> Self {
        let mut nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);
        Self {
            issued_at_millis,
            nonce,
        }
    }

    /// Deterministically compare two tokens' raw bytes, high-to-low. Used
    /// as the tie-break input to the coin-negotiation collision protocol,
    /// never as the sole decision rule (see [`crate::collision`]).
    pub fn raw_ordering_key(&self) -> [u8; 16] {
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&self.issued_at_millis.to_be_bytes());
        key[8..].copy_from_slice(&self.nonce);
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_distinct() {
        let a = RegistrationToken::issue(1000);
        let b = RegistrationToken::issue(1000);
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn raw_ordering_key_encodes_timestamp_then_nonce_big_endian() {
        let token = RegistrationToken {
            issued_at_millis: 0x0102030405060708,
            nonce: [0xAA; 8],
        };
        let key = token.raw_ordering_key();
        assert_eq!(&key[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&key[8..], &[0xAA; 8]);
    }

    #[test]
    fn later_timestamp_sorts_higher_in_ordering_key() {
        let earlier = RegistrationToken {
            issued_at_millis: 1,
            nonce: [0xFF; 8],
        };
        let later = RegistrationToken {
            issued_at_millis: 2,
            nonce: [0; 8],
        };
        assert!(later.raw_ordering_key() > earlier.raw_ordering_key());
    }
}
