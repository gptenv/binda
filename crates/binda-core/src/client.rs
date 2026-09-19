//! Client identity: a keypair plus the reverse-DNS hostname a registration
//! is bound to.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;

/// A client's public identity: an Ed25519 verifying key plus the reverse-DNS
/// hostname it claims to resolve from.
///
/// Reverse DNS is preferred over a bare IP because it survives the client
/// migrating across addresses within the same hosting account, while still
/// costing an attacker a real delegation to forge at scale. Deployments
/// that consider RDNS too easy to spoof for their threat model may fall
/// back to [`ClientIdentity::rdns`] being an IP-string instead; BINDA
/// itself does not distinguish the two forms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientIdentity {
    pub verifying_key: VerifyingKey,
    pub rdns: String,
}

/// Errors verifying a client's signature over a registration request.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientAuthError {
    #[error("signature does not verify against the supplied public key")]
    InvalidSignature,
}

impl ClientIdentity {
    pub fn new(verifying_key: VerifyingKey, rdns: impl Into<String>) -> Self {
        Self {
            verifying_key,
            rdns: rdns.into(),
        }
    }

    /// A stable string key identifying this client, for use as a map key in
    /// the liveness/registration store: the public key and RDNS combined,
    /// so a stolen RDNS record alone can't impersonate an existing client.
    pub fn key(&self) -> String {
        format!(
            "{}@{}",
            hex_encode(self.verifying_key.as_bytes()),
            self.rdns
        )
    }

    /// The scarce, verified-host subject that gates registration capacity.
    ///
    /// Owner keys are intentionally cheap to rotate.  They authenticate
    /// updates, but must never create fresh domain capacity.  The daemon
    /// forward-confirms this hostname against the request's observed source
    /// address before allowing a registration; canonicalising it here makes
    /// case and a trailing DNS dot unable to split one host's quota.
    pub fn quota_key(&self) -> String {
        self.rdns.trim().trim_end_matches('.').to_ascii_lowercase()
    }

    /// Verify that `signature` over `message` was produced by this client's
    /// private key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), ClientAuthError> {
        self.verifying_key
            .verify(message, signature)
            .map_err(|_| ClientAuthError::InvalidSignature)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn verifies_valid_signature() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let identity = ClientIdentity::new(signing_key.verifying_key(), "host.example.net");
        let msg = b"register: example.binda";
        let sig = signing_key.sign(msg);
        assert!(identity.verify(msg, &sig).is_ok());
    }

    #[test]
    fn rejects_tampered_message() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let identity = ClientIdentity::new(signing_key.verifying_key(), "host.example.net");
        let sig = signing_key.sign(b"register: example.binda");
        assert_eq!(
            identity.verify(b"register: evil.binda", &sig),
            Err(ClientAuthError::InvalidSignature)
        );
    }

    #[test]
    fn quota_key_is_host_scoped_and_canonical() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let a = ClientIdentity::new(signing_key.verifying_key(), "Host.Example.Net.");
        let b = ClientIdentity::new(
            SigningKey::generate(&mut OsRng).verifying_key(),
            "host.example.net",
        );
        assert_eq!(a.quota_key(), b.quota_key());
        assert_ne!(a.key(), b.key());
    }
}
