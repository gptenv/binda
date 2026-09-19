//! The client-facing registration API: signed requests an end user's
//! client sends directly to a BINDA node to prove liveness, register a
//! domain, or publish records for one it already owns.
//!
//! Every request is authenticated by an Ed25519 signature over a
//! canonical message built from the request's own fields plus a
//! timestamp, so a captured request can't be replayed outside a short
//! freshness window (see [`is_fresh`]).

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::client::{ClientAuthError, ClientIdentity};
use crate::domain::DomainName;
use crate::token::RegistrationToken;
use crate::zone::Record;

/// How far a request's claimed timestamp may drift from this node's own
/// clock before it's refused as stale or from-the-future (defends against
/// replay of an old captured request).
pub const REQUEST_FRESHNESS_WINDOW_MILLIS: u64 = 10_000;

/// A request from an end-user client to a BINDA node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientRequest {
    /// Prove liveness: extends the sender's registrations for another
    /// [`crate::liveness::LIVENESS_WINDOW`].
    Probe(SignedEnvelope<ProbeBody>),
    /// Claim a free domain name.
    Register(SignedEnvelope<RegisterBody>),
    /// Publish zone records for a domain the sender already owns.
    SetRecords(SignedEnvelope<SetRecordsBody>),
}

/// A request body plus the identity and signature authenticating it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope<T> {
    pub verifying_key: Vec<u8>,
    pub rdns: String,
    pub timestamp_millis: u64,
    pub signature: Vec<u8>,
    pub body: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeBody;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterBody {
    pub domain: DomainName,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetRecordsBody {
    pub domain: DomainName,
    pub records: Vec<Record>,
}

/// The outcome of handling a [`ClientRequest`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientResponse {
    ProbeAck,
    Registered { token: RegistrationToken },
    RecordsSet,
    Error { message: String },
}

/// Errors authenticating a [`ClientRequest`] before it ever reaches the
/// registry store's own business-rule checks.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RequestAuthError {
    #[error("malformed public key")]
    MalformedKey,
    #[error("malformed signature")]
    MalformedSignature,
    #[error(transparent)]
    Signature(#[from] ClientAuthError),
    #[error("request timestamp is outside the freshness window")]
    Stale,
}

/// Build the canonical byte message a `Probe` request's signature covers.
pub fn probe_message(timestamp_millis: u64) -> Vec<u8> {
    format!("binda-probe:{timestamp_millis}").into_bytes()
}

/// Build the canonical byte message a `Register` request's signature
/// covers.
pub fn register_message(domain: &DomainName, timestamp_millis: u64) -> Vec<u8> {
    format!("binda-register:{domain}:{timestamp_millis}").into_bytes()
}

/// Build the canonical byte message a `SetRecords` request's signature
/// covers.
pub fn set_records_message(domain: &DomainName, records: &[Record], timestamp_millis: u64) -> Vec<u8> {
    let mut msg = format!("binda-set-records:{domain}:{timestamp_millis}:").into_bytes();
    if let Ok(json) = serde_json::to_vec(records) {
        msg.extend(json);
    }
    msg
}

/// Whether `timestamp_millis` is within [`REQUEST_FRESHNESS_WINDOW_MILLIS`]
/// of `now_millis`.
pub fn is_fresh(timestamp_millis: u64, now_millis: u64) -> bool {
    now_millis.abs_diff(timestamp_millis) <= REQUEST_FRESHNESS_WINDOW_MILLIS
}

/// Authenticate a [`SignedEnvelope`] against the canonical `message` bytes
/// it should have signed, returning the caller's verified identity.
pub fn authenticate<T>(
    envelope: &SignedEnvelope<T>,
    message: &[u8],
    now_millis: u64,
) -> Result<ClientIdentity, RequestAuthError> {
    if !is_fresh(envelope.timestamp_millis, now_millis) {
        return Err(RequestAuthError::Stale);
    }
    let key_bytes: [u8; 32] = envelope
        .verifying_key
        .as_slice()
        .try_into()
        .map_err(|_| RequestAuthError::MalformedKey)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| RequestAuthError::MalformedKey)?;
    let signature = Signature::from_slice(&envelope.signature)
        .map_err(|_| RequestAuthError::MalformedSignature)?;
    let identity = ClientIdentity::new(verifying_key, envelope.rdns.clone());
    identity.verify(message, &signature)?;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn authenticates_valid_probe() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let msg = probe_message(1000);
        let signature = signing_key.sign(&msg);
        let envelope = SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns: "host.example.net".into(),
            timestamp_millis: 1000,
            signature: signature.to_bytes().to_vec(),
            body: ProbeBody,
        };
        assert!(authenticate(&envelope, &msg, 1000).is_ok());
    }

    #[test]
    fn rejects_stale_timestamp() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let msg = probe_message(1000);
        let signature = signing_key.sign(&msg);
        let envelope = SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns: "host.example.net".into(),
            timestamp_millis: 1000,
            signature: signature.to_bytes().to_vec(),
            body: ProbeBody,
        };
        let far_future = 1000 + REQUEST_FRESHNESS_WINDOW_MILLIS + 1;
        assert_eq!(authenticate(&envelope, &msg, far_future), Err(RequestAuthError::Stale));
    }

    #[test]
    fn rejects_wrong_signature() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let other_key = SigningKey::generate(&mut OsRng);
        let msg = probe_message(1000);
        let signature = other_key.sign(&msg);
        let envelope = SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns: "host.example.net".into(),
            timestamp_millis: 1000,
            signature: signature.to_bytes().to_vec(),
            body: ProbeBody,
        };
        assert!(matches!(
            authenticate(&envelope, &msg, 1000),
            Err(RequestAuthError::Signature(_))
        ));
    }
}
