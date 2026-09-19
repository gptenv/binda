//! Glue between the authenticated [`crate::client_api`] requests and the
//! [`crate::store::RegistryStore`]'s business rules.

use crate::client_api::{
    authenticate, probe_message, register_message, set_records_message, ClientRequest,
    ClientResponse, ProbeBody, RegisterBody, SetRecordsBody, SignedEnvelope,
};
use crate::liveness::TimeSource;
use crate::store::RegistryStore;

/// Authenticate and apply one [`ClientRequest`] against `store`.
///
/// `rdns_verified` says whether the request's claimed `rdns` hostname has
/// already been checked (by the caller, against its actual observed
/// source address — see [`crate::fcrdns`]) to forward-confirm. This
/// function stays pure/synchronous and doesn't do that network check
/// itself; only [`ClientRequest::Register`] consults the flag, since
/// that's the action the "5 domains per live socket" cap actually gates.
pub fn handle_client_request(
    store: &mut RegistryStore,
    time: &dyn TimeSource,
    request: ClientRequest,
    rdns_verified: bool,
) -> ClientResponse {
    let now = time.now_millis();
    match request {
        ClientRequest::Probe(envelope) => handle_probe(store, time, now, envelope),
        ClientRequest::Register(envelope) => {
            handle_register(store, time, now, envelope, rdns_verified)
        }
        ClientRequest::SetRecords(envelope) => handle_set_records(store, now, envelope),
    }
}

fn handle_probe(
    store: &mut RegistryStore,
    time: &dyn TimeSource,
    now: u64,
    envelope: SignedEnvelope<ProbeBody>,
) -> ClientResponse {
    let message = probe_message(envelope.timestamp_millis);
    match authenticate(&envelope, &message, now) {
        Ok(identity) => {
            store.probe(&identity, time);
            ClientResponse::ProbeAck
        }
        Err(err) => ClientResponse::Error {
            message: err.to_string(),
        },
    }
}

fn handle_register(
    store: &mut RegistryStore,
    time: &dyn TimeSource,
    now: u64,
    envelope: SignedEnvelope<RegisterBody>,
    rdns_verified: bool,
) -> ClientResponse {
    let message = register_message(&envelope.body.domain, envelope.timestamp_millis);
    match authenticate(&envelope, &message, now) {
        Ok(identity) => {
            if !rdns_verified {
                return ClientResponse::Error {
                    message: "claimed rdns hostname does not forward-confirm against the request's source address".to_string(),
                };
            }
            match store.register(envelope.body.domain, &identity, time) {
                Ok(token) => ClientResponse::Registered { token },
                Err(err) => ClientResponse::Error {
                    message: err.to_string(),
                },
            }
        }
        Err(err) => ClientResponse::Error {
            message: err.to_string(),
        },
    }
}

fn handle_set_records(
    store: &mut RegistryStore,
    now: u64,
    envelope: SignedEnvelope<SetRecordsBody>,
) -> ClientResponse {
    let message = set_records_message(
        &envelope.body.domain,
        &envelope.body.records,
        envelope.timestamp_millis,
    );
    match authenticate(&envelope, &message, now) {
        Ok(identity) => {
            if store.set_records(&envelope.body.domain, &identity, envelope.body.records) {
                ClientResponse::RecordsSet
            } else {
                ClientResponse::Error {
                    message: "client does not own this domain".to_string(),
                }
            }
        }
        Err(err) => ClientResponse::Error {
            message: err.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_api::{register_message, RegisterBody};
    use crate::domain::DomainName;
    use crate::liveness::MockTimeSource;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn envelope_register(
        signing_key: &SigningKey,
        domain: DomainName,
        timestamp: u64,
    ) -> ClientRequest {
        let message = register_message(&domain, timestamp);
        let signature = signing_key.sign(&message);
        ClientRequest::Register(SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns: "host.example.net".into(),
            timestamp_millis: timestamp,
            signature: signature.to_bytes().to_vec(),
            body: RegisterBody { domain },
        })
    }

    #[test]
    fn probe_then_register_succeeds_end_to_end() {
        let time = MockTimeSource::new(1_000);
        let mut store = RegistryStore::new();
        let signing_key = SigningKey::generate(&mut OsRng);

        let probe_msg = crate::client_api::probe_message(1_000);
        let probe_sig = signing_key.sign(&probe_msg);
        let probe_req = ClientRequest::Probe(SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns: "host.example.net".into(),
            timestamp_millis: 1_000,
            signature: probe_sig.to_bytes().to_vec(),
            body: ProbeBody,
        });
        assert_eq!(
            handle_client_request(&mut store, &time, probe_req, true),
            ClientResponse::ProbeAck
        );

        let domain = DomainName::new("example.binda").unwrap();
        let register_req = envelope_register(&signing_key, domain, 1_000);
        assert!(matches!(
            handle_client_request(&mut store, &time, register_req, true),
            ClientResponse::Registered { .. }
        ));
    }

    #[test]
    fn register_without_prior_probe_is_refused() {
        let time = MockTimeSource::new(1_000);
        let mut store = RegistryStore::new();
        let signing_key = SigningKey::generate(&mut OsRng);
        let domain = DomainName::new("example.binda").unwrap();
        let register_req = envelope_register(&signing_key, domain, 1_000);
        assert!(matches!(
            handle_client_request(&mut store, &time, register_req, true),
            ClientResponse::Error { .. }
        ));
    }

    #[test]
    fn register_with_bad_signature_is_refused() {
        let time = MockTimeSource::new(1_000);
        let mut store = RegistryStore::new();
        let signing_key = SigningKey::generate(&mut OsRng);
        handle_client_request(&mut store, &time, probe(&signing_key, 1_000), true);

        let domain = DomainName::new("example.binda").unwrap();
        let mut req = envelope_register(&signing_key, domain, 1_000);
        if let ClientRequest::Register(envelope) = &mut req {
            envelope.signature = vec![0u8; 64];
        }
        assert!(matches!(
            handle_client_request(&mut store, &time, req, true),
            ClientResponse::Error { .. }
        ));
    }

    #[test]
    fn register_without_rdns_verification_is_refused_even_if_otherwise_valid() {
        let time = MockTimeSource::new(1_000);
        let mut store = RegistryStore::new();
        let signing_key = SigningKey::generate(&mut OsRng);

        let probe_msg = crate::client_api::probe_message(1_000);
        let probe_sig = signing_key.sign(&probe_msg);
        let probe_req = ClientRequest::Probe(SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns: "host.example.net".into(),
            timestamp_millis: 1_000,
            signature: probe_sig.to_bytes().to_vec(),
            body: ProbeBody,
        });
        handle_client_request(&mut store, &time, probe_req, true);

        let domain = DomainName::new("example.binda").unwrap();
        let register_req = envelope_register(&signing_key, domain, 1_000);
        assert!(matches!(
            handle_client_request(&mut store, &time, register_req, false),
            ClientResponse::Error { .. }
        ));
    }

    fn probe(signing_key: &SigningKey, timestamp: u64) -> ClientRequest {
        let msg = crate::client_api::probe_message(timestamp);
        let sig = signing_key.sign(&msg);
        ClientRequest::Probe(SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns: "host.example.net".into(),
            timestamp_millis: timestamp,
            signature: sig.to_bytes().to_vec(),
            body: ProbeBody,
        })
    }

    #[test]
    fn probe_with_bad_signature_is_refused() {
        let time = MockTimeSource::new(1_000);
        let mut store = RegistryStore::new();
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut req = probe(&signing_key, 1_000);
        if let ClientRequest::Probe(envelope) = &mut req {
            envelope.signature = vec![0u8; 64]; // wrong signature
        }
        assert!(matches!(
            handle_client_request(&mut store, &time, req, true),
            ClientResponse::Error { .. }
        ));
    }

    #[test]
    fn registering_an_already_taken_domain_is_refused() {
        let time = MockTimeSource::new(1_000);
        let mut store = RegistryStore::new();
        let owner_key = SigningKey::generate(&mut OsRng);
        let other_key = SigningKey::generate(&mut OsRng);
        handle_client_request(&mut store, &time, probe(&owner_key, 1_000), true);
        handle_client_request(&mut store, &time, probe(&other_key, 1_000), true);

        let domain = DomainName::new("example.binda").unwrap();
        handle_client_request(
            &mut store,
            &time,
            envelope_register(&owner_key, domain.clone(), 1_000),
            true,
        );
        assert!(matches!(
            handle_client_request(
                &mut store,
                &time,
                envelope_register(&other_key, domain, 1_000),
                true,
            ),
            ClientResponse::Error { .. }
        ));
    }

    fn envelope_set_records(
        signing_key: &SigningKey,
        domain: DomainName,
        records: Vec<crate::zone::Record>,
        timestamp: u64,
    ) -> ClientRequest {
        let message = crate::client_api::set_records_message(&domain, &records, timestamp);
        let signature = signing_key.sign(&message);
        ClientRequest::SetRecords(SignedEnvelope {
            verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
            rdns: "host.example.net".into(),
            timestamp_millis: timestamp,
            signature: signature.to_bytes().to_vec(),
            body: crate::client_api::SetRecordsBody { domain, records },
        })
    }

    #[test]
    fn set_records_succeeds_for_domain_owner() {
        let time = MockTimeSource::new(1_000);
        let mut store = RegistryStore::new();
        let signing_key = SigningKey::generate(&mut OsRng);
        handle_client_request(&mut store, &time, probe(&signing_key, 1_000), true);
        let domain = DomainName::new("example.binda").unwrap();
        handle_client_request(
            &mut store,
            &time,
            envelope_register(&signing_key, domain.clone(), 1_000),
            true,
        );

        let records = vec![crate::zone::Record {
            name: "@".into(),
            record_type: crate::zone::RecordType::A,
            ttl_secs: 300,
            value: "203.0.113.1".into(),
        }];
        let req = envelope_set_records(&signing_key, domain, records, 1_000);
        assert_eq!(
            handle_client_request(&mut store, &time, req, true),
            ClientResponse::RecordsSet
        );
    }

    #[test]
    fn set_records_fails_for_non_owner() {
        let time = MockTimeSource::new(1_000);
        let mut store = RegistryStore::new();
        let owner_key = SigningKey::generate(&mut OsRng);
        let stranger_key = SigningKey::generate(&mut OsRng);
        handle_client_request(&mut store, &time, probe(&owner_key, 1_000), true);
        let domain = DomainName::new("example.binda").unwrap();
        handle_client_request(
            &mut store,
            &time,
            envelope_register(&owner_key, domain.clone(), 1_000),
            true,
        );

        let req = envelope_set_records(&stranger_key, domain, Vec::new(), 1_000);
        assert!(matches!(
            handle_client_request(&mut store, &time, req, true),
            ClientResponse::Error { .. }
        ));
    }

    #[test]
    fn set_records_with_bad_signature_is_refused() {
        let time = MockTimeSource::new(1_000);
        let mut store = RegistryStore::new();
        let signing_key = SigningKey::generate(&mut OsRng);
        let domain = DomainName::new("example.binda").unwrap();
        let mut req = envelope_set_records(&signing_key, domain, Vec::new(), 1_000);
        if let ClientRequest::SetRecords(envelope) = &mut req {
            envelope.signature = vec![0u8; 64];
        }
        assert!(matches!(
            handle_client_request(&mut store, &time, req, true),
            ClientResponse::Error { .. }
        ));
    }
}
