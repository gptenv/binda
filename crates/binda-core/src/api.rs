//! Glue between the authenticated [`crate::client_api`] requests and the
//! [`crate::store::RegistryStore`]'s business rules.

use crate::client_api::{
    authenticate, probe_message, register_message, set_records_message, ClientRequest,
    ClientResponse, ProbeBody, RegisterBody, SetRecordsBody, SignedEnvelope,
};
use crate::liveness::TimeSource;
use crate::store::RegistryStore;

/// Authenticate and apply one [`ClientRequest`] against `store`.
pub fn handle_client_request(
    store: &mut RegistryStore,
    time: &dyn TimeSource,
    request: ClientRequest,
) -> ClientResponse {
    let now = time.now_millis();
    match request {
        ClientRequest::Probe(envelope) => handle_probe(store, time, now, envelope),
        ClientRequest::Register(envelope) => handle_register(store, time, now, envelope),
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
) -> ClientResponse {
    let message = register_message(&envelope.body.domain, envelope.timestamp_millis);
    match authenticate(&envelope, &message, now) {
        Ok(identity) => match store.register(envelope.body.domain, &identity, time) {
            Ok(token) => ClientResponse::Registered { token },
            Err(err) => ClientResponse::Error {
                message: err.to_string(),
            },
        },
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
    let message = set_records_message(&envelope.body.domain, &envelope.body.records, envelope.timestamp_millis);
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

    fn envelope_register(signing_key: &SigningKey, domain: DomainName, timestamp: u64) -> ClientRequest {
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
        assert_eq!(handle_client_request(&mut store, &time, probe_req), ClientResponse::ProbeAck);

        let domain = DomainName::new("example.binda").unwrap();
        let register_req = envelope_register(&signing_key, domain, 1_000);
        match handle_client_request(&mut store, &time, register_req) {
            ClientResponse::Registered { .. } => {}
            other => panic!("expected Registered, got {other:?}"),
        }
    }

    #[test]
    fn register_without_prior_probe_is_refused() {
        let time = MockTimeSource::new(1_000);
        let mut store = RegistryStore::new();
        let signing_key = SigningKey::generate(&mut OsRng);
        let domain = DomainName::new("example.binda").unwrap();
        let register_req = envelope_register(&signing_key, domain, 1_000);
        match handle_client_request(&mut store, &time, register_req) {
            ClientResponse::Error { .. } => {}
            other => panic!("expected Error, got {other:?}"),
        }
    }
}
