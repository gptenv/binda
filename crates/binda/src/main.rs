//! `binda`: the BINDA node daemon binary.
//!
//! This is a minimal single-node scaffold: it starts an in-memory
//! [`binda_core::RegistryStore`], simulates a client probing liveness and
//! registering a domain, and prints the result. Networking (the gossip
//! transport and resolver query handling) is not yet wired up.

use std::time::Duration;

use binda_core::client::ClientIdentity;
use binda_core::domain::DomainName;
use binda_core::liveness::SystemTimeSource;
use binda_core::store::RegistryStore;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[tokio::main]
async fn main() {
    println!("binda (bind10) — starting a single-node scaffold instance");

    let time = SystemTimeSource;
    let mut store = RegistryStore::new();

    let signing_key = SigningKey::generate(&mut OsRng);
    let client = ClientIdentity::new(signing_key.verifying_key(), "localhost.");

    store.probe(&client, &time);

    let domain = DomainName::new("example.binda").expect("valid domain name");
    match store.register(domain.clone(), &client, &time) {
        Ok(token) => println!(
            "registered {domain} for client {} at t={} nonce={:02x?}",
            client.rdns, token.issued_at_millis, token.nonce
        ),
        Err(err) => eprintln!("registration failed: {err}"),
    }

    println!("liveness window is {:?}; probe again before it lapses to keep the name", Duration::from_secs(3));
}
