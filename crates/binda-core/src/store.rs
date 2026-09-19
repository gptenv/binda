//! The ephemeral registration store: an in-memory table (standing in for
//! the embedded memcached/redis-style datastore) mapping domain names to
//! their current registration, keyed with a timestamp + random-nonce
//! token to make collisions detectable and resolvable.

use std::collections::HashMap;

use crate::client::ClientIdentity;
use crate::collision::negotiate_locally;
use crate::domain::DomainName;
use crate::liveness::{LivenessTracker, TimeSource};
use crate::token::RegistrationToken;
use crate::zone::Record;

/// A single domain's current registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub client_key: String,
    pub token: RegistrationToken,
    pub records: Vec<Record>,
}

/// Reasons a registration attempt can be refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistrationError {
    #[error("client is not currently live (must probe within the liveness window first)")]
    NotLive,
    #[error("client already holds the maximum number of registrations")]
    RegistrationLimitReached,
}

/// The in-memory, per-node registration store.
///
/// This is the "temporary memcached or redis in-memory datastore embedded
/// in binda": registrations live only as long as the client keeps probing
/// liveness, and a domain whose owner goes stale falls back into the pool
/// for anyone to claim.
#[derive(Debug, Default)]
pub struct RegistryStore {
    registrations: HashMap<DomainName, Registration>,
    liveness: LivenessTracker,
}

impl RegistryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a liveness probe from `client`.
    pub fn probe(&mut self, client: &ClientIdentity, time: &dyn TimeSource) {
        self.liveness.record_probe(client, time);
    }

    /// Attempt to register `domain` on behalf of `client`.
    ///
    /// If the domain is free, the client is registered outright (subject
    /// to liveness and the per-client cap). If another live client already
    /// holds it, this call cannot succeed by itself — see
    /// [`Self::resolve_collision`] for the path taken when two BINDA
    /// nodes race to register the same name at the same time.
    pub fn register(
        &mut self,
        domain: DomainName,
        client: &ClientIdentity,
        time: &dyn TimeSource,
    ) -> Result<RegistrationToken, RegistrationError> {
        if !self.liveness.is_live(client, time) {
            return Err(RegistrationError::NotLive);
        }

        // A domain held by a client who has since gone stale is reclaimed
        // before the capacity/collision checks below run.
        self.reclaim_stale(time);

        if self.registrations.contains_key(&domain) {
            // Someone already holds it and is (as far as this node knows)
            // still live; the caller must go through collision resolution
            // instead of a plain register.
            return Err(RegistrationError::RegistrationLimitReached);
        }

        if !self.liveness.can_register(client, time) {
            return Err(RegistrationError::RegistrationLimitReached);
        }

        let token = RegistrationToken::issue(time.now_millis());
        self.registrations.insert(
            domain,
            Registration {
                client_key: client.key(),
                token,
                records: Vec::new(),
            },
        );
        self.liveness.increment_registration(client);
        Ok(token)
    }

    /// Resolve two simultaneous claims on the same domain (e.g. gossip
    /// revealed that a peer registered the same name at effectively the
    /// same instant) via the mutual coin-negotiation protocol, and install
    /// the winner.
    pub fn resolve_collision(
        &mut self,
        domain: DomainName,
        a: (String, RegistrationToken),
        b: (String, RegistrationToken),
    ) {
        let winner_token = negotiate_locally(a.1, b.1);
        let (client_key, token) = if winner_token == a.1 { a } else { b };
        self.registrations.insert(
            domain,
            Registration {
                client_key,
                token,
                records: Vec::new(),
            },
        );
    }

    /// Attach zone records to a domain this node's own client already
    /// owns. Fails silently (no-op) if `client` does not hold `domain`.
    pub fn set_records(
        &mut self,
        domain: &DomainName,
        client: &ClientIdentity,
        records: Vec<Record>,
    ) -> bool {
        match self.registrations.get_mut(domain) {
            Some(reg) if reg.client_key == client.key() => {
                reg.records = records;
                true
            }
            _ => false,
        }
    }

    /// Absorb a fact learned from gossip: another node claims `domain` is
    /// held by `client_key` as of `token`. Never subject to this node's
    /// own liveness/cap rules — those only gate registrations *this* node
    /// issues locally. If the domain is already held here under a
    /// different claim, the two claims are arbitrated via the same mutual
    /// coin-negotiation protocol used for a live collision.
    pub fn adopt_rumor(
        &mut self,
        domain: DomainName,
        client_key: String,
        token: RegistrationToken,
    ) {
        match self.registrations.get(&domain) {
            None => {
                self.registrations.insert(
                    domain,
                    Registration {
                        client_key,
                        token,
                        records: Vec::new(),
                    },
                );
            }
            Some(existing) if existing.client_key == client_key && existing.token == token => {
                // Already known; nothing to do.
            }
            Some(existing) => {
                self.resolve_collision(
                    domain,
                    (existing.client_key.clone(), existing.token),
                    (client_key, token),
                );
            }
        }
    }

    /// Every `(domain, client_key, token)` this node currently holds, for
    /// building a gossip digest.
    pub fn all_rumors(&self) -> impl Iterator<Item = (&DomainName, &str, RegistrationToken)> {
        self.registrations
            .iter()
            .map(|(domain, reg)| (domain, reg.client_key.as_str(), reg.token))
    }

    /// Release every registration belonging to clients who have missed
    /// their liveness window.
    pub fn reclaim_stale(&mut self, time: &dyn TimeSource) {
        let expired: std::collections::HashSet<String> =
            self.liveness.expired_clients(time).into_iter().collect();
        if expired.is_empty() {
            return;
        }
        self.registrations
            .retain(|_, reg| !expired.contains(&reg.client_key));
    }

    /// Look up the current registration for `domain`, if any.
    pub fn lookup(&self, domain: &DomainName) -> Option<&Registration> {
        self.registrations.get(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::liveness::MockTimeSource;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn client() -> ClientIdentity {
        let signing_key = SigningKey::generate(&mut OsRng);
        ClientIdentity::new(signing_key.verifying_key(), "host.example.net")
    }

    #[test]
    fn live_client_can_register_free_domain() {
        let time = MockTimeSource::new(0);
        let mut store = RegistryStore::new();
        let c = client();
        store.probe(&c, &time);
        let domain = DomainName::new("example.binda").unwrap();
        assert!(store.register(domain, &c, &time).is_ok());
    }

    #[test]
    fn stale_client_cannot_register() {
        let time = MockTimeSource::new(0);
        let mut store = RegistryStore::new();
        let c = client();
        let domain = DomainName::new("example.binda").unwrap();
        assert_eq!(
            store.register(domain, &c, &time),
            Err(RegistrationError::NotLive)
        );
    }

    #[test]
    fn stale_owner_loses_domain_on_reclaim() {
        let time = MockTimeSource::new(0);
        let mut store = RegistryStore::new();
        let c = client();
        store.probe(&c, &time);
        let domain = DomainName::new("example.binda").unwrap();
        store.register(domain.clone(), &c, &time).unwrap();

        time.advance(std::time::Duration::from_millis(
            crate::liveness::LIVENESS_WINDOW.as_millis() as u64 + 1,
        ));
        store.reclaim_stale(&time);
        assert!(store.lookup(&domain).is_none());
    }
}
