//! The ephemeral registration store: an in-memory table (standing in for
//! the embedded memcached/redis-style datastore) mapping domain names to
//! their current registration, keyed with a timestamp + random-nonce
//! token to make collisions detectable and resolvable.

use std::collections::HashMap;

use crate::client::ClientIdentity;
use crate::collision::negotiate_locally;
use crate::domain::DomainName;
use crate::gossip::RegistrationRumor;
use crate::liveness::{LivenessTracker, TimeSource};
use crate::token::RegistrationToken;
use crate::zone::Record;

/// A single domain's current registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub client_key: String,
    pub token: RegistrationToken,
    pub records: Vec<Record>,
    pub rumor: Option<RegistrationRumor>,
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
    probe_evidence: HashMap<String, (u64, Vec<u8>)>,
}

impl RegistryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a liveness probe from `client`.
    pub fn probe(&mut self, client: &ClientIdentity, time: &dyn TimeSource) {
        self.liveness.record_probe(client, time);
    }

    pub fn probe_with_evidence(
        &mut self,
        client: &ClientIdentity,
        time: &dyn TimeSource,
        timestamp: u64,
        signature: Vec<u8>,
    ) {
        self.probe(client, time);
        self.probe_evidence
            .insert(client.key(), (timestamp, signature));
    }

    pub fn last_probe_evidence(&self, client: &ClientIdentity) -> Option<(u64, Vec<u8>)> {
        self.probe_evidence.get(&client.key()).cloned()
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
                rumor: None,
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
                rumor: None,
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

    /// Persist the owner-signed lease created by the API layer. Only an
    /// exact locally-issued claim may gain gossip authority.
    pub fn attach_rumor(&mut self, rumor: RegistrationRumor) -> bool {
        match self.registrations.get_mut(&rumor.domain) {
            Some(reg) if reg.client_key == rumor.client_key && reg.token == rumor.token => {
                reg.records = rumor.records.clone();
                reg.rumor = Some(rumor);
                true
            }
            _ => false,
        }
    }

    /// Refresh every locally held lease for an owner after its authenticated
    /// probe. This makes expiry globally reproducible on the next gossip.
    pub fn refresh_probe_evidence(&mut self, client_key: &str, timestamp: u64, signature: Vec<u8>) {
        for registration in self.registrations.values_mut() {
            if registration.client_key == client_key {
                if let Some(rumor) = &mut registration.rumor {
                    rumor.probe_timestamp_millis = timestamp;
                    rumor.probe_signature = signature.clone();
                }
            }
        }
    }

    pub fn attach_record_evidence(
        &mut self,
        domain: &DomainName,
        client_key: &str,
        timestamp: u64,
        signature: Vec<u8>,
    ) {
        if let Some(registration) = self.registrations.get_mut(domain) {
            if registration.client_key == client_key {
                if let Some(rumor) = &mut registration.rumor {
                    rumor.records = registration.records.clone();
                    rumor.records_timestamp_millis = Some(timestamp);
                    rumor.records_signature = Some(signature);
                }
            }
        }
    }

    /// Absorb a fact learned from gossip: another node claims `domain` is
    /// held by `client_key` as of `token`. Never subject to this node's
    /// own liveness/cap rules — those only gate registrations *this* node
    /// issues locally. If the domain is already held here under a
    /// different claim, the two claims are arbitrated via the same mutual
    /// coin-negotiation protocol used for a live collision.
    pub fn adopt_rumor(&mut self, rumor: RegistrationRumor, time: &dyn TimeSource) -> bool {
        if !rumor.is_authorized()
            || time
                .now_millis()
                .saturating_sub(rumor.probe_timestamp_millis)
                > crate::liveness::LIVENESS_WINDOW.as_millis() as u64
        {
            return false;
        }
        let domain = rumor.domain.clone();
        let client_key = rumor.client_key.clone();
        let token = rumor.token;
        match self.registrations.get(&domain) {
            None => {
                self.registrations.insert(
                    domain,
                    Registration {
                        client_key,
                        token,
                        records: rumor.records.clone(),
                        rumor: Some(rumor),
                    },
                );
            }
            Some(existing) if existing.client_key == client_key && existing.token == token => {
                // Already known; nothing to do.
            }
            Some(existing) => {
                // `negotiate_locally` is a symmetric derivation from both
                // tokens, so every replica makes the same choice. Retain
                // the winning lease itself; retaining only its key/token
                // would make the next anti-entropy round unauthenticated.
                if negotiate_locally(existing.token, token) == token {
                    self.registrations.insert(
                        domain,
                        Registration {
                            client_key,
                            token,
                            records: rumor.records.clone(),
                            rumor: Some(rumor),
                        },
                    );
                }
            }
        }
        true
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
    ///
    /// This also forgets those clients' registration counts, not just
    /// their domains: without that, a client that later comes back live
    /// would find its slot count still pinned at whatever it was before
    /// going stale, even though none of its old domains still exist to
    /// justify that count.
    pub fn reclaim_stale(&mut self, time: &dyn TimeSource) {
        let expired = self.liveness.expired_clients(time);
        if expired.is_empty() {
            return;
        }
        let expired: std::collections::HashSet<String> = expired.into_iter().collect();
        self.registrations
            .retain(|_, reg| !expired.contains(&reg.client_key));
        for key in &expired {
            self.liveness.forget_client_by_key(key);
        }
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

    #[test]
    fn client_can_reach_the_cap_again_after_going_stale_and_coming_back() {
        // Regression test: reclaim_stale used to remove a stale client's
        // domains but leave its registration count untouched, which
        // would permanently pin it at the cap even after every one of
        // its old domains had already been freed.
        let time = MockTimeSource::new(0);
        let mut store = RegistryStore::new();
        let c = client();
        store.probe(&c, &time);
        for i in 0..crate::liveness::MAX_REGISTRATIONS_PER_CLIENT {
            let domain = DomainName::new(format!("d{i}.binda")).unwrap();
            store.register(domain, &c, &time).unwrap();
        }

        time.advance(std::time::Duration::from_millis(
            crate::liveness::LIVENESS_WINDOW.as_millis() as u64 + 1,
        ));
        store.reclaim_stale(&time);

        // Client comes back live and should be able to register a full
        // batch again, not be stuck at the old count.
        store.probe(&c, &time);
        let domain = DomainName::new("fresh.binda").unwrap();
        assert!(store.register(domain, &c, &time).is_ok());
    }

    #[test]
    fn set_records_fails_for_non_owner() {
        let time = MockTimeSource::new(0);
        let mut store = RegistryStore::new();
        let owner = client();
        let stranger = client();
        store.probe(&owner, &time);
        let domain = DomainName::new("example.binda").unwrap();
        store.register(domain.clone(), &owner, &time).unwrap();

        assert!(!store.set_records(&domain, &stranger, Vec::new()));
    }

    #[test]
    fn set_records_fails_for_unregistered_domain() {
        let mut store = RegistryStore::new();
        let c = client();
        let domain = DomainName::new("example.binda").unwrap();
        assert!(!store.set_records(&domain, &c, Vec::new()));
    }

    #[test]
    fn set_records_succeeds_for_owner() {
        let time = MockTimeSource::new(0);
        let mut store = RegistryStore::new();
        let c = client();
        store.probe(&c, &time);
        let domain = DomainName::new("example.binda").unwrap();
        store.register(domain.clone(), &c, &time).unwrap();

        let records = vec![crate::zone::Record {
            name: "@".into(),
            record_type: crate::zone::RecordType::A,
            ttl_secs: 300,
            value: "203.0.113.1".into(),
        }];
        assert!(store.set_records(&domain, &c, records.clone()));
        assert_eq!(store.lookup(&domain).unwrap().records, records);
    }

    #[test]
    fn all_rumors_reflects_every_registration() {
        let time = MockTimeSource::new(0);
        let mut store = RegistryStore::new();
        let c = client();
        store.probe(&c, &time);
        let d1 = DomainName::new("one.binda").unwrap();
        let d2 = DomainName::new("two.binda").unwrap();
        store.register(d1.clone(), &c, &time).unwrap();
        store.register(d2.clone(), &c, &time).unwrap();

        let domains: std::collections::HashSet<_> = store
            .all_rumors()
            .map(|(domain, _, _)| domain.clone())
            .collect();
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&d1));
        assert!(domains.contains(&d2));
    }

    #[test]
    fn registering_an_already_held_live_domain_is_refused() {
        let time = MockTimeSource::new(0);
        let mut store = RegistryStore::new();
        let owner = client();
        let other = client();
        store.probe(&owner, &time);
        store.probe(&other, &time);
        let domain = DomainName::new("example.binda").unwrap();
        store.register(domain.clone(), &owner, &time).unwrap();

        assert_eq!(
            store.register(domain, &other, &time),
            Err(RegistrationError::RegistrationLimitReached)
        );
    }

    #[test]
    fn a_sixth_distinct_domain_is_refused_while_still_live() {
        let time = MockTimeSource::new(0);
        let mut store = RegistryStore::new();
        let c = client();
        store.probe(&c, &time);
        for i in 0..crate::liveness::MAX_REGISTRATIONS_PER_CLIENT {
            let domain = DomainName::new(format!("d{i}.binda")).unwrap();
            store.register(domain, &c, &time).unwrap();
        }

        let sixth = DomainName::new("one-too-many.binda").unwrap();
        assert_eq!(
            store.register(sixth, &c, &time),
            Err(RegistrationError::RegistrationLimitReached)
        );
    }
}
