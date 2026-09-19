//! Liveness tracking.
//!
//! A client keeps its registrations only as long as it answers a liveness
//! probe within [`LIVENESS_WINDOW`] of a trusted time source (in
//! production, NTP-disciplined; see [`TimeSource`]). Missing the window
//! releases every domain the client holds back into the pool.

use std::collections::HashMap;
use std::time::Duration;

use crate::client::ClientIdentity;

/// The maximum gap allowed between successive liveness probes before a
/// client's registrations are considered abandoned. Originally 3 seconds;
/// relaxed to a minute so a client reconfiguring its infrastructure has
/// some real slack before losing its name.
pub const LIVENESS_WINDOW: Duration = Duration::from_secs(60);

/// The maximum number of live domain registrations a single client
/// identity may hold at once, enforced while it remains within
/// [`LIVENESS_WINDOW`].
pub const MAX_REGISTRATIONS_PER_CLIENT: usize = 5;

/// A source of trusted wall-clock time.
///
/// Production deployments implement this against an NTP-disciplined clock
/// (e.g. verifying `chrony`/`ntpd` sync status before trusting
/// [`SystemTime::now`](std::time::SystemTime::now)); tests use a
/// [`MockTimeSource`] instead.
pub trait TimeSource: Send + Sync {
    /// Milliseconds since the Unix epoch, as measured by a trusted clock.
    fn now_millis(&self) -> u64;
}

/// A [`TimeSource`] backed by the OS clock, with no external verification.
///
/// Intended only for local development; production nodes should wrap a
/// clock whose sync status against NTP peers has actually been checked.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn now_millis(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// A [`TimeSource`] with a manually-advanced clock, for deterministic tests.
#[derive(Debug, Default)]
pub struct MockTimeSource {
    millis: std::sync::atomic::AtomicU64,
}

impl MockTimeSource {
    pub fn new(start_millis: u64) -> Self {
        Self {
            millis: std::sync::atomic::AtomicU64::new(start_millis),
        }
    }

    pub fn advance(&self, delta: Duration) {
        self.millis.fetch_add(
            delta.as_millis() as u64,
            std::sync::atomic::Ordering::SeqCst,
        );
    }
}

impl TimeSource for MockTimeSource {
    fn now_millis(&self) -> u64 {
        self.millis.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Tracks the last-seen timestamp of every client currently holding
/// registrations, and how many domains each one holds.
#[derive(Debug, Default)]
pub struct LivenessTracker {
    last_seen_millis: HashMap<String, u64>,
    registration_counts: HashMap<String, usize>,
}

impl LivenessTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a liveness probe response from `client` at the current time.
    pub fn record_probe(&mut self, client: &ClientIdentity, time: &dyn TimeSource) {
        self.last_seen_millis
            .insert(client.key(), time.now_millis());
    }

    /// Whether `client` has probed within [`LIVENESS_WINDOW`] of `time`'s
    /// current reading. A client never probed is not considered live.
    pub fn is_live(&self, client: &ClientIdentity, time: &dyn TimeSource) -> bool {
        match self.last_seen_millis.get(&client.key()) {
            Some(&last) => {
                let now = time.now_millis();
                now.saturating_sub(last) <= LIVENESS_WINDOW.as_millis() as u64
            }
            None => false,
        }
    }

    /// Current number of registrations attributed to `client`.
    pub fn registration_count(&self, client: &ClientIdentity) -> usize {
        self.registration_counts
            .get(&client.key())
            .copied()
            .unwrap_or(0)
    }

    /// Whether `client` may register one more domain: it must be live and
    /// under [`MAX_REGISTRATIONS_PER_CLIENT`].
    pub fn can_register(&self, client: &ClientIdentity, time: &dyn TimeSource) -> bool {
        self.is_live(client, time) && self.registration_count(client) < MAX_REGISTRATIONS_PER_CLIENT
    }

    /// Attribute one more registration to `client`. Callers must have
    /// already checked [`Self::can_register`].
    pub fn increment_registration(&mut self, client: &ClientIdentity) {
        *self.registration_counts.entry(client.key()).or_insert(0) += 1;
    }

    /// Release all of `client`'s registration slots, e.g. after it drops
    /// out of the live set and its domains are reclaimed.
    pub fn clear_registrations(&mut self, client: &ClientIdentity) {
        self.registration_counts.remove(&client.key());
    }

    /// Every client identity key that has missed its liveness window as of
    /// `time`, i.e. whose held domains should now be released.
    pub fn expired_clients(&self, time: &dyn TimeSource) -> Vec<String> {
        let now = time.now_millis();
        self.last_seen_millis
            .iter()
            .filter(|(_, &last)| now.saturating_sub(last) > LIVENESS_WINDOW.as_millis() as u64)
            .map(|(key, _)| key.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn client() -> ClientIdentity {
        let signing_key = SigningKey::generate(&mut OsRng);
        ClientIdentity::new(signing_key.verifying_key(), "host.example.net")
    }

    #[test]
    fn client_is_live_immediately_after_probe() {
        let time = MockTimeSource::new(0);
        let mut tracker = LivenessTracker::new();
        let c = client();
        tracker.record_probe(&c, &time);
        assert!(tracker.is_live(&c, &time));
    }

    #[test]
    fn client_goes_stale_after_window() {
        let time = MockTimeSource::new(0);
        let mut tracker = LivenessTracker::new();
        let c = client();
        tracker.record_probe(&c, &time);
        time.advance(Duration::from_millis(
            LIVENESS_WINDOW.as_millis() as u64 + 1,
        ));
        assert!(!tracker.is_live(&c, &time));
    }

    #[test]
    fn registration_cap_enforced() {
        let time = MockTimeSource::new(0);
        let mut tracker = LivenessTracker::new();
        let c = client();
        tracker.record_probe(&c, &time);
        for _ in 0..MAX_REGISTRATIONS_PER_CLIENT {
            assert!(tracker.can_register(&c, &time));
            tracker.increment_registration(&c);
        }
        assert!(!tracker.can_register(&c, &time));
    }
}
