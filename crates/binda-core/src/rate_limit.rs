//! A per-key token-bucket rate limiter.
//!
//! This exists instead of a hard cap on any single message's size: a
//! large-but-legitimate message (an enormous zalgo domain name, say)
//! shouldn't be penalized just for being big, but a sender flooding a
//! listener with many messages — of any size — should be throttled. The
//! limiter tracks a token bucket per key (typically a peer's socket
//! address) and refuses a request once that key's bucket runs dry, and
//! recovers on its own as tokens refill over time.
//!
//! Because a key here is usually a UDP source address, and UDP source
//! addresses are trivially spoofable, an attacker can still make this
//! limiter track a huge number of distinct (mostly bogus) keys. To keep
//! the limiter's own memory bounded regardless, it caps how many keys it
//! will track at once and evicts the least-recently-used one to make room
//! for a new one — so total memory stays O(`max_tracked_keys`) no matter
//! how the traffic is shaped.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// A token-bucket rate limiter keyed by `K` (e.g. a peer's `SocketAddr`).
pub struct RateLimiter<K> {
    capacity: f64,
    refill_per_sec: f64,
    max_tracked_keys: usize,
    buckets: HashMap<K, Bucket>,
}

impl<K: Eq + Hash + Clone> RateLimiter<K> {
    /// `capacity` is the burst size (max tokens a bucket can hold);
    /// `refill_per_sec` is how many tokens per second it regains;
    /// `max_tracked_keys` bounds how many distinct keys are remembered at
    /// once, evicting the least-recently-seen key to make room.
    pub fn new(capacity: u32, refill_per_sec: f64, max_tracked_keys: usize) -> Self {
        Self {
            capacity: capacity as f64,
            refill_per_sec,
            max_tracked_keys,
            buckets: HashMap::new(),
        }
    }

    /// Whether a request from `key` should be allowed right now. Consumes
    /// one token from `key`'s bucket if so.
    pub fn allow(&mut self, key: K) -> bool {
        self.allow_at(key, Instant::now())
    }

    /// [`Self::allow`] with an explicit clock reading, for deterministic
    /// tests.
    pub fn allow_at(&mut self, key: K, now: Instant) -> bool {
        if !self.buckets.contains_key(&key) && self.buckets.len() >= self.max_tracked_keys {
            self.evict_least_recently_seen();
        }

        let bucket = self.buckets.entry(key).or_insert(Bucket {
            tokens: self.capacity,
            last_refill: now,
        });

        let elapsed = now.saturating_duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop every key not seen within `max_age`, reclaiming memory from
    /// peers that have gone quiet. Call periodically from a maintenance
    /// task; not required for correctness (eviction on insert already
    /// bounds memory), just keeps the tracked set closer to "currently
    /// active."
    pub fn prune_older_than(&mut self, max_age: Duration, now: Instant) {
        self.buckets
            .retain(|_, bucket| now.saturating_duration_since(bucket.last_refill) < max_age);
    }

    fn evict_least_recently_seen(&mut self) {
        if let Some(oldest_key) = self
            .buckets
            .iter()
            .min_by_key(|(_, bucket)| bucket.last_refill)
            .map(|(key, _)| key.clone())
        {
            self.buckets.remove(&oldest_key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_bursts_up_to_capacity_then_throttles() {
        let mut limiter = RateLimiter::new(3, 1.0, 100);
        let now = Instant::now();
        assert!(limiter.allow_at("a", now));
        assert!(limiter.allow_at("a", now));
        assert!(limiter.allow_at("a", now));
        assert!(!limiter.allow_at("a", now));
    }

    #[test]
    fn refills_over_time() {
        let mut limiter = RateLimiter::new(1, 1.0, 100);
        let t0 = Instant::now();
        assert!(limiter.allow_at("a", t0));
        assert!(!limiter.allow_at("a", t0));
        let t1 = t0 + Duration::from_millis(1100);
        assert!(limiter.allow_at("a", t1));
    }

    #[test]
    fn keys_are_independent() {
        let mut limiter = RateLimiter::new(1, 1.0, 100);
        let now = Instant::now();
        assert!(limiter.allow_at("a", now));
        assert!(limiter.allow_at("b", now));
        assert!(!limiter.allow_at("a", now));
        assert!(!limiter.allow_at("b", now));
    }

    #[test]
    fn evicts_least_recently_seen_key_when_over_capacity() {
        let mut limiter = RateLimiter::new(1, 1.0, 2);
        let t0 = Instant::now();
        limiter.allow_at("a", t0);
        limiter.allow_at("b", t0 + Duration::from_millis(10));
        // "a" is now the least-recently-seen key; adding "c" should evict
        // it rather than growing past max_tracked_keys.
        limiter.allow_at("c", t0 + Duration::from_millis(20));
        assert_eq!(limiter.buckets.len(), 2);
        assert!(!limiter.buckets.contains_key("a"));
    }

    #[test]
    fn prune_removes_stale_keys() {
        let mut limiter = RateLimiter::new(1, 1.0, 100);
        let t0 = Instant::now();
        limiter.allow_at("a", t0);
        limiter.prune_older_than(Duration::from_secs(60), t0 + Duration::from_secs(120));
        assert!(limiter.buckets.is_empty());
    }
}
