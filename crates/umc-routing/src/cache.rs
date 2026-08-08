//! Bounded expiring route cache (routing.md §24).
use crate::types::{RouteKey, RouteRecord, RouteState};
use std::collections::HashMap;
use umc_types::runtime::{Duration, Instant};

pub const DEFAULT_CACHE_TARGET: usize = 3;
pub const DEFAULT_CACHE_MAX: usize = 8;
pub const DEFAULT_MAX_ROUTE_LIFETIME_MS: u64 = 10 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct RouteCache {
    by_key: HashMap<RouteKey, Vec<RouteRecord>>,
    max_per_key: usize,
    max_lifetime: Duration,
}

impl RouteCache {
    #[must_use]
    pub fn new(max_per_key: usize, max_lifetime: Duration) -> Self {
        Self {
            by_key: HashMap::new(),
            max_per_key,
            max_lifetime,
        }
    }

    pub fn insert(&mut self, mut record: RouteRecord, now: Instant) {
        record.cap_expiry(now + self.max_lifetime);
        let key = record.key.clone();
        let entries = self.by_key.entry(key).or_default();
        entries.retain(|r| !r.is_expired(now) && r.next_hop != record.next_hop);
        entries.push(record);
        // Eviction order (routing.md §24.4): expired, failed, redundant, least useful.
        entries.sort_by_key(|r| match r.state {
            RouteState::Usable => 0,
            RouteState::Candidate => 1,
            RouteState::Probing => 2,
            RouteState::Degraded => 3,
            RouteState::Failed => 4,
            _ => 5,
        });
        entries.truncate(self.max_per_key);
    }

    #[must_use]
    pub fn candidates(&self, key: &RouteKey, now: Instant) -> Vec<RouteRecord> {
        self.by_key
            .get(key)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|r| !r.is_expired(now))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Removes every cached record for `key` (routing.md §24
    /// invalidation): a control-surface `InvalidateRoute` drops the entry
    /// so the forwarder cannot pick it again.
    pub fn remove(&mut self, key: &RouteKey) {
        self.by_key.remove(key);
    }

    pub fn evict_expired(&mut self, now: Instant) {
        self.by_key.retain(|_, entries| {
            entries.retain(|r| !r.is_expired(now));
            !entries.is_empty()
        });
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_key.values().map(Vec::len).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> RouteKey {
        RouteKey {
            destination_profile: 0,
            destination_hash: [n; 32],
            scope: crate::types::RouteScope::General,
            policy_class: 0,
        }
    }

    fn record(key: &RouteKey, hop: &str, now: Instant) -> RouteRecord {
        RouteRecord {
            key: key.clone(),
            state: RouteState::Usable,
            next_hop: hop.into(),
            metadata: vec![],
            source_peer: vec![],
            created_at: now,
            expires_at: now + Duration::from_millis(600_000),
            last_success: None,
            last_failure: None,
            failure_count: 0,
            scope: crate::types::RouteScope::General,
        }
    }

    #[test]
    fn insert_and_candidates() {
        let now = Instant(0);
        let mut cache = RouteCache::new(
            DEFAULT_CACHE_MAX,
            Duration::from_millis(DEFAULT_MAX_ROUTE_LIFETIME_MS),
        );
        cache.insert(record(&key(1), "hop-a", now), now);
        cache.insert(record(&key(1), "hop-b", now), now);
        assert_eq!(cache.candidates(&key(1), now).len(), 2);
        assert_eq!(cache.candidates(&key(2), now).len(), 0);
    }

    #[test]
    fn per_key_bound_enforced() {
        let now = Instant(0);
        let mut cache = RouteCache::new(3, Duration::from_millis(DEFAULT_MAX_ROUTE_LIFETIME_MS));
        for i in 0..5 {
            cache.insert(record(&key(1), &format!("hop-{i}"), now), now);
        }
        assert_eq!(cache.candidates(&key(1), now).len(), 3);
    }

    #[test]
    fn expired_entries_evicted() {
        let now = Instant(0);
        let mut cache = RouteCache::new(
            DEFAULT_CACHE_MAX,
            Duration::from_millis(DEFAULT_MAX_ROUTE_LIFETIME_MS),
        );
        cache.insert(record(&key(1), "hop-a", now), now);
        cache.evict_expired(now + Duration::from_millis(DEFAULT_MAX_ROUTE_LIFETIME_MS + 1));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn remove_drops_only_the_matching_key() {
        let now = Instant(0);
        let mut cache = RouteCache::new(
            DEFAULT_CACHE_MAX,
            Duration::from_millis(DEFAULT_MAX_ROUTE_LIFETIME_MS),
        );
        cache.insert(record(&key(1), "hop-a", now), now);
        cache.insert(record(&key(2), "hop-b", now), now);
        cache.remove(&key(1));
        assert_eq!(cache.candidates(&key(1), now).len(), 0);
        assert_eq!(cache.candidates(&key(2), now).len(), 1);
        // Removing an unknown key is a no-op.
        cache.remove(&key(3));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_lifetime_capped_at_max() {
        let now = Instant(0);
        let mut cache = RouteCache::new(DEFAULT_CACHE_MAX, Duration::from_millis(600_000));
        let mut r = record(&key(1), "hop", now);
        r.expires_at = now + Duration::from_millis(3_600_000); // evidence says 1h
        cache.insert(r, now);
        // Cache caps at 10 minutes.
        let candidates = cache.candidates(&key(1), now + Duration::from_millis(600_001));
        assert!(candidates.is_empty());
    }
}
