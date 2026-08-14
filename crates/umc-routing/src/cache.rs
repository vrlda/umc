//! Bounded expiring route cache (routing.md §24).
use crate::types::{RouteKey, RouteRecord, RouteState};
use std::collections::HashMap;
use umc_types::runtime::{Duration, Instant};

pub const DEFAULT_CACHE_TARGET: usize = 3;
pub const DEFAULT_CACHE_MAX: usize = 8;
pub const DEFAULT_MAX_ROUTE_LIFETIME_MS: u64 = 10 * 60 * 1000;

fn metadata_value<'a>(metadata: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    metadata
        .split(|byte| *byte == 0)
        .find_map(|field| field.strip_prefix(key))
}

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

    /// Return eligible candidates in stable usefulness order while retaining
    /// distinct first hops. `insert` already deduplicates a first hop, so this
    /// is the bounded route-diversity selection primitive used by live
    /// forwarding (routing.md §§23-26).
    #[must_use]
    pub fn ranked_candidates(&self, key: &RouteKey, now: Instant) -> Vec<RouteRecord> {
        let mut candidates = self.candidates(key, now);
        candidates.sort_by_key(|record| {
            (
                !matches!(record.state, RouteState::Usable),
                record.failure_count,
                record.last_failure.map_or(0, |failure| failure.0),
                record.next_hop.clone(),
            )
        });
        candidates
    }

    /// Select a bounded failover set that prefers independent authenticated
    /// failure domains before adding a second route from an already-used
    /// domain. The domain is carried as a NUL-delimited `domain=` metadata
    /// field; missing evidence is deliberately treated as one shared unknown
    /// domain rather than as proof of diversity.
    #[must_use]
    pub fn diverse_candidates(
        &self,
        key: &RouteKey,
        now: Instant,
        maximum: usize,
    ) -> Vec<RouteRecord> {
        let maximum = maximum.min(self.max_per_key);
        if maximum == 0 {
            return Vec::new();
        }
        let ranked = self.ranked_candidates(key, now);
        let mut selected = Vec::with_capacity(maximum);
        let mut domains = Vec::<Vec<u8>>::new();
        for candidate in &ranked {
            if selected.len() == maximum {
                break;
            }
            let domain = metadata_value(&candidate.metadata, b"domain=")
                .map_or_else(|| b"unknown".to_vec(), ToOwned::to_owned);
            if domains.contains(&domain) {
                continue;
            }
            domains.push(domain);
            selected.push(candidate.clone());
        }
        if selected.len() < maximum {
            for candidate in ranked {
                if selected.len() == maximum {
                    break;
                }
                if selected
                    .iter()
                    .any(|chosen| chosen.next_hop == candidate.next_hop)
                {
                    continue;
                }
                selected.push(candidate);
            }
        }
        selected
    }

    /// Record an observed route failure without deleting the evidence. The
    /// candidate is temporarily marked `FAILED`; a later fresh response may
    /// replace it through the normal bounded insert path.
    pub fn mark_failure(&mut self, key: &RouteKey, next_hop: &str, now: Instant) -> bool {
        let Some(entries) = self.by_key.get_mut(key) else {
            return false;
        };
        let Some(record) = entries
            .iter_mut()
            .find(|record| record.next_hop == next_hop)
        else {
            return false;
        };
        record.mark(RouteState::Failed, now);
        true
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
            carrier_type: None,
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

    fn record_with_domain(key: &RouteKey, hop: &str, domain: &str, now: Instant) -> RouteRecord {
        let mut record = record(key, hop, now);
        record.metadata = format!("domain={domain}").into_bytes();
        record
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

    #[test]
    fn ranked_candidates_preserve_first_hop_diversity_and_failures() {
        let now = Instant(0);
        let mut cache = RouteCache::new(3, Duration::from_millis(DEFAULT_MAX_ROUTE_LIFETIME_MS));
        let route_key = key(7);
        cache.insert(record(&route_key, "hop-a", now), now);
        cache.insert(record(&route_key, "hop-b", now), now);
        cache.mark_failure(&route_key, "hop-a", now + Duration::from_millis(1));
        let ranked = cache.ranked_candidates(&route_key, now + Duration::from_millis(1));
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].next_hop, "hop-b");
        assert_eq!(ranked[1].state, RouteState::Failed);
    }

    #[test]
    fn diverse_candidates_prefer_distinct_failure_domains() {
        let now = Instant(0);
        let mut cache = RouteCache::new(4, Duration::from_millis(DEFAULT_MAX_ROUTE_LIFETIME_MS));
        let route_key = key(8);
        cache.insert(
            record_with_domain(&route_key, "hop-a", "domain-a", now),
            now,
        );
        cache.insert(
            record_with_domain(&route_key, "hop-b", "domain-a", now),
            now,
        );
        cache.insert(
            record_with_domain(&route_key, "hop-c", "domain-b", now),
            now,
        );
        let selected = cache.diverse_candidates(&route_key, now, 2);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].next_hop, "hop-a");
        assert_eq!(selected[1].next_hop, "hop-c");
    }
}
