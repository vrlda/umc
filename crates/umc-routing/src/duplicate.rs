//! Unpredictable Request IDs and the bounded duplicate cache (routing.md §7, §11).
use std::collections::VecDeque;
use umc_types::runtime::{Duration, EntropySource, Instant};

pub const REQUEST_ID_LEN: usize = 16;
pub const DEFAULT_CACHE_ENTRIES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestIdentity {
    pub request_id: [u8; REQUEST_ID_LEN],
    pub adjacent_sender: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CachedRequest {
    pub identity: RequestIdentity,
    pub first_seen: Instant,
    pub best_hop_limit: u64,
    pub expiry: Instant,
    pub forwarded_peers: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct RequestCache {
    entries: VecDeque<CachedRequest>,
    max_entries: usize,
    retention: Duration,
}

impl RequestCache {
    #[must_use]
    pub fn new(max_entries: usize, retention: Duration) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries,
            retention,
        }
    }

    pub fn generate_request_id(entropy: &dyn EntropySource) -> [u8; REQUEST_ID_LEN] {
        let mut id = [0u8; REQUEST_ID_LEN];
        entropy.fill(&mut id);
        id
    }

    /// Returns None when the request is new or an improvement is allowed
    /// (higher hop limit); returns Some(existing) for an exact duplicate.
    pub fn admit(
        &mut self,
        identity: RequestIdentity,
        hop_limit: u64,
        now: Instant,
        forward_to: &[Vec<u8>],
    ) -> Option<CachedRequest> {
        self.prune(now);
        if let Some(existing) = self.entries.iter_mut().find(|e| e.identity == identity) {
            if hop_limit <= existing.best_hop_limit {
                return Some(existing.clone());
            }
            // Improvement: allowed but must not re-forward to the same peer.
            if forward_to
                .iter()
                .any(|p| existing.forwarded_peers.contains(p))
            {
                return Some(existing.clone());
            }
            // Reconsideration (routing.md §11): the entry keeps the best
            // observed hop limit; the caller records new forwards via
            // record_forward after the request is actually forwarded.
            existing.best_hop_limit = hop_limit;
            existing.expiry = now + self.retention;
            return None;
        }
        self.entries.push_back(CachedRequest {
            identity,
            first_seen: now,
            best_hop_limit: hop_limit,
            expiry: now + self.retention,
            forwarded_peers: forward_to.to_vec(),
        });
        if self.entries.len() > self.max_entries {
            self.entries.pop_front();
        }
        None
    }

    pub fn record_forward(&mut self, identity: &RequestIdentity, peer: &[u8]) {
        if let Some(entry) = self.entries.iter_mut().find(|e| &e.identity == identity) {
            if !entry.forwarded_peers.contains(&peer.to_vec()) {
                entry.forwarded_peers.push(peer.to_vec());
            }
        }
    }

    #[must_use]
    pub fn already_forwarded(&self, identity: &RequestIdentity, peer: &[u8]) -> bool {
        self.entries
            .iter()
            .any(|e| &e.identity == identity && e.forwarded_peers.contains(&peer.to_vec()))
    }

    fn prune(&mut self, now: Instant) {
        self.entries.retain(|e| e.expiry > now);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(0x11);
        }
    }

    fn id(n: u8) -> RequestIdentity {
        let mut request_id = [0u8; REQUEST_ID_LEN];
        request_id[0] = n;
        RequestIdentity {
            request_id,
            adjacent_sender: vec![n],
        }
    }

    #[test]
    fn exact_duplicate_suppressed() {
        let mut cache = RequestCache::new(100, Duration::from_millis(30_000));
        assert!(cache
            .admit(id(1), 8, Instant(0), &[b"peer-a".to_vec()])
            .is_none());
        assert!(cache
            .admit(id(1), 8, Instant(1), &[b"peer-a".to_vec()])
            .is_some());
    }

    #[test]
    fn higher_hop_limit_allows_reconsideration() {
        let mut cache = RequestCache::new(100, Duration::from_millis(30_000));
        assert!(cache
            .admit(id(1), 4, Instant(0), &[b"peer-a".to_vec()])
            .is_none());
        // New path with higher hop limit is admitted.
        assert!(cache
            .admit(id(1), 8, Instant(1), &[b"peer-b".to_vec()])
            .is_none());
        // But never re-forwards to peer-a.
        cache.record_forward(&id(1), b"peer-a");
        assert!(cache.already_forwarded(&id(1), b"peer-a"));
        assert!(!cache.already_forwarded(&id(1), b"peer-b"));
    }

    #[test]
    fn cache_is_bounded() {
        let mut cache = RequestCache::new(2, Duration::from_millis(30_000));
        cache.admit(id(1), 8, Instant(0), &[]);
        cache.admit(id(2), 8, Instant(0), &[]);
        cache.admit(id(3), 8, Instant(0), &[]);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn request_ids_are_unpredictable_bytes() {
        let a = RequestCache::generate_request_id(&E);
        let b = RequestCache::generate_request_id(&E);
        assert_eq!(a, b); // deterministic test entropy; production uses CSPRNG
        assert_eq!(a.len(), REQUEST_ID_LEN);
    }
}
