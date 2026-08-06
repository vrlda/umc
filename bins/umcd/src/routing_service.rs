//! Routing service (routing.md §6-24): request admission, reverse-path
//! tracking, and the bounded route cache, wired into the runtime state.
//! Persistence lands in Phase 12; all state is process-local for now.
use umc_routing::cache::{RouteCache, DEFAULT_CACHE_MAX, DEFAULT_MAX_ROUTE_LIFETIME_MS};
use umc_routing::duplicate::{RequestCache, DEFAULT_CACHE_ENTRIES};
use umc_routing::request::{admit_request, Admission, AdmissionError, RequestPolicy};
use umc_routing::reverse::ReverseState;
use umc_routing::types::{RouteKey, RouteRecord, RouteScope, RouteState};
use umc_types::runtime::{Duration, Instant};

/// Retention for reverse-path state (routing.md §17).
pub const REVERSE_RETENTION_MS: u64 = 30_000;

/// Process-local routing state.
#[derive(Debug)]
pub struct RoutingService {
    pub cache: RouteCache,
    pub reverse: ReverseState,
    pub duplicate: RequestCache,
    pub request_policy: RequestPolicy,
}

#[allow(clippy::too_many_arguments)] // admit_route_request() takes the full ROUTE_REQUEST header
impl RoutingService {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: RouteCache::new(
                DEFAULT_CACHE_MAX,
                Duration::from_millis(DEFAULT_MAX_ROUTE_LIFETIME_MS),
            ),
            reverse: ReverseState::new(Duration::from_millis(REVERSE_RETENTION_MS)),
            duplicate: RequestCache::new(DEFAULT_CACHE_ENTRIES, Duration::from_millis(30_000)),
            request_policy: RequestPolicy::default(),
        }
    }

    /// Validate and admit a `ROUTE_REQUEST` (routing.md §10); an admitted
    /// request pins its reverse path so responses route back to the sender.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when a cheap admission check fails.
    pub fn admit_route_request(
        &mut self,
        request_id: &[u8; 16],
        adjacent_sender: &[u8],
        flags: u8,
        hop_limit: u64,
        lifetime_ms: u64,
        candidates: &[Vec<u8>],
        now: Instant,
    ) -> Result<Admission, AdmissionError> {
        let admission = admit_request(
            request_id,
            adjacent_sender,
            flags,
            hop_limit,
            lifetime_ms,
            candidates,
            &self.request_policy,
            &mut self.duplicate,
            now,
        )?;
        if matches!(admission, Admission::Admit { .. }) {
            self.reverse
                .create(*request_id, adjacent_sender.to_vec(), now);
        }
        Ok(admission)
    }

    /// Record a route response: insert the learned route into the cache and
    /// route the response back toward the requesting upstream peer
    /// (routing.md §17-18). Returns the record when a response may travel.
    #[must_use]
    pub fn record_route_response(
        &mut self,
        key: RouteKey,
        request_id: [u8; 16],
        next_hop: String,
        lifetime_ms: u64,
        now: Instant,
    ) -> RouteRecord {
        let upstream = self.reverse.route_response(&request_id, now);
        let record = RouteRecord {
            key,
            state: RouteState::Usable,
            next_hop,
            metadata: vec![],
            source_peer: upstream.unwrap_or_default(),
            created_at: now,
            expires_at: now + Duration::from_millis(lifetime_ms),
            last_success: Some(now),
            last_failure: None,
            failure_count: 0,
            scope: RouteScope::General,
        };
        self.cache.insert(record.clone(), now);
        record
    }

    /// Best cached route for a key (routing.md §24).
    // find_route is test-only until a forwarder consults the cache before
    // probing; the session loop currently records responses only.
    #[allow(dead_code)]
    #[must_use]
    pub fn find_route(&self, key: &RouteKey, now: Instant) -> Option<RouteRecord> {
        self.cache.candidates(key, now).into_iter().next()
    }
}

impl Default for RoutingService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> RouteKey {
        RouteKey {
            destination_profile: 0,
            destination_hash: [n; 32],
            scope: RouteScope::General,
            policy_class: 0,
        }
    }

    #[test]
    fn admit_record_find_cycle() {
        let mut routing = RoutingService::new();
        let rid = [1u8; 16];
        let peers = vec![b"peer-a".to_vec(), b"peer-b".to_vec()];
        assert!(matches!(
            routing
                .admit_route_request(&rid, b"upstream", 0, 8, 30_000, &peers, Instant(0))
                .unwrap(),
            Admission::Admit { .. }
        ));
        let _ = routing.record_route_response(key(1), rid, "hop-a".into(), 600_000, Instant(1));
        let found = routing.find_route(&key(1), Instant(1)).expect("route");
        assert_eq!(found.next_hop, "hop-a");
        assert_eq!(found.state, RouteState::Usable);
        assert!(routing.find_route(&key(2), Instant(1)).is_none());
    }

    #[test]
    fn duplicate_request_suppressed() {
        let mut routing = RoutingService::new();
        let rid = [2u8; 16];
        let peers = vec![b"peer-a".to_vec()];
        routing
            .admit_route_request(&rid, b"upstream", 0, 8, 30_000, &peers, Instant(0))
            .unwrap();
        // Same request id + sender again: suppressed, not re-forwarded.
        assert_eq!(
            routing
                .admit_route_request(&rid, b"upstream", 0, 8, 30_000, &peers, Instant(1))
                .unwrap(),
            Admission::Suppress
        );
    }

    #[test]
    fn zero_hop_limit_rejected() {
        let mut routing = RoutingService::new();
        assert_eq!(
            routing.admit_route_request(&[3u8; 16], b"u", 0, 0, 30_000, &[], Instant(0)),
            Err(AdmissionError::HopLimitZero)
        );
    }

    #[test]
    fn response_routes_back_to_upstream() {
        let mut routing = RoutingService::new();
        let rid = [4u8; 16];
        routing
            .admit_route_request(&rid, b"upstream", 0, 8, 30_000, &[], Instant(0))
            .unwrap();
        let record =
            routing.record_route_response(key(3), rid, "hop-x".into(), 600_000, Instant(1));
        assert_eq!(record.source_peer, b"upstream");
    }
}
