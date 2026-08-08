//! Routing service (routing.md §6-24): request admission, reverse-path
//! tracking, and the bounded route cache, wired into the runtime state.
//! Learned routes persist to the node database (storage.md §15); after a
//! restart the cache restores every persisted route as `CANDIDATE` (§15.2)
//! until a fresh `ROUTE_RESPONSE` revalidates it as usable.
use std::sync::Arc;
use umc_routing::cache::{RouteCache, DEFAULT_CACHE_MAX, DEFAULT_MAX_ROUTE_LIFETIME_MS};
use umc_routing::duplicate::{RequestCache, DEFAULT_CACHE_ENTRIES};
use umc_routing::request::{admit_request, Admission, AdmissionError, RequestPolicy};
use umc_routing::reverse::ReverseState;
use umc_routing::sybil::{SybilGroup, SybilGuard};
use umc_routing::types::{RouteKey, RouteRecord, RouteScope, RouteState};
use umc_storage::records;
use umc_storage::sqlite::SqliteStore;
use umc_storage::store::Store;
use umc_types::runtime::{Duration, Instant};

/// Retention for reverse-path state (routing.md §17).
pub const REVERSE_RETENTION_MS: u64 = 30_000;

/// Process-local routing state, optionally bound to the node database for
/// route persistence.
pub struct RoutingService {
    pub cache: RouteCache,
    pub reverse: ReverseState,
    pub duplicate: RequestCache,
    pub sybil: SybilGuard,
    pub request_policy: RequestPolicy,
    store: Option<Arc<SqliteStore>>,
}

impl std::fmt::Debug for RoutingService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingService")
            .field("cache", &self.cache)
            .field("reverse", &self.reverse)
            .field("duplicate", &self.duplicate)
            .field("sybil", &self.sybil)
            .field("request_policy", &self.request_policy)
            .field("store_attached", &self.store.is_some())
            .finish()
    }
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
            sybil: SybilGuard::default(),
            request_policy: RequestPolicy::default(),
            store: None,
        }
    }

    /// Attaches the node database so learned routes persist (storage.md §15).
    pub fn attach_store(&mut self, store: Arc<SqliteStore>) {
        self.store = Some(store);
    }

    /// Loads persisted route snapshots into the cache as `CANDIDATE` entries
    /// (storage.md §15.2): a restart never trusts persisted routes — they
    /// become usable only when a fresh `ROUTE_RESPONSE` revalidates them.
    /// One snapshot per key hash survives (multi-hop revalidation is the
    /// multi-hop routing phase's work).
    pub fn restore(&mut self, store: &dyn Store, now: Instant) {
        let snapshots = match records::list_routes(store) {
            Ok(snapshots) => snapshots,
            Err(e) => {
                log::error!("[routing] failed to restore persisted routes: {e:?}");
                return;
            }
        };
        for snapshot in snapshots {
            // Persisted routes already past their evidence lifetime are
            // dropped at restore (storage.md §15.2): revalidation cannot
            // resurrect them.
            if Instant(snapshot.learned_at_ms) + Duration::from_millis(snapshot.lifetime_ms) <= now
            {
                continue;
            }
            let Ok(hash) = <[u8; 32]>::try_from(snapshot.key_hash) else {
                log::warn!("[routing] skipping persisted route with a non-32-byte key hash");
                continue;
            };
            let Some(scope) = scope_from_u8(snapshot.scope) else {
                log::warn!(
                    "[routing] skipping persisted route with unknown scope {}",
                    snapshot.scope
                );
                continue;
            };
            let created_at = Instant(snapshot.learned_at_ms);
            let record = RouteRecord {
                key: RouteKey {
                    destination_profile: 0,
                    destination_hash: hash,
                    scope,
                    policy_class: 0,
                },
                state: RouteState::Candidate,
                next_hop: String::from_utf8_lossy(&snapshot.next_hop).into_owned(),
                metadata: vec![],
                source_peer: vec![],
                created_at,
                expires_at: created_at + Duration::from_millis(snapshot.lifetime_ms),
                last_success: None,
                last_failure: None,
                failure_count: 0,
                scope,
            };
            self.cache.insert(record, now);
        }
    }

    /// Persists a route snapshot (storage.md §15.1). Best-effort: the cache
    /// stays authoritative, failures are logged.
    fn persist_route(&self, record: &RouteRecord) {
        let Some(store) = &self.store else {
            return;
        };
        let snapshot = records::RouteRecordSnapshot {
            key_hash: record.key.destination_hash.to_vec(),
            next_hop: record.next_hop.as_bytes().to_vec(),
            lifetime_ms: record
                .expires_at
                .duration_since(record.created_at)
                .as_millis(),
            learned_at_ms: record.created_at.0,
            scope: scope_to_u8(record.scope),
        };
        if let Err(e) = records::save_route(store.as_ref(), &snapshot) {
            log::error!("[routing] failed to persist route: {e:?}");
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
            let group = SybilGroup::from_requester(adjacent_sender, &[]);
            if !self.sybil.admit(group, now) {
                return Err(AdmissionError::RateLimited);
            }
            self.reverse
                .create(*request_id, adjacent_sender.to_vec(), now);
        }
        Ok(admission)
    }

    /// Record a route response: insert the learned route into the cache,
    /// persist it, and route the response back toward the requesting
    /// upstream peer (routing.md §17-18). Returns the record when a
    /// response may travel.
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
        self.persist_route(&record);
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

/// Stable route-scope encoding for persistence. Must match `RouteScope`'s
/// declared variant order (umc-routing `types.rs`).
fn scope_to_u8(scope: RouteScope) -> u8 {
    match scope {
        RouteScope::LinkLocal => 0,
        RouteScope::LocalMesh => 1,
        RouteScope::Introduced => 2,
        RouteScope::General => 3,
    }
}

fn scope_from_u8(scope: u8) -> Option<RouteScope> {
    match scope {
        0 => Some(RouteScope::LinkLocal),
        1 => Some(RouteScope::LocalMesh),
        2 => Some(RouteScope::Introduced),
        3 => Some(RouteScope::General),
        _ => None,
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
    fn sybil_group_budget_limits_shared_source_prefix() {
        let mut routing = RoutingService::new();
        let peers = vec![b"peer-a".to_vec()];
        for request_number in 0..umc_routing::sybil::REQUESTS_PER_GROUP_PER_MINUTE {
            let request_tag = u8::try_from(request_number).expect("test budget fits in u8");
            let mut request_id = [0u8; 16];
            request_id[0] = request_tag;
            let requester = [1, 2, 3, 4, request_tag];
            assert!(matches!(
                routing.admit_route_request(
                    &request_id,
                    &requester,
                    0,
                    8,
                    30_000,
                    &peers,
                    Instant(0),
                ),
                Ok(Admission::Admit { .. })
            ));
        }
        let mut request_id = [0u8; 16];
        request_id[0] = 99;
        assert_eq!(
            routing.admit_route_request(
                &request_id,
                &[1, 2, 3, 4, 99],
                0,
                8,
                30_000,
                &peers,
                Instant(0),
            ),
            Err(AdmissionError::RateLimited)
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

    fn temp_store() -> Arc<umc_storage::sqlite::SqliteStore> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("umcd-routing-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("routing-{c}.db"));
        Arc::new(umc_storage::sqlite::SqliteStore::open(&path).unwrap())
    }

    #[test]
    fn routes_persist_and_restore_as_candidates() {
        let store = temp_store();
        let mut routing = RoutingService::new();
        routing.attach_store(store.clone());
        let rid = [5u8; 16];
        routing
            .admit_route_request(
                &rid,
                b"upstream",
                0,
                8,
                30_000,
                &[b"peer-a".to_vec()],
                Instant(0),
            )
            .unwrap();
        let _ = routing.record_route_response(key(7), rid, "hop-a".into(), 600_000, Instant(1));
        // A freshly learned route is usable and persisted to the store.
        assert_eq!(
            routing.find_route(&key(7), Instant(1)).unwrap().state,
            RouteState::Usable
        );
        let persisted = umc_storage::records::list_routes(store.as_ref()).unwrap();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].next_hop, b"hop-a");
        drop(routing);

        // A new service over the same store restores the route, but only as
        // a CANDIDATE (storage.md §15.2): it must not be used until a fresh
        // ROUTE_RESPONSE revalidates it.
        let mut restarted = RoutingService::new();
        restarted.restore(store.as_ref(), Instant(1000));
        let found = restarted
            .find_route(&key(7), Instant(1000))
            .expect("restored route");
        assert_eq!(found.next_hop, "hop-a");
        assert_eq!(found.state, RouteState::Candidate);
    }
}
