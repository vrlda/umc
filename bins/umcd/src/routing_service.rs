//! Routing service (routing.md §6-24): request admission, reverse-path
//! tracking, and the bounded route cache, wired into the runtime state.
//! Learned routes persist to the node database (storage.md §15); after a
//! restart the cache restores every persisted route as `CANDIDATE` (§15.2)
//! until a fresh `ROUTE_RESPONSE` revalidates it as usable.
use std::{collections::HashMap, sync::Arc};
use umc_routing::cache::{RouteCache, DEFAULT_CACHE_MAX, DEFAULT_MAX_ROUTE_LIFETIME_MS};
use umc_routing::duplicate::{RequestCache, DEFAULT_CACHE_ENTRIES};
use umc_routing::paths::{PathBuilder, PathError, PathHop, PathPolicy, RoutePath};
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
const MAX_REQUEST_CONTEXTS: usize = 1_024;

/// Local context needed to bind a response to the destination and policy of
/// the request that produced it. The wire response carries only the next hop;
/// keeping this bounded context prevents cache entries from being keyed by
/// that hop instead of the requested destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRequestContext {
    pub destination_hash: [u8; 32],
    pub scope: RouteScope,
    pub require_private_response: bool,
    pub max_hops: u64,
    pub max_relays: usize,
    pub allow_relay: bool,
    pub allow_store_forward: bool,
    expires_at: Instant,
}

/// Process-local routing state, optionally bound to the node database for
/// route persistence.
pub struct RoutingService {
    pub cache: RouteCache,
    pub reverse: ReverseState,
    pub duplicate: RequestCache,
    pub sybil: SybilGuard,
    pub request_policy: RequestPolicy,
    request_contexts: HashMap<[u8; 16], RouteRequestContext>,
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
            .field("request_contexts", &self.request_contexts.len())
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
            request_contexts: HashMap::new(),
            store: None,
        }
    }

    /// Remember the bounded destination/scope context for a live route
    /// request. Route responses do not repeat the destination hint, so the
    /// context is required to key learned routes correctly.
    #[allow(dead_code)] // retained as the default-policy convenience API
    pub fn remember_route_request(
        &mut self,
        request_id: [u8; 16],
        destination_hash: [u8; 32],
        scope: RouteScope,
        now: Instant,
    ) {
        self.remember_route_request_with_constraints(
            request_id,
            destination_hash,
            scope,
            false,
            umc_routing::types::DEFAULT_HOP_LIMIT,
            umc_routing::paths::DEFAULT_MAX_RELAYS,
            true,
            false,
            now,
        );
    }

    /// Remember a route request together with its privacy requirement. The
    /// flag is bounded reverse-state policy, not application-visible topology.
    #[allow(dead_code)]
    pub fn remember_route_request_with_policy(
        &mut self,
        request_id: [u8; 16],
        destination_hash: [u8; 32],
        scope: RouteScope,
        require_private_response: bool,
        now: Instant,
    ) {
        self.remember_route_request_with_constraints(
            request_id,
            destination_hash,
            scope,
            require_private_response,
            umc_routing::types::DEFAULT_HOP_LIMIT,
            umc_routing::paths::DEFAULT_MAX_RELAYS,
            true,
            false,
            now,
        );
    }

    /// Remember route construction constraints alongside the destination
    /// binding. Route responses carry only path metadata, so the requester
    /// needs the original hop/relay policy to validate that metadata before
    /// caching or handing the candidate to session setup.
    #[allow(clippy::too_many_arguments)]
    pub fn remember_route_request_with_constraints(
        &mut self,
        request_id: [u8; 16],
        destination_hash: [u8; 32],
        scope: RouteScope,
        require_private_response: bool,
        max_hops: u64,
        max_relays: usize,
        allow_relay: bool,
        allow_store_forward: bool,
        now: Instant,
    ) {
        self.prune_request_contexts(now);
        if self.request_contexts.len() >= MAX_REQUEST_CONTEXTS {
            if let Some(oldest) = self
                .request_contexts
                .iter()
                .min_by_key(|(_, context)| context.expires_at)
                .map(|(request_id, _)| *request_id)
            {
                self.request_contexts.remove(&oldest);
            }
        }
        self.request_contexts.insert(
            request_id,
            RouteRequestContext {
                destination_hash,
                scope,
                require_private_response,
                max_hops: max_hops.clamp(1, umc_routing::types::MAX_HOP_LIMIT),
                max_relays: max_relays.min(umc_routing::paths::MAX_PATH_HOPS),
                allow_relay,
                allow_store_forward,
                expires_at: now + Duration::from_millis(REVERSE_RETENTION_MS),
            },
        );
    }

    /// Return request context while it remains within the reverse-state
    /// retention window.
    pub fn route_context(
        &mut self,
        request_id: &[u8; 16],
        now: Instant,
    ) -> Option<RouteRequestContext> {
        self.prune_request_contexts(now);
        self.request_contexts.get(request_id).cloned()
    }

    fn prune_request_contexts(&mut self, now: Instant) {
        self.request_contexts
            .retain(|_, context| context.expires_at > now);
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
                carrier_type: snapshot.carrier_type,
                metadata: snapshot.metadata,
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
            carrier_type: record.carrier_type.clone(),
            lifetime_ms: record
                .expires_at
                .duration_since(record.created_at)
                .as_millis(),
            learned_at_ms: record.created_at.0,
            scope: scope_to_u8(record.scope),
            metadata: record.metadata.clone(),
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
    #[allow(dead_code)]
    pub fn record_route_response(
        &mut self,
        key: RouteKey,
        request_id: [u8; 16],
        next_hop: String,
        lifetime_ms: u64,
        now: Instant,
    ) -> RouteRecord {
        let upstream = self.reverse.route_response(&request_id, now);
        self.record_route_response_from_upstream(key, next_hop, lifetime_ms, now, upstream)
    }

    /// Record a response after the caller has already validated and consumed
    /// reverse state (including response sequence checks).
    #[must_use]
    pub fn record_route_response_from_upstream(
        &mut self,
        key: RouteKey,
        next_hop: String,
        lifetime_ms: u64,
        now: Instant,
        upstream: Option<Vec<u8>>,
    ) -> RouteRecord {
        self.record_route_response_with_metadata(
            key,
            next_hop,
            lifetime_ms,
            now,
            upstream,
            Vec::new(),
        )
    }

    /// Records a route response while retaining its bounded policy metadata.
    /// Callers should pass metadata only after the response's authentication
    /// and branch validity have been checked; hard route constraints fail
    /// closed when this evidence is absent.
    #[must_use]
    pub fn record_route_response_with_metadata(
        &mut self,
        key: RouteKey,
        next_hop: String,
        lifetime_ms: u64,
        now: Instant,
        upstream: Option<Vec<u8>>,
        metadata: Vec<u8>,
    ) -> RouteRecord {
        self.record_route_response_with_evidence(
            key,
            next_hop,
            lifetime_ms,
            now,
            upstream,
            metadata,
            None,
        )
    }

    /// Records a response with authenticated adjacent carrier evidence.
    #[must_use]
    pub fn record_route_response_with_evidence(
        &mut self,
        key: RouteKey,
        next_hop: String,
        lifetime_ms: u64,
        now: Instant,
        upstream: Option<Vec<u8>>,
        metadata: Vec<u8>,
        carrier_type: Option<String>,
    ) -> RouteRecord {
        let scope = key.scope;
        let record = RouteRecord {
            key,
            state: RouteState::Usable,
            next_hop,
            carrier_type,
            metadata,
            source_peer: upstream.unwrap_or_default(),
            created_at: now,
            expires_at: now + Duration::from_millis(lifetime_ms),
            last_success: Some(now),
            last_failure: None,
            failure_count: 0,
            scope,
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
        self.cache.ranked_candidates(key, now).into_iter().next()
    }

    /// Return bounded, failure-aware route alternatives for live forwarding.
    /// Candidates remain partitioned by the full route key; no metadata from
    /// another destination or policy class is merged.
    #[allow(dead_code)]
    #[must_use]
    pub fn route_candidates(&self, key: &RouteKey, now: Instant) -> Vec<RouteRecord> {
        self.cache.ranked_candidates(key, now)
    }

    /// Return a bounded topology-aware failover set. Independent authenticated
    /// failure domains are preferred before a second candidate from a shared
    /// domain, while the route key and all hard policy evidence remain
    /// unchanged.
    #[must_use]
    pub fn diverse_route_candidates(
        &self,
        key: &RouteKey,
        now: Instant,
        maximum: usize,
    ) -> Vec<RouteRecord> {
        self.cache.diverse_candidates(key, now, maximum)
    }

    /// Record a failed forwarding attempt while retaining the route evidence
    /// for diagnostics and later replacement by a fresh response.
    pub fn mark_route_failure(&mut self, key: &RouteKey, next_hop: &str, now: Instant) -> bool {
        self.cache.mark_failure(key, next_hop, now)
    }

    /// Constructs a bounded multi-hop path under the same hop policy used for
    /// route-request admission.  Each adjacent hop is checked for loops,
    /// exclusions, scope broadening, relay/hop caps, and explicit failure
    /// domain diversity before it can reach session/relay setup.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] when any path policy check fails.
    #[allow(dead_code)] // consumed by the session/relay path-construction handoff
    pub fn construct_path(
        &self,
        request_scope: RouteScope,
        exclusions: &[Vec<u8>],
        hops: &[PathHop],
        mut policy: PathPolicy,
    ) -> Result<RoutePath, PathError> {
        let request_max_hops = usize::try_from(self.request_policy.max_hops).unwrap_or(usize::MAX);
        policy.max_hops = policy.max_hops.min(request_max_hops);
        let mut builder = PathBuilder::new(request_scope, exclusions, policy)?;
        for hop in hops {
            builder.push(hop.clone())?;
        }
        builder.finish()
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
    fn route_response_metadata_is_retained_for_hard_policy_checks() {
        let mut routing = RoutingService::new();
        let record = routing.record_route_response_with_metadata(
            key(4),
            "hop-a".into(),
            1_000,
            Instant(0),
            None,
            b"carrier=ump.tcp/1\0trust=3\0hops=1".to_vec(),
        );
        assert_eq!(record.metadata, b"carrier=ump.tcp/1\0trust=3\0hops=1");
    }

    #[test]
    fn route_response_retains_authenticated_carrier_evidence() {
        let mut routing = RoutingService::new();
        let record = routing.record_route_response_with_evidence(
            key(8),
            "hop-a".into(),
            1_000,
            Instant(0),
            None,
            Vec::new(),
            Some("ump.tcp/1".into()),
        );
        assert_eq!(record.carrier_type.as_deref(), Some("ump.tcp/1"));
    }

    #[test]
    fn diverse_route_candidates_prefer_independent_domains() {
        let mut routing = RoutingService::new();
        let _ = routing.record_route_response_with_metadata(
            key(5),
            "hop-a".into(),
            1_000,
            Instant(0),
            None,
            b"domain=a".to_vec(),
        );
        let _ = routing.record_route_response_with_metadata(
            key(5),
            "hop-b".into(),
            1_000,
            Instant(0),
            None,
            b"domain=a".to_vec(),
        );
        let _ = routing.record_route_response_with_metadata(
            key(5),
            "hop-c".into(),
            1_000,
            Instant(0),
            None,
            b"domain=b".to_vec(),
        );
        let selected = routing.diverse_route_candidates(&key(5), Instant(1), 2);
        assert_eq!(
            selected
                .iter()
                .map(|r| r.next_hop.as_str())
                .collect::<Vec<_>>(),
            vec!["hop-a", "hop-c"]
        );
    }

    #[test]
    fn route_record_preserves_key_scope() {
        let mut routing = RoutingService::new();
        let scoped_key = RouteKey {
            scope: RouteScope::LocalMesh,
            ..key(8)
        };
        let record = routing.record_route_response_with_metadata(
            scoped_key,
            "hop-local".into(),
            1_000,
            Instant(0),
            None,
            Vec::new(),
        );
        assert_eq!(record.scope, RouteScope::LocalMesh);
        assert_eq!(record.key.scope, RouteScope::LocalMesh);
    }

    #[test]
    fn route_request_context_binds_destination_and_scope() {
        let mut routing = RoutingService::new();
        let request_id = [9u8; 16];
        routing.remember_route_request(
            request_id,
            crate::session_task::hash_destination(b"destination-token"),
            RouteScope::Introduced,
            Instant(10),
        );
        let context = routing
            .route_context(&request_id, Instant(11))
            .expect("live route context");
        assert_eq!(
            context.destination_hash,
            crate::session_task::hash_destination(b"destination-token")
        );
        assert_eq!(context.scope, RouteScope::Introduced);
        assert!(routing
            .route_context(&request_id, Instant(30_011))
            .is_none());
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

    #[test]
    fn path_construction_applies_runtime_hop_policy() {
        let routing = RoutingService::new();
        let hops = vec![
            PathHop {
                peer: b"relay-a".to_vec(),
                scope: RouteScope::Introduced,
                failure_domain: b"domain-a".to_vec(),
                relay: true,
            },
            PathHop {
                peer: b"relay-b".to_vec(),
                scope: RouteScope::LocalMesh,
                failure_domain: b"domain-b".to_vec(),
                relay: true,
            },
        ];
        let path = routing
            .construct_path(
                RouteScope::General,
                &[],
                &hops,
                PathPolicy {
                    minimum_distinct_failure_domains: 2,
                    ..PathPolicy::default()
                },
            )
            .unwrap();
        assert_eq!(path.hops.len(), 2);
        assert_eq!(path.effective_scope, RouteScope::LocalMesh);
        assert_eq!(path.distinct_failure_domains, 2);
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
        let _ = routing.record_route_response_with_evidence(
            key(7),
            "hop-a".into(),
            600_000,
            Instant(1),
            None,
            Vec::new(),
            Some("ump.tcp/1".into()),
        );
        // A freshly learned route is usable and persisted to the store.
        assert_eq!(
            routing.find_route(&key(7), Instant(1)).unwrap().state,
            RouteState::Usable
        );
        let persisted = umc_storage::records::list_routes(store.as_ref()).unwrap();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].next_hop, b"hop-a");
        assert_eq!(persisted[0].carrier_type.as_deref(), Some("ump.tcp/1"));
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
        assert_eq!(found.carrier_type.as_deref(), Some("ump.tcp/1"));
        assert_eq!(found.state, RouteState::Candidate);
    }
}
