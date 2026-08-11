//! 3-node route discovery: A asks for a route to C through B.
//! A -> B (B knows C directly); B answers; A caches a single-relay candidate.
use umc_routing::cache::RouteCache;
use umc_routing::duplicate::RequestCache;
use umc_routing::request::{admit_request, Admission, RequestPolicy};
use umc_routing::reverse::ReverseState;
use umc_routing::types::{RouteKey, RouteRecord, RouteScope, RouteState};
use umc_types::runtime::{Duration, EntropySource, Instant};

struct E;
impl EntropySource for E {
    fn fill(&self, out: &mut [u8]) {
        out.fill(1);
    }
}

#[test]
fn route_discovery_three_nodes() {
    let now = Instant(0);
    let mut cache = RequestCache::new(1_024, Duration::from_millis(30_000));
    let mut reverse = ReverseState::new(Duration::from_millis(30_000));
    let mut route_cache = RouteCache::new(8, Duration::from_millis(600_000));
    let policy = RequestPolicy::default();

    // Node B knows node C directly (pre-seeded route).
    let key_c = RouteKey {
        destination_profile: 0,
        destination_hash: [3u8; 32],
        scope: RouteScope::General,
        policy_class: 0,
    };
    route_cache.insert(
        RouteRecord {
            key: key_c.clone(),
            state: RouteState::Usable,
            next_hop: "node-c".into(),
            metadata: vec![],
            source_peer: vec![],
            created_at: now,
            expires_at: now + Duration::from_millis(600_000),
            last_success: Some(now),
            last_failure: None,
            failure_count: 0,
            scope: RouteScope::General,
        },
        now,
    );

    // A sends ROUTE_REQUEST to B with no forward candidates: direct match only.
    let request_id = RequestCache::generate_request_id(&E);
    let admission = admit_request(
        &request_id,
        b"node-a",
        0,
        8,
        30_000,
        &[],
        &policy,
        &mut cache,
        now,
    )
    .unwrap();
    match admission {
        Admission::Admit { forward_to, .. } => assert!(forward_to.is_empty()),
        other => panic!("expected admit, got {other:?}"),
    }
    reverse.create(request_id, b"node-a".to_vec(), now);

    // B matches C from its cache and returns a route.
    let candidates = route_cache.candidates(&key_c, now);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].next_hop, "node-c");

    // The response travels back to A through reverse state.
    let upstream = reverse
        .route_response(&request_id, now)
        .expect("reverse path");
    assert_eq!(upstream, b"node-a");
}

#[test]
fn response_budget_and_expiry() {
    let mut reverse = ReverseState::new(Duration::from_millis(30_000));
    let rid = [9u8; 16];
    reverse.create(rid, b"node-a".to_vec(), Instant(0));
    for _ in 0..umc_routing::types::MAX_RESPONSES_PER_BRANCH {
        assert!(reverse.route_response(&rid, Instant(1)).is_some());
    }
    assert!(reverse.route_response(&rid, Instant(1)).is_none());
    assert!(reverse.upstream_of(&rid, Instant(29_999)).is_some());
    assert!(reverse.upstream_of(&rid, Instant(30_000)).is_none());
}
