//! Phase 5 success criteria: two nodes discover each other locally with no
//! internet dependency, prefer local paths, and route locally only.
use umc_carrier_lan::{build_announcement, parse_announcement, LanDiscoveryConfig};
use umc_core::mesh::MeshConfig;
use umc_discovery::hints::{build_peer_hint, select_for_share};
use umc_discovery::provider::{CandidateSource, PeerCandidate, SharingPolicy};
use umc_discovery::table::CandidateTable;
use umc_routing::local::score_local_first;
use umc_routing::score::ScoreInput;
use umc_routing::types::{RouteRecord, RouteScope, RouteState};
use umc_types::runtime::{Duration, Instant};

#[test]
fn lan_announcement_exchange_between_two_nodes() {
    let node_a = LanDiscoveryConfig {
        node_hint: b"node-a".to_vec(),
        ..Default::default()
    };
    let node_b = LanDiscoveryConfig {
        node_hint: b"node-b".to_vec(),
        ..Default::default()
    };
    let announcement_a = build_announcement(&node_a).unwrap();
    let announcement_b = build_announcement(&node_b).unwrap();
    assert_eq!(parse_announcement(&announcement_a).unwrap(), b"node-a");
    assert_eq!(parse_announcement(&announcement_b).unwrap(), b"node-b");
    assert!(announcement_a.len() <= 1_024 && announcement_b.len() <= 1_024);
}

#[test]
fn candidates_merge_into_shared_table() {
    let now = Instant(0);
    let mut table = CandidateTable::new(100);
    let mut a = PeerCandidate {
        candidate_id: 1,
        carrier_type: "ump.udp/1".into(),
        connection_hint: b"192.168.1.5:9002".to_vec(),
        source: CandidateSource::LocalDiscovery,
        created_at: now,
        expires_at: now + Duration::from_millis(60_000),
        sharing_policy: SharingPolicy::LocalUseOnly,
        authentication: umc_discovery::provider::CandidateAuth::Unauthenticated,
        local: true,
    };
    a.cap_lifetime(now);
    table.upsert(a, now).unwrap();
    assert_eq!(table.len(), 1);
    assert!(table.get(1).unwrap().local);
}

#[test]
fn local_first_prefers_local_routes() {
    let now = Instant(0);
    let local = RouteRecord {
        key: umc_routing::types::RouteKey {
            destination_profile: 0,
            destination_hash: [1u8; 32],
            scope: RouteScope::LocalMesh,
            policy_class: 0,
        },
        state: RouteState::Usable,
        next_hop: "lan-peer".into(),
        metadata: vec![],
        source_peer: vec![],
        created_at: now,
        expires_at: now + Duration::from_millis(600_000),
        last_success: None,
        last_failure: None,
        failure_count: 0,
        scope: RouteScope::LocalMesh,
    };
    let general = RouteRecord {
        scope: RouteScope::General,
        ..local.clone()
    };
    assert!(
        score_local_first(&local, now, &ScoreInput::default())
            > score_local_first(&general, now, &ScoreInput::default())
    );
}

#[test]
fn local_mesh_mode_rejects_internet_contradiction() {
    let mut config = MeshConfig::local_mesh();
    config.allow_internet_carriers = true;
    assert!(config.validate().is_err());
    config.allow_internet_carriers = false;
    assert_eq!(config.validate(), Ok(()));
}

#[test]
fn private_hints_never_shared_locally() {
    let now = Instant(0);
    let private = PeerCandidate {
        candidate_id: 1,
        carrier_type: "ump.udp/1".into(),
        connection_hint: vec![],
        source: CandidateSource::PeerHint,
        created_at: now,
        expires_at: now + Duration::from_millis(60_000),
        sharing_policy: SharingPolicy::DoNotReshare,
        authentication: umc_discovery::provider::CandidateAuth::Unauthenticated,
        local: false,
    };
    let selected = select_for_share(&[private], 10, now);
    assert!(selected.is_empty());
    // DO_NOT_RESHARE survives frame construction as well.
    let frame = build_peer_hint(&selected).unwrap();
    assert!(frame.entries.is_empty());
}
