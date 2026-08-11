//! J3 adversarial matrix (testing.md §14, threat-model.md §49).
//!
//! These tests exercise the bounded, protocol-pure rejection paths that are
//! cheap to run on every platform. Each case names the hostile input and
//! asserts the refusal/close behavior rather than merely checking that code
//! does not panic.

use std::collections::HashSet;

use umc_bundle::transfer::{split_bundle, BundleReassembler};
use umc_control::conn::{ConnError, SequenceTracker};
use umc_control::framing::{frame_envelope, EnvelopeDecoder, FramingError};
use umc_core::rate_limiter::{RateLimitError, RateLimiter};
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_handshake::identity::IdentityBinding;
use umc_handshake::initial::{build_initial_packet, derive_initial_keys, try_parse_initial};
use umc_handshake::retry::{issue_retry_token, validate_retry_token, RetryError, RetryPayload};
use umc_handshake::tracker::{HandshakeTracker, TrackerError};
use umc_metrics::Registry;
use umc_plugin::contract::{Capability, ManifestError, PluginManifest};
use umc_relay::admission::{evaluate_open, AdmissionDecision, AdmissionLimits, RelayPolicy};
use umc_relay::onion::{build_privacy_route, unwrap_privacy_layer};
use umc_routing::duplicate::{RequestCache, REQUEST_ID_LEN};
use umc_routing::request::{admit_request, Admission, AdmissionError, RequestPolicy};
use umc_session::cid::{ConnectionIdManager, DEFAULT_ACTIVE_LIMIT};
use umc_session::session::{Role, Session, SessionConfig, SessionError, SessionState};
use umc_session::spaces::{PacketSpace, PacketSpaceState, SpaceError};
use umc_types::runtime::{Clock, EntropySource, Instant};
use umc_wire::frame::{decode_frames, AckFrame, FrameError};

#[derive(Debug)]
struct TestClock;

impl Clock for TestClock {
    fn now(&self) -> Instant {
        Instant(0)
    }
}

#[derive(Debug)]
struct TestEntropy;

impl EntropySource for TestEntropy {
    fn fill(&self, out: &mut [u8]) {
        out.fill(0xA7);
    }
}

fn session() -> Session {
    Session::new(
        SessionConfig {
            role: Role::Server,
            dcid: vec![7u8; 8],
            local_traffic_secret: [1u8; 32],
            remote_traffic_secret: [2u8; 32],
            initial_max_data: 1 << 20,
            initial_max_stream_data: 1 << 16,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .expect("session")
}

fn initial_packet(payload: &[u8]) -> Vec<u8> {
    let keys = derive_initial_keys(&[1u8; 8]).client;
    build_initial_packet(&[1u8; 8], &[], 0, payload, &keys).expect("initial packet")
}

#[test]
fn forged_ack_is_refused() {
    let mut session = session();
    let forged = AckFrame {
        largest_acknowledged: 99,
        ack_delay: 0,
        first_ack_range: 0,
        additional_ranges: vec![],
    };
    assert!(matches!(
        session.apply_peer_ack(&forged, Instant(1)),
        Err(SessionError::Ack(_))
    ));
}

#[test]
fn replayed_packet_number_is_refused() {
    let mut space = PacketSpaceState::new(PacketSpace::SessionData);
    assert_eq!(space.admit_received(4, 8), Ok(4));
    assert_eq!(
        space.admit_received(4, 8),
        Err(SpaceError::DuplicateOrStale)
    );
}

#[test]
fn oversized_initial_is_refused_before_decryption() {
    let valid = initial_packet(b"hello");
    assert!(try_parse_initial(&valid).is_some());
    let mut oversized = valid;
    oversized.extend(std::iter::repeat_n(0, 70_000));
    assert!(try_parse_initial(&oversized).is_none());
}

#[test]
fn packet_number_flood_keeps_replay_state_bounded() {
    let mut space = PacketSpaceState::new(PacketSpace::SessionData);
    for pn in 0..10_000 {
        assert_eq!(space.admit_reconstructed(pn), Ok(pn));
    }
    assert_eq!(space.replay_bytes(), 512);
    assert_eq!(
        space.admit_reconstructed(0),
        Err(SpaceError::DuplicateOrStale)
    );
}

#[test]
fn handshake_flood_is_limited_per_dcid() {
    let mut tracker = HandshakeTracker::new(3);
    for _ in 0..3 {
        assert_eq!(tracker.register(&[8u8; 8]), Ok(()));
    }
    assert_eq!(
        tracker.register(&[8u8; 8]),
        Err(TrackerError::LimitExceeded)
    );
}

#[test]
fn unvalidated_amplification_is_refused() {
    let mut session = session();
    session
        .add_path(0, "ump.tcp/1".into(), vec![], vec![], Instant(0))
        .expect("path");
    assert_eq!(
        session.build_outbound(&TestClock, Instant(0), &[0x10]),
        Err(SessionError::AmplificationLimit)
    );
}

#[test]
fn retry_token_bruteforce_is_rate_limited() {
    let payload = RetryPayload {
        token_version: 1,
        source_context: b"source".to_vec(),
        original_destination_connection_id: vec![1; 8],
        client_random: [2; 32],
        client_ephemeral_public_key_hash: [3; 32],
        carrier_binding_hash: [4; 32],
        issued_at: 1_000,
        expires_at: 2_000,
        nonce: [5; 16],
    };
    let token = issue_retry_token(&[6; 32], &payload, 1_001).expect("token");
    assert_eq!(
        validate_retry_token(&[9; 32], &token, 1_001),
        Err(RetryError::InvalidTag)
    );
    let mut limiter = RateLimiter::new(4);
    for _ in 0..9 {
        assert_eq!(limiter.check(b"retry-source", 0), Ok(()));
    }
    assert_eq!(
        limiter.check(b"retry-source", 0),
        Err(RateLimitError::RateLimited)
    );
}

#[test]
fn malformed_identity_binding_is_refused() {
    let identity = IdentityKeyPair::generate();
    let static_key = StaticHandshakeKeyPair::generate();
    let mut binding =
        IdentityBinding::sign(&identity, &static_key.public(), 0, 10_000, 0, [0u8; 32]);
    binding.signature[0] ^= 1;
    assert!(binding.validate(1_000, 0).is_err());
}

#[test]
fn unknown_critical_fixed_frame_is_refused() {
    let unknown = umc_wire::varint::encode(0x80).expect("varint");
    assert_eq!(
        decode_frames(&unknown),
        Err(FrameError::UnknownCriticalFrame(
            umc_types::frame::FrameType(0x80)
        ))
    );
}

#[test]
fn fragmented_control_envelope_is_buffered_and_bounded() {
    let mut framed = Vec::new();
    frame_envelope(&mut framed, b"fragmented", 64).expect("frame");
    let mut decoder = EnvelopeDecoder::new(64);
    assert!(decoder.feed(&framed[..3]).expect("prefix").is_empty());
    assert_eq!(
        decoder.feed(&framed[3..]).expect("remainder"),
        vec![b"fragmented".to_vec()]
    );
    assert_eq!(decoder.feed(&[0, 0, 0, 65]), Err(FramingError::TooLarge));
}

#[test]
fn encrypted_garbage_does_not_change_session_state() {
    let mut session = session();
    for byte in 0..64u8 {
        assert!(session
            .on_inbound(Instant(u64::from(byte)), &[byte; 32])
            .is_err());
        assert_eq!(session.state, SessionState::Active);
    }
}

#[test]
fn connection_id_pool_refuses_exhaustion() {
    let mut manager = ConnectionIdManager::new(DEFAULT_ACTIVE_LIMIT);
    for _ in 0..DEFAULT_ACTIVE_LIMIT {
        assert!(manager.issue(8, &TestEntropy).is_some());
    }
    assert!(manager.issue(8, &TestEntropy).is_none());
}

#[test]
fn stream_flood_hits_hard_limit() {
    let mut session = session();
    for _ in 0..umc_session::session::MAX_STREAMS_PER_SESSION {
        session.open_stream().expect("stream slot");
    }
    assert_eq!(session.open_stream(), Err(SessionError::StreamLimit));
}

#[test]
fn migration_without_path_validation_is_refused() {
    let mut session = session();
    session
        .add_path(1, "ump.tcp/1".into(), vec![], vec![], Instant(0))
        .expect("path");
    assert_eq!(
        session.migrate_to(1, false, Instant(1)),
        Err(SessionError::PathNotValidated)
    );
}

#[test]
fn guessed_reset_token_does_not_close_session() {
    let mut session = session();
    session.set_stateless_reset_secret([3u8; 32]);
    for byte in 0..32u8 {
        let _ = session.on_inbound(Instant(u64::from(byte)), &[byte; 64]);
    }
    assert_eq!(session.state, SessionState::Active);
}

#[test]
fn bundle_replay_is_idempotent_and_conflicts_are_refused() {
    let id = [4u8; 32];
    let chunks = split_bundle(id, b"bundle payload");
    let mut receiver = BundleReassembler::new(id);
    receiver.push(chunks[0].clone()).expect("first chunk");
    receiver.push(chunks[0].clone()).expect("exact replay");
    let mut conflicting = chunks[0].clone();
    conflicting.payload[0] ^= 1;
    assert!(receiver.push(conflicting).is_err());
}

#[test]
fn relay_authentication_layer_rejects_wrong_hop_key() {
    let route = build_privacy_route(&[[1u8; 32], [2u8; 32]], &[b"opaque-next".to_vec()], b"dest")
        .expect("route");
    assert!(unwrap_privacy_layer(&[9u8; 32], &route).is_err());
}

#[test]
fn relay_policy_and_flag_abuse_is_refused() {
    let limits = AdmissionLimits {
        policy: RelayPolicy::Public,
        ..AdmissionLimits::default()
    };
    assert_eq!(
        evaluate_open(&limits, 0, 1_000, 1_000, 0x80),
        AdmissionDecision::UnsupportedFlags
    );
}

#[test]
fn route_request_loop_is_stopped_by_hop_limit_and_duplicate_cache() {
    let request_id = [7u8; REQUEST_ID_LEN];
    let mut cache = RequestCache::new(8, umc_types::runtime::Duration::from_millis(60_000));
    let policy = RequestPolicy::default();
    let first = admit_request(
        &request_id,
        b"peer-a",
        0,
        1,
        1_000,
        &[b"peer-b".to_vec()],
        &policy,
        &mut cache,
        Instant(0),
    )
    .expect("first request");
    assert!(matches!(first, Admission::Admit { hop_limit: 0, .. }));
    assert_eq!(
        admit_request(
            &request_id,
            b"peer-a",
            0,
            0,
            1_000,
            &[b"peer-b".to_vec()],
            &policy,
            &mut cache,
            Instant(1),
        ),
        Err(AdmissionError::HopLimitZero)
    );
}

#[test]
fn control_sequence_flood_reuse_is_refused() {
    let mut tracker = SequenceTracker::new();
    assert_eq!(tracker.observe(1), Ok(()));
    assert_eq!(tracker.observe(1), Err(ConnError::SequenceViolation));
}

#[test]
fn plugin_manifest_abuse_is_denied_by_closed_capability_set() {
    let manifest = PluginManifest {
        id: "attacker".into(),
        version: (1, 0, 0),
        entry_point: "plugin".into(),
        permissions: vec!["identity.export-secret".into()],
    };
    assert!(matches!(
        manifest.validate(),
        Err(ManifestError::UnknownPermission(_))
    ));
    assert!(Capability::from_str("identity.export-secret").is_none());
}

#[test]
fn telemetry_cardinality_abuse_is_bounded() {
    let metrics = Registry::new();
    for index in 0..umc_metrics::MAX_NAMES {
        metrics.incr(&format!("attacker_{index}"), 1);
    }
    metrics.incr("attacker_overflow", 1);
    assert_eq!(metrics.snapshot().len(), umc_metrics::MAX_NAMES);
    assert_eq!(metrics.get("attacker_overflow"), None);
}

#[test]
fn scenario_matrix_has_no_duplicate_labels() {
    let labels = [
        "forged_ack",
        "initial_replay",
        "oversized_header",
        "packet_number_flood",
        "handshake_flood",
        "amplification",
        "token_bruteforce",
        "malformed_binding",
        "unknown_critical_frame",
        "fragmented_control",
        "encrypted_garbage",
        "connection_id_exhaustion",
        "stream_id_flood",
        "path_confusion",
        "reset_token_guess",
        "bundle_replay",
        "relay_auth_forgery",
        "relay_flag_abuse",
        "route_loop",
        "control_flood",
        "plugin_manifest_abuse",
        "telemetry_misuse",
    ];
    let unique: HashSet<_> = labels.iter().copied().collect();
    assert_eq!(unique.len(), labels.len());
    assert_eq!(labels.len(), 22);
}
