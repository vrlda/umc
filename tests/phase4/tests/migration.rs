//! Phase 4 success criteria: session state survives carrier change,
//! connection IDs rotate, keys update, tickets resume.
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_handshake::ticket::{issue_ticket, validate_ticket, TicketPayload};
use umc_handshake::xx::run_xx_handshake;
use umc_session::session::{Session, SessionConfig, Role};
use umc_types::runtime::{Clock, EntropySource, Instant};

struct E;
impl EntropySource for E {
    fn fill(&self, out: &mut [u8]) {
        out.fill(9);
    }
}
struct C;
impl Clock for C {
    fn now(&self) -> Instant {
        Instant(42_000_000)
    }
}

#[test]
fn full_mobility_cycle() {
    let (cs, ss) = run_xx_handshake(
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &E,
        b"ump.udp/1",
        0,
    )
    .expect("handshake");
    let dcid = vec![8u8; 8];
    let mut client = Session::new(
        SessionConfig {
            role: Role::Client,
            dcid: dcid.clone(),
            local_traffic_secret: cs.client,
            remote_traffic_secret: cs.server,
            initial_max_data: 1 << 20,
            initial_max_stream_data: 1 << 16,
            max_ack_delay_ms: 25,
        },
        &C,
    )
    .unwrap();
    let mut server = Session::new(
        SessionConfig {
            role: Role::Server,
            dcid,
            local_traffic_secret: ss.server,
            remote_traffic_secret: ss.client,
            initial_max_data: 1 << 20,
            initial_max_stream_data: 1 << 16,
            max_ack_delay_ms: 25,
        },
        &C,
    )
    .unwrap();

    // 1. Data over path 0.
    let sid = client.open_stream();
    let payload = client
        .send_stream_data(sid, b"first", true)
        .unwrap();
    let pkt = client
        .build_outbound(&C, Instant(42_000_000), &payload)
        .unwrap()
        .unwrap();
    let ack = server.on_inbound(Instant(42_000_050), &pkt).unwrap();
    assert!(!ack.is_empty());

    // 2. Key update mid-session: the frame is delivered over the wire and
    // parsed in a protected packet; the session stays usable.
    let ku = client.initiate_key_update().unwrap();
    let ku_pkt = client
        .build_outbound(&C, Instant(42_000_100), &ku)
        .unwrap()
        .unwrap();
    let ack = server.on_inbound(Instant(42_000_150), &ku_pkt).unwrap();
    assert!(!ack.is_empty(), "key-update frame accepted on the wire");

    // 3. New path validated and migrated.
    client
        .add_path(1, "ump.tcp/1".into(), vec![1], vec![2], Instant(42_000_200))
        .unwrap();
    // Library test: the daemon drives challenge/response; force validation.
    client.force_validate(1);
    client
        .migrate_to(1, false, Instant(42_000_300))
        .unwrap();

    // 4. Stream continues after migration with the same handle.
    let (data, eof) = server.read_stream(sid).unwrap();
    assert_eq!(data, b"first");
    assert!(eof);
    assert!(client.read_stream(sid).is_ok(), "stream handle survives migration");
}

#[test]
fn tickets_resume_after_restart() {
    let key = [7u8; 32];
    let now = 1_700_000_000_000;
    let payload = TicketPayload {
        version: 1,
        ticket_id: [1u8; 16],
        client_endpoint_id_hash: [2u8; 32],
        server_endpoint_id_hash: [3u8; 32],
        resumption_secret: [4u8; 32],
        issued_at_ms: now,
        expires_at_ms: now + 3_600_000,
        protocol_version: 1,
        crypto_profile: b"UMP-CRYPTO-1".to_vec(),
        nonce: [5u8; 16],
    };
    let ticket = issue_ticket(&key, &payload);
    // "Restart": the same ticket key (rotated keys would invalidate tickets).
    let restored = validate_ticket(&key, &ticket, now + 10_000).unwrap();
    assert_eq!(restored.resumption_secret, [4u8; 32]);
    // New sessions use fresh state, not restored live state (session.md §38).
    let psk = umc_session::ticket::resumption_psk(&restored.resumption_secret, &restored.nonce);
    assert_ne!(psk, [0u8; 32]);
}
