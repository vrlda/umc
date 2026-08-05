//! Phase 1 success criterion: a stream round-trips between two sessions with
//! the full protected-packet path (`build_protected_packet` -> `on_inbound`).
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_handshake::xx::run_xx_handshake;
use umc_session::session::{Role, Session, SessionConfig};
use umc_types::runtime::{Clock, EntropySource, Instant};

struct TestEntropy;
impl EntropySource for TestEntropy {
    fn fill(&self, out: &mut [u8]) {
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::try_from(i * 3 + 1).unwrap_or(0);
        }
    }
}

struct TestClock;
impl Clock for TestClock {
    fn now(&self) -> Instant {
        Instant(5_000_000)
    }
}

#[test]
fn stream_echo_with_protected_packets() {
    let (client_secrets, server_secrets) = run_xx_handshake(
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &TestEntropy,
        b"ump.tcp/1",
        0,
    )
    .expect("handshake");

    let dcid = vec![3u8; 8];
    let mut client_session = Session::new(
        SessionConfig {
            role: Role::Client,
            dcid: dcid.clone(),
            local_traffic_secret: client_secrets.client,
            remote_traffic_secret: client_secrets.server,
            initial_max_data: 1 << 20,
            initial_max_stream_data: 1 << 16,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .unwrap();
    let mut server_session = Session::new(
        SessionConfig {
            role: Role::Server,
            dcid,
            local_traffic_secret: server_secrets.server,
            remote_traffic_secret: server_secrets.client,
            initial_max_data: 1 << 20,
            initial_max_stream_data: 1 << 16,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .unwrap();

    let sid = client_session.open_stream();
    let payload = client_session
        .send_stream_data(sid, b"hello", true)
        .unwrap();
    let pkt = client_session
        .build_outbound(&TestClock, Instant(5_000_000), &payload)
        .unwrap()
        .unwrap();

    // The full protected packet travels to the server session.
    let ack = server_session.on_inbound(Instant(5_000_050), &pkt).unwrap();
    assert!(!ack.is_empty());
    let (data, eof) = server_session.read_stream(sid).unwrap();
    assert_eq!(data, b"hello");
    assert!(eof);

    // Echo back on a new stream.
    let echo_sid = server_session.open_stream();
    let echo_payload = server_session
        .send_stream_data(echo_sid, &data, true)
        .unwrap();
    let echo_pkt = server_session
        .build_outbound(&TestClock, Instant(5_000_100), &echo_payload)
        .unwrap()
        .unwrap();
    client_session
        .on_inbound(Instant(5_000_150), &echo_pkt)
        .unwrap();
    let (echoed, _) = client_session.read_stream(echo_sid).unwrap();
    assert_eq!(echoed, b"hello");
}
