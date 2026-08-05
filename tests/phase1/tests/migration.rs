//! Phase 1 invariant: the session layer never sees the carrier object, so a
//! carrier swap cannot lose session state (full migration is Phase 4).
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_handshake::xx::run_xx_handshake;
use umc_session::session::{Role, Session, SessionConfig};
use umc_types::runtime::{Clock, EntropySource, Instant};

struct E;
impl EntropySource for E {
    fn fill(&self, out: &mut [u8]) {
        out.fill(7);
    }
}
struct C;
impl Clock for C {
    fn now(&self) -> Instant {
        Instant(9_000_000)
    }
}

#[test]
fn session_survives_carrier_swap() {
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
    let dcid = vec![4u8; 8];
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

    let sid = client.open_stream();
    let payload = client
        .send_stream_data(sid, b"across-carriers", true)
        .unwrap();
    let pkt = client
        .build_outbound(&C, Instant(9_000_000), &payload)
        .unwrap()
        .unwrap();
    let ack = server.on_inbound(Instant(9_000_050), &pkt).unwrap();
    assert!(!ack.is_empty());
    let (data, eof) = server.read_stream(sid).unwrap();
    assert_eq!(data, b"across-carriers");
    assert!(eof);
}
