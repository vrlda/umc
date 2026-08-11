//! Migration preserves stream state and packet numbers (session.md §27).
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_handshake::xx::run_xx_handshake;
use umc_session::session::{Role, Session, SessionConfig};
use umc_types::runtime::{Clock, EntropySource, Instant};

struct E;
impl EntropySource for E {
    fn fill(&self, out: &mut [u8]) {
        out.fill(3);
    }
}
struct C;
impl Clock for C {
    fn now(&self) -> Instant {
        Instant(7_000_000)
    }
}

fn session(role: Role, local: [u8; 32], remote: [u8; 32], dcid: Vec<u8>) -> Session {
    Session::new(
        SessionConfig {
            role,
            dcid,
            local_traffic_secret: local,
            remote_traffic_secret: remote,
            initial_max_data: 1 << 20,
            initial_max_stream_data: 1 << 16,
            max_ack_delay_ms: 25,
        },
        &C,
    )
    .unwrap()
}

#[test]
fn migration_preserves_streams_and_numbers() {
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
    let dcid = vec![1u8; 8];
    let mut client = session(Role::Client, cs.client, cs.server, dcid.clone());
    let mut server = session(Role::Server, ss.server, ss.client, dcid);

    // Send data over path 0.
    let sid = client.open_stream().expect("stream");
    let payload = client
        .send_stream_data(sid, b"before-migration", true)
        .unwrap();
    let pkt = client
        .build_outbound(&C, Instant(7_000_000), &payload)
        .unwrap()
        .unwrap();
    let ack = server.on_inbound(Instant(7_000_050), &pkt).unwrap();
    assert!(!ack.is_empty());
    let (data, eof) = server.read_stream(sid).unwrap();
    assert_eq!(data, b"before-migration");
    assert!(eof);

    // Add and validate a second path, then migrate.
    client
        .add_path(1, "ump.tcp/1".into(), vec![1], vec![2], Instant(7_000_100))
        .unwrap();
    // Library test: force validation (the daemon drives challenge/response).
    client.force_validate(1);
    client.migrate_to(1, false, Instant(7_000_200)).unwrap();

    // Stream state is untouched.
    assert!(
        client.read_stream(sid).is_ok(),
        "stream handle survives migration"
    );
}

#[test]
fn migration_requires_validation() {
    let (cs, _) = run_xx_handshake(
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &E,
        b"ump.udp/1",
        0,
    )
    .expect("handshake");
    let mut client = session(Role::Client, cs.client, cs.server, vec![1u8; 8]);
    client
        .add_path(1, "ump.tcp/1".into(), vec![], vec![], Instant(0))
        .unwrap();
    assert_eq!(
        client.migrate_to(1, false, Instant(1)),
        Err(umc_session::session::SessionError::PathNotValidated)
    );
}
