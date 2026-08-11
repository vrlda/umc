//! Phase-14 hostile transport checks (testing.md §14).

use umc_session::session::{Role, Session, SessionConfig};
use umc_types::runtime::{Clock, Instant};

#[derive(Debug)]
struct TestClock;

impl Clock for TestClock {
    fn now(&self) -> Instant {
        Instant(0)
    }
}

fn session(role: Role, local: [u8; 32], remote: [u8; 32]) -> Session {
    Session::new(
        SessionConfig {
            role,
            dcid: vec![1u8; 8],
            local_traffic_secret: local,
            remote_traffic_secret: remote,
            initial_max_data: 1 << 20,
            initial_max_stream_data: 1 << 16,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .expect("session")
}

#[test]
fn duplicate_packets_are_rejected_without_duplicate_delivery() {
    let mut client = session(Role::Client, [1u8; 32], [2u8; 32]);
    let mut server = session(Role::Server, [2u8; 32], [1u8; 32]);
    let stream_id = client.open_stream().expect("stream");
    let payload = client
        .send_stream_data(stream_id, b"data", true)
        .expect("stream frame");
    let packet = client
        .build_outbound(&TestClock, Instant(0), &payload)
        .expect("packet")
        .expect("active session");

    server
        .on_inbound(Instant(1), &packet)
        .expect("first delivery");
    assert!(server.on_inbound(Instant(2), &packet).is_err());
    let (data, eof) = server.read_stream(stream_id).expect("read stream");
    assert_eq!(data, b"data");
    assert!(eof);
}

#[test]
fn truncated_packets_fail_closed_without_panicking() {
    let mut server = session(Role::Server, [2u8; 32], [1u8; 32]);
    for length in 0..200usize {
        let bytes = vec![0xABu8; length];
        let _ = server.on_inbound(Instant(length as u64), &bytes);
    }
}
