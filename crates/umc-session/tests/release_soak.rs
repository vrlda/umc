//! Release evidence soak: exercise an encrypted stream and datagram path for
//! a bounded wall-clock duration and emit a machine-readable trend marker.
use std::time::{Duration as StdDuration, Instant as StdInstant};

use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_handshake::xx::run_xx_handshake;
use umc_session::datagram::Datagram;
use umc_session::session::{Role, Session, SessionConfig};
use umc_types::runtime::{Clock, EntropySource, Instant};

struct TestEntropy;

impl EntropySource for TestEntropy {
    #[allow(clippy::cast_possible_truncation)]
    fn fill(&self, out: &mut [u8]) {
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = index.wrapping_mul(17).wrapping_add(9) as u8;
        }
    }
}

struct TestClock;

impl Clock for TestClock {
    fn now(&self) -> Instant {
        Instant(1_000_000)
    }
}

fn session_pair() -> (Session, Session) {
    let (client_secrets, server_secrets) = run_xx_handshake(
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &TestEntropy,
        b"ump.udp/1",
        0,
    )
    .expect("XX handshake");
    let dcid = vec![0xA5; 8];
    let config = |role, local, remote| SessionConfig {
        role,
        dcid: dcid.clone(),
        local_traffic_secret: local,
        remote_traffic_secret: remote,
        initial_max_data: 4 * 1024 * 1024,
        initial_max_stream_data: 256 * 1024,
        max_ack_delay_ms: 25,
    };
    (
        Session::new(
            config(Role::Client, client_secrets.client, client_secrets.server),
            &TestClock,
        )
        .expect("client session"),
        Session::new(
            config(Role::Server, server_secrets.server, server_secrets.client),
            &TestClock,
        )
        .expect("server session"),
    )
}

#[test]
#[ignore = "release evidence campaign"]
fn encrypted_stream_datagram_release_soak() {
    let duration_ms = std::env::var("UMC_SOAK_DURATION_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(600_000);
    let (mut client, mut server) = session_pair();
    let stream_id = client.open_stream().expect("open stream");
    let clock = TestClock;
    let started = StdInstant::now();
    let deadline = started + StdDuration::from_millis(duration_ms);
    let stream_data = vec![0x5A; 256];
    let datagram_data = vec![0xC3; 128];
    let mut iterations = 0u64;
    let mut stream_bytes = 0u64;
    let mut datagram_bytes = 0u64;
    let mut peak_queued = 0usize;

    while StdInstant::now() < deadline {
        let stream_payload = client
            .send_stream_data(stream_id, &stream_data, false)
            .expect("stream payload");
        let stream_packet = client
            .build_outbound(&clock, Instant(1_000_000), &stream_payload)
            .expect("stream packet")
            .expect("stream packet present");
        let stream_ack = server
            .on_inbound(Instant(1_000_001), &stream_packet)
            .expect("stream inbound");
        if !stream_ack.is_empty() {
            let ack_packet = server
                .build_outbound(&clock, Instant(1_000_002), &stream_ack)
                .expect("stream ack packet")
                .expect("stream ack present");
            client
                .on_inbound(Instant(1_000_003), &ack_packet)
                .expect("stream ack inbound");
        }
        let (received, _eof) = server.read_stream(stream_id).expect("stream read");
        stream_bytes = stream_bytes.saturating_add(received.len() as u64);

        client
            .send_datagram(
                Datagram {
                    context_id: 7,
                    data: datagram_data.clone(),
                    expires_at_ms: None,
                    ack_requested: false,
                },
                1_200,
            )
            .expect("queue datagram");
        if let Some(datagram_payload) = client.pop_outbound_datagram_payload(1_000_000) {
            let datagram_packet = client
                .build_outbound(&clock, Instant(1_000_004), &datagram_payload)
                .expect("datagram packet")
                .expect("datagram present");
            server
                .on_inbound(Instant(1_000_005), &datagram_packet)
                .expect("datagram inbound");
            if let Some(datagram) = server.recv_datagram() {
                datagram_bytes = datagram_bytes.saturating_add(datagram.data.len() as u64);
            }
        }
        iterations = iterations.saturating_add(1);
        peak_queued = peak_queued.max(client.congestion_mut().in_flight());
    }

    let elapsed_ms = started.elapsed().as_millis();
    assert!(iterations > 0, "soak performed no iterations");
    assert!(stream_bytes > 0, "soak delivered no stream bytes");
    assert!(datagram_bytes > 0, "soak delivered no datagram bytes");
    assert!(elapsed_ms >= u128::from(duration_ms));
    println!(
        "RELEASE_BASELINE schema=umc-resource-trend-v1 iterations={} stream_bytes={} datagram_bytes={} elapsed_ms={} peak_queued={} queue_capacity={}",
        iterations,
        stream_bytes,
        datagram_bytes,
        elapsed_ms,
        peak_queued,
        client.congestion_mut().cwnd()
    );
}
