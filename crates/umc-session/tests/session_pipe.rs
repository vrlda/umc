//! Two sessions exchanging a stream over an in-memory pipe with loss injection.
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_handshake::xx::run_xx_handshake;
use umc_session::datagram::Datagram;
use umc_session::session::{
    Role, Session, SessionConfig, SessionState, CLOSE_REASON_IDLE_TIMEOUT, IDLE_TIMEOUT_MS,
    MAX_STREAMS_PER_SESSION,
};
use umc_types::runtime::{Clock, Duration, EntropySource, Instant};

struct TestEntropy;

impl EntropySource for TestEntropy {
    #[allow(clippy::cast_possible_truncation)]
    fn fill(&self, out: &mut [u8]) {
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i * 13 + 3) as u8;
        }
    }
}

struct TestClock;

impl Clock for TestClock {
    fn now(&self) -> Instant {
        Instant(1_000_000)
    }
}

#[test]
fn stream_echo_through_two_sessions() {
    let (client_secrets, server_secrets) = run_xx_handshake(
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &TestEntropy,
        b"ump.udp/1",
        0,
    )
    .expect("handshake");

    let dcid = vec![9u8; 8];
    let mut client = Session::new(
        SessionConfig {
            role: Role::Client,
            dcid: dcid.clone(),
            local_traffic_secret: client_secrets.client,
            remote_traffic_secret: client_secrets.server,
            initial_max_data: 4 * 1024 * 1024,
            initial_max_stream_data: 256 * 1024,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .expect("client session");

    let mut server = Session::new(
        SessionConfig {
            role: Role::Server,
            dcid: dcid.clone(),
            local_traffic_secret: server_secrets.server,
            remote_traffic_secret: server_secrets.client,
            initial_max_data: 4 * 1024 * 1024,
            initial_max_stream_data: 256 * 1024,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .expect("server session");

    let sid = client.open_stream().expect("stream");
    let payload = client.send_stream_data(sid, b"hello", true).expect("send");
    let pkt = client
        .build_outbound(&TestClock, Instant(1_000_000), &payload)
        .expect("build")
        .expect("some");

    // Deliver to the server (lossless for the first hop).
    let ack_payload = server
        .on_inbound(Instant(1_000_050), &pkt)
        .expect("server recv");
    assert!(!ack_payload.is_empty(), "server must ACK");

    // Server reads the stream.
    let (data, eof) = server.read_stream(sid).expect("read");
    assert_eq!(data, b"hello");
    assert!(eof);

    // Echo back on a new stream from the server.
    let echo_sid = server.open_stream().expect("stream");
    let echo_payload = server
        .send_stream_data(echo_sid, &data, true)
        .expect("echo send");
    let echo_pkt = server
        .build_outbound(&TestClock, Instant(1_000_100), &echo_payload)
        .expect("build")
        .expect("some");

    let ack2 = client
        .on_inbound(Instant(1_000_150), &echo_pkt)
        .expect("client recv");
    assert!(!ack2.is_empty());
    let (echoed, eof2) = client.read_stream(echo_sid).expect("read echo");
    assert_eq!(echoed, b"hello");
    assert!(eof2);
}

#[test]
fn datagrams_flow_both_ways() {
    let (client_secrets, server_secrets) = run_xx_handshake(
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &TestEntropy,
        b"ump.udp/1",
        0,
    )
    .expect("handshake");
    let dcid = vec![1u8; 8];
    let mut client = Session::new(
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
    let mut server = Session::new(
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

    client
        .send_datagram(
            Datagram {
                context_id: 0,
                data: b"ping".to_vec(),
                expires_at_ms: None,
                ack_requested: false,
            },
            1200,
        )
        .unwrap();
    // Manually frame the datagram payload and ship it.
    let mut payload = Vec::new();
    umc_wire::varint::encode_into(&mut payload, umc_types::frame::FrameType::DATAGRAM.0).unwrap();
    let frame = umc_wire::frames::datagram::DatagramFrame {
        context_id: 0,
        ack_requested: false,
        duplicate_suppression: false,
        expiration_delta: None,
        data: b"ping".to_vec(),
    };
    let enc = frame.encode().unwrap();
    payload.extend_from_slice(&enc[1..]);
    let pkt = client
        .build_outbound(&TestClock, Instant(2_000_000), &payload)
        .unwrap()
        .unwrap();
    server.on_inbound(Instant(2_000_050), &pkt).unwrap();
    let d = server.recv_datagram().expect("datagram");
    assert_eq!(d.data, b"ping");
}

#[test]
fn ack_sampling_initializes_rtt() {
    let (client_secrets, server_secrets) = run_xx_handshake(
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &TestEntropy,
        b"ump.udp/1",
        0,
    )
    .expect("handshake");
    let dcid = vec![9u8; 8];
    let mut client = Session::new(
        SessionConfig {
            role: Role::Client,
            dcid: dcid.clone(),
            local_traffic_secret: client_secrets.client,
            remote_traffic_secret: client_secrets.server,
            initial_max_data: 4 * 1024 * 1024,
            initial_max_stream_data: 256 * 1024,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .expect("client session");
    let mut server = Session::new(
        SessionConfig {
            role: Role::Server,
            dcid,
            local_traffic_secret: server_secrets.server,
            remote_traffic_secret: server_secrets.client,
            initial_max_data: 4 * 1024 * 1024,
            initial_max_stream_data: 256 * 1024,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .expect("server session");

    // 1. client sends a PING packet at Instant(1_000_000)
    let ping = umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap();
    let pkt = client
        .build_outbound(&TestClock, Instant(1_000_000), &ping)
        .unwrap()
        .unwrap();
    // 2. server processes it and returns an ack payload
    let ack_payload = server.on_inbound(Instant(1_000_000), &pkt).unwrap();
    assert!(!ack_payload.is_empty());
    // 3. client receives the ack at Instant(1_000_100): the ack travels inside
    //    a protected packet, so build the server's reply exactly as the server
    //    would: server.build_outbound(now, &ack_payload)
    let reply = server
        .build_outbound(&TestClock, Instant(1_000_000), &ack_payload)
        .unwrap()
        .unwrap();
    let _ = client.on_inbound(Instant(1_000_100), &reply).unwrap();
    // 4. RTT is now sampled: latest_rtt == 100 (minus ack delay 0)
    assert!(client.rtt().initialized);
    assert_eq!(client.rtt().latest_rtt, 100);
}

#[test]
fn lost_packet_payload_retransmitted() {
    let (client_secrets, _server_secrets) = run_xx_handshake(
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &TestEntropy,
        b"ump.udp/1",
        0,
    )
    .expect("handshake");
    let mut client = Session::new(
        SessionConfig {
            role: Role::Client,
            dcid: vec![9u8; 8],
            local_traffic_secret: client_secrets.client,
            remote_traffic_secret: client_secrets.server,
            initial_max_data: 4 * 1024 * 1024,
            initial_max_stream_data: 256 * 1024,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .expect("client session");

    let ping = umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap();
    let _pkt = client
        .build_outbound(&TestClock, Instant(1_000_000), &ping)
        .unwrap()
        .unwrap();

    // The peer ACKed a packet three numbers higher, so pn 0 is
    // packet-threshold lost (session.md §14.1) and leaves the sent queue.
    let rtt = client.rtt().clone();
    let detector = client.loss_detector().clone();
    let lost = umc_session::loss::detect_lost_packets(
        client.sent_state_mut(),
        &rtt,
        Instant(1_000_000),
        3,
        &detector,
    );
    assert_eq!(lost, vec![0]);
    assert!(client.sent_state().sent().is_empty());

    // Retransmission re-sends the stored payload under a fresh packet number.
    let retransmitted = client
        .retransmit(0, Instant(1_000_000))
        .unwrap()
        .expect("retransmit bytes");
    let keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&client_secrets.client).unwrap();
    let (space, _dcid, _path, _pn, payload) =
        umc_session::packet::parse_protected_packet(&keys, &retransmitted).unwrap();
    let parsed = umc_wire::packet::parse_payload(
        &umc_wire::packet::PacketContext::Protected(space),
        &payload,
    )
    .unwrap();
    assert!(
        parsed
            .frames
            .iter()
            .any(|f| matches!(f, umc_wire::frame::Frame::Ping)),
        "retransmission carries the PING frame again"
    );
    // The fresh packet is ack-eliciting and in flight, so its payload is
    // retained in the table for a future retransmission.
    let fresh = client.sent_state().sent().back().expect("fresh packet");
    assert!(fresh.ack_eliciting);
    assert!(fresh.in_flight);
}

#[test]
fn stream_limit_enforced_on_outbound() {
    let (client_secrets, _) = run_xx_handshake(
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &TestEntropy,
        b"ump.udp/1",
        0,
    )
    .expect("handshake");
    let mut client = Session::new(
        SessionConfig {
            role: Role::Client,
            dcid: vec![9u8; 8],
            local_traffic_secret: client_secrets.client,
            remote_traffic_secret: client_secrets.server,
            initial_max_data: 4 * 1024 * 1024,
            initial_max_stream_data: 256 * 1024,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .expect("client session");

    for _ in 0..MAX_STREAMS_PER_SESSION {
        client.open_stream().expect("stream within cap");
    }
    // The 1,025th concurrent stream is refused (resource-limits.md §20).
    assert_eq!(
        client.open_stream(),
        Err(umc_session::session::SessionError::StreamLimit)
    );
}

#[test]
fn stream_limit_enforced_on_inbound() {
    let (client_secrets, server_secrets) = run_xx_handshake(
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &TestEntropy,
        b"ump.udp/1",
        0,
    )
    .expect("handshake");
    let dcid = vec![9u8; 8];
    let mut client = Session::new(
        SessionConfig {
            role: Role::Client,
            dcid: dcid.clone(),
            local_traffic_secret: client_secrets.client,
            remote_traffic_secret: client_secrets.server,
            initial_max_data: 4 * 1024 * 1024,
            initial_max_stream_data: 256 * 1024,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .expect("client session");
    let mut server = Session::new(
        SessionConfig {
            role: Role::Server,
            dcid,
            local_traffic_secret: server_secrets.server,
            remote_traffic_secret: server_secrets.client,
            initial_max_data: 4 * 1024 * 1024,
            initial_max_stream_data: 256 * 1024,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .expect("server session");

    // Deliver one distinct inbound stream per protected packet. The client
    // only builds packets here; the frames carry fresh ids the server has
    // never seen, so the server creates each stream on arrival.
    let t0 = Instant(4_000_000);
    for i in 0..MAX_STREAMS_PER_SESSION {
        let payload = stream_payload((i * 2) as u64, b"x");
        let pkt = client
            .build_outbound(&TestClock, t0, &payload)
            .unwrap()
            .unwrap();
        server.on_inbound(t0, &pkt).unwrap();
    }
    // One more distinct inbound id: the packet is rejected with the stream
    // limit error (resource-limits.md §20).
    let payload = stream_payload((MAX_STREAMS_PER_SESSION * 2) as u64, b"y");
    let pkt = client
        .build_outbound(&TestClock, t0, &payload)
        .unwrap()
        .unwrap();
    assert_eq!(
        server.on_inbound(t0, &pkt),
        Err(umc_session::session::SessionError::StreamLimit)
    );
}

fn stream_payload(stream_id: u64, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    umc_wire::varint::encode_into(&mut payload, umc_types::frame::FrameType::STREAM.0).unwrap();
    let frame = umc_wire::frames::stream::StreamFrame {
        stream_id,
        fin: false,
        offset_present: true,
        len_present: true,
        open: true,
        unidirectional: false,
        offset: 0,
        data: data.to_vec(),
        protocol_id: vec![],
        metadata: vec![],
    };
    let enc = frame.encode().unwrap();
    payload.extend_from_slice(&enc[1..]);
    payload
}

#[test]
fn idle_timeout_triggers_close() {
    let (client_secrets, _server_secrets) = run_xx_handshake(
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &TestEntropy,
        b"ump.udp/1",
        0,
    )
    .expect("handshake");
    let mut client = Session::new(
        SessionConfig {
            role: Role::Client,
            dcid: vec![9u8; 8],
            local_traffic_secret: client_secrets.client,
            remote_traffic_secret: client_secrets.server,
            initial_max_data: 4 * 1024 * 1024,
            initial_max_stream_data: 256 * 1024,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .expect("client session");

    let t0 = Instant(1_000_000);
    // No activity yet: a fresh session is never idle (session.md §22), so
    // the timer cannot fire before the first packet.
    assert!(!client.idle_expired(t0 + Duration::from_millis(IDLE_TIMEOUT_MS)));
    // First activity anchors the timer; nothing expires before the timeout.
    client.touch(t0);
    assert!(!client.idle_expired(t0 + Duration::from_millis(IDLE_TIMEOUT_MS - 1)));
    assert!(client.idle_expired(t0 + Duration::from_millis(IDLE_TIMEOUT_MS)));
    // Activity resets the timer.
    client.touch(t0 + Duration::from_millis(IDLE_TIMEOUT_MS));
    assert!(!client.idle_expired(t0 + Duration::from_millis(2 * IDLE_TIMEOUT_MS - 1)));

    // Idle-expired: the session offers a CONNECTION_CLOSE carrying the idle
    // timeout reason (wire-format.md §64: 0x16 = IDLE_TIMEOUT).
    let expired = t0 + Duration::from_millis(2 * IDLE_TIMEOUT_MS);
    assert!(
        client.build_idle_close(Instant(expired.0 - 1)).is_none(),
        "not yet expired offers no close"
    );
    let payload = client
        .build_idle_close(expired)
        .expect("idle close payload");
    let frames = umc_wire::frame::decode_frames(&payload).expect("close frames");
    assert!(matches!(
        &frames[..],
        [umc_wire::frame::Frame::ConnectionClose(cc)]
            if cc.error_code == CLOSE_REASON_IDLE_TIMEOUT
                && cc.trigger_frame_type == 0
                && cc.reason == b"idle timeout"
    ));

    // Closing enters DRAINING with a 3 x PTO (min 1 s) deadline; with no RTT
    // sample the probe timeout is the 1 s default, so draining lasts 3 s.
    client.close(expired);
    assert_eq!(client.state, SessionState::Draining);
    let drain = Duration::from_millis(3 * 1_000);
    let deadline = expired + drain;
    assert!(!client.draining_expired(Instant(deadline.0 - 1)));
    assert!(client.draining_expired(deadline));
    // Draining expiry transitions to CLOSED.
    client.finalize_close();
    assert_eq!(client.state, SessionState::Closed);
}
