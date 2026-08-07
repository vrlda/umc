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

/// Driver handshake + fresh client/server sessions (pipe pattern).
fn pipe_pair() -> (Session, Session) {
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
    let client = Session::new(
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
    let server = Session::new(
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
    (client, server)
}

/// Build a client-side protected packet carrying the given frame payload.
fn client_packet(client: &mut Session, payload: &[u8]) -> Vec<u8> {
    client
        .build_outbound(&TestClock, Instant(0), payload)
        .expect("build")
        .expect("some")
}

/// Deliver one encoded frame (type byte included) from client to server.
fn deliver_frame(client: &mut Session, server: &mut Session, frame_bytes: &[u8]) {
    let pkt = client_packet(client, frame_bytes);
    server.on_inbound(Instant(0), &pkt).expect("inbound");
}

#[test]
fn reset_final_size_consumed_once() {
    let (mut client, mut server) = pipe_pair();
    let sid = client.open_stream().expect("stream");
    // The server must know the stream: deliver 10 bytes first.
    let stream = umc_wire::frames::stream::StreamFrame {
        stream_id: sid,
        fin: false,
        offset_present: false,
        len_present: true,
        open: true,
        unidirectional: false,
        offset: 0,
        data: vec![0xAA; 10],
        protocol_id: Vec::new(),
        metadata: Vec::new(),
    };
    deliver_frame(&mut client, &mut server, &stream.encode().unwrap());
    assert_eq!(server.flow_consumed(), 10);
    let reset = umc_wire::frames::stream::ResetStreamFrame {
        stream_id: sid,
        app_error_code: 0,
        final_size: 50,
    };
    deliver_frame(&mut client, &mut server, &reset.encode().unwrap());
    // The reset's final size is accounted once: 10 (stream) + 50 (reset).
    assert_eq!(server.flow_consumed(), 60);
    // A retransmitted RESET must not double-consume.
    deliver_frame(&mut client, &mut server, &reset.encode().unwrap());
    assert_eq!(server.flow_consumed(), 60);
}

#[test]
fn reset_final_size_below_received_rejected() {
    let (mut client, mut server) = pipe_pair();
    let sid = client.open_stream().expect("stream");
    // Deliver 100 bytes of stream data first (offset 0, len 100).
    let stream = umc_wire::frames::stream::StreamFrame {
        stream_id: sid,
        fin: false,
        offset_present: false,
        len_present: true,
        open: true,
        unidirectional: false,
        offset: 0,
        data: vec![0xAB; 100],
        protocol_id: Vec::new(),
        metadata: Vec::new(),
    };
    deliver_frame(&mut client, &mut server, &stream.encode().unwrap());
    // RESET with final_size 50 < received 100 must fail the packet.
    let reset = umc_wire::frames::stream::ResetStreamFrame {
        stream_id: sid,
        app_error_code: 0,
        final_size: 50,
    };
    let pkt = client_packet(&mut client, &reset.encode().unwrap());
    assert!(server.on_inbound(Instant(0), &pkt).is_err());
}

#[test]
fn credit_emitted_on_app_consumption() {
    let (mut client, mut server) = pipe_pair();
    let sid = client.open_stream().expect("stream");
    // Stream credit is 256 KiB. Deliver 200 KiB at real offsets WITHOUT
    // reading: the received-not-delivered delta (200 KiB) exceeds half the
    // limit, so MAX_STREAM_DATA fires (grant -> 512 KiB).
    // 200 KiB in 25 chunks of 8 KiB (single-frame packets cap at 65 535 B).
    let chunk = vec![0xCD; 8_000];
    for i in 0..25u64 {
        let frame = umc_wire::frames::stream::StreamFrame {
            stream_id: sid,
            fin: false,
            offset_present: i != 0,
            len_present: true,
            open: true,
            unidirectional: false,
            offset: i * 8_000,
            data: chunk.clone(),
            protocol_id: Vec::new(),
            metadata: Vec::new(),
        };
        deliver_frame(&mut client, &mut server, &frame.encode().unwrap());
    }
    let frames = server.flow_control_frames(Instant(0));
    assert!(
        frames
            .iter()
            .any(|f| umc_wire::varint::decode(f).map(|(t, _)| t)
                == Ok(umc_types::frame::FrameType::MAX_STREAM_DATA.0)),
        "MAX_STREAM_DATA emitted when the unread delta crosses half the limit"
    );
    // Read everything: the delta drops to zero.
    let (data, _) = server.read_stream(sid).expect("read");
    assert_eq!(data.len(), 200_000);
    // Deliver another 200 KiB (offsets 200_000..400_000): the delta is again
    // 200 KiB, but the NEW limit is 512 KiB and half of it is 256 KiB —
    // 200 KiB < 256 KiB, so NO re-emission. (Received-total accounting would
    // have fired here: 400 KiB total vs the old 256 KiB limit.)
    // Another 200 KiB (offsets 200_000..400_000), chunked.
    for i in 0..25u64 {
        let frame = umc_wire::frames::stream::StreamFrame {
            stream_id: sid,
            fin: false,
            offset_present: true,
            len_present: true,
            open: true,
            unidirectional: false,
            offset: 200_000 + i * 8_000,
            data: chunk.clone(),
            protocol_id: Vec::new(),
            metadata: Vec::new(),
        };
        deliver_frame(&mut client, &mut server, &frame.encode().unwrap());
    }
    let frames = server.flow_control_frames(Instant(0));
    assert!(
        !frames
            .iter()
            .any(|f| umc_wire::varint::decode(f).map(|(t, _)| t)
                == Ok(umc_types::frame::FrameType::MAX_STREAM_DATA.0)),
        "no re-emission while the unread delta stays under half the new limit"
    );
}

#[test]
fn unknown_id_reset_is_noop() {
    let (mut client, mut server) = pipe_pair();
    let reset = umc_wire::frames::stream::ResetStreamFrame {
        stream_id: 999,
        app_error_code: 0,
        final_size: 10,
    };
    deliver_frame(&mut client, &mut server, &reset.encode().unwrap());
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

/// A protected packet whose wire length is exactly `len`: the fixed
/// overhead (header byte, 8-byte DCID, path varint, 2-byte PN, 16-byte AEAD
/// tag) is 28 bytes, so the payload is `len - 28` bytes of PING + padding
/// frames (which decode cleanly on receipt).
fn sized_protected_packet(s: &mut Session, len: usize, now: Instant) -> Vec<u8> {
    let mut payload = umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap();
    payload.extend(std::iter::repeat(0x00).take(len - 28 - payload.len()));
    s.build_outbound(&TestClock, now, &payload)
        .unwrap()
        .expect("built packet")
}

#[test]
fn amplification_budget_enforced_on_unvalidated_path() {
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
    let t0 = Instant(6_000_000);
    // Path 0 exists and is UNVALIDATED (congestion.md §18: budget applies).
    server.paths.insert(
        0,
        umc_session::path::Path::new(0, "ump.udp/1".into(), vec![], vec![], t0),
    );

    // Deliver a 100-byte protected packet: 3x budget = 300 bytes.
    let pkt = sized_protected_packet(&mut client, 100, t0);
    server.on_inbound(t0, &pkt).expect("server recv");
    assert_eq!(server.path(0).expect("path 0").send_allowance(), 300);

    // 400 payload bytes exceed the 300-byte budget: refused.
    assert_eq!(
        server.build_outbound(&TestClock, t0, &vec![0u8; 400]),
        Err(umc_session::session::SessionError::AmplificationLimit)
    );
    // 300 payload bytes fit the budget exactly: allowed.
    assert!(server
        .build_outbound(&TestClock, t0, &vec![0u8; 300])
        .unwrap()
        .is_some());
}

#[test]
fn validated_path_has_no_limit() {
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
    let t0 = Instant(6_100_000);
    server.paths.insert(
        0,
        umc_session::path::Path::new(0, "ump.udp/1".into(), vec![], vec![], t0),
    );
    // Receiving 100 bytes then confirming the path: validation removes the
    // budget (session.md §26 — the 3x rule applies only before validation).
    let pkt = sized_protected_packet(&mut client, 100, t0);
    server.on_inbound(t0, &pkt).expect("server recv");
    server.force_validate(0);

    assert!(server
        .build_outbound(&TestClock, t0, &vec![0u8; 400])
        .unwrap()
        .is_some());
    assert!(server
        .build_outbound(&TestClock, t0, &vec![0u8; 2_000])
        .unwrap()
        .is_some());
}

#[test]
fn ack_payloads_exempt() {
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
    let t0 = Instant(6_200_000);
    server.paths.insert(
        0,
        umc_session::path::Path::new(0, "ump.udp/1".into(), vec![], vec![], t0),
    );

    // The ACK payload comes from the normal on_inbound ack path.
    let pkt = sized_protected_packet(&mut client, 100, t0);
    let ack_payload = server.on_inbound(t0, &pkt).expect("server recv");
    assert!(!ack_payload.is_empty(), "server must ACK");

    // Exhaust the 300-byte budget with two 300-byte data sends (the first
    // also charges ~28 bytes of wire overhead, so the budget is empty).
    assert!(server
        .build_outbound(&TestClock, t0, &vec![0u8; 300])
        .unwrap()
        .is_some());
    assert_eq!(
        server.build_outbound(&TestClock, t0, &vec![0u8; 300]),
        Err(umc_session::session::SessionError::AmplificationLimit)
    );
    // A data build is refused, but the ACK still goes out (congestion.md
    // §18: refusing an ACK would stall the protocol).
    assert!(server
        .build_outbound(&TestClock, t0, &ack_payload)
        .unwrap()
        .is_some());
}

/// A `RESET_STREAM` payload for a protected packet (wire-format.md §18.5).
fn reset_stream_payload(stream_id: u64, final_size: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    umc_wire::varint::encode_into(&mut payload, umc_types::frame::FrameType::RESET_STREAM.0)
        .unwrap();
    let frame = umc_wire::frames::stream::ResetStreamFrame {
        stream_id,
        app_error_code: 0,
        final_size,
    };
    let enc = frame.encode().unwrap();
    payload.extend_from_slice(&enc[1..]);
    payload
}

/// A `STOP_SENDING` payload for a protected packet (wire-format.md §18.5).
fn stop_sending_payload(stream_id: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    umc_wire::varint::encode_into(&mut payload, umc_types::frame::FrameType::STOP_SENDING.0)
        .unwrap();
    let frame = umc_wire::frames::stream::StopSendingFrame {
        stream_id,
        app_error_code: 0,
    };
    let enc = frame.encode().unwrap();
    payload.extend_from_slice(&enc[1..]);
    payload
}

/// A `STREAM` payload for a protected packet, at an explicit offset.
fn stream_payload_at(stream_id: u64, offset: u64, data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    umc_wire::varint::encode_into(&mut payload, umc_types::frame::FrameType::STREAM.0).unwrap();
    let frame = umc_wire::frames::stream::StreamFrame {
        stream_id,
        fin: false,
        offset_present: true,
        len_present: true,
        open: offset == 0,
        unidirectional: false,
        offset,
        data: data.to_vec(),
        protocol_id: vec![],
        metadata: vec![],
    };
    let enc = frame.encode().unwrap();
    payload.extend_from_slice(&enc[1..]);
    payload
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

#[test]
fn flow_credit_emitted_at_half_consumption() {
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
            initial_max_data: 100_000,
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
            initial_max_data: 300_000,
            initial_max_stream_data: 256 * 1024,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .expect("server session");
    let t0 = Instant(8_000_000);
    // Deliver two 40 KiB segments: 80 KiB consumed of the 100 KiB
    // connection credit, and of the 100 KiB per-stream limit the server
    // grants a new inbound stream (session.md §20: credit is re-granted at
    // the half-consumed watermark, doubling the limit). Each segment fits a
    // 65 535-byte packet (MAX_PACKET_SIZE).
    // Consume past half of BOTH limits: the connection limit is 100 000
    // (half 50 000) and the per-stream limit is 256 KiB (half 128 000).
    for offset in [0u64, 40_000, 80_000, 120_000] {
        let payload = stream_payload_at(0, offset, &vec![0x61; 40_000]);
        let pkt = client
            .build_outbound(&TestClock, t0, &payload)
            .unwrap()
            .unwrap();
        server.on_inbound(t0, &pkt).unwrap();
    }
    let frames = server.flow_control_frames(t0);
    assert!(
        !frames.is_empty(),
        "credit exhausted past half: frames expected"
    );
    let decoded: Vec<umc_wire::frame::Frame> = frames
        .iter()
        .flat_map(|f| umc_wire::frame::decode_frames(f).unwrap())
        .collect();
    assert!(
        decoded.iter().any(
            |f| matches!(f, umc_wire::frame::Frame::MaxData(md) if md.maximum_data == 600_000)
        ),
        "MAX_DATA must double the connection limit"
    );
    assert!(
        decoded.iter().any(|f| matches!(
            f,
            umc_wire::frame::Frame::MaxStreamData(msd)
                if msd.stream_id == 0 && msd.maximum_stream_data == 512 * 1024
        )),
        "MAX_STREAM_DATA must double the per-stream limit"
    );
    // Nothing is emitted again until the next half is consumed.
    assert!(
        server.flow_control_frames(t0).is_empty(),
        "granted credit is not re-emitted"
    );
}

#[test]
fn reset_stream_marks_recv_reset() {
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
    let t0 = Instant(8_100_000);
    // Stream 0 carries data the server has not read yet.
    let payload = stream_payload(0, b"partial");
    let pkt = client
        .build_outbound(&TestClock, t0, &payload)
        .unwrap()
        .unwrap();
    server.on_inbound(t0, &pkt).unwrap();
    // The peer resets its send side (session.md §18.5): our recv side is
    // reset, buffered data becomes unreachable, and reading reports it.
    let reset = reset_stream_payload(0, 7);
    let pkt = client
        .build_outbound(&TestClock, t0, &reset)
        .unwrap()
        .unwrap();
    server.on_inbound(t0, &pkt).unwrap();
    assert_eq!(
        server.read_stream(0),
        Err(umc_session::session::SessionError::Stream(
            umc_session::stream::StreamError::ResetByPeer
        ))
    );
    // No further data is accepted on the reset stream.
    let payload = stream_payload(0, b"more");
    let pkt = client
        .build_outbound(&TestClock, t0, &payload)
        .unwrap()
        .unwrap();
    assert_eq!(
        server.on_inbound(t0, &pkt),
        Err(umc_session::session::SessionError::StreamClosed)
    );
    // A retransmitted RESET_STREAM is idempotent.
    let pkt = client
        .build_outbound(&TestClock, t0, &reset)
        .unwrap()
        .unwrap();
    assert!(server.on_inbound(t0, &pkt).is_ok());
}

#[test]
fn stop_sending_marks_send_stopped() {
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
    let t0 = Instant(8_200_000);
    let sid = client.open_stream().expect("stream");
    let payload = client.send_stream_data(sid, b"hello", false).expect("send");
    assert!(client
        .build_outbound(&TestClock, t0, &payload)
        .unwrap()
        .is_some());
    // The peer stops reading our send side (session.md §18.5): sending more
    // data is refused from then on.
    let stop = stop_sending_payload(sid);
    let pkt = server
        .build_outbound(&TestClock, t0, &stop)
        .unwrap()
        .unwrap();
    client.on_inbound(t0, &pkt).unwrap();
    assert_eq!(
        client.streams[&sid].send_state,
        umc_session::stream::SendState::ResetSent
    );
    assert_eq!(
        client.send_stream_data(sid, b"more", false),
        Err(umc_session::session::SessionError::Stream(
            umc_session::stream::StreamError::AlreadyClosed
        ))
    );
}
