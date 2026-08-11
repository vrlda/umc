//! Phase 13 DoS-resilience (resource-limits.md §49, threat-model.md
//! scenarios 8/12/21): oversized Initials are rejected in bounded time,
//! handshake floods are rate-limited per DCID, unknown optional frame types
//! are skipped while critical types fail closed, and a closed session stops
//! producing output.
use umc_crypto::aead::PacketKeys;
use umc_handshake::initial::{build_initial_packet, derive_initial_keys, try_parse_initial};
use umc_handshake::tracker::{HandshakeTracker, TrackerError};
use umc_session::packet::build_protected_packet;
use umc_session::session::{Role, Session, SessionConfig, SessionState};
use umc_types::runtime::{Clock, Instant};
use umc_types::version::PROTOCOL_VERSION;
use umc_wire::frame::{ConnectionCloseFrame, Frame, FrameError};
use umc_wire::header::ShortPacketSpace;
use umc_wire::packet::{parse_payload, PacketContext};

#[derive(Debug)]
struct FakeClock(Instant);

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        self.0
    }
}

/// Synthetic client Initial packet: valid long header + sealed payload
/// (the mirror image of `try_parse_initial`).
fn build_initial(dcid: &[u8], pn: u64, payload: &[u8]) -> Vec<u8> {
    let keys = derive_initial_keys(dcid).client;
    build_initial_packet(dcid, &[], pn, payload, &keys).expect("initial packet")
}

#[test]
fn oversized_initial_packets_rejected() {
    let base = build_initial(&[1u8; 8], 0, b"hello");
    assert!(
        try_parse_initial(&base).is_some(),
        "sanity: a normal Initial packet parses"
    );
    // Growth past the maximum packet size (65_535) must be rejected without
    // panicking or allocating from the untrusted payload length.
    for extra in [16_384usize, 32_768, 48_576, 65_536, 131_072] {
        let mut big = base.clone();
        big.extend(std::iter::repeat_n(0x00u8, extra));
        assert_eq!(
            try_parse_initial(&big),
            None,
            "Initial of {} bytes must be rejected",
            big.len()
        );
    }
    // Fully random buffers of 64 KiB and 1 MiB: rejected, not crashed.
    assert_eq!(try_parse_initial(&vec![0xA5u8; 65_536]), None);
    assert_eq!(try_parse_initial(&vec![0xA5u8; 1_048_576]), None);
    // A hostile token length must fail the bounds check, never allocate.
    let mut evil = vec![0x80];
    evil.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    evil.push(8);
    evil.extend_from_slice(&[0u8; 8]);
    evil.push(0);
    evil.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(try_parse_initial(&evil), None);
}

#[test]
fn rapid_hello_attempts_rate_limited() {
    let mut tracker = HandshakeTracker::new(3);
    let dcid = [9u8; 8];
    for _ in 0..3 {
        assert_eq!(tracker.register(&dcid), Ok(()), "first three attempts pass");
    }
    assert_eq!(
        tracker.register(&dcid),
        Err(TrackerError::LimitExceeded),
        "the fourth attempt per DCID is refused"
    );
    // A fresh DCID gets its own budget: the flood is per connection id.
    assert!(tracker.register(&[8u8; 8]).is_ok());
}

#[test]
fn unknown_frame_types_follow_extension_behavior() {
    // 0x3F is optional length-delimited and self-delimiting, so it is skipped
    // while the known frames around it stay intact.
    let mut payload = Vec::new();
    payload.push(0x04); // PING
    payload.extend_from_slice(&[0x3F, 0x01, 0xCC]); // unknown, len 1
    payload.push(0x04); // PING
    let parsed = parse_payload(
        &PacketContext::Protected(ShortPacketSpace::SessionData),
        &payload,
    )
    .expect("unknown optional frames must be skipped");
    assert_eq!(parsed.frames, vec![Frame::Ping, Frame::Ping]);
    // 0x3E is critical length-delimited and must fail closed even though its
    // body is self-delimiting.
    assert_eq!(
        parse_payload(
            &PacketContext::Protected(ShortPacketSpace::SessionData),
            &[0x3E, 0x02, 0xAA, 0xBB, 0x04],
        ),
        Err(umc_wire::packet::PacketError::Frame(
            FrameError::UnknownCriticalFrame(umc_types::frame::FrameType(0x3E)),
        ))
    );
    // A truncated declared body is an error, never a panic.
    assert!(parse_payload(
        &PacketContext::Protected(ShortPacketSpace::SessionData),
        &[0x3F, 0x10, 0x01],
    )
    .is_err());
}

#[test]
fn session_close_releases_state() {
    let config = SessionConfig {
        role: Role::Client,
        dcid: vec![7u8; 8],
        local_traffic_secret: [1u8; 32],
        remote_traffic_secret: [2u8; 32],
        initial_max_data: 1 << 20,
        initial_max_stream_data: 1 << 16,
        max_ack_delay_ms: 25,
    };
    let mut session = Session::new(config, &FakeClock(Instant(0))).unwrap();
    let keys = PacketKeys::from_traffic_secret(&[2u8; 32]).unwrap();
    let frame = ConnectionCloseFrame {
        error_code: 0x02,
        trigger_frame_type: 0x10,
        reason: b"shutdown".to_vec(),
    };
    let payload = frame.encode().expect("close frame");
    let pkt = build_protected_packet(
        &keys,
        &umc_crypto::header_protection::header_protection_key(&[2u8; 32]),
        ShortPacketSpace::SessionData,
        &[7u8; 8],
        0,
        0,
        false,
        &payload,
    )
    .expect("packet");
    session
        .on_inbound(Instant(0), &pkt)
        .expect("close processes");
    assert_eq!(session.state, SessionState::Closed);
    assert_eq!(
        session.build_outbound(&FakeClock(Instant(0)), Instant(0), &[]),
        Ok(None),
        "a closed session must not build further packets"
    );
}
