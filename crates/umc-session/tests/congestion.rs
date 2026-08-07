//! Congestion controller conformance (congestion.md §24.1): slow start,
//! congestion avoidance, loss-driven window reduction, in-flight bounds,
//! the `2 × SMSS` floor, and the session-level send gate.
// The controller counts in `SMSS` u64 units; the tests build usize values
// from it, which is lossless on every supported platform (64-bit).
#![allow(clippy::cast_possible_truncation)]
use umc_session::congestion::{CongestionController, RenoCongestionController, SMSS};
use umc_session::session::{Role, Session, SessionConfig, SessionError, DEFAULT_DCID_LEN};
use umc_types::runtime::{Clock, Instant};

struct TestClock;

impl Clock for TestClock {
    fn now(&self) -> Instant {
        Instant(0)
    }
}

/// Mock controller with a fixed allowance, for the session gate test.
struct FixedAllowance(usize);

impl CongestionController for FixedAllowance {
    fn on_ack(&mut self, _newly_acked_bytes: usize) {}
    fn on_loss(&mut self, _lost_bytes: usize) {}
    fn on_packet_sent(&mut self, _bytes: usize) {}
    fn on_packet_acknowledged(&mut self, _bytes: usize) {}
    fn on_packet_lost(&mut self, _bytes: usize) {}
    fn send_allowance(&self) -> usize {
        self.0
    }
    fn cwnd(&self) -> usize {
        self.0
    }
    fn in_flight(&self) -> usize {
        0
    }
    fn reset(&mut self) {}
}

fn session() -> Session {
    Session::new(
        SessionConfig {
            role: Role::Server,
            dcid: vec![0u8; DEFAULT_DCID_LEN],
            local_traffic_secret: [1u8; 32],
            remote_traffic_secret: [2u8; 32],
            initial_max_data: 1_000_000,
            initial_max_stream_data: 256 * 1024,
            max_ack_delay_ms: 25,
        },
        &TestClock,
    )
    .expect("session")
}

#[test]
fn slow_start_doubles_cwnd() {
    let mut c = RenoCongestionController::new();
    assert_eq!(c.cwnd(), 10 * SMSS as usize);
    // Slow start grows the window by one maximum packet per acknowledged
    // packet (congestion.md §14.2): 10 SMSS-sized packets double it.
    for _ in 0..10 {
        c.on_ack(SMSS as usize);
    }
    assert_eq!(c.cwnd(), 20 * SMSS as usize);
}

#[test]
fn congestion_avoidance_additive() {
    let mut c = RenoCongestionController::new();
    // A loss halves the window: ssthresh = cwnd/2 and cwnd = ssthresh, so
    // the next ack is handled in congestion avoidance.
    c.on_loss(0);
    assert_eq!(c.cwnd(), 5 * SMSS as usize);
    // Above ssthresh the window grows additively (congestion.md §14.3):
    // cwnd += SMSS * acked / cwnd = 1200 * 12000 / 6000 = 2400.
    c.on_ack(10 * SMSS as usize);
    assert_eq!(c.cwnd(), (5 * SMSS + 2 * SMSS) as usize);
}

#[test]
fn loss_halves_cwnd() {
    let mut c = RenoCongestionController::new();
    // Grow the window first (slow start): 20 × SMSS.
    c.on_ack(10 * SMSS as usize);
    assert_eq!(c.cwnd(), 20 * SMSS as usize);
    // Isolated losses do not react; the third consecutive lost packet
    // triggers the Reno reduction (congestion.md §14.4): ssthresh =
    // max(cwnd/2, 2×SMSS), cwnd = ssthresh.
    c.on_packet_lost(SMSS as usize);
    c.on_packet_lost(SMSS as usize);
    assert_eq!(c.cwnd(), 20 * SMSS as usize);
    c.on_packet_lost(SMSS as usize);
    assert_eq!(c.cwnd(), 10 * SMSS as usize);
    // The window is now AT ssthresh: the next ack grows additively
    // (1200 * 1200 / 12000 = 120 bytes), not multiplicatively.
    c.on_ack(SMSS as usize);
    assert_eq!(c.cwnd(), (10 * SMSS + 120) as usize);
}

#[test]
fn in_flight_bounds_sends() {
    let mut c = RenoCongestionController::new();
    assert_eq!(c.send_allowance(), 10 * SMSS as usize);
    // Sending charges in-flight: the allowance shrinks.
    c.on_packet_sent(4 * SMSS as usize);
    assert_eq!(c.in_flight(), 4 * SMSS as usize);
    assert_eq!(c.send_allowance(), 6 * SMSS as usize);
    // Acking a packet releases its bytes from in-flight...
    c.on_packet_acknowledged(3 * SMSS as usize);
    assert_eq!(c.send_allowance(), 9 * SMSS as usize);
    // ...and the ack grows the window in slow start: allowance = cwnd −
    // in_flight.
    c.on_ack(3 * SMSS as usize);
    assert_eq!(c.send_allowance(), 12 * SMSS as usize);
    // The allowance clamps at zero; in-flight can exceed cwnd after loss.
    c.on_packet_sent(50 * SMSS as usize);
    assert_eq!(c.send_allowance(), 0);
}

#[test]
fn cwnd_floor_two_smss() {
    let mut c = RenoCongestionController::new();
    // Loss events halve the window down to the 2 × SMSS floor
    // (congestion.md §14.1 minimum_cwnd): 12000 → 6000 → 3000 → 2400.
    for _ in 0..3 {
        c.on_loss(0);
    }
    assert_eq!(c.cwnd(), 2 * SMSS as usize);
    // Further loss cannot push the window below the floor.
    c.on_loss(0);
    assert_eq!(c.cwnd(), 2 * SMSS as usize);
}

/// A valid ACK frame payload (type, largest, delay, range count, first
/// range).
fn ack_payload() -> Vec<u8> {
    let mut out = Vec::new();
    umc_wire::varint::encode_into(&mut out, umc_types::frame::FrameType::ACK.0).expect("ack type");
    for field in [0u64, 0, 1, 1] {
        umc_wire::varint::encode_into(&mut out, field).expect("ack field");
    }
    out
}

#[test]
fn congestion_gate_blocks_above_allowance() {
    let mut s = session();
    s.set_congestion_controller(Box::new(FixedAllowance(100)));
    let sid = s.open_stream().expect("stream");
    // A 200-byte data payload exceeds the 100-byte allowance: refused.
    let payload = s
        .send_stream_data(sid, &[0xAB; 200], false)
        .expect("data payload");
    assert!(payload.len() > 100);
    assert_eq!(
        s.build_outbound(&TestClock, Instant(0), &payload),
        Err(SessionError::CongestionLimited)
    );
    // Within the allowance the same data path builds fine.
    let small = s
        .send_stream_data(sid, &[0xAB; 50], false)
        .expect("data payload");
    assert!(small.len() <= 100);
    assert!(s
        .build_outbound(&TestClock, Instant(0), &small)
        .expect("build")
        .is_some());
    // ACK payloads are exempt, with the same exemption as the
    // anti-amplification gate (congestion.md §7.3 control reserve).
    let ack = ack_payload();
    assert!(s
        .build_outbound(&TestClock, Instant(0), &ack)
        .expect("build")
        .is_some());
}
