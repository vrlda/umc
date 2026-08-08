//! Congestion controller conformance (congestion.md §24.1): slow start,
//! congestion avoidance, loss-driven window reduction, in-flight bounds,
//! the `2 × SMSS` floor, and the session-level send gate.
// The controller counts in `SMSS` u64 units; the tests build usize values
// from it, which is lossless on every supported platform (64-bit).
#![allow(clippy::cast_possible_truncation)]
use umc_session::ack::MAX_OUTSTANDING_PACKETS;
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

/// Mock controller that tracks in-flight accounting, for the cap-eviction
/// test: the session's accounting is under test, not the window math.
#[derive(Default)]
struct TrackingCongestion {
    in_flight: usize,
}

impl CongestionController for TrackingCongestion {
    fn on_ack(&mut self, _newly_acked_bytes: usize) {}
    fn on_loss(&mut self, _lost_bytes: usize) {}
    fn on_packet_sent(&mut self, bytes: usize) {
        self.in_flight += bytes;
    }
    fn on_packet_acknowledged(&mut self, bytes: usize) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
    }
    fn on_packet_lost(&mut self, bytes: usize) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
    }
    fn send_allowance(&self) -> usize {
        usize::MAX
    }
    fn cwnd(&self) -> usize {
        usize::MAX
    }
    fn in_flight(&self) -> usize {
        self.in_flight
    }
    fn reset(&mut self) {
        self.in_flight = 0;
    }
}

/// The encoded STREAM-frame payload for `n` data bytes on a fresh offset.
fn stream_payload(s: &mut Session, sid: u64, n: usize) -> Vec<u8> {
    let data = vec![0xAB; n];
    s.send_stream_data(sid, &data, false).expect("data payload")
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
    // Within the allowance — counting the protected packet overhead — the
    // same data path builds fine.
    let small = stream_payload(&mut s, sid, 20);
    assert!(small.len() + 64 <= 100, "payload plus overhead fits");
    assert!(s
        .build_outbound(&TestClock, Instant(0), &small)
        .expect("build")
        .is_some());
    // The gate measures the protected packet size, not the raw payload: a
    // payload that fits by itself but not with its packet overhead is
    // refused (the wire bytes charge in-flight, so they must fit).
    let near = stream_payload(&mut s, sid, 40);
    assert!(near.len() <= 100, "payload alone fits the allowance");
    assert!(near.len() + 64 > 100, "payload plus overhead does not");
    assert_eq!(
        s.build_outbound(&TestClock, Instant(0), &near),
        Err(SessionError::CongestionLimited)
    );
    // ACK payloads are exempt, with the same exemption as the
    // anti-amplification gate (congestion.md §7.3 control reserve).
    let ack = ack_payload();
    assert!(s
        .build_outbound(&TestClock, Instant(0), &ack)
        .expect("build")
        .is_some());
}

#[test]
fn pto_probe_bypasses_congestion_gate() {
    let mut s = session();
    // Zero allowance: the send gate is fully shut (congestion.md §7.1)...
    s.set_congestion_controller(Box::new(FixedAllowance(0)));
    // ...but the PTO probe PING is control traffic (congestion.md §7.3
    // control reserve): with in_flight == cwnd nothing else may be sent, so
    // refusing the probe would stall recovery permanently.
    let ping = umc_wire::varint::encode(umc_types::frame::FrameType::PING.0).unwrap();
    assert!(s
        .build_outbound(&TestClock, Instant(0), &ping)
        .expect("probe build")
        .is_some());
}

#[test]
fn isolated_losses_separated_by_acks_do_not_halve() {
    let mut c = RenoCongestionController::new();
    // Three isolated losses, each broken by an ACK, must not trip the
    // three-strike halving (congestion.md §14.4): an ACK in between proves
    // the streak was reordering, not loss.
    c.on_packet_lost(SMSS as usize);
    c.on_ack(SMSS as usize);
    c.on_packet_lost(SMSS as usize);
    c.on_ack(SMSS as usize);
    c.on_packet_lost(SMSS as usize);
    // No halving: the window only grew by the two slow-start acks.
    assert_eq!(c.cwnd(), 10 * SMSS as usize + 2 * SMSS as usize);
}

#[test]
fn cap_eviction_releases_in_flight_bytes() {
    let mut s = session();
    s.set_congestion_controller(Box::new(TrackingCongestion::default()));
    // Fill the outstanding queue to the cap, then one more build evicts the
    // oldest packet (pn 0); the cap test fills beyond any Reno window, so
    // the tracking controller never limits.
    let mut charged = 0usize;
    let mut evicted_size = 0usize;
    for i in 0..=MAX_OUTSTANDING_PACKETS as u64 {
        let pkt = s
            .build_outbound(&TestClock, Instant(i), b"x")
            .unwrap()
            .expect("built packet");
        charged += pkt.len();
        if i == 0 {
            evicted_size = pkt.len();
        }
    }
    // The cap eviction (resource-limits.md §24) releases the evicted
    // packet's bytes from in-flight: the packet is gone from the sent queue,
    // so keeping its bytes charged would leak the window forever.
    assert_eq!(s.congestion_mut().in_flight(), charged - evicted_size);
    // A full cycle nets zero: acknowledging every surviving packet releases
    // the rest, and in-flight returns to 0.
    let ack = umc_wire::frame::AckFrame {
        largest_acknowledged: MAX_OUTSTANDING_PACKETS as u64,
        ack_delay: 0,
        first_ack_range: MAX_OUTSTANDING_PACKETS as u64,
        additional_ranges: Vec::new(),
    };
    s.apply_peer_ack(&ack, Instant(0)).unwrap();
    assert_eq!(s.congestion_mut().in_flight(), 0);
}

#[test]
fn pacing_rate_matches_cwnd_over_rtt() {
    let mut c = RenoCongestionController::new();
    assert_eq!(c.cwnd(), 10 * SMSS as usize);
    // Uninitialized RTT: no pacing (congestion.md §12.2) — the rate is 0,
    // which means unlimited, and every send is immediate.
    assert_eq!(c.pacing_rate_bps(), 0);
    assert_eq!(c.next_send_time(Instant(0), SMSS as usize), None);
    // A 12,000-byte window over a 100 ms RTT: cwnd × 8 × 1000 / rtt =
    // 12000 × 8000 / 100 = 960,000 bits/s. The burst is capped at
    // min(cwnd / 2, 10 × SMSS) = min(6000, 12000) = 6000 bytes and the
    // freshly enabled bucket starts full at that cap.
    c.set_smoothed_rtt(100, Instant(0));
    assert_eq!(c.pacing_rate_bps(), 960_000);
    assert_eq!(c.pacing_burst_bytes(), 6_000);
    assert_eq!(c.pacing_tokens(), 6_000);
}

#[test]
fn burst_cap_limits_tokens() {
    let mut c = RenoCongestionController::new();
    c.set_smoothed_rtt(100, Instant(0));
    // Drain the bucket completely.
    c.consume_pacing(6_000, Instant(0));
    assert_eq!(c.pacing_tokens(), 0);
    // A long idle (an hour) refills the bucket, but only up to the burst
    // allowance (congestion.md §12.2 "limit bursts"): the effective tokens
    // are exactly 6000, so a 12,000-byte packet waits for the remaining
    // 6000 × 8000 / 960000 = 50 ms. An uncapped bucket would have refilled
    // 43 GB and sent instantly.
    let now = Instant(3_600_000);
    let wait = c
        .next_send_time(now, 12_000)
        .expect("pacing active after a sample");
    assert_eq!(wait.duration_since(now).as_millis(), 50);
}

#[test]
fn next_send_time_delays_when_tokens_insufficient() {
    let mut c = RenoCongestionController::new();
    c.set_smoothed_rtt(100, Instant(0));
    c.consume_pacing(6_000, Instant(0));
    assert_eq!(c.pacing_tokens(), 0);
    // With an empty bucket a 1200-byte packet waits 1200 × 8000 / 960000 =
    // 10 ms — the deficit is refilled at the pacing rate.
    let now = Instant(0);
    let wait = c
        .next_send_time(now, 1_200)
        .expect("pacing active after a sample");
    assert_eq!(wait.duration_since(now).as_millis(), 10);
}

#[test]
fn no_pacing_without_rtt() {
    let mut c = RenoCongestionController::new();
    // Sent traffic without any RTT sample: the rate stays 0 (unlimited)
    // and no send is ever delayed, whatever the window or the bucket.
    c.on_packet_sent(SMSS as usize);
    assert_eq!(c.pacing_rate_bps(), 0);
    assert_eq!(c.next_send_time(Instant(5), 1_200), None);
    // An explicit zero RTT (the session estimator before its first sample)
    // behaves identically.
    c.set_smoothed_rtt(0, Instant(0));
    assert_eq!(c.pacing_rate_bps(), 0);
    assert_eq!(c.next_send_time(Instant(5), 1_200), None);
}

#[test]
fn pacing_rate_tracks_window_changes() {
    let mut c = RenoCongestionController::new();
    c.set_smoothed_rtt(100, Instant(0));
    assert_eq!(c.pacing_rate_bps(), 960_000);
    // A loss halves the window: the pacing rate and burst follow the new
    // window (congestion.md §12): 6000 × 8000 / 100 = 480,000 bits/s and
    // min(3000, 12000) = 3000 bytes.
    c.on_loss(0);
    assert_eq!(c.cwnd(), 5 * SMSS as usize);
    assert_eq!(c.pacing_rate_bps(), 480_000);
    assert_eq!(c.pacing_burst_bytes(), 3_000);
    // The existing tokens are clamped to the shrunken burst.
    assert!(c.pacing_tokens() <= 3_000);
}

#[test]
fn reset_clears_pacing() {
    let mut c = RenoCongestionController::new();
    c.set_smoothed_rtt(100, Instant(0));
    assert_eq!(c.pacing_rate_bps(), 960_000);
    // Restart clears congestion state (congestion.md §24.21): the pacing
    // rate resets to 0 (unlimited) until a fresh RTT sample arrives.
    c.reset();
    assert_eq!(c.pacing_rate_bps(), 0);
    assert_eq!(c.next_send_time(Instant(0), 1_200), None);
}

#[test]
fn retransmit_gated_keeps_payload() {
    let mut s = session();
    let sid = s.open_stream().expect("stream");
    // Fill the window: in-flight reaches the initial 10 × SMSS cwnd and the
    // gate shuts.
    let mut pkt_len = 0;
    loop {
        let payload = stream_payload(&mut s, sid, 25);
        match s.build_outbound(&TestClock, Instant(0), &payload) {
            Ok(Some(pkt)) => pkt_len = pkt.len(),
            Err(SessionError::CongestionLimited) => break,
            other => panic!("unexpected build result: {other:?}"),
        }
    }
    // Three consecutive losses halve the window (LOSS_THRESHOLD = 3); the
    // gate stays shut: in-flight still exceeds the halved cwnd.
    for _ in 0..3 {
        s.congestion_mut().on_packet_lost(pkt_len);
    }
    assert_eq!(s.congestion_mut().send_allowance(), 0);
    // The gate is shut: retransmitting the first packet is refused...
    assert_eq!(
        s.retransmit(0, Instant(0)),
        Err(SessionError::CongestionLimited)
    );
    // ...and the payload must SURVIVE the refused attempt (session.md
    // §14.3): once the controller recovers, the same packet number
    // retransmits fine.
    s.congestion_mut().on_packet_acknowledged(5 * SMSS as usize);
    assert!(
        s.retransmit(0, Instant(0)).expect("retransmit").is_some(),
        "payload survives a gated retransmit"
    );
}
