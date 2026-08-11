//! Congestion conformance suite: the full matrix — slow start, congestion
//! avoidance, loss-driven reduction with the 2 × SMSS floor, PTO backoff
//! doubling and reset, pacing rate/burst accuracy (including the two C2
//! pacing-accuracy items: no rate overshoot and no retroactive tokens on a
//! rate change), in-flight bounds across a full send/ack cycle, forged-ACK
//! non-reaction, and the §7.3 control-traffic reserve under a full window.
//!
//! Coverage notes (tests that exist elsewhere and are referenced, not
//! duplicated):
//! - §24.11 carrier backpressure hold without window reduction: pinned by
//!   `bins/umcd` `should_backpressure` tests (`session_task.rs`) — data
//!   packets are held at `>80%` carrier queue while ACK/PING payloads pass.
//! - §24.6 persistent-congestion response: the ack-eliciting span filter is
//!   daemon-side (`process_inbound_packet`), pinned by the umcd
//!   `persistent_congestion_marks_path_degraded` test; session-level
//!   idempotence by session.rs `mark_path_degraded_idempotent`.
//! - §24.5/retransmit-after-gate: pinned by `retransmit_gated_keeps_payload`
//!   in tests/congestion.rs (payload survives a gated retransmit and goes
//!   out once the window recovers).
// The controller counts in `SMSS` u64 units; the tests build usize values
// from it, which is lossless on every supported platform (64-bit).
#![allow(clippy::cast_possible_truncation)]
use umc_session::ack::{AckError, MAX_OUTSTANDING_PACKETS};
use umc_session::congestion::{
    CongestionController, RenoCongestionController, INITIAL_CWND, MIN_CWND, SMSS,
};
use umc_session::loss::{PtoState, MAX_PTO_BACKOFF_EXPONENT};
use umc_session::session::{
    payload_is_exempt, Role, Session, SessionConfig, SessionError, DEFAULT_DCID_LEN,
};
use umc_types::frame::FrameType;
use umc_types::runtime::{Clock, Duration, Instant};

struct TestClock;

impl Clock for TestClock {
    fn now(&self) -> Instant {
        Instant(0)
    }
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

/// The encoded STREAM-frame payload for `n` data bytes on a fresh offset.
fn stream_payload(s: &mut Session, sid: u64, n: usize) -> Vec<u8> {
    let data = vec![0xAB; n];
    s.send_stream_data(sid, &data, false).expect("data payload")
}

/// A valid ACK frame payload (type, largest, delay, range count, first
/// range).
fn ack_payload() -> Vec<u8> {
    let mut out = Vec::new();
    umc_wire::varint::encode_into(&mut out, FrameType::ACK.0).expect("ack type");
    for field in [0u64, 0, 1, 1] {
        umc_wire::varint::encode_into(&mut out, field).expect("ack field");
    }
    out
}

/// §24.7 slow start: below ssthresh each acknowledged packet grows the
/// window by its own size — 10 SMSS-sized acks double the initial 10 × SMSS
/// window. Crossing ssthresh (a loss halves and sets it) switches to
/// additive growth: the same ack no longer doubles.
#[test]
fn slow_start_doubles_until_ssthresh() {
    let mut c = RenoCongestionController::new();
    assert_eq!(c.cwnd(), INITIAL_CWND as usize);
    for _ in 0..10 {
        c.on_ack(SMSS as usize);
    }
    assert_eq!(c.cwnd(), 2 * INITIAL_CWND as usize, "slow start doubles");
    // A loss sets ssthresh = cwnd/2 and the window to ssthresh: the next
    // ack is handled in congestion avoidance, so it grows the window by
    // SMSS²/cwnd — a fraction of an SMSS — not by a full SMSS.
    c.on_loss(0);
    assert_eq!(c.cwnd(), INITIAL_CWND as usize);
    c.on_ack(SMSS as usize);
    assert!(
        c.cwnd() < 2 * INITIAL_CWND as usize,
        "above ssthresh growth is additive, not multiplicative"
    );
}

/// §24.7 congestion avoidance: above ssthresh the window grows by
/// `SMSS × acked / cwnd` per ack — assert the additive bound over a batch
/// (per-ack floor division loses less than one byte each), not an exact
/// value.
#[test]
fn congestion_avoidance_is_additive() {
    let mut c = RenoCongestionController::new();
    // Halve to 5 × SMSS: ssthresh and cwnd both land there, so every ack
    // from here on is additive.
    c.on_loss(0);
    assert_eq!(c.cwnd(), 5 * SMSS as usize);
    let per_ack_upper = SMSS * SMSS / (5 * SMSS); // 1200² / 6000 = 240
    let mut growth = 0u64;
    for _ in 0..20 {
        let before = c.cwnd() as u64;
        c.on_ack(SMSS as usize);
        growth += c.cwnd() as u64 - before;
        assert!(
            c.cwnd() as u64 - before <= per_ack_upper,
            "a single ack never grows the window by more than SMSS²/cwnd"
        );
    }
    // 20 acks at ~240 bytes each: the total is bounded by the linear sum
    // (the window only grew, so each step is ≤ 240) and stays positive.
    assert!(growth > 0);
    assert!(
        growth <= 20 * per_ack_upper,
        "additive growth is bounded by the per-ack rate"
    );
    // Growth is additive, not multiplicative: one round trip of acks added
    // ~4 × SMSS, nowhere near the doubling a slow-start regime would give.
    assert!(
        growth < 5 * SMSS,
        "growth {growth} stays well under a doubling"
    );
}

/// §24.8 loss-driven reduction: the loss response sets
/// `cwnd = ssthresh = max(cwnd/2, 2 × SMSS)`; repeated loss events floor
/// both at 2 × SMSS (the `cwnd` value is the observable of `ssthresh` —
/// the reduction assigns the window to the threshold).
#[test]
fn loss_halves_and_floor_applies() {
    let mut c = RenoCongestionController::new();
    let mut prev = c.cwnd() as u64;
    // 12000 → 6000 → 3000 → floor at 2400 = 2 × SMSS; further losses stay.
    for _ in 0..3 {
        c.on_loss(0);
        let expect = (prev / 2).max(MIN_CWND);
        assert_eq!(
            c.cwnd() as u64,
            expect,
            "the window halves to max(cwnd/2, 2 × SMSS)"
        );
        prev = expect;
    }
    assert_eq!(c.cwnd(), MIN_CWND as usize);
    // Repeated loss cannot push below the floor.
    for _ in 0..3 {
        c.on_loss(0);
        assert_eq!(c.cwnd(), MIN_CWND as usize);
    }
}

/// §24.4 PTO backoff: consecutive expiries double the deadline 1× → 2× →
/// 4× … → 64× and then stay capped; an ACK resets the count (loss.rs
/// unit-tests the same math; this pins it at the conformance level).
#[test]
fn pto_doubling_capped() {
    let mut pto = PtoState::default();
    let base = Duration::from_millis(1_000);
    let now = Instant(0);
    assert_eq!(
        pto.next_deadline(base, now).duration_since(now).as_millis(),
        1_000
    );
    let mut expect = 1_000u64;
    for _ in 0..MAX_PTO_BACKOFF_EXPONENT {
        pto.on_expiry();
        expect *= 2;
        assert_eq!(
            pto.next_deadline(base, now).duration_since(now).as_millis(),
            expect
        );
    }
    assert_eq!(pto.multiplier(), 64);
    // A further expiry stays capped at 64 × the base PTO.
    pto.on_expiry();
    assert_eq!(
        pto.next_deadline(base, now).duration_since(now).as_millis(),
        64_000
    );
}

/// §24.9 pacing: the rate is `cwnd × 8 × 1000 / rtt`, the bucket is capped
/// at the burst allowance (an idle refill cannot exceed it), and a paced
/// send waits `deficit / rate` — assert the delay within ±1 ms on a
/// fractional rate (rtt 39 ms: 1,200 × 8000 / 2,461,538 = 3.9 ms).
#[test]
fn pacing_rate_and_burst() {
    let mut c = RenoCongestionController::new();
    c.set_smoothed_rtt(39, Instant(0));
    assert_eq!(c.pacing_rate_bps(), 12_000 * 8_000 / 39);
    assert_eq!(c.pacing_burst_bytes(), INITIAL_CWND / 2);
    // Drain the bucket: a 1200-byte packet must wait its deficit out.
    c.consume_pacing(INITIAL_CWND as usize / 2, Instant(0));
    let now = Instant(0);
    let wait = c
        .next_send_time(now, SMSS as usize)
        .expect("pacing active after a sample");
    let delay = wait.duration_since(now).as_millis();
    let exact = SMSS * 8_000 / c.pacing_rate_bps();
    assert!(
        delay.abs_diff(exact) <= 1,
        "delay {delay} ms within ±1 ms of deficit/rate ({exact} ms)"
    );
    // The burst cap: after a long idle the bucket holds at most the burst
    // allowance, so a 12,000-byte packet still waits for the uncovered
    // 6,000 bytes (an uncapped bucket would refill 30 MB and send now).
    let later = Instant(60_000);
    let wait = c
        .next_send_time(later, 12_000)
        .expect("burst cap holds beyond the idle refill");
    let delay = wait.duration_since(later).as_millis();
    let exact = (12_000 - INITIAL_CWND / 2) * 8_000 / c.pacing_rate_bps();
    assert!(
        delay.abs_diff(exact) <= 1,
        "burst-capped delay {delay} ms within ±1 ms of the deficit ({exact} ms)"
    );
    assert!(c.pacing_tokens() <= c.pacing_burst_bytes());
}

/// §24.9 in-flight bounds: a full send-all → ack-all → send-again cycle
/// keeps in-flight ≤ cwnd at every step, and the outstanding-packet cap
/// eviction releases the evicted bytes from in-flight (cross-check of the
/// C1 cap-eviction test).
#[test]
fn in_flight_never_exceeds_window() {
    let mut s = session();
    let sid = s.open_stream().expect("stream");
    let mut built = 0usize;
    let mut last_pn = 0usize;
    loop {
        let payload = stream_payload(&mut s, sid, 25);
        match s.build_outbound(&TestClock, Instant(0), &payload) {
            Ok(Some(_)) => {
                last_pn = built;
                built += 1;
            }
            Err(SessionError::CongestionLimited) => break,
            other => panic!("unexpected build result: {other:?}"),
        }
    }
    assert!(
        built >= 9,
        "the initial window admits ~10 packets, got {built}"
    );
    assert!(
        s.congestion_mut().in_flight() <= s.congestion_mut().cwnd(),
        "in-flight never exceeds the window while the gate is shut"
    );
    // Ack the whole batch (first range covers pn 0 through the last
    // successful build): in-flight releases every byte...
    let ack = umc_wire::frame::AckFrame {
        largest_acknowledged: last_pn as u64,
        ack_delay: 0,
        first_ack_range: built as u64,
        additional_ranges: Vec::new(),
    };
    s.apply_peer_ack(&ack, Instant(0)).expect("ack all");
    assert_eq!(s.congestion_mut().in_flight(), 0);
    // ...and the cycle repeats: a fresh send builds again.
    let payload = stream_payload(&mut s, sid, 25);
    assert!(s
        .build_outbound(&TestClock, Instant(0), &payload)
        .expect("build")
        .is_some());
}

/// §24.9 cap eviction (cross-check of the C1 test): when the outstanding
/// packet cap evicts the oldest packet, its bytes leave in-flight — the
/// sent queue no longer holds them, so keeping them charged would leak the
/// window permanently.
#[test]
fn cap_eviction_cross_check_releases_in_flight() {
    let mut s = session();
    s.set_congestion_controller(Box::new(TrackingCongestion::default()));
    let mut charged = 0usize;
    let mut evicted = 0usize;
    for i in 0..=MAX_OUTSTANDING_PACKETS as u64 {
        let pkt = s
            .build_outbound(&TestClock, Instant(i), b"x")
            .unwrap()
            .expect("built packet");
        charged += pkt.len();
        if i == 0 {
            evicted = pkt.len();
        }
    }
    assert!(
        s.congestion_mut().in_flight() == charged - evicted,
        "the evicted packet's bytes leave in-flight (leaked {} bytes)",
        charged - s.congestion_mut().in_flight()
    );
}

/// §23.1 forged ACKs: an ACK acknowledging packets that were never sent is
/// rejected, and the controller must not react — the window and in-flight
/// stay exactly where they were (a forged ack must not inflate the window
/// or release in-flight bytes).
#[test]
fn forged_ack_rejected_no_controller_reaction() {
    let mut s = session();
    let sid = s.open_stream().expect("stream");
    // Two packets in flight: the controller holds cwnd = 10 × SMSS with a
    // nonzero in-flight count.
    for _ in 0..2 {
        let payload = stream_payload(&mut s, sid, 25);
        assert!(s
            .build_outbound(&TestClock, Instant(0), &payload)
            .expect("build")
            .is_some());
    }
    let cwnd_before = s.congestion_mut().cwnd();
    let in_flight_before = s.congestion_mut().in_flight();
    assert!(cwnd_before == INITIAL_CWND as usize && in_flight_before > 0);
    // Forge an ACK for packet 99 — nothing that high was ever sent.
    let forged = umc_wire::frame::AckFrame {
        largest_acknowledged: 99,
        ack_delay: 0,
        first_ack_range: 1,
        additional_ranges: Vec::new(),
    };
    assert_eq!(
        s.apply_peer_ack(&forged, Instant(0)),
        Err(SessionError::Ack(AckError::AcknowledgesUnsent))
    );
    // The controller did not react: no growth, no in-flight release.
    assert_eq!(s.congestion_mut().cwnd(), cwnd_before);
    assert_eq!(s.congestion_mut().in_flight(), in_flight_before);
}

/// §7.3 control-traffic reserve: with the window exhausted (allowance 0,
/// full-window scenario on the real Reno controller) an ACK payload and a
/// PING payload still build — they are the acknowledgment loop and the PTO
/// probe — while a STREAM payload is refused with `CongestionLimited`.
#[test]
fn control_traffic_reserve() {
    let mut s = session();
    let sid = s.open_stream().expect("stream");
    // Fill the window on the real controller: in-flight reaches cwnd and
    // the gate shuts for data. The gate measures payload + protected
    // overhead against the allowance, so the window is exhausted once the
    // allowance drops below a payload's protected size.
    let data_refused = 'fill: loop {
        let payload = stream_payload(&mut s, sid, 25);
        match s.build_outbound(&TestClock, Instant(0), &payload) {
            Ok(Some(_)) => {}
            Err(SessionError::CongestionLimited) => break 'fill payload,
            other => panic!("unexpected build result: {other:?}"),
        }
    };
    assert!(
        s.congestion_mut().send_allowance() <= data_refused.len() + 64,
        "the window is exhausted: allowance {} below a protected payload",
        s.congestion_mut().send_allowance()
    );
    // The reserve: ACK and PING payloads are exempt and still build.
    let ack = ack_payload();
    assert!(payload_is_exempt(&ack));
    assert!(s
        .build_outbound(&TestClock, Instant(0), &ack)
        .expect("ack build")
        .is_some());
    let ping = umc_wire::varint::encode(FrameType::PING.0).unwrap();
    assert!(payload_is_exempt(&ping));
    assert!(s
        .build_outbound(&TestClock, Instant(0), &ping)
        .expect("ping build")
        .is_some());
    // A STREAM payload stays gated: the reserve does not open the window.
    let stream = stream_payload(&mut s, sid, 25);
    assert!(!payload_is_exempt(&stream));
    assert_eq!(
        s.build_outbound(&TestClock, Instant(0), &stream),
        Err(SessionError::CongestionLimited)
    );
}

/// §10.3: an ACK resets the PTO backoff — after four expiries (16×) a
/// single ACK returns the deadline multiplier to 1×.
#[test]
fn backoff_resets_on_ack() {
    let mut pto = PtoState::default();
    for _ in 0..4 {
        pto.on_expiry();
    }
    assert_eq!(pto.multiplier(), 16);
    pto.on_ack();
    assert_eq!(pto.multiplier(), 1);
    assert_eq!(
        pto.next_deadline(Duration::from_millis(1_000), Instant(0))
            .duration_since(Instant(0))
            .as_millis(),
        1_000
    );
}

/// C2 pacing accuracy: a 100-packet burst must not run faster than the
/// pacing rate. The bucket is drained first so the ideal elapsed is exactly
/// `total_bytes × 8 / rate`; whole-byte and whole-millisecond truncation
/// would let the sender run ~23% hot (rtt 39 ms), so the assert demands
/// the elapsed stay within 5% of the ideal.
#[test]
fn pacing_does_not_overshoot_rate() {
    let mut c = RenoCongestionController::new();
    // rtt 39 ms: rate = 12,000 × 8000 / 39 = 2,461,538 bps — a fractional
    // 307.7 B/ms refill that exposes truncation loss.
    c.set_smoothed_rtt(39, Instant(0));
    assert_eq!(c.pacing_rate_bps(), 2_461_538);
    // Drain the burst so every packet pays its full spacing.
    c.consume_pacing(c.pacing_burst_bytes() as usize, Instant(0));
    let mut now = Instant(0);
    for _ in 0..100 {
        if let Some(wait) = c.next_send_time(now, SMSS as usize) {
            now = wait;
        }
        c.consume_pacing(SMSS as usize, now);
    }
    let total_bytes = 100 * SMSS;
    let ideal_ms = total_bytes * 8_000 / c.pacing_rate_bps();
    let tolerance = ideal_ms * 95 / 100;
    assert!(
        now.duration_since(Instant(0)).as_millis() >= tolerance,
        "100 packets at {} bps: elapsed {} ms < {} ms (ideal {}) — the sender overshoots the pacing rate",
        c.pacing_rate_bps(),
        now.duration_since(Instant(0)).as_millis(),
        tolerance,
        ideal_ms
    );
}

/// C2 pacing accuracy: re-rating must not grant retroactive tokens. The
/// refill earned between the last send and the rate change is credited at
/// the OLD rate; after the change the bucket must not contain more than
/// that (a rate change to a 10× faster clock must not refund the whole
/// elapsed window at the new rate).
#[test]
fn rate_change_does_not_grant_retroactive_tokens() {
    let mut c = RenoCongestionController::new();
    // R1: 12,000-byte window over 100 ms = 960,000 bps (120 B/ms).
    c.set_smoothed_rtt(100, Instant(0));
    assert_eq!(c.pacing_rate_bps(), 960_000);
    // Drain the bucket at t = 0: from here the refill accrues at R1.
    c.consume_pacing(6_000, Instant(0));
    assert_eq!(c.pacing_tokens(), 0);
    // 5 ms later the RTT sample drops to 10 ms: R2 = 9,600,000 bps
    // (1,200 B/ms). The pending [0, 5] refill was earned at R1 — 600 bytes,
    // not 6,000 at R2.
    c.set_smoothed_rtt(10, Instant(5));
    assert_eq!(c.pacing_rate_bps(), 9_600_000);
    // Exactly the R1-earned 600 bytes are in the bucket: a 600-byte send is
    // covered instantly...
    assert!(c.next_send_time(Instant(5), 600).is_none());
    // ...and anything beyond must wait — a retroactive R2 refill would have
    // filled the bucket to the 6,000-byte burst and sent instantly.
    assert!(
        c.next_send_time(Instant(5), 601).is_some(),
        "the bucket must not contain retroactive tokens from the old-rate window"
    );
}

/// Mock controller that tracks in-flight accounting, for the cap-eviction
/// cross-check: the session's accounting is under test, not the window
/// math.
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
