//! Congestion control (congestion.md §7, §12, §14): a controller bounds
//! in-flight bytes, gates sends, and paces the wire rate. The Reno
//! controller grows the window in slow start, switches to additive growth
//! in congestion avoidance, halves it on loss, and spaces sends at
//! `cwnd / smoothed_rtt` once the RTT has a sample.
//!
//! The controller is per-session for now; per-path isolation is a later
//! phase (congestion.md §17). Every mutation is deterministic — the same
//! event sequence always produces the same window — and state is bounded:
//! the window has a floor and in-flight never grows without a matching
//! send.
use umc_types::runtime::{Duration, Instant};

/// Congestion controller interface (congestion.md §6): the session feeds
/// packet and ACK events, and `send_allowance` gates outbound packets.
///
/// The pacing methods default to "off": only a controller that opts in
/// (the Reno controller) paces; mock controllers keep the no-op defaults.
pub trait CongestionController: Send {
    /// An ACK arrived for `newly_acked_bytes` total across its packets:
    /// drives window growth (slow start or congestion avoidance).
    fn on_ack(&mut self, newly_acked_bytes: usize);
    /// A loss event of `lost_bytes` total: reduces the window.
    fn on_loss(&mut self, lost_bytes: usize);
    /// A packet of `bytes` was put on the wire: charges in-flight.
    fn on_packet_sent(&mut self, bytes: usize);
    /// A packet of `bytes` was acknowledged: releases in-flight.
    fn on_packet_acknowledged(&mut self, bytes: usize);
    /// A packet of `bytes` was declared lost: releases in-flight.
    fn on_packet_lost(&mut self, bytes: usize);
    /// Bytes the sender may still put in flight now: `cwnd − in_flight`.
    #[must_use]
    fn send_allowance(&self) -> usize;
    /// The current congestion window in bytes.
    #[must_use]
    fn cwnd(&self) -> usize;
    /// Bytes sent but not yet acknowledged or declared lost.
    #[must_use]
    fn in_flight(&self) -> usize;
    /// Clear all state (new path, restart): back to initial slow start.
    fn reset(&mut self);
    /// Feed the sender's smoothed RTT in milliseconds (congestion.md §12):
    /// activates pacing. A 0 RTT (the estimator before its first sample)
    /// keeps the rate at 0 = unlimited, so pacing changes nothing until the
    /// RTT is measured.
    fn set_smoothed_rtt(&mut self, _ms: u64) {}
    /// When the next `bytes` may be put on the wire (congestion.md §12):
    /// `None` sends immediately (tokens cover the packet, or pacing is
    /// unlimited); `Some(t)` waits until `t`. The caller consults this
    /// BEFORE the send and sleeps until the returned instant.
    #[must_use]
    fn next_send_time(&self, _now: Instant, _bytes: usize) -> Option<Instant> {
        None
    }
    /// The current pacing rate in bits per second; 0 = unlimited.
    #[must_use]
    fn pacing_rate_bps(&self) -> u64 {
        0
    }
    /// Record an actual wire send of `bytes` at `now`: consumes the pacing
    /// tokens at the real send time, so the token clock never drifts across
    /// a paced sleep. The caller invokes this AFTER a successful send.
    fn consume_pacing(&mut self, _bytes: usize, _now: Instant) {}
}

/// Maximum segment size (congestion.md §14.1 `initial_max_packet_size`
/// default): the unit the window counts in.
pub const SMSS: u64 = 1_200;
/// Initial window: 10 × SMSS (congestion.md §14.1).
pub const INITIAL_CWND: u64 = 10 * SMSS;
/// Minimum window: 2 × SMSS (congestion.md §14.1 `minimum_cwnd`).
pub const MIN_CWND: u64 = 2 * SMSS;
/// Consecutive lost packets before the per-packet feed triggers the Reno
/// halving: isolated single losses (e.g. one reordered packet) must not
/// cut the window.
///
/// Note: congestion.md §14.4 defines the loss response without a streak
/// threshold. The three-strike heuristic is a deliberate, conservative
/// deviation — the spec's immediate halving on any single loss is harsher
/// than `NewReno` practice and would cut the window on reordering — and the
/// streak resets on every ACK and on every aggregate loss event, so it only
/// accumulates for genuinely consecutive loss.
const LOSS_THRESHOLD: u32 = 3;

/// Pacing state (congestion.md §12): a token bucket sized to the burst
/// allowance, refilled at the pacing rate derived from the congestion
/// window and the smoothed RTT. The rate is 0 until the sender's RTT has a
/// sample — pacing stays unlimited (0 = no pacing).
///
/// The bucket is time-annotated rather than continuously ticking: tokens
/// are refilled only at events that carry `now`, and `next_send_time`
/// computes the effective tokens at the query instant from the last send
/// anchor. That way a paced send that sleeps between the query and the
/// wire never double-counts its own delay.
#[derive(Debug)]
pub struct PacingState {
    rate_bps: u64,
    burst_bytes: u64,
    tokens: u64,
    last_send: Option<Instant>,
}

impl PacingState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rate_bps: 0,
            burst_bytes: 0,
            tokens: 0,
            last_send: None,
        }
    }

    /// Re-size the bucket from the window and the smoothed RTT (congestion
    /// §12, §14.5): `rate_bps = cwnd × 8 × 1000 / smoothed_rtt_ms`, burst =
    /// `min(cwnd / 2, 10 × SMSS)`. An uninitialized RTT (0) disables pacing
    /// (rate 0 = unlimited). Enabling the bucket starts it full; a
    /// shrinking burst clamps the existing tokens to the new cap.
    pub fn set_rate(&mut self, cwnd: u64, smoothed_rtt_ms: u64, smss: u64) {
        let was_unlimited = self.rate_bps == 0;
        self.rate_bps = if smoothed_rtt_ms == 0 {
            0
        } else {
            cwnd.saturating_mul(8).saturating_mul(1_000) / smoothed_rtt_ms
        };
        self.burst_bytes = if smoothed_rtt_ms == 0 {
            0
        } else {
            (cwnd / 2).min(smss.saturating_mul(10))
        };
        if self.rate_bps == 0 {
            self.tokens = 0;
        } else if was_unlimited {
            self.tokens = self.burst_bytes;
        } else {
            self.tokens = self.tokens.min(self.burst_bytes);
        }
    }

    /// Effective tokens at `now`: the stored tokens plus the refill earned
    /// since the last send, capped at the burst allowance. Read-only — the
    /// caller queries without mutating the bucket.
    fn tokens_at(&self, now: Instant) -> u64 {
        let Some(last) = self.last_send else {
            return self.tokens;
        };
        let elapsed = now.duration_since(last).as_millis();
        let refilled = self.rate_bps.saturating_mul(elapsed) / 8_000;
        self.tokens.saturating_add(refilled).min(self.burst_bytes)
    }

    /// When the next `needed` bytes may be sent (congestion.md §12):
    /// `None` when the bucket already covers the packet or the rate is 0
    /// (unlimited); `Some(now + deficit / rate)` otherwise — the deficit is
    /// refilled at the pacing rate.
    #[must_use]
    pub fn next_send_time(&self, now: Instant, needed: usize) -> Option<Instant> {
        if self.rate_bps == 0 {
            return None;
        }
        let tokens = self.tokens_at(now);
        let needed = needed as u64;
        if tokens >= needed {
            return None;
        }
        let delay_ms = (needed - tokens).saturating_mul(8_000) / self.rate_bps;
        Some(now + Duration::from_millis(delay_ms))
    }

    /// A wire send of `bytes` at `now`: refills to `now`, consumes the
    /// bytes, and anchors the bucket at the real send time.
    pub fn consume(&mut self, bytes: usize, now: Instant) {
        let tokens = self.tokens_at(now);
        self.tokens = tokens.saturating_sub(bytes as u64);
        self.last_send = Some(now);
    }

    /// The pacing rate in bits per second (0 = unlimited).
    #[must_use]
    pub const fn rate_bps(&self) -> u64 {
        self.rate_bps
    }

    /// The burst allowance in bytes: the bucket's cap.
    #[must_use]
    pub const fn burst_bytes(&self) -> u64 {
        self.burst_bytes
    }

    /// Tokens currently in the bucket.
    #[must_use]
    pub const fn tokens(&self) -> u64 {
        self.tokens
    }
}

impl Default for PacingState {
    fn default() -> Self {
        Self::new()
    }
}

/// NewReno-style loss-based controller (congestion.md §14): slow start
/// grows the window by the acknowledged bytes below `ssthresh`,
/// congestion avoidance grows it by `SMSS × acked / cwnd` above, and loss
/// halves it with a 2 × SMSS floor. Paces the wire at `cwnd / smoothed_rtt`
/// (congestion.md §12) once the RTT has a sample.
#[derive(Debug)]
pub struct RenoCongestionController {
    cwnd: u64,
    ssthresh: u64,
    in_flight: u64,
    smss: u64,
    consecutive_losses: u32,
    smoothed_rtt_ms: u64,
    pacing: PacingState,
}

impl RenoCongestionController {
    /// A fresh controller: `cwnd = 10 × SMSS`, unlimited `ssthresh`
    /// (slow start from the first ack), and no pacing until the RTT is
    /// sampled (`set_smoothed_rtt`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: u64::MAX,
            in_flight: 0,
            smss: SMSS,
            consecutive_losses: 0,
            smoothed_rtt_ms: 0,
            pacing: PacingState::new(),
        }
    }

    /// Recompute the pacing rate and burst from the current window and RTT
    /// (congestion.md §12): every window or RTT change re-sizes the bucket.
    /// An uninitialized RTT keeps the rate at 0 (unlimited).
    fn update_pacing(&mut self) {
        self.pacing
            .set_rate(self.cwnd, self.smoothed_rtt_ms, self.smss);
    }

    /// The burst allowance in bytes: the pacing bucket's cap.
    #[must_use]
    pub fn pacing_burst_bytes(&self) -> u64 {
        self.pacing.burst_bytes()
    }

    /// Tokens currently in the pacing bucket (test/observability accessor).
    #[must_use]
    pub fn pacing_tokens(&self) -> u64 {
        self.pacing.tokens()
    }

    /// The Reno loss response (congestion.md §14.4): halve the window and
    /// set the slow-start threshold to the new window, floored at
    /// 2 × SMSS.
    fn reduce_window(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
        self.cwnd = self.ssthresh;
        self.update_pacing();
    }
}

impl Default for RenoCongestionController {
    fn default() -> Self {
        Self::new()
    }
}

impl CongestionController for RenoCongestionController {
    fn on_ack(&mut self, newly_acked_bytes: usize) {
        let acked = newly_acked_bytes as u64;
        // An ACK breaks any loss streak: packets declared lost that turn out
        // acknowledged were reordered, not lost (congestion.md §14.4 — see
        // the LOSS_THRESHOLD note on the conservative deviation).
        self.consecutive_losses = 0;
        if self.cwnd < self.ssthresh {
            // Slow start (congestion.md §14.2): the window grows by the
            // acknowledged bytes — one maximum packet per acked packet.
            self.cwnd = self.cwnd.saturating_add(acked);
        } else {
            // Congestion avoidance (congestion.md §14.3): one maximum
            // packet per round trip — `SMSS × acked / cwnd` per ack.
            self.cwnd = self
                .cwnd
                .saturating_add(self.smss.saturating_mul(acked) / self.cwnd);
        }
        self.update_pacing();
    }

    fn on_loss(&mut self, lost_bytes: usize) {
        self.in_flight = self.in_flight.saturating_sub(lost_bytes as u64);
        // An aggregate loss event already reduced the window: the streak
        // counter starts fresh so the per-packet feed cannot stack a second
        // reduction on top of it.
        self.consecutive_losses = 0;
        self.reduce_window();
    }

    fn on_packet_sent(&mut self, bytes: usize) {
        self.in_flight = self.in_flight.saturating_add(bytes as u64);
    }

    fn on_packet_acknowledged(&mut self, bytes: usize) {
        self.in_flight = self.in_flight.saturating_sub(bytes as u64);
    }

    fn on_packet_lost(&mut self, bytes: usize) {
        self.in_flight = self.in_flight.saturating_sub(bytes as u64);
        // React only to the third consecutive lost packet (LOSS_THRESHOLD):
        // a single isolated loss must not halve the window.
        self.consecutive_losses += 1;
        if self.consecutive_losses >= LOSS_THRESHOLD {
            self.consecutive_losses = 0;
            self.reduce_window();
        }
    }

    fn send_allowance(&self) -> usize {
        usize::try_from(self.cwnd.saturating_sub(self.in_flight)).unwrap_or(usize::MAX)
    }

    fn cwnd(&self) -> usize {
        usize::try_from(self.cwnd).unwrap_or(usize::MAX)
    }

    fn in_flight(&self) -> usize {
        usize::try_from(self.in_flight).unwrap_or(usize::MAX)
    }

    fn reset(&mut self) {
        self.cwnd = INITIAL_CWND;
        self.ssthresh = u64::MAX;
        self.in_flight = 0;
        self.consecutive_losses = 0;
        // Restart clears the RTT and pacing state too (congestion.md
        // §24.21): the rate resets to 0 (unlimited) until a fresh sample.
        self.smoothed_rtt_ms = 0;
        self.pacing = PacingState::new();
    }

    fn set_smoothed_rtt(&mut self, ms: u64) {
        self.smoothed_rtt_ms = ms;
        self.update_pacing();
    }

    fn next_send_time(&self, now: Instant, bytes: usize) -> Option<Instant> {
        self.pacing.next_send_time(now, bytes)
    }

    fn pacing_rate_bps(&self) -> u64 {
        self.pacing.rate_bps()
    }

    fn consume_pacing(&mut self, bytes: usize, now: Instant) {
        self.pacing.consume(bytes, now);
    }
}
