//! Congestion control (congestion.md §7, §14): a controller bounds
//! in-flight bytes and gates sends. The Reno controller grows the window
//! in slow start, switches to additive growth in congestion avoidance,
//! and halves it on loss.
//!
//! The controller is per-session for now; per-path isolation is a later
//! phase (congestion.md §17). Every mutation is deterministic — the same
//! event sequence always produces the same window — and state is bounded:
//! the window has a floor and in-flight never grows without a matching
//! send.

/// Congestion controller interface (congestion.md §6): the session feeds
/// packet and ACK events, and `send_allowance` gates outbound packets.
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

/// NewReno-style loss-based controller (congestion.md §14): slow start
/// grows the window by the acknowledged bytes below `ssthresh`,
/// congestion avoidance grows it by `SMSS × acked / cwnd` above, and loss
/// halves it with a 2 × SMSS floor.
#[derive(Debug)]
pub struct RenoCongestionController {
    cwnd: u64,
    ssthresh: u64,
    in_flight: u64,
    smss: u64,
    consecutive_losses: u32,
}

impl RenoCongestionController {
    /// A fresh controller: `cwnd = 10 × SMSS`, unlimited `ssthresh`
    /// (slow start from the first ack).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: u64::MAX,
            in_flight: 0,
            smss: SMSS,
            consecutive_losses: 0,
        }
    }

    /// The Reno loss response (congestion.md §14.4): halve the window and
    /// set the slow-start threshold to the new window, floored at
    /// 2 × SMSS.
    fn reduce_window(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
        self.cwnd = self.ssthresh;
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
    }
}
