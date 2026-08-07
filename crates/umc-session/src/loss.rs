use super::ack::AckSendState;
use super::rtt::RttEstimator;
use umc_types::runtime::{Duration, Instant};

pub const TIMER_GRANULARITY_MS: u64 = 1;
pub const DEFAULT_PTO_MS: u64 = 1_000;
pub const PACKET_THRESHOLD: u64 = 3;
/// Probe timeout backoff cap: 6 doublings (congestion.md §10.3).
pub const MAX_PTO_BACKOFF: u32 = 64;
const MAX_PTO_BACKOFF_EXPONENT: u32 = 6;

/// Probe timeout backoff state (congestion.md §10.3): each consecutive PTO
/// expiry doubles the probe deadline, capped at 64x the base PTO; any ACK
/// resets the count. Pure math, testable without the daemon loop.
#[derive(Debug, Clone, Default)]
pub struct PtoState {
    /// Consecutive PTO expiries since the last ACK (capped at 6).
    consecutive: u32,
    /// Effective deadline multiplier: `2^consecutive`, capped at
    /// `MAX_PTO_BACKOFF`. Mirrors `consecutive`; the derived default is 0,
    /// which the accessor reads as 1x.
    multiplier: u32,
}

impl PtoState {
    /// Deadline `now + pto * 2^consecutive`, capped at `now + pto * 64`.
    #[must_use]
    pub fn next_deadline(&self, pto: Duration, now: Instant) -> Instant {
        now + Duration::from_millis(
            pto.as_millis()
                .saturating_mul(u64::from(self.multiplier().min(MAX_PTO_BACKOFF))),
        )
    }

    /// A PTO expiry: consecutive expiries double the deadline until the
    /// 64x cap.
    pub fn on_expiry(&mut self) {
        self.consecutive = (self.consecutive + 1).min(MAX_PTO_BACKOFF_EXPONENT);
        self.multiplier = 1 << self.consecutive;
    }

    /// An ACK-bearing inbound resets the backoff to 1x.
    pub fn on_ack(&mut self) {
        self.consecutive = 0;
        self.multiplier = 1;
    }

    /// The effective deadline multiplier (1x while no expiry has occurred).
    #[must_use]
    pub fn multiplier(&self) -> u32 {
        self.multiplier.max(1)
    }
}

#[derive(Debug, Clone)]
pub struct LossDetector {
    pub max_ack_delay_ms: u64,
}

impl LossDetector {
    #[must_use]
    pub fn new(max_ack_delay_ms: u64) -> Self {
        Self { max_ack_delay_ms }
    }

    /// PTO (session.md §14.3).
    #[must_use]
    pub fn pto(&self, rtt: &RttEstimator) -> Duration {
        if !rtt.initialized {
            return Duration::from_millis(DEFAULT_PTO_MS);
        }
        let variance_term = (4 * rtt.rtt_variance).max(TIMER_GRANULARITY_MS);
        Duration::from_millis(rtt.smoothed_rtt + variance_term + self.max_ack_delay_ms)
    }

    /// Packet-threshold loss: packet is lost when a peer ACKs a packet at least
    /// three numbers higher in the same space (session.md §14.1).
    #[must_use]
    pub fn packet_threshold_lost(&self, sent_pn: u64, largest_acked: u64) -> bool {
        largest_acked >= sent_pn + PACKET_THRESHOLD
    }

    /// Time-threshold loss: lost when a higher packet was acked AND
    /// elapsed >= 9/8 * max(`latest_rtt`, `smoothed_rtt`) (session.md §14.2).
    #[must_use]
    pub fn time_threshold_lost(
        &self,
        rtt: &RttEstimator,
        sent_at: Instant,
        now: Instant,
        higher_acked: bool,
    ) -> bool {
        if !higher_acked || !rtt.initialized {
            return false;
        }
        let threshold = (9 * rtt.latest_rtt.max(rtt.smoothed_rtt)) / 8;
        now.duration_since(sent_at).as_millis() >= threshold
    }

    /// Persistent congestion: all ack-eliciting packets lost over at least
    /// three PTO durations (session.md §14.4).
    #[must_use]
    pub fn persistent_congestion(
        &self,
        pto: Duration,
        oldest_lost_at: Instant,
        newest_lost_at: Instant,
    ) -> bool {
        let span = newest_lost_at.duration_since(oldest_lost_at);
        span.as_millis() >= 3 * pto.as_millis()
    }
}

/// Find lost packets from the sent queue (session.md §14).
pub fn detect_lost_packets(
    sent_state: &mut AckSendState,
    rtt: &RttEstimator,
    now: Instant,
    largest_acked: u64,
    loss_detector: &LossDetector,
) -> Vec<u64> {
    let mut lost = Vec::new();
    let mut keep = std::collections::VecDeque::new();
    for p in sent_state.sent().iter().cloned() {
        let pn = p.packet_number;
        let packet_lost = loss_detector.packet_threshold_lost(pn, largest_acked)
            || loss_detector.time_threshold_lost(rtt, p.sent_at, now, largest_acked > pn);
        if packet_lost {
            // Every lost packet leaves the queue and is reported; the caller
            // decides what to retransmit (only ack-eliciting payloads are
            // retained for re-sending) and prunes the rest (session.md §14).
            lost.push(pn);
        } else {
            keep.push_back(p);
        }
    }
    *sent_state = AckSendState::new();
    for p in keep {
        sent_state.record_sent(p);
    }
    lost
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sent_packet::SentPacket;
    use crate::spaces::PacketSpace;

    #[test]
    fn pto_defaults_before_rtt() {
        let d = LossDetector::new(25);
        assert_eq!(
            d.pto(&RttEstimator::new()),
            Duration::from_millis(DEFAULT_PTO_MS)
        );
    }

    #[test]
    fn packet_threshold_at_three() {
        let d = LossDetector::new(25);
        assert!(!d.packet_threshold_lost(10, 12));
        assert!(d.packet_threshold_lost(10, 13));
    }

    #[test]
    fn time_threshold_requires_higher_ack() {
        let mut rtt = RttEstimator::new();
        rtt.sample(100);
        let d = LossDetector::new(25);
        let sent_at = Instant(0);
        assert!(!d.time_threshold_lost(&rtt, sent_at, Instant(200), false));
        assert!(d.time_threshold_lost(&rtt, sent_at, Instant(200), true));
        // 9/8 * 100 = 112.5 -> 112ms
        assert!(!d.time_threshold_lost(&rtt, sent_at, Instant(100), true));
    }

    #[test]
    fn persistent_congestion_requires_three_ptos() {
        let d = LossDetector::new(25);
        let pto = Duration::from_millis(100);
        assert!(!d.persistent_congestion(pto, Instant(0), Instant(299)));
        assert!(d.persistent_congestion(pto, Instant(0), Instant(300)));
    }

    #[test]
    fn detect_lost_packets_marks_and_removes() {
        let mut sent = AckSendState::new();
        for pn in 0..6 {
            sent.record_sent(SentPacket::new(
                pn,
                PacketSpace::SessionData,
                Instant(0),
                64,
                true,
                0,
            ));
        }
        let mut rtt = RttEstimator::new();
        rtt.sample(100);
        let d = LossDetector::new(25);
        // now=50 keeps elapsed (50ms) below the 112ms time-threshold so the test
        // isolates packet-threshold loss (now=200 would time-lose pn 3-5 too).
        let lost = detect_lost_packets(&mut sent, &rtt, Instant(50), 5, &d);
        assert!(lost.contains(&0) && lost.contains(&1) && lost.contains(&2));
        assert!(!lost.contains(&3) && !lost.contains(&4) && !lost.contains(&5));
        assert_eq!(sent.sent().len(), 3);
    }

    #[test]
    fn backoff_doubles_per_expiry() {
        let mut pto = PtoState::default();
        let now = Instant(0);
        let base = Duration::from_millis(100);
        // 0 expiries: the deadline is 1x the base PTO.
        assert_eq!(pto.next_deadline(base, now), Instant(100));
        assert_eq!(pto.multiplier(), 1);
        // Each consecutive expiry doubles the deadline: 2x, 4x, ..., 64x.
        let mut expect = 100u64;
        for _ in 0..6 {
            pto.on_expiry();
            expect *= 2;
            assert_eq!(pto.next_deadline(base, now), Instant(expect));
            assert_eq!(u64::from(pto.multiplier()), expect / 100);
        }
        // The 7th expiry stays capped at 64x.
        pto.on_expiry();
        assert_eq!(pto.multiplier(), 64);
        assert_eq!(pto.next_deadline(base, now), Instant(6_400));
    }

    #[test]
    fn ack_resets_backoff() {
        let mut pto = PtoState::default();
        for _ in 0..4 {
            pto.on_expiry();
        }
        assert_eq!(pto.multiplier(), 16);
        // Any ACK-bearing inbound resets the count: the next deadline is
        // back at 1x (congestion.md §10.3).
        pto.on_ack();
        assert_eq!(pto.multiplier(), 1);
        assert_eq!(
            pto.next_deadline(Duration::from_millis(100), Instant(0)),
            Instant(100)
        );
    }

    #[test]
    fn deadline_capped_at_64x() {
        let mut pto = PtoState::default();
        let now = Instant(5_000);
        let base = Duration::from_millis(1_000);
        for _ in 0..10 {
            pto.on_expiry();
        }
        assert_eq!(pto.multiplier(), 64);
        assert_eq!(pto.next_deadline(base, now), Instant(5_000 + 64_000));
    }

    #[test]
    fn non_ack_eliciting_lost_packet_leaves_queue() {
        let mut sent = AckSendState::new();
        sent.record_sent(SentPacket::new(
            0,
            PacketSpace::SessionData,
            Instant(0),
            64,
            true,
            0,
        ));
        sent.record_sent(SentPacket::new(
            1,
            PacketSpace::SessionData,
            Instant(0),
            64,
            false,
            0,
        ));
        let mut rtt = RttEstimator::new();
        rtt.sample(100);
        let d = LossDetector::new(25);
        let lost = detect_lost_packets(&mut sent, &rtt, Instant(50), 4, &d);
        assert!(
            lost.contains(&0) && lost.contains(&1),
            "all lost packet numbers are reported, ack-eliciting or not"
        );
        assert!(
            sent.sent().is_empty(),
            "a lost non-ack-eliciting packet leaves the sent queue"
        );
    }
}
