//! `RELAY_CLOSE` semantics and reason codes (relay.md §23-24).
use crate::circuit::{Circuit, CircuitState};
use umc_types::runtime::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum RelayReason {
    NoError = 0,
    Refused = 1,
    AuthFailed = 2,
    NoRoute = 3,
    DownstreamFailed = 4,
    UpstreamFailed = 5,
    QuotaExhausted = 6,
    Expired = 7,
    IdleTimeout = 8,
    ResourceLimit = 9,
    PolicyRevoked = 10,
    ProtocolError = 11,
    PayloadTooLarge = 12,
    EmergencyShutdown = 13,
}

impl RelayReason {
    #[must_use]
    pub fn from_u64(code: u64) -> Option<Self> {
        match code {
            0 => Some(RelayReason::NoError),
            1 => Some(RelayReason::Refused),
            2 => Some(RelayReason::AuthFailed),
            3 => Some(RelayReason::NoRoute),
            4 => Some(RelayReason::DownstreamFailed),
            5 => Some(RelayReason::UpstreamFailed),
            6 => Some(RelayReason::QuotaExhausted),
            7 => Some(RelayReason::Expired),
            8 => Some(RelayReason::IdleTimeout),
            9 => Some(RelayReason::ResourceLimit),
            10 => Some(RelayReason::PolicyRevoked),
            11 => Some(RelayReason::ProtocolError),
            12 => Some(RelayReason::PayloadTooLarge),
            13 => Some(RelayReason::EmergencyShutdown),
            _ => None,
        }
    }
}

pub const DRAIN_PERIOD_MS: u64 = 1_000;

/// Close a circuit, entering CLOSING (relay.md §9.5). The drain stages
/// (CLOSING → DRAINING → CLOSED) are driven by `drain_circuit`.
/// Returns the final sequence the close should carry (or None = no data accepted).
pub fn close_circuit(
    circuit: &mut Circuit,
    reason: RelayReason,
    now: Instant,
    final_sequence: Option<u64>,
) -> RelayReason {
    circuit.state = CircuitState::Closing;
    circuit.idle_deadline = now + Duration::from_millis(DRAIN_PERIOD_MS);
    let _ = final_sequence;
    reason
}

/// Advance closing circuits through the two-stage drain: CLOSING → DRAINING →
/// CLOSED (relay.md §9.6). Each stage runs for its own drain period.
pub fn drain_circuit(circuit: &mut Circuit, now: Instant) {
    if now < circuit.idle_deadline {
        return;
    }
    match circuit.state {
        CircuitState::Closing => {
            circuit.state = CircuitState::Draining;
            circuit.idle_deadline = now + Duration::from_millis(DRAIN_PERIOD_MS);
        }
        CircuitState::Draining => {
            circuit.state = CircuitState::Closed;
        }
        _ => {}
    }
}

/// Idle or lifetime expiry (relay.md §21).
#[must_use]
pub fn expiry_reason(circuit: &Circuit, now: Instant) -> Option<RelayReason> {
    if circuit.is_expired(now) {
        return Some(RelayReason::Expired);
    }
    if circuit.is_idle(now) {
        return Some(RelayReason::IdleTimeout);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_code_round_trip() {
        for code in 0..=13 {
            let reason = RelayReason::from_u64(code).unwrap();
            assert_eq!(reason as u64, code);
        }
        assert!(RelayReason::from_u64(14).is_none());
    }

    #[test]
    fn close_then_drain() {
        let now = Instant(0);
        let mut c = Circuit::new(1, now, 600_000, 100, true, false);
        c.accept(now);
        close_circuit(&mut c, RelayReason::QuotaExhausted, now, Some(3));
        assert_eq!(c.state, CircuitState::Closing);
        drain_circuit(&mut c, now + Duration::from_millis(DRAIN_PERIOD_MS));
        assert_eq!(c.state, CircuitState::Draining);
        drain_circuit(&mut c, now + Duration::from_millis(2 * DRAIN_PERIOD_MS));
        assert_eq!(c.state, CircuitState::Closed);
    }

    #[test]
    fn drain_requires_deadline() {
        let now = Instant(0);
        let mut c = Circuit::new(3, now, 600_000, 100, true, false);
        c.accept(now);
        close_circuit(&mut c, RelayReason::NoError, now, None);
        drain_circuit(&mut c, now + Duration::from_millis(DRAIN_PERIOD_MS - 1));
        assert_eq!(c.state, CircuitState::Closing);
        drain_circuit(&mut c, now + Duration::from_millis(DRAIN_PERIOD_MS - 1));
        assert_eq!(c.state, CircuitState::Closing);
    }

    #[test]
    fn expiry_priority_over_idle() {
        let now = Instant(0);
        let mut c = Circuit::new(2, now, 1_000, 100, true, false);
        // Lifetime expires first at 1000ms; idle at 120s.
        assert_eq!(
            expiry_reason(&c, now + Duration::from_millis(1_000)),
            Some(RelayReason::Expired)
        );
    }
}
