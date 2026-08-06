//! Relay admission (relay.md §34): cheap checks before any downstream work.
use crate::circuit::MAX_LIFETIME_MS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPolicy {
    Disabled,
    FriendsOnly,
    Community,
    Public,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    Accepted {
        granted_lifetime_ms: u64,
        granted_byte_quota: u64,
        maximum_relay_payload: usize,
    },
    Refused,
    NoRoute,
    AuthFailed,
    ResourceLimit,
    UnsupportedFlags,
}

#[derive(Debug, Clone)]
pub struct AdmissionLimits {
    pub policy: RelayPolicy,
    pub max_circuits_per_peer: usize,
    pub active_circuits: usize,
    pub max_lifetime_ms: u64,
    pub max_byte_quota: u64,
    pub max_payload: usize,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            policy: RelayPolicy::Disabled,
            max_circuits_per_peer: 4,
            active_circuits: 0,
            max_lifetime_ms: 30 * 60 * 1000,
            max_byte_quota: 256 * 1024 * 1024,
            max_payload: 64 * 1024,
        }
    }
}

/// Evaluate `RELAY_OPEN` (relay.md §13, §34). No dialing happens here.
#[must_use]
pub fn evaluate_open(
    limits: &AdmissionLimits,
    peer_circuits: usize,
    requested_lifetime_ms: u64,
    requested_byte_quota: u64,
    flags: u8,
) -> AdmissionDecision {
    if limits.policy == RelayPolicy::Disabled {
        return AdmissionDecision::Refused;
    }
    if flags & 0xF0 != 0 {
        return AdmissionDecision::UnsupportedFlags;
    }
    if peer_circuits >= limits.max_circuits_per_peer {
        return AdmissionDecision::ResourceLimit;
    }
    if requested_lifetime_ms > MAX_LIFETIME_MS {
        return AdmissionDecision::Refused;
    }
    if requested_lifetime_ms > limits.max_lifetime_ms {
        return AdmissionDecision::Refused;
    }
    let lifetime = if requested_lifetime_ms == 0 {
        limits.max_lifetime_ms
    } else {
        requested_lifetime_ms
    };
    // A zero request means "accept the relay's policy default" (relay.md §11.3).
    let quota = if requested_byte_quota == 0 {
        limits.max_byte_quota
    } else {
        requested_byte_quota.min(limits.max_byte_quota)
    };
    AdmissionDecision::Accepted {
        granted_lifetime_ms: lifetime,
        granted_byte_quota: quota,
        maximum_relay_payload: limits.max_payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_policy_refuses() {
        let limits = AdmissionLimits::default();
        assert_eq!(
            evaluate_open(&limits, 0, 600_000, 1_048_576, 0),
            AdmissionDecision::Refused
        );
    }

    #[test]
    fn accepted_with_granted_limits() {
        let mut limits = AdmissionLimits::default();
        limits.policy = RelayPolicy::Community;
        match evaluate_open(&limits, 0, 600_000, 1_048_576, 0x01) {
            AdmissionDecision::Accepted {
                granted_lifetime_ms,
                granted_byte_quota,
                ..
            } => {
                assert_eq!(granted_lifetime_ms, 600_000);
                assert_eq!(granted_byte_quota, 1_048_576);
            }
            other => panic!("expected accepted, got {other:?}"),
        }
    }

    #[test]
    fn per_peer_circuit_limit() {
        let mut limits = AdmissionLimits::default();
        limits.policy = RelayPolicy::Public;
        assert_eq!(
            evaluate_open(&limits, 4, 600_000, 0, 0),
            AdmissionDecision::ResourceLimit
        );
    }

    #[test]
    fn quota_capped_at_local_max() {
        let mut limits = AdmissionLimits::default();
        limits.policy = RelayPolicy::Public;
        match evaluate_open(&limits, 0, 600_000, 1 << 30, 0) {
            AdmissionDecision::Accepted {
                granted_byte_quota, ..
            } => assert_eq!(granted_byte_quota, limits.max_byte_quota),
            other => panic!("expected accepted, got {other:?}"),
        }
    }

    #[test]
    fn zero_quota_uses_policy_default() {
        let mut limits = AdmissionLimits::default();
        limits.policy = RelayPolicy::Public;
        match evaluate_open(&limits, 0, 600_000, 0, 0) {
            AdmissionDecision::Accepted {
                granted_byte_quota, ..
            } => assert_eq!(granted_byte_quota, limits.max_byte_quota),
            other => panic!("expected accepted, got {other:?}"),
        }
    }

    #[test]
    fn unknown_flags_rejected() {
        let mut limits = AdmissionLimits::default();
        limits.policy = RelayPolicy::Public;
        assert_eq!(
            evaluate_open(&limits, 0, 600_000, 0, 0x10),
            AdmissionDecision::UnsupportedFlags
        );
    }
}
