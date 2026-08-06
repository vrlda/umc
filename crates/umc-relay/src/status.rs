//! `RELAY_STATUS` codes (relay.md §12.2): the status registry is distinct
//! from the reason-code registry. Every close reason maps to the status a
//! relay would have reported; the reverse direction yields the canonical
//! reason for terminal statuses only.
use crate::close::RelayReason;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayStatus {
    Pending = 0,
    Accepted = 1,
    Refused = 2,
    NoRoute = 3,
    AuthFailed = 4,
    ResourceLimit = 5,
    DestinationRejected = 6,
    Degraded = 7,
    QuotaWarning = 8,
    Expiring = 9,
    Closed = 10,
    UnsupportedFlags = 11,
}

impl RelayStatus {
    #[must_use]
    pub fn from_u64(code: u64) -> Option<Self> {
        match code {
            0 => Some(RelayStatus::Pending),
            1 => Some(RelayStatus::Accepted),
            2 => Some(RelayStatus::Refused),
            3 => Some(RelayStatus::NoRoute),
            4 => Some(RelayStatus::AuthFailed),
            5 => Some(RelayStatus::ResourceLimit),
            6 => Some(RelayStatus::DestinationRejected),
            7 => Some(RelayStatus::Degraded),
            8 => Some(RelayStatus::QuotaWarning),
            9 => Some(RelayStatus::Expiring),
            10 => Some(RelayStatus::Closed),
            11 => Some(RelayStatus::UnsupportedFlags),
            _ => None,
        }
    }
}

/// Map a `RELAY_CLOSE` reason to the `RELAY_STATUS` code that reports it
/// (relay.md §12.2, §24).
#[must_use]
pub fn status_for_reason(reason: RelayReason) -> u64 {
    use RelayReason as R;
    use RelayStatus as S;
    match reason {
        R::NoError | R::IdleTimeout | R::EmergencyShutdown => S::Closed as u64,
        R::Refused | R::PolicyRevoked | R::PayloadTooLarge => S::Refused as u64,
        R::AuthFailed => S::AuthFailed as u64,
        R::NoRoute => S::NoRoute as u64,
        R::DownstreamFailed | R::UpstreamFailed => S::DestinationRejected as u64,
        R::QuotaExhausted | R::ResourceLimit => S::ResourceLimit as u64,
        R::Expired => S::Expiring as u64,
        R::ProtocolError => S::UnsupportedFlags as u64,
    }
}

/// The canonical close reason for a `RELAY_STATUS` code. Non-terminal statuses
/// (`PENDING`, `ACCEPTED`, `DEGRADED`, `QUOTA_WARNING`) carry no close reason.
#[must_use]
pub fn reason_for_status(code: u64) -> Option<RelayReason> {
    use RelayReason as R;
    match RelayStatus::from_u64(code)? {
        RelayStatus::Refused => Some(R::Refused),
        RelayStatus::NoRoute => Some(R::NoRoute),
        RelayStatus::AuthFailed => Some(R::AuthFailed),
        RelayStatus::ResourceLimit => Some(R::ResourceLimit),
        RelayStatus::DestinationRejected => Some(R::DownstreamFailed),
        RelayStatus::Expiring => Some(R::Expired),
        RelayStatus::Closed => Some(R::NoError),
        RelayStatus::UnsupportedFlags => Some(R::ProtocolError),
        RelayStatus::Pending
        | RelayStatus::Accepted
        | RelayStatus::Degraded
        | RelayStatus::QuotaWarning => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_match_spec() {
        for code in 0..=11 {
            assert_eq!(RelayStatus::from_u64(code).unwrap() as u64, code);
        }
        assert!(RelayStatus::from_u64(12).is_none());
    }

    #[test]
    fn every_reason_maps_to_a_registered_status() {
        for code in 0..=13 {
            let reason = RelayReason::from_u64(code).expect("reason");
            let status = status_for_reason(reason);
            assert!(
                RelayStatus::from_u64(status).is_some(),
                "reason {reason:?} maps to unregistered status {status}"
            );
        }
    }

    #[test]
    fn one_to_one_entries_round_trip() {
        let one_to_one: &[(RelayReason, u64)] = &[
            (RelayReason::Refused, 2),
            (RelayReason::NoRoute, 3),
            (RelayReason::AuthFailed, 4),
            (RelayReason::ResourceLimit, 5),
            (RelayReason::DownstreamFailed, 6),
            (RelayReason::Expired, 9),
            (RelayReason::NoError, 10),
            (RelayReason::ProtocolError, 11),
        ];
        for (reason, status) in one_to_one {
            assert_eq!(status_for_reason(*reason), *status);
            assert_eq!(reason_for_status(*status), Some(*reason));
        }
    }

    #[test]
    fn non_terminal_statuses_have_no_reason() {
        for code in [0, 1, 7, 8] {
            assert_eq!(reason_for_status(code), None);
        }
        assert_eq!(reason_for_status(12), None);
    }
}
