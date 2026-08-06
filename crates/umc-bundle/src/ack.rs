//! `BUNDLE_ACK` status mapping (wire-format.md §50, bundles.md §13).
use crate::manager::BundleStatus;

/// Status values MUST match the wire registry (wire-format.md §50).
#[must_use]
pub fn status_code(status: &BundleStatus) -> u64 {
    match status {
        BundleStatus::Received => 0,
        BundleStatus::CustodyAccepted => 1,
        BundleStatus::Forwarded => 2,
        BundleStatus::Delivered => 3,
        BundleStatus::Rejected => 4,
        BundleStatus::Expired => 5,
        BundleStatus::Evicted => 6,
    }
}

#[must_use]
pub fn status_from_code(code: u64) -> Option<BundleStatus> {
    match code {
        0 => Some(BundleStatus::Received),
        1 => Some(BundleStatus::CustodyAccepted),
        2 => Some(BundleStatus::Forwarded),
        3 => Some(BundleStatus::Delivered),
        4 => Some(BundleStatus::Rejected),
        5 => Some(BundleStatus::Expired),
        6 => Some(BundleStatus::Evicted),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_wire_registry() {
        assert_eq!(status_code(&BundleStatus::Received), 0);
        assert_eq!(status_code(&BundleStatus::CustodyAccepted), 1);
        assert_eq!(status_code(&BundleStatus::Forwarded), 2);
        assert_eq!(status_code(&BundleStatus::Delivered), 3);
        assert_eq!(status_code(&BundleStatus::Rejected), 4);
        assert_eq!(status_code(&BundleStatus::Expired), 5);
        assert_eq!(status_code(&BundleStatus::Evicted), 6);
    }

    #[test]
    fn round_trip() {
        for code in 0..=6 {
            assert_eq!(status_from_code(code).map(|s| status_code(&s)), Some(code));
        }
        assert!(status_from_code(7).is_none());
    }
}
