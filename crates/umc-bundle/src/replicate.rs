//! Replication policy (bundles.md §15): bounded, explicit, quota-charged.
use crate::manager::{BundleManager, BundleStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationDecision {
    Replicate,
    DoNotReplicate,
    Skip,
}

/// Replication is governed by the `DO_NOT_REPLICATE` flag, the replication
/// limit, sender policy, and storage pressure (bundles.md §15.1).
#[must_use]
pub fn decide_replication(
    manager: &BundleManager,
    id: &[u8; 32],
    do_not_replicate: bool,
    storage_pressure_high: bool,
) -> ReplicationDecision {
    if do_not_replicate || record_do_not_replicate(manager, id) {
        return ReplicationDecision::DoNotReplicate;
    }
    let Some(record) = manager.record(id) else {
        return ReplicationDecision::Skip;
    };
    if record.replication_count >= record.replication_limit || record.do_not_replicate {
        return ReplicationDecision::DoNotReplicate;
    }
    if record.status == BundleStatus::Delivered {
        return ReplicationDecision::Skip;
    }
    if storage_pressure_high && record.priority == 0 {
        return ReplicationDecision::Skip;
    }
    ReplicationDecision::Replicate
}

fn record_do_not_replicate(manager: &BundleManager, id: &[u8; 32]) -> bool {
    manager
        .record(id)
        .is_some_and(|record| record.do_not_replicate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::{BundleManager, DEFAULT_LIFETIME_MS};
    use std::sync::atomic::{AtomicU64, Ordering};
    use umc_storage::objects::ObjectStore;
    use umc_storage::quota::{Profile, QuotaAccount};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn manager() -> BundleManager {
        let dir = std::env::temp_dir().join(format!(
            "umc-repl-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        BundleManager::new(
            ObjectStore::open(dir).unwrap(),
            QuotaAccount::new(Profile::Standard, 0, 1_048_576),
        )
    }

    #[test]
    fn flags_and_limits_govern() {
        let mut m = manager();
        let id = m
            .admit(
                b"p",
                b"s",
                b"d",
                1,
                DEFAULT_LIFETIME_MS,
                3,
                false,
                umc_types::runtime::Instant(0),
            )
            .unwrap();
        assert_eq!(
            decide_replication(&m, &id, false, false),
            ReplicationDecision::Replicate
        );
        assert_eq!(
            decide_replication(&m, &id, true, false),
            ReplicationDecision::DoNotReplicate
        );
    }

    #[test]
    fn delivered_bundles_skip() {
        let mut m = manager();
        let id = m
            .admit(
                b"p",
                b"s",
                b"d",
                1,
                DEFAULT_LIFETIME_MS,
                3,
                false,
                umc_types::runtime::Instant(0),
            )
            .unwrap();
        m.set_status(&id, BundleStatus::Delivered).unwrap();
        assert_eq!(
            decide_replication(&m, &id, false, false),
            ReplicationDecision::Skip
        );
    }

    #[test]
    fn pressure_sheds_low_priority() {
        let mut m = manager();
        let id = m
            .admit(
                b"p",
                b"s",
                b"d",
                0,
                DEFAULT_LIFETIME_MS,
                3,
                false,
                umc_types::runtime::Instant(0),
            )
            .unwrap();
        assert_eq!(
            decide_replication(&m, &id, false, true),
            ReplicationDecision::Skip
        );
    }
}
