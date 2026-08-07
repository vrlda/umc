//! Expiration and eviction (bundles.md §11, §19).
use crate::manager::BundleManager;
use umc_types::runtime::Instant;

/// Eviction order (resource-limits.md §33): expired, invalid, delivered,
/// unauthenticated, lowest priority, highest replication, largest, oldest.
/// Delegates to [`BundleManager::evict_expired`], which removes the record
/// and deletes the object-store payload.
#[must_use]
pub fn evict_expired(manager: &mut BundleManager, now: Instant) -> usize {
    manager.evict_expired(now).len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::{BundleManager, DEFAULT_LIFETIME_MS};
    use std::sync::atomic::{AtomicU64, Ordering};
    use umc_storage::objects::ObjectStore;
    use umc_storage::quota::{Profile, QuotaAccount};
    use umc_types::runtime::Duration;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn manager() -> BundleManager {
        let dir = std::env::temp_dir().join(format!(
            "umc-expiry-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        BundleManager::new(
            ObjectStore::open(dir).unwrap(),
            QuotaAccount::new(Profile::Standard, 0, 1_048_576),
        )
    }

    #[test]
    fn expired_bundles_evicted() {
        let mut m = manager();
        m.admit(b"a", b"s", b"d", 1, 1_000, 3, false, Instant(0))
            .unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(evict_expired(&mut m, Instant(1_000)), 1);
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn live_bundles_survive() {
        let mut m = manager();
        m.admit(
            b"a",
            b"s",
            b"d",
            1,
            DEFAULT_LIFETIME_MS,
            3,
            false,
            Instant(0),
        )
        .unwrap();
        assert_eq!(evict_expired(&mut m, Instant(1_000)), 0);
        assert_eq!(m.len(), 1);
        let _ = Duration::from_millis(1);
    }
}
