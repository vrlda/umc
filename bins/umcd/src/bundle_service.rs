//! Bundle service (bundles.md §9-12): the daemon's bundle admission, lookup,
//! expiry, and control-surface listing, backed by the object store.
use crate::event_log::{DaemonEvent, DaemonEvents};
use std::sync::{Arc, Mutex};
use umc_bundle::manager::BundleStatus;
use umc_bundle::manager::{BundleError, BundleManager, BundleRecord};
use umc_storage::objects::ObjectStore;
use umc_storage::quota::QuotaAccount;
use umc_storage::store::Store;
use umc_types::runtime::Instant;

/// Upper bound for control-surface bundle listings.
pub const MAX_LIST_BUNDLES: usize = 100;

/// Process-local bundle service over the shared object store.
#[derive(Debug)]
pub struct BundleService {
    pub manager: BundleManager,
    events: Arc<Mutex<DaemonEvents>>,
}

#[allow(clippy::too_many_arguments)] // admit() takes the full bundle header
impl BundleService {
    #[must_use]
    pub fn new(
        objects: ObjectStore,
        quota: QuotaAccount,
        events: Arc<Mutex<DaemonEvents>>,
    ) -> Self {
        Self {
            manager: BundleManager::new(objects, quota),
            events,
        }
    }

    /// Attaches the node database so bundle metadata persists
    /// (storage.md §6.3): admits save metas, removals delete them.
    pub fn attach_store(&mut self, store: Arc<dyn Store + Send + Sync>) {
        self.manager.set_persistence(Some(store));
    }

    /// Restores persisted bundles after a restart (storage.md §6.3):
    /// ciphertext payloads survive in the object store and are read back
    /// through the persisted content address. Returns the number restored.
    ///
    /// # Errors
    ///
    /// Returns a message when the persisted metadata cannot be scanned.
    pub fn restore(&mut self, store: &dyn Store, now: Instant) -> Result<usize, String> {
        self.manager.restore(store, now)
    }

    /// Admit a bundle (bundles.md §8.1), recording a `bundle_admitted` event.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError`] for policy violations, duplicates, quota
    /// exhaustion, and object-store failures.
    pub fn admit(
        &mut self,
        payload: &[u8],
        sender: &[u8],
        destination_hint: &[u8],
        priority: u64,
        lifetime_ms: u64,
        replication_limit: u64,
        custody: bool,
        now: Instant,
    ) -> Result<[u8; 32], BundleError> {
        let id = self.manager.admit(
            payload,
            sender,
            destination_hint,
            priority,
            lifetime_ms,
            replication_limit,
            custody,
            now,
        )?;
        self.events.lock().expect("event log").push(DaemonEvent {
            kind: "bundle_admitted".into(),
            at_ms: now.0,
            detail: format!("bundle {:02x?} ({} bytes)", id, payload.len()),
        });
        Ok(id)
    }

    /// Look up a bundle record by id.
    // find/count are test-only until a diagnostics surface needs them
    // outside the control path.
    #[allow(dead_code)]
    #[must_use]
    pub fn find(&self, id: &[u8; 32]) -> Option<&BundleRecord> {
        self.manager.record(id)
    }

    #[allow(dead_code)]
    #[must_use]
    pub fn count(&self) -> usize {
        self.manager.len()
    }

    /// Evict expired bundles (bundles.md §11): the manager removes the
    /// records and their object-store payloads, releasing quota and sender
    /// counts. A `bundle_expired` event is recorded per removed id.
    /// Returns the evicted ids.
    #[must_use]
    pub fn expire_old(&mut self, now: Instant) -> Vec<[u8; 32]> {
        let ids = self.manager.evict_expired(now);
        let mut events = self.events.lock().expect("event log");
        for id in &ids {
            events.push(DaemonEvent {
                kind: "bundle_expired".into(),
                at_ms: now.0,
                detail: format!("bundle {id:02x?}"),
            });
        }
        ids
    }

    /// Control-surface listing: `(id, size, status)` tuples, bounded to
    /// [`MAX_LIST_BUNDLES`].
    #[must_use]
    pub fn list(&self) -> Vec<(Vec<u8>, usize, BundleStatus)> {
        self.manager
            .records_iter()
            .take(MAX_LIST_BUNDLES)
            .map(|r| (r.id.to_vec(), r.size, r.status.clone()))
            .collect()
    }

    /// Ids of bundles awaiting delivery (status `Received`, not yet
    /// expired): the session loop wraps each stored ciphertext in a `BUNDLE`
    /// frame over active sessions (bundles.md §10.1).
    #[must_use]
    pub fn pending_delivery(&self, now: Instant) -> Vec<[u8; 32]> {
        self.manager
            .records_iter()
            .filter(|r| matches!(r.status, BundleStatus::Received) && now < r.expires_at)
            .map(|r| r.id)
            .collect()
    }

    /// The stored ciphertext for a bundle id, when it exists.
    #[must_use]
    pub fn payload(&self, id: &[u8; 32]) -> Option<Vec<u8>> {
        self.manager.get_payload(id).ok()
    }

    /// Record a bundle that has been wrapped into a `BUNDLE` frame as
    /// `Forwarded` (bundles.md §10.2).
    pub fn mark_forwarded(&mut self, id: &[u8; 32]) {
        let _ = self.manager.set_status(id, BundleStatus::Forwarded);
    }

    /// Apply a peer-reported `BUNDLE_ACK` status to a locally held bundle
    /// (bundles.md §13). Unknown ids are ignored.
    pub fn mark_status(&mut self, id: &[u8; 32], status: BundleStatus) {
        let _ = self.manager.set_status(id, status);
    }

    /// The record for a bundle id, for frame wrapping (destination hint,
    /// priority, lifetime).
    #[must_use]
    pub fn record(&self, id: &[u8; 32]) -> Option<&BundleRecord> {
        self.manager.record(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn service() -> BundleService {
        let dir = std::env::temp_dir().join(format!(
            "umcd-bundle-service-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        BundleService::new(
            ObjectStore::open(dir).unwrap(),
            QuotaAccount::new(
                umc_storage::quota::Profile::Standard,
                0,
                umc_storage::quota::Profile::Standard.bundle_storage_bytes(),
            ),
            Arc::new(Mutex::new(DaemonEvents::new(200))),
        )
    }

    fn admit(
        service: &mut BundleService,
        payload: &[u8],
        lifetime_ms: u64,
        now: Instant,
    ) -> [u8; 32] {
        service
            .admit(
                payload,
                b"sender-a",
                b"dest-hint",
                1,
                lifetime_ms,
                3,
                false,
                now,
            )
            .unwrap()
    }

    #[test]
    fn admit_find_round_trip() {
        let mut service = service();
        let id = admit(
            &mut service,
            b"payload",
            umc_bundle::manager::DEFAULT_LIFETIME_MS,
            Instant(0),
        );
        let record = service.find(&id).expect("record");
        assert_eq!(record.size, 7);
        assert_eq!(record.sender, b"sender-a");
        assert_eq!(service.manager.get_payload(&id).unwrap(), b"payload");
        assert!(service.find(&[0u8; 32]).is_none());
    }

    #[test]
    fn expire_removes_expired_bundles() {
        let mut service = service();
        admit(&mut service, b"a", 1_000, Instant(0));
        admit(&mut service, b"b", 1_000, Instant(0));
        assert_eq!(service.count(), 2);
        assert_eq!(service.expire_old(Instant(999)).len(), 0);
        assert_eq!(service.expire_old(Instant(1_000)).len(), 2);
        assert_eq!(service.count(), 0);
    }

    #[test]
    fn duplicate_rejected() {
        let mut service = service();
        admit(
            &mut service,
            b"same",
            umc_bundle::manager::DEFAULT_LIFETIME_MS,
            Instant(0),
        );
        assert_eq!(
            service.admit(
                b"same",
                b"sender-a",
                b"dest-hint",
                1,
                umc_bundle::manager::DEFAULT_LIFETIME_MS,
                3,
                false,
                Instant(0)
            ),
            Err(BundleError::Duplicate)
        );
    }

    #[test]
    fn admit_pushes_event() {
        let events = Arc::new(Mutex::new(DaemonEvents::new(200)));
        let mut service = BundleService::new(
            ObjectStore::open(
                std::env::temp_dir().join(format!("umcd-bundle-events-{}", std::process::id())),
            )
            .unwrap(),
            QuotaAccount::new(
                umc_storage::quota::Profile::Standard,
                0,
                umc_storage::quota::Profile::Standard.bundle_storage_bytes(),
            ),
            events.clone(),
        );
        admit(
            &mut service,
            b"p",
            umc_bundle::manager::DEFAULT_LIFETIME_MS,
            Instant(9),
        );
        let recent = events.lock().unwrap().recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].kind, "bundle_admitted");
        assert_eq!(recent[0].at_ms, 9);
    }

    #[test]
    fn list_bounded_and_shaped() {
        let mut service = service();
        for i in 0..3 {
            admit(
                &mut service,
                &[i],
                umc_bundle::manager::DEFAULT_LIFETIME_MS,
                Instant(0),
            );
        }
        let listing = service.list();
        assert_eq!(listing.len(), 3);
        assert!(listing.iter().all(|(id, size, state)| {
            id.len() == 32
                && *size == 1
                && matches!(state, umc_bundle::manager::BundleStatus::Received)
        }));
    }

    #[test]
    fn pending_delivery_lists_only_received_not_expired() {
        let mut service = service();
        admit(&mut service, b"a", 5_000, Instant(0));
        admit(&mut service, b"b", 5_000, Instant(0));
        // Lifetimes below 1s are clamped up by the manager (minimum 1000ms).
        let expired_id = admit(&mut service, b"c", 1_000, Instant(0));
        assert_eq!(service.pending_delivery(Instant(0)).len(), 3);
        assert_eq!(service.pending_delivery(Instant(1_001)).len(), 2);
        assert!(!service
            .pending_delivery(Instant(1_001))
            .contains(&expired_id));
        let forwarded_id = service.pending_delivery(Instant(0))[0];
        service.mark_forwarded(&forwarded_id);
        let pending = service.pending_delivery(Instant(0));
        assert_eq!(pending.len(), 2);
        assert!(!pending.contains(&forwarded_id));
    }

    #[test]
    fn payload_and_record_expose_the_stored_bundle() {
        let mut service = service();
        let id = admit(&mut service, b"ciphertext", 1_000, Instant(0));
        assert_eq!(service.payload(&id).expect("payload"), b"ciphertext");
        let record = service.record(&id).expect("record");
        assert_eq!(record.destination_hint, b"dest-hint");
        assert_eq!(record.priority, 1);
        assert!(service.payload(&[0u8; 32]).is_none());
        assert!(service.record(&[0u8; 32]).is_none());
        service.mark_forwarded(&[0u8; 32]); // unknown id: no-op
        assert!(service.payload(&id).is_some());
    }
}
