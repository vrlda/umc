//! Bundle manager (bundles.md §9-10, §12): validate policy before allocation,
//! store payloads as content-addressed objects, deduplicate by Bundle ID.
use crate::id::{bundle_id, BUNDLE_ID_LEN};
use crate::persist::{delete_meta, load_all_metas, save_meta, BundleMeta};
use std::collections::HashMap;
use std::sync::Arc;
use umc_storage::objects::{blake2s, ObjectStore};
use umc_storage::quota::QuotaAccount;
use umc_storage::store::{Store, StoreError};
use umc_types::runtime::{Duration, Instant};

pub const DEFAULT_MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub const MAX_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;
pub const DEFAULT_MAX_REPLICATION: u64 = 8;
pub const MAX_BUNDLES_PER_SENDER: u64 = 1_000;
/// Retention of a removed Bundle ID, preventing an immediate replay from
/// consuming storage again (bundles.md §12.2).
pub const DUPLICATE_CACHE_TTL_MS: u64 = DEFAULT_LIFETIME_MS;
pub const DUPLICATE_CACHE_CAPACITY: usize = 1_024;

pub type BundleTransferChunk = (BundleRecord, Vec<u8>, u64, bool);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleStatus {
    Received,
    CustodyAccepted,
    Forwarded,
    Delivered,
    Rejected,
    Expired,
    Evicted,
}

#[derive(Debug, Clone)]
pub struct BundleRecord {
    pub id: [u8; BUNDLE_ID_LEN],
    pub object_id: [u8; 32],
    pub sender: Vec<u8>,
    pub destination_hint: Vec<u8>,
    pub size: usize,
    pub priority: u64,
    pub created_at: Instant,
    pub expires_at: Instant,
    pub replication_count: u64,
    pub replication_limit: u64,
    pub custody: bool,
    /// A custody commitment may outlive the payload's ordinary expiry. The
    /// node retains the record until this deadline or explicit release.
    pub custody_deadline: Option<Instant>,
    /// Next packet-sized BUNDLE chunk to send. This operational cursor is
    /// persisted so a restart safely resumes from the beginning or cursor.
    pub transfer_chunk_index: u64,
    pub status: BundleStatus,
}

#[derive(Debug, Clone, Copy)]
struct DuplicateEntry {
    expires_at: Instant,
    inserted_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    QuotaExceeded,
    TooLarge,
    Expired,
    Duplicate,
    Conflict,
    ReplicationLimit,
    NotFound,
    Storage(StoreError),
}

pub struct BundleManager {
    objects: ObjectStore,
    quota: QuotaAccount,
    records: HashMap<[u8; BUNDLE_ID_LEN], BundleRecord>,
    bundles_per_sender: HashMap<Vec<u8>, u64>,
    duplicate_cache: HashMap<[u8; BUNDLE_ID_LEN], DuplicateEntry>,
    last_now: Instant,
    /// Persistence backend for bundle metadata (storage.md §6.3). Attached
    /// by the daemon at startup; `None` keeps the manager in-memory-only.
    store: Option<Arc<dyn Store + Send + Sync>>,
}

impl std::fmt::Debug for BundleManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleManager")
            .field("records", &self.records)
            .field("bundles_per_sender", &self.bundles_per_sender)
            .field("persisted", &self.store.is_some())
            .finish_non_exhaustive()
    }
}

impl BundleManager {
    #[must_use]
    pub fn new(objects: ObjectStore, quota: QuotaAccount) -> Self {
        Self {
            objects,
            quota,
            records: HashMap::new(),
            bundles_per_sender: HashMap::new(),
            duplicate_cache: HashMap::new(),
            last_now: Instant(0),
            store: None,
        }
    }

    /// Attaches (or detaches, with `None`) the metadata persistence
    /// backend: admits then save metas, removals and evictions delete them.
    pub fn set_persistence(&mut self, store: Option<Arc<dyn Store + Send + Sync>>) {
        self.store = store;
    }

    /// Current storage quota used by profile diagnostics and admission tests.
    #[must_use]
    pub fn quota(&self) -> &QuotaAccount {
        &self.quota
    }

    /// Restores persisted bundle records (storage.md §6.3): metadata is
    /// loaded from `store` and records are reconstructed for bundles whose
    /// ciphertext object still exists and whose expiry has not passed.
    /// Expired or orphaned metas are deleted. Quota reservations and
    /// per-sender counts are rebuilt so post-restart admission stays
    /// correctly accounted.
    ///
    /// # Errors
    ///
    /// Returns a message when the metadata cannot be scanned.
    pub fn restore(&mut self, store: &dyn Store, now: Instant) -> Result<usize, String> {
        self.last_now = now;
        self.prune_duplicate_cache(now);
        let metas = load_all_metas(store).map_err(|e| format!("bundle meta scan: {e:?}"))?;
        let mut restored = 0;
        for meta in metas {
            let Some(record) = meta.to_record() else {
                eprintln!("[bundle] restore: skipping corrupt bundle meta");
                continue;
            };
            if record.expires_at <= now && !record.custody_holds(now) {
                if let Err(e) = delete_meta(store, &record.id) {
                    eprintln!("[bundle] restore: expired meta delete failed: {e:?}");
                }
                continue;
            }
            if !self.objects.exists(&record.object_id) {
                eprintln!(
                    "[bundle] restore: dropping meta {:02x?}, payload object missing",
                    record.id
                );
                let _ = delete_meta(store, &record.id);
                continue;
            }
            if let Err(e) = self.quota.reserve(record.size as u64) {
                eprintln!(
                    "[bundle] restore: quota exceeded, dropping {:02x?}: {e:?}",
                    record.id
                );
                let _ = delete_meta(store, &record.id);
                continue;
            }
            *self
                .bundles_per_sender
                .entry(record.sender.clone())
                .or_insert(0) += 1;
            self.records.insert(record.id, record);
            restored += 1;
        }
        // Recalculate from the records that actually survived validation.
        // This makes restore idempotent and prevents a stale quota counter
        // from accumulating when recovery is retried in-process.
        self.rebuild_quota();
        Ok(restored)
    }

    /// Rebuilds storage usage from the live bundle records.
    ///
    /// Recovery and administrative repair paths may load, remove, or replace
    /// metadata without replaying every historical quota reservation.  The
    /// record set is authoritative, so recompute usage from its bounded sizes
    /// while preserving the configured profile and hard limit.
    pub fn rebuild_quota(&mut self) {
        let used = self.records.values().map(|record| record.size as u64).sum();
        self.quota = QuotaAccount::new(self.quota.profile, used, self.quota.hard_limit);
    }

    /// Admission (bundles.md §8.1): policy before allocation. Size, lifetime,
    /// and replication caps are validated first, then the Bundle ID duplicate
    /// check — a duplicate is rejected without reserving quota or writing the
    /// object — and only then is quota reserved and the payload stored.
    ///
    /// # Errors
    ///
    /// Returns `BundleError::TooLarge`, `BundleError::Expired`, or
    /// `BundleError::ReplicationLimit` for policy violations, and
    /// `BundleError::Duplicate` when the Bundle ID is already held.
    /// `BundleError::QuotaExceeded` covers both the per-sender bundle cap and
    /// the storage quota; `BundleError::Storage` wraps object-store failures.
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<[u8; BUNDLE_ID_LEN], BundleError> {
        self.last_now = now;
        self.prune_duplicate_cache(now);
        if payload.len() > DEFAULT_MAX_BUNDLE_BYTES {
            return Err(BundleError::TooLarge);
        }
        if lifetime_ms > MAX_LIFETIME_MS {
            return Err(BundleError::Expired);
        }
        if replication_limit > DEFAULT_MAX_REPLICATION {
            return Err(BundleError::ReplicationLimit);
        }
        if *self.bundles_per_sender.get(sender).unwrap_or(&0) >= MAX_BUNDLES_PER_SENDER {
            return Err(BundleError::QuotaExceeded);
        }
        // Duplicate check BEFORE allocation (bundles.md §12): no quota
        // reservation and no object write for a bundle we already hold.
        // Provisional envelope: the Bundle ID is content-derived from the
        // ciphertext payload; the sender-side envelope path lands later.
        let envelope = crate::envelope::BundleEnvelope {
            sender_ephemeral_public_key: [0u8; 32],
            encrypted_payload: payload.to_vec(),
        };
        let id = bundle_id(&envelope, destination_hint);
        if self.records.contains_key(&id) {
            return Err(BundleError::Duplicate);
        }
        if self.duplicate_cache.contains_key(&id) {
            return Err(BundleError::Duplicate);
        }
        // Reserve quota BEFORE allocation (resource-limits.md §32).
        self.quota
            .reserve(payload.len() as u64)
            .map_err(|_| BundleError::QuotaExceeded)?;
        let object_id = blake2s(payload);
        self.objects
            .put(&object_id, payload)
            .map_err(BundleError::Storage)?;
        let lifetime = lifetime_ms.max(1_000);
        self.records.insert(
            id,
            BundleRecord {
                id,
                object_id,
                sender: sender.to_vec(),
                destination_hint: destination_hint.to_vec(),
                size: payload.len(),
                priority,
                created_at: now,
                expires_at: now + Duration::from_millis(lifetime),
                replication_count: 0,
                replication_limit,
                custody,
                custody_deadline: custody.then_some(now + Duration::from_millis(lifetime)),
                transfer_chunk_index: 0,
                status: if custody {
                    BundleStatus::CustodyAccepted
                } else {
                    BundleStatus::Received
                },
            },
        );
        *self.bundles_per_sender.entry(sender.to_vec()).or_insert(0) += 1;
        // Persistence is best-effort: a failed meta write never fails the
        // admission; the record lives on in memory and the next restart
        // simply loses it (storage.md §6.3).
        if let Some(store) = &self.store {
            if let Some(record) = self.records.get(&id) {
                if let Err(e) = save_meta(store.as_ref(), &BundleMeta::from_record(record)) {
                    println!("[bundle] admit: meta persist failed: {e:?}");
                }
            }
        }
        Ok(id)
    }

    /// Reads the stored ciphertext payload for a bundle record.
    ///
    /// # Errors
    ///
    /// Returns `BundleError::NotFound` for an unknown ID, or
    /// `BundleError::Storage` when the object is missing or corrupt.
    pub fn get_payload(&self, id: &[u8; BUNDLE_ID_LEN]) -> Result<Vec<u8>, BundleError> {
        let record = self.records.get(id).ok_or(BundleError::NotFound)?;
        self.objects
            .get(&record.object_id)
            .map_err(BundleError::Storage)
    }

    /// Returns and advances one bounded transfer chunk for a stored bundle.
    /// The record remains `Received` until the caller observes `final_chunk`
    /// and explicitly marks the handoff.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::NotFound`] for an unknown bundle,
    /// [`BundleError::Conflict`] for an invalid chunk size or cursor, and
    /// [`BundleError::Storage`] when the payload cannot be read.
    pub fn next_transfer_chunk(
        &mut self,
        id: &[u8; BUNDLE_ID_LEN],
        chunk_size: usize,
    ) -> Result<Option<BundleTransferChunk>, BundleError> {
        if chunk_size == 0 {
            return Err(BundleError::Conflict);
        }
        let record = self.records.get(id).cloned().ok_or(BundleError::NotFound)?;
        let payload = self.get_payload(id)?;
        let index = record.transfer_chunk_index;
        let start = usize::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(chunk_size))
            .ok_or(BundleError::Conflict)?;
        if start >= payload.len() {
            return Ok(None);
        }
        let end = start
            .checked_add(chunk_size)
            .unwrap_or(payload.len())
            .min(payload.len());
        let final_chunk = end == payload.len();
        if let Some(current) = self.records.get_mut(id) {
            current.transfer_chunk_index = index.saturating_add(1);
        }
        self.persist_record(id);
        Ok(Some((
            self.records.get(id).cloned().unwrap_or(record),
            payload[start..end].to_vec(),
            index,
            final_chunk,
        )))
    }

    #[must_use]
    pub fn record(&self, id: &[u8; BUNDLE_ID_LEN]) -> Option<&BundleRecord> {
        self.records.get(id)
    }

    #[must_use]
    pub fn record_mut(&mut self, id: &[u8; BUNDLE_ID_LEN]) -> Option<&mut BundleRecord> {
        self.records.get_mut(id)
    }

    /// Updates a bundle's status (bundles.md §13).
    ///
    /// # Errors
    ///
    /// Returns `BundleError::NotFound` for an unknown ID.
    pub fn set_status(
        &mut self,
        id: &[u8; BUNDLE_ID_LEN],
        status: BundleStatus,
    ) -> Result<(), BundleError> {
        let record = self.records.get_mut(id).ok_or(BundleError::NotFound)?;
        record.status = status;
        // Status changes must survive restarts: re-persist the metadata
        // (best-effort, like admit).
        if let Some(store) = self.store.as_deref() {
            let meta = crate::persist::BundleMeta::from_record(record);
            let _ = crate::persist::save_meta(store, &meta);
        }
        Ok(())
    }

    /// Extends or shortens the deadline of an accepted custody commitment.
    /// The deadline is explicit so a node cannot accidentally promise
    /// unbounded retention.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::NotFound`] for an unknown bundle and
    /// [`BundleError::Conflict`] when the bundle is not in custody.
    pub fn set_custody_deadline(
        &mut self,
        id: &[u8; BUNDLE_ID_LEN],
        deadline: Instant,
    ) -> Result<(), BundleError> {
        let record = self.records.get_mut(id).ok_or(BundleError::NotFound)?;
        if !record.custody || record.status != BundleStatus::CustodyAccepted {
            return Err(BundleError::Conflict);
        }
        record.custody_deadline = Some(deadline);
        self.persist_record(id);
        Ok(())
    }

    /// Explicitly releases custody after a delivery acknowledgement. The
    /// payload remains addressable until normal expiry/eviction.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::NotFound`] for an unknown bundle.
    pub fn release_custody(&mut self, id: &[u8; BUNDLE_ID_LEN]) -> Result<(), BundleError> {
        let record = self.records.get_mut(id).ok_or(BundleError::NotFound)?;
        if !record.custody {
            return Ok(());
        }
        record.custody = false;
        record.custody_deadline = None;
        record.status = BundleStatus::Delivered;
        self.persist_record(id);
        Ok(())
    }

    fn persist_record(&self, id: &[u8; BUNDLE_ID_LEN]) {
        if let (Some(store), Some(record)) = (&self.store, self.records.get(id)) {
            let _ = save_meta(store.as_ref(), &BundleMeta::from_record(record));
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn records_iter(&self) -> impl Iterator<Item = &BundleRecord> {
        self.records.values()
    }

    #[must_use]
    pub fn duplicate_cache_len(&self) -> usize {
        self.duplicate_cache.len()
    }

    /// Removes a bundle record, releasing its quota reservation and sender
    /// count (bundles.md §11, resource-limits.md §33).
    pub fn remove(&mut self, id: &[u8; BUNDLE_ID_LEN]) {
        self.remove_at(id, self.last_now);
    }

    /// Removes a bundle and records its id in the bounded replay cache at a
    /// caller-supplied clock value.
    pub fn remove_at(&mut self, id: &[u8; BUNDLE_ID_LEN], now: Instant) {
        self.last_now = now;
        if let Some(record) = self.records.remove(id) {
            self.quota.release(record.size as u64);
            if let Some(count) = self.bundles_per_sender.get_mut(&record.sender) {
                *count = count.saturating_sub(1);
            }
            if let Some(store) = &self.store {
                if let Err(e) = delete_meta(store.as_ref(), id) {
                    println!("[bundle] remove: meta delete failed: {e:?}");
                }
            }
            self.remember_duplicate(record.id, now);
        }
    }

    /// Evicts expired bundles (bundles.md §11): each expired record is
    /// removed and its object-store payload deleted, releasing the quota
    /// reservation and sender count via [`BundleManager::remove`]. Returns
    /// the evicted ids, sorted for deterministic ordering.
    #[must_use]
    pub fn evict_expired(&mut self, now: Instant) -> Vec<[u8; BUNDLE_ID_LEN]> {
        self.last_now = now;
        self.prune_duplicate_cache(now);
        let mut expired: Vec<([u8; BUNDLE_ID_LEN], [u8; 32])> = self
            .records_iter()
            .filter(|r| r.expires_at <= now && !r.custody_holds(now))
            .map(|r| (r.id, r.object_id))
            .collect();
        expired.sort_unstable();
        let mut ids = Vec::with_capacity(expired.len());
        for (id, object_id) in expired {
            // Content-addressed objects may be shared by identical payloads
            // under different destinations: only delete when no OTHER live
            // record references the object.
            let still_referenced = self
                .records_iter()
                .any(|r| r.id != id && r.object_id == object_id);
            if !still_referenced {
                if let Err(e) = self.objects.delete(&object_id) {
                    println!("[bundle] evict: object delete failed: {e:?}");
                }
            }
            self.remove_at(&id, now);
            ids.push(id);
        }
        ids
    }

    fn prune_duplicate_cache(&mut self, now: Instant) {
        self.duplicate_cache
            .retain(|_, entry| entry.expires_at > now);
    }

    fn remember_duplicate(&mut self, id: [u8; BUNDLE_ID_LEN], now: Instant) {
        self.prune_duplicate_cache(now);
        if self.duplicate_cache.len() >= DUPLICATE_CACHE_CAPACITY {
            if let Some(oldest) = self
                .duplicate_cache
                .iter()
                .min_by_key(|(_, entry)| entry.inserted_at)
                .map(|(id, _)| *id)
            {
                self.duplicate_cache.remove(&oldest);
            }
        }
        self.duplicate_cache.insert(
            id,
            DuplicateEntry {
                expires_at: now + Duration::from_millis(DUPLICATE_CACHE_TTL_MS),
                inserted_at: now,
            },
        );
    }
}

impl BundleRecord {
    #[must_use]
    pub fn custody_holds(&self, now: Instant) -> bool {
        self.custody
            && self.status == BundleStatus::CustodyAccepted
            && self.custody_deadline.is_some_and(|deadline| now < deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "umc-bundle-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn manager() -> BundleManager {
        let dir = temp_dir();
        let objects = ObjectStore::open(dir).unwrap();
        let quota = QuotaAccount::new(umc_storage::quota::Profile::Standard, 0, 1_048_576);
        BundleManager::new(objects, quota)
    }

    #[test]
    fn admit_store_read_round_trip() {
        let mut m = manager();
        let id = m
            .admit(
                b"payload",
                b"sender-a",
                b"dest-hint",
                1,
                DEFAULT_LIFETIME_MS,
                3,
                false,
                Instant(0),
            )
            .unwrap();
        assert_eq!(m.get_payload(&id).unwrap(), b"payload");
        assert_eq!(m.record(&id).unwrap().status, BundleStatus::Received);
    }

    #[test]
    fn duplicates_rejected() {
        let mut m = manager();
        m.admit(
            b"same",
            b"s",
            b"d",
            1,
            DEFAULT_LIFETIME_MS,
            3,
            false,
            Instant(0),
        )
        .unwrap();
        assert_eq!(
            m.admit(
                b"same",
                b"s",
                b"d",
                1,
                DEFAULT_LIFETIME_MS,
                3,
                false,
                Instant(0)
            ),
            Err(BundleError::Duplicate)
        );
    }

    #[test]
    fn size_and_lifetime_bounds() {
        let mut m = manager();
        let oversized = vec![0u8; DEFAULT_MAX_BUNDLE_BYTES + 1];
        assert_eq!(
            m.admit(
                &oversized,
                b"s",
                b"d",
                1,
                DEFAULT_LIFETIME_MS,
                3,
                false,
                Instant(0)
            ),
            Err(BundleError::TooLarge)
        );
        assert_eq!(
            m.admit(
                b"x",
                b"s",
                b"d",
                1,
                MAX_LIFETIME_MS + 1,
                3,
                false,
                Instant(0)
            ),
            Err(BundleError::Expired)
        );
        assert_eq!(
            m.admit(
                b"x",
                b"s",
                b"d",
                1,
                DEFAULT_LIFETIME_MS,
                9,
                false,
                Instant(0)
            ),
            Err(BundleError::ReplicationLimit)
        );
    }

    #[test]
    fn quota_enforced_before_allocation() {
        let objects = ObjectStore::open(temp_dir()).unwrap();
        let quota = QuotaAccount::new(umc_storage::quota::Profile::Standard, 0, 10);
        let mut m = BundleManager::new(objects, quota);
        assert_eq!(
            m.admit(
                &[0u8; 11],
                b"s",
                b"d",
                1,
                DEFAULT_LIFETIME_MS,
                3,
                false,
                Instant(0)
            ),
            Err(BundleError::QuotaExceeded)
        );
    }

    #[test]
    fn custody_sets_status() {
        let mut m = manager();
        let id = m
            .admit(
                b"p",
                b"s",
                b"d",
                1,
                DEFAULT_LIFETIME_MS,
                3,
                true,
                Instant(0),
            )
            .unwrap();
        assert_eq!(m.record(&id).unwrap().status, BundleStatus::CustodyAccepted);
    }

    #[test]
    fn custody_hold_survives_expiry_until_deadline_or_release() {
        let mut m = manager();
        let id = m
            .admit(b"custody", b"s", b"d", 1, 1_000, 3, true, Instant(0))
            .unwrap();
        m.set_custody_deadline(&id, Instant(5_000)).unwrap();
        assert!(m.evict_expired(Instant(1_000)).is_empty());
        assert!(m.record(&id).is_some());

        m.release_custody(&id).unwrap();
        assert_eq!(m.record(&id).unwrap().status, BundleStatus::Delivered);
        assert_eq!(m.evict_expired(Instant(5_000)), vec![id]);
    }

    #[test]
    fn removed_bundle_ids_are_suppressed_by_bounded_cache() {
        let mut m = manager();
        let id = m
            .admit(b"replay", b"s", b"d", 1, 1_000, 3, false, Instant(0))
            .unwrap();
        m.remove_at(&id, Instant(10));
        assert_eq!(m.duplicate_cache_len(), 1);
        assert_eq!(
            m.admit(b"replay", b"s", b"d", 1, 1_000, 3, false, Instant(11)),
            Err(BundleError::Duplicate)
        );
        assert_eq!(m.duplicate_cache_len(), 1);
        assert!(m
            .admit(
                b"replay",
                b"s",
                b"d",
                1,
                1_000,
                3,
                false,
                Instant(10 + DUPLICATE_CACHE_TTL_MS + 1),
            )
            .is_ok());
    }

    #[test]
    fn evict_expired_removes_records_objects_and_accounting() {
        let mut m = manager();
        let id = m
            .admit(b"a", b"s", b"d", 1, 1_000, 3, false, Instant(0))
            .unwrap();
        let object_id = m.records[&id].object_id;
        assert!(m.objects.exists(&object_id));
        assert_eq!(m.quota.used(), 1);
        assert_eq!(m.evict_expired(Instant(1_000)), vec![id]);
        assert!(m.records.is_empty());
        assert!(!m.objects.exists(&object_id));
        assert_eq!(m.quota.used(), 0);
    }

    #[test]
    fn rebuild_quota_matches_live_records() {
        let mut m = manager();
        m.admit(
            b"first",
            b"sender",
            b"dest-1",
            1,
            1_000,
            1,
            false,
            Instant(0),
        )
        .unwrap();
        m.admit(
            b"second-payload",
            b"sender",
            b"dest-2",
            1,
            1_000,
            1,
            false,
            Instant(0),
        )
        .unwrap();
        m.quota.release(m.quota.used());
        assert_eq!(m.quota.used(), 0);
        m.rebuild_quota();
        assert_eq!(m.quota.used(), 5 + 14);
    }
}
