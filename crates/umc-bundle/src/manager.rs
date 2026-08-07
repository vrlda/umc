//! Bundle manager (bundles.md §9-10, §12): validate policy before allocation,
//! store payloads as content-addressed objects, deduplicate by Bundle ID.
use crate::id::{bundle_id, BUNDLE_ID_LEN};
use std::collections::HashMap;
use umc_storage::objects::{blake2s, ObjectStore};
use umc_storage::quota::QuotaAccount;
use umc_storage::store::StoreError;
use umc_types::runtime::{Duration, Instant};

pub const DEFAULT_MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub const MAX_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;
pub const DEFAULT_MAX_REPLICATION: u64 = 8;
pub const MAX_BUNDLES_PER_SENDER: u64 = 1_000;

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
    pub status: BundleStatus,
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

#[derive(Debug)]
pub struct BundleManager {
    objects: ObjectStore,
    quota: QuotaAccount,
    records: HashMap<[u8; BUNDLE_ID_LEN], BundleRecord>,
    bundles_per_sender: HashMap<Vec<u8>, u64>,
}

impl BundleManager {
    #[must_use]
    pub fn new(objects: ObjectStore, quota: QuotaAccount) -> Self {
        Self {
            objects,
            quota,
            records: HashMap::new(),
            bundles_per_sender: HashMap::new(),
        }
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
                status: if custody {
                    BundleStatus::CustodyAccepted
                } else {
                    BundleStatus::Received
                },
            },
        );
        *self.bundles_per_sender.entry(sender.to_vec()).or_insert(0) += 1;
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
        Ok(())
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

    /// Removes a bundle record, releasing its quota reservation and sender
    /// count (bundles.md §11, resource-limits.md §33).
    pub fn remove(&mut self, id: &[u8; BUNDLE_ID_LEN]) {
        if let Some(record) = self.records.remove(id) {
            self.quota.release(record.size as u64);
            if let Some(count) = self.bundles_per_sender.get_mut(&record.sender) {
                *count = count.saturating_sub(1);
            }
        }
    }

    /// Evicts expired bundles (bundles.md §11): each expired record is
    /// removed and its object-store payload deleted, releasing the quota
    /// reservation and sender count via [`BundleManager::remove`]. Returns
    /// the evicted ids, sorted for deterministic ordering.
    #[must_use]
    pub fn evict_expired(&mut self, now: Instant) -> Vec<[u8; BUNDLE_ID_LEN]> {
        let mut expired: Vec<([u8; BUNDLE_ID_LEN], [u8; 32])> = self
            .records_iter()
            .filter(|r| r.expires_at <= now)
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
            self.remove(&id);
            ids.push(id);
        }
        ids
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
}
