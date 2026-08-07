//! Bundle metadata persistence (storage.md §6.3): records survive daemon
//! restarts as JSON under the `bundle` namespace, keyed by the 32-byte
//! Bundle ID. The ciphertext payloads themselves are content-addressed
//! objects in the object store (objects.rs) and are the durable copy; a
//! restored record reads its payload back via the persisted `object_id`.
use crate::manager::{BundleRecord, BundleStatus};
use serde::{Deserialize, Serialize};
use umc_storage::store::{Namespace, Store, StoreError};
use umc_types::runtime::Instant;

/// Stable on-wire status codes: the persisted format is fixed, independent
/// of enum declaration order.
#[must_use]
pub fn status_code(status: &BundleStatus) -> u8 {
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
pub fn status_from_code(code: u8) -> Option<BundleStatus> {
    Some(match code {
        0 => BundleStatus::Received,
        1 => BundleStatus::CustodyAccepted,
        2 => BundleStatus::Forwarded,
        3 => BundleStatus::Delivered,
        4 => BundleStatus::Rejected,
        5 => BundleStatus::Expired,
        6 => BundleStatus::Evicted,
        _ => return None,
    })
}

/// Serialized form of a [`BundleRecord`]. Slices are stored as `Vec<u8>`
/// (serde cannot derive fixed-size arrays beyond 32 elements without
/// helpers); `object_id` is persisted because the content address can only
/// be recomputed from the ciphertext payload, which the restore path does
/// not hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleMeta {
    pub id: Vec<u8>,
    pub object_id: Vec<u8>,
    pub size: usize,
    pub status: u8,
    pub lifetime_ms: u64,
    pub expires_at_ms: u64,
    pub created_at_ms: u64,
    pub sender: Vec<u8>,
    pub destination_hint: Vec<u8>,
    pub priority: u64,
    pub replication_limit: u64,
    pub custody: bool,
}

impl BundleMeta {
    #[must_use]
    pub fn from_record(record: &BundleRecord) -> Self {
        Self {
            id: record.id.to_vec(),
            object_id: record.object_id.to_vec(),
            size: record.size,
            status: status_code(&record.status),
            lifetime_ms: record
                .expires_at
                .duration_since(record.created_at)
                .as_millis(),
            expires_at_ms: record.expires_at.0,
            created_at_ms: record.created_at.0,
            sender: record.sender.clone(),
            destination_hint: record.destination_hint.clone(),
            priority: record.priority,
            replication_limit: record.replication_limit,
            custody: record.custody,
        }
    }

    /// Rebuilds the in-memory record. Returns `None` when the meta has a
    /// corrupt shape (wrong `id`/`object_id` lengths) or an unknown status code.
    #[must_use]
    pub fn to_record(&self) -> Option<BundleRecord> {
        let id: [u8; 32] = self.id.as_slice().try_into().ok()?;
        let object_id: [u8; 32] = self.object_id.as_slice().try_into().ok()?;
        Some(BundleRecord {
            id,
            object_id,
            sender: self.sender.clone(),
            destination_hint: self.destination_hint.clone(),
            size: self.size,
            priority: self.priority,
            created_at: Instant(self.created_at_ms),
            expires_at: Instant(self.expires_at_ms),
            replication_count: 0,
            replication_limit: self.replication_limit,
            custody: self.custody,
            status: status_from_code(self.status)?,
        })
    }
}

/// Persists one bundle meta under the bundle namespace, keyed by id bytes.
///
/// # Errors
///
/// Returns [`StoreError::Serialization`] when the meta cannot be encoded,
/// or the store's own error on backend failure.
pub fn save_meta(store: &dyn Store, meta: &BundleMeta) -> Result<(), StoreError> {
    let value = serde_json::to_vec(meta).map_err(|_| StoreError::Serialization)?;
    store.put(Namespace::Bundle, &meta.id, &value)
}

/// Removes the persisted meta for a bundle id; a missing key is a no-op.
///
/// # Errors
///
/// Returns the store's error on backend failure.
pub fn delete_meta(store: &dyn Store, id: &[u8; 32]) -> Result<(), StoreError> {
    store.delete(Namespace::Bundle, id)
}

/// Loads every persisted bundle meta; corrupt entries are skipped with a
/// log line (a partial restore is better than a fatal one).
///
/// # Errors
///
/// Returns the store's error when the namespace cannot be scanned.
pub fn load_all_metas(store: &dyn Store) -> Result<Vec<BundleMeta>, StoreError> {
    let mut metas = Vec::new();
    for entry in store.scan(Namespace::Bundle)? {
        match serde_json::from_slice::<BundleMeta>(&entry.value) {
            Ok(meta) => metas.push(meta),
            Err(e) => eprintln!("[bundle] skipping corrupt bundle meta: {e}"),
        }
    }
    Ok(metas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::{BundleManager, DEFAULT_LIFETIME_MS};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use umc_storage::objects::{blake2s, ObjectStore};
    use umc_storage::quota::{Profile, QuotaAccount};
    use umc_storage::sqlite::SqliteStore;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "umc-bundle-persist-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn store(dir: &std::path::Path) -> Arc<SqliteStore> {
        std::fs::create_dir_all(dir).expect("create temp dir");
        Arc::new(SqliteStore::open(&dir.join("meta.db")).expect("sqlite store"))
    }

    #[test]
    fn meta_round_trip() {
        let dir = temp_dir();
        let store = store(&dir);
        let mut m = BundleManager::new(
            ObjectStore::open(dir).unwrap(),
            QuotaAccount::new(Profile::Standard, 0, 1_048_576),
        );
        m.set_persistence(Some(store.clone()));
        let id = m
            .admit(
                b"payload",
                b"sender-a",
                b"dest-hint",
                3,
                DEFAULT_LIFETIME_MS,
                2,
                true,
                Instant(0),
            )
            .unwrap();
        let metas = load_all_metas(store.as_ref()).unwrap();
        assert_eq!(metas.len(), 1);
        let meta = &metas[0];
        assert_eq!(meta.id, id.to_vec());
        assert_eq!(meta.sender, b"sender-a");
        assert_eq!(meta.destination_hint, b"dest-hint");
        assert_eq!(meta.size, 7);
        assert_eq!(meta.priority, 3);
        assert_eq!(meta.status, status_code(&BundleStatus::CustodyAccepted));
        assert!(meta.custody);
        assert_eq!(meta.created_at_ms, 0);
        assert_eq!(meta.expires_at_ms, DEFAULT_LIFETIME_MS);
        assert_eq!(meta.lifetime_ms, DEFAULT_LIFETIME_MS);
        assert_eq!(meta.object_id, blake2s(b"payload").to_vec());

        // Round-trip back into a record.
        let record = meta.to_record().expect("record");
        assert_eq!(record.id, id);
        assert_eq!(record.sender, b"sender-a");
        assert_eq!(record.destination_hint, b"dest-hint");
        assert_eq!(record.size, 7);
        assert_eq!(record.priority, 3);
        assert!(record.custody);
        assert_eq!(record.created_at, Instant(0));
        assert_eq!(record.expires_at, Instant(DEFAULT_LIFETIME_MS));
        assert_eq!(record.status, BundleStatus::CustodyAccepted);

        // Delete removes the meta; a second delete is a no-op.
        delete_meta(store.as_ref(), &id).unwrap();
        assert!(load_all_metas(store.as_ref()).unwrap().is_empty());
        delete_meta(store.as_ref(), &id).unwrap();
    }

    #[test]
    fn corrupt_entries_are_skipped() {
        let dir = temp_dir();
        let store = store(&dir);
        store
            .put(Namespace::Bundle, b"corrupt", b"not json")
            .unwrap();
        assert!(load_all_metas(store.as_ref()).unwrap().is_empty());
    }

    #[test]
    fn restore_reconstructs_records() {
        let dir = temp_dir();
        let store = store(&dir);
        let mut first = BundleManager::new(
            ObjectStore::open(dir.clone()).unwrap(),
            QuotaAccount::new(Profile::Standard, 0, 1_048_576),
        );
        first.set_persistence(Some(store.clone()));
        let id = first
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
        // A bundle with the minimum clamped lifetime expires at t=1000.
        let expired_id = first
            .admit(
                b"expired",
                b"sender-b",
                b"dest-hint",
                1,
                1_000,
                3,
                false,
                Instant(0),
            )
            .unwrap();
        assert_eq!(first.len(), 2);
        drop(first);

        // A fresh manager over the same object store and database restores
        // the live bundle; the expired one is dropped and its meta deleted.
        let mut second = BundleManager::new(
            ObjectStore::open(dir).unwrap(),
            QuotaAccount::new(Profile::Standard, 0, 1_048_576),
        );
        assert_eq!(second.restore(store.as_ref(), Instant(1_000)).unwrap(), 1);

        let record = second.record(&id).expect("restored record");
        assert_eq!(record.size, 7);
        assert_eq!(record.sender, b"sender-a");
        assert_eq!(record.status, BundleStatus::Received);
        assert_eq!(second.get_payload(&id).unwrap(), b"payload");
        assert!(second.record(&expired_id).is_none());
        let metas = load_all_metas(store.as_ref()).unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].id, id.to_vec());
    }

    #[test]
    fn restore_keeps_quota_and_sender_accounting() {
        let dir = temp_dir();
        let store = store(&dir);
        let mut first = BundleManager::new(
            ObjectStore::open(dir.clone()).unwrap(),
            QuotaAccount::new(Profile::Standard, 0, 100),
        );
        first.set_persistence(Some(store.clone()));
        let id = first
            .admit(
                b"0123456789",
                b"sender-a",
                b"dest-hint",
                1,
                DEFAULT_LIFETIME_MS,
                3,
                false,
                Instant(0),
            )
            .unwrap();
        drop(first);

        let mut second = BundleManager::new(
            ObjectStore::open(dir).unwrap(),
            QuotaAccount::new(Profile::Standard, 0, 100),
        );
        second.restore(store.as_ref(), Instant(0)).unwrap();
        // Quota and sender counts are restored: removing the bundle frees
        // its 10 bytes, and the sender cap still sees one live bundle.
        second.remove(&id);
        assert!(second
            .admit(
                b"0123456789",
                b"sender-a",
                b"dest-hint",
                1,
                DEFAULT_LIFETIME_MS,
                3,
                false,
                Instant(0)
            )
            .is_ok());
    }
}
