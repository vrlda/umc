//! Daemon event log (core.md §8): a bounded in-memory record of notable
//! runtime transitions (session active, circuit opened, bundle admitted).
//! When a store is attached the events also persist under the `api`
//! namespace (core.md §15 audit logging), so the history survives restarts.
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use umc_storage::sqlite::SqliteStore;
use umc_storage::store::{Namespace, Store, StoreError};

/// Upper bound on persisted audit rows: pushes beyond this cap trim the
/// oldest persisted entry, keeping the on-disk ring bounded like the
/// in-memory one.
pub const PERSISTED_MAX_ENTRIES: u64 = 10_000;

/// One recorded event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonEvent {
    pub kind: String,
    pub at_ms: u64,
    pub detail: String,
}

impl fmt::Display for DaemonEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}: {}", self.kind, self.at_ms, self.detail)
    }
}

/// Bounded event ring: pushes trim to `max_entries`; `recent` returns the
/// newest first. With a store attached, every push is also persisted under
/// the `api` namespace keyed by a zero-padded sequence number (keys order
/// lexicographically like the sequence).
pub struct DaemonEvents {
    log: Vec<DaemonEvent>,
    max_entries: usize,
    store: Option<Arc<SqliteStore>>,
    /// Monotonic key sequence for persisted events; continues from the
    /// highest sequence observed at restore.
    persisted_seq: u64,
}

impl fmt::Debug for DaemonEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DaemonEvents")
            .field("len", &self.log.len())
            .field("max_entries", &self.max_entries)
            .field("persisted_seq", &self.persisted_seq)
            .field("store_attached", &self.store.is_some())
            .finish()
    }
}

impl DaemonEvents {
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            log: Vec::new(),
            max_entries,
            store: None,
            persisted_seq: 0,
        }
    }

    /// Attaches the node database so events persist under the `api`
    /// namespace (storage.md §15 audit logging).
    pub fn attach_store(&mut self, store: Arc<SqliteStore>) {
        self.store = Some(store);
    }

    /// Loads persisted events back into the ring so audit history survives
    /// restarts: rows under the `api` namespace are read in sequence order,
    /// corrupt or non-numeric entries are skipped, and the ring is trimmed
    /// to `max_entries` (newest wins). Restore failures are logged, never
    /// fatal.
    pub fn restore_persisted(&mut self, store: &dyn Store) {
        let entries = match store.scan(Namespace::Api) {
            Ok(entries) => entries,
            Err(e) => {
                log::error!("[events] failed to scan persisted events: {e:?}");
                return;
            }
        };
        let mut max_seq = 0u64;
        for entry in entries {
            let key = String::from_utf8_lossy(&entry.key);
            let Ok(seq) = key.parse::<u64>() else {
                log::warn!("[events] skipping persisted event with non-numeric key {key:?}");
                continue;
            };
            max_seq = max_seq.max(seq);
            match serde_json::from_slice::<DaemonEvent>(&entry.value) {
                Ok(event) => self.log.push(event),
                Err(e) => {
                    log::warn!("[events] skipping corrupt persisted event {key}: {e}");
                }
            }
        }
        // The in-memory ring is bounded: only the newest max_entries
        // survive a restore.
        let excess = self.log.len().saturating_sub(self.max_entries);
        if excess > 0 {
            self.log.drain(..excess);
        }
        // Continue the persisted sequence where the store left off.
        self.persisted_seq = self.persisted_seq.max(max_seq);
    }

    /// Append an event, dropping the oldest entries beyond the cap.
    pub fn push(&mut self, event: DaemonEvent) {
        if let Some(store) = self.store.clone() {
            self.persist(store.as_ref(), &event);
        }
        self.log.push(event);
        let excess = self.log.len().saturating_sub(self.max_entries);
        if excess > 0 {
            self.log.drain(..excess);
        }
    }

    /// Writes one event under the `api` namespace and trims the persisted
    /// ring to [`PERSISTED_MAX_ENTRIES`] rows (FIFO). Persistence failures
    /// are logged; they never fail the in-memory push.
    fn persist(&mut self, store: &dyn Store, event: &DaemonEvent) {
        self.persisted_seq += 1;
        let seq = self.persisted_seq;
        let key = format!("{seq:020}");
        let value = match serde_json::to_vec(event).map_err(|_| StoreError::Serialization) {
            Ok(value) => value,
            Err(e) => {
                log::error!("[events] failed to serialize event: {e:?}");
                return;
            }
        };
        if let Err(e) = store.put(Namespace::Api, key.as_bytes(), &value) {
            log::error!("[events] failed to persist event {seq}: {e:?}");
        }
        if seq > PERSISTED_MAX_ENTRIES {
            let stale = format!("{:020}", seq - PERSISTED_MAX_ENTRIES);
            if let Err(e) = store.delete(Namespace::Api, stale.as_bytes()) {
                log::error!("[events] failed to trim persisted event {stale}: {e:?}");
            }
        }
    }

    /// The `limit` most recent events, newest first.
    #[must_use]
    pub fn recent(&self, limit: usize) -> Vec<DaemonEvent> {
        let start = self.log.len().saturating_sub(limit);
        self.log[start..].iter().rev().cloned().collect()
    }

    // len/is_empty are test-only until a metrics or diagnostics surface
    // reports the ring occupancy; the control path reads via recent().
    #[allow(dead_code)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.log.len()
    }

    #[allow(dead_code)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use umc_storage::sqlite::SqliteStore;
    use umc_storage::store::Namespace;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn event(kind: &str, at_ms: u64) -> DaemonEvent {
        DaemonEvent {
            kind: kind.to_string(),
            at_ms,
            detail: "detail".to_string(),
        }
    }

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "umcd-events-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn store(dir: &std::path::Path) -> Arc<SqliteStore> {
        std::fs::create_dir_all(dir).expect("create temp dir");
        Arc::new(SqliteStore::open(&dir.join("events.db")).expect("sqlite store"))
    }

    #[test]
    fn push_persists_and_restore_recovers() {
        let dir = temp_dir();
        let store = store(&dir);
        let mut log = DaemonEvents::new(200);
        log.attach_store(store.clone());
        log.push(event("session_active", 10));
        log.push(event("circuit_opened", 20));
        log.push(event("bundle_admitted", 30));
        drop(log);

        // A fresh log over the same database restores the full history,
        // newest first.
        let mut restarted = DaemonEvents::new(200);
        restarted.restore_persisted(store.as_ref());
        let recent = restarted.recent(10);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].at_ms, 30);
        assert_eq!(recent[1].at_ms, 20);
        assert_eq!(recent[2].at_ms, 10);
    }

    #[test]
    fn persisted_ring_is_bounded() {
        let dir = temp_dir();
        let store = store(&dir);
        let mut log = DaemonEvents::new(100);
        log.attach_store(store.clone());
        for i in 0..=PERSISTED_MAX_ENTRIES {
            log.push(event("session_active", i));
        }
        let rows = store.scan(Namespace::Api).expect("scan api");
        assert_eq!(rows.len() as u64, PERSISTED_MAX_ENTRIES);
        // The in-memory ring still trims at max_entries.
        assert_eq!(log.len(), 100);
        assert_eq!(log.recent(10)[0].at_ms, PERSISTED_MAX_ENTRIES);
    }

    #[test]
    fn restore_skips_corrupt() {
        let dir = temp_dir();
        let store = store(&dir);
        let mut log = DaemonEvents::new(200);
        log.attach_store(store.clone());
        log.push(event("session_active", 10));
        log.push(event("circuit_opened", 20));
        // A garbage row under the api namespace: not JSON, non-numeric key.
        store
            .put(Namespace::Api, b"garbage", b"not json")
            .expect("put garbage");
        drop(log);

        // The valid events load; the corrupt row is skipped without a panic.
        let mut restarted = DaemonEvents::new(200);
        restarted.restore_persisted(store.as_ref());
        let recent = restarted.recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].at_ms, 20);
        assert_eq!(recent[1].at_ms, 10);
    }

    #[test]
    fn push_trims_at_cap() {
        let mut log = DaemonEvents::new(3);
        for i in 0..5 {
            log.push(event("session_active", i));
        }
        assert_eq!(log.len(), 3);
        assert_eq!(log.recent(10)[0].at_ms, 4);
        assert_eq!(log.recent(10)[2].at_ms, 2);
    }

    #[test]
    fn recent_returns_newest_first_and_bounded() {
        let mut log = DaemonEvents::new(200);
        for i in 0..5 {
            log.push(event("bundle_admitted", i));
        }
        let recent = log.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].at_ms, 4);
        assert_eq!(recent[1].at_ms, 3);
        assert!(log.recent(0).is_empty());
    }
}
