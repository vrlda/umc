//! In-process storage backend for embedded and ephemeral deployments.
//!
//! `MemoryStore` implements the same atomic namespace/key contract as the
//! `SQLite` backend. It intentionally has no persistence or crash-recovery
//! promise; callers that need restart durability must use `SqliteStore`.

use crate::store::{Entry, Namespace, Store, StoreError};
use std::collections::BTreeMap;
use std::sync::Mutex;

type MemoryEntries = BTreeMap<(String, Vec<u8>), Vec<u8>>;

#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: Mutex<MemoryEntries>,
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn get(&self, namespace: Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.entries
            .lock()
            .map_err(|_| StoreError::Transaction)
            .map(|entries| {
                entries
                    .get(&(namespace.as_str().to_owned(), key.to_vec()))
                    .cloned()
            })
    }

    fn put(&self, namespace: Namespace, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.entries
            .lock()
            .map_err(|_| StoreError::Transaction)
            .map(|mut entries| {
                entries.insert(
                    (namespace.as_str().to_owned(), key.to_vec()),
                    value.to_vec(),
                );
            })
    }

    fn delete(&self, namespace: Namespace, key: &[u8]) -> Result<(), StoreError> {
        self.entries
            .lock()
            .map_err(|_| StoreError::Transaction)
            .map(|mut entries| {
                entries.remove(&(namespace.as_str().to_owned(), key.to_vec()));
            })
    }

    fn scan(&self, namespace: Namespace) -> Result<Vec<Entry>, StoreError> {
        self.entries
            .lock()
            .map_err(|_| StoreError::Transaction)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|((stored_namespace, _), _)| stored_namespace == namespace.as_str())
                    .map(|((_, key), value)| Entry {
                        key: key.clone(),
                        value: value.clone(),
                    })
                    .collect()
            })
    }

    fn put_batch(
        &self,
        namespace: Namespace,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StoreError> {
        let mut stored = self.entries.lock().map_err(|_| StoreError::Transaction)?;
        for (key, value) in entries {
            stored.insert((namespace.as_str().to_owned(), key.clone()), value.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_round_trips_and_scans_in_key_order() {
        let store = MemoryStore::new();
        store.put(Namespace::Route, b"b", b"two").unwrap();
        store
            .put_batch(
                Namespace::Route,
                &[
                    (b"a".to_vec(), b"one".to_vec()),
                    (b"c".to_vec(), b"three".to_vec()),
                ],
            )
            .unwrap();
        assert_eq!(
            store.get(Namespace::Route, b"a").unwrap(),
            Some(b"one".to_vec())
        );
        assert_eq!(
            store
                .scan(Namespace::Route)
                .unwrap()
                .into_iter()
                .map(|entry| entry.key)
                .collect::<Vec<_>>(),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
        );
        assert!(store.scan(Namespace::Peer).unwrap().is_empty());
    }

    #[test]
    fn memory_store_delete_is_idempotent() {
        let store = MemoryStore::new();
        store.delete(Namespace::Config, b"missing").unwrap();
        store.put(Namespace::Config, b"key", b"value").unwrap();
        store.delete(Namespace::Config, b"key").unwrap();
        assert_eq!(store.get(Namespace::Config, b"key").unwrap(), None);
    }
}
