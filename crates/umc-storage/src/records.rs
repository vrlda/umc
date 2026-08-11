//! Typed record persistence over the kv store (storage.md §15-16): peer
//! observations and route-cache snapshots, serialized as JSON.

use crate::store::{Namespace, Store, StoreError};
use serde::{Deserialize, Serialize};

/// Peer observation record (storage.md §16). Raw endpoint bytes key the
/// record; JSON is the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRecord {
    pub endpoint_id: Vec<u8>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub trust_level: u8,
    pub metadata: Vec<(String, String)>,
}

/// Route-cache snapshot (storage.md §15.1). Persisted so the cache can be
/// restored as `CANDIDATE` entries after restart (§15.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRecordSnapshot {
    pub key_hash: Vec<u8>,
    pub next_hop: Vec<u8>,
    pub lifetime_ms: u64,
    pub learned_at_ms: u64,
    pub scope: u8,
    /// Authenticated, bounded route-policy metadata retained for topology
    /// diversity and hard constraint checks after restart.
    #[serde(default)]
    pub metadata: Vec<u8>,
}

/// Persists a peer record under its raw endpoint id (storage.md §16.4).
///
/// # Errors
/// Returns [`StoreError::Serialization`] when encoding fails, or a backend
/// error from [`Store::put`].
pub fn save_peer(store: &dyn Store, record: &PeerRecord) -> Result<(), StoreError> {
    let value = serde_json::to_vec(record).map_err(|_| StoreError::Serialization)?;
    store.put(Namespace::Peer, &record.endpoint_id, &value)
}

/// All peer records. Corrupt entries are skipped with a log line, never
/// fatal for the whole scan.
///
/// # Errors
/// Returns a backend error from [`Store::scan`].
pub fn list_peers(store: &dyn Store) -> Result<Vec<PeerRecord>, StoreError> {
    scan_records(store, Namespace::Peer, "peer")
}

/// Persists a route snapshot under its raw key hash (storage.md §15.1);
/// re-saving the same key hash overwrites.
///
/// # Errors
/// Returns [`StoreError::Serialization`] when encoding fails, or a backend
/// error from [`Store::put`].
pub fn save_route(store: &dyn Store, snapshot: &RouteRecordSnapshot) -> Result<(), StoreError> {
    let value = serde_json::to_vec(snapshot).map_err(|_| StoreError::Serialization)?;
    store.put(Namespace::Route, &snapshot.key_hash, &value)
}

/// All route snapshots. Corrupt entries are skipped with a log line, never
/// fatal for the whole scan.
///
/// # Errors
/// Returns a backend error from [`Store::scan`].
pub fn list_routes(store: &dyn Store) -> Result<Vec<RouteRecordSnapshot>, StoreError> {
    scan_records(store, Namespace::Route, "route")
}

/// Removes every persisted route snapshot (storage.md §15.3 purge paths).
///
/// # Errors
/// Returns a backend error from [`Store::scan`] or [`Store::delete`].
pub fn clear_routes(store: &dyn Store) -> Result<(), StoreError> {
    for entry in store.scan(Namespace::Route)? {
        store.delete(Namespace::Route, &entry.key)?;
    }
    Ok(())
}

fn scan_records<T: serde::de::DeserializeOwned>(
    store: &dyn Store,
    namespace: Namespace,
    kind: &str,
) -> Result<Vec<T>, StoreError> {
    let mut out = Vec::new();
    for entry in store.scan(namespace)? {
        match serde_json::from_slice(&entry.value) {
            Ok(record) => out.push(record),
            Err(e) => {
                eprintln!(
                    "[storage] skipping corrupt {kind} record ({} bytes): {e}",
                    entry.value.len()
                );
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::SqliteStore;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_store() -> SqliteStore {
        let dir = std::env::temp_dir().join(format!("umc-storage-records-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = dir.join(format!("records-{now}-{c}.db"));
        SqliteStore::open(&path).unwrap()
    }

    fn peer(id: u8) -> PeerRecord {
        PeerRecord {
            endpoint_id: vec![id; 32],
            first_seen_ms: 1_000,
            last_seen_ms: 2_000,
            trust_level: 3,
            metadata: vec![("hint".into(), "ump.udp/1".into())],
        }
    }

    fn route(key: u8) -> RouteRecordSnapshot {
        RouteRecordSnapshot {
            key_hash: vec![key; 32],
            next_hop: b"peer-a".to_vec(),
            lifetime_ms: 600_000,
            learned_at_ms: 42,
            scope: 3,
            metadata: Vec::new(),
        }
    }

    #[test]
    fn route_metadata_round_trips_for_policy_evidence() {
        let store = temp_store();
        let mut snapshot = route(4);
        snapshot.metadata = b"domain=mesh-a\0carrier=ump.tcp/1".to_vec();
        save_route(&store, &snapshot).unwrap();
        assert_eq!(list_routes(&store).unwrap()[0].metadata, snapshot.metadata);
    }

    #[test]
    fn peers_round_trip_and_overwrite() {
        let store = temp_store();
        save_peer(&store, &peer(1)).unwrap();
        save_peer(&store, &peer(2)).unwrap();
        let peers = list_peers(&store).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].endpoint_id, vec![1u8; 32]);
        assert_eq!(peers[0].metadata, vec![("hint".into(), "ump.udp/1".into())]);
        // The same endpoint id overwrites instead of duplicating.
        let mut updated = peer(1);
        updated.trust_level = 5;
        save_peer(&store, &updated).unwrap();
        let peers = list_peers(&store).unwrap();
        assert_eq!(peers.len(), 2);
        let p1 = peers
            .iter()
            .find(|p| p.endpoint_id == vec![1u8; 32])
            .unwrap();
        assert_eq!(p1.trust_level, 5);
    }

    #[test]
    fn routes_round_trip_and_clear() {
        let store = temp_store();
        save_route(&store, &route(1)).unwrap();
        save_route(&store, &route(2)).unwrap();
        let routes = list_routes(&store).unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].next_hop, b"peer-a");
        clear_routes(&store).unwrap();
        assert!(list_routes(&store).unwrap().is_empty());
    }

    #[test]
    fn corrupt_route_entry_is_skipped_not_fatal() {
        let store = temp_store();
        // A garbage value under the route namespace must not fail the scan.
        store
            .put(Namespace::Route, b"corrupt-key", b"not-json")
            .unwrap();
        save_route(&store, &route(9)).unwrap();
        let routes = list_routes(&store).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].key_hash, vec![9u8; 32]);
    }
}
