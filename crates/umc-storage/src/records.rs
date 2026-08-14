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
    /// Authenticated adjacent carrier type, if known.
    #[serde(default)]
    pub carrier_type: Option<String>,
    pub lifetime_ms: u64,
    pub learned_at_ms: u64,
    pub scope: u8,
    /// Authenticated, bounded route-policy metadata retained for topology
    /// diversity and hard constraint checks after restart.
    #[serde(default)]
    pub metadata: Vec<u8>,
}

/// A daemon-side resumption ticket retained for one authenticated peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTicketRecord {
    pub peer_endpoint_id: Vec<u8>,
    pub carrier_type: String,
    pub ticket: Vec<u8>,
    pub resumption_secret: Vec<u8>,
    pub expires_at_ms: u64,
    pub received_at_ms: u64,
}

fn peer_identity_key_key(peer_endpoint_id: &[u8]) -> Vec<u8> {
    let mut key = b"peer-identity-key/".to_vec();
    key.extend_from_slice(peer_endpoint_id);
    key
}

/// Persists the authenticated identity public key associated with one peer
/// endpoint. The key is public trust metadata, not a credential; it allows a
/// ticket-resumed session to verify signed optional control extensions before
/// a fresh XX handshake re-establishes the same binding.
///
/// # Errors
/// Returns a backend error when the endpoint or key is malformed or storage
/// fails.
pub fn save_peer_identity_public_key(
    store: &dyn Store,
    peer_endpoint_id: &[u8],
    identity_public_key: &[u8],
) -> Result<(), StoreError> {
    if peer_endpoint_id.len() != 32 || identity_public_key.len() != 32 {
        return Err(StoreError::Serialization);
    }
    store.put(
        Namespace::Peer,
        &peer_identity_key_key(peer_endpoint_id),
        identity_public_key,
    )
}

/// Loads a previously authenticated peer identity public key.
///
/// # Errors
/// Returns a backend error when the record cannot be read. Malformed records
/// are treated as absent and deleted so they cannot be reused.
pub fn load_peer_identity_public_key(
    store: &dyn Store,
    peer_endpoint_id: &[u8],
) -> Result<Option<[u8; 32]>, StoreError> {
    if peer_endpoint_id.len() != 32 {
        return Ok(None);
    }
    let key = peer_identity_key_key(peer_endpoint_id);
    let Some(value) = store.get(Namespace::Peer, &key)? else {
        return Ok(None);
    };
    let Ok(value) = value.as_slice().try_into() else {
        let _ = store.delete(Namespace::Peer, &key);
        return Ok(None);
    };
    Ok(Some(value))
}

/// Durable relay lease and replay fence. Transport/session bindings are not
/// persisted; a restored lease must be rebound by a fresh authenticated peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayCircuitRecord {
    pub circuit_id: u64,
    pub epoch: u64,
    pub owner_peer: Vec<u8>,
    pub destination_peer: Vec<u8>,
    pub expires_at_ms: u64,
    pub replay_until_ms: u64,
    pub granted_byte_quota: u64,
    pub bidirectional: bool,
    pub private_handling: bool,
    #[serde(default)]
    pub multipath_granted: bool,
    pub next_upstream_sequence: u64,
    pub next_downstream_sequence: u64,
    pub state: u8,
}

fn relay_circuit_key(circuit_id: u64, epoch: u64) -> Vec<u8> {
    let mut key = b"circuit/".to_vec();
    key.extend_from_slice(&circuit_id.to_be_bytes());
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

/// # Errors
/// Returns [`StoreError::Serialization`] when encoding fails or a backend
/// error from [`Store::put`].
pub fn save_relay_circuit(
    store: &dyn Store,
    record: &RelayCircuitRecord,
) -> Result<(), StoreError> {
    let value = serde_json::to_vec(record).map_err(|_| StoreError::Serialization)?;
    store.put(
        Namespace::Relay,
        &relay_circuit_key(record.circuit_id, record.epoch),
        &value,
    )
}

/// # Errors
/// Returns a backend error from [`Store::scan`]. Corrupt records are skipped.
pub fn list_relay_circuits(store: &dyn Store) -> Result<Vec<RelayCircuitRecord>, StoreError> {
    scan_records(store, Namespace::Relay, "relay circuit")
}

/// # Errors
/// Returns a backend error from [`Store::delete`].
pub fn delete_relay_circuit(
    store: &dyn Store,
    circuit_id: u64,
    epoch: u64,
) -> Result<(), StoreError> {
    store.delete(Namespace::Relay, &relay_circuit_key(circuit_id, epoch))
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
    let mut out = Vec::new();
    for entry in store.scan(Namespace::Peer)? {
        if entry.key.starts_with(b"session-ticket/") {
            continue;
        }
        match serde_json::from_slice(&entry.value) {
            Ok(record) => out.push(record),
            Err(e) => eprintln!(
                "[storage] skipping corrupt peer record ({} bytes): {e}",
                entry.value.len()
            ),
        }
    }
    Ok(out)
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

fn session_ticket_key(peer_endpoint_id: &[u8]) -> Vec<u8> {
    let mut key = b"session-ticket/".to_vec();
    key.extend_from_slice(peer_endpoint_id);
    key
}

/// Persists one peer-scoped session ticket.
///
/// # Errors
/// Returns a backend or serialization error when the record cannot be stored.
pub fn save_session_ticket(
    store: &dyn Store,
    record: &SessionTicketRecord,
) -> Result<(), StoreError> {
    let value = serde_json::to_vec(record).map_err(|_| StoreError::Serialization)?;
    store.put(
        Namespace::Peer,
        &session_ticket_key(&record.peer_endpoint_id),
        &value,
    )
}

/// Loads one unexpired peer-scoped session ticket.
///
/// # Errors
/// Returns a backend or serialization error when the record cannot be read.
pub fn load_session_ticket(
    store: &dyn Store,
    peer_endpoint_id: &[u8],
    now_ms: u64,
) -> Result<Option<SessionTicketRecord>, StoreError> {
    let Some(value) = store.get(Namespace::Peer, &session_ticket_key(peer_endpoint_id))? else {
        return Ok(None);
    };
    let record: SessionTicketRecord =
        serde_json::from_slice(&value).map_err(|_| StoreError::Serialization)?;
    if record.peer_endpoint_id != peer_endpoint_id || record.expires_at_ms <= now_ms {
        let _ = store.delete(Namespace::Peer, &session_ticket_key(peer_endpoint_id));
        return Ok(None);
    }
    Ok(Some(record))
}

/// Lists all persisted session tickets, skipping malformed records.
///
/// # Errors
/// Returns a backend error when the peer namespace cannot be scanned.
pub fn list_session_tickets(store: &dyn Store) -> Result<Vec<SessionTicketRecord>, StoreError> {
    let mut out = Vec::new();
    for entry in store.scan(Namespace::Peer)? {
        if !entry.key.starts_with(b"session-ticket/") {
            continue;
        }
        if let Ok(record) = serde_json::from_slice(&entry.value) {
            out.push(record);
        }
    }
    Ok(out)
}

/// Deletes the persisted session ticket for one peer.
///
/// # Errors
/// Returns a backend error when the record cannot be deleted.
pub fn delete_session_ticket(store: &dyn Store, peer_endpoint_id: &[u8]) -> Result<(), StoreError> {
    store.delete(Namespace::Peer, &session_ticket_key(peer_endpoint_id))
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

    #[test]
    fn relay_circuit_record_round_trip() {
        let store = temp_store();
        let record = RelayCircuitRecord {
            circuit_id: 17,
            epoch: 4,
            owner_peer: vec![7; 32],
            destination_peer: vec![8; 32],
            expires_at_ms: 9_000,
            replay_until_ms: 12_000,
            granted_byte_quota: 1_024,
            bidirectional: true,
            private_handling: false,
            multipath_granted: false,
            next_upstream_sequence: 3,
            next_downstream_sequence: 5,
            state: 4,
        };
        save_relay_circuit(&store, &record).unwrap();
        assert_eq!(list_relay_circuits(&store).unwrap(), vec![record]);
        delete_relay_circuit(&store, 17, 4).unwrap();
        assert!(list_relay_circuits(&store).unwrap().is_empty());
    }

    #[test]
    fn session_ticket_round_trip_is_peer_scoped() {
        let store = temp_store();
        let record = SessionTicketRecord {
            peer_endpoint_id: vec![7; 32],
            carrier_type: "ump.tcp/1".into(),
            ticket: vec![1, 2, 3],
            resumption_secret: vec![4; 32],
            expires_at_ms: 9_000,
            received_at_ms: 1_000,
        };
        save_session_ticket(&store, &record).unwrap();
        assert_eq!(list_session_tickets(&store).unwrap(), vec![record]);
    }

    #[test]
    fn peer_identity_public_key_round_trip_is_bounded_and_fail_closed() {
        let store = temp_store();
        let endpoint = [7u8; 32];
        let public_key = [9u8; 32];
        save_peer_identity_public_key(&store, &endpoint, &public_key).unwrap();
        assert_eq!(
            load_peer_identity_public_key(&store, &endpoint).unwrap(),
            Some(public_key)
        );
        assert!(load_peer_identity_public_key(&store, &[8u8; 32])
            .unwrap()
            .is_none());

        store
            .put(
                Namespace::Peer,
                &peer_identity_key_key(&endpoint),
                &[1u8; 31],
            )
            .unwrap();
        assert!(load_peer_identity_public_key(&store, &endpoint)
            .unwrap()
            .is_none());
        assert!(store
            .get(Namespace::Peer, &peer_identity_key_key(&endpoint))
            .unwrap()
            .is_none());
    }

    fn route(key: u8) -> RouteRecordSnapshot {
        RouteRecordSnapshot {
            key_hash: vec![key; 32],
            next_hop: b"peer-a".to_vec(),
            carrier_type: None,
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
