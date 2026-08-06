//! Abuse records (control-api.md §48, threat-model.md §50): persistent
//! incident ledger over the `Abuse` namespace.
use crate::store::{Namespace, Store, StoreError};
use std::sync::atomic::{AtomicU64, Ordering};

/// Severity of an abuse event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn to_byte(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Critical => 3,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Low),
            1 => Some(Self::Medium),
            2 => Some(Self::High),
            3 => Some(Self::Critical),
            _ => None,
        }
    }
}

/// One persisted abuse event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseRecord {
    pub peer_endpoint_id: Vec<u8>,
    pub event_type: String,
    pub occurred_at_ms: u64,
    pub severity: Severity,
    pub detail: String,
}

/// Aggregated ledger state; `open` counts records not yet acknowledged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AbuseStats {
    pub total: u64,
    pub acknowledged: u64,
    pub open: u64,
}

/// Abuse ledger over a shared [`Store`] (namespace `Abuse`).
pub struct AbuseStore<'a> {
    store: &'a dyn Store,
    counter: AtomicU64,
}

impl std::fmt::Debug for AbuseStore<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AbuseStore").finish_non_exhaustive()
    }
}

impl<'a> AbuseStore<'a> {
    /// Ledger persisting over `store` (namespace `Abuse`).
    #[must_use]
    pub fn new(store: &'a dyn Store) -> Self {
        Self {
            store,
            counter: AtomicU64::new(0),
        }
    }

    /// Records an abuse event and returns its id (timestamp + monotonic
    /// counter — deterministic within a store lifetime).
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure.
    #[allow(clippy::needless_pass_by_value)] // the record is consumed by encoding
    pub fn add(&self, record: AbuseRecord) -> Result<Vec<u8>, StoreError> {
        let mut id = Vec::with_capacity(16);
        id.extend_from_slice(&record.occurred_at_ms.to_le_bytes());
        id.extend_from_slice(&self.counter.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        self.store.put(Namespace::Abuse, &id, &encode(&record))?;
        Ok(id)
    }

    /// Reads the record stored under `id`; `Ok(None)` when absent.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure or bad encoding.
    pub fn find(&self, id: &[u8]) -> Result<Option<AbuseRecord>, StoreError> {
        match self.store.get(Namespace::Abuse, id)? {
            Some(bytes) => decode(&bytes).map(|(record, _)| Some(record)),
            None => Ok(None),
        }
    }

    /// Marks the record acknowledged (resolved); a missing id is a no-op.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure or bad encoding.
    pub fn acknowledge(&self, id: &[u8]) -> Result<(), StoreError> {
        let Some(bytes) = self.store.get(Namespace::Abuse, id)? else {
            return Ok(());
        };
        let (record, _) = decode(&bytes)?;
        self.store.put(Namespace::Abuse, id, &encode_acked(&record))
    }

    /// Aggregates the ledger; `open` counts not-acknowledged records.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure or bad encoding.
    pub fn stats(&self) -> Result<AbuseStats, StoreError> {
        let mut stats = AbuseStats::default();
        for entry in self.store.scan(Namespace::Abuse)? {
            let (_, acknowledged) = decode(&entry.value)?;
            stats.total += 1;
            if acknowledged {
                stats.acknowledged += 1;
            } else {
                stats.open += 1;
            }
        }
        Ok(stats)
    }
}

/// Wire format: `[peer_len u32][peer][event_len u32][event]
/// [occurred_at u64][severity u8][detail_len u32][detail][ack u8]`.
fn encode(record: &AbuseRecord) -> Vec<u8> {
    encode_acked_with(record, false)
}

fn encode_acked(record: &AbuseRecord) -> Vec<u8> {
    encode_acked_with(record, true)
}

#[allow(clippy::cast_possible_truncation)] // fields are bounded by wire limits
fn encode_acked_with(record: &AbuseRecord, acknowledged: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        4 + record.peer_endpoint_id.len()
            + 4
            + record.event_type.len()
            + 8
            + 1
            + 4
            + record.detail.len()
            + 1,
    );
    out.extend_from_slice(&(record.peer_endpoint_id.len() as u32).to_le_bytes());
    out.extend_from_slice(&record.peer_endpoint_id);
    out.extend_from_slice(&(record.event_type.len() as u32).to_le_bytes());
    out.extend_from_slice(record.event_type.as_bytes());
    out.extend_from_slice(&record.occurred_at_ms.to_le_bytes());
    out.push(record.severity.to_byte());
    out.extend_from_slice(&(record.detail.len() as u32).to_le_bytes());
    out.extend_from_slice(record.detail.as_bytes());
    out.push(u8::from(acknowledged));
    out
}

fn decode(bytes: &[u8]) -> Result<(AbuseRecord, bool), StoreError> {
    let mut at = 0usize;
    let peer_endpoint_id = take_bytes(bytes, &mut at)?;
    let event_type_bytes = take_bytes(bytes, &mut at)?;
    let occurred_at_ms = take_u64(bytes, &mut at)?;
    let severity = Severity::from_byte(take_u8(bytes, &mut at)?)
        .ok_or_else(|| StoreError::Corrupt("unknown severity".into()))?;
    let detail_bytes = take_bytes(bytes, &mut at)?;
    let acknowledged = take_u8(bytes, &mut at)? != 0;
    if at != bytes.len() {
        return Err(StoreError::Corrupt("trailing bytes in abuse record".into()));
    }
    Ok((
        AbuseRecord {
            peer_endpoint_id,
            event_type: String::from_utf8(event_type_bytes)
                .map_err(|_| StoreError::Corrupt("bad event type".into()))?,
            occurred_at_ms,
            severity,
            detail: String::from_utf8(detail_bytes)
                .map_err(|_| StoreError::Corrupt("bad detail".into()))?,
        },
        acknowledged,
    ))
}

fn take_u8(bytes: &[u8], at: &mut usize) -> Result<u8, StoreError> {
    let byte = bytes
        .get(*at)
        .copied()
        .ok_or_else(|| StoreError::Corrupt("truncated abuse record".into()))?;
    *at += 1;
    Ok(byte)
}

fn take_u64(bytes: &[u8], at: &mut usize) -> Result<u64, StoreError> {
    let end = at
        .checked_add(8)
        .ok_or_else(|| StoreError::Corrupt("abuse record overflow".into()))?;
    let slice = bytes
        .get(*at..end)
        .ok_or_else(|| StoreError::Corrupt("truncated abuse record".into()))?;
    *at = end;
    Ok(u64::from_le_bytes(slice.try_into().map_err(|_| {
        StoreError::Corrupt("bad abuse record length".into())
    })?))
}

fn take_bytes(bytes: &[u8], at: &mut usize) -> Result<Vec<u8>, StoreError> {
    let len_end = at
        .checked_add(4)
        .ok_or_else(|| StoreError::Corrupt("abuse record overflow".into()))?;
    let len_bytes = bytes
        .get(*at..len_end)
        .ok_or_else(|| StoreError::Corrupt("truncated abuse record".into()))?;
    *at = len_end;
    let len = u32::from_le_bytes(
        len_bytes
            .try_into()
            .map_err(|_| StoreError::Corrupt("bad abuse record length".into()))?,
    ) as usize;
    let end = at
        .checked_add(len)
        .ok_or_else(|| StoreError::Corrupt("abuse record overflow".into()))?;
    let body = bytes
        .get(*at..end)
        .ok_or_else(|| StoreError::Corrupt("truncated abuse record".into()))?;
    *at = end;
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn open_temp() -> crate::sqlite::SqliteStore {
        let dir = std::env::temp_dir().join(format!("umc-abuse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let c = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path: PathBuf = dir.join(format!("abuse-{n}-{c}.db"));
        crate::sqlite::SqliteStore::open(&path).unwrap()
    }

    fn record(peer: &[u8]) -> AbuseRecord {
        AbuseRecord {
            peer_endpoint_id: peer.to_vec(),
            event_type: "enumeration".into(),
            occurred_at_ms: 1_000,
            severity: Severity::High,
            detail: "query burst".into(),
        }
    }

    #[test]
    fn add_find_round_trip() {
        let store = open_temp();
        let abuse = AbuseStore::new(&store);
        let id = abuse.add(record(b"peer-1")).unwrap();
        let found = abuse.find(&id).unwrap().unwrap();
        assert_eq!(found.peer_endpoint_id, b"peer-1");
        assert_eq!(found.event_type, "enumeration");
        assert_eq!(found.occurred_at_ms, 1_000);
        assert_eq!(found.severity, Severity::High);
        assert_eq!(found.detail, "query burst");
        // The monotonic counter makes ids distinct.
        let second = abuse.add(record(b"peer-1")).unwrap();
        assert_ne!(second, id);
    }

    #[test]
    fn acknowledge_marks_resolved() {
        let store = open_temp();
        let abuse = AbuseStore::new(&store);
        let id = abuse.add(record(b"peer-1")).unwrap();
        abuse.acknowledge(&id).unwrap();
        let stats = abuse.stats().unwrap();
        assert_eq!(stats.total, 1);
        assert_eq!(stats.acknowledged, 1);
        assert_eq!(stats.open, 0);
    }

    #[test]
    fn stats_counts_open_only() {
        let store = open_temp();
        let abuse = AbuseStore::new(&store);
        let a = abuse.add(record(b"peer-a")).unwrap();
        let b = abuse.add(record(b"peer-b")).unwrap();
        abuse.acknowledge(&a).unwrap();
        let stats = abuse.stats().unwrap();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.acknowledged, 1);
        assert_eq!(stats.open, 1);
        let _ = b;
    }
}
