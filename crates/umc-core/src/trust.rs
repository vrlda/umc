//! Trust store (routing.md §29): per-endpoint trust levels persisted over
//! the umc-storage `Trust` namespace.
use umc_storage::store::{Namespace, Store, StoreError};

/// Endpoint trust levels, weakest to strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    /// Actively distrusted: no traffic accepted.
    Distrusted,
    /// No information: the default for unseen endpoints.
    Unknown,
    /// Basic: direct connectivity observed.
    Basic,
    /// Familiar: long-lived direct relationship.
    Familiar,
    /// Privileged: operator-approved, gets reserved capacity.
    Privileged,
}

impl TrustLevel {
    fn to_byte(self) -> u8 {
        match self {
            Self::Distrusted => 0,
            Self::Unknown => 1,
            Self::Basic => 2,
            Self::Familiar => 3,
            Self::Privileged => 4,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Distrusted),
            1 => Some(Self::Unknown),
            2 => Some(Self::Basic),
            3 => Some(Self::Familiar),
            4 => Some(Self::Privileged),
            _ => None,
        }
    }
}

/// Trust metadata persisted per endpoint (routing.md §29.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustMetadata {
    pub level: TrustLevel,
    /// Whether the level was established by direct tooling (direct
    /// observation) rather than by report.
    pub direct_tooling: bool,
    /// Monotonic timestamp of the last mutation, in milliseconds.
    pub last_updated_ms: u64,
}

impl TrustMetadata {
    #[must_use]
    pub fn new(level: TrustLevel, direct_tooling: bool, last_updated_ms: u64) -> Self {
        Self {
            level,
            direct_tooling,
            last_updated_ms,
        }
    }
}

/// Trust store over a shared [`Store`] (namespace `Trust`): levels persist
/// across store reopen and are readable by any component with the store.
pub struct TrustStore<'a> {
    store: &'a dyn Store,
    default_trust_level: TrustLevel,
}

impl std::fmt::Debug for TrustStore<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustStore")
            .field("default_trust_level", &self.default_trust_level)
            .finish_non_exhaustive()
    }
}

impl<'a> TrustStore<'a> {
    /// Trust store persisting over `store` (namespace `Trust`); unseen
    /// endpoints evaluate to `default_trust_level`.
    #[must_use]
    pub fn new(store: &'a dyn Store, default_trust_level: TrustLevel) -> Self {
        Self {
            store,
            default_trust_level,
        }
    }

    /// The level applied to endpoints with no stored metadata.
    #[must_use]
    pub fn default_trust_level(&self) -> TrustLevel {
        self.default_trust_level
    }

    /// Reads the persisted metadata for `endpoint`; `Ok(None)` when absent.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure or bad encoding.
    pub fn get_trust_metadata(&self, endpoint: &[u8]) -> Result<Option<TrustMetadata>, StoreError> {
        match self.store.get(Namespace::Trust, endpoint)? {
            Some(bytes) => decode(&bytes).map(Some),
            None => Ok(None),
        }
    }

    /// Effective level: persisted level, falling back to the default when
    /// the endpoint is unknown.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure or bad encoding.
    pub fn effective_trust_level(&self, endpoint: &[u8]) -> Result<TrustLevel, StoreError> {
        Ok(self
            .get_trust_metadata(endpoint)?
            .map_or(self.default_trust_level, |metadata| metadata.level))
    }

    /// Whether the endpoint's level was set via direct tooling.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure or bad encoding.
    pub fn direct_tooling(&self, endpoint: &[u8]) -> Result<bool, StoreError> {
        Ok(self
            .get_trust_metadata(endpoint)?
            .is_some_and(|metadata| metadata.direct_tooling))
    }

    /// Marks `endpoint` distrusted (a direct-tooling record).
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure.
    pub fn mark_distrusted(&self, endpoint: &[u8], now_ms: u64) -> Result<(), StoreError> {
        let metadata = TrustMetadata::new(TrustLevel::Distrusted, true, now_ms);
        self.store
            .put(Namespace::Trust, endpoint, &encode(&metadata))
    }

    /// Removes the trust record: the default level applies again.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure.
    pub fn remove_distrust(&self, endpoint: &[u8]) -> Result<(), StoreError> {
        self.store.delete(Namespace::Trust, endpoint)
    }
}

fn encode(metadata: &TrustMetadata) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    out.push(metadata.level.to_byte());
    out.push(u8::from(metadata.direct_tooling));
    out.extend_from_slice(&metadata.last_updated_ms.to_le_bytes());
    out
}

fn decode(bytes: &[u8]) -> Result<TrustMetadata, StoreError> {
    if bytes.len() != 10 {
        return Err(StoreError::Corrupt("bad trust record length".into()));
    }
    let level = TrustLevel::from_byte(bytes[0])
        .ok_or_else(|| StoreError::Corrupt("unknown trust level".into()))?;
    let last_updated_ms = u64::from_le_bytes(
        bytes[2..10]
            .try_into()
            .map_err(|_| StoreError::Corrupt("bad trust timestamp".into()))?,
    );
    Ok(TrustMetadata {
        level,
        direct_tooling: bytes[1] != 0,
        last_updated_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("umc-core-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        dir.join(format!("trust-{n}.db"))
    }

    fn open_store(path: &Path) -> umc_storage::sqlite::SqliteStore {
        umc_storage::sqlite::SqliteStore::open(path).unwrap()
    }

    #[test]
    fn distrust_takes_effect() {
        let path = temp_path();
        let store = open_store(&path);
        let trust = TrustStore::new(&store, TrustLevel::Basic);
        assert_eq!(
            trust.effective_trust_level(b"peer-1").unwrap(),
            TrustLevel::Basic
        );
        trust.mark_distrusted(b"peer-1", 100).unwrap();
        assert_eq!(
            trust.effective_trust_level(b"peer-1").unwrap(),
            TrustLevel::Distrusted
        );
        assert!(trust.direct_tooling(b"peer-1").unwrap());
    }

    #[test]
    fn removal_restores_default() {
        let path = temp_path();
        let store = open_store(&path);
        let trust = TrustStore::new(&store, TrustLevel::Basic);
        trust.mark_distrusted(b"peer-1", 100).unwrap();
        trust.remove_distrust(b"peer-1").unwrap();
        assert_eq!(
            trust.effective_trust_level(b"peer-1").unwrap(),
            TrustLevel::Basic
        );
    }

    #[test]
    fn persisted_across_store_reopen() {
        let path = temp_path();
        {
            let store = open_store(&path);
            let trust = TrustStore::new(&store, TrustLevel::Basic);
            trust.mark_distrusted(b"peer-1", 100).unwrap();
        }
        let store = open_store(&path);
        let trust = TrustStore::new(&store, TrustLevel::Basic);
        assert_eq!(
            trust.effective_trust_level(b"peer-1").unwrap(),
            TrustLevel::Distrusted
        );
    }

    #[test]
    fn default_applies_when_unknown() {
        let path = temp_path();
        let store = open_store(&path);
        let trust = TrustStore::new(&store, TrustLevel::Unknown);
        assert_eq!(trust.get_trust_metadata(b"nobody").unwrap(), None);
        assert_eq!(
            trust.effective_trust_level(b"nobody").unwrap(),
            TrustLevel::Unknown
        );
    }
}
