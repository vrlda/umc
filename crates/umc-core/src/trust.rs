//! Trust store (routing.md §29): per-endpoint trust levels persisted over
//! the umc-storage `Trust` namespace.
use umc_storage::store::{Namespace, Store, StoreError};

const TRUST_RECORD_VERSION: u8 = 0x71;

/// The seven local trust states defined by identity-trust.md §14–15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustState {
    /// No authenticated observation exists.
    Unknown,
    /// A valid authenticated identity with no additional trust grant.
    Observed,
    /// Scoped context from a valid signed introduction.
    Introduced,
    /// Explicitly trusted by local policy.
    Trusted,
    /// Explicitly reduced scopes and rates.
    Restricted,
    /// Refuse interaction, while retaining relationship records.
    Blocked,
    /// Revoked identity; cached evidence must be invalidated.
    Revoked,
}

/// Compatibility view retained for pre-G1 callers. New code should use
/// [`TrustState`]; the store persists the seven-state value and maps it to
/// this legacy view only through [`TrustStore::effective_trust_level`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    Distrusted,
    Unknown,
    Basic,
    Familiar,
    Privileged,
}

impl From<TrustLevel> for TrustState {
    fn from(level: TrustLevel) -> Self {
        match level {
            TrustLevel::Distrusted => Self::Blocked,
            TrustLevel::Unknown => Self::Unknown,
            TrustLevel::Basic => Self::Observed,
            TrustLevel::Familiar | TrustLevel::Privileged => Self::Trusted,
        }
    }
}

impl From<TrustState> for TrustLevel {
    fn from(state: TrustState) -> Self {
        match state {
            TrustState::Unknown => Self::Unknown,
            TrustState::Observed | TrustState::Introduced => Self::Basic,
            TrustState::Trusted => Self::Familiar,
            TrustState::Restricted | TrustState::Blocked | TrustState::Revoked => Self::Distrusted,
        }
    }
}

impl TrustState {
    fn to_byte(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Observed => 1,
            Self::Introduced => 2,
            Self::Trusted => 3,
            Self::Restricted => 4,
            Self::Blocked => 5,
            Self::Revoked => 6,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Unknown),
            1 => Some(Self::Observed),
            2 => Some(Self::Introduced),
            3 => Some(Self::Trusted),
            4 => Some(Self::Restricted),
            5 => Some(Self::Blocked),
            6 => Some(Self::Revoked),
            _ => None,
        }
    }

    /// Whether a local transition is permitted by identity-trust.md §15.1.
    #[must_use]
    #[allow(clippy::unnested_or_patterns)]
    pub const fn can_transition_to(self, target: Self) -> bool {
        if self as u8 == target as u8 {
            return true;
        }
        if matches!(target, Self::Restricted | Self::Blocked | Self::Revoked) {
            return true;
        }
        matches!(
            (self, target),
            (Self::Unknown, Self::Observed)
                | (Self::Unknown, Self::Introduced)
                | (Self::Observed, Self::Introduced)
                | (Self::Observed, Self::Trusted)
                | (Self::Introduced, Self::Trusted)
                | (Self::Blocked, Self::Observed)
                | (Self::Restricted, Self::Observed)
        )
    }

    /// Applies one validated state transition.
    ///
    /// # Errors
    ///
    /// Returns [`TrustTransitionError`] when the requested transition is not
    /// present in the protocol matrix.
    pub fn transition_to(self, target: Self) -> Result<Self, TrustTransitionError> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(TrustTransitionError {
                from: self,
                to: target,
            })
        }
    }

    /// Whether a new authenticated session is allowed by the default policy.
    #[must_use]
    pub const fn allows_new_session(self) -> bool {
        matches!(
            self,
            Self::Unknown | Self::Observed | Self::Introduced | Self::Trusted
        )
    }
}

/// Invalid local trust transition according to the protocol matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustTransitionError {
    pub from: TrustState,
    pub to: TrustState,
}

/// Trust metadata persisted per endpoint (routing.md §29.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustMetadata {
    pub level: TrustState,
    /// Whether the level was established by direct tooling (direct
    /// observation) rather than by report.
    pub direct_tooling: bool,
    /// Monotonic timestamp of the last mutation, in milliseconds.
    pub last_updated_ms: u64,
}

impl TrustMetadata {
    #[must_use]
    pub fn new(level: TrustState, direct_tooling: bool, last_updated_ms: u64) -> Self {
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
    default_trust_level: TrustState,
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
    pub fn new<T: Into<TrustState>>(store: &'a dyn Store, default_trust_level: T) -> Self {
        Self {
            store,
            default_trust_level: default_trust_level.into(),
        }
    }

    /// The level applied to endpoints with no stored metadata.
    #[must_use]
    pub fn default_trust_level(&self) -> TrustState {
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
        Ok(self.effective_trust_state(endpoint)?.into())
    }

    /// Returns the spec-named effective state and keeps the seven-state model
    /// explicit at call sites.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the trust record is missing or corrupt.
    pub fn effective_trust_state(&self, endpoint: &[u8]) -> Result<TrustState, StoreError> {
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

    /// Sets the persisted level for `endpoint` (a direct-tooling record).
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure.
    pub fn set_level(
        &self,
        endpoint: &[u8],
        level: TrustLevel,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let metadata = TrustMetadata::new(level.into(), true, now_ms);
        self.store
            .put(Namespace::Trust, endpoint, &encode(&metadata))
    }

    /// Marks `endpoint` distrusted (a direct-tooling record).
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure.
    pub fn mark_distrusted(&self, endpoint: &[u8], now_ms: u64) -> Result<(), StoreError> {
        let metadata = TrustMetadata::new(TrustState::Blocked, true, now_ms);
        self.store
            .put(Namespace::Trust, endpoint, &encode(&metadata))
    }

    /// Sets a spec trust state while retaining the historical direct-tooling
    /// write path used by administrative callers.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the trust record cannot be persisted.
    pub fn set_state(
        &self,
        endpoint: &[u8],
        state: TrustState,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let metadata = TrustMetadata::new(state, true, now_ms);
        self.store
            .put(Namespace::Trust, endpoint, &encode(&metadata))
    }

    /// Applies a state transition and persists it only when the transition is
    /// allowed by the protocol matrix.
    ///
    /// # Errors
    ///
    /// Returns [`TrustTransitionStoreError::Invalid`] for a disallowed
    /// transition or [`TrustTransitionStoreError::Storage`] for a persistence
    /// failure.
    pub fn transition(
        &self,
        endpoint: &[u8],
        target: TrustState,
        now_ms: u64,
    ) -> Result<TrustState, TrustTransitionStoreError> {
        let current = self
            .effective_trust_state(endpoint)
            .map_err(TrustTransitionStoreError::Storage)?;
        let next = current
            .transition_to(target)
            .map_err(TrustTransitionStoreError::Invalid)?;
        self.set_state(endpoint, next, now_ms)
            .map_err(TrustTransitionStoreError::Storage)?;
        Ok(next)
    }

    /// Removes the trust record: the default level applies again.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] on backend failure.
    pub fn remove_distrust(&self, endpoint: &[u8]) -> Result<(), StoreError> {
        self.store.delete(Namespace::Trust, endpoint)
    }
}

/// Error returned when a persisted trust transition is invalid or storage
/// cannot be updated.
#[derive(Debug)]
pub enum TrustTransitionStoreError {
    Invalid(TrustTransitionError),
    Storage(StoreError),
}

fn encode(metadata: &TrustMetadata) -> Vec<u8> {
    let mut out = Vec::with_capacity(11);
    out.push(TRUST_RECORD_VERSION);
    out.push(metadata.level.to_byte());
    out.push(u8::from(metadata.direct_tooling));
    out.extend_from_slice(&metadata.last_updated_ms.to_le_bytes());
    out
}

fn decode(bytes: &[u8]) -> Result<TrustMetadata, StoreError> {
    let (level_byte, direct_byte, timestamp_start) = if bytes.len() == 11 {
        if bytes[0] != TRUST_RECORD_VERSION {
            return Err(StoreError::Corrupt("unknown trust record version".into()));
        }
        (bytes[1], bytes[2], 3)
    } else if bytes.len() == 10 {
        // Pre-G1 records used the five-level `TrustLevel` encoding. Decode
        // those bytes explicitly so an old block remains a Blocked state.
        let legacy = match bytes[0] {
            0 => TrustState::Blocked,
            1 => TrustState::Unknown,
            2 => TrustState::Observed,
            3 | 4 => TrustState::Trusted,
            _ => return Err(StoreError::Corrupt("unknown legacy trust level".into())),
        };
        return Ok(TrustMetadata {
            level: legacy,
            direct_tooling: bytes[1] != 0,
            last_updated_ms: u64::from_le_bytes(
                bytes[2..10]
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("bad trust timestamp".into()))?,
            ),
        });
    } else {
        return Err(StoreError::Corrupt("bad trust record length".into()));
    };
    let level = TrustState::from_byte(level_byte)
        .ok_or_else(|| StoreError::Corrupt("unknown trust level".into()))?;
    let last_updated_ms = u64::from_le_bytes(
        bytes[timestamp_start..timestamp_start + 8]
            .try_into()
            .map_err(|_| StoreError::Corrupt("bad trust timestamp".into()))?,
    );
    Ok(TrustMetadata {
        level,
        direct_tooling: direct_byte != 0,
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
    fn set_level_persists_any_level() {
        let path = temp_path();
        let store = open_store(&path);
        let trust = TrustStore::new(&store, TrustLevel::Unknown);
        trust
            .set_level(b"peer-2", TrustLevel::Familiar, 200)
            .unwrap();
        assert_eq!(
            trust.effective_trust_level(b"peer-2").unwrap(),
            TrustLevel::Familiar
        );
        assert!(trust.direct_tooling(b"peer-2").unwrap());
        // Overwriting replaces, not duplicates.
        trust.set_level(b"peer-2", TrustLevel::Basic, 300).unwrap();
        assert_eq!(
            trust.effective_trust_level(b"peer-2").unwrap(),
            TrustLevel::Basic
        );
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

    #[test]
    fn spec_trust_states_enforce_transition_matrix() {
        assert!(TrustState::Unknown.can_transition_to(TrustState::Observed));
        assert!(TrustState::Observed.can_transition_to(TrustState::Introduced));
        assert!(TrustState::Introduced.can_transition_to(TrustState::Trusted));
        assert!(TrustState::Observed.can_transition_to(TrustState::Trusted));
        assert!(TrustState::Trusted.can_transition_to(TrustState::Restricted));
        assert!(TrustState::Unknown.can_transition_to(TrustState::Blocked));
        assert!(TrustState::Trusted.can_transition_to(TrustState::Revoked));
        assert!(TrustState::Blocked.can_transition_to(TrustState::Observed));
        assert!(!TrustState::Unknown.can_transition_to(TrustState::Trusted));
        assert!(!TrustState::Revoked.can_transition_to(TrustState::Observed));
        assert!(TrustState::Observed.allows_new_session());
        assert!(!TrustState::Restricted.allows_new_session());
        assert!(!TrustState::Blocked.allows_new_session());
        assert!(!TrustState::Revoked.allows_new_session());
    }

    #[test]
    fn spec_state_defaults_and_legacy_levels_map_explicitly() {
        let path = temp_path();
        let store = open_store(&path);
        let trust = TrustStore::new(&store, TrustState::Observed);
        assert_eq!(
            trust.effective_trust_state(b"new").unwrap(),
            TrustState::Observed
        );
        trust
            .set_state(b"peer", TrustState::Restricted, 42)
            .unwrap();
        assert_eq!(
            trust.effective_trust_state(b"peer").unwrap(),
            TrustState::Restricted
        );
        assert_eq!(
            trust.effective_trust_level(b"peer").unwrap(),
            TrustLevel::Distrusted
        );
    }

    #[test]
    fn legacy_ten_byte_records_are_decoded_without_state_upgrade_loss() {
        let path = temp_path();
        let store = open_store(&path);
        let mut legacy = vec![0u8, 1u8];
        legacy.extend_from_slice(&42u64.to_le_bytes());
        store.put(Namespace::Trust, b"old", &legacy).unwrap();
        let trust = TrustStore::new(&store, TrustState::Unknown);
        assert_eq!(
            trust.effective_trust_state(b"old").unwrap(),
            TrustState::Blocked
        );
    }
}
