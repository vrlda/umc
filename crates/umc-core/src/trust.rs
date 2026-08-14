//! Trust store (routing.md §29): per-endpoint trust levels persisted over
//! the umc-storage `Trust` namespace.
use crate::trust_statement::{
    DelegatedAuthority, DelegationChain, SignedDelegation, SignedIntroduction,
    MAX_DELEGATION_CAPABILITIES, MAX_DELEGATION_CAPABILITY_BYTES, MAX_DELEGATION_CAPABILITY_LEN,
    MAX_DELEGATION_CHAIN_BYTES,
};
use umc_crypto::signatures::IdentityPublicKey;
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

/// Maximum number of introducer edges followed when deriving scoped trust.
pub const MAX_INTRODUCTION_DEPTH: usize = 2;
const MAX_INTRODUCTIONS_PER_SUBJECT: usize = 32;
const SIGNED_INTRODUCTION_PREFIX: &[u8] = b"intro-signed/";
const SIGNED_DELEGATION_PREFIX: &[u8] = b"delegation/";

/// A persisted delegation chain together with the root authority needed to
/// re-verify it after restart (identity-trust.md §§20-21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDelegationChain {
    pub root_public_key: IdentityPublicKey,
    pub root_capabilities: Vec<Vec<u8>>,
    pub certificates: Vec<SignedDelegation>,
}

/// Encodes the bounded delegation envelope carried in `CLIENT_AUTH` and
/// `SERVER_AUTH`. The returned bytes are intentionally independent of the
/// persistence record: they contain only the certificate count and canonical
/// signed certificates, while the responder obtains the root authority from
/// its local trust store.
///
/// # Errors
///
/// Returns [`StoreError::Corrupt`] for an empty/oversized chain or malformed
/// certificates, and [`StoreError::QuotaExceeded`] for profile bounds.
pub fn encode_delegation_chain(certificates: &[SignedDelegation]) -> Result<Vec<u8>, StoreError> {
    if certificates.is_empty()
        || certificates.len() > crate::trust_statement::MAX_DELEGATION_CHAIN_LENGTH
    {
        return Err(StoreError::QuotaExceeded);
    }
    let mut out = Vec::with_capacity(1 + certificates.len() * 2);
    out.push(u8::try_from(certificates.len()).map_err(|_| StoreError::QuotaExceeded)?);
    for certificate in certificates {
        let encoded = certificate
            .to_bytes()
            .map_err(|error| StoreError::Corrupt(format!("invalid delegation: {error:?}")))?;
        let length = u16::try_from(encoded.len()).map_err(|_| StoreError::QuotaExceeded)?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&encoded);
    }
    if out.len() > MAX_DELEGATION_CHAIN_BYTES {
        return Err(StoreError::QuotaExceeded);
    }
    Ok(out)
}

/// Decodes the bounded handshake delegation envelope. This validates framing
/// and each certificate's canonical structure; authority and validity are
/// checked separately by [`DelegationStore`].
///
/// # Errors
///
/// Returns [`StoreError::Corrupt`] for malformed framing/certificates and
/// [`StoreError::QuotaExceeded`] when profile bounds are exceeded.
pub fn decode_delegation_chain(bytes: &[u8]) -> Result<Vec<SignedDelegation>, StoreError> {
    if bytes.is_empty() || bytes.len() > MAX_DELEGATION_CHAIN_BYTES {
        return Err(StoreError::QuotaExceeded);
    }
    let count = usize::from(bytes[0]);
    if count == 0 || count > crate::trust_statement::MAX_DELEGATION_CHAIN_LENGTH {
        return Err(StoreError::QuotaExceeded);
    }
    let mut offset = 1usize;
    let mut certificates = Vec::with_capacity(count);
    for _ in 0..count {
        let length_end = offset
            .checked_add(2)
            .ok_or_else(|| StoreError::Corrupt("delegation envelope overflow".into()))?;
        let length = usize::from(u16::from_be_bytes(
            bytes
                .get(offset..length_end)
                .ok_or_else(|| StoreError::Corrupt("delegation envelope truncated".into()))?
                .try_into()
                .map_err(|_| StoreError::Corrupt("delegation certificate length".into()))?,
        ));
        offset = length_end;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| StoreError::Corrupt("delegation envelope overflow".into()))?;
        let certificate = SignedDelegation::from_bytes(
            bytes
                .get(offset..end)
                .ok_or_else(|| StoreError::Corrupt("delegation certificate truncated".into()))?,
        )
        .map_err(|error| StoreError::Corrupt(format!("delegation certificate: {error:?}")))?;
        offset = end;
        certificates.push(certificate);
    }
    if offset != bytes.len() {
        return Err(StoreError::Corrupt(
            "delegation envelope trailing bytes".into(),
        ));
    }
    Ok(certificates)
}

/// Bounded delegation persistence over the trust namespace. Certificates are
/// accepted only after full chain verification; restart reads verify every
/// signature again before exposing an authority to callers.
pub struct DelegationStore<'a> {
    store: &'a dyn Store,
}

impl std::fmt::Debug for DelegationStore<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DelegationStore")
            .finish_non_exhaustive()
    }
}

impl<'a> DelegationStore<'a> {
    /// Creates a delegation store backed by the trust namespace.
    #[must_use]
    pub const fn new(store: &'a dyn Store) -> Self {
        Self { store }
    }

    /// Verifies and persists one bounded delegation chain. A later write for
    /// the same delegated leaf must have a strictly higher leaf sequence, so
    /// restoring an older snapshot cannot roll a device back.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] when the chain is invalid or malformed,
    /// [`StoreError::QuotaExceeded`] when the encoded chain is too large, and
    /// the backend error when persistence fails.
    pub fn accept_chain(
        &self,
        root_public_key: &IdentityPublicKey,
        root_capabilities: &[Vec<u8>],
        certificates: &[SignedDelegation],
        now_ms: u64,
    ) -> Result<DelegatedAuthority, StoreError> {
        let authority =
            DelegationChain::verify(root_public_key, root_capabilities, certificates, now_ms)
                .map_err(|error| {
                    StoreError::Corrupt(format!("invalid delegation chain: {error:?}"))
                })?;
        let mut root_capabilities = root_capabilities.to_vec();
        root_capabilities.sort();
        root_capabilities.dedup();
        validate_delegation_capabilities(&root_capabilities)?;
        let record = StoredDelegationChain {
            root_public_key: root_public_key.clone(),
            root_capabilities,
            certificates: certificates.to_vec(),
        };
        let encoded = encode_delegation(&record)?;
        let key = delegation_key(&authority.public_key.0);
        if let Some(previous) = self.store.get(Namespace::Trust, &key)? {
            let previous = decode_delegation(&key, &previous)?;
            if previous.root_public_key != *root_public_key {
                return Err(StoreError::Corrupt(
                    "delegation root changed for existing leaf".into(),
                ));
            }
            let previous_sequence = previous
                .certificates
                .last()
                .map_or(0, |certificate| certificate.sequence);
            let next_sequence = record
                .certificates
                .last()
                .map_or(0, |certificate| certificate.sequence);
            if next_sequence <= previous_sequence {
                return Err(StoreError::Corrupt("delegation sequence regressed".into()));
            }
        }
        self.store.put(Namespace::Trust, &key, &encoded)?;
        Ok(authority)
    }

    /// Loads every persisted chain and re-verifies its signatures and
    /// validity. Expired chains are omitted; malformed rows fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] when a persisted row fails canonical
    /// decoding or verification.
    pub fn valid_chains(&self, now_ms: u64) -> Result<Vec<StoredDelegationChain>, StoreError> {
        let mut chains = Vec::new();
        for entry in self.store.scan(Namespace::Trust)? {
            if !entry.key.starts_with(SIGNED_DELEGATION_PREFIX) {
                continue;
            }
            let record = decode_delegation(&entry.key, &entry.value)?;
            match DelegationChain::verify(
                &record.root_public_key,
                &record.root_capabilities,
                &record.certificates,
                now_ms,
            ) {
                Ok(_) => chains.push(record),
                Err(crate::trust_statement::DelegationError::Expired) => {}
                Err(error) => {
                    return Err(StoreError::Corrupt(format!(
                        "invalid persisted delegation: {error:?}"
                    )))
                }
            }
        }
        Ok(chains)
    }

    /// Loads and re-verifies the chain for one delegated public key without
    /// scanning the entire trust namespace.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] for malformed or cryptographically
    /// invalid persisted evidence, and the backend error for storage failure.
    pub fn valid_chain_for_public_key(
        &self,
        delegated_public_key: &[u8; 32],
        now_ms: u64,
    ) -> Result<Option<StoredDelegationChain>, StoreError> {
        let key = delegation_key(delegated_public_key);
        let Some(value) = self.store.get(Namespace::Trust, &key)? else {
            return Ok(None);
        };
        let record = decode_delegation(&key, &value)?;
        match DelegationChain::verify(
            &record.root_public_key,
            &record.root_capabilities,
            &record.certificates,
            now_ms,
        ) {
            Ok(_) => Ok(Some(record)),
            Err(crate::trust_statement::DelegationError::Expired) => Ok(None),
            Err(error) => Err(StoreError::Corrupt(format!(
                "invalid persisted delegation: {error:?}"
            ))),
        }
    }

    /// Finds a valid chain containing a delegated certificate link. This is
    /// used by root-authorized revocation so an operator can revoke either a
    /// leaf device or an intermediate delegating device.
    ///
    /// # Errors
    ///
    /// Returns storage or persisted-chain validation errors from the trust
    /// namespace.
    pub fn valid_chain_containing_public_key(
        &self,
        delegated_public_key: &[u8; 32],
        now_ms: u64,
    ) -> Result<Option<StoredDelegationChain>, StoreError> {
        for chain in self.valid_chains(now_ms)? {
            if chain
                .certificates
                .iter()
                .any(|certificate| &certificate.delegated_public_key == delegated_public_key)
            {
                return Ok(Some(chain));
            }
        }
        Ok(None)
    }

    /// Finds a valid delegated chain by its derived endpoint id. This is used
    /// by ticket resumption, whose compact credential carries the endpoint id
    /// but not the delegated public key or certificate envelope.
    ///
    /// # Errors
    /// Returns storage/corruption errors from the trust namespace.
    pub fn valid_chain_for_endpoint_id(
        &self,
        endpoint_id: &[u8; 32],
        now_ms: u64,
    ) -> Result<Option<StoredDelegationChain>, StoreError> {
        for chain in self.valid_chains(now_ms)? {
            if let Some(leaf) = chain.certificates.last() {
                if umc_handshake::identity::endpoint_id(&IdentityPublicKey(
                    leaf.delegated_public_key,
                )) == *endpoint_id
                {
                    return Ok(Some(chain));
                }
            }
        }
        Ok(None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IntroductionRecord {
    introducer: Vec<u8>,
    subject: Vec<u8>,
    scope: String,
    expires_at_ms: u64,
    sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SignedIntroductionRecord {
    statement: SignedIntroduction,
}

/// Persisted, bounded introduction graph (identity-trust.md §18).
pub struct TrustGraph<'a> {
    store: &'a dyn Store,
    max_depth: usize,
}

impl std::fmt::Debug for TrustGraph<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustGraph")
            .field("max_depth", &self.max_depth)
            .finish_non_exhaustive()
    }
}

impl<'a> TrustGraph<'a> {
    /// Creates a graph backed by the trust namespace.
    #[must_use]
    pub const fn new(store: &'a dyn Store) -> Self {
        Self {
            store,
            max_depth: MAX_INTRODUCTION_DEPTH,
        }
    }

    /// Creates a graph with a lower depth bound for constrained profiles.
    #[must_use]
    pub const fn with_max_depth(store: &'a dyn Store, max_depth: usize) -> Self {
        Self { store, max_depth }
    }

    /// Persists one scoped, expiring introducer edge.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] for malformed identities/scope, an
    /// expired edge, or an introducer without active authority for `scope`,
    /// and [`StoreError::QuotaExceeded`] when the subject has reached the
    /// bounded introduction count.
    pub fn introduce(
        &self,
        introducer: &[u8],
        subject: &[u8],
        scope: &str,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        if introducer.is_empty() || subject.is_empty() || introducer == subject {
            return Err(StoreError::Corrupt(
                "invalid introduction identities".into(),
            ));
        }
        if scope.is_empty() || expires_at_ms <= now_ms {
            return Err(StoreError::Corrupt(
                "invalid introduction scope or expiry".into(),
            ));
        }
        let introducer_state = self.effective_state(introducer, scope, now_ms)?;
        if !matches!(
            introducer_state,
            TrustState::Trusted | TrustState::Introduced
        ) {
            return Err(StoreError::Corrupt(
                "introducer lacks active authority for scope".into(),
            ));
        }
        let records = self.all_records()?;
        if records
            .iter()
            .filter(|record| record.subject == subject)
            .count()
            >= MAX_INTRODUCTIONS_PER_SUBJECT
        {
            return Err(StoreError::QuotaExceeded);
        }
        let sequence = records
            .iter()
            .filter(|record| record.introducer == introducer && record.subject == subject)
            .map(|record| record.sequence)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let record = IntroductionRecord {
            introducer: introducer.to_vec(),
            subject: subject.to_vec(),
            scope: scope.to_string(),
            expires_at_ms,
            sequence,
        };
        self.store.put(
            Namespace::Trust,
            &introduction_key(&record),
            &encode_introduction(&record),
        )
    }

    /// Verifies and persists a signed introduction statement.  The issuer
    /// public key is supplied by the authenticated binding that carried the
    /// statement and is persisted beside it for restart-time verification.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] for an invalid signature, expired
    /// statement, unauthorized introducer, or regressed sequence, and
    /// [`StoreError::QuotaExceeded`] when the subject is at its bounded
    /// introduction limit.
    pub fn accept_signed_introduction(
        &self,
        statement: &SignedIntroduction,
        introducer_public_key: &IdentityPublicKey,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        statement
            .validate(introducer_public_key, now_ms)
            .map_err(|error| {
                StoreError::Corrupt(format!("invalid signed introduction: {error:?}"))
            })?;
        let introducer_state = self.effective_state(
            &statement.introducer_endpoint_id,
            &statement.allowed_use,
            now_ms,
        )?;
        if !matches!(
            introducer_state,
            TrustState::Trusted | TrustState::Introduced
        ) {
            return Err(StoreError::Corrupt(
                "introducer lacks active authority for scope".into(),
            ));
        }
        let records = self.all_records()?;
        if records
            .iter()
            .filter(|record| record.subject == statement.subject_endpoint_id)
            .count()
            >= MAX_INTRODUCTIONS_PER_SUBJECT
        {
            return Err(StoreError::QuotaExceeded);
        }
        if records.iter().any(|record| {
            record.introducer == statement.introducer_endpoint_id
                && record.subject == statement.subject_endpoint_id
                && record.sequence >= statement.sequence
        }) {
            return Err(StoreError::Corrupt(
                "signed introduction sequence regressed".into(),
            ));
        }
        let encoded = statement.to_bytes().map_err(|error| {
            StoreError::Corrupt(format!("invalid signed introduction: {error:?}"))
        })?;
        let mut value = Vec::with_capacity(32 + encoded.len());
        value.extend_from_slice(&introducer_public_key.0);
        value.extend_from_slice(&encoded);
        self.store.put(
            Namespace::Trust,
            &signed_introduction_key(statement),
            &value,
        )
    }

    /// Returns the effective state for a subject and requested scope. An
    /// active, authorized path from a trusted introducer yields `Introduced`;
    /// it never promotes the subject to `Trusted`.
    ///
    /// # Errors
    /// Returns [`StoreError`] when trust or introduction records are corrupt.
    pub fn effective_state(
        &self,
        subject: &[u8],
        scope: &str,
        now_ms: u64,
    ) -> Result<TrustState, StoreError> {
        let trust = TrustStore::new(self.store, TrustState::Unknown);
        let current = trust.effective_trust_state(subject)?;
        if !matches!(current, TrustState::Unknown | TrustState::Observed) {
            return Ok(current);
        }
        if self.has_authorized_introduction(subject, scope, now_ms, 0, &mut Vec::new())? {
            Ok(TrustState::Introduced)
        } else {
            Ok(current)
        }
    }

    fn has_authorized_introduction(
        &self,
        subject: &[u8],
        scope: &str,
        now_ms: u64,
        depth: usize,
        visiting: &mut Vec<Vec<u8>>,
    ) -> Result<bool, StoreError> {
        if depth > self.max_depth || visiting.iter().any(|seen| seen == subject) {
            return Ok(false);
        }
        let trust = TrustStore::new(self.store, TrustState::Unknown);
        if trust.effective_trust_state(subject)? == TrustState::Trusted {
            return Ok(true);
        }
        visiting.push(subject.to_vec());
        let records = self.all_records()?;
        for record in records.iter().filter(|record| {
            record.subject == subject
                && record.expires_at_ms > now_ms
                && scope_matches(&record.scope, scope)
        }) {
            if self.has_authorized_introduction(
                &record.introducer,
                scope,
                now_ms,
                depth + 1,
                visiting,
            )? {
                visiting.pop();
                return Ok(true);
            }
        }
        visiting.pop();
        Ok(false)
    }

    fn records(&self) -> Result<Vec<IntroductionRecord>, StoreError> {
        self.store
            .scan(Namespace::Trust)?
            .into_iter()
            .filter(|entry| entry.key.starts_with(b"intro/"))
            .map(|entry| decode_introduction(&entry.key, &entry.value))
            .collect()
    }

    fn all_records(&self) -> Result<Vec<IntroductionRecord>, StoreError> {
        let mut records = self.records()?;
        records.extend(
            self.signed_records()?
                .into_iter()
                .map(|signed| IntroductionRecord {
                    introducer: signed.statement.introducer_endpoint_id.to_vec(),
                    subject: signed.statement.subject_endpoint_id.to_vec(),
                    scope: signed.statement.allowed_use,
                    expires_at_ms: signed.statement.expires_at_ms,
                    sequence: signed.statement.sequence,
                }),
        );
        Ok(records)
    }

    fn signed_records(&self) -> Result<Vec<SignedIntroductionRecord>, StoreError> {
        self.store
            .scan(Namespace::Trust)?
            .into_iter()
            .filter(|entry| entry.key.starts_with(SIGNED_INTRODUCTION_PREFIX))
            .map(|entry| {
                if entry.value.len() < 32 {
                    return Err(StoreError::Corrupt(
                        "bad signed introduction issuer key".into(),
                    ));
                }
                let introducer_public_key =
                    IdentityPublicKey(entry.value[..32].try_into().map_err(|_| {
                        StoreError::Corrupt("bad signed introduction issuer key".into())
                    })?);
                let statement =
                    SignedIntroduction::from_bytes(&entry.value[32..]).map_err(|error| {
                        StoreError::Corrupt(format!("bad signed introduction: {error:?}"))
                    })?;
                if signed_introduction_key(&statement) != entry.key {
                    return Err(StoreError::Corrupt(
                        "signed introduction key does not match statement".into(),
                    ));
                }
                statement
                    .verify_signature(&introducer_public_key)
                    .map_err(|error| {
                        StoreError::Corrupt(format!("bad signed introduction signature: {error:?}"))
                    })?;
                Ok(SignedIntroductionRecord { statement })
            })
            .collect()
    }
}

fn scope_matches(record_scope: &str, requested_scope: &str) -> bool {
    record_scope == "*" || record_scope == requested_scope
}

fn introduction_key(record: &IntroductionRecord) -> Vec<u8> {
    let mut key = b"intro/".to_vec();
    append_len_prefixed(&mut key, &record.introducer);
    append_len_prefixed(&mut key, &record.subject);
    key.extend_from_slice(&record.sequence.to_be_bytes());
    key
}

fn signed_introduction_key(statement: &SignedIntroduction) -> Vec<u8> {
    let mut key = SIGNED_INTRODUCTION_PREFIX.to_vec();
    key.extend_from_slice(&statement.introducer_endpoint_id);
    key.extend_from_slice(&statement.subject_endpoint_id);
    key.extend_from_slice(&statement.sequence.to_be_bytes());
    key
}

fn delegation_key(delegated_public_key: &[u8; 32]) -> Vec<u8> {
    let mut key = SIGNED_DELEGATION_PREFIX.to_vec();
    key.extend_from_slice(delegated_public_key);
    key
}

fn validate_delegation_capabilities(capabilities: &[Vec<u8>]) -> Result<(), StoreError> {
    if capabilities.len() > MAX_DELEGATION_CAPABILITIES
        || capabilities.iter().map(Vec::len).sum::<usize>() > MAX_DELEGATION_CAPABILITY_BYTES
        || capabilities.iter().any(|capability| {
            capability.is_empty() || capability.len() > MAX_DELEGATION_CAPABILITY_LEN
        })
    {
        return Err(StoreError::QuotaExceeded);
    }
    Ok(())
}

fn encode_delegation(record: &StoredDelegationChain) -> Result<Vec<u8>, StoreError> {
    validate_delegation_capabilities(&record.root_capabilities)?;
    if record.certificates.is_empty() {
        return Err(StoreError::Corrupt("empty delegation chain".into()));
    }
    let mut out = Vec::with_capacity(128);
    out.push(1);
    out.extend_from_slice(&record.root_public_key.0);
    out.push(u8::try_from(record.root_capabilities.len()).map_err(|_| StoreError::QuotaExceeded)?);
    for capability in &record.root_capabilities {
        out.extend_from_slice(
            &u16::try_from(capability.len())
                .map_err(|_| StoreError::QuotaExceeded)?
                .to_be_bytes(),
        );
        out.extend_from_slice(capability);
    }
    out.push(u8::try_from(record.certificates.len()).map_err(|_| StoreError::QuotaExceeded)?);
    for certificate in &record.certificates {
        let bytes = certificate
            .to_bytes()
            .map_err(|error| StoreError::Corrupt(format!("invalid delegation: {error:?}")))?;
        out.extend_from_slice(
            &u16::try_from(bytes.len())
                .map_err(|_| StoreError::QuotaExceeded)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&bytes);
    }
    if out.len() > MAX_DELEGATION_CHAIN_BYTES {
        return Err(StoreError::QuotaExceeded);
    }
    Ok(out)
}

fn decode_delegation(key: &[u8], bytes: &[u8]) -> Result<StoredDelegationChain, StoreError> {
    if !key.starts_with(SIGNED_DELEGATION_PREFIX)
        || key.len() != SIGNED_DELEGATION_PREFIX.len() + 32
        || bytes.len() > MAX_DELEGATION_CHAIN_BYTES
    {
        return Err(StoreError::Corrupt("bad delegation record bounds".into()));
    }
    let mut offset = 0usize;
    let version = read_delegation_byte(bytes, &mut offset)?;
    if version != 1 {
        return Err(StoreError::Corrupt(
            "unknown delegation record version".into(),
        ));
    }
    let root_public_key = IdentityPublicKey(read_delegation_array(bytes, &mut offset)?);
    let capability_count = usize::from(read_delegation_byte(bytes, &mut offset)?);
    if capability_count > MAX_DELEGATION_CAPABILITIES {
        return Err(StoreError::Corrupt(
            "too many root delegation capabilities".into(),
        ));
    }
    let mut root_capabilities = Vec::with_capacity(capability_count);
    for _ in 0..capability_count {
        let length = usize::from(u16::from_be_bytes(read_delegation_array::<2>(
            bytes,
            &mut offset,
        )?));
        let capability = read_delegation_slice(bytes, &mut offset, length)?.to_vec();
        root_capabilities.push(capability);
    }
    validate_delegation_capabilities(&root_capabilities)?;
    let certificate_count = usize::from(read_delegation_byte(bytes, &mut offset)?);
    if certificate_count == 0
        || certificate_count > crate::trust_statement::MAX_DELEGATION_CHAIN_LENGTH
    {
        return Err(StoreError::Corrupt(
            "invalid delegation chain length".into(),
        ));
    }
    let mut certificates = Vec::with_capacity(certificate_count);
    for _ in 0..certificate_count {
        let length = usize::from(u16::from_be_bytes(read_delegation_array::<2>(
            bytes,
            &mut offset,
        )?));
        let encoded = read_delegation_slice(bytes, &mut offset, length)?;
        certificates.push(SignedDelegation::from_bytes(encoded).map_err(|error| {
            StoreError::Corrupt(format!(
                "invalid persisted delegation certificate: {error:?}"
            ))
        })?);
    }
    if offset != bytes.len()
        || delegation_key(&certificates[certificate_count - 1].delegated_public_key) != key
    {
        return Err(StoreError::Corrupt("delegation key mismatch".into()));
    }
    Ok(StoredDelegationChain {
        root_public_key,
        root_capabilities,
        certificates,
    })
}

fn read_delegation_byte(bytes: &[u8], offset: &mut usize) -> Result<u8, StoreError> {
    let value = *bytes
        .get(*offset)
        .ok_or_else(|| StoreError::Corrupt("truncated delegation record".into()))?;
    *offset += 1;
    Ok(value)
}

fn read_delegation_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], StoreError> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| StoreError::Corrupt("delegation record overflow".into()))?;
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| StoreError::Corrupt("truncated delegation record".into()))?;
    *offset = end;
    value
        .try_into()
        .map_err(|_| StoreError::Corrupt("invalid delegation record array".into()))
}

fn read_delegation_slice<'b>(
    bytes: &'b [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'b [u8], StoreError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| StoreError::Corrupt("delegation record overflow".into()))?;
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| StoreError::Corrupt("truncated delegation record".into()))?;
    *offset = end;
    Ok(value)
}

fn append_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(value);
}

fn encode_introduction(record: &IntroductionRecord) -> Vec<u8> {
    let mut value = Vec::new();
    value.push(1);
    value.extend_from_slice(&record.expires_at_ms.to_be_bytes());
    value.extend_from_slice(
        &u16::try_from(record.scope.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    value.extend_from_slice(record.scope.as_bytes());
    value
}

fn decode_introduction(key: &[u8], value: &[u8]) -> Result<IntroductionRecord, StoreError> {
    if !key.starts_with(b"intro/") || key.len() < 6 {
        return Err(StoreError::Corrupt("bad introduction key".into()));
    }
    let mut offset = 6;
    let introducer = read_len_prefixed(key, &mut offset)?;
    let subject = read_len_prefixed(key, &mut offset)?;
    if key.len() != offset + 8 || value.len() < 11 || value[0] != 1 {
        return Err(StoreError::Corrupt("bad introduction record".into()));
    }
    let sequence = u64::from_be_bytes(
        key[offset..]
            .try_into()
            .map_err(|_| StoreError::Corrupt("bad introduction sequence".into()))?,
    );
    let expires_at_ms = u64::from_be_bytes(
        value[1..9]
            .try_into()
            .map_err(|_| StoreError::Corrupt("bad introduction expiry".into()))?,
    );
    let scope_len =
        usize::from(u16::from_be_bytes(value[9..11].try_into().map_err(
            |_| StoreError::Corrupt("bad introduction scope".into()),
        )?));
    if value.len() != 11 + scope_len {
        return Err(StoreError::Corrupt("bad introduction scope length".into()));
    }
    let scope = String::from_utf8(value[11..].to_vec())
        .map_err(|_| StoreError::Corrupt("introduction scope is not utf8".into()))?;
    Ok(IntroductionRecord {
        introducer,
        subject,
        scope,
        expires_at_ms,
        sequence,
    })
}

fn read_len_prefixed(bytes: &[u8], offset: &mut usize) -> Result<Vec<u8>, StoreError> {
    if *offset + 2 > bytes.len() {
        return Err(StoreError::Corrupt(
            "bad introduction identity length".into(),
        ));
    }
    let len = usize::from(u16::from_be_bytes(
        bytes[*offset..*offset + 2]
            .try_into()
            .map_err(|_| StoreError::Corrupt("bad introduction identity length".into()))?,
    ));
    *offset += 2;
    if *offset + len > bytes.len() {
        return Err(StoreError::Corrupt("bad introduction identity".into()));
    }
    let value = bytes[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(value)
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
    use crate::trust_statement::{SignedDelegation, SignedIntroduction, SubjectEvidence};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};

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

    #[test]
    fn introduction_graph_is_scoped_expiring_and_depth_bounded() {
        let path = temp_path();
        let store = open_store(&path);
        let trust = TrustStore::new(&store, TrustState::Unknown);
        let graph = TrustGraph::new(&store);
        let root = b"root";
        let middle = b"middle";
        let leaf = b"leaf";
        trust.set_state(root, TrustState::Trusted, 1).unwrap();
        graph.introduce(root, middle, "chat", 100, 2).unwrap();
        graph.introduce(middle, leaf, "chat", 100, 3).unwrap();
        assert_eq!(
            graph.effective_state(leaf, "chat", 4).unwrap(),
            TrustState::Introduced
        );
        assert_eq!(
            graph.effective_state(leaf, "files", 4).unwrap(),
            TrustState::Unknown
        );
        assert_eq!(
            graph.effective_state(leaf, "chat", 100).unwrap(),
            TrustState::Unknown
        );

        let too_deep = b"too-deep";
        graph.introduce(leaf, too_deep, "chat", 200, 5).unwrap();
        assert_eq!(
            graph.effective_state(too_deep, "chat", 6).unwrap(),
            TrustState::Unknown
        );
    }

    #[test]
    fn untrusted_introducer_cannot_create_authority() {
        let path = temp_path();
        let store = open_store(&path);
        let graph = TrustGraph::new(&store);
        assert!(matches!(
            graph.introduce(b"unknown", b"peer", "chat", 100, 1),
            Err(StoreError::Corrupt(message)) if message.contains("lacks active authority")
        ));
    }

    #[test]
    fn introductions_persist_across_store_reopen() {
        let path = temp_path();
        {
            let store = open_store(&path);
            let trust = TrustStore::new(&store, TrustState::Unknown);
            trust.set_state(b"root", TrustState::Trusted, 1).unwrap();
            TrustGraph::new(&store)
                .introduce(b"root", b"peer", "public", 100, 2)
                .unwrap();
        }
        let store = open_store(&path);
        assert_eq!(
            TrustGraph::new(&store)
                .effective_state(b"peer", "public", 3)
                .unwrap(),
            TrustState::Introduced
        );
    }

    #[test]
    fn signed_introduction_is_verified_scoped_and_persistent() {
        let path = temp_path();
        let root = IdentityKeyPair::from_seed([21u8; 32]);
        let subject = IdentityKeyPair::from_seed([22u8; 32]);
        let subject_static = StaticHandshakeKeyPair::from_seed([23u8; 32]);
        let root_endpoint = umc_handshake::identity::endpoint_id(&root.public());
        let subject_endpoint = umc_handshake::identity::endpoint_id(&subject.public());
        let statement = SignedIntroduction::sign(
            &root,
            subject_endpoint,
            SubjectEvidence::StaticHandshakeKey(subject_static.public().0),
            "relay",
            100,
            75,
            0b0000_0001,
            3,
        )
        .unwrap();
        {
            let store = open_store(&path);
            TrustStore::new(&store, TrustState::Unknown)
                .set_state(&root_endpoint, TrustState::Trusted, 1)
                .unwrap();
            TrustGraph::new(&store)
                .accept_signed_introduction(&statement, &root.public(), 2)
                .unwrap();
            assert_eq!(
                TrustGraph::new(&store)
                    .effective_state(&subject_endpoint, "relay", 3)
                    .unwrap(),
                TrustState::Introduced
            );
            assert_eq!(
                TrustGraph::new(&store)
                    .effective_state(&subject_endpoint, "files", 3)
                    .unwrap(),
                TrustState::Unknown
            );
        }
        let store = open_store(&path);
        assert_eq!(
            TrustGraph::new(&store)
                .effective_state(&subject_endpoint, "relay", 4)
                .unwrap(),
            TrustState::Introduced
        );
        assert_eq!(
            TrustGraph::new(&store)
                .effective_state(&subject_endpoint, "relay", 100)
                .unwrap(),
            TrustState::Unknown
        );
    }

    #[test]
    fn signed_introduction_rejects_bad_key_and_sequence_regression() {
        let path = temp_path();
        let root = IdentityKeyPair::from_seed([31u8; 32]);
        let other = IdentityKeyPair::from_seed([32u8; 32]);
        let subject = IdentityKeyPair::from_seed([33u8; 32]);
        let root_endpoint = umc_handshake::identity::endpoint_id(&root.public());
        let subject_endpoint = umc_handshake::identity::endpoint_id(&subject.public());
        let statement = SignedIntroduction::sign(
            &root,
            subject_endpoint,
            SubjectEvidence::BindingDigest([44u8; 32]),
            "chat",
            100,
            1,
            0,
            2,
        )
        .unwrap();
        let store = open_store(&path);
        TrustStore::new(&store, TrustState::Unknown)
            .set_state(&root_endpoint, TrustState::Trusted, 1)
            .unwrap();
        let graph = TrustGraph::new(&store);
        assert!(matches!(
            graph.accept_signed_introduction(&statement, &other.public(), 2),
            Err(StoreError::Corrupt(message)) if message.contains("invalid signed introduction")
        ));
        graph
            .accept_signed_introduction(&statement, &root.public(), 2)
            .unwrap();
        assert!(matches!(
            graph.accept_signed_introduction(&statement, &root.public(), 2),
            Err(StoreError::Corrupt(message)) if message.contains("sequence regressed")
        ));
    }

    #[test]
    fn delegation_chain_persists_revalidates_and_rejects_rollback() {
        let path = temp_path();
        let root = IdentityKeyPair::from_seed([81u8; 32]);
        let delegated = IdentityKeyPair::from_seed([82u8; 32]);
        let certificate = SignedDelegation::sign(
            &root,
            delegated.public().0,
            vec![b"relay".to_vec(), b"chat".to_vec()],
            100,
            1_000,
            1,
        )
        .unwrap();
        {
            let store = open_store(&path);
            let authority = DelegationStore::new(&store)
                .accept_chain(
                    &root.public(),
                    &[b"chat".to_vec(), b"relay".to_vec()],
                    std::slice::from_ref(&certificate),
                    200,
                )
                .unwrap();
            assert_eq!(authority.public_key, delegated.public());
        }
        let store = open_store(&path);
        let restored = DelegationStore::new(&store).valid_chains(300).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].certificates, vec![certificate.clone()]);
        let by_leaf = DelegationStore::new(&store)
            .valid_chain_for_public_key(&delegated.public().0, 300)
            .unwrap()
            .expect("leaf lookup");
        assert_eq!(by_leaf.certificates, vec![certificate.clone()]);
        assert!(DelegationStore::new(&store)
            .valid_chain_for_public_key(&[9u8; 32], 300)
            .unwrap()
            .is_none());

        let newer = SignedDelegation::sign(
            &root,
            delegated.public().0,
            vec![b"chat".to_vec()],
            200,
            900,
            2,
        )
        .unwrap();
        DelegationStore::new(&store)
            .accept_chain(
                &root.public(),
                &[b"chat".to_vec(), b"relay".to_vec()],
                std::slice::from_ref(&newer),
                300,
            )
            .unwrap();
        assert!(matches!(
            DelegationStore::new(&store).accept_chain(
                &root.public(),
                &[b"chat".to_vec(), b"relay".to_vec()],
                std::slice::from_ref(&certificate),
                300,
            ),
            Err(StoreError::Corrupt(message)) if message.contains("sequence regressed")
        ));
    }

    #[test]
    fn malformed_persisted_delegation_fails_closed() {
        let path = temp_path();
        let store = open_store(&path);
        let key = delegation_key(&[7u8; 32]);
        store.put(Namespace::Trust, &key, &[1, 2, 3]).unwrap();
        assert!(matches!(
            DelegationStore::new(&store).valid_chains(0),
            Err(StoreError::Corrupt(message)) if message.contains("truncated") || message.contains("bounds")
        ));
    }
}
