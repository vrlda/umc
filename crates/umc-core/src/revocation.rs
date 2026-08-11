//! Revocation and trust-on-first-use records (identity-trust.md §13, §17).
use crate::recovery::{RecoveryError, RecoveryStore};
use crate::trust_statement::{RevocationSubject, SignedRevocation};
use umc_crypto::signatures::IdentityPublicKey;
use umc_handshake::identity::IdentityBinding;
use umc_storage::store::{Namespace, Store, StoreError};

const RECORD_VERSION: u8 = 1;
const SIGNED_REVOCATION_PREFIX: &[u8] = b"revoke-signed/";
const SIGNED_BATCH_VERSION: u8 = 1;
const MAX_SIGNED_BATCH_ENTRIES: usize = 64;
const MAX_SIGNED_BATCH_BYTES: usize = 16 * 1024;

/// A revocation record for one endpoint and binding sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRecord {
    pub endpoint_id: [u8; 32],
    pub revoked_sequence: u64,
    pub not_after_ms: u64,
    pub revoker_id: Vec<u8>,
    pub recorded_at_ms: u64,
}

/// Revocation lookup error. A revoked binding is deliberately distinct from
/// storage corruption so the handshake can emit `IDENTITY_REVOKED`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationError {
    Revoked {
        endpoint_id: [u8; 32],
        sequence: u64,
    },
    Storage(StoreError),
    Invalid(String),
}

/// Local view of how recently persisted revocation evidence was recorded.
/// `Unknown` is deliberately distinct from `Fresh`: no local revocation
/// record proves that the node has never received a revocation update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationFreshness {
    Unknown,
    Fresh { latest_recorded_at_ms: u64 },
    Stale { latest_recorded_at_ms: u64 },
}

impl RevocationFreshness {
    /// Whether the local evidence must be qualified in trust claims.
    #[must_use]
    pub const fn requires_warning(self) -> bool {
        !matches!(self, Self::Fresh { .. })
    }
}

/// Persistent endpoint revocation records.
pub struct RevocationStore<'a> {
    store: &'a dyn Store,
}

impl std::fmt::Debug for RevocationStore<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RevocationStore")
            .finish_non_exhaustive()
    }
}

impl<'a> RevocationStore<'a> {
    #[must_use]
    pub const fn new(store: &'a dyn Store) -> Self {
        Self { store }
    }

    /// Records or advances a revocation sequence for an endpoint.
    ///
    /// # Errors
    /// Returns [`RevocationError::Invalid`] for malformed input, or
    /// [`RevocationError::Storage`] when persistence fails.
    pub fn revoke(
        &self,
        endpoint_id: &[u8; 32],
        revoked_sequence: u64,
        not_after_ms: u64,
        revoker_id: &[u8],
        recorded_at_ms: u64,
    ) -> Result<(), RevocationError> {
        if revoker_id.is_empty() || (not_after_ms != 0 && not_after_ms <= recorded_at_ms) {
            return Err(RevocationError::Invalid("invalid revocation record".into()));
        }
        if let Some(existing) = self.record(endpoint_id).map_err(RevocationError::Storage)? {
            if revoked_sequence < existing.revoked_sequence {
                return Err(RevocationError::Invalid(
                    "revocation sequence regressed".into(),
                ));
            }
        }
        let mut value = Vec::with_capacity(1 + 8 + 8 + 8 + revoker_id.len());
        value.push(RECORD_VERSION);
        value.extend_from_slice(&revoked_sequence.to_be_bytes());
        value.extend_from_slice(&not_after_ms.to_be_bytes());
        value.extend_from_slice(&recorded_at_ms.to_be_bytes());
        value.extend_from_slice(
            &u16::try_from(revoker_id.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        value.extend_from_slice(revoker_id);
        self.store
            .put(Namespace::Trust, &revocation_key(endpoint_id), &value)
            .map_err(RevocationError::Storage)
    }

    /// Verifies and persists a self-authorized signed revocation statement.
    ///
    /// Identity and binding revocations are self-authorized by the issuer's
    /// identity key. Delegation, introduction, and recovery-key authority
    /// remain explicit local-policy/distribution work and are rejected here.
    ///
    /// # Errors
    /// Returns [`RevocationError::Invalid`] for an invalid signature, validity
    /// interval, unauthorized subject, or regressed sequence, and
    /// [`RevocationError::Storage`] when persistence fails.
    pub fn accept_signed(
        &self,
        statement: &SignedRevocation,
        issuer_public_key: &IdentityPublicKey,
        now_ms: u64,
    ) -> Result<(), RevocationError> {
        statement
            .validate(issuer_public_key, now_ms)
            .map_err(|error| {
                RevocationError::Invalid(format!("invalid signed revocation: {error:?}"))
            })?;
        if !statement.is_self_authorized() {
            return Err(RevocationError::Invalid(
                "signed revocation issuer lacks subject authority".into(),
            ));
        }
        let existing = self.signed_records().map_err(RevocationError::Storage)?;
        if existing.iter().any(|record| {
            record.issuer_endpoint_id == statement.issuer_endpoint_id
                && record.subject == statement.subject
                && record.sequence >= statement.sequence
        }) {
            return Err(RevocationError::Invalid(
                "signed revocation sequence regressed".into(),
            ));
        }
        let encoded = statement.to_bytes().map_err(|error| {
            RevocationError::Invalid(format!("invalid signed revocation: {error:?}"))
        })?;
        let mut value = Vec::with_capacity(32 + encoded.len());
        value.extend_from_slice(&issuer_public_key.0);
        value.extend_from_slice(&encoded);
        self.store
            .put(Namespace::Trust, &signed_revocation_key(statement), &value)
            .map_err(RevocationError::Storage)
    }

    /// Exports locally persisted self-authorized statements for propagation
    /// over an already authenticated peer exchange.  The issuer key travels
    /// beside each statement and every receiver re-verifies it; the carrier
    /// or forwarding peer is never treated as the revocation authority.
    ///
    /// # Errors
    /// Returns [`RevocationError`] when persisted records are corrupt or
    /// cannot be encoded within the exchange bound.
    pub fn export_signed_batch(&self) -> Result<Vec<u8>, RevocationError> {
        let mut out = vec![b'R', b'S', SIGNED_BATCH_VERSION, 0, 0];
        let mut count = 0usize;
        for (issuer_public_key, statement) in self
            .signed_record_entries()
            .map_err(RevocationError::Storage)?
        {
            if count == MAX_SIGNED_BATCH_ENTRIES {
                break;
            }
            let encoded = statement.to_bytes().map_err(|error| {
                RevocationError::Invalid(format!("invalid persisted revocation: {error:?}"))
            })?;
            let len = u16::try_from(encoded.len())
                .map_err(|_| RevocationError::Invalid("revocation batch item too large".into()))?;
            out.extend_from_slice(&issuer_public_key.0);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&encoded);
            if out.len() > MAX_SIGNED_BATCH_BYTES {
                return Err(RevocationError::Invalid(
                    "revocation batch too large".into(),
                ));
            }
            count += 1;
        }
        out[3..5].copy_from_slice(
            &u16::try_from(count)
                .map_err(|_| RevocationError::Invalid("revocation batch count".into()))?
                .to_be_bytes(),
        );
        Ok(out)
    }

    /// Imports a bounded signed-revocation exchange.  All entries are parsed
    /// and verified before any is committed, preventing a malformed suffix
    /// from producing a partially accepted propagation result.
    ///
    /// # Errors
    /// Returns [`RevocationError`] when the payload is malformed, oversized,
    /// unauthenticated, or conflicts with persisted sequence state.
    pub fn accept_signed_batch(&self, bytes: &[u8], now_ms: u64) -> Result<usize, RevocationError> {
        if bytes.len() > MAX_SIGNED_BATCH_BYTES || bytes.get(..3) != Some(b"RS\x01") {
            return Err(RevocationError::Invalid("invalid revocation batch".into()));
        }
        let count = u16::from_be_bytes(
            bytes
                .get(3..5)
                .ok_or_else(|| RevocationError::Invalid("truncated revocation batch".into()))?
                .try_into()
                .map_err(|_| RevocationError::Invalid("truncated revocation batch".into()))?,
        ) as usize;
        if count > MAX_SIGNED_BATCH_ENTRIES {
            return Err(RevocationError::Invalid("revocation batch count".into()));
        }
        let mut offset = 5usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let issuer = bytes
                .get(offset..offset + 32)
                .ok_or_else(|| RevocationError::Invalid("truncated issuer key".into()))?;
            offset += 32;
            let len = u16::from_be_bytes(
                bytes
                    .get(offset..offset + 2)
                    .ok_or_else(|| RevocationError::Invalid("truncated item length".into()))?
                    .try_into()
                    .map_err(|_| RevocationError::Invalid("truncated item length".into()))?,
            ) as usize;
            offset += 2;
            let statement = bytes
                .get(offset..offset + len)
                .ok_or_else(|| RevocationError::Invalid("truncated statement".into()))?;
            offset += len;
            let statement = SignedRevocation::from_bytes(statement).map_err(|error| {
                RevocationError::Invalid(format!("invalid statement: {error:?}"))
            })?;
            let issuer_public_key = IdentityPublicKey(
                issuer
                    .try_into()
                    .map_err(|_| RevocationError::Invalid("invalid issuer key".into()))?,
            );
            statement
                .validate(&issuer_public_key, now_ms)
                .map_err(|error| {
                    RevocationError::Invalid(format!("invalid statement: {error:?}"))
                })?;
            if !statement.is_self_authorized() {
                return Err(RevocationError::Invalid(
                    "unauthorized propagated statement".into(),
                ));
            }
            if self
                .signed_record_entries()
                .map_err(RevocationError::Storage)?
                .into_iter()
                .any(|(_, existing)| {
                    existing.issuer_endpoint_id == statement.issuer_endpoint_id
                        && existing.subject == statement.subject
                        && existing.sequence >= statement.sequence
                        && existing.signed_bytes() != statement.signed_bytes()
                })
            {
                return Err(RevocationError::Invalid(
                    "revocation sequence regressed".into(),
                ));
            }
            entries.push((issuer_public_key, statement));
        }
        if offset != bytes.len() {
            return Err(RevocationError::Invalid(
                "trailing revocation batch bytes".into(),
            ));
        }
        for (issuer, statement) in &entries {
            self.accept_signed(statement, issuer, now_ms)?;
        }
        Ok(entries.len())
    }

    /// Reads one persisted revocation record.
    ///
    /// # Errors
    /// Returns [`RevocationError::Storage`] when the record is corrupt or the
    /// backend cannot be read.
    pub fn record(&self, endpoint_id: &[u8; 32]) -> Result<Option<RevocationRecord>, StoreError> {
        let Some(value) = self
            .store
            .get(Namespace::Trust, &revocation_key(endpoint_id))?
        else {
            return Ok(None);
        };
        decode_revocation(endpoint_id, &value).map(Some)
    }

    /// Checks whether the binding is currently revoked.
    ///
    /// # Errors
    /// Returns [`RevocationError::Revoked`] for an active matching record and
    /// [`RevocationError::Storage`] for backend or encoding failures.
    pub fn check(&self, binding: &IdentityBinding, now_ms: u64) -> Result<(), RevocationError> {
        if let Some(record) = self
            .record(&binding.endpoint_id)
            .map_err(RevocationError::Storage)?
        {
            if (record.not_after_ms == 0 || now_ms <= record.not_after_ms)
                && binding.sequence <= record.revoked_sequence
            {
                return Err(RevocationError::Revoked {
                    endpoint_id: binding.endpoint_id,
                    sequence: binding.sequence,
                });
            }
        }
        for statement in self.signed_records().map_err(RevocationError::Storage)? {
            if now_ms < statement.issued_at_ms
                || (statement.expires_at_ms != 0 && now_ms >= statement.expires_at_ms)
            {
                continue;
            }
            let revoked = match statement.subject {
                RevocationSubject::Identity(endpoint_id) => endpoint_id == binding.endpoint_id,
                RevocationSubject::Binding {
                    endpoint_id,
                    binding_sequence,
                } => endpoint_id == binding.endpoint_id && binding.sequence <= binding_sequence,
                RevocationSubject::Delegation(_)
                | RevocationSubject::Introduction(_)
                | RevocationSubject::RecoveryKey(_) => false,
            };
            if revoked {
                return Err(RevocationError::Revoked {
                    endpoint_id: binding.endpoint_id,
                    sequence: binding.sequence,
                });
            }
        }
        match RecoveryStore::new(self.store).check(binding, now_ms) {
            Ok(()) => {}
            Err(RecoveryError::Revoked) => {
                return Err(RevocationError::Revoked {
                    endpoint_id: binding.endpoint_id,
                    sequence: binding.sequence,
                });
            }
            Err(error) => {
                return Err(RevocationError::Invalid(format!(
                    "recovery revocation check failed: {error:?}"
                )));
            }
        }
        Ok(())
    }

    fn signed_records(&self) -> Result<Vec<SignedRevocation>, StoreError> {
        Ok(self
            .signed_record_entries()?
            .into_iter()
            .map(|(_, statement)| statement)
            .collect())
    }

    fn signed_record_entries(
        &self,
    ) -> Result<Vec<(IdentityPublicKey, SignedRevocation)>, StoreError> {
        self.store
            .scan(Namespace::Trust)?
            .into_iter()
            .filter(|entry| entry.key.starts_with(SIGNED_REVOCATION_PREFIX))
            .map(|entry| {
                if entry.value.len() < 32 {
                    return Err(StoreError::Corrupt(
                        "bad signed revocation issuer key".into(),
                    ));
                }
                let issuer_public_key =
                    IdentityPublicKey(entry.value[..32].try_into().map_err(|_| {
                        StoreError::Corrupt("bad signed revocation issuer key".into())
                    })?);
                let statement =
                    SignedRevocation::from_bytes(&entry.value[32..]).map_err(|error| {
                        StoreError::Corrupt(format!("bad signed revocation: {error:?}"))
                    })?;
                if signed_revocation_key(&statement) != entry.key {
                    return Err(StoreError::Corrupt(
                        "signed revocation key does not match statement".into(),
                    ));
                }
                statement
                    .verify_signature(&issuer_public_key)
                    .map_err(|error| {
                        StoreError::Corrupt(format!("bad signed revocation signature: {error:?}"))
                    })?;
                if !statement.is_self_authorized() {
                    return Err(StoreError::Corrupt(
                        "signed revocation issuer lacks subject authority".into(),
                    ));
                }
                Ok((issuer_public_key, statement))
            })
            .collect()
    }

    /// Classifies the age of the newest persisted revocation statement.
    ///
    /// This is an explicit local-freshness signal, not proof that the peer
    /// has no newer revocation. Callers must qualify claims whenever the
    /// result is [`RevocationFreshness::Unknown`] or `Stale`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the trust namespace cannot be scanned or a
    /// reserved revocation record is corrupt.
    pub fn freshness(
        &self,
        now_ms: u64,
        max_age_ms: u64,
    ) -> Result<RevocationFreshness, StoreError> {
        let prefix = b"revoke/";
        let mut latest = None;
        for entry in self.store.scan(Namespace::Trust)? {
            if !entry.key.starts_with(prefix) {
                continue;
            }
            let endpoint_bytes = entry
                .key
                .get(prefix.len()..)
                .filter(|bytes| bytes.len() == 32)
                .ok_or_else(|| StoreError::Corrupt("bad revocation key".into()))?;
            let endpoint_id: [u8; 32] = endpoint_bytes
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad revocation key".into()))?;
            let record = decode_revocation(&endpoint_id, &entry.value)?;
            latest = Some(latest.map_or(record.recorded_at_ms, |value: u64| {
                value.max(record.recorded_at_ms)
            }));
        }
        let Some(latest_recorded_at_ms) = latest else {
            return Ok(RevocationFreshness::Unknown);
        };
        let age_ms = now_ms.saturating_sub(latest_recorded_at_ms);
        if age_ms <= max_age_ms {
            Ok(RevocationFreshness::Fresh {
                latest_recorded_at_ms,
            })
        } else {
            Ok(RevocationFreshness::Stale {
                latest_recorded_at_ms,
            })
        }
    }
}

fn revocation_key(endpoint_id: &[u8; 32]) -> Vec<u8> {
    let mut key = b"revoke/".to_vec();
    key.extend_from_slice(endpoint_id);
    key
}

fn signed_revocation_key(statement: &SignedRevocation) -> Vec<u8> {
    let mut key = SIGNED_REVOCATION_PREFIX.to_vec();
    key.extend_from_slice(&statement.issuer_endpoint_id);
    key.extend_from_slice(&statement.signed_bytes());
    key
}

fn decode_revocation(endpoint_id: &[u8; 32], value: &[u8]) -> Result<RevocationRecord, StoreError> {
    if value.len() < 1 + 8 + 8 + 8 + 2 || value[0] != RECORD_VERSION {
        return Err(StoreError::Corrupt("bad revocation record".into()));
    }
    let revoker_len = usize::from(u16::from_be_bytes(
        value[25..27]
            .try_into()
            .map_err(|_| StoreError::Corrupt("bad revoker length".into()))?,
    ));
    if value.len() != 27 + revoker_len {
        return Err(StoreError::Corrupt("bad revocation record length".into()));
    }
    Ok(RevocationRecord {
        endpoint_id: *endpoint_id,
        revoked_sequence: u64::from_be_bytes(
            value[1..9]
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad revoked sequence".into()))?,
        ),
        not_after_ms: u64::from_be_bytes(
            value[9..17]
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad revocation expiry".into()))?,
        ),
        recorded_at_ms: u64::from_be_bytes(
            value[17..25]
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad revocation timestamp".into()))?,
        ),
        revoker_id: value[27..].to_vec(),
    })
}

/// Trust-on-first-use record for a binding's public material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TofuRecord {
    pub endpoint_id: [u8; 32],
    pub binding_digest: [u8; 32],
    pub sequence: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TofuError {
    BindingChanged { endpoint_id: [u8; 32] },
    Storage(StoreError),
    Invalid(String),
}

/// Persistent TOFU first-seen binding store.
pub struct TofuStore<'a> {
    store: &'a dyn Store,
}

impl std::fmt::Debug for TofuStore<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("TofuStore").finish_non_exhaustive()
    }
}

impl<'a> TofuStore<'a> {
    #[must_use]
    pub const fn new(store: &'a dyn Store) -> Self {
        Self { store }
    }

    /// Records the first binding or verifies it matches the stored binding.
    ///
    /// # Errors
    /// Returns [`TofuError::BindingChanged`] when a different binding is
    /// presented without an explicit rotation approval.
    pub fn observe(&self, binding: &IdentityBinding, now_ms: u64) -> Result<(), TofuError> {
        binding
            .validate(now_ms, 300_000)
            .map_err(|error| TofuError::Invalid(format!("binding validation failed: {error:?}")))?;
        let digest = binding_digest(binding);
        let key = tofu_key(&binding.endpoint_id);
        let Some(value) = self
            .store
            .get(Namespace::Trust, &key)
            .map_err(TofuError::Storage)?
        else {
            let record = TofuRecord {
                endpoint_id: binding.endpoint_id,
                binding_digest: digest,
                sequence: binding.sequence,
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
            };
            self.store
                .put(Namespace::Trust, &key, &encode_tofu(&record))
                .map_err(TofuError::Storage)?;
            return Ok(());
        };
        let mut record = decode_tofu(&binding.endpoint_id, &value).map_err(TofuError::Storage)?;
        if record.binding_digest != digest {
            return Err(TofuError::BindingChanged {
                endpoint_id: binding.endpoint_id,
            });
        }
        if binding.sequence < record.sequence {
            return Err(TofuError::BindingChanged {
                endpoint_id: binding.endpoint_id,
            });
        }
        record.sequence = binding.sequence;
        record.last_seen_ms = now_ms;
        self.store
            .put(Namespace::Trust, &key, &encode_tofu(&record))
            .map_err(TofuError::Storage)
    }

    /// Reads the stored first-seen record.
    ///
    /// # Errors
    /// Returns [`StoreError`] for a corrupt record or backend failure.
    pub fn record(&self, endpoint_id: &[u8; 32]) -> Result<Option<TofuRecord>, StoreError> {
        let Some(value) = self.store.get(Namespace::Trust, &tofu_key(endpoint_id))? else {
            return Ok(None);
        };
        decode_tofu(endpoint_id, &value).map(Some)
    }
}

fn tofu_key(endpoint_id: &[u8; 32]) -> Vec<u8> {
    let mut key = b"tofu/".to_vec();
    key.extend_from_slice(endpoint_id);
    key
}

fn binding_digest(binding: &IdentityBinding) -> [u8; 32] {
    umc_crypto::hkdf::extract(b"UMP-TOFU-v1", &binding.signed_bytes())
}

fn encode_tofu(record: &TofuRecord) -> Vec<u8> {
    let mut value = Vec::with_capacity(1 + 32 + 8 + 8 + 8);
    value.push(RECORD_VERSION);
    value.extend_from_slice(&record.binding_digest);
    value.extend_from_slice(&record.sequence.to_be_bytes());
    value.extend_from_slice(&record.first_seen_ms.to_be_bytes());
    value.extend_from_slice(&record.last_seen_ms.to_be_bytes());
    value
}

fn decode_tofu(endpoint_id: &[u8; 32], value: &[u8]) -> Result<TofuRecord, StoreError> {
    if value.len() != 57 || value[0] != RECORD_VERSION {
        return Err(StoreError::Corrupt("bad tofu record".into()));
    }
    Ok(TofuRecord {
        endpoint_id: *endpoint_id,
        binding_digest: value[1..33]
            .try_into()
            .map_err(|_| StoreError::Corrupt("bad tofu digest".into()))?,
        sequence: u64::from_be_bytes(
            value[33..41]
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad tofu sequence".into()))?,
        ),
        first_seen_ms: u64::from_be_bytes(
            value[41..49]
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad tofu first-seen time".into()))?,
        ),
        last_seen_ms: u64::from_be_bytes(
            value[49..57]
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad tofu last-seen time".into()))?,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_statement::{RevocationSubject, SignedRevocation};
    use std::sync::atomic::{AtomicU64, Ordering};
    use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
    use umc_handshake::identity::IdentityBinding;
    use umc_storage::sqlite::SqliteStore;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn store() -> SqliteStore {
        let path = std::env::temp_dir().join(format!(
            "umc-revocation-{}-{}.db",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        SqliteStore::open(&path).expect("store")
    }

    fn binding(
        identity: &IdentityKeyPair,
        static_key: &StaticHandshakeKeyPair,
        sequence: u64,
    ) -> IdentityBinding {
        IdentityBinding::sign(
            identity,
            &static_key.public(),
            0,
            u64::MAX,
            sequence,
            [0; 32],
        )
    }

    #[test]
    fn revocation_refuses_old_binding_until_expiry() {
        let store = store();
        let identity = IdentityKeyPair::generate();
        let static_key = StaticHandshakeKeyPair::generate();
        let binding = binding(&identity, &static_key, 3);
        let revocations = RevocationStore::new(&store);
        assert!(revocations.check(&binding, 10).is_ok());
        revocations
            .revoke(&binding.endpoint_id, 3, 100, b"operator", 10)
            .expect("revoke");
        assert!(matches!(
            revocations.check(&binding, 11),
            Err(RevocationError::Revoked { .. })
        ));
        assert!(revocations.check(&binding, 101).is_ok());
    }

    #[test]
    fn freshness_distinguishes_unknown_fresh_and_stale() {
        let store = store();
        let revocations = RevocationStore::new(&store);
        assert_eq!(
            revocations.freshness(100, 10).unwrap(),
            RevocationFreshness::Unknown
        );
        let endpoint = [4u8; 32];
        revocations
            .revoke(&endpoint, 0, 0, b"operator", 95)
            .unwrap();
        assert_eq!(
            revocations.freshness(100, 10).unwrap(),
            RevocationFreshness::Fresh {
                latest_recorded_at_ms: 95
            }
        );
        assert_eq!(
            revocations.freshness(105, 10).unwrap(),
            RevocationFreshness::Fresh {
                latest_recorded_at_ms: 95
            }
        );
        assert_eq!(
            revocations.freshness(106, 5).unwrap(),
            RevocationFreshness::Stale {
                latest_recorded_at_ms: 95
            }
        );
    }

    #[test]
    fn tofu_rejects_unapproved_binding_change() {
        let store = store();
        let identity = IdentityKeyPair::generate();
        let first_static = StaticHandshakeKeyPair::generate();
        let second_static = StaticHandshakeKeyPair::generate();
        let first = binding(&identity, &first_static, 0);
        let changed = binding(&identity, &second_static, 1);
        let tofu = TofuStore::new(&store);
        tofu.observe(&first, 10).expect("first seen");
        tofu.observe(&first, 11).expect("same binding");
        assert!(matches!(
            tofu.observe(&changed, 12),
            Err(TofuError::BindingChanged { .. })
        ));
    }

    #[test]
    fn signed_binding_revocation_persists_and_invalidates() {
        let path = std::env::temp_dir().join(format!(
            "umc-signed-revocation-{}-{}.db",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let identity = IdentityKeyPair::from_seed([51u8; 32]);
        let static_key = StaticHandshakeKeyPair::from_seed([52u8; 32]);
        let binding = binding(&identity, &static_key, 4);
        let statement = SignedRevocation::sign(
            &identity,
            RevocationSubject::Binding {
                endpoint_id: binding.endpoint_id,
                binding_sequence: 4,
            },
            1,
            10,
            100,
        )
        .unwrap();
        {
            let store = SqliteStore::open(&path).unwrap();
            let revocations = RevocationStore::new(&store);
            revocations
                .accept_signed(&statement, &identity.public(), 11)
                .unwrap();
            assert!(matches!(
                revocations.check(&binding, 12),
                Err(RevocationError::Revoked { .. })
            ));
        }
        let store = SqliteStore::open(&path).unwrap();
        assert!(matches!(
            RevocationStore::new(&store).check(&binding, 12),
            Err(RevocationError::Revoked { .. })
        ));
        assert!(RevocationStore::new(&store).check(&binding, 100).is_ok());
    }

    #[test]
    fn signed_revocation_rejects_unauthorized_and_regressed_statements() {
        let store = store();
        let identity = IdentityKeyPair::from_seed([61u8; 32]);
        let other = IdentityKeyPair::from_seed([62u8; 32]);
        let endpoint = umc_handshake::identity::endpoint_id(&identity.public());
        let revocations = RevocationStore::new(&store);
        let delegation = SignedRevocation::sign(
            &identity,
            RevocationSubject::Delegation([8u8; 32]),
            1,
            10,
            0,
        )
        .unwrap();
        assert!(matches!(
            revocations.accept_signed(&delegation, &identity.public(), 11),
            Err(RevocationError::Invalid(message)) if message.contains("lacks subject authority")
        ));
        let statement =
            SignedRevocation::sign(&identity, RevocationSubject::Identity(endpoint), 3, 10, 0)
                .unwrap();
        assert!(matches!(
            revocations.accept_signed(&statement, &other.public(), 11),
            Err(RevocationError::Invalid(message)) if message.contains("invalid signed revocation")
        ));
        revocations
            .accept_signed(&statement, &identity.public(), 11)
            .unwrap();
        assert!(matches!(
            revocations.accept_signed(&statement, &identity.public(), 11),
            Err(RevocationError::Invalid(message)) if message.contains("sequence regressed")
        ));
    }

    #[test]
    fn signed_revocation_batch_is_authenticated_and_bounded() {
        let source = store();
        let identity = IdentityKeyPair::from_seed([71u8; 32]);
        let endpoint = umc_handshake::identity::endpoint_id(&identity.public());
        let statement =
            SignedRevocation::sign(&identity, RevocationSubject::Identity(endpoint), 1, 10, 0)
                .unwrap();
        let source_revocations = RevocationStore::new(&source);
        source_revocations
            .accept_signed(&statement, &identity.public(), 11)
            .unwrap();
        let batch = source_revocations.export_signed_batch().unwrap();

        let destination = store();
        let destination_revocations = RevocationStore::new(&destination);
        assert_eq!(
            destination_revocations
                .accept_signed_batch(&batch, 11)
                .unwrap(),
            1
        );
        assert!(matches!(
            destination_revocations.check(
                &binding(&identity, &StaticHandshakeKeyPair::generate(), 0),
                12
            ),
            Err(RevocationError::Revoked { .. })
        ));

        let mut tampered = batch;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            RevocationStore::new(&store()).accept_signed_batch(&tampered, 11),
            Err(RevocationError::Invalid(_))
        ));
    }
}
