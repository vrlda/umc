//! Revocation and trust-on-first-use records (identity-trust.md §13, §17).
use umc_handshake::identity::IdentityBinding;
use umc_storage::store::{Namespace, Store, StoreError};

const RECORD_VERSION: u8 = 1;

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
        let Some(record) = self
            .record(&binding.endpoint_id)
            .map_err(RevocationError::Storage)?
        else {
            return Ok(());
        };
        if record.not_after_ms != 0 && now_ms > record.not_after_ms {
            return Ok(());
        }
        if binding.sequence <= record.revoked_sequence {
            return Err(RevocationError::Revoked {
                endpoint_id: binding.endpoint_id,
                sequence: binding.sequence,
            });
        }
        Ok(())
    }
}

fn revocation_key(endpoint_id: &[u8; 32]) -> Vec<u8> {
    let mut key = b"revoke/".to_vec();
    key.extend_from_slice(endpoint_id);
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
}
