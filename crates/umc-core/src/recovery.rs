//! Bounded recovery-key authority and authenticated revocation propagation.
//!
//! Recovery keys never authenticate sessions as the root identity.  The root
//! identity signs a short-lived, sequence-numbered authority statement that
//! narrows the revocation classes the recovery key may issue.  Recovery
//! revocations carry both the root identity and recovery-key `EndpointIDs`, so a
//! receiver can verify them after restart without trusting the transport or
//! the sender's claims.
#![allow(clippy::missing_errors_doc)]

use crate::trust_statement::{RevocationClass, RevocationSubject};
use blake2::Digest;
use umc_crypto::signatures::{IdentityKeyPair, IdentityPublicKey, SIGNATURE_LEN};
use umc_handshake::identity::endpoint_id;
use umc_handshake::identity::IdentityBinding;
use umc_storage::store::{Namespace, Store, StoreError};

const AUTH_VERSION: u8 = 1;
const REVOCATION_VERSION: u8 = 1;
const BATCH_VERSION: u8 = 1;
const AUTH_PREFIX: &[u8] = b"recovery-authority/";
const REVOCATION_PREFIX: &[u8] = b"revoke-recovery/";
const MAX_BATCH_ENTRIES: usize = 64;
const MAX_BATCH_BYTES: usize = 32 * 1024;
const CLASS_IDENTITY: u8 = 1 << 0;
const CLASS_BINDING: u8 = 1 << 1;
const CLASS_DELEGATION: u8 = 1 << 2;
const CLASS_INTRODUCTION: u8 = 1 << 3;
const CLASS_RECOVERY_KEY: u8 = 1 << 4;

/// A root-signed grant authorizing one recovery key to issue bounded
/// revocations.  The recovery key is identified by its public Ed25519 key,
/// not by secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryAuthorization {
    pub version: u8,
    pub root_endpoint_id: [u8; 32],
    pub recovery_public_key: [u8; 32],
    pub allowed_classes: u8,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

/// A revocation signed by a designated recovery key under a root authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRevocation {
    pub version: u8,
    pub root_endpoint_id: [u8; 32],
    pub recovery_endpoint_id: [u8; 32],
    pub recovery_public_key: [u8; 32],
    pub subject: RevocationSubject,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    Version,
    InvalidKey,
    InvalidRoot,
    InvalidSubject,
    InvalidScope,
    InvalidValidity,
    NotYetValid,
    Expired,
    BadSignature,
    Oversized,
    Truncated,
    TrailingBytes,
    Unauthorized,
    Revoked,
    SequenceRegressed,
    Storage(StoreError),
}

impl RecoveryAuthorization {
    /// Signs an authority statement with the root identity key.
    pub fn sign(
        root: &IdentityKeyPair,
        recovery_public_key: [u8; 32],
        allowed_classes: u8,
        sequence: u64,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, RecoveryError> {
        let mut statement = Self {
            version: AUTH_VERSION,
            root_endpoint_id: endpoint_id(&root.public()),
            recovery_public_key,
            allowed_classes,
            sequence,
            issued_at_ms,
            expires_at_ms,
            signature: [0u8; SIGNATURE_LEN],
        };
        statement.validate_structure()?;
        statement.signature = root.sign(&statement.signed_message());
        Ok(statement)
    }

    /// Validates the root signature and validity interval.
    pub fn validate(
        &self,
        root_public_key: &IdentityPublicKey,
        now_ms: u64,
    ) -> Result<(), RecoveryError> {
        self.verify_signature(root_public_key)?;
        validate_window(self.issued_at_ms, self.expires_at_ms, now_ms)
    }

    /// Verifies the root signature without applying the authority's current
    /// expiry. Persisted revocations remain effective when a previously
    /// issued authority later expires.
    pub fn verify_signature(
        &self,
        root_public_key: &IdentityPublicKey,
    ) -> Result<(), RecoveryError> {
        self.validate_structure()?;
        if endpoint_id(root_public_key) != self.root_endpoint_id {
            return Err(RecoveryError::InvalidRoot);
        }
        if !root_public_key.verify(&self.signed_message(), &self.signature) {
            return Err(RecoveryError::BadSignature);
        }
        Ok(())
    }

    #[must_use]
    pub const fn allows(&self, class: RevocationClass) -> bool {
        self.allowed_classes & class_bit(class) != 0
    }

    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(90);
        out.push(self.version);
        out.extend_from_slice(&self.root_endpoint_id);
        out.extend_from_slice(&self.recovery_public_key);
        out.push(self.allowed_classes);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out
    }

    #[must_use]
    pub fn signed_message(&self) -> [u8; 32] {
        digest(b"UMP-RECOVERY-AUTH-v1", &self.signed_bytes())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RecoveryError> {
        self.validate_structure()?;
        let mut out = self.signed_bytes();
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecoveryError> {
        if bytes.len() > 256 {
            return Err(RecoveryError::Oversized);
        }
        let mut offset = 0;
        let version = read_byte(bytes, &mut offset)?;
        let root_endpoint_id = read_array(bytes, &mut offset)?;
        let recovery_public_key = read_array(bytes, &mut offset)?;
        let allowed_classes = read_byte(bytes, &mut offset)?;
        let sequence = u64::from_be_bytes(read_array(bytes, &mut offset)?);
        let issued_at_ms = u64::from_be_bytes(read_array(bytes, &mut offset)?);
        let expires_at_ms = u64::from_be_bytes(read_array(bytes, &mut offset)?);
        let signature = read_array(bytes, &mut offset)?;
        if offset != bytes.len() {
            return Err(RecoveryError::TrailingBytes);
        }
        let statement = Self {
            version,
            root_endpoint_id,
            recovery_public_key,
            allowed_classes,
            sequence,
            issued_at_ms,
            expires_at_ms,
            signature,
        };
        statement.validate_structure()?;
        Ok(statement)
    }

    fn validate_structure(&self) -> Result<(), RecoveryError> {
        if self.version != AUTH_VERSION {
            return Err(RecoveryError::Version);
        }
        if self.root_endpoint_id == [0u8; 32] || self.recovery_public_key == [0u8; 32] {
            return Err(RecoveryError::InvalidKey);
        }
        if self.allowed_classes
            & !(CLASS_IDENTITY
                | CLASS_BINDING
                | CLASS_DELEGATION
                | CLASS_INTRODUCTION
                | CLASS_RECOVERY_KEY)
            != 0
        {
            return Err(RecoveryError::InvalidScope);
        }
        if self.expires_at_ms != 0 && self.expires_at_ms <= self.issued_at_ms {
            return Err(RecoveryError::InvalidValidity);
        }
        Ok(())
    }
}

impl RecoveryRevocation {
    /// Signs a revocation with the designated recovery key.
    pub fn sign(
        recovery: &IdentityKeyPair,
        root_endpoint_id: [u8; 32],
        subject: RevocationSubject,
        sequence: u64,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, RecoveryError> {
        let mut statement = Self {
            version: REVOCATION_VERSION,
            root_endpoint_id,
            recovery_endpoint_id: endpoint_id(&recovery.public()),
            recovery_public_key: recovery.public().0,
            subject,
            sequence,
            issued_at_ms,
            expires_at_ms,
            signature: [0u8; SIGNATURE_LEN],
        };
        statement.validate_structure()?;
        statement.signature = recovery.sign(&statement.signed_message());
        Ok(statement)
    }

    pub fn validate(
        &self,
        authority: &RecoveryAuthorization,
        root_public_key: &IdentityPublicKey,
        now_ms: u64,
    ) -> Result<(), RecoveryError> {
        authority.verify_signature(root_public_key)?;
        self.validate_structure()?;
        if self.root_endpoint_id != authority.root_endpoint_id
            || self.recovery_public_key != authority.recovery_public_key
            || self.recovery_endpoint_id
                != endpoint_id(&IdentityPublicKey(self.recovery_public_key))
        {
            return Err(RecoveryError::Unauthorized);
        }
        if !authority.allows(self.subject.class()) {
            return Err(RecoveryError::Unauthorized);
        }
        if self.issued_at_ms < authority.issued_at_ms
            || (authority.expires_at_ms != 0 && self.issued_at_ms >= authority.expires_at_ms)
        {
            return Err(RecoveryError::Unauthorized);
        }
        if !IdentityPublicKey(self.recovery_public_key)
            .verify(&self.signed_message(), &self.signature)
        {
            return Err(RecoveryError::BadSignature);
        }
        validate_window(self.issued_at_ms, self.expires_at_ms, now_ms)
    }

    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let (tag, subject_bytes) = self.subject.tag_and_bytes();
        let mut out = Vec::with_capacity(130);
        out.push(self.version);
        out.extend_from_slice(&self.root_endpoint_id);
        out.extend_from_slice(&self.recovery_endpoint_id);
        out.extend_from_slice(&self.recovery_public_key);
        out.push(tag);
        out.extend_from_slice(&subject_bytes);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out
    }

    #[must_use]
    pub fn signed_message(&self) -> [u8; 32] {
        digest(b"UMP-RECOVERY-REVOKE-v1", &self.signed_bytes())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RecoveryError> {
        self.validate_structure()?;
        let mut out = self.signed_bytes();
        out.extend_from_slice(&self.signature);
        if out.len() > 256 {
            return Err(RecoveryError::Oversized);
        }
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecoveryError> {
        if bytes.len() > 256 {
            return Err(RecoveryError::Oversized);
        }
        let mut offset = 0;
        let version = read_byte(bytes, &mut offset)?;
        let root_endpoint_id = read_array(bytes, &mut offset)?;
        let recovery_endpoint_id = read_array(bytes, &mut offset)?;
        let recovery_public_key = read_array(bytes, &mut offset)?;
        let tag = read_byte(bytes, &mut offset)?;
        let subject_len = if tag == 1 { 40 } else { 32 };
        let subject_bytes = read_slice(bytes, &mut offset, subject_len)?;
        let subject = RevocationSubject::from_parts(tag, subject_bytes)
            .map_err(|_| RecoveryError::InvalidSubject)?;
        let sequence = u64::from_be_bytes(read_array(bytes, &mut offset)?);
        let issued_at_ms = u64::from_be_bytes(read_array(bytes, &mut offset)?);
        let expires_at_ms = u64::from_be_bytes(read_array(bytes, &mut offset)?);
        let signature = read_array(bytes, &mut offset)?;
        if offset != bytes.len() {
            return Err(RecoveryError::TrailingBytes);
        }
        let statement = Self {
            version,
            root_endpoint_id,
            recovery_endpoint_id,
            recovery_public_key,
            subject,
            sequence,
            issued_at_ms,
            expires_at_ms,
            signature,
        };
        statement.validate_structure()?;
        Ok(statement)
    }

    fn validate_structure(&self) -> Result<(), RecoveryError> {
        if self.version != REVOCATION_VERSION {
            return Err(RecoveryError::Version);
        }
        if self.root_endpoint_id == [0u8; 32]
            || self.recovery_endpoint_id == [0u8; 32]
            || self.recovery_public_key == [0u8; 32]
        {
            return Err(RecoveryError::InvalidKey);
        }
        let (_, subject_bytes) = self.subject.tag_and_bytes();
        if subject_bytes.len() < 32 || subject_bytes[..32] == [0u8; 32] {
            return Err(RecoveryError::InvalidSubject);
        }
        if self.expires_at_ms != 0 && self.expires_at_ms <= self.issued_at_ms {
            return Err(RecoveryError::InvalidValidity);
        }
        Ok(())
    }
}

/// Persistent recovery authority and revocation records.  Every read path
/// re-verifies signatures, so a restored or tampered database cannot silently
/// widen authority.
pub struct RecoveryStore<'a> {
    store: &'a dyn Store,
}

impl std::fmt::Debug for RecoveryStore<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryStore")
            .finish_non_exhaustive()
    }
}

impl<'a> RecoveryStore<'a> {
    #[must_use]
    pub const fn new(store: &'a dyn Store) -> Self {
        Self { store }
    }

    /// Persists a root-signed authority, rejecting sequence rollback.
    pub fn provision(
        &self,
        authority: &RecoveryAuthorization,
        root_public_key: &IdentityPublicKey,
        now_ms: u64,
    ) -> Result<(), RecoveryError> {
        authority.validate(root_public_key, now_ms)?;
        let key = authority_key(&authority.root_endpoint_id, &authority.recovery_public_key);
        let encoded_authority = authority.to_bytes()?;
        if let Some(existing) = self
            .store
            .get(Namespace::Trust, &key)
            .map_err(RecoveryError::Storage)?
        {
            let existing = decode_authority_record(&existing)?;
            if existing.sequence >= authority.sequence {
                if existing == *authority {
                    return Ok(());
                }
                return Err(RecoveryError::SequenceRegressed);
            }
        }
        let mut value = root_public_key.0.to_vec();
        value.extend_from_slice(&encoded_authority);
        self.store
            .put(Namespace::Trust, &key, &value)
            .map_err(RecoveryError::Storage)
    }

    /// Persists one recovery revocation after checking the authority and
    /// recovery signature.
    pub fn accept_revocation(
        &self,
        statement: &RecoveryRevocation,
        authority: &RecoveryAuthorization,
        root_public_key: &IdentityPublicKey,
        now_ms: u64,
    ) -> Result<(), RecoveryError> {
        statement.validate(authority, root_public_key, now_ms)?;
        let key = recovery_revocation_key(statement);
        let encoded_statement = statement.to_bytes()?;
        for entry in self
            .store
            .scan(Namespace::Trust)
            .map_err(RecoveryError::Storage)?
        {
            if !entry.key.starts_with(REVOCATION_PREFIX) {
                continue;
            }
            let existing = RecoveryRevocation::from_bytes(
                entry.value.get(32..).ok_or(RecoveryError::Truncated)?,
            )?;
            if same_subject(&existing, statement) && existing.sequence >= statement.sequence {
                if existing == *statement {
                    return Ok(());
                }
                return Err(RecoveryError::SequenceRegressed);
            }
        }
        let mut value = root_public_key.0.to_vec();
        value.extend_from_slice(&authority.to_bytes()?);
        value.extend_from_slice(&encoded_statement);
        self.store
            .put(Namespace::Trust, &key, &value)
            .map_err(RecoveryError::Storage)
    }

    /// Checks recovery-issued records against a binding.
    pub fn check(&self, binding: &IdentityBinding, now_ms: u64) -> Result<(), RecoveryError> {
        for entry in self
            .store
            .scan(Namespace::Trust)
            .map_err(RecoveryError::Storage)?
        {
            if !entry.key.starts_with(REVOCATION_PREFIX) {
                continue;
            }
            let root_public_key = IdentityPublicKey(
                entry
                    .value
                    .get(..32)
                    .ok_or(RecoveryError::Truncated)?
                    .try_into()
                    .map_err(|_| RecoveryError::Truncated)?,
            );
            let authority_len = entry
                .value
                .get(32..)
                .and_then(|bytes| bytes.get(..90 + SIGNATURE_LEN))
                .ok_or(RecoveryError::Truncated)?;
            let authority = RecoveryAuthorization::from_bytes(authority_len)?;
            let statement = RecoveryRevocation::from_bytes(
                entry
                    .value
                    .get(32 + authority_len.len()..)
                    .ok_or(RecoveryError::Truncated)?,
            )?;
            // A newer root-signed authority supersedes older recovery keys or
            // narrows their scope. Old statements remain stored for replay
            // diagnostics but must no longer affect admission.
            if let Some(current) = self
                .store
                .get(
                    Namespace::Trust,
                    &authority_key(&authority.root_endpoint_id, &authority.recovery_public_key),
                )
                .map_err(RecoveryError::Storage)?
            {
                let current = decode_authority_record(&current)?;
                if current != authority {
                    continue;
                }
            }
            statement.validate(&authority, &root_public_key, now_ms)?;
            if subject_matches_binding(&statement.subject, binding) {
                return Err(RecoveryError::Revoked);
            }
        }
        Ok(())
    }

    /// Encodes all persisted authorities and recovery revocations as a
    /// bounded exchange payload. Each element remains independently signed;
    /// the authenticated session carrying this payload is only a transport,
    /// never the authority source.
    pub fn export_batch(&self) -> Result<Vec<u8>, RecoveryError> {
        let mut entries = Vec::new();
        for entry in self
            .store
            .scan(Namespace::Trust)
            .map_err(RecoveryError::Storage)?
        {
            if !entry.key.starts_with(REVOCATION_PREFIX) {
                continue;
            }
            let root = entry.value.get(..32).ok_or(RecoveryError::Truncated)?;
            let rest = entry.value.get(32..).ok_or(RecoveryError::Truncated)?;
            let authority_len = 90 + SIGNATURE_LEN;
            let authority = rest.get(..authority_len).ok_or(RecoveryError::Truncated)?;
            let revocation = rest.get(authority_len..).ok_or(RecoveryError::Truncated)?;
            let mut item = Vec::new();
            item.extend_from_slice(root);
            push_len_bytes(&mut item, authority)?;
            push_len_bytes(&mut item, revocation)?;
            entries.push(item);
            if entries.len() == MAX_BATCH_ENTRIES {
                break;
            }
        }
        let mut out = vec![b'R', b'C', BATCH_VERSION];
        out.extend_from_slice(
            &(u16::try_from(entries.len()).map_err(|_| RecoveryError::Oversized)?).to_be_bytes(),
        );
        for item in entries {
            out.extend_from_slice(&item);
            if out.len() > MAX_BATCH_BYTES {
                return Err(RecoveryError::Oversized);
            }
        }
        Ok(out)
    }

    /// Imports and verifies a bounded exchange payload. Invalid entries fail
    /// closed; a valid prefix is never partially committed.
    pub fn accept_batch(&self, bytes: &[u8], now_ms: u64) -> Result<usize, RecoveryError> {
        if bytes.len() > MAX_BATCH_BYTES || bytes.get(..3) != Some(b"RC\x01") {
            return Err(RecoveryError::Oversized);
        }
        let count = u16::from_be_bytes(
            bytes
                .get(3..5)
                .ok_or(RecoveryError::Truncated)?
                .try_into()
                .map_err(|_| RecoveryError::Truncated)?,
        ) as usize;
        if count > MAX_BATCH_ENTRIES {
            return Err(RecoveryError::Oversized);
        }
        let mut offset = 5;
        let mut decoded = Vec::with_capacity(count);
        for _ in 0..count {
            let root = IdentityPublicKey(read_array(bytes, &mut offset)?);
            let authority = RecoveryAuthorization::from_bytes(read_len_bytes(bytes, &mut offset)?)?;
            let statement = RecoveryRevocation::from_bytes(read_len_bytes(bytes, &mut offset)?)?;
            decoded.push((root, authority, statement));
        }
        if offset != bytes.len() {
            return Err(RecoveryError::TrailingBytes);
        }
        for (root, authority, statement) in &decoded {
            authority.verify_signature(root)?;
            statement.validate(authority, root, now_ms)?;
            if self
                .store
                .scan(Namespace::Trust)
                .map_err(RecoveryError::Storage)?
                .into_iter()
                .filter(|entry| entry.key.starts_with(REVOCATION_PREFIX))
                .filter_map(|entry| {
                    entry
                        .value
                        .get(32 + (90 + SIGNATURE_LEN)..)
                        .and_then(|bytes| RecoveryRevocation::from_bytes(bytes).ok())
                })
                .any(|existing| {
                    same_subject(&existing, statement)
                        && existing.sequence >= statement.sequence
                        && existing.signed_bytes() != statement.signed_bytes()
                })
            {
                return Err(RecoveryError::SequenceRegressed);
            }
        }
        for (root, authority, statement) in &decoded {
            self.accept_revocation(statement, authority, root, now_ms)?;
        }
        Ok(decoded.len())
    }
}

fn subject_matches_binding(subject: &RevocationSubject, binding: &IdentityBinding) -> bool {
    match subject {
        RevocationSubject::Identity(endpoint) => endpoint == &binding.endpoint_id,
        RevocationSubject::Binding {
            endpoint_id,
            binding_sequence,
        } => endpoint_id == &binding.endpoint_id && binding.sequence <= *binding_sequence,
        RevocationSubject::Delegation(_)
        | RevocationSubject::Introduction(_)
        | RevocationSubject::RecoveryKey(_) => false,
    }
}

fn same_subject(left: &RecoveryRevocation, right: &RecoveryRevocation) -> bool {
    left.root_endpoint_id == right.root_endpoint_id
        && left.recovery_endpoint_id == right.recovery_endpoint_id
        && left.subject == right.subject
}

fn authority_key(root: &[u8; 32], recovery: &[u8; 32]) -> Vec<u8> {
    let mut key = AUTH_PREFIX.to_vec();
    key.extend_from_slice(root);
    key.extend_from_slice(recovery);
    key
}

fn recovery_revocation_key(statement: &RecoveryRevocation) -> Vec<u8> {
    let mut key = REVOCATION_PREFIX.to_vec();
    key.extend_from_slice(&statement.root_endpoint_id);
    key.extend_from_slice(&statement.recovery_endpoint_id);
    key.extend_from_slice(&statement.signed_bytes());
    key
}

fn decode_authority_record(value: &[u8]) -> Result<RecoveryAuthorization, RecoveryError> {
    RecoveryAuthorization::from_bytes(value.get(32..).ok_or(RecoveryError::Truncated)?)
}

const fn class_bit(class: RevocationClass) -> u8 {
    match class {
        RevocationClass::Identity => CLASS_IDENTITY,
        RevocationClass::Binding => CLASS_BINDING,
        RevocationClass::Delegation => CLASS_DELEGATION,
        RevocationClass::Introduction => CLASS_INTRODUCTION,
        RevocationClass::RecoveryKey => CLASS_RECOVERY_KEY,
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake2::Blake2s256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn validate_window(
    issued_at_ms: u64,
    expires_at_ms: u64,
    now_ms: u64,
) -> Result<(), RecoveryError> {
    if now_ms < issued_at_ms {
        return Err(RecoveryError::NotYetValid);
    }
    if expires_at_ms != 0 && now_ms >= expires_at_ms {
        return Err(RecoveryError::Expired);
    }
    Ok(())
}

fn read_byte(bytes: &[u8], offset: &mut usize) -> Result<u8, RecoveryError> {
    let byte = *bytes.get(*offset).ok_or(RecoveryError::Truncated)?;
    *offset += 1;
    Ok(byte)
}

fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], RecoveryError> {
    let value = bytes
        .get(*offset..(*offset).saturating_add(N))
        .ok_or(RecoveryError::Truncated)?
        .try_into()
        .map_err(|_| RecoveryError::Truncated)?;
    *offset += N;
    Ok(value)
}

fn read_slice<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], RecoveryError> {
    let value = bytes
        .get(*offset..(*offset).saturating_add(len))
        .ok_or(RecoveryError::Truncated)?;
    *offset += len;
    Ok(value)
}

fn push_len_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RecoveryError> {
    let len = u16::try_from(bytes.len()).map_err(|_| RecoveryError::Oversized)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn read_len_bytes<'a>(bytes: &'a [u8], offset: &mut usize) -> Result<&'a [u8], RecoveryError> {
    let len = u16::from_be_bytes(read_array(bytes, offset)?) as usize;
    read_slice(bytes, offset, len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_crypto::signatures::StaticHandshakeKeyPair;
    use umc_handshake::identity::IdentityBinding;
    use umc_storage::sqlite::SqliteStore;

    fn store() -> SqliteStore {
        let path = std::env::temp_dir().join(format!(
            "umc-recovery-{}-{}.db",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_file(&path);
        SqliteStore::open(&path).expect("sqlite")
    }

    fn binding(root: &IdentityKeyPair) -> IdentityBinding {
        let static_key = StaticHandshakeKeyPair::from_seed([7u8; 32]);
        IdentityBinding::sign(root, &static_key.public(), 1, 0, 2, [0u8; 32])
    }

    #[test]
    fn recovery_authority_revokes_binding_and_survives_restart() {
        let source_store = store();
        let root = IdentityKeyPair::from_seed([1u8; 32]);
        let recovery = IdentityKeyPair::from_seed([2u8; 32]);
        let auth = RecoveryAuthorization::sign(
            &root,
            recovery.public().0,
            CLASS_IDENTITY | CLASS_BINDING,
            1,
            1,
            10_000,
        )
        .expect("authority");
        let revocation = RecoveryRevocation::sign(
            &recovery,
            endpoint_id(&root.public()),
            RevocationSubject::Identity(endpoint_id(&root.public())),
            1,
            2,
            10_000,
        )
        .expect("revocation");
        let recoveries = RecoveryStore::new(&source_store);
        recoveries
            .provision(&auth, &root.public(), 2)
            .expect("persist authority");
        recoveries
            .accept_revocation(&revocation, &auth, &root.public(), 2)
            .expect("persist revocation");
        assert_eq!(
            recoveries.check(&binding(&root), 3),
            Err(RecoveryError::Revoked)
        );
        let batch = recoveries.export_batch().expect("batch");
        let other = store();
        let imported = RecoveryStore::new(&other);
        assert_eq!(imported.accept_batch(&batch, 3).expect("import"), 1);
        assert_eq!(
            imported.check(&binding(&root), 3),
            Err(RecoveryError::Revoked)
        );
    }

    #[test]
    fn recovery_rejects_scope_expansion_and_sequence_rollback() {
        let source_store = store();
        let root = IdentityKeyPair::from_seed([3u8; 32]);
        let recovery = IdentityKeyPair::from_seed([4u8; 32]);
        let auth =
            RecoveryAuthorization::sign(&root, recovery.public().0, CLASS_BINDING, 2, 1, 100)
                .expect("authority");
        let recoveries = RecoveryStore::new(&source_store);
        recoveries
            .provision(&auth, &root.public(), 2)
            .expect("persist");
        let old = RecoveryAuthorization::sign(&root, recovery.public().0, CLASS_BINDING, 1, 1, 100)
            .expect("old authority");
        assert_eq!(
            recoveries.provision(&old, &root.public(), 2),
            Err(RecoveryError::SequenceRegressed)
        );
        let identity_revocation = RecoveryRevocation::sign(
            &recovery,
            endpoint_id(&root.public()),
            RevocationSubject::Identity(endpoint_id(&root.public())),
            1,
            2,
            100,
        )
        .expect("revocation");
        assert_eq!(
            recoveries.accept_revocation(&identity_revocation, &auth, &root.public(), 2),
            Err(RecoveryError::Unauthorized)
        );
    }
}
