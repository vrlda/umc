//! Canonical signed trust statements (identity-trust.md §§12, 18).
//!
//! The wire format is deliberately fixed and bounded.  An introduction does
//! not carry an issuer public key: the key is supplied by the authenticated
//! binding that delivered the statement.  Persistence stores that key beside
//! the statement so a restart can re-verify the signature before using it.

use umc_crypto::signatures::{IdentityKeyPair, IdentityPublicKey};
use umc_handshake::identity::endpoint_id;

pub const INTRODUCTION_STATEMENT_VERSION: u8 = 1;
pub const MAX_INTRODUCTION_SCOPE: usize = 256;
pub const MAX_INTRODUCTION_STATEMENT: usize = 512;
pub const INTRODUCTION_RESTRICTION_MASK: u8 = 0b0000_0111;
pub const REVOCATION_STATEMENT_VERSION: u8 = 1;
pub const MAX_REVOCATION_STATEMENT: usize = 256;
pub const DELEGATION_STATEMENT_VERSION: u8 = 1;
pub const MAX_DELEGATION_CAPABILITIES: usize = 32;
pub const MAX_DELEGATION_CAPABILITY_LEN: usize = 64;
pub const MAX_DELEGATION_CAPABILITY_BYTES: usize = 1_024;
pub const MAX_DELEGATION_CHAIN_LENGTH: usize = 4;
pub const MAX_DELEGATION_CHAIN_BYTES: usize = 8 * 1_024;
const SIGNATURE_LEN: usize = 64;

/// Evidence bound to an introduction's subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectEvidence {
    /// Digest of a canonical identity binding.
    BindingDigest([u8; 32]),
    /// The subject's static X25519 handshake public key.
    StaticHandshakeKey([u8; 32]),
}

impl SubjectEvidence {
    const BINDING_DIGEST_TAG: u8 = 0;
    const STATIC_HANDSHAKE_KEY_TAG: u8 = 1;

    fn tag_and_bytes(&self) -> (u8, &[u8; 32]) {
        match self {
            Self::BindingDigest(value) => (Self::BINDING_DIGEST_TAG, value),
            Self::StaticHandshakeKey(value) => (Self::STATIC_HANDSHAKE_KEY_TAG, value),
        }
    }

    fn from_parts(tag: u8, value: [u8; 32]) -> Result<Self, IntroductionStatementError> {
        if value == [0u8; 32] {
            return Err(IntroductionStatementError::InvalidEvidence);
        }
        match tag {
            Self::BINDING_DIGEST_TAG => Ok(Self::BindingDigest(value)),
            Self::STATIC_HANDSHAKE_KEY_TAG => Ok(Self::StaticHandshakeKey(value)),
            _ => Err(IntroductionStatementError::InvalidEvidence),
        }
    }
}

/// A signed, scoped, expiring introduction statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIntroduction {
    pub version: u8,
    pub introducer_endpoint_id: [u8; 32],
    pub subject_endpoint_id: [u8; 32],
    pub subject_evidence: SubjectEvidence,
    pub allowed_use: String,
    pub expires_at_ms: u64,
    /// Bounded confidence score.  The value is scoped metadata, not a trust
    /// promotion; callers must still apply local policy.
    pub delegated_confidence: u8,
    /// Profile-defined sharing restrictions.  Unknown bits are rejected.
    pub sharing_restrictions: u8,
    pub sequence: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

/// Validation or canonical-encoding failure for a signed introduction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntroductionStatementError {
    Version,
    EndpointIdMismatch,
    SameEndpoint,
    BadSignature,
    Expired,
    InvalidScope,
    InvalidEvidence,
    InvalidConfidence,
    InvalidRestrictions,
    Oversized,
    Truncated,
    TrailingBytes,
}

/// Revocation subject classes from identity-trust.md §13.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationClass {
    Identity,
    Binding,
    Delegation,
    Introduction,
    RecoveryKey,
}

/// The material invalidated by a signed revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationSubject {
    Identity([u8; 32]),
    Binding {
        endpoint_id: [u8; 32],
        binding_sequence: u64,
    },
    Delegation([u8; 32]),
    Introduction([u8; 32]),
    RecoveryKey([u8; 32]),
}

impl RevocationSubject {
    const IDENTITY_TAG: u8 = 0;
    const BINDING_TAG: u8 = 1;
    const DELEGATION_TAG: u8 = 2;
    const INTRODUCTION_TAG: u8 = 3;
    const RECOVERY_KEY_TAG: u8 = 4;

    #[must_use]
    pub const fn class(&self) -> RevocationClass {
        match self {
            Self::Identity(_) => RevocationClass::Identity,
            Self::Binding { .. } => RevocationClass::Binding,
            Self::Delegation(_) => RevocationClass::Delegation,
            Self::Introduction(_) => RevocationClass::Introduction,
            Self::RecoveryKey(_) => RevocationClass::RecoveryKey,
        }
    }

    pub(crate) fn tag_and_bytes(&self) -> (u8, Vec<u8>) {
        match self {
            Self::Identity(endpoint_id)
            | Self::Delegation(endpoint_id)
            | Self::Introduction(endpoint_id)
            | Self::RecoveryKey(endpoint_id) => {
                let tag = match self {
                    Self::Identity(_) => Self::IDENTITY_TAG,
                    Self::Delegation(_) => Self::DELEGATION_TAG,
                    Self::Introduction(_) => Self::INTRODUCTION_TAG,
                    Self::RecoveryKey(_) => Self::RECOVERY_KEY_TAG,
                    Self::Binding { .. } => unreachable!(),
                };
                (tag, endpoint_id.to_vec())
            }
            Self::Binding {
                endpoint_id,
                binding_sequence,
            } => {
                let mut bytes = endpoint_id.to_vec();
                bytes.extend_from_slice(&binding_sequence.to_be_bytes());
                (Self::BINDING_TAG, bytes)
            }
        }
    }

    pub(crate) fn from_parts(tag: u8, bytes: &[u8]) -> Result<Self, RevocationStatementError> {
        if bytes.len() < 32 || bytes[..32] == [0u8; 32] {
            return Err(RevocationStatementError::InvalidSubject);
        }
        let endpoint_id: [u8; 32] = bytes[..32]
            .try_into()
            .map_err(|_| RevocationStatementError::InvalidSubject)?;
        match tag {
            Self::IDENTITY_TAG if bytes.len() == 32 => Ok(Self::Identity(endpoint_id)),
            Self::BINDING_TAG if bytes.len() == 40 => Ok(Self::Binding {
                endpoint_id,
                binding_sequence: u64::from_be_bytes(
                    bytes[32..]
                        .try_into()
                        .map_err(|_| RevocationStatementError::InvalidSubject)?,
                ),
            }),
            Self::DELEGATION_TAG if bytes.len() == 32 => Ok(Self::Delegation(endpoint_id)),
            Self::INTRODUCTION_TAG if bytes.len() == 32 => Ok(Self::Introduction(endpoint_id)),
            Self::RECOVERY_KEY_TAG if bytes.len() == 32 => Ok(Self::RecoveryKey(endpoint_id)),
            _ => Err(RevocationStatementError::InvalidSubject),
        }
    }
}

/// A signed revocation statement with explicit subject class and validity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRevocation {
    pub version: u8,
    pub issuer_endpoint_id: [u8; 32],
    pub subject: RevocationSubject,
    pub sequence: u64,
    pub issued_at_ms: u64,
    /// `0` means no expiry.
    pub expires_at_ms: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

/// Validation or canonical-encoding failure for a signed revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatementError {
    Version,
    EndpointIdMismatch,
    InvalidSubject,
    InvalidValidity,
    NotYetValid,
    Expired,
    BadSignature,
    Oversized,
    Truncated,
    TrailingBytes,
    UnauthorizedSubject,
}

impl SignedRevocation {
    /// Signs a revocation statement with the issuer identity key.
    ///
    /// # Errors
    ///
    /// Returns [`RevocationStatementError`] for malformed subject or validity
    /// fields.
    pub fn sign(
        identity: &IdentityKeyPair,
        subject: RevocationSubject,
        sequence: u64,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, RevocationStatementError> {
        let mut statement = Self {
            version: REVOCATION_STATEMENT_VERSION,
            issuer_endpoint_id: endpoint_id(&identity.public()),
            subject,
            sequence,
            issued_at_ms,
            expires_at_ms,
            signature: [0u8; SIGNATURE_LEN],
        };
        statement.validate_structure()?;
        statement.signature = identity.sign(&statement.signed_message());
        Ok(statement)
    }

    /// Returns the subject class carried by the statement.
    #[must_use]
    pub const fn class(&self) -> RevocationClass {
        self.subject.class()
    }

    /// Whether the statement is self-authorized without a recovery or local
    /// policy grant.  The local store currently accepts only these classes;
    /// delegation, introduction, and recovery-key authority remain explicit
    /// policy/distribution work.
    #[must_use]
    pub fn is_self_authorized(&self) -> bool {
        match &self.subject {
            RevocationSubject::Identity(endpoint_id)
            | RevocationSubject::Binding { endpoint_id, .. } => {
                *endpoint_id == self.issuer_endpoint_id
            }
            RevocationSubject::Delegation(_)
            | RevocationSubject::Introduction(_)
            | RevocationSubject::RecoveryKey(_) => false,
        }
    }

    /// Canonical bytes covered by the signature (signature omitted).
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let (subject_tag, subject_bytes) = self.subject.tag_and_bytes();
        let mut out = Vec::with_capacity(90);
        out.push(self.version);
        out.extend_from_slice(&self.issuer_endpoint_id);
        out.push(subject_tag);
        out.extend_from_slice(&subject_bytes);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out
    }

    /// Domain-separated digest signed by the issuer identity key.
    #[must_use]
    pub fn signed_message(&self) -> [u8; 32] {
        use blake2::Digest;
        let mut hasher = blake2::Blake2s256::new();
        hasher.update(b"UMP-REVOCATION-v1");
        hasher.update(self.signed_bytes());
        hasher.finalize().into()
    }

    /// Verifies structure, issuer `EndpointID` binding, and signature.
    ///
    /// # Errors
    ///
    /// Returns [`RevocationStatementError`] when the statement is malformed
    /// or the supplied key cannot verify it.
    pub fn verify_signature(
        &self,
        issuer_public_key: &IdentityPublicKey,
    ) -> Result<(), RevocationStatementError> {
        self.validate_structure()?;
        if endpoint_id(issuer_public_key) != self.issuer_endpoint_id {
            return Err(RevocationStatementError::EndpointIdMismatch);
        }
        if !issuer_public_key.verify(&self.signed_message(), &self.signature) {
            return Err(RevocationStatementError::BadSignature);
        }
        Ok(())
    }

    /// Verifies the statement and validity interval at `now_ms`.
    ///
    /// # Errors
    ///
    /// Returns [`RevocationStatementError::NotYetValid`] or
    /// [`RevocationStatementError::Expired`] when the statement is outside
    /// its validity interval.
    pub fn validate(
        &self,
        issuer_public_key: &IdentityPublicKey,
        now_ms: u64,
    ) -> Result<(), RevocationStatementError> {
        self.verify_signature(issuer_public_key)?;
        if now_ms < self.issued_at_ms {
            return Err(RevocationStatementError::NotYetValid);
        }
        if self.expires_at_ms != 0 && now_ms >= self.expires_at_ms {
            return Err(RevocationStatementError::Expired);
        }
        Ok(())
    }

    /// Encodes the complete canonical statement, including its signature.
    ///
    /// # Errors
    ///
    /// Returns [`RevocationStatementError`] for malformed or oversized data.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RevocationStatementError> {
        self.validate_structure()?;
        let mut out = self.signed_bytes();
        out.extend_from_slice(&self.signature);
        if out.len() > MAX_REVOCATION_STATEMENT {
            return Err(RevocationStatementError::Oversized);
        }
        Ok(out)
    }

    /// Decodes one complete canonical statement.
    ///
    /// # Errors
    ///
    /// Returns [`RevocationStatementError`] for malformed, truncated, or
    /// trailing data.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RevocationStatementError> {
        if bytes.len() > MAX_REVOCATION_STATEMENT {
            return Err(RevocationStatementError::Oversized);
        }
        let mut offset = 0;
        let version =
            read_byte(bytes, &mut offset).map_err(|_| RevocationStatementError::Truncated)?;
        let issuer_endpoint_id =
            read_array(bytes, &mut offset).map_err(|_| RevocationStatementError::Truncated)?;
        let subject_tag =
            read_byte(bytes, &mut offset).map_err(|_| RevocationStatementError::Truncated)?;
        let subject_len = if subject_tag == RevocationSubject::BINDING_TAG {
            40
        } else {
            32
        };
        let subject_bytes = read_slice(bytes, &mut offset, subject_len)
            .map_err(|_| RevocationStatementError::Truncated)?;
        let subject = RevocationSubject::from_parts(subject_tag, subject_bytes)?;
        let sequence = u64::from_be_bytes(
            read_array(bytes, &mut offset).map_err(|_| RevocationStatementError::Truncated)?,
        );
        let issued_at_ms = u64::from_be_bytes(
            read_array(bytes, &mut offset).map_err(|_| RevocationStatementError::Truncated)?,
        );
        let expires_at_ms = u64::from_be_bytes(
            read_array(bytes, &mut offset).map_err(|_| RevocationStatementError::Truncated)?,
        );
        let signature =
            read_array(bytes, &mut offset).map_err(|_| RevocationStatementError::Truncated)?;
        if offset != bytes.len() {
            return Err(RevocationStatementError::TrailingBytes);
        }
        let statement = Self {
            version,
            issuer_endpoint_id,
            subject,
            sequence,
            issued_at_ms,
            expires_at_ms,
            signature,
        };
        statement.validate_structure()?;
        Ok(statement)
    }

    fn validate_structure(&self) -> Result<(), RevocationStatementError> {
        if self.version != REVOCATION_STATEMENT_VERSION {
            return Err(RevocationStatementError::Version);
        }
        if self.issuer_endpoint_id == [0u8; 32] {
            return Err(RevocationStatementError::EndpointIdMismatch);
        }
        let (_, subject_bytes) = self.subject.tag_and_bytes();
        if subject_bytes.len() < 32 || subject_bytes[..32] == [0u8; 32] {
            return Err(RevocationStatementError::InvalidSubject);
        }
        if self.expires_at_ms != 0 && self.expires_at_ms <= self.issued_at_ms {
            return Err(RevocationStatementError::InvalidValidity);
        }
        if self.signed_bytes().len() + SIGNATURE_LEN > MAX_REVOCATION_STATEMENT {
            return Err(RevocationStatementError::Oversized);
        }
        Ok(())
    }
}

/// A signed certificate authorizing one additional Ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDelegation {
    pub version: u8,
    pub issuer_endpoint_id: [u8; 32],
    pub delegated_public_key: [u8; 32],
    pub allowed_capabilities: Vec<Vec<u8>>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub sequence: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

/// Validation failure for one delegation certificate or chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationError {
    Version,
    EndpointIdMismatch,
    InvalidKey,
    InvalidCapabilities,
    NonCanonicalCapabilities,
    InvalidValidity,
    NotYetValid,
    Expired,
    BadSignature,
    Oversized,
    Truncated,
    TrailingBytes,
    EmptyChain,
    ChainTooLong,
    ChainTooLarge,
    Cycle,
    CapabilityExpansion,
    OutlivesIssuer,
}

impl SignedDelegation {
    /// Creates a canonical signed delegation certificate.
    ///
    /// Capability input is sorted and duplicate entries are removed before
    /// signing, so every equivalent grant has one canonical representation.
    ///
    /// # Errors
    ///
    /// Returns [`DelegationError`] when a key, capability, or validity bound
    /// is malformed.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        identity: &IdentityKeyPair,
        delegated_public_key: [u8; 32],
        mut allowed_capabilities: Vec<Vec<u8>>,
        created_at_ms: u64,
        expires_at_ms: u64,
        sequence: u64,
    ) -> Result<Self, DelegationError> {
        allowed_capabilities.sort();
        allowed_capabilities.dedup();
        let mut certificate = Self {
            version: DELEGATION_STATEMENT_VERSION,
            issuer_endpoint_id: endpoint_id(&identity.public()),
            delegated_public_key,
            allowed_capabilities,
            created_at_ms,
            expires_at_ms,
            sequence,
            signature: [0u8; SIGNATURE_LEN],
        };
        certificate.validate_structure()?;
        certificate.signature = identity.sign(&certificate.signed_message());
        Ok(certificate)
    }

    /// Canonical bytes covered by the signature (signature omitted).
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.allowed_capabilities.len() * 8);
        out.push(self.version);
        out.extend_from_slice(&self.issuer_endpoint_id);
        out.extend_from_slice(&self.delegated_public_key);
        out.push(u8::try_from(self.allowed_capabilities.len()).unwrap_or(u8::MAX));
        for capability in &self.allowed_capabilities {
            out.extend_from_slice(
                &u16::try_from(capability.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
            out.extend_from_slice(capability);
        }
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out
    }

    /// Domain-separated digest signed by the issuer identity key.
    #[must_use]
    pub fn signed_message(&self) -> [u8; 32] {
        use blake2::Digest;
        let mut hasher = blake2::Blake2s256::new();
        hasher.update(b"UMP-DELEGATION-v1");
        hasher.update(self.signed_bytes());
        hasher.finalize().into()
    }

    /// Verifies structure, issuer `EndpointID` binding, and signature.
    ///
    /// # Errors
    ///
    /// Returns [`DelegationError`] when the certificate is malformed or the
    /// supplied issuer key cannot verify it.
    pub fn verify_signature(
        &self,
        issuer_public_key: &IdentityPublicKey,
    ) -> Result<(), DelegationError> {
        self.validate_structure()?;
        if endpoint_id(issuer_public_key) != self.issuer_endpoint_id {
            return Err(DelegationError::EndpointIdMismatch);
        }
        if !issuer_public_key.verify(&self.signed_message(), &self.signature) {
            return Err(DelegationError::BadSignature);
        }
        Ok(())
    }

    /// Verifies this certificate and its validity interval.
    ///
    /// # Errors
    ///
    /// Returns [`DelegationError::NotYetValid`] or
    /// [`DelegationError::Expired`] when the interval is not active.
    pub fn validate(
        &self,
        issuer_public_key: &IdentityPublicKey,
        now_ms: u64,
    ) -> Result<(), DelegationError> {
        self.verify_signature(issuer_public_key)?;
        if now_ms < self.created_at_ms {
            return Err(DelegationError::NotYetValid);
        }
        if now_ms >= self.expires_at_ms {
            return Err(DelegationError::Expired);
        }
        Ok(())
    }

    /// Encodes the complete canonical certificate, including the signature.
    ///
    /// # Errors
    ///
    /// Returns [`DelegationError`] for malformed or oversized data.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DelegationError> {
        self.validate_structure()?;
        let mut out = self.signed_bytes();
        out.extend_from_slice(&self.signature);
        if out.len() > MAX_DELEGATION_CHAIN_BYTES {
            return Err(DelegationError::Oversized);
        }
        Ok(out)
    }

    /// Decodes one complete canonical certificate.
    ///
    /// # Errors
    ///
    /// Returns [`DelegationError`] for malformed, truncated, or trailing data.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DelegationError> {
        if bytes.len() > MAX_DELEGATION_CHAIN_BYTES {
            return Err(DelegationError::Oversized);
        }
        let mut offset = 0;
        let version = read_byte(bytes, &mut offset).map_err(|_| DelegationError::Truncated)?;
        let issuer_endpoint_id =
            read_array(bytes, &mut offset).map_err(|_| DelegationError::Truncated)?;
        let delegated_public_key =
            read_array(bytes, &mut offset).map_err(|_| DelegationError::Truncated)?;
        let capability_count =
            usize::from(read_byte(bytes, &mut offset).map_err(|_| DelegationError::Truncated)?);
        if capability_count > MAX_DELEGATION_CAPABILITIES {
            return Err(DelegationError::InvalidCapabilities);
        }
        let mut allowed_capabilities = Vec::with_capacity(capability_count);
        for _ in 0..capability_count {
            let length = usize::from(u16::from_be_bytes(
                read_array(bytes, &mut offset).map_err(|_| DelegationError::Truncated)?,
            ));
            let capability = read_slice(bytes, &mut offset, length)
                .map_err(|_| DelegationError::Truncated)?
                .to_vec();
            allowed_capabilities.push(capability);
        }
        let created_at_ms = u64::from_be_bytes(
            read_array(bytes, &mut offset).map_err(|_| DelegationError::Truncated)?,
        );
        let expires_at_ms = u64::from_be_bytes(
            read_array(bytes, &mut offset).map_err(|_| DelegationError::Truncated)?,
        );
        let sequence = u64::from_be_bytes(
            read_array(bytes, &mut offset).map_err(|_| DelegationError::Truncated)?,
        );
        let signature = read_array(bytes, &mut offset).map_err(|_| DelegationError::Truncated)?;
        if offset != bytes.len() {
            return Err(DelegationError::TrailingBytes);
        }
        let certificate = Self {
            version,
            issuer_endpoint_id,
            delegated_public_key,
            allowed_capabilities,
            created_at_ms,
            expires_at_ms,
            sequence,
            signature,
        };
        certificate.validate_structure()?;
        Ok(certificate)
    }

    fn validate_structure(&self) -> Result<(), DelegationError> {
        if self.version != DELEGATION_STATEMENT_VERSION {
            return Err(DelegationError::Version);
        }
        if self.issuer_endpoint_id == [0u8; 32] || self.delegated_public_key == [0u8; 32] {
            return Err(DelegationError::InvalidKey);
        }
        validate_capabilities(&self.allowed_capabilities)?;
        if self.expires_at_ms <= self.created_at_ms {
            return Err(DelegationError::InvalidValidity);
        }
        if self.signed_bytes().len() + SIGNATURE_LEN > MAX_DELEGATION_CHAIN_BYTES {
            return Err(DelegationError::Oversized);
        }
        Ok(())
    }
}

/// The final authority produced by a verified delegation chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedAuthority {
    pub public_key: IdentityPublicKey,
    pub capabilities: Vec<Vec<u8>>,
    pub depth: usize,
}

/// Verifies a bounded chain of signed delegation certificates.
#[derive(Debug, Clone, Copy, Default)]
pub struct DelegationChain;

impl DelegationChain {
    /// Verifies every link, capability restriction, cycle, and validity bound.
    ///
    /// `root_capabilities` is the authority held by the root identity.  Each
    /// certificate can only narrow that set, and a child certificate cannot
    /// outlive its parent link.
    ///
    /// # Errors
    ///
    /// Returns [`DelegationError`] when the chain exceeds profile bounds or a
    /// link fails signature, authority, cycle, or validity checks.
    pub fn verify(
        root_public_key: &IdentityPublicKey,
        root_capabilities: &[Vec<u8>],
        certificates: &[SignedDelegation],
        now_ms: u64,
    ) -> Result<DelegatedAuthority, DelegationError> {
        if certificates.is_empty() {
            return Err(DelegationError::EmptyChain);
        }
        if certificates.len() > MAX_DELEGATION_CHAIN_LENGTH {
            return Err(DelegationError::ChainTooLong);
        }
        let root_capabilities = canonical_capabilities(root_capabilities.to_vec())?;
        let total_bytes = certificates.iter().try_fold(0usize, |total, certificate| {
            certificate
                .to_bytes()
                .map(|encoded| total.saturating_add(encoded.len()))
        })?;
        if total_bytes > MAX_DELEGATION_CHAIN_BYTES {
            return Err(DelegationError::ChainTooLarge);
        }
        let mut issuer_key = root_public_key.clone();
        let mut issuer_capabilities = root_capabilities;
        let mut issuer_expiry = u64::MAX;
        let mut seen_keys = vec![issuer_key.0];
        for (depth, certificate) in certificates.iter().enumerate() {
            certificate.validate(&issuer_key, now_ms)?;
            if certificate.expires_at_ms > issuer_expiry {
                return Err(DelegationError::OutlivesIssuer);
            }
            if !certificate
                .allowed_capabilities
                .iter()
                .all(|capability| issuer_capabilities.contains(capability))
            {
                return Err(DelegationError::CapabilityExpansion);
            }
            if seen_keys.contains(&certificate.delegated_public_key) {
                return Err(DelegationError::Cycle);
            }
            seen_keys.push(certificate.delegated_public_key);
            issuer_key = IdentityPublicKey(certificate.delegated_public_key);
            issuer_capabilities.clone_from(&certificate.allowed_capabilities);
            issuer_expiry = certificate.expires_at_ms;
            if depth + 1 == certificates.len() {
                return Ok(DelegatedAuthority {
                    public_key: issuer_key,
                    capabilities: issuer_capabilities,
                    depth: depth + 1,
                });
            }
        }
        Err(DelegationError::EmptyChain)
    }
}

fn canonical_capabilities(mut capabilities: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, DelegationError> {
    capabilities.sort();
    capabilities.dedup();
    validate_capabilities(&capabilities)?;
    Ok(capabilities)
}

fn validate_capabilities(capabilities: &[Vec<u8>]) -> Result<(), DelegationError> {
    if capabilities.len() > MAX_DELEGATION_CAPABILITIES
        || capabilities.iter().any(|capability| {
            capability.is_empty() || capability.len() > MAX_DELEGATION_CAPABILITY_LEN
        })
        || capabilities.iter().map(Vec::len).sum::<usize>() > MAX_DELEGATION_CAPABILITY_BYTES
    {
        return Err(DelegationError::InvalidCapabilities);
    }
    if capabilities.windows(2).any(|window| window[0] >= window[1]) {
        return Err(DelegationError::NonCanonicalCapabilities);
    }
    Ok(())
}

impl SignedIntroduction {
    /// Signs a canonical introduction with the introducer's identity key.
    ///
    /// # Errors
    ///
    /// Returns [`IntroductionStatementError`] when any bounded field is
    /// invalid.
    #[allow(clippy::too_many_arguments)] // canonical statement fields are explicit at the API boundary
    pub fn sign(
        identity: &IdentityKeyPair,
        subject_endpoint_id: [u8; 32],
        subject_evidence: SubjectEvidence,
        allowed_use: &str,
        expires_at_ms: u64,
        delegated_confidence: u8,
        sharing_restrictions: u8,
        sequence: u64,
    ) -> Result<Self, IntroductionStatementError> {
        let mut statement = Self {
            version: INTRODUCTION_STATEMENT_VERSION,
            introducer_endpoint_id: endpoint_id(&identity.public()),
            subject_endpoint_id,
            subject_evidence,
            allowed_use: allowed_use.to_owned(),
            expires_at_ms,
            delegated_confidence,
            sharing_restrictions,
            sequence,
            signature: [0u8; SIGNATURE_LEN],
        };
        statement.validate_structure()?;
        statement.signature = identity.sign(&statement.signed_message());
        Ok(statement)
    }

    /// Canonical bytes covered by the signature (signature omitted).
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let (evidence_tag, evidence) = self.subject_evidence.tag_and_bytes();
        let mut out = Vec::with_capacity(118 + self.allowed_use.len());
        out.push(self.version);
        out.extend_from_slice(&self.introducer_endpoint_id);
        out.extend_from_slice(&self.subject_endpoint_id);
        out.push(evidence_tag);
        out.extend_from_slice(evidence);
        out.extend_from_slice(
            &u16::try_from(self.allowed_use.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(self.allowed_use.as_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.push(self.delegated_confidence);
        out.push(self.sharing_restrictions);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out
    }

    /// Domain-separated digest signed by the introducer identity key.
    #[must_use]
    pub fn signed_message(&self) -> [u8; 32] {
        use blake2::Digest;
        let mut hasher = blake2::Blake2s256::new();
        hasher.update(b"UMP-INTRODUCTION-v1");
        hasher.update(self.signed_bytes());
        hasher.finalize().into()
    }

    /// Verifies structure, `EndpointID` binding, and the signature.
    ///
    /// # Errors
    ///
    /// Returns [`IntroductionStatementError`] when the statement is malformed
    /// or the supplied key cannot verify it.
    pub fn verify_signature(
        &self,
        introducer_public_key: &IdentityPublicKey,
    ) -> Result<(), IntroductionStatementError> {
        self.validate_structure()?;
        if endpoint_id(introducer_public_key) != self.introducer_endpoint_id {
            return Err(IntroductionStatementError::EndpointIdMismatch);
        }
        if !introducer_public_key.verify(&self.signed_message(), &self.signature) {
            return Err(IntroductionStatementError::BadSignature);
        }
        Ok(())
    }

    /// Verifies the statement and its expiry at `now_ms`.
    ///
    /// # Errors
    ///
    /// Returns [`IntroductionStatementError::Expired`] when the statement is
    /// no longer active.
    pub fn validate(
        &self,
        introducer_public_key: &IdentityPublicKey,
        now_ms: u64,
    ) -> Result<(), IntroductionStatementError> {
        self.verify_signature(introducer_public_key)?;
        if self.expires_at_ms <= now_ms {
            return Err(IntroductionStatementError::Expired);
        }
        Ok(())
    }

    /// Encodes the complete canonical statement, including the signature.
    ///
    /// # Errors
    ///
    /// Returns [`IntroductionStatementError`] for invalid or oversized data.
    pub fn to_bytes(&self) -> Result<Vec<u8>, IntroductionStatementError> {
        self.validate_structure()?;
        let mut out = self.signed_bytes();
        out.extend_from_slice(&self.signature);
        if out.len() > MAX_INTRODUCTION_STATEMENT {
            return Err(IntroductionStatementError::Oversized);
        }
        Ok(out)
    }

    /// Decodes one complete canonical statement.
    ///
    /// # Errors
    ///
    /// Returns [`IntroductionStatementError`] for truncation, trailing bytes,
    /// or any malformed bounded field.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IntroductionStatementError> {
        if bytes.len() > MAX_INTRODUCTION_STATEMENT {
            return Err(IntroductionStatementError::Oversized);
        }
        let mut offset = 0;
        let version = read_byte(bytes, &mut offset)?;
        let introducer_endpoint_id = read_array(bytes, &mut offset)?;
        let subject_endpoint_id = read_array(bytes, &mut offset)?;
        let evidence_tag = read_byte(bytes, &mut offset)?;
        let evidence_value = read_array(bytes, &mut offset)?;
        let evidence = SubjectEvidence::from_parts(evidence_tag, evidence_value)?;
        let scope_len = usize::from(u16::from_be_bytes(read_array(bytes, &mut offset)?));
        if scope_len == 0 || scope_len > MAX_INTRODUCTION_SCOPE {
            return Err(IntroductionStatementError::InvalidScope);
        }
        let scope_bytes = read_slice(bytes, &mut offset, scope_len)?;
        let allowed_use = String::from_utf8(scope_bytes.to_vec())
            .map_err(|_| IntroductionStatementError::InvalidScope)?;
        let expires_at_ms = u64::from_be_bytes(read_array(bytes, &mut offset)?);
        let delegated_confidence = read_byte(bytes, &mut offset)?;
        let sharing_restrictions = read_byte(bytes, &mut offset)?;
        let sequence = u64::from_be_bytes(read_array(bytes, &mut offset)?);
        let signature = read_array(bytes, &mut offset)?;
        if offset != bytes.len() {
            return Err(IntroductionStatementError::TrailingBytes);
        }
        let statement = Self {
            version,
            introducer_endpoint_id,
            subject_endpoint_id,
            subject_evidence: evidence,
            allowed_use,
            expires_at_ms,
            delegated_confidence,
            sharing_restrictions,
            sequence,
            signature,
        };
        statement.validate_structure()?;
        Ok(statement)
    }

    fn validate_structure(&self) -> Result<(), IntroductionStatementError> {
        if self.version != INTRODUCTION_STATEMENT_VERSION {
            return Err(IntroductionStatementError::Version);
        }
        if self.introducer_endpoint_id == [0u8; 32] || self.subject_endpoint_id == [0u8; 32] {
            return Err(IntroductionStatementError::EndpointIdMismatch);
        }
        if self.introducer_endpoint_id == self.subject_endpoint_id {
            return Err(IntroductionStatementError::SameEndpoint);
        }
        let (_, evidence) = self.subject_evidence.tag_and_bytes();
        if *evidence == [0u8; 32] {
            return Err(IntroductionStatementError::InvalidEvidence);
        }
        if self.allowed_use.is_empty() || self.allowed_use.len() > MAX_INTRODUCTION_SCOPE {
            return Err(IntroductionStatementError::InvalidScope);
        }
        if self.delegated_confidence > 100 {
            return Err(IntroductionStatementError::InvalidConfidence);
        }
        if self.sharing_restrictions & !INTRODUCTION_RESTRICTION_MASK != 0 {
            return Err(IntroductionStatementError::InvalidRestrictions);
        }
        if self.expires_at_ms == 0 {
            return Err(IntroductionStatementError::Expired);
        }
        let encoded_len = 182usize.saturating_add(self.allowed_use.len());
        if encoded_len > MAX_INTRODUCTION_STATEMENT {
            return Err(IntroductionStatementError::Oversized);
        }
        Ok(())
    }
}

fn read_byte(bytes: &[u8], offset: &mut usize) -> Result<u8, IntroductionStatementError> {
    let value = *bytes
        .get(*offset)
        .ok_or(IntroductionStatementError::Truncated)?;
    *offset += 1;
    Ok(value)
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], IntroductionStatementError> {
    let end = offset
        .checked_add(N)
        .ok_or(IntroductionStatementError::Truncated)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(IntroductionStatementError::Truncated)?
        .try_into()
        .map_err(|_| IntroductionStatementError::Truncated)?;
    *offset = end;
    Ok(value)
}

fn read_slice<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], IntroductionStatementError> {
    let end = offset
        .checked_add(length)
        .ok_or(IntroductionStatementError::Truncated)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(IntroductionStatementError::Truncated)?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement() -> (IdentityKeyPair, SignedIntroduction) {
        let identity = IdentityKeyPair::from_seed([7u8; 32]);
        let statement = SignedIntroduction::sign(
            &identity,
            [9u8; 32],
            SubjectEvidence::StaticHandshakeKey([3u8; 32]),
            "relay",
            10_000,
            80,
            0b0000_0011,
            4,
        )
        .expect("valid statement");
        (identity, statement)
    }

    #[test]
    fn canonical_statement_round_trips_and_verifies() {
        let (identity, statement) = statement();
        let bytes = statement.to_bytes().expect("encode");
        let decoded = SignedIntroduction::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, statement);
        decoded
            .validate(&identity.public(), 9_999)
            .expect("signature and expiry");
    }

    #[test]
    fn tampering_or_wrong_issuer_fails_closed() {
        let (identity, mut statement) = statement();
        statement.allowed_use = "admin".into();
        assert_eq!(
            statement.verify_signature(&identity.public()),
            Err(IntroductionStatementError::BadSignature)
        );
        let other = IdentityKeyPair::from_seed([8u8; 32]);
        assert_eq!(
            SignedIntroduction::sign(
                &identity,
                [9u8; 32],
                SubjectEvidence::BindingDigest([4u8; 32]),
                "relay",
                10_000,
                80,
                0,
                1,
            )
            .expect("valid statement")
            .verify_signature(&other.public()),
            Err(IntroductionStatementError::EndpointIdMismatch)
        );
    }

    #[test]
    fn expiry_and_bounds_are_enforced() {
        let identity = IdentityKeyPair::from_seed([7u8; 32]);
        assert_eq!(
            SignedIntroduction::sign(
                &identity,
                [9u8; 32],
                SubjectEvidence::StaticHandshakeKey([3u8; 32]),
                "relay",
                10,
                101,
                0,
                0,
            ),
            Err(IntroductionStatementError::InvalidConfidence)
        );
        let statement = SignedIntroduction::sign(
            &identity,
            [9u8; 32],
            SubjectEvidence::StaticHandshakeKey([3u8; 32]),
            "relay",
            10,
            100,
            0,
            0,
        )
        .expect("valid statement");
        assert_eq!(
            statement.validate(&identity.public(), 10),
            Err(IntroductionStatementError::Expired)
        );
        let oversized = "x".repeat(MAX_INTRODUCTION_SCOPE + 1);
        assert_eq!(
            SignedIntroduction::sign(
                &identity,
                [9u8; 32],
                SubjectEvidence::StaticHandshakeKey([3u8; 32]),
                &oversized,
                10,
                1,
                0,
                0,
            ),
            Err(IntroductionStatementError::InvalidScope)
        );
    }

    #[test]
    fn malformed_encoding_is_rejected() {
        let (_, statement) = statement();
        let mut bytes = statement.to_bytes().expect("encode");
        bytes.pop();
        assert_eq!(
            SignedIntroduction::from_bytes(&bytes),
            Err(IntroductionStatementError::Truncated)
        );
        let mut bytes = statement.to_bytes().expect("encode");
        bytes.push(0);
        assert_eq!(
            SignedIntroduction::from_bytes(&bytes),
            Err(IntroductionStatementError::TrailingBytes)
        );
    }

    #[test]
    fn canonical_revocation_round_trips_and_verifies() {
        let identity = IdentityKeyPair::from_seed([41u8; 32]);
        let endpoint_id = endpoint_id(&identity.public());
        let statement = SignedRevocation::sign(
            &identity,
            RevocationSubject::Binding {
                endpoint_id,
                binding_sequence: 7,
            },
            3,
            100,
            10_000,
        )
        .expect("valid revocation");
        assert_eq!(statement.class(), RevocationClass::Binding);
        assert!(statement.is_self_authorized());
        let bytes = statement.to_bytes().expect("encode");
        let decoded = SignedRevocation::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, statement);
        decoded
            .validate(&identity.public(), 101)
            .expect("signature and validity");
    }

    #[test]
    fn revocation_bounds_authority_and_validity_fail_closed() {
        let identity = IdentityKeyPair::from_seed([42u8; 32]);
        let other = IdentityKeyPair::from_seed([43u8; 32]);
        let endpoint_id = endpoint_id(&identity.public());
        let statement = SignedRevocation::sign(
            &identity,
            RevocationSubject::Identity(endpoint_id),
            1,
            100,
            200,
        )
        .expect("valid revocation");
        assert_eq!(
            statement.validate(&other.public(), 101),
            Err(RevocationStatementError::EndpointIdMismatch)
        );
        assert_eq!(
            statement.validate(&identity.public(), 99),
            Err(RevocationStatementError::NotYetValid)
        );
        assert_eq!(
            statement.validate(&identity.public(), 200),
            Err(RevocationStatementError::Expired)
        );
        let delegation = SignedRevocation::sign(
            &identity,
            RevocationSubject::Delegation([9u8; 32]),
            1,
            100,
            0,
        )
        .expect("valid statement");
        assert!(!delegation.is_self_authorized());
    }

    #[test]
    fn malformed_revocation_encoding_is_rejected() {
        let identity = IdentityKeyPair::from_seed([44u8; 32]);
        let statement = SignedRevocation::sign(
            &identity,
            RevocationSubject::Introduction([8u8; 32]),
            0,
            1,
            0,
        )
        .expect("valid revocation");
        let mut bytes = statement.to_bytes().expect("encode");
        bytes.pop();
        assert_eq!(
            SignedRevocation::from_bytes(&bytes),
            Err(RevocationStatementError::Truncated)
        );
        let mut bytes = statement.to_bytes().expect("encode");
        bytes.push(0);
        assert_eq!(
            SignedRevocation::from_bytes(&bytes),
            Err(RevocationStatementError::TrailingBytes)
        );
    }

    #[test]
    fn canonical_delegation_round_trips_and_verifies() {
        let issuer = IdentityKeyPair::from_seed([51u8; 32]);
        let delegated = IdentityKeyPair::from_seed([52u8; 32]);
        let certificate = SignedDelegation::sign(
            &issuer,
            delegated.public().0,
            vec![b"relay".to_vec(), b"chat".to_vec(), b"chat".to_vec()],
            100,
            1_000,
            7,
        )
        .expect("valid delegation");
        assert_eq!(
            certificate.allowed_capabilities,
            vec![b"chat".to_vec(), b"relay".to_vec()]
        );
        let bytes = certificate.to_bytes().expect("encode");
        let decoded = SignedDelegation::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, certificate);
        decoded
            .validate(&issuer.public(), 500)
            .expect("signature and validity");
    }

    #[test]
    fn delegation_chain_narrows_capabilities_and_expiry() {
        let root = IdentityKeyPair::from_seed([61u8; 32]);
        let first = IdentityKeyPair::from_seed([62u8; 32]);
        let second = IdentityKeyPair::from_seed([63u8; 32]);
        let first_link = SignedDelegation::sign(
            &root,
            first.public().0,
            vec![b"relay".to_vec(), b"chat".to_vec()],
            100,
            500,
            1,
        )
        .expect("first link");
        let second_link = SignedDelegation::sign(
            &first,
            second.public().0,
            vec![b"chat".to_vec()],
            200,
            400,
            1,
        )
        .expect("second link");
        let authority = DelegationChain::verify(
            &root.public(),
            &[b"chat".to_vec(), b"relay".to_vec()],
            &[first_link, second_link],
            300,
        )
        .expect("chain verifies");
        assert_eq!(authority.public_key, second.public());
        assert_eq!(authority.capabilities, vec![b"chat".to_vec()]);
        assert_eq!(authority.depth, 2);
    }

    #[test]
    fn delegation_chain_rejects_expansion_cycles_and_outliving_links() {
        let root = IdentityKeyPair::from_seed([71u8; 32]);
        let first = IdentityKeyPair::from_seed([72u8; 32]);
        let second = IdentityKeyPair::from_seed([73u8; 32]);
        let expansion = SignedDelegation::sign(
            &root,
            first.public().0,
            vec![b"admin".to_vec()],
            100,
            500,
            1,
        )
        .expect("expanding link is structurally valid");
        assert_eq!(
            DelegationChain::verify(&root.public(), &[b"chat".to_vec()], &[expansion], 200),
            Err(DelegationError::CapabilityExpansion)
        );

        let first_link =
            SignedDelegation::sign(&root, first.public().0, vec![b"chat".to_vec()], 100, 500, 1)
                .expect("first link");
        let cycle =
            SignedDelegation::sign(&first, root.public().0, vec![b"chat".to_vec()], 200, 400, 1)
                .expect("cycle link");
        assert_eq!(
            DelegationChain::verify(
                &root.public(),
                &[b"chat".to_vec()],
                &[first_link.clone(), cycle],
                300,
            ),
            Err(DelegationError::Cycle)
        );

        let outliving = SignedDelegation::sign(
            &first,
            second.public().0,
            vec![b"chat".to_vec()],
            200,
            600,
            2,
        )
        .expect("outliving link");
        assert_eq!(
            DelegationChain::verify(
                &root.public(),
                &[b"chat".to_vec()],
                &[first_link, outliving],
                300,
            ),
            Err(DelegationError::OutlivesIssuer)
        );

        let expired =
            SignedDelegation::sign(&root, first.public().0, vec![b"chat".to_vec()], 100, 200, 3)
                .expect("expired link");
        assert_eq!(
            DelegationChain::verify(&root.public(), &[b"chat".to_vec()], &[expired], 200,),
            Err(DelegationError::Expired)
        );
    }
}
