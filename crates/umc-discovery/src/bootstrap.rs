//! Signed bootstrap bundles (discovery.md §15.2).

use crate::provider::{CandidateAuth, CandidateSource, PeerCandidate, SharingPolicy};
use umc_crypto::signatures::{IdentityKeyPair, IdentityPublicKey, SIGNATURE_LEN};
use umc_types::runtime::Instant;
use umc_wire::frames::misc::{MAX_CARRIER_TYPE, MAX_CONNECTION_HINT};

const BUNDLE_VERSION: u8 = 1;
const BUNDLE_DOMAIN: &[u8] = b"UMP-BOOTSTRAP-v1";
const MAX_CANDIDATES: usize = 32;
const MAX_BUNDLE_BYTES: usize = 64 * 1024;

/// A candidate carried by a signed bootstrap bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapCandidate {
    pub candidate_id: u64,
    pub carrier_type: String,
    pub connection_hint: Vec<u8>,
    pub expires_at_ms: u64,
    pub sharing_policy: SharingPolicy,
}

/// Signed, bounded bootstrap data. Bootstrap authenticates the bundle
/// issuer, not the advertised endpoints; each endpoint is still authenticated
/// by the handshake after dialing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapBundle {
    pub issuer: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub candidates: Vec<BootstrapCandidate>,
    pub signature: [u8; SIGNATURE_LEN],
}

/// Bootstrap validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapError {
    TooManyCandidates,
    FieldLimit,
    InvalidValidity,
    CandidateOutsideBundle,
    TableFull,
    Expired,
    IssuerMismatch,
    InvalidSignature,
    Malformed,
    TrailingBytes,
}

impl BootstrapBundle {
    /// Signs a new bundle under `issuer` after validating all bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when the validity window, candidate count, or field
    /// limits are invalid.
    pub fn sign(
        issuer: &IdentityKeyPair,
        issued_at_ms: u64,
        expires_at_ms: u64,
        candidates: Vec<BootstrapCandidate>,
    ) -> Result<Self, BootstrapError> {
        let bundle = Self {
            issuer: issuer.public().0,
            issued_at_ms,
            expires_at_ms,
            candidates,
            signature: [0u8; SIGNATURE_LEN],
        };
        bundle.validate_shape()?;
        let signature = issuer.sign(&bundle.unsigned_bytes());
        Ok(Self {
            signature,
            ..bundle
        })
    }

    /// Encodes the signed bundle for a file or provider transport.
    ///
    /// # Errors
    ///
    /// Returns an error when the bundle shape exceeds the bounded wire form.
    pub fn encode(&self) -> Result<Vec<u8>, BootstrapError> {
        self.validate_shape()?;
        let mut out = self.unsigned_bytes();
        out.extend_from_slice(&self.signature);
        if out.len() > MAX_BUNDLE_BYTES {
            return Err(BootstrapError::FieldLimit);
        }
        Ok(out)
    }

    /// Parses a bounded signed bundle without trusting its issuer.
    ///
    /// # Errors
    ///
    /// Returns an error when framing, bounds, or trailing bytes are invalid.
    pub fn decode(bytes: &[u8]) -> Result<Self, BootstrapError> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(BootstrapError::FieldLimit);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(BUNDLE_DOMAIN.len())? != BUNDLE_DOMAIN {
            return Err(BootstrapError::Malformed);
        }
        if cursor.take_u8()? != BUNDLE_VERSION {
            return Err(BootstrapError::Malformed);
        }
        let issuer = cursor.take_array::<32>()?;
        let issued_at_ms = cursor.take_u64()?;
        let expires_at_ms = cursor.take_u64()?;
        let count = usize::from(cursor.take_u16()?);
        if count > MAX_CANDIDATES {
            return Err(BootstrapError::TooManyCandidates);
        }
        let mut candidates = Vec::with_capacity(count);
        for _ in 0..count {
            let candidate_id = cursor.take_u64()?;
            let carrier_type = String::from_utf8(cursor.take_bytes(MAX_CARRIER_TYPE)?)
                .map_err(|_| BootstrapError::Malformed)?;
            let connection_hint = cursor.take_bytes(MAX_CONNECTION_HINT)?;
            let expires_at_ms_candidate = cursor.take_u64()?;
            let sharing_policy =
                sharing_from_byte(cursor.take_u8()?).ok_or(BootstrapError::Malformed)?;
            candidates.push(BootstrapCandidate {
                candidate_id,
                carrier_type,
                connection_hint,
                expires_at_ms: expires_at_ms_candidate,
                sharing_policy,
            });
        }
        let signature = cursor.take_array::<SIGNATURE_LEN>()?;
        if !cursor.is_empty() {
            return Err(BootstrapError::TrailingBytes);
        }
        let bundle = Self {
            issuer,
            issued_at_ms,
            expires_at_ms,
            candidates,
            signature,
        };
        bundle.validate_shape()?;
        Ok(bundle)
    }

    /// Verifies the issuer signature and validity window, returning candidates
    /// marked as signed bootstrap data.
    ///
    /// # Errors
    ///
    /// Returns an error when the issuer, signature, validity, or candidate
    /// windows do not validate.
    pub fn verify(
        &self,
        issuer_key: &IdentityPublicKey,
        now_ms: u64,
    ) -> Result<Vec<PeerCandidate>, BootstrapError> {
        self.validate_shape()?;
        if self.issuer != issuer_key.0 {
            return Err(BootstrapError::IssuerMismatch);
        }
        if now_ms < self.issued_at_ms || now_ms >= self.expires_at_ms {
            return Err(BootstrapError::Expired);
        }
        if !issuer_key.verify(&self.unsigned_bytes(), &self.signature) {
            return Err(BootstrapError::InvalidSignature);
        }
        Ok(self
            .candidates
            .iter()
            .map(|candidate| PeerCandidate {
                candidate_id: candidate.candidate_id,
                carrier_type: candidate.carrier_type.clone(),
                connection_hint: candidate.connection_hint.clone(),
                source: CandidateSource::Bootstrap,
                created_at: Instant(self.issued_at_ms),
                expires_at: Instant(candidate.expires_at_ms.min(self.expires_at_ms)),
                sharing_policy: candidate.sharing_policy,
                authentication: CandidateAuth::SignedBootstrap,
                local: false,
            })
            .collect())
    }

    fn validate_shape(&self) -> Result<(), BootstrapError> {
        if self.issued_at_ms >= self.expires_at_ms {
            return Err(BootstrapError::InvalidValidity);
        }
        if self.candidates.len() > MAX_CANDIDATES {
            return Err(BootstrapError::TooManyCandidates);
        }
        for candidate in &self.candidates {
            if candidate.carrier_type.is_empty()
                || candidate.carrier_type.len() > MAX_CARRIER_TYPE
                || candidate.connection_hint.len() > MAX_CONNECTION_HINT
            {
                return Err(BootstrapError::FieldLimit);
            }
            if candidate.expires_at_ms <= self.issued_at_ms
                || candidate.expires_at_ms > self.expires_at_ms
            {
                return Err(BootstrapError::CandidateOutsideBundle);
            }
        }
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation)] // all encoded fields are bounded above
    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(BUNDLE_DOMAIN);
        out.push(BUNDLE_VERSION);
        out.extend_from_slice(&self.issuer);
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.extend_from_slice(&(self.candidates.len() as u16).to_be_bytes());
        for candidate in &self.candidates {
            out.extend_from_slice(&candidate.candidate_id.to_be_bytes());
            append_bytes(&mut out, candidate.carrier_type.as_bytes());
            append_bytes(&mut out, &candidate.connection_hint);
            out.extend_from_slice(&candidate.expires_at_ms.to_be_bytes());
            out.push(sharing_to_byte(candidate.sharing_policy));
        }
        out
    }
}

fn sharing_to_byte(policy: SharingPolicy) -> u8 {
    match policy {
        SharingPolicy::LocalUseOnly => 0,
        SharingPolicy::ShareSelected => 1,
        SharingPolicy::ShareLocalScope => 2,
        SharingPolicy::ShareGeneral => 3,
        SharingPolicy::DoNotReshare => 4,
    }
}

fn sharing_from_byte(value: u8) -> Option<SharingPolicy> {
    match value {
        0 => Some(SharingPolicy::LocalUseOnly),
        1 => Some(SharingPolicy::ShareSelected),
        2 => Some(SharingPolicy::ShareLocalScope),
        3 => Some(SharingPolicy::ShareGeneral),
        4 => Some(SharingPolicy::DoNotReshare),
        _ => None,
    }
}

#[allow(clippy::cast_possible_truncation)] // callers validate carrier/hint limits first
fn append_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BootstrapError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BootstrapError::Malformed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BootstrapError::Malformed)?;
        self.offset = end;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8, BootstrapError> {
        Ok(*self.take(1)?.first().ok_or(BootstrapError::Malformed)?)
    }

    fn take_u16(&mut self) -> Result<u16, BootstrapError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| BootstrapError::Malformed)?,
        ))
    }

    fn take_u64(&mut self) -> Result<u64, BootstrapError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| BootstrapError::Malformed)?,
        ))
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], BootstrapError> {
        self.take(N)?
            .try_into()
            .map_err(|_| BootstrapError::Malformed)
    }

    fn take_bytes(&mut self, maximum: usize) -> Result<Vec<u8>, BootstrapError> {
        let length = usize::from(self.take_u16()?);
        if length > maximum {
            return Err(BootstrapError::FieldLimit);
        }
        Ok(self.take(length)?.to_vec())
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(expires_at_ms: u64) -> BootstrapCandidate {
        BootstrapCandidate {
            candidate_id: 7,
            carrier_type: "ump.tcp/1".into(),
            connection_hint: b"127.0.0.1:9000".to_vec(),
            expires_at_ms,
            sharing_policy: SharingPolicy::ShareSelected,
        }
    }

    #[test]
    fn signed_bundle_round_trips_and_marks_candidates() {
        let issuer = IdentityKeyPair::generate();
        let bundle = BootstrapBundle::sign(&issuer, 10, 100, vec![candidate(90)]).unwrap();
        let encoded = bundle.encode().unwrap();
        let decoded = BootstrapBundle::decode(&encoded).unwrap();
        let candidates = decoded.verify(&issuer.public(), 50).unwrap();
        assert_eq!(candidates[0].source, CandidateSource::Bootstrap);
        assert_eq!(candidates[0].authentication, CandidateAuth::SignedBootstrap);
        assert_eq!(candidates[0].expires_at, Instant(90));
    }

    #[test]
    fn tampering_expiry_or_signature_is_rejected() {
        let issuer = IdentityKeyPair::generate();
        let mut bundle = BootstrapBundle::sign(&issuer, 10, 100, vec![candidate(90)]).unwrap();
        bundle.expires_at_ms = 101;
        assert_eq!(
            bundle.verify(&issuer.public(), 50),
            Err(BootstrapError::InvalidSignature)
        );
    }

    #[test]
    fn expired_bundle_is_rejected_before_endpoint_use() {
        let issuer = IdentityKeyPair::generate();
        let bundle = BootstrapBundle::sign(&issuer, 10, 100, vec![candidate(90)]).unwrap();
        assert_eq!(
            bundle.verify(&issuer.public(), 100),
            Err(BootstrapError::Expired)
        );
    }
}
