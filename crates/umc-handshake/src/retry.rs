// Stateless retry token (handshake.md §21), encrypted with a rotating Retry key.
use umc_crypto::aead::PacketKeys;

pub const RETRY_VALIDITY_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPayload {
    pub token_version: u8,
    pub source_context: Vec<u8>,
    pub original_destination_connection_id: Vec<u8>,
    pub client_random: [u8; 32],
    pub client_ephemeral_public_key_hash: [u8; 32],
    pub carrier_binding_hash: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; 16],
}

impl RetryPayload {
    /// Wire encoding of the retry payload.
    ///
    /// # Panics
    /// Panics if `source_context` exceeds 256 bytes or
    /// `original_destination_connection_id` exceeds 20 bytes; both are
    /// bounded by construction.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.token_version);
        umc_wire::bytes::encode(&mut out, &self.source_context, 256).expect("bounded");
        umc_wire::bytes::encode(&mut out, &self.original_destination_connection_id, 20)
            .expect("bounded");
        out.extend_from_slice(&self.client_random);
        out.extend_from_slice(&self.client_ephemeral_public_key_hash);
        out.extend_from_slice(&self.carrier_binding_hash);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }

    /// Decode a wire-encoded retry payload.
    ///
    /// # Errors
    /// Returns `RetryError::Truncated` if `body` ends before every field is
    /// present.
    ///
    /// # Panics
    /// Panics if a length-prefixed field declares a length beyond the
    /// bounds of `body`; all such slices are checked with `get`.
    pub fn decode(body: &[u8]) -> Result<Self, RetryError> {
        let token_version = *body.first().ok_or(RetryError::Truncated)?;
        let mut pos = 1usize;
        let (source_context, n) =
            umc_wire::bytes::decode(&body[pos..], 256).map_err(|_| RetryError::Truncated)?;
        pos += n;
        let (dcid, n) =
            umc_wire::bytes::decode(&body[pos..], 20).map_err(|_| RetryError::Truncated)?;
        pos += n;
        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(body.get(pos..pos + 32).ok_or(RetryError::Truncated)?);
        pos += 32;
        let mut client_eph_hash = [0u8; 32];
        client_eph_hash.copy_from_slice(body.get(pos..pos + 32).ok_or(RetryError::Truncated)?);
        pos += 32;
        let mut carrier_binding_hash = [0u8; 32];
        carrier_binding_hash.copy_from_slice(body.get(pos..pos + 32).ok_or(RetryError::Truncated)?);
        pos += 32;
        let issued_at = u64::from_be_bytes(
            body.get(pos..pos + 8)
                .ok_or(RetryError::Truncated)?
                .try_into()
                .unwrap(),
        );
        pos += 8;
        let expires_at = u64::from_be_bytes(
            body.get(pos..pos + 8)
                .ok_or(RetryError::Truncated)?
                .try_into()
                .unwrap(),
        );
        pos += 8;
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(body.get(pos..pos + 16).ok_or(RetryError::Truncated)?);
        Ok(Self {
            token_version,
            source_context: source_context.to_vec(),
            original_destination_connection_id: dcid.to_vec(),
            client_random,
            client_ephemeral_public_key_hash: client_eph_hash,
            carrier_binding_hash,
            issued_at,
            expires_at,
            nonce,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryError {
    Truncated,
    Version,
    Expired,
    InvalidTag,
}

/// Encrypt and sign a retry payload into a stateless token.
///
/// # Errors
/// Returns `RetryError::Expired` if `payload` is already expired or its
/// validity window exceeds [`RETRY_VALIDITY_MS`], and
/// `RetryError::InvalidTag` if key derivation or sealing fails.
pub fn issue_retry_token(
    retry_key: &[u8; 32],
    payload: &RetryPayload,
    now_ms: u64,
) -> Result<Vec<u8>, RetryError> {
    if payload.expires_at <= now_ms || payload.issued_at + RETRY_VALIDITY_MS < payload.expires_at {
        return Err(RetryError::Expired);
    }
    let keys = PacketKeys::from_traffic_secret(retry_key).map_err(|_| RetryError::InvalidTag)?;
    keys.seal(0, b"UMP-RETRY-TOKEN-v1", &payload.encode())
        .map_err(|_| RetryError::InvalidTag)
}

/// Verify a stateless retry token, returning its plaintext payload.
///
/// # Errors
/// Returns `RetryError::InvalidTag` if authentication fails,
/// `RetryError::Truncated` if the plaintext is malformed,
/// `RetryError::Version` if the token version is unsupported, and
/// `RetryError::Expired` if the token has expired at `now_ms`.
pub fn validate_retry_token(
    retry_key: &[u8; 32],
    token: &[u8],
    now_ms: u64,
) -> Result<RetryPayload, RetryError> {
    let keys = PacketKeys::from_traffic_secret(retry_key).map_err(|_| RetryError::InvalidTag)?;
    let plaintext = keys
        .open(0, b"UMP-RETRY-TOKEN-v1", token)
        .map_err(|_| RetryError::InvalidTag)?;
    let payload = RetryPayload::decode(&plaintext)?;
    if payload.token_version != 1 {
        return Err(RetryError::Version);
    }
    if payload.expires_at <= now_ms {
        return Err(RetryError::Expired);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(now: u64) -> RetryPayload {
        RetryPayload {
            token_version: 1,
            source_context: vec![1, 2, 3],
            original_destination_connection_id: vec![4, 5, 6, 7, 8],
            client_random: [9u8; 32],
            client_ephemeral_public_key_hash: [10u8; 32],
            carrier_binding_hash: [11u8; 32],
            issued_at: now,
            expires_at: now + 60_000,
            nonce: [12u8; 16],
        }
    }

    #[test]
    fn issue_validate_round_trip() {
        let key = [1u8; 32];
        let now = 1_700_000_000_000;
        let token = issue_retry_token(&key, &payload(now), now).unwrap();
        let back = validate_retry_token(&key, &token, now + 10_000).unwrap();
        assert_eq!(back.client_random, [9u8; 32]);
        assert_eq!(back.expires_at, now + 60_000);
    }

    #[test]
    fn expired_token_rejected() {
        let key = [1u8; 32];
        let now = 1_700_000_000_000;
        let token = issue_retry_token(&key, &payload(now), now).unwrap();
        assert_eq!(
            validate_retry_token(&key, &token, now + 61_000),
            Err(RetryError::Expired)
        );
    }

    #[test]
    fn wrong_key_rejected() {
        let now = 1_700_000_000_000;
        let token = issue_retry_token(&[1u8; 32], &payload(now), now).unwrap();
        assert_eq!(
            validate_retry_token(&[2u8; 32], &token, now),
            Err(RetryError::InvalidTag)
        );
    }

    #[test]
    fn payload_round_trip() {
        let p = payload(1);
        let enc = p.encode();
        assert_eq!(RetryPayload::decode(&enc).unwrap(), p);
    }
}
