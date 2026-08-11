//! Stateless Retry packet framing (wire-format.md §14).

use blake2::{Blake2s256, Digest};
use umc_types::version::{MAX_CONNECTION_ID_LEN, MAX_TOKEN_LEN};
use umc_wire::header::{HeaderByte, LongPacketType};

/// The fixed integrity tag size at the end of a Retry packet.
pub const RETRY_INTEGRITY_TAG_LEN: usize = 16;
const RETRY_INTEGRITY_LABEL: &[u8] = b"retry integrity";
const RETRY_CONTEXT_LABEL: &[u8] = b"UMP-RETRY-CONTEXT-v1";

/// A parsed Retry packet. The token remains opaque to the initiator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPacket {
    pub version: u32,
    pub destination_connection_id: Vec<u8>,
    pub source_connection_id: Vec<u8>,
    pub token: Vec<u8>,
}

/// Computes the synthetic transcript input required after a Retry exchange
/// (handshake.md §21.1). Both sides can derive it statelessly when the Retry
/// source connection id is deterministic from the token nonce.
#[must_use]
pub fn retry_context(original_client_hello: &[u8], retry_packet: &[u8]) -> [u8; 32] {
    let hello_hash: [u8; 32] = Blake2s256::digest(original_client_hello).into();
    let packet_hash: [u8; 32] = Blake2s256::digest(retry_packet).into();
    let mut hasher = Blake2s256::new();
    hasher.update(RETRY_CONTEXT_LABEL);
    hasher.update(hello_hash);
    hasher.update(packet_hash);
    hasher.finalize().into()
}

/// Retry packet framing or authentication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryPacketError {
    Header,
    Truncated,
    InvalidType,
    InvalidVersion,
    ConnectionIdTooLong,
    TokenTooLong,
    Integrity,
    TrailingBytes,
}

/// Builds an authenticated Retry packet. Retry has no packet number, payload
/// length, or encrypted frames; its token and fixed integrity tag follow the
/// long-header connection IDs directly (wire-format.md §14).
///
/// # Errors
///
/// Returns an error when the version, connection IDs, or token exceed the
/// protocol bounds.
pub fn build_retry_packet(
    version: u32,
    destination_connection_id: &[u8],
    source_connection_id: &[u8],
    token: &[u8],
    retry_key: &[u8; 32],
) -> Result<Vec<u8>, RetryPacketError> {
    if version == 0 {
        return Err(RetryPacketError::InvalidVersion);
    }
    if destination_connection_id.len() > MAX_CONNECTION_ID_LEN
        || source_connection_id.len() > MAX_CONNECTION_ID_LEN
    {
        return Err(RetryPacketError::ConnectionIdTooLong);
    }
    if token.len() > MAX_TOKEN_LEN {
        return Err(RetryPacketError::TokenTooLong);
    }
    let mut out = Vec::with_capacity(
        1 + 4
            + 2
            + destination_connection_id.len()
            + source_connection_id.len()
            + 9
            + token.len()
            + RETRY_INTEGRITY_TAG_LEN,
    );
    out.push(HeaderByte::LONG_RETRY.encode());
    out.extend_from_slice(&version.to_be_bytes());
    let destination_connection_id_len = u8::try_from(destination_connection_id.len())
        .map_err(|_| RetryPacketError::ConnectionIdTooLong)?;
    out.push(destination_connection_id_len);
    out.extend_from_slice(destination_connection_id);
    let source_connection_id_len = u8::try_from(source_connection_id.len())
        .map_err(|_| RetryPacketError::ConnectionIdTooLong)?;
    out.push(source_connection_id_len);
    out.extend_from_slice(source_connection_id);
    umc_wire::varint::encode_into(&mut out, token.len() as u64)
        .map_err(|_| RetryPacketError::TokenTooLong)?;
    out.extend_from_slice(token);
    let tag = integrity_tag(retry_key, &out);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Parses and authenticates a Retry packet with the current retry key.
///
/// # Errors
///
/// Returns an error when framing, bounds, or the integrity tag is invalid.
pub fn parse_retry_packet(
    bytes: &[u8],
    retry_key: &[u8; 32],
) -> Result<RetryPacket, RetryPacketError> {
    parse_retry_packet_inner(bytes, Some(retry_key))
}

/// Decodes a Retry packet without authenticating its opaque token. An
/// initiator does not possess the responder-local retry key; it validates the
/// packet shape and echoes the token, while the responder authenticates it
/// with [`crate::retry::validate_retry_token`].
///
/// # Errors
///
/// Returns an error when the packet has invalid Retry framing or bounds.
pub fn decode_retry_packet(bytes: &[u8]) -> Result<RetryPacket, RetryPacketError> {
    parse_retry_packet_inner(bytes, None)
}

fn parse_retry_packet_inner(
    bytes: &[u8],
    retry_key: Option<&[u8; 32]>,
) -> Result<RetryPacket, RetryPacketError> {
    let header = HeaderByte::decode(*bytes.first().ok_or(RetryPacketError::Truncated)?)
        .map_err(|_| RetryPacketError::Header)?;
    if !header.long || header.long_type() != Some(LongPacketType::Retry) {
        return Err(RetryPacketError::InvalidType);
    }
    if bytes.len() < 5 {
        return Err(RetryPacketError::Truncated);
    }
    let version = u32::from_be_bytes(
        bytes[1..5]
            .try_into()
            .map_err(|_| RetryPacketError::Truncated)?,
    );
    if version == 0 {
        return Err(RetryPacketError::InvalidVersion);
    }
    let mut pos = 5usize;
    let dcid_len = usize::from(*bytes.get(pos).ok_or(RetryPacketError::Truncated)?);
    pos = pos.checked_add(1).ok_or(RetryPacketError::Truncated)?;
    if dcid_len > MAX_CONNECTION_ID_LEN {
        return Err(RetryPacketError::ConnectionIdTooLong);
    }
    let destination_connection_id = bytes
        .get(
            pos..pos
                .checked_add(dcid_len)
                .ok_or(RetryPacketError::Truncated)?,
        )
        .ok_or(RetryPacketError::Truncated)?
        .to_vec();
    pos = pos
        .checked_add(dcid_len)
        .ok_or(RetryPacketError::Truncated)?;
    let scid_len = usize::from(*bytes.get(pos).ok_or(RetryPacketError::Truncated)?);
    pos = pos.checked_add(1).ok_or(RetryPacketError::Truncated)?;
    if scid_len > MAX_CONNECTION_ID_LEN {
        return Err(RetryPacketError::ConnectionIdTooLong);
    }
    let source_connection_id = bytes
        .get(
            pos..pos
                .checked_add(scid_len)
                .ok_or(RetryPacketError::Truncated)?,
        )
        .ok_or(RetryPacketError::Truncated)?
        .to_vec();
    pos = pos
        .checked_add(scid_len)
        .ok_or(RetryPacketError::Truncated)?;
    let (token_len, width) =
        umc_wire::varint::decode(bytes.get(pos..).ok_or(RetryPacketError::Truncated)?)
            .map_err(|_| RetryPacketError::Header)?;
    let token_len = usize::try_from(token_len).map_err(|_| RetryPacketError::TokenTooLong)?;
    if token_len > MAX_TOKEN_LEN {
        return Err(RetryPacketError::TokenTooLong);
    }
    pos = pos
        .checked_add(width)
        .and_then(|offset| offset.checked_add(token_len))
        .ok_or(RetryPacketError::Truncated)?;
    let tag_start = pos;
    let tag_end = tag_start
        .checked_add(RETRY_INTEGRITY_TAG_LEN)
        .ok_or(RetryPacketError::Truncated)?;
    if bytes.len() < tag_end {
        return Err(RetryPacketError::Truncated);
    }
    if bytes.len() > tag_end {
        return Err(RetryPacketError::TrailingBytes);
    }
    if let Some(retry_key) = retry_key {
        let expected = integrity_tag(retry_key, &bytes[..tag_start]);
        if !constant_time_equal(bytes[tag_start..].as_ref(), &expected) {
            return Err(RetryPacketError::Integrity);
        }
    }
    Ok(RetryPacket {
        version,
        destination_connection_id,
        source_connection_id,
        token: bytes[tag_start - token_len..tag_start].to_vec(),
    })
}

fn integrity_tag(retry_key: &[u8; 32], authenticated: &[u8]) -> [u8; RETRY_INTEGRITY_TAG_LEN] {
    let key = umc_crypto::label::expand_label(retry_key, RETRY_INTEGRITY_LABEL, b"", 32)
        .expect("fixed retry integrity key length");
    let mut hasher = Blake2s256::new();
    hasher.update(key);
    hasher.update(authenticated);
    let digest: [u8; 32] = hasher.finalize().into();
    digest[..RETRY_INTEGRITY_TAG_LEN]
        .try_into()
        .expect("fixed tag length")
}

fn constant_time_equal(left: &[u8], right: &[u8; RETRY_INTEGRITY_TAG_LEN]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_packet_round_trip_and_integrity() {
        let key = [7u8; 32];
        let packet = build_retry_packet(1, &[1; 8], &[2; 8], b"opaque-token", &key).unwrap();
        let parsed = parse_retry_packet(&packet, &key).unwrap();
        let unverified = decode_retry_packet(&packet).unwrap();
        assert_eq!(unverified, parsed);
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.destination_connection_id, vec![1; 8]);
        assert_eq!(parsed.source_connection_id, vec![2; 8]);
        assert_eq!(parsed.token, b"opaque-token");

        let mut tampered = packet;
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            parse_retry_packet(&tampered, &key),
            Err(RetryPacketError::Integrity)
        );
    }

    #[test]
    fn retry_packet_rejects_wrong_key_and_trailing_bytes() {
        let packet = build_retry_packet(1, &[1; 8], &[2; 8], b"token", &[7u8; 32]).unwrap();
        assert_eq!(
            parse_retry_packet(&packet, &[8u8; 32]),
            Err(RetryPacketError::Integrity)
        );
        let mut trailing = packet;
        trailing.push(0);
        assert_eq!(
            parse_retry_packet(&trailing, &[7u8; 32]),
            Err(RetryPacketError::TrailingBytes)
        );
    }

    #[test]
    fn retry_context_binds_both_messages() {
        let packet = build_retry_packet(1, &[1; 8], &[2; 8], b"token", &[7u8; 32]).unwrap();
        let context = retry_context(b"hello", &packet);
        assert_ne!(context, retry_context(b"changed", &packet));
        let mut changed = packet;
        changed[0] ^= 0x20;
        assert_ne!(context, retry_context(b"hello", &changed));
    }
}
