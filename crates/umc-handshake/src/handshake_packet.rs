use umc_crypto::aead::{AeadError, PacketKeys, TAG_LEN};
use umc_crypto::header_protection::{protect, unprotect, SAMPLE_LEN};
use umc_wire::header::{HeaderByte, HeaderError, LongHeader, LongPacketType};
use umc_wire::pn::PnError;

/// Errors while building or opening a protected Handshake packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePacketError {
    Header(HeaderError),
    Aead(AeadError),
    PacketNumber(PnError),
    Truncated,
    InvalidType,
    InvalidLength,
}

/// Parsed fields from an encrypted Handshake packet.
pub type HandshakePacketParts = (Vec<u8>, Vec<u8>, u64, Vec<u8>);

/// Build one encrypted long-header Handshake packet (wire-format §15 and
/// handshake.md §§25, 28). Packet number is one byte in v1's bounded
/// handshake space; the payload is authenticated with the complete header.
///
/// # Errors
///
/// Returns an error when the packet number, header, or AEAD payload is
/// invalid.
pub fn build_handshake_packet(
    dcid: &[u8],
    scid: &[u8],
    packet_number: u64,
    payload: &[u8],
    keys: &PacketKeys,
) -> Result<Vec<u8>, HandshakePacketError> {
    if packet_number > u64::from(u8::MAX) {
        return Err(HandshakePacketError::InvalidLength);
    }
    let payload_len = u64::try_from(1usize + payload.len() + TAG_LEN)
        .map_err(|_| HandshakePacketError::InvalidLength)?;
    let header = LongHeader {
        ptype: LongPacketType::Handshake,
        version: umc_types::version::PROTOCOL_VERSION,
        dcid: dcid.to_vec(),
        scid: scid.to_vec(),
        token: Vec::new(),
        payload_len,
        packet_number,
        pn_bits: 8,
    }
    .encode()
    .map_err(HandshakePacketError::Header)?;
    let ciphertext = keys
        .seal(packet_number, &header, payload)
        .map_err(HandshakePacketError::Aead)?;
    let pn_offset = header
        .len()
        .checked_sub(1)
        .ok_or(HandshakePacketError::Truncated)?;
    let sample = ciphertext
        .get(..SAMPLE_LEN)
        .ok_or(HandshakePacketError::Truncated)?;
    let mut pn_bytes = header[pn_offset..].to_vec();
    let (protected_first, _) = protect(&keys.hp_key, header[0], false, sample, &mut pn_bytes);
    let mut out = header[..pn_offset].to_vec();
    out[0] = protected_first;
    out.extend_from_slice(&pn_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open one encrypted long-header Handshake packet. Returns destination and
/// source connection IDs, reconstructed packet number, and plaintext payload.
///
/// # Errors
///
/// Returns an error when framing, packet-number reconstruction, or AEAD
/// authentication fails.
pub fn parse_handshake_packet(
    bytes: &[u8],
    keys: &PacketKeys,
    expected_packet_number: u64,
) -> Result<HandshakePacketParts, HandshakePacketError> {
    parse_protected_handshake_packet(bytes, keys, expected_packet_number)
}

fn parse_protected_handshake_packet(
    bytes: &[u8],
    keys: &PacketKeys,
    expected_packet_number: u64,
) -> Result<HandshakePacketParts, HandshakePacketError> {
    let first = *bytes.first().ok_or(HandshakePacketError::Truncated)?;
    let header_byte = HeaderByte::decode(first).map_err(HandshakePacketError::Header)?;
    if !header_byte.long {
        return Err(HandshakePacketError::InvalidType);
    }
    if header_byte.long_type() != Some(LongPacketType::Handshake) {
        return Err(HandshakePacketError::InvalidType);
    }
    let mut pos = 5usize;
    let dcid_len = usize::from(*bytes.get(pos).ok_or(HandshakePacketError::Truncated)?);
    pos += 1;
    let dcid = bytes
        .get(pos..pos.saturating_add(dcid_len))
        .ok_or(HandshakePacketError::Truncated)?
        .to_vec();
    pos += dcid_len;
    let scid_len = usize::from(*bytes.get(pos).ok_or(HandshakePacketError::Truncated)?);
    pos += 1;
    let scid = bytes
        .get(pos..pos.saturating_add(scid_len))
        .ok_or(HandshakePacketError::Truncated)?
        .to_vec();
    pos += scid_len;
    let (token_len, token_bytes) =
        umc_wire::varint::decode(bytes.get(pos..).ok_or(HandshakePacketError::Truncated)?)
            .map_err(|_| HandshakePacketError::Truncated)?;
    pos = pos
        .checked_add(token_bytes)
        .and_then(|value| value.checked_add(usize::try_from(token_len).ok()?))
        .ok_or(HandshakePacketError::InvalidLength)?;
    if pos > bytes.len() {
        return Err(HandshakePacketError::Truncated);
    }
    let (payload_len, payload_len_bytes) =
        umc_wire::varint::decode(bytes.get(pos..).ok_or(HandshakePacketError::Truncated)?)
            .map_err(|_| HandshakePacketError::Truncated)?;
    pos = pos
        .checked_add(payload_len_bytes)
        .ok_or(HandshakePacketError::InvalidLength)?;
    let pn_len = (header_byte.pn_bits as usize) / 8;
    if payload_len < pn_len as u64 {
        return Err(HandshakePacketError::InvalidLength);
    }
    let protected_pn = bytes
        .get(pos..pos.saturating_add(pn_len))
        .ok_or(HandshakePacketError::Truncated)?;
    let ciphertext_len = usize::try_from(payload_len - pn_len as u64)
        .map_err(|_| HandshakePacketError::InvalidLength)?;
    let ciphertext_start = pos
        .checked_add(pn_len)
        .ok_or(HandshakePacketError::InvalidLength)?;
    let ciphertext = bytes
        .get(ciphertext_start..ciphertext_start.saturating_add(ciphertext_len))
        .ok_or(HandshakePacketError::Truncated)?;
    if ciphertext.len() != ciphertext_len || ciphertext_start + ciphertext_len != bytes.len() {
        return Err(HandshakePacketError::InvalidLength);
    }
    let sample = ciphertext
        .get(..SAMPLE_LEN)
        .ok_or(HandshakePacketError::Truncated)?;
    let (unprotected_first, _key_phase, unprotected_pn) =
        unprotect(&keys.hp_key, first, sample, protected_pn);
    let unprotected_header =
        HeaderByte::decode(unprotected_first).map_err(HandshakePacketError::Header)?;
    if !unprotected_header.long
        || unprotected_header.long_type() != Some(LongPacketType::Handshake)
        || unprotected_header.pn_bits != header_byte.pn_bits
    {
        return Err(HandshakePacketError::InvalidType);
    }
    let mut pn_full = [0u8; 8];
    pn_full[8 - pn_len..].copy_from_slice(&unprotected_pn);
    let truncated = u64::from_be_bytes(pn_full);
    let packet_number = umc_wire::pn::reconstruct(
        truncated,
        unprotected_header.pn_bits,
        expected_packet_number,
    )
    .map_err(HandshakePacketError::PacketNumber)?;
    let mut aad = bytes
        .get(..ciphertext_start)
        .ok_or(HandshakePacketError::Truncated)?
        .to_vec();
    aad[0] = unprotected_first;
    aad[ciphertext_start - pn_len..].copy_from_slice(&unprotected_pn);
    let payload = keys
        .open(packet_number, &aad, ciphertext)
        .map_err(HandshakePacketError::Aead)?;
    Ok((dcid, scid, packet_number, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_crypto::aead::PacketKeys;

    #[test]
    fn handshake_packet_round_trip() {
        let secret = [4u8; 32];
        let keys = PacketKeys::from_traffic_secret(&secret).expect("keys");
        let bytes = build_handshake_packet(&[1u8; 8], &[2u8; 8], 7, b"handshake-frame", &keys)
            .expect("packet");
        let parsed = parse_handshake_packet(&bytes, &keys, 0).expect("parse");
        assert_eq!(parsed.0, vec![1u8; 8]);
        assert_eq!(parsed.1, vec![2u8; 8]);
        assert_eq!(parsed.2, 7);
        assert_eq!(parsed.3, b"handshake-frame");
    }

    #[test]
    fn handshake_packet_masks_packet_number() {
        let secret = [8u8; 32];
        let keys = PacketKeys::from_traffic_secret(&secret).expect("keys");
        let bytes = build_handshake_packet(&[1u8; 8], &[2u8; 8], 7, b"handshake-frame", &keys)
            .expect("packet");
        let header_len = LongHeader {
            ptype: LongPacketType::Handshake,
            version: umc_types::version::PROTOCOL_VERSION,
            dcid: vec![1u8; 8],
            scid: vec![2u8; 8],
            token: Vec::new(),
            payload_len: u64::try_from(1 + b"handshake-frame".len() + TAG_LEN).unwrap(),
            packet_number: 7,
            pn_bits: 8,
        }
        .encode()
        .expect("header")
        .len();
        assert_ne!(
            bytes[header_len - 1],
            7,
            "handshake PN must be header protected"
        );
        assert_eq!(
            parse_handshake_packet(&bytes, &keys, 0).expect("parse").2,
            7
        );
    }

    #[test]
    fn handshake_packet_rejects_wrong_keys() {
        let keys = PacketKeys::from_traffic_secret(&[4u8; 32]).expect("keys");
        let wrong = PacketKeys::from_traffic_secret(&[5u8; 32]).expect("keys");
        let bytes = build_handshake_packet(&[1u8; 8], &[2u8; 8], 0, b"x", &keys).unwrap();
        assert!(parse_handshake_packet(&bytes, &wrong, 0).is_err());
    }

    #[test]
    fn legacy_unprotected_handshake_layout_is_rejected() {
        let keys = PacketKeys::from_traffic_secret(&[6u8; 32]).expect("keys");
        let payload = b"legacy-handshake";
        let header = LongHeader {
            ptype: LongPacketType::Handshake,
            version: umc_types::version::PROTOCOL_VERSION,
            dcid: vec![1u8; 8],
            scid: vec![2u8; 8],
            token: Vec::new(),
            payload_len: u64::try_from(1 + payload.len() + TAG_LEN).expect("length"),
            packet_number: 0,
            pn_bits: 8,
        }
        .encode()
        .expect("header");
        let ciphertext = keys.seal(0, &header, payload).expect("seal");
        let mut packet = header;
        packet.extend_from_slice(&ciphertext);
        assert!(parse_handshake_packet(&packet, &keys, 0).is_err());
    }
}
