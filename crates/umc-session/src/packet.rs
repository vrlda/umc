use umc_crypto::aead::PacketKeys;
use umc_crypto::header_protection::{protect, unprotect};
use umc_wire::header::{HeaderByte, ShortPacketSpace};

pub const DEFAULT_PATH_ID: u64 = 0;

/// Read the routing-visible portion of a protected short header without
/// decrypting it. Header protection masks only key phase and packet number;
/// fixed-size DCID and path id remain available so a daemon can attach an
/// established-session packet to the correct session before it has the
/// session's traffic keys in hand.
///
/// This helper deliberately returns no packet number or payload. Callers
/// MUST still authenticate the complete packet with
/// [`parse_protected_packet`] before accepting it.
///
/// # Errors
///
/// Returns a packet/header error when the buffer is truncated or is not a
/// protected short-header packet.
pub fn peek_protected_header(
    bytes: &[u8],
) -> Result<(ShortPacketSpace, Vec<u8>, u64), PacketBuildError> {
    let first = *bytes.first().ok_or(PacketBuildError::TooLarge)?;
    let hb = umc_wire::header::HeaderByte::decode(first).map_err(PacketBuildError::Header)?;
    if hb.long {
        return Err(PacketBuildError::Header(
            umc_wire::header::HeaderError::InvalidType,
        ));
    }
    let space = hb.short_space().ok_or(PacketBuildError::Header(
        umc_wire::header::HeaderError::InvalidSpace,
    ))?;
    let dcid = bytes
        .get(1..1 + 8)
        .ok_or(PacketBuildError::TooLarge)?
        .to_vec();
    let (path_id, _) =
        umc_wire::varint::decode(bytes.get(1 + 8..).ok_or(PacketBuildError::TooLarge)?)
            .map_err(|_| PacketBuildError::TooLarge)?;
    Ok((space, dcid, path_id))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketBuildError {
    Header(umc_wire::header::HeaderError),
    Pn(umc_wire::pn::PnError),
    Aead(umc_crypto::aead::AeadError),
    TooLarge,
}

/// Build one protected short-header packet (wire-format §17).
///
/// The header protection key (`hp_key`, wire-format §18) is derived from
/// the sender's traffic secret via
/// [`umc_crypto::header_protection::header_protection_key`].
///
/// # Errors
///
/// Returns [`PacketBuildError::TooLarge`] if the packet would exceed
/// [`umc_types::version::MAX_PACKET_SIZE`], and
/// [`PacketBuildError::Aead`] if sealing fails.
#[allow(clippy::too_many_arguments)] // keys + hp key + space/dcid/path/pn/phase/payload
pub fn build_protected_packet(
    keys: &PacketKeys,
    hp_key: &[u8; 32],
    space: ShortPacketSpace,
    dcid: &[u8],
    path_id: u64,
    packet_number: u64,
    key_phase: bool,
    payload: &[u8],
) -> Result<Vec<u8>, PacketBuildError> {
    if payload.len() + 16 + 32 > umc_types::version::MAX_PACKET_SIZE {
        return Err(PacketBuildError::TooLarge);
    }
    let mut hb = match space {
        ShortPacketSpace::SessionData => HeaderByte::SHORT_SESSION,
        ShortPacketSpace::PathControl => HeaderByte::SHORT_PATH,
        ShortPacketSpace::RelayData => HeaderByte::SHORT_RELAY,
    };
    hb.key_phase = key_phase;
    hb.pn_bits = 16;
    let mut header = Vec::new();
    header.push(hb.encode());
    header.extend_from_slice(dcid);
    umc_wire::varint::encode_into(&mut header, path_id).map_err(|_| PacketBuildError::TooLarge)?;
    let mut pn_bytes = packet_number.to_be_bytes()[6..].to_vec();
    // Associated data: the complete UNPROTECTED header (handshake.md §28).
    // The AEAD seals over the plaintext header + pn; header protection
    // masks the sealed packet afterwards (wire-format §18).
    let mut aad = header.clone();
    aad.extend_from_slice(&pn_bytes);
    let ciphertext = keys
        .seal(packet_number, &aad, payload)
        .map_err(PacketBuildError::Aead)?;
    // Header protection AFTER sealing: the mask covers the pn bytes and
    // the key-phase bit of the first byte.
    let sample = ciphertext
        .get(..umc_crypto::header_protection::SAMPLE_LEN)
        .ok_or(PacketBuildError::TooLarge)?;
    let (protected_first, _) = protect(hp_key, hb.encode(), key_phase, sample, &mut pn_bytes);
    let mut out = header;
    out[0] = protected_first;
    out.extend_from_slice(&pn_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Parse a protected short-header packet. Returns
/// (`space`, `dcid`, `path_id`, `pn`, `payload`).
///
/// The header protection key (`hp_key`, wire-format §18) is derived from
/// the sender's traffic secret via
/// [`umc_crypto::header_protection::header_protection_key`].
///
/// The returned packet number is the truncated wire value; the session layer
/// reconstructs it with [`super::spaces::PacketSpaceState::admit_received`].
///
/// # Errors
///
/// Returns [`PacketBuildError::TooLarge`] if the buffer is truncated,
/// [`PacketBuildError::Header`] if the header form is invalid, and
/// [`PacketBuildError::Aead`] if authentication or decryption fails.
#[allow(clippy::type_complexity)]
pub fn parse_protected_packet(
    keys: &PacketKeys,
    hp_key: &[u8; 32],
    expected_pn: u64,
    bytes: &[u8],
) -> Result<(ShortPacketSpace, Vec<u8>, u64, u64, Vec<u8>), PacketBuildError> {
    let protected_first = *bytes.first().ok_or(PacketBuildError::TooLarge)?;
    // The mask covers only the key-phase bit (0x10) of the first byte, so
    // the form, space, and pn-length fields survive and the pn field can be
    // located before unprotection.
    let pn_len = (umc_wire::header::HeaderByte::decode(protected_first)
        .map_err(PacketBuildError::Header)?
        .pn_bits as usize)
        / 8;
    let mut pos = 1usize;
    let dcid_len = 8usize; // negotiated in Phase 1 as fixed 8 bytes
    let dcid = bytes
        .get(pos..pos + dcid_len)
        .ok_or(PacketBuildError::TooLarge)?
        .to_vec();
    pos += dcid_len;
    let (path_id, n) =
        umc_wire::varint::decode(&bytes[pos..]).map_err(|_| PacketBuildError::TooLarge)?;
    pos += n;
    let pn_bytes = bytes
        .get(pos..pos + pn_len)
        .ok_or(PacketBuildError::TooLarge)?;
    let sample = bytes
        .get(pos + pn_len..pos + pn_len + umc_crypto::header_protection::SAMPLE_LEN)
        .ok_or(PacketBuildError::TooLarge)?;
    // Unprotect FIRST (wire-format §18): the packet number and the first
    // byte are masked; the pn and the header byte are meaningful only after
    // unprotection.
    let (first, _phase, unprotected_pn) = unprotect(hp_key, protected_first, sample, pn_bytes);
    let hb = umc_wire::header::HeaderByte::decode(first).map_err(PacketBuildError::Header)?;
    if hb.long {
        return Err(PacketBuildError::Header(
            umc_wire::header::HeaderError::InvalidType,
        ));
    }
    let space = hb.short_space().ok_or(PacketBuildError::Header(
        umc_wire::header::HeaderError::InvalidSpace,
    ))?;
    let mut pn_full = [0u8; 8];
    pn_full[8 - pn_len..].copy_from_slice(&unprotected_pn);
    let truncated_pn = u64::from_be_bytes(pn_full);
    // Reconstruct the FULL packet number before the AEAD open: the sender
    // seals with the full pn, so opening with the truncated value would
    // diverge after pn 65 535 (nonce mismatch, session breakage).
    let pn = umc_wire::pn::reconstruct(truncated_pn, hb.pn_bits, expected_pn)
        .map_err(PacketBuildError::Pn)?;
    // Associated data: the complete UNPROTECTED header (handshake.md §28):
    // the masked first byte and pn are restored before the AEAD open.
    let mut aad = bytes[..pos].to_vec();
    aad[0] = first;
    aad.extend_from_slice(&unprotected_pn);
    pos += pn_len;
    let payload = keys
        .open(pn, &aad, &bytes[pos..])
        .map_err(PacketBuildError::Aead)?;
    Ok((space, dcid, path_id, pn, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hp(secret: &[u8; 32]) -> [u8; 32] {
        umc_crypto::header_protection::header_protection_key(secret)
    }

    #[test]
    fn build_parse_round_trip() {
        let secret = [1u8; 32];
        let keys = PacketKeys::from_traffic_secret(&secret).unwrap();
        let dcid = vec![7u8; 8];
        let pkt = build_protected_packet(
            &keys,
            &hp(&secret),
            ShortPacketSpace::SessionData,
            &dcid,
            0,
            42,
            false,
            b"frames",
        )
        .unwrap();
        let (space, d, path, pn, payload) =
            parse_protected_packet(&keys, &hp(&secret), 0, &pkt).unwrap();
        assert_eq!(space, ShortPacketSpace::SessionData);
        assert_eq!(d, dcid);
        assert_eq!(path, 0);
        assert_eq!(pn, 42);
        assert_eq!(payload, b"frames");
    }

    #[test]
    fn peek_header_routes_without_keys() {
        let secret = [1u8; 32];
        let keys = PacketKeys::from_traffic_secret(&secret).unwrap();
        let dcid = vec![7u8; 8];
        let pkt = build_protected_packet(
            &keys,
            &hp(&secret),
            ShortPacketSpace::SessionData,
            &dcid,
            9,
            1,
            false,
            b"frames",
        )
        .unwrap();
        let (space, peek_dcid, path_id) = peek_protected_header(&pkt).unwrap();
        assert_eq!(space, ShortPacketSpace::SessionData);
        assert_eq!(peek_dcid, dcid);
        assert_eq!(path_id, 9);
    }

    #[test]
    fn wrong_key_fails_parse() {
        let a = PacketKeys::from_traffic_secret(&[1u8; 32]).unwrap();
        let b = PacketKeys::from_traffic_secret(&[2u8; 32]).unwrap();
        let dcid = vec![7u8; 8];
        let pkt = build_protected_packet(
            &a,
            &hp(&[1u8; 32]),
            ShortPacketSpace::SessionData,
            &dcid,
            0,
            1,
            false,
            b"x",
        )
        .unwrap();
        assert!(parse_protected_packet(&b, &hp(&[2u8; 32]), 0, &pkt).is_err());
    }

    #[test]
    fn protected_packet_hides_pn_bytes() {
        let secret = [1u8; 32];
        let keys = PacketKeys::from_traffic_secret(&secret).unwrap();
        let dcid = vec![7u8; 8];
        let pkt = build_protected_packet(
            &keys,
            &hp(&secret),
            ShortPacketSpace::SessionData,
            &dcid,
            0,
            42,
            false,
            b"frames",
        )
        .unwrap();
        // Layout: first byte (1) + dcid (8) + path varint (1) + pn (2).
        let pn_off = 1 + dcid.len() + 1;
        let plain_pn = 42u64.to_be_bytes()[6..].to_vec();
        assert_ne!(
            &pkt[pn_off..pn_off + 2],
            plain_pn.as_slice(),
            "the wire pn bytes are masked"
        );
        // The round trip still recovers the plaintext packet number.
        let (_space, _d, _path, pn, _payload) =
            parse_protected_packet(&keys, &hp(&secret), 0, &pkt).unwrap();
        assert_eq!(pn, 42);
    }

    #[test]
    fn wrong_hp_key_fails_parse() {
        let secret = [1u8; 32];
        let keys = PacketKeys::from_traffic_secret(&secret).unwrap();
        let dcid = vec![7u8; 8];
        let pkt = build_protected_packet(
            &keys,
            &hp(&secret),
            ShortPacketSpace::SessionData,
            &dcid,
            0,
            1,
            false,
            b"x",
        )
        .unwrap();
        // Same AEAD keys, wrong hp key: the pn misreads, so the nonce and
        // AAD no longer match and the open must fail.
        assert!(parse_protected_packet(&keys, &hp(&[2u8; 32]), 0, &pkt).is_err());
    }
}
