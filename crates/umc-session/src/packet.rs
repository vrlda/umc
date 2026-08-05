use umc_crypto::aead::PacketKeys;
use umc_wire::header::{HeaderByte, ShortPacketSpace};

pub const DEFAULT_PATH_ID: u64 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketBuildError {
    Header(umc_wire::header::HeaderError),
    Aead(umc_crypto::aead::AeadError),
    TooLarge,
}

/// Build one protected short-header packet (wire-format §17).
///
/// # Errors
///
/// Returns [`PacketBuildError::TooLarge`] if the packet would exceed
/// [`umc_types::version::MAX_PACKET_SIZE`], and
/// [`PacketBuildError::Aead`] if sealing fails.
pub fn build_protected_packet(
    keys: &PacketKeys,
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
    let pn_bytes = packet_number.to_be_bytes()[6..].to_vec();
    // Associated data: the complete unencrypted header (handshake.md §28).
    let mut aad = header.clone();
    aad.extend_from_slice(&pn_bytes);
    let ciphertext = keys
        .seal(packet_number, &aad, payload)
        .map_err(PacketBuildError::Aead)?;
    let mut out = header;
    out.extend_from_slice(&pn_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Parse a protected short-header packet. Returns
/// (`space`, `dcid`, `path_id`, `pn`, `payload`).
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
    bytes: &[u8],
) -> Result<(ShortPacketSpace, Vec<u8>, u64, u64, Vec<u8>), PacketBuildError> {
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
    let pn_len = (hb.pn_bits as usize) / 8;
    let pn_bytes = bytes
        .get(pos..pos + pn_len)
        .ok_or(PacketBuildError::TooLarge)?;
    let mut pn_full = [0u8; 8];
    pn_full[8 - pn_len..].copy_from_slice(pn_bytes);
    let truncated_pn = u64::from_be_bytes(pn_full);
    // Associated data: the complete unencrypted header (handshake.md §28).
    let mut aad = bytes[..pos].to_vec();
    aad.extend_from_slice(pn_bytes);
    pos += pn_len;
    let payload = keys
        .open(truncated_pn, &aad, &bytes[pos..])
        .map_err(PacketBuildError::Aead)?;
    Ok((space, dcid, path_id, truncated_pn, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_parse_round_trip() {
        let keys = PacketKeys::from_traffic_secret(&[1u8; 32]).unwrap();
        let dcid = vec![7u8; 8];
        let pkt = build_protected_packet(
            &keys,
            ShortPacketSpace::SessionData,
            &dcid,
            0,
            42,
            false,
            b"frames",
        )
        .unwrap();
        let (space, d, path, pn, payload) = parse_protected_packet(&keys, &pkt).unwrap();
        assert_eq!(space, ShortPacketSpace::SessionData);
        assert_eq!(d, dcid);
        assert_eq!(path, 0);
        assert_eq!(pn, 42);
        assert_eq!(payload, b"frames");
    }

    #[test]
    fn wrong_key_fails_parse() {
        let a = PacketKeys::from_traffic_secret(&[1u8; 32]).unwrap();
        let b = PacketKeys::from_traffic_secret(&[2u8; 32]).unwrap();
        let dcid = vec![7u8; 8];
        let pkt =
            build_protected_packet(&a, ShortPacketSpace::SessionData, &dcid, 0, 1, false, b"x")
                .unwrap();
        assert!(parse_protected_packet(&b, &pkt).is_err());
    }
}
