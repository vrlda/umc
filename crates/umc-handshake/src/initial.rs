use umc_crypto::aead::PacketKeys;
use umc_crypto::header_protection::{protect, unprotect, SAMPLE_LEN};
use umc_wire::header::{HeaderByte, LongHeader, LongPacketType};

/// Provisional `InitialSalt` for v0.1 (handshake.md §12). Fixed per version.
/// Value is provisional until interop freeze.
pub const INITIAL_SALT: [u8; 32] = {
    let mut salt = [0u8; 32];
    let label = b"UMP-1-INITIAL-SALT";
    let mut i = 0;
    while i < label.len() && i < 32 {
        salt[i] = label[i];
        i += 1;
    }
    salt
};

#[derive(Debug, Clone)]
pub struct InitialKeys {
    pub client: PacketKeys,
    pub server: PacketKeys,
}

/// Initial secret derivation (handshake.md §12).
///
/// # Panics
/// Panics if label expansion or packet-key derivation fails (32-byte
/// expansion cannot fail).
#[must_use]
pub fn derive_initial_keys(destination_connection_id: &[u8]) -> InitialKeys {
    let initial_secret = umc_crypto::hkdf::extract(&INITIAL_SALT, destination_connection_id);
    let client_secret = derive(initial_secret, b"client initial");
    let server_secret = derive(initial_secret, b"server initial");
    InitialKeys {
        client: PacketKeys::from_traffic_secret(&client_secret).expect("32-byte key"),
        server: PacketKeys::from_traffic_secret(&server_secret).expect("32-byte key"),
    }
}

/// Build a protected Initial packet carrying `payload` (wire-format §13).
///
/// The payload is padded to the carrier's minimum Initial size before sealing;
/// the packet number is then header-protected with the same traffic key. This
/// is the canonical packet constructor shared by clients, daemon fixtures,
/// and protocol conformance tests.
///
/// # Errors
///
/// Returns an error when the header cannot be encoded, the payload length is
/// not representable, or sealing/header protection cannot be applied.
pub fn build_initial_packet(
    dcid: &[u8],
    scid: &[u8],
    pn: u64,
    payload: &[u8],
    keys: &PacketKeys,
) -> Result<Vec<u8>, String> {
    let tag_len = umc_crypto::aead::TAG_LEN;
    let mut plaintext = payload.to_vec();
    loop {
        let header = LongHeader {
            ptype: LongPacketType::Initial,
            version: umc_types::version::PROTOCOL_VERSION,
            dcid: dcid.to_vec(),
            scid: scid.to_vec(),
            token: Vec::new(),
            payload_len: u64::try_from(plaintext.len() + tag_len)
                .map_err(|_| "payload too large".to_string())?,
            packet_number: pn,
            pn_bits: 8,
        }
        .encode()
        .map_err(|error| format!("header: {error:?}"))?;
        if header.len() + plaintext.len() + tag_len >= umc_types::version::MIN_INITIAL_UDP {
            let ciphertext = keys
                .seal(pn, &header, &plaintext)
                .map_err(|error| format!("seal: {error:?}"))?;
            let pn_offset = header
                .len()
                .checked_sub(1)
                .ok_or_else(|| "initial header missing packet number".to_string())?;
            let sample = ciphertext
                .get(..SAMPLE_LEN)
                .ok_or_else(|| "initial payload too short for header protection".to_string())?;
            let mut pn_bytes = header[pn_offset..].to_vec();
            let (protected_first, _) =
                protect(&keys.hp_key, header[0], false, sample, &mut pn_bytes);
            let mut packet = header[..pn_offset].to_vec();
            packet[0] = protected_first;
            packet.extend_from_slice(&pn_bytes);
            packet.extend_from_slice(&ciphertext);
            return Ok(packet);
        }
        plaintext.push(0);
    }
}

fn derive(initial_secret: [u8; 32], label: &[u8]) -> [u8; 32] {
    let out = umc_crypto::label::expand_label(&initial_secret, label, b"", 32)
        .expect("32-byte expansion");
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&out);
    secret
}

/// A parsed client Initial packet: `(dcid, truncated_pn, payload, scid)`.
pub type ParsedInitial = (Vec<u8>, u64, Vec<u8>, Vec<u8>);

/// Decode a client Initial packet into a [`ParsedInitial`] (wire-format §24-25).
///
/// Returns `None` when the bytes are not an Initial long-header packet, the
/// header is malformed, or the AEAD open fails. Length fields are
/// bounds-checked before any copy and the payload is never pre-allocated
/// from untrusted lengths, so oversized or hostile buffers are rejected in
/// bounded time (handshake.md §15, resource-limits.md §49).
#[must_use]
pub fn try_parse_initial(bytes: &[u8]) -> Option<ParsedInitial> {
    let dcid = initial_dcid(bytes)?;
    let keys = derive_initial_keys(&dcid).client;
    parse_initial_with_keys(bytes, &keys)
}

/// Parse an Initial packet with caller-selected packet keys. This is used for
/// the server's Initial response, whose DCID echoes the client's SCID while
/// its keys still derive from the client's original destination ID.
#[must_use]
pub fn parse_initial_with_keys(bytes: &[u8], keys: &PacketKeys) -> Option<ParsedInitial> {
    parse_initial_protected(bytes, keys)
}

fn parse_initial_protected(bytes: &[u8], keys: &PacketKeys) -> Option<ParsedInitial> {
    let hb = HeaderByte::decode(*bytes.first()?).ok()?;
    if !hb.long || hb.long_type()? != LongPacketType::Initial {
        return None;
    }
    let dcid_len = usize::from(*bytes.get(5)?);
    let dcid = bytes.get(6..6 + dcid_len)?.to_vec();
    let scid_len = usize::from(*bytes.get(6 + dcid_len)?);
    let scid = bytes.get(7 + dcid_len..7 + dcid_len + scid_len)?.to_vec();
    let mut pos = 7 + dcid_len + scid_len;
    let (token_len, n) = umc_wire::varint::decode(bytes.get(pos..)?).ok()?;
    pos += n;
    let token_len = usize::try_from(token_len).ok()?;
    if token_len > umc_types::version::MAX_TOKEN_LEN {
        return None;
    }
    pos = pos.checked_add(token_len)?;
    if pos > bytes.len() {
        return None;
    }
    let (payload_len, n) = umc_wire::varint::decode(bytes.get(pos..)?).ok()?;
    pos = pos.checked_add(n)?;
    if pos > bytes.len() {
        return None;
    }
    // Initial builders encode the length of the encrypted payload (the
    // packet-number bytes are outside that field), unlike the Handshake
    // helper's legacy layout which includes the PN. Keep this parser aligned
    // with the Initial wire form and require an exact packet boundary.
    let ciphertext_len = usize::try_from(payload_len).ok()?;
    // The packet-number length bits are themselves header-protected. Derive
    // the width from the exact packet boundary instead of trusting the
    // masked first byte; otherwise a protection sample that flips those bits
    // shifts the ciphertext offset and makes a valid packet fail open.
    let pn_bytes = bytes.len().checked_sub(pos)?.checked_sub(ciphertext_len)?;
    if !matches!(pn_bytes, 1 | 2 | 4 | 8) {
        return None;
    }
    let protected_pn = bytes.get(pos..pos + pn_bytes)?;
    let ciphertext_start = pos.checked_add(pn_bytes)?;
    let ciphertext = bytes.get(ciphertext_start..ciphertext_start.checked_add(ciphertext_len)?)?;
    if ciphertext.len() != ciphertext_len || ciphertext_start + ciphertext_len != bytes.len() {
        return None;
    }
    let sample = ciphertext.get(..SAMPLE_LEN)?;
    let (unprotected_first, _key_phase, unprotected_pn) =
        unprotect(&keys.hp_key, hb.encode(), sample, protected_pn);
    let unprotected_hb = HeaderByte::decode(unprotected_first).ok()?;
    if !unprotected_hb.long
        || unprotected_hb.long_type()? != LongPacketType::Initial
        || unprotected_hb.pn_bits != u32::try_from(pn_bytes * 8).ok()?
    {
        return None;
    }
    let mut pn_full = [0u8; 8];
    pn_full[8 - pn_bytes..].copy_from_slice(&unprotected_pn);
    let truncated_pn = u64::from_be_bytes(pn_full);
    // The first Initial packet of a connection has packet number 0.
    let packet_number = umc_wire::pn::reconstruct(truncated_pn, hb.pn_bits, 0).ok()?;
    // AAD is the complete unprotected header, including the restored PN.
    let mut aad = bytes.get(..ciphertext_start)?.to_vec();
    aad[0] = unprotected_first;
    aad[ciphertext_start - pn_bytes..].copy_from_slice(&unprotected_pn);
    let payload = keys.open(packet_number, &aad, ciphertext).ok()?;
    Some((dcid, truncated_pn, payload, scid))
}

fn initial_dcid(bytes: &[u8]) -> Option<Vec<u8>> {
    let hb = HeaderByte::decode(*bytes.first()?).ok()?;
    if !hb.long || hb.long_type()? != LongPacketType::Initial {
        return None;
    }
    let dcid_len = usize::from(*bytes.get(5)?);
    bytes.get(6..6 + dcid_len).map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_and_server_keys_differ() {
        let keys = derive_initial_keys(&[1, 2, 3, 4]);
        assert_ne!(keys.client.key, keys.server.key);
        assert_ne!(keys.client.iv, keys.server.iv);
    }

    #[test]
    fn keys_depend_on_destination_connection_id() {
        let a = derive_initial_keys(&[1, 2, 3, 4]);
        let b = derive_initial_keys(&[1, 2, 3, 5]);
        assert_ne!(a.client.key, b.client.key);
    }

    #[test]
    fn initial_seal_open_works() {
        let keys = derive_initial_keys(&[9; 8]);
        let aad = b"public header";
        let ct = keys.client.seal(0, aad, b"initial payload").unwrap();
        let pt = keys.client.open(0, aad, &ct).unwrap();
        assert_eq!(pt, b"initial payload");
        // Server keys cannot decrypt client packets.
        assert!(keys.server.open(0, aad, &ct).is_err());
    }

    #[test]
    fn protected_initial_pn_mask_never_changes_ciphertext_offset() {
        let dcid = [4u8; 8];
        let scid = [5u8; 8];
        let keys = derive_initial_keys(&dcid).client;
        for packet_number in 0..128 {
            let packet = build_initial_packet(
                &dcid,
                &scid,
                packet_number,
                b"header-protection-offset",
                &keys,
            )
            .expect("initial packet");
            let (_, truncated, payload, parsed_scid) =
                try_parse_initial(&packet).expect("protected initial parses");
            assert_eq!(truncated, packet_number);
            assert_eq!(parsed_scid, scid);
            assert!(payload.starts_with(b"header-protection-offset"));
        }
    }
}
