use umc_crypto::aead::PacketKeys;
use umc_wire::header::{HeaderByte, LongPacketType};

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
    pos = pos.checked_add(token_len)?;
    if pos > bytes.len() {
        return None;
    }
    let (_payload_len, n) = umc_wire::varint::decode(bytes.get(pos..)?).ok()?;
    pos = pos.checked_add(n)?;
    if pos > bytes.len() {
        return None;
    }
    let pn_bytes = (hb.pn_bits as usize) / 8;
    let protected_pn = bytes.get(pos..pos + pn_bytes)?;
    let mut pn_full = [0u8; 8];
    pn_full[8 - pn_bytes..].copy_from_slice(protected_pn);
    let truncated_pn = u64::from_be_bytes(pn_full);
    // AAD is the header up to and including the PN bytes (wire-format §25).
    let aad = bytes.get(..pos + pn_bytes)?;
    let keys = derive_initial_keys(&dcid).client;
    // The first Initial packet of a connection has packet number 0.
    let packet_number = umc_wire::pn::reconstruct(truncated_pn, hb.pn_bits, 0).ok()?;
    let payload = keys
        .open(packet_number, aad, bytes.get(pos + pn_bytes..)?)
        .ok()?;
    Some((dcid, truncated_pn, payload, scid))
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
}
