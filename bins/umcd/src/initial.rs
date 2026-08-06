//! Initial packet handling (wire-format §24-25): minimal long-header decode
//! and AEAD open with the client initial keys.
//!
//! `umc_wire` exposes the long-header *builder* (`LongHeader::encode`) but
//! no parser, so the minimal field decode lives here and mirrors the
//! builder's layout: header byte, version, DCID length + DCID, SCID length
//! + SCID, token length + token, payload length, PN bytes, ciphertext.
use umc_handshake::encoding::{self, CLIENT_HELLO};
use umc_handshake::initial::derive_initial_keys;
use umc_wire::header::{HeaderByte, LongPacketType};
use umc_wire::pn;
use umc_wire::varint;

/// A parsed client Initial packet: `(dcid, truncated_pn, payload, scid)`.
pub type ParsedInitial = (Vec<u8>, u64, Vec<u8>, Vec<u8>);

/// Decode a client Initial packet into a [`ParsedInitial`].
///
/// Returns `None` when the bytes are not an Initial long-header packet, the
/// header is malformed, or the AEAD open fails.
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
    let (token_len, n) = varint::decode(&bytes[pos..]).ok()?;
    pos += n;
    let token_len = usize::try_from(token_len).ok()?;
    pos = pos.checked_add(token_len)?;
    let (_payload_len, n) = varint::decode(&bytes[pos..]).ok()?;
    pos += n;
    let pn_bytes = (hb.pn_bits as usize) / 8;
    let protected_pn = bytes.get(pos..pos + pn_bytes)?;
    let mut pn_full = [0u8; 8];
    pn_full[8 - pn_bytes..].copy_from_slice(protected_pn);
    let truncated_pn = u64::from_be_bytes(pn_full);
    // AAD is the header up to and including the PN bytes (wire-format §25).
    let aad = bytes.get(..pos + pn_bytes)?;
    let keys = derive_initial_keys(&dcid).client;
    // The first Initial packet of a connection has packet number 0.
    let packet_number = pn::reconstruct(truncated_pn, hb.pn_bits, 0).ok()?;
    let payload = keys
        .open(packet_number, aad, bytes.get(pos + pn_bytes..)?)
        .ok()?;
    Some((dcid, truncated_pn, payload, scid))
}

/// Extract the raw `CLIENT_HELLO` message bytes from the first inbound
/// packet: either the decrypted Initial payload (which may carry the hello
/// as a raw body or inside a handshake stream envelope) or the raw hello
/// itself (`Node::connect` sends the hello unwrapped over the carrier).
///
/// # Errors
///
/// Returns a message when the bytes decode to neither a `CLIENT_HELLO`
/// body nor a handshake stream carrying one.
pub fn decode_client_hello(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if umc_handshake::xx::ClientHello::decode(bytes).is_ok() {
        return Ok(bytes.to_vec());
    }
    let (message, _) =
        encoding::decode_message(bytes).map_err(|e| format!("hello framing: {e:?}"))?;
    if message.message_type != CLIENT_HELLO {
        return Err(format!(
            "expected CLIENT_HELLO, got message type {}",
            message.message_type
        ));
    }
    Ok(message.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_crypto::signatures::StaticHandshakeKeyPair;
    use umc_handshake::xx::ClientHello;
    use umc_types::runtime::EntropySource;
    use umc_wire::header::{LongHeader, LongPacketType};

    struct TestEntropy;

    impl EntropySource for TestEntropy {
        fn fill(&self, out: &mut [u8]) {
            out.fill(0xAB);
        }
    }

    /// Synthetic Initial packet built with the wire crate's long-header
    /// builder and the client initial keys (the parse's mirror image).
    fn build_initial(dcid: &[u8], scid: &[u8], pn: u64, payload: &[u8]) -> Vec<u8> {
        let header = LongHeader {
            ptype: LongPacketType::Initial,
            version: 1,
            dcid: dcid.to_vec(),
            scid: scid.to_vec(),
            token: Vec::new(),
            payload_len: u64::try_from(payload.len() + 16).expect("fits u64"),
            packet_number: pn,
            pn_bits: 8,
        }
        .encode()
        .expect("header");
        let keys = derive_initial_keys(dcid).client;
        let ciphertext = keys.seal(pn, &header, payload).expect("seal");
        let mut out = header;
        out.extend_from_slice(&ciphertext);
        out
    }

    #[test]
    fn initial_round_trip_with_client_hello() {
        let hello = ClientHello::new(&TestEntropy, &StaticHandshakeKeyPair::generate());
        let hello_bytes = hello.encode().expect("hello");
        let mut payload = Vec::new();
        encoding::encode_message(&mut payload, CLIENT_HELLO, &hello_bytes).expect("envelope");
        let pkt = build_initial(&[1u8; 8], &[2u8; 8], 0, &payload);
        let (dcid, truncated_pn, parsed, scid) = try_parse_initial(&pkt).expect("parses");
        assert_eq!(dcid, vec![1u8; 8]);
        assert_eq!(scid, vec![2u8; 8]);
        assert_eq!(truncated_pn, 0);
        assert_eq!(parsed, payload);
        assert_eq!(decode_client_hello(&parsed).expect("hello"), hello_bytes);
    }

    #[test]
    fn raw_hello_decodes_without_initial_wrapper() {
        let hello = ClientHello::new(&TestEntropy, &StaticHandshakeKeyPair::generate());
        let raw = hello.encode().expect("hello");
        assert_eq!(decode_client_hello(&raw).expect("hello"), raw);
    }

    #[test]
    fn non_initial_bytes_rejected() {
        assert!(try_parse_initial(&[0x00, 0x01, 0x02]).is_none());
        // Long header, but the Retry packet type.
        assert!(try_parse_initial(&[0xA0, 0x00, 0x00, 0x00, 0x01]).is_none());
        assert!(decode_client_hello(b"garbage").is_err());
    }
}
