//! Initial packet handling (wire-format §24-25): minimal long-header decode
//! and AEAD open with the client initial keys.
//!
//! The parser lives in `umc_handshake::initial` (Phase 13 hardening added
//! bounds checks so hostile length fields are rejected, never panicked);
//! this module re-exports it for the daemon's accept path.
use umc_handshake::encoding::{self, CLIENT_HELLO};

pub use umc_handshake::initial::try_parse_initial;

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
    use umc_handshake::initial::derive_initial_keys;
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

    #[test]
    fn hostile_oversized_token_length_does_not_panic() {
        // A valid Initial long-header prefix (0xC0: long, Initial, 8-bit PN),
        // then a token length varint declaring a body far beyond the buffer.
        // The pre-hardening parser indexed past the buffer and panicked here.
        let mut buf = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 8];
        buf.extend_from_slice(&[1u8; 8]);
        buf.push(8);
        buf.extend_from_slice(&[2u8; 8]);
        umc_wire::varint::encode_into(&mut buf, 1_000_000).expect("varint");
        assert!(try_parse_initial(&buf).is_none());
        // MAX_VARINT token length: checked arithmetic must reject, not wrap.
        let mut buf = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 8];
        buf.extend_from_slice(&[1u8; 8]);
        buf.push(8);
        buf.extend_from_slice(&[2u8; 8]);
        umc_wire::varint::encode_into(&mut buf, umc_wire::varint::MAX_VARINT).expect("varint");
        assert!(try_parse_initial(&buf).is_none());
    }
}
