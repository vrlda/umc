//! Initial packet handling (wire-format §24-25): minimal long-header decode
//! and AEAD open with the client initial keys.
//!
//! The parser lives in `umc_handshake::initial` (Phase 13 hardening added
//! bounds checks so hostile length fields are rejected, never panicked);
//! this module re-exports it for the daemon's accept path.
use umc_handshake::encoding::{self, CLIENT_HELLO};
use umc_wire::header::{LongHeader, LongPacketType};

pub use umc_handshake::initial::try_parse_initial;

/// Build an Initial-protected packet (wire-format §13): a long-header
/// Initial carrying `payload` sealed with `keys`, padded with PADDING
/// frames so the whole packet reaches the carrier's minimum Initial size
/// (1,200 bytes). The AAD is the encoded header up to and including the
/// packet-number bytes — the exact convention `try_parse_initial` uses to
/// open the packet.
///
/// # Errors
///
/// Returns a message when the header cannot be encoded or the AEAD seal
/// fails.
pub fn build_initial_packet(
    dcid: &[u8],
    scid: &[u8],
    pn: u64,
    payload: &[u8],
    keys: &umc_crypto::aead::PacketKeys,
) -> Result<Vec<u8>, String> {
    let tag_len = umc_crypto::aead::TAG_LEN;
    let mut plaintext = payload.to_vec();
    // Add one PADDING frame (0x00) per pass until the packet reaches the
    // minimum Initial size. The header length is monotonic in the payload
    // length varint, so the loop terminates within MIN_INITIAL_UDP passes.
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
        .map_err(|e| format!("header: {e:?}"))?;
        if header.len() + plaintext.len() + tag_len >= umc_types::version::MIN_INITIAL_UDP {
            let ciphertext = keys
                .seal(pn, &header, &plaintext)
                .map_err(|e| format!("seal: {e:?}"))?;
            let mut out = header;
            out.extend_from_slice(&ciphertext);
            return Ok(out);
        }
        plaintext.push(0x00);
    }
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
    if let Ok(hello) = umc_handshake::xx::ClientHello::decode(bytes) {
        // Re-encode the canonical form: an Initial payload may carry
        // PADDING frames after the hello (wire-format §13) that `decode`
        // ignores, and the transcript must bind the hello bytes only.
        // The codec round-trips exactly, so the raw path is unchanged.
        return hello
            .encode()
            .map_err(|e| format!("hello re-encode: {e:?}"));
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
    use umc_handshake::xx::{ClientHello, ServerHello};
    use umc_types::runtime::EntropySource;
    use umc_wire::header::{LongHeader, LongPacketType};

    struct TestEntropy;

    impl EntropySource for TestEntropy {
        fn fill(&self, out: &mut [u8]) {
            out.fill(0xAB);
        }
    }

    /// The outbound Initial builder: an Initial-protected `SERVER_HELLO`
    /// parses back with the wire parser (`try_parse_initial` decrypts with
    /// the client initial keys, so the packet is built with those), the
    /// packet is padded to the 1,200-byte minimum Initial size, and the
    /// decrypted payload leads with the hello bytes followed by PADDING
    /// frames.
    #[test]
    fn server_hello_initial_round_trip() {
        let hello = ServerHello {
            server_random: [7u8; 32],
            server_ephemeral_public_key: [8u8; 32],
            selected_protocol_version: 1,
            selected_crypto_profile: b"UMP-CRYPTO-1".to_vec(),
            selected_handshake_mode: b"XX".to_vec(),
            encrypted_server_authentication: vec![9u8; 128],
            padding: vec![0u8; 32],
        }
        .encode()
        .expect("hello");
        let dcid = vec![1u8; 8];
        let scid = vec![2u8; 8];
        let keys = derive_initial_keys(&dcid);
        let pkt = build_initial_packet(&dcid, &scid, 0, &hello, &keys.client).expect("build");
        assert!(
            pkt.len() >= umc_types::version::MIN_INITIAL_UDP,
            "Initial must be padded to >= 1,200 bytes, got {}",
            pkt.len()
        );
        let (parsed_dcid, pn, payload, parsed_scid) = try_parse_initial(&pkt).expect("parses");
        assert_eq!(parsed_dcid, dcid);
        assert_eq!(parsed_scid, scid);
        assert_eq!(pn, 0);
        assert!(
            payload.starts_with(&hello),
            "decrypted payload leads with the hello bytes"
        );
        assert!(
            payload[hello.len()..].iter().all(|&b| b == 0),
            "payload tail after the hello is PADDING frames"
        );
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
