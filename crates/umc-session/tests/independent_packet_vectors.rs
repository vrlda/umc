//! Independent packet vectors generated with Python `cryptography`.
//!
//! The packet bytes are literals: this test does not call the UMP packet
//! builder to produce its input, so it catches drift in HKDF labels, nonce
//! construction, AEAD associated data, and short-header protection.

use umc_crypto::aead::PacketKeys;
use umc_crypto::header_protection::header_protection_key;
use umc_session::packet::parse_protected_packet;
use umc_wire::header::ShortPacketSpace;

fn bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex vector"))
        .collect()
}

#[test]
fn python_protected_session_packet_parses() {
    let secret: [u8; 32] =
        bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .try_into()
            .expect("secret length");
    let keys = PacketKeys::from_traffic_secret(&secret).expect("packet keys");
    let packet = bytes("14010203040506070800e2d146f33eacb0e06aec527ce2dc57a4391a69");
    let (space, dcid, path_id, packet_number, payload) =
        parse_protected_packet(&keys, &header_protection_key(&secret), 0, &packet)
            .expect("independent packet vector");
    assert_eq!(space, ShortPacketSpace::SessionData);
    assert_eq!(dcid, bytes("0102030405060708"));
    assert_eq!(path_id, 0);
    assert_eq!(packet_number, 1);
    assert_eq!(payload, bytes("04"));
}
