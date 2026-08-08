#![no_main]

use libfuzzer_sys::fuzz_target;
use umc_crypto::signatures::{IdentityPublicKey, StaticHandshakePublicKey};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + 32 + 32 + 8 + 8 + 8 + 32 + 64 {
        return;
    }
    let mut offset = 0;
    let mut endpoint_id = [0u8; 32];
    endpoint_id.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let mut identity = [0u8; 32];
    identity.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let mut static_key = [0u8; 32];
    static_key.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let read_u64 = |bytes: &[u8]| u64::from_be_bytes(bytes.try_into().unwrap());
    let not_before = read_u64(&data[offset..offset + 8]);
    offset += 8;
    let not_after = read_u64(&data[offset..offset + 8]);
    offset += 8;
    let sequence = read_u64(&data[offset..offset + 8]);
    offset += 8;
    let mut capabilities_hash = [0u8; 32];
    capabilities_hash.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[offset..offset + 64]);
    let binding = umc_handshake::identity::IdentityBinding {
        version: data[0],
        endpoint_id,
        identity_public_key: IdentityPublicKey(identity),
        static_handshake_public_key: StaticHandshakePublicKey(static_key),
        not_before,
        not_after,
        sequence,
        capabilities_hash,
        signature,
    };
    let _ = binding.validate(0, 0);
});
