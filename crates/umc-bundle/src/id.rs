//! Bundle ID (bundles.md §6): provisional construction; deduplicates without
//! exposing contents.
use crate::envelope::BundleEnvelope;
use blake2::{Blake2s256, Digest};

pub const BUNDLE_ID_LEN: usize = 32;

/// `BundleID` = `BLAKE2s-256`("UMP-BUNDLE-ID-v1" || `encrypted_payload_hash` ||
/// `destination_hint_hash`) (bundles.md §6.2). Final derivation is an open
/// design decision before v0.2.
#[must_use]
pub fn bundle_id(envelope: &BundleEnvelope, destination_hint: &[u8]) -> [u8; BUNDLE_ID_LEN] {
    let payload_hash: [u8; 32] = {
        let mut hasher = Blake2s256::new();
        hasher.update(&envelope.encrypted_payload);
        hasher.finalize().into()
    };
    let hint_hash: [u8; 32] = {
        let mut hasher = Blake2s256::new();
        hasher.update(destination_hint);
        hasher.finalize().into()
    };
    let mut hasher = Blake2s256::new();
    hasher.update(b"UMP-BUNDLE-ID-v1");
    hasher.update(payload_hash);
    hasher.update(hint_hash);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_crypto::signatures::StaticHandshakeKeyPair;

    fn envelope() -> BundleEnvelope {
        let sender = StaticHandshakeKeyPair::generate();
        let destination = StaticHandshakeKeyPair::generate();
        crate::envelope::seal_bundle(&sender, &destination.public(), b"payload")
    }

    #[test]
    fn id_is_stable_and_content_bound() {
        let e = envelope();
        let a = bundle_id(&e, b"dest-1");
        let b = bundle_id(&e, b"dest-1");
        let c = bundle_id(&e, b"dest-2");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn id_does_not_expose_plaintext() {
        let sender = StaticHandshakeKeyPair::generate();
        let destination = StaticHandshakeKeyPair::generate();
        let e1 = crate::envelope::seal_bundle(&sender, &destination.public(), b"plaintext-A");
        let e2 = crate::envelope::seal_bundle(&sender, &destination.public(), b"plaintext-B");
        // Same sender/dest hint: IDs differ because the payloads differ.
        assert_ne!(bundle_id(&e1, b"d"), bundle_id(&e2, b"d"));
    }
}
