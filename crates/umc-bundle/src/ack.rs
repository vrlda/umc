//! `BUNDLE_ACK` status mapping (wire-format.md §50, bundles.md §13).
use crate::manager::BundleStatus;
use umc_crypto::signatures::{IdentityKeyPair, IdentityPublicKey, PUBLIC_KEY_LEN, SIGNATURE_LEN};

const ACK_DOMAIN: &[u8] = b"UMP-BUNDLE-ACK-v1";
const ACK_AUTH_LEN: usize = PUBLIC_KEY_LEN + SIGNATURE_LEN;

/// Builds the canonical, domain-separated bytes covered by a bundle receipt.
/// The issuer and recipient endpoint IDs prevent a valid receipt being
/// replayed as an acknowledgement for a different peer or direction.
#[must_use]
pub fn signed_message(
    bundle_id: &[u8],
    status: u64,
    stored_until: u64,
    issuer_endpoint_id: &[u8; 32],
    recipient_endpoint_id: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ACK_DOMAIN.len() + 8 + bundle_id.len() + 8 + 8 + 64);
    out.extend_from_slice(ACK_DOMAIN);
    let bundle_len = u64::try_from(bundle_id.len()).unwrap_or(u64::MAX);
    out.extend_from_slice(&bundle_len.to_be_bytes());
    out.extend_from_slice(bundle_id);
    out.extend_from_slice(&status.to_be_bytes());
    out.extend_from_slice(&stored_until.to_be_bytes());
    out.extend_from_slice(issuer_endpoint_id);
    out.extend_from_slice(recipient_endpoint_id);
    out
}

/// Signs a receipt and returns `[issuer identity public key || signature]`.
#[must_use]
pub fn sign_auth(
    identity: &IdentityKeyPair,
    bundle_id: &[u8],
    status: u64,
    stored_until: u64,
    recipient_endpoint_id: &[u8; 32],
) -> Vec<u8> {
    let issuer_endpoint_id = umc_handshake::identity::endpoint_id(&identity.public());
    let message = signed_message(
        bundle_id,
        status,
        stored_until,
        &issuer_endpoint_id,
        recipient_endpoint_id,
    );
    let signature = identity.sign(&message);
    let mut auth = Vec::with_capacity(ACK_AUTH_LEN);
    auth.extend_from_slice(&identity.public().0);
    auth.extend_from_slice(&signature);
    auth
}

/// Verifies a receipt against the authenticated session peer and local node.
/// The public key is carried in the receipt only as a compact certificate: its
/// hash must equal the endpoint ID established by the UMP handshake.
#[must_use]
pub fn verify_auth(
    authentication: &[u8],
    bundle_id: &[u8],
    status: u64,
    stored_until: u64,
    expected_issuer_endpoint_id: &[u8; 32],
    recipient_endpoint_id: &[u8; 32],
) -> bool {
    if authentication.len() != ACK_AUTH_LEN {
        return false;
    }
    let Ok(public_key_bytes) = authentication[..PUBLIC_KEY_LEN].try_into() else {
        return false;
    };
    let public_key = IdentityPublicKey(public_key_bytes);
    let issuer_endpoint_id = umc_handshake::identity::endpoint_id(&public_key);
    if &issuer_endpoint_id != expected_issuer_endpoint_id {
        return false;
    }
    let message = signed_message(
        bundle_id,
        status,
        stored_until,
        &issuer_endpoint_id,
        recipient_endpoint_id,
    );
    public_key.verify(&message, &authentication[PUBLIC_KEY_LEN..])
}

/// Status values MUST match the wire registry (wire-format.md §50).
#[must_use]
pub fn status_code(status: &BundleStatus) -> u64 {
    match status {
        BundleStatus::Received => 0,
        BundleStatus::CustodyAccepted => 1,
        BundleStatus::Forwarded => 2,
        BundleStatus::Delivered => 3,
        BundleStatus::Rejected => 4,
        BundleStatus::Expired => 5,
        BundleStatus::Evicted => 6,
    }
}

#[must_use]
pub fn status_from_code(code: u64) -> Option<BundleStatus> {
    match code {
        0 => Some(BundleStatus::Received),
        1 => Some(BundleStatus::CustodyAccepted),
        2 => Some(BundleStatus::Forwarded),
        3 => Some(BundleStatus::Delivered),
        4 => Some(BundleStatus::Rejected),
        5 => Some(BundleStatus::Expired),
        6 => Some(BundleStatus::Evicted),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_receipt_round_trip_binds_direction_and_identity() {
        let issuer = IdentityKeyPair::from_seed([7; 32]);
        let issuer_endpoint = umc_handshake::identity::endpoint_id(&issuer.public());
        let recipient = [9; 32];
        let auth = sign_auth(&issuer, &[1; 32], 1, 1234, &recipient);
        assert!(verify_auth(
            &auth,
            &[1; 32],
            1,
            1234,
            &issuer_endpoint,
            &recipient
        ));
        assert!(!verify_auth(
            &auth,
            &[1; 32],
            3,
            1234,
            &issuer_endpoint,
            &recipient
        ));
        assert!(!verify_auth(
            &auth,
            &[1; 32],
            1,
            1234,
            &issuer_endpoint,
            &[8; 32]
        ));
    }

    #[test]
    fn codes_match_wire_registry() {
        assert_eq!(status_code(&BundleStatus::Received), 0);
        assert_eq!(status_code(&BundleStatus::CustodyAccepted), 1);
        assert_eq!(status_code(&BundleStatus::Forwarded), 2);
        assert_eq!(status_code(&BundleStatus::Delivered), 3);
        assert_eq!(status_code(&BundleStatus::Rejected), 4);
        assert_eq!(status_code(&BundleStatus::Expired), 5);
        assert_eq!(status_code(&BundleStatus::Evicted), 6);
    }

    #[test]
    fn round_trip() {
        for code in 0..=6 {
            assert_eq!(status_from_code(code).map(|s| status_code(&s)), Some(code));
        }
        assert!(status_from_code(7).is_none());
    }
}
