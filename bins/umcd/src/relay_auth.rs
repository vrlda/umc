//! Relay-open authorization (relay.md §11.5).
//!
//! A relay authorization is an operator-issued, bounded capability. The
//! v1 wire shape is endpoint id (32 bytes), expiry (big-endian u64), nonce
//! (16 bytes), and an HMAC-BLAKE2s tag (32 bytes). The HMAC key is the relay
//! identity seed kept inside the daemon; it never crosses the carrier or
//! control boundaries. Empty authorization remains accepted for the legacy
//! public-relay path so existing peers can migrate, while any supplied value
//! is fail-closed and must verify.

use blake2::digest::{KeyInit, Mac};
use umc_crypto::signatures::IdentityKeyPair;
use umc_handshake::identity::endpoint_id;

const DOMAIN: &[u8] = b"UMP-RELAY-AUTH-v1";
const ENDPOINT_LEN: usize = 32;
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 32;
const WIRE_LEN: usize = ENDPOINT_LEN + 8 + NONCE_LEN + TAG_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAuthorization {
    pub relay_endpoint_id: [u8; ENDPOINT_LEN],
    pub expires_at_ms: u64,
    pub nonce: [u8; NONCE_LEN],
    tag: [u8; TAG_LEN],
}

impl RelayAuthorization {
    /// Issue an authorization for this relay identity. Production callers
    /// should persist the nonce/expiry in their operator workflow and keep
    /// the returned bytes opaque to untrusted applications.
    #[must_use]
    #[allow(dead_code)]
    pub fn issue(
        identity: &IdentityKeyPair,
        expires_at_ms: u64,
        nonce: [u8; NONCE_LEN],
    ) -> Vec<u8> {
        let relay_endpoint_id = endpoint_id(&identity.public());
        let mut auth = Self {
            relay_endpoint_id,
            expires_at_ms,
            nonce,
            tag: [0u8; TAG_LEN],
        };
        auth.tag = auth.compute_tag(identity);
        auth.encode()
    }

    /// Decode the fixed-size authorization wire value.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != WIRE_LEN {
            return Err(format!(
                "relay authorization length {} (expected {WIRE_LEN})",
                bytes.len()
            ));
        }
        let relay_endpoint_id = bytes[..ENDPOINT_LEN]
            .try_into()
            .map_err(|_| "relay authorization endpoint id")?;
        let expires_at_ms = u64::from_be_bytes(
            bytes[ENDPOINT_LEN..ENDPOINT_LEN + 8]
                .try_into()
                .map_err(|_| "relay authorization expiry")?,
        );
        let nonce = bytes[ENDPOINT_LEN + 8..ENDPOINT_LEN + 8 + NONCE_LEN]
            .try_into()
            .map_err(|_| "relay authorization nonce")?;
        let tag = bytes[ENDPOINT_LEN + 8 + NONCE_LEN..]
            .try_into()
            .map_err(|_| "relay authorization tag")?;
        Ok(Self {
            relay_endpoint_id,
            expires_at_ms,
            nonce,
            tag,
        })
    }

    /// Verify endpoint binding, expiry, and the identity-seed HMAC.
    pub fn verify(&self, identity: &IdentityKeyPair, now_ms: u64) -> Result<(), String> {
        let expected_endpoint = endpoint_id(&identity.public());
        if self.relay_endpoint_id != expected_endpoint {
            return Err("relay authorization endpoint mismatch".into());
        }
        if now_ms >= self.expires_at_ms {
            return Err("relay authorization expired".into());
        }
        let expected_tag = self.compute_tag(identity);
        let mut diff = 0u8;
        for (actual, expected) in self.tag.iter().zip(expected_tag) {
            diff |= actual ^ expected;
        }
        if diff != 0 {
            return Err("relay authorization MAC mismatch".into());
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(WIRE_LEN);
        bytes.extend_from_slice(&self.relay_endpoint_id);
        bytes.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.tag);
        bytes
    }

    fn compute_tag(&self, identity: &IdentityKeyPair) -> [u8; TAG_LEN] {
        let mut mac = <blake2::Blake2sMac256 as KeyInit>::new_from_slice(&identity.to_seed())
            .expect("identity seed is 32 bytes");
        mac.update(DOMAIN);
        mac.update(&self.relay_endpoint_id);
        mac.update(&self.expires_at_ms.to_be_bytes());
        mac.update(&self.nonce);
        mac.finalize().into_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_decode_verify_round_trip() {
        let identity = IdentityKeyPair::generate();
        let bytes = RelayAuthorization::issue(&identity, 10_000, [7u8; NONCE_LEN]);
        let auth = RelayAuthorization::decode(&bytes).expect("decode");
        auth.verify(&identity, 9_999).expect("valid auth");
        assert!(auth.verify(&identity, 10_000).is_err());
        assert_eq!(auth.nonce, [7u8; NONCE_LEN]);
    }

    #[test]
    fn forged_and_wrong_identity_fail() {
        let identity = IdentityKeyPair::generate();
        let other = IdentityKeyPair::generate();
        let mut bytes = RelayAuthorization::issue(&identity, 10_000, [1u8; NONCE_LEN]);
        bytes[WIRE_LEN - 1] ^= 1;
        let forged = RelayAuthorization::decode(&bytes).expect("decode");
        assert!(forged.verify(&identity, 1).is_err());

        let bytes = RelayAuthorization::issue(&identity, 10_000, [1u8; NONCE_LEN]);
        let auth = RelayAuthorization::decode(&bytes).expect("decode");
        assert!(auth.verify(&other, 1).is_err());
    }
}
