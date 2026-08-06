//! Invitation lifecycle (discovery.md §14, handshake.md §22).
use std::collections::HashMap;
use umc_types::runtime::EntropySource;

pub const INVITATION_KEY_LEN: usize = 32;
pub const MAX_INVITATIONS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub id: [u8; 16],
    pub key: [u8; INVITATION_KEY_LEN],
    pub expires_at_ms: u64,
    pub single_use: bool,
    pub used: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvitationError {
    Unknown,
    Expired,
    AlreadyUsed,
    Full,
}

#[derive(Debug)]
pub struct InvitationStore {
    invitations: HashMap<[u8; 16], Invitation>,
}

impl Default for InvitationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InvitationStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            invitations: HashMap::new(),
        }
    }

    /// Create an invitation; the raw key is returned exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`InvitationError::Full`] when [`MAX_INVITATIONS`] live
    /// invitations are already stored.
    pub fn create(
        &mut self,
        expires_at_ms: u64,
        single_use: bool,
        entropy: &dyn EntropySource,
    ) -> Result<Invitation, InvitationError> {
        if self.invitations.len() >= MAX_INVITATIONS {
            return Err(InvitationError::Full);
        }
        let mut id = [0u8; 16];
        let mut key = [0u8; INVITATION_KEY_LEN];
        entropy.fill(&mut id);
        entropy.fill(&mut key);
        let invitation = Invitation {
            id,
            key,
            expires_at_ms,
            single_use,
            used: false,
        };
        self.invitations.insert(id, invitation.clone());
        Ok(invitation)
    }

    /// Validates the key and, for single-use invitations, consumes it.
    ///
    /// # Errors
    ///
    /// Returns [`InvitationError::Unknown`] for an unknown id or wrong key,
    /// [`InvitationError::Expired`] past the expiry, and
    /// [`InvitationError::AlreadyUsed`] for a consumed single-use invitation.
    pub fn validate(
        &mut self,
        id: &[u8; 16],
        key: &[u8],
        now_ms: u64,
    ) -> Result<(), InvitationError> {
        let Some(invitation) = self.invitations.get_mut(id) else {
            return Err(InvitationError::Unknown);
        };
        if now_ms >= invitation.expires_at_ms {
            return Err(InvitationError::Expired);
        }
        if invitation.single_use && invitation.used {
            return Err(InvitationError::AlreadyUsed);
        }
        if invitation.key.as_slice() != key {
            return Err(InvitationError::Unknown);
        }
        if invitation.single_use {
            invitation.used = true;
        }
        Ok(())
    }

    pub fn revoke(&mut self, id: &[u8; 16]) {
        self.invitations.remove(id);
    }

    pub fn prune_expired(&mut self, now_ms: u64) {
        self.invitations.retain(|_, i| i.expires_at_ms > now_ms);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.invitations.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.invitations.is_empty()
    }
}

/// HMAC-style admission authenticator (handshake.md §15.4), truncated to 16 bytes.
#[must_use]
pub fn invitation_authenticator(
    invitation_key: &[u8; 32],
    client_random: &[u8; 32],
    client_ephemeral_public_key: &[u8; 32],
    destination_connection_id: &[u8],
    carrier_binding: &[u8],
) -> [u8; 16] {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(b"UMP-INVITE-AUTH-v1");
    hasher.update(invitation_key);
    hasher.update(client_random);
    hasher.update(client_ephemeral_public_key);
    hasher.update(destination_connection_id);
    hasher.update(carrier_binding);
    let full: [u8; 32] = hasher.finalize().into();
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&full[..16]);
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(5);
        }
    }

    #[test]
    fn create_validate_revoke() {
        let mut store = InvitationStore::new();
        let invitation = store.create(u64::MAX, true, &E).unwrap();
        assert_eq!(store.validate(&invitation.id, &invitation.key, 0), Ok(()));
        assert_eq!(
            store.validate(&invitation.id, &invitation.key, 0),
            Err(InvitationError::AlreadyUsed)
        );
        store.revoke(&invitation.id);
        assert_eq!(
            store.validate(&invitation.id, &invitation.key, 0),
            Err(InvitationError::Unknown)
        );
    }

    #[test]
    fn expiry_enforced() {
        let mut store = InvitationStore::new();
        let invitation = store.create(100, false, &E).unwrap();
        assert_eq!(store.validate(&invitation.id, &invitation.key, 99), Ok(()));
        assert_eq!(
            store.validate(&invitation.id, &invitation.key, 100),
            Err(InvitationError::Expired)
        );
    }

    #[test]
    fn wrong_key_unknown() {
        let mut store = InvitationStore::new();
        let invitation = store.create(u64::MAX, false, &E).unwrap();
        assert_eq!(
            store.validate(&invitation.id, &[0u8; 32], 0),
            Err(InvitationError::Unknown)
        );
    }

    #[test]
    fn authenticator_is_deterministic_and_binds_inputs() {
        let key = [1u8; 32];
        let a = invitation_authenticator(&key, &[2u8; 32], &[3u8; 32], b"dcid", b"binding");
        let b = invitation_authenticator(&key, &[2u8; 32], &[3u8; 32], b"dcid", b"binding");
        let c = invitation_authenticator(&key, &[9u8; 32], &[3u8; 32], b"dcid", b"binding");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 16);
    }
}
