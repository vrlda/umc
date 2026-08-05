use umc_crypto::aead::PacketKeys;

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
