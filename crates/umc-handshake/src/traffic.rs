use umc_crypto::aead::PacketKeys;

/// Session secret derivation (handshake.md §26).
#[derive(Debug, Clone)]
pub struct SessionSecrets {
    pub client: [u8; 32],
    pub server: [u8; 32],
    pub exporter: [u8; 32],
    pub resumption: [u8; 32],
    pub path_validation: [u8; 32],
    pub connection_id: [u8; 32],
    pub stateless_reset: [u8; 32],
}

/// Derives the session traffic secrets for both endpoints (handshake.md §26).
///
/// The handshake secret and final transcript are bound into a master secret
/// via HKDF-Extract; each session secret is then expanded with its own label.
#[must_use]
pub fn derive_session_secrets(
    handshake_secret: &[u8; 32],
    final_transcript: &[u8; 32],
) -> SessionSecrets {
    let derived = expand(handshake_secret, b"derived", final_transcript);
    let master = umc_crypto::hkdf::extract(&derived, &[0u8; 32]);
    SessionSecrets {
        client: expand(&master, b"client session traffic", final_transcript),
        server: expand(&master, b"server session traffic", final_transcript),
        exporter: expand(&master, b"exporter", final_transcript),
        resumption: expand(&master, b"resumption", final_transcript),
        path_validation: expand(&master, b"path validation", final_transcript),
        connection_id: expand(&master, b"connection id", final_transcript),
        stateless_reset: expand(&master, b"stateless reset", final_transcript),
    }
}

/// Derives packet keys from a session traffic secret.
///
/// # Panics
///
/// Panics if the secret cannot be expanded into packet keys; a 32-byte
/// session traffic secret always fits.
#[must_use]
pub fn traffic_keys(secret: &[u8; 32]) -> PacketKeys {
    PacketKeys::from_traffic_secret(secret).expect("32-byte key")
}

fn expand(secret: &[u8; 32], label: &[u8], context: &[u8; 32]) -> [u8; 32] {
    let out =
        umc_crypto::label::expand_label(secret, label, context, 32).expect("32-byte expansion");
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_labels_are_distinct() {
        let hs = [1u8; 32];
        let tr = [2u8; 32];
        let s = derive_session_secrets(&hs, &tr);
        let mut secrets = vec![
            s.client,
            s.server,
            s.exporter,
            s.resumption,
            s.path_validation,
            s.connection_id,
            s.stateless_reset,
        ];
        secrets.sort();
        secrets.dedup();
        assert_eq!(secrets.len(), 7);
    }

    #[test]
    fn transcript_changes_everything() {
        let hs = [1u8; 32];
        let a = derive_session_secrets(&hs, &[2u8; 32]);
        let b = derive_session_secrets(&hs, &[3u8; 32]);
        assert_ne!(a.client, b.client);
        assert_ne!(a.path_validation, b.path_validation);
    }

    #[test]
    fn handshake_secret_changes_everything() {
        let tr = [2u8; 32];
        let a = derive_session_secrets(&[1u8; 32], &tr);
        let b = derive_session_secrets(&[4u8; 32], &tr);
        assert_ne!(a.client, b.client);
    }
}
