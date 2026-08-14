//! Password-protected identity export envelopes.
//!
//! Secret identity material must not cross the control API as raw seed bytes.
//! Passphrase, recipient-public-key, and platform keychain protections share
//! bounded, authenticated envelopes. The platform store is injected through
//! [`crate::keychain::SecretStore`] so tests never need a real credential UI.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand_core::{OsRng, RngCore};
use umc_crypto::signatures::{StaticHandshakeKeyPair, StaticHandshakePublicKey};

use crate::keychain::{KeychainError, SecretStore};

/// Domain-separated envelope header. The header is authenticated as AAD and
/// makes accidental interpretation of legacy raw-seed bytes impossible.
pub const EXPORT_MAGIC: &[u8] = b"UMC-IDENTITY-EXPORT-v1\0";
/// Recipient-public-key envelope. The ephemeral X25519 public key and
/// recipient public key are authenticated as part of the envelope header.
pub const RECIPIENT_EXPORT_MAGIC: &[u8] = b"UMC-IDENTITY-RECIPIENT-v1\0";
/// OS-keychain envelope. The keychain reference is authenticated as local
/// context, preventing an envelope from being silently moved between items.
pub const KEYCHAIN_EXPORT_MAGIC: &[u8] = b"UMC-IDENTITY-KEYCHAIN-v1\0";
/// Whole-backup envelope. Backup payloads use a separate domain so an
/// identity export cannot be misinterpreted as a backup archive.
pub const BACKUP_EXPORT_MAGIC: &[u8] = b"UMC-BACKUP-v1\0";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Identity exports are small; this bound also limits work and allocation on
/// an untrusted import request.
pub const MAX_EXPORT_BYTES: usize = 64 * 1024;
/// Bounded upper limit for a password-protected backup archive.
pub const MAX_BACKUP_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretExportError {
    EmptyPassphrase,
    TooLarge,
    Malformed,
    AuthenticationFailed,
    InvalidRecipientKey,
    InvalidKeychainReference,
    KeychainMissing,
    KeychainUnavailable,
    KeychainCorrupt,
}

/// Encrypts secret identity material with an Argon2id-derived key and an
/// independently random ChaCha20-Poly1305 nonce.
///
/// Envelope format: `EXPORT_MAGIC || salt[16] || nonce[12] || ciphertext`.
/// The magic, salt, and nonce are public; the seed material and passphrase
/// never appear in the envelope in plaintext.
///
/// # Errors
///
/// Returns [`SecretExportError::EmptyPassphrase`] for an empty passphrase,
/// [`SecretExportError::TooLarge`] for empty or oversized plaintext, or
/// [`SecretExportError::AuthenticationFailed`] if sealing fails.
pub fn seal(passphrase: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SecretExportError> {
    seal_with_magic(passphrase, plaintext, EXPORT_MAGIC, MAX_EXPORT_BYTES)
}

/// Encrypts a whole backup archive with the same Argon2id/ChaCha20-Poly1305
/// envelope as identity exports, but with backup-specific domain separation.
///
/// # Errors
/// Returns [`SecretExportError::EmptyPassphrase`] for an empty password or
/// [`SecretExportError::TooLarge`] when the archive exceeds its bound.
pub fn seal_backup(passphrase: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SecretExportError> {
    seal_with_magic(passphrase, plaintext, BACKUP_EXPORT_MAGIC, MAX_BACKUP_BYTES)
}

fn seal_with_magic(
    passphrase: &[u8],
    plaintext: &[u8],
    magic: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, SecretExportError> {
    if passphrase.is_empty() {
        return Err(SecretExportError::EmptyPassphrase);
    }
    if plaintext.is_empty() || plaintext.len() > max_bytes {
        return Err(SecretExportError::TooLarge);
    }

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(passphrase, &salt);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: magic,
            },
        )
        .map_err(|_| SecretExportError::AuthenticationFailed)?;

    let mut envelope = Vec::with_capacity(magic.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(magic);
    envelope.extend_from_slice(&salt);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Opens a passphrase-protected identity export envelope.
///
/// # Errors
///
/// Returns [`SecretExportError::EmptyPassphrase`] for an empty passphrase,
/// [`SecretExportError::Malformed`] for an invalid envelope,
/// [`SecretExportError::TooLarge`] for oversized plaintext, or
/// [`SecretExportError::AuthenticationFailed`] when authentication fails.
pub fn open(passphrase: &[u8], envelope: &[u8]) -> Result<Vec<u8>, SecretExportError> {
    open_with_magic(passphrase, envelope, EXPORT_MAGIC, MAX_EXPORT_BYTES)
}

/// Opens a password-protected whole-backup archive.
///
/// # Errors
/// Returns [`SecretExportError::Malformed`] for an invalid envelope,
/// [`SecretExportError::AuthenticationFailed`] for a wrong password, or
/// [`SecretExportError::TooLarge`] for an oversized archive.
pub fn open_backup(passphrase: &[u8], envelope: &[u8]) -> Result<Vec<u8>, SecretExportError> {
    open_with_magic(passphrase, envelope, BACKUP_EXPORT_MAGIC, MAX_BACKUP_BYTES)
}

fn open_with_magic(
    passphrase: &[u8],
    envelope: &[u8],
    magic: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, SecretExportError> {
    if passphrase.is_empty() {
        return Err(SecretExportError::EmptyPassphrase);
    }
    let header_len = magic.len() + SALT_LEN + NONCE_LEN;
    if envelope.len() < header_len + TAG_LEN || !envelope.starts_with(magic) {
        return Err(SecretExportError::Malformed);
    }
    let salt_start = magic.len();
    let nonce_start = salt_start + SALT_LEN;
    let ciphertext = &envelope[nonce_start + NONCE_LEN..];
    if ciphertext.len() - TAG_LEN > max_bytes {
        return Err(SecretExportError::TooLarge);
    }
    let key = derive_key(passphrase, &envelope[salt_start..nonce_start]);
    let cipher = ChaCha20Poly1305::new((&key).into());
    cipher
        .decrypt(
            Nonce::from_slice(&envelope[nonce_start..nonce_start + NONCE_LEN]),
            Payload {
                msg: ciphertext,
                aad: magic,
            },
        )
        .map_err(|_| SecretExportError::AuthenticationFailed)
}

/// Encrypts secret material to a 32-byte X25519 recipient public key.
///
/// Envelope format: `RECIPIENT_EXPORT_MAGIC || ephemeral_public[32] ||
/// nonce[12] || ciphertext`. The content-encryption key is derived from the
/// ephemeral/recipient Diffie-Hellman result with the protocol BLAKE2s HKDF.
///
/// # Errors
/// Returns [`SecretExportError`] when the recipient key or plaintext bound is
/// invalid, the shared key is a low-order point, or sealing fails.
pub fn seal_to_recipient(
    recipient_public_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SecretExportError> {
    if recipient_public_key.len() != 32 {
        return Err(SecretExportError::InvalidRecipientKey);
    }
    validate_plaintext(plaintext)?;
    let recipient_public: [u8; 32] = recipient_public_key
        .try_into()
        .map_err(|_| SecretExportError::InvalidRecipientKey)?;
    let recipient = StaticHandshakePublicKey(recipient_public);
    let ephemeral = StaticHandshakeKeyPair::generate();
    let shared = ephemeral.diffie_hellman(&recipient);
    if is_zero_key(&shared) {
        return Err(SecretExportError::InvalidRecipientKey);
    }
    let ephemeral_public = ephemeral.public().0;
    let key = recipient_encryption_key(&shared, &ephemeral_public, &recipient_public);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let aad = recipient_aad(&ephemeral_public, &recipient_public);
    let ciphertext = ChaCha20Poly1305::new((&key).into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| SecretExportError::AuthenticationFailed)?;
    let mut envelope =
        Vec::with_capacity(RECIPIENT_EXPORT_MAGIC.len() + 32 + NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(RECIPIENT_EXPORT_MAGIC);
    envelope.extend_from_slice(&ephemeral_public);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Opens a recipient-public-key envelope with the corresponding X25519
/// private key seed.
///
/// # Errors
/// Returns [`SecretExportError`] for malformed envelopes, invalid key
/// material, or failed authenticated decryption.
pub fn open_with_recipient(
    recipient_private_key: &[u8],
    envelope: &[u8],
) -> Result<Vec<u8>, SecretExportError> {
    if recipient_private_key.len() != 32 {
        return Err(SecretExportError::InvalidRecipientKey);
    }
    let header_len = RECIPIENT_EXPORT_MAGIC.len() + 32 + NONCE_LEN;
    if envelope.len() < header_len + TAG_LEN || !envelope.starts_with(RECIPIENT_EXPORT_MAGIC) {
        return Err(SecretExportError::Malformed);
    }
    if envelope.len() - header_len - TAG_LEN > MAX_EXPORT_BYTES {
        return Err(SecretExportError::TooLarge);
    }
    let ephemeral_start = RECIPIENT_EXPORT_MAGIC.len();
    let nonce_start = ephemeral_start + 32;
    let ephemeral_public: [u8; 32] = envelope[ephemeral_start..nonce_start]
        .try_into()
        .map_err(|_| SecretExportError::Malformed)?;
    let private: [u8; 32] = recipient_private_key
        .try_into()
        .map_err(|_| SecretExportError::InvalidRecipientKey)?;
    let recipient = StaticHandshakeKeyPair::from_seed(private);
    let recipient_public = recipient.public().0;
    let shared = recipient.diffie_hellman(&StaticHandshakePublicKey(ephemeral_public));
    if is_zero_key(&shared) {
        return Err(SecretExportError::InvalidRecipientKey);
    }
    let key = recipient_encryption_key(&shared, &ephemeral_public, &recipient_public);
    let ciphertext = &envelope[nonce_start + NONCE_LEN..];
    let aad = recipient_aad(&ephemeral_public, &recipient_public);
    ChaCha20Poly1305::new((&key).into())
        .decrypt(
            Nonce::from_slice(&envelope[nonce_start..nonce_start + NONCE_LEN]),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| SecretExportError::AuthenticationFailed)
}

/// Encrypts secret material under a 32-byte wrapping key held by a
/// [`SecretStore`]. A missing keychain entry is provisioned once with random
/// key material; subsequent exports reuse that entry.
///
/// # Errors
/// Returns [`SecretExportError`] for invalid references or plaintext, an
/// unavailable/corrupt keychain entry, or sealing failure.
pub fn seal_to_keychain<S: SecretStore + ?Sized>(
    store: &S,
    reference: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, SecretExportError> {
    validate_plaintext(plaintext)?;
    let key = match store.get_secret(reference) {
        Ok(key) => key,
        Err(KeychainError::Missing) => {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            store
                .set_secret(reference, &key)
                .map_err(map_keychain_error)?;
            key.to_vec()
        }
        Err(error) => return Err(map_keychain_error(error)),
    };
    if key.len() != 32 {
        return Err(SecretExportError::KeychainCorrupt);
    }
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let aad = keychain_aad(reference)?;
    let ciphertext = ChaCha20Poly1305::new((&key[..]).into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| SecretExportError::AuthenticationFailed)?;
    let mut envelope =
        Vec::with_capacity(KEYCHAIN_EXPORT_MAGIC.len() + NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(KEYCHAIN_EXPORT_MAGIC);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Opens either a keychain-wrapped envelope or a recipient envelope using a
/// 32-byte X25519 private key stored under `reference`.
///
/// # Errors
/// Returns [`SecretExportError`] for invalid references, malformed envelopes,
/// missing/unavailable keychain entries, or failed authenticated decryption.
pub fn open_with_keychain<S: SecretStore + ?Sized>(
    store: &S,
    reference: &str,
    envelope: &[u8],
) -> Result<Vec<u8>, SecretExportError> {
    if envelope.starts_with(RECIPIENT_EXPORT_MAGIC) {
        let key = store.get_secret(reference).map_err(map_keychain_error)?;
        if key.len() != 32 {
            return Err(SecretExportError::KeychainCorrupt);
        }
        return open_with_recipient(&key, envelope);
    }
    if !envelope.starts_with(KEYCHAIN_EXPORT_MAGIC) {
        return Err(SecretExportError::Malformed);
    }
    let header_len = KEYCHAIN_EXPORT_MAGIC.len() + NONCE_LEN;
    if envelope.len() < header_len + TAG_LEN {
        return Err(SecretExportError::Malformed);
    }
    if envelope.len() - header_len - TAG_LEN > MAX_EXPORT_BYTES {
        return Err(SecretExportError::TooLarge);
    }
    let key = store.get_secret(reference).map_err(map_keychain_error)?;
    if key.len() != 32 {
        return Err(SecretExportError::KeychainCorrupt);
    }
    let aad = keychain_aad(reference)?;
    ChaCha20Poly1305::new((&key[..]).into())
        .decrypt(
            Nonce::from_slice(&envelope[KEYCHAIN_EXPORT_MAGIC.len()..header_len]),
            Payload {
                msg: &envelope[header_len..],
                aad: &aad,
            },
        )
        .map_err(|_| SecretExportError::AuthenticationFailed)
}

fn validate_plaintext(plaintext: &[u8]) -> Result<(), SecretExportError> {
    if plaintext.is_empty() || plaintext.len() > MAX_EXPORT_BYTES {
        return Err(SecretExportError::TooLarge);
    }
    Ok(())
}

fn is_zero_key(key: &[u8; 32]) -> bool {
    key.iter().all(|byte| *byte == 0)
}

fn recipient_aad(ephemeral_public: &[u8; 32], recipient_public: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECIPIENT_EXPORT_MAGIC.len() + 64);
    aad.extend_from_slice(RECIPIENT_EXPORT_MAGIC);
    aad.extend_from_slice(ephemeral_public);
    aad.extend_from_slice(recipient_public);
    aad
}

fn recipient_encryption_key(
    shared: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
) -> [u8; 32] {
    let prk = umc_crypto::hkdf::extract(RECIPIENT_EXPORT_MAGIC, shared);
    let mut info = Vec::with_capacity(RECIPIENT_EXPORT_MAGIC.len() + 64);
    info.extend_from_slice(RECIPIENT_EXPORT_MAGIC);
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(recipient_public);
    umc_crypto::hkdf::expand(&prk, &info, 32)
        .expect("fixed-size recipient key expansion")
        .try_into()
        .expect("recipient key length")
}

fn keychain_aad(reference: &str) -> Result<Vec<u8>, SecretExportError> {
    if reference.is_empty() || reference.len() > 256 || reference.bytes().any(|byte| byte == 0) {
        return Err(SecretExportError::InvalidKeychainReference);
    }
    let mut aad = Vec::with_capacity(KEYCHAIN_EXPORT_MAGIC.len() + reference.len());
    aad.extend_from_slice(KEYCHAIN_EXPORT_MAGIC);
    aad.extend_from_slice(reference.as_bytes());
    Ok(aad)
}

fn map_keychain_error(error: KeychainError) -> SecretExportError {
    match error {
        KeychainError::InvalidReference => SecretExportError::InvalidKeychainReference,
        KeychainError::Missing => SecretExportError::KeychainMissing,
        KeychainError::Unavailable => SecretExportError::KeychainUnavailable,
    }
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(19 * 1024, 2, 1, Some(32)).expect("valid Argon2 parameters");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .expect("valid Argon2 parameters");
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::{KeychainError, SecretStore};
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct MemoryStore(Mutex<HashMap<String, Vec<u8>>>);

    impl SecretStore for MemoryStore {
        fn get_secret(&self, reference: &str) -> Result<Vec<u8>, KeychainError> {
            self.0
                .lock()
                .expect("memory store")
                .get(reference)
                .cloned()
                .ok_or(KeychainError::Missing)
        }

        fn set_secret(&self, reference: &str, secret: &[u8]) -> Result<(), KeychainError> {
            self.0
                .lock()
                .expect("memory store")
                .insert(reference.to_owned(), secret.to_vec());
            Ok(())
        }

        fn delete_secret(&self, reference: &str) -> Result<(), KeychainError> {
            self.0.lock().expect("memory store").remove(reference);
            Ok(())
        }
    }

    #[test]
    fn passphrase_export_round_trips_without_raw_plaintext() {
        let plaintext = [0x42u8; 64];
        let envelope = seal(b"correct horse", &plaintext).expect("seal");
        assert!(envelope.starts_with(EXPORT_MAGIC));
        assert_ne!(&envelope[EXPORT_MAGIC.len()..], plaintext.as_slice());
        assert_eq!(open(b"correct horse", &envelope).expect("open"), plaintext);
    }

    #[test]
    fn wrong_passphrase_and_tampering_fail_closed() {
        let mut envelope = seal(b"correct horse", b"secret seeds").expect("seal");
        assert_eq!(
            open(b"wrong horse", &envelope),
            Err(SecretExportError::AuthenticationFailed)
        );
        let last = envelope.len() - 1;
        envelope[last] ^= 1;
        assert_eq!(
            open(b"correct horse", &envelope),
            Err(SecretExportError::AuthenticationFailed)
        );
    }

    #[test]
    fn malformed_and_empty_inputs_are_rejected() {
        assert_eq!(seal(b"", b"seed"), Err(SecretExportError::EmptyPassphrase));
        assert_eq!(open(b"pw", b"raw seeds"), Err(SecretExportError::Malformed));
        assert_eq!(seal(b"pw", b""), Err(SecretExportError::TooLarge));
    }

    #[test]
    fn recipient_export_round_trips_and_binds_the_private_key() {
        let recipient_private = [7u8; 32];
        let recipient = StaticHandshakeKeyPair::from_seed(recipient_private);
        let envelope = seal_to_recipient(&recipient.public().0, b"recipient secret").expect("seal");

        assert!(envelope.starts_with(RECIPIENT_EXPORT_MAGIC));
        assert_eq!(
            open_with_recipient(&recipient_private, &envelope).expect("open"),
            b"recipient secret"
        );
        assert_eq!(
            open_with_recipient(&[8u8; 32], &envelope),
            Err(SecretExportError::AuthenticationFailed)
        );
        let store = MemoryStore::default();
        store
            .set_secret("recipient/private", &recipient_private)
            .expect("store recipient key");
        assert_eq!(
            open_with_keychain(&store, "recipient/private", &envelope).expect("keychain open"),
            b"recipient secret"
        );
    }

    #[test]
    fn keychain_export_round_trips_and_creates_a_wrapping_key_once() {
        let store = MemoryStore::default();
        let envelope =
            seal_to_keychain(&store, "identity/export", b"keychain secret").expect("seal");
        assert!(envelope.starts_with(KEYCHAIN_EXPORT_MAGIC));
        assert_eq!(
            open_with_keychain(&store, "identity/export", &envelope).expect("open"),
            b"keychain secret"
        );
        let first_key = store
            .0
            .lock()
            .expect("memory store")
            .get("identity/export")
            .cloned()
            .expect("wrapping key");
        let second = seal_to_keychain(&store, "identity/export", b"second").expect("seal");
        assert_eq!(
            store.0.lock().expect("memory store").get("identity/export"),
            Some(&first_key)
        );
        assert_eq!(
            open_with_keychain(&store, "identity/export", &second).expect("open"),
            b"second"
        );
    }
}
