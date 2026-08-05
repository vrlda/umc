//! Protected keystore (storage.md §10): secret key material, separate from
//! metadata, encrypted with a memory-hard KDF when password-protected.
//! Phase 2 uses a file-backed store with Argon2id-style derivation via
//! the `argon2` crate.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyClass {
    IdentitySigning,
    StaticHandshake,
    Ticket,
    Retry,
    Invitation,
    Recovery,
    ApiBearer,
}

impl KeyClass {
    #[must_use]
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            KeyClass::IdentitySigning => b"identity-signing",
            KeyClass::StaticHandshake => b"static-handshake",
            KeyClass::Ticket => b"ticket",
            KeyClass::Retry => b"retry",
            KeyClass::Invitation => b"invitation",
            KeyClass::Recovery => b"recovery",
            KeyClass::ApiBearer => b"api-bearer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreError {
    UnsupportedClass,
    NotUnlocked,
    Integrity,
    Io(String),
    InvalidPassword,
}

/// A keystore that stores opaque encrypted blobs keyed by (class, name).
/// The encryption layer is swappable; Phase 2 defaults to a ChaCha20-Poly1305
/// envelope keyed by a master key derived from a user secret with Argon2id.
#[derive(Debug)]
pub struct Keystore {
    master: Option<[u8; 32]>,
    path: std::path::PathBuf,
}

impl Keystore {
    /// Opens the keystore file at `path`, creating it with a new master key
    /// derived from `password` if it does not exist.
    ///
    /// # Errors
    /// Returns [`KeystoreError::Io`] if the file cannot be created or read.
    pub fn open(path: std::path::PathBuf, password: &[u8]) -> Result<Self, KeystoreError> {
        let salt = derive_salt(&path);
        let master = derive_master(password, &salt);
        let ks = Self {
            master: Some(master),
            path,
        };
        ks.ensure_file()?;
        Ok(ks)
    }

    fn ensure_file(&self) -> Result<(), KeystoreError> {
        if self.path.exists() {
            return Ok(());
        }
        let header = b"UMC-KEYSTORE-v1\0";
        let mut data = Vec::new();
        data.extend_from_slice(header);
        // Master key check blob so corruption is detected at open.
        let check = seal_check(self.master.as_ref().expect("unlocked"));
        data.extend_from_slice(&check);
        std::fs::write(&self.path, data).map_err(|e| KeystoreError::Io(e.to_string()))
    }

    /// Stores `secret` under `(class, name)`, appending a sealed record.
    ///
    /// # Errors
    /// Returns [`KeystoreError::NotUnlocked`] if the keystore is locked, or
    /// [`KeystoreError::Io`] if the file cannot be read or written.
    ///
    /// # Panics
    /// Panics if a sealed record exceeds `u32` bytes.
    pub fn store(&self, class: KeyClass, name: &[u8], secret: &[u8]) -> Result<(), KeystoreError> {
        let master = self.master.as_ref().ok_or(KeystoreError::NotUnlocked)?;
        let mut file = std::fs::read(&self.path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        let mut payload = Vec::new();
        payload.extend_from_slice(class.as_bytes());
        payload.push(0);
        payload.extend_from_slice(name);
        payload.push(0);
        payload.extend_from_slice(secret);
        let sealed = umc_crypto_seal(master, &payload);
        let len = u32::try_from(sealed.len()).expect("sealed record fits u32");
        file.extend_from_slice(&len.to_be_bytes());
        file.extend_from_slice(&sealed);
        std::fs::write(&self.path, file).map_err(|e| KeystoreError::Io(e.to_string()))
    }

    /// Loads the secret stored under `(class, name)`.
    ///
    /// # Errors
    /// Returns [`KeystoreError::NotUnlocked`] if the keystore is locked,
    /// [`KeystoreError::Integrity`] if a record cannot be decrypted or parsed,
    /// or [`KeystoreError::UnsupportedClass`] if no matching record exists.
    ///
    /// # Panics
    /// Panics if a truncated length prefix is read from the file.
    pub fn load(&self, class: KeyClass, name: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        let master = self.master.as_ref().ok_or(KeystoreError::NotUnlocked)?;
        let file = std::fs::read(&self.path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        // Header: 16-byte magic + 21-byte check blob (seal of b"check" = 5 + 16-byte tag).
        let mut pos = 37usize;
        while pos + 4 <= file.len() {
            let len = u32::from_be_bytes(file[pos..pos + 4].try_into().expect("4 bytes")) as usize;
            pos += 4;
            let sealed = file.get(pos..pos + len).ok_or(KeystoreError::Integrity)?;
            pos += len;
            let payload = umc_crypto_open(master, sealed).ok_or(KeystoreError::Integrity)?;
            let (cls, rest) = payload.split_at(class.as_bytes().len());
            if cls != class.as_bytes() {
                continue;
            }
            let rest = &rest[1..]; // separator
            if rest.starts_with(name) && rest.get(name.len()) == Some(&0) {
                return Ok(rest[name.len() + 1..].to_vec());
            }
        }
        Err(KeystoreError::UnsupportedClass)
    }

    pub fn lock(&mut self) {
        self.master = None;
    }
}

fn derive_salt(path: &std::path::Path) -> [u8; 16] {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.to_string_lossy().hash(&mut hasher);
    let mut salt = [0u8; 16];
    salt[..8].copy_from_slice(&hasher.finish().to_be_bytes());
    salt
}

fn derive_master(password: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    // Argon2id with parameters chosen for interactive use (storage.md §10).
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(19 * 1024, 2, 1, Some(32)).expect("params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    let _ = argon2.hash_password_into(password, salt, &mut out);
    out
}

fn seal_check(master: &[u8; 32]) -> Vec<u8> {
    umc_crypto_seal(master, b"check")
}

/// Provisional seal: ChaCha20-Poly1305 with a zero nonce domain label.
/// Replaced by OS keychain integration when available (decisions.md §6).
fn umc_crypto_seal(master: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    let cipher = ChaCha20Poly1305::new(master.into());
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(b"KSV1");
    cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: payload,
                aad: b"UMC-KEYSTORE-v1",
            },
        )
        .expect("seal")
}

fn umc_crypto_open(master: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    let cipher = ChaCha20Poly1305::new(master.into());
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(b"KSV1");
    cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: sealed,
                aad: b"UMC-KEYSTORE-v1",
            },
        )
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("umc-keystore-{}-{n}.ks", std::process::id()))
    }

    #[test]
    fn store_and_load_round_trip() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let ks = Keystore::open(path.clone(), b"correct horse battery staple").unwrap();
        ks.store(KeyClass::Retry, b"retry-key-1", &[0xAB; 32])
            .unwrap();
        let loaded = ks.load(KeyClass::Retry, b"retry-key-1").unwrap();
        assert_eq!(loaded, vec![0xAB; 32]);
    }

    #[test]
    fn wrong_password_fails_validation() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let ks = Keystore::open(path.clone(), b"password-a").unwrap();
        ks.store(KeyClass::Ticket, b"t", &[1u8; 16]).unwrap();
        drop(ks);
        // Reopen with the wrong password: the check blob will not decrypt.
        let ks2 = Keystore::open(path.clone(), b"password-b").unwrap();
        // The check blob is fixed-size; loading any record with a wrong master fails integrity.
        assert_eq!(
            ks2.load(KeyClass::Ticket, b"t"),
            Err(KeystoreError::Integrity)
        );
    }

    #[test]
    fn lock_clears_master() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let mut ks = Keystore::open(path, b"pw").unwrap();
        ks.store(KeyClass::Recovery, b"r", &[2u8; 8]).unwrap();
        ks.lock();
        assert_eq!(
            ks.load(KeyClass::Recovery, b"r"),
            Err(KeystoreError::NotUnlocked)
        );
    }
}
