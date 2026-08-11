//! Protected keystore (storage.md §10): secret key material, separate from
//! metadata, encrypted with a memory-hard KDF when password-protected.
//! Phase 2 uses a file-backed store with Argon2id-style derivation via
//! the `argon2` crate.
use std::path::Path;

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

const LEGACY_FILE_HEADER: &[u8] = b"UMC-KEYSTORE-v2\0";
const FILE_HEADER: &[u8] = b"UMC-KEYSTORE-v3\0";
const HEADER_LEN: usize = FILE_HEADER.len();
const LEGACY_HEADER_LEN: usize = LEGACY_FILE_HEADER.len();
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// The check blob is nonce (12) + seal of `b"check"` (5 bytes + 16-byte tag).
const CHECK_BLOB: &[u8] = b"check";
const CHECK_BLOB_LEN: usize = NONCE_LEN + CHECK_BLOB.len() + TAG_LEN;
const CHECK_END: usize = HEADER_LEN + SALT_LEN + CHECK_BLOB_LEN;
const LEGACY_CHECK_BLOB_LEN: usize = CHECK_BLOB.len() + TAG_LEN;
const LEGACY_CHECK_END: usize = LEGACY_HEADER_LEN + LEGACY_CHECK_BLOB_LEN;

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
    /// derived from `password` if it does not exist. When the file already
    /// exists, the master-key check blob is verified so a wrong password
    /// fails here instead of at the first `load`.
    ///
    /// # Errors
    /// Returns [`KeystoreError::Io`] if the file cannot be created or read,
    /// [`KeystoreError::Integrity`] if the file is malformed, or
    /// [`KeystoreError::InvalidPassword`] if the check blob does not
    /// decrypt with the password-derived master key.
    pub fn open(path: std::path::PathBuf, password: &[u8]) -> Result<Self, KeystoreError> {
        if !path.exists() {
            let salt = random_salt();
            let master = derive_master(password, &salt);
            let ks = Self {
                master: Some(master),
                path,
            };
            ks.create_file(&salt)?;
            ks.verify_integrity()?;
            return Ok(ks);
        }

        let file = std::fs::read(&path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        if file.get(..LEGACY_HEADER_LEN) == Some(LEGACY_FILE_HEADER) {
            migrate_legacy(&path, password, &file)?;
        } else if file.get(..HEADER_LEN) != Some(FILE_HEADER) {
            return Err(KeystoreError::Integrity);
        }

        let file = std::fs::read(&path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        let salt_bytes = file
            .get(HEADER_LEN..HEADER_LEN + SALT_LEN)
            .ok_or(KeystoreError::Integrity)?;
        let salt: [u8; SALT_LEN] = salt_bytes
            .try_into()
            .map_err(|_| KeystoreError::Integrity)?;
        let master = derive_master(password, &salt);
        let ks = Self {
            master: Some(master),
            path,
        };
        ks.verify_integrity()?;
        Ok(ks)
    }

    fn create_file(&self, salt: &[u8; SALT_LEN]) -> Result<(), KeystoreError> {
        let mut data = Vec::new();
        data.extend_from_slice(FILE_HEADER);
        data.extend_from_slice(salt);
        // Master key check blob so corruption and wrong passwords are
        // detected at open.
        let check = seal_check(self.master.as_ref().expect("unlocked"));
        data.extend_from_slice(&check);
        write_private(&self.path, &data)
    }

    /// Decrypts the creation-time check blob with the derived master key.
    /// A wrong password makes the decrypt fail; tampered files fail the
    /// payload comparison.
    fn verify_integrity(&self) -> Result<(), KeystoreError> {
        let file = std::fs::read(&self.path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        if file.get(..HEADER_LEN) != Some(FILE_HEADER) {
            return Err(KeystoreError::Integrity);
        }
        let check = file
            .get(HEADER_LEN + SALT_LEN..CHECK_END)
            .ok_or(KeystoreError::Integrity)?;
        let master = self.master.as_ref().ok_or(KeystoreError::NotUnlocked)?;
        let plain = umc_crypto_open(master, check).ok_or(KeystoreError::InvalidPassword)?;
        if plain != CHECK_BLOB {
            return Err(KeystoreError::Integrity);
        }
        Ok(())
    }

    /// Stores `secret` under `(class, name)`, appending a sealed record.
    ///
    /// # Errors
    /// Returns [`KeystoreError::NotUnlocked`] if the keystore is locked, or
    /// [`KeystoreError::Io`] if the file cannot be read or written.
    ///
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
        let len = u32::try_from(sealed.len()).map_err(|_| KeystoreError::Integrity)?;
        file.extend_from_slice(&len.to_be_bytes());
        file.extend_from_slice(&sealed);
        write_private(&self.path, &file)
    }

    /// Loads the secret stored under `(class, name)`.
    ///
    /// # Errors
    /// Returns [`KeystoreError::NotUnlocked`] if the keystore is locked,
    /// [`KeystoreError::Integrity`] if a record cannot be decrypted or parsed,
    /// or [`KeystoreError::UnsupportedClass`] if no matching record exists.
    ///
    pub fn load(&self, class: KeyClass, name: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        let master = self.master.as_ref().ok_or(KeystoreError::NotUnlocked)?;
        let file = std::fs::read(&self.path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        if file.len() < CHECK_END {
            return Err(KeystoreError::Integrity);
        }
        // Header, random salt, and check blob precede the records.
        let mut pos = CHECK_END;
        while pos < file.len() {
            let prefix = file.get(pos..pos + 4).ok_or(KeystoreError::Integrity)?;
            let len = u32::from_be_bytes(prefix.try_into().map_err(|_| KeystoreError::Integrity)?)
                as usize;
            pos += 4;
            let sealed = file.get(pos..pos + len).ok_or(KeystoreError::Integrity)?;
            pos += len;
            let payload = umc_crypto_open(master, sealed).ok_or(KeystoreError::Integrity)?;
            if let Some(secret) = matching_secret(&payload, class, name)? {
                return Ok(secret.to_vec());
            }
        }
        Err(KeystoreError::UnsupportedClass)
    }

    /// Deletes every record stored under `(class, name)`. The store is
    /// append-only, so deletion rewrites the file without the matching
    /// records; a subsequent `store` under the same name is then the only
    /// record and `load` returns it (identity rotation relies on this
    /// replace semantics).
    ///
    /// # Errors
    /// Returns [`KeystoreError::NotUnlocked`] if the keystore is locked,
    /// [`KeystoreError::Integrity`] if a record cannot be decrypted or
    /// parsed, or [`KeystoreError::Io`] if the file cannot be read or
    /// written.
    ///
    pub fn delete(&self, class: KeyClass, name: &[u8]) -> Result<(), KeystoreError> {
        let master = self.master.as_ref().ok_or(KeystoreError::NotUnlocked)?;
        let file = std::fs::read(&self.path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        if file.len() < CHECK_END {
            return Err(KeystoreError::Integrity);
        }
        let mut out = file[..CHECK_END].to_vec();
        let mut pos = CHECK_END;
        while pos < file.len() {
            let prefix = file.get(pos..pos + 4).ok_or(KeystoreError::Integrity)?;
            let len = u32::from_be_bytes(prefix.try_into().map_err(|_| KeystoreError::Integrity)?)
                as usize;
            pos += 4;
            let sealed = file.get(pos..pos + len).ok_or(KeystoreError::Integrity)?;
            pos += len;
            let payload = umc_crypto_open(master, sealed).ok_or(KeystoreError::Integrity)?;
            let matches = matching_secret(&payload, class, name)?.is_some();
            if !matches {
                let len_u32 = u32::try_from(len).map_err(|_| KeystoreError::Integrity)?;
                out.extend_from_slice(&len_u32.to_be_bytes());
                out.extend_from_slice(sealed);
            }
        }
        write_private(&self.path, &out)
    }

    pub fn lock(&mut self) {
        self.master = None;
    }

    /// Reports whether the file at `path` is a recognized keystore: its header
    /// must carry the v2 or v3 magic and minimum fixed header/check length.
    /// Password verification is deliberately NOT done
    /// here — restore/backup flows run without the password, and the
    /// daemon verifies the check blob at boot (storage.md §21.1: format
    /// validation only, no secret handling).
    ///
    /// Returns `false` when the file is missing, unreadable, or not a recognized
    /// keystore.
    #[must_use]
    pub fn is_valid_format(path: &Path) -> bool {
        let Ok(file) = std::fs::read(path) else {
            return false;
        };
        if file.get(..HEADER_LEN) == Some(FILE_HEADER) {
            file.len() >= CHECK_END
        } else if file.get(..LEGACY_HEADER_LEN) == Some(LEGACY_FILE_HEADER) {
            file.len() >= LEGACY_CHECK_END
        } else {
            false
        }
    }
}

/// Writes `data` to `path`, creating the file with owner-only permissions
/// (0600 on unix). Secret key material must never be world-readable.
fn write_private(path: &std::path::Path, data: &[u8]) -> Result<(), KeystoreError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        // Atomic replace: write a temp file, fsync, rename over the target.
        // A crash mid-write must not corrupt the keystore (identity is the
        // node's single point of truth).
        let tmp = path.with_extension("tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true).mode(0o600);
        let mut file = opts
            .open(&tmp)
            .map_err(|e| KeystoreError::Io(e.to_string()))?;
        file.write_all(data)
            .map_err(|e| KeystoreError::Io(e.to_string()))?;
        file.sync_all()
            .map_err(|e| KeystoreError::Io(e.to_string()))?;
        drop(file);
        std::fs::rename(&tmp, path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(|e| KeystoreError::Io(e.to_string()))?;
        }
        // Tighten permissions even when the file pre-existed (mode(0o600)
        // only applies at creation).
        let _ = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data).map_err(|e| KeystoreError::Io(e.to_string()))
    }
}

fn random_salt() -> [u8; SALT_LEN] {
    use rand_core::{OsRng, RngCore};
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Legacy v2 derivation retained only long enough to migrate an existing file.
fn legacy_derive_salt(password: &[u8]) -> [u8; SALT_LEN] {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(b"UMP-KEYSTORE-SALT-v1");
    hasher.update(password);
    let digest = hasher.finalize();
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&digest[..SALT_LEN]);
    salt
}

fn derive_master(password: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    // Argon2id with parameters chosen for interactive use (storage.md §10).
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(19 * 1024, 2, 1, Some(32)).expect("params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut out)
        .expect("argon2 parameters are valid");
    out
}

fn seal_check(master: &[u8; 32]) -> Vec<u8> {
    umc_crypto_seal(master, b"check")
}

/// File-keystore seal: ChaCha20-Poly1305 with a fresh random nonce per
/// envelope. The nonce is stored before the ciphertext and is authenticated
/// by the AEAD tag. Platform keychain protection is provided by `keychain` for
/// export envelopes; the file keystore remains password-unlocked by design.
fn umc_crypto_seal(master: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    use rand_core::{OsRng, RngCore};
    let cipher = ChaCha20Poly1305::new(master.into());
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: payload,
                aad: b"UMC-KEYSTORE-v3",
            },
        )
        .expect("seal");
    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    sealed
}

fn umc_crypto_open(master: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    let nonce = sealed.get(..NONCE_LEN)?;
    let ciphertext = sealed.get(NONCE_LEN..)?;
    let cipher = ChaCha20Poly1305::new(master.into());
    cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: b"UMC-KEYSTORE-v3",
            },
        )
        .ok()
}

fn matching_secret<'a>(
    payload: &'a [u8],
    class: KeyClass,
    name: &[u8],
) -> Result<Option<&'a [u8]>, KeystoreError> {
    let payload_class = payload_class(payload)?;
    if payload_class != class.as_bytes() {
        return Ok(None);
    }
    let rest = &payload[class.as_bytes().len() + 1..];
    if !rest.starts_with(name) {
        return Ok(None);
    }
    if rest.get(name.len()) == Some(&0) {
        Ok(Some(&rest[name.len() + 1..]))
    } else {
        Ok(None)
    }
}

fn payload_class(payload: &[u8]) -> Result<&'static [u8], KeystoreError> {
    for class in [
        KeyClass::IdentitySigning,
        KeyClass::StaticHandshake,
        KeyClass::Ticket,
        KeyClass::Retry,
        KeyClass::Invitation,
        KeyClass::Recovery,
        KeyClass::ApiBearer,
    ] {
        let bytes = class.as_bytes();
        if payload.starts_with(bytes) {
            if payload.get(bytes.len()) != Some(&0) || payload.len() <= bytes.len() + 1 {
                return Err(KeystoreError::Integrity);
            }
            return Ok(bytes);
        }
    }
    Err(KeystoreError::Integrity)
}

fn migrate_legacy(path: &Path, password: &[u8], file: &[u8]) -> Result<(), KeystoreError> {
    let salt = legacy_derive_salt(password);
    let master = derive_master(password, &salt);
    let check = file
        .get(LEGACY_HEADER_LEN..LEGACY_CHECK_END)
        .ok_or(KeystoreError::Integrity)?;
    let check_plain = legacy_crypto_open(&master, check).ok_or(KeystoreError::InvalidPassword)?;
    if check_plain != CHECK_BLOB {
        return Err(KeystoreError::Integrity);
    }

    let mut records = Vec::new();
    let mut pos = LEGACY_CHECK_END;
    while pos < file.len() {
        let prefix = file.get(pos..pos + 4).ok_or(KeystoreError::Integrity)?;
        let len =
            u32::from_be_bytes(prefix.try_into().map_err(|_| KeystoreError::Integrity)?) as usize;
        pos += 4;
        let sealed = file.get(pos..pos + len).ok_or(KeystoreError::Integrity)?;
        pos += len;
        let payload = legacy_crypto_open(&master, sealed).ok_or(KeystoreError::Integrity)?;
        payload_class(&payload)?;
        records.push(payload);
    }

    let new_salt = random_salt();
    let new_master = derive_master(password, &new_salt);
    let mut migrated = Vec::new();
    migrated.extend_from_slice(FILE_HEADER);
    migrated.extend_from_slice(&new_salt);
    migrated.extend_from_slice(&seal_check(&new_master));
    for payload in records {
        let sealed = umc_crypto_seal(&new_master, &payload);
        let len = u32::try_from(sealed.len()).map_err(|_| KeystoreError::Integrity)?;
        migrated.extend_from_slice(&len.to_be_bytes());
        migrated.extend_from_slice(&sealed);
    }
    write_private(path, &migrated)
}

fn legacy_crypto_open(master: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    let cipher = ChaCha20Poly1305::new(master.into());
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..4].copy_from_slice(b"KSV1");
    cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: sealed,
                aad: b"UMC-KEYSTORE-v2",
            },
        )
        .ok()
}

#[cfg(test)]
fn legacy_crypto_seal(master: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    let cipher = ChaCha20Poly1305::new(master.into());
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..4].copy_from_slice(b"KSV1");
    cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: payload,
                aad: b"UMC-KEYSTORE-v2",
            },
        )
        .expect("legacy seal")
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
    fn wrong_password_fails_at_open() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let ks = Keystore::open(path.clone(), b"password-a").unwrap();
        ks.store(KeyClass::Ticket, b"t", &[1u8; 16]).unwrap();
        drop(ks);
        // Reopen with the wrong password: the check blob does not decrypt,
        // so the failure is detected at open, not lazily at the first load.
        assert!(matches!(
            Keystore::open(path.clone(), b"password-b"),
            Err(KeystoreError::InvalidPassword)
        ));
    }

    #[test]
    fn keystore_file_is_owner_only() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = temp_path();
            let _ = std::fs::remove_file(&path);
            let ks = Keystore::open(path.clone(), b"pw").unwrap();
            ks.store(KeyClass::Retry, b"k", &[7u8; 8]).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "keystore file must be owner-only");
        }
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

    #[test]
    fn delete_removes_only_the_matching_record() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let ks = Keystore::open(path.clone(), b"pw").unwrap();
        ks.store(KeyClass::IdentitySigning, b"node-identity", &[1u8; 64])
            .unwrap();
        ks.store(KeyClass::IdentitySigning, b"secondary-1", &[2u8; 64])
            .unwrap();
        ks.store(KeyClass::Ticket, b"t", &[3u8; 16]).unwrap();
        ks.delete(KeyClass::IdentitySigning, b"secondary-1")
            .unwrap();
        assert_eq!(
            ks.load(KeyClass::IdentitySigning, b"secondary-1"),
            Err(KeystoreError::UnsupportedClass)
        );
        assert_eq!(
            ks.load(KeyClass::IdentitySigning, b"node-identity")
                .unwrap(),
            vec![1u8; 64],
            "the sibling record survives"
        );
        assert_eq!(
            ks.load(KeyClass::Ticket, b"t").unwrap(),
            vec![3u8; 16],
            "a different class record survives"
        );
    }

    #[test]
    fn store_after_delete_replaces_the_record() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let ks = Keystore::open(path.clone(), b"pw").unwrap();
        ks.store(KeyClass::IdentitySigning, b"node-identity", &[1u8; 64])
            .unwrap();
        // Without delete the first record shadows the second (load returns
        // the first match); delete + store gives replace semantics, which
        // identity rotation depends on.
        ks.delete(KeyClass::IdentitySigning, b"node-identity")
            .unwrap();
        ks.store(KeyClass::IdentitySigning, b"node-identity", &[9u8; 64])
            .unwrap();
        assert_eq!(
            ks.load(KeyClass::IdentitySigning, b"node-identity")
                .unwrap(),
            vec![9u8; 64]
        );
    }

    #[test]
    fn binary_record_names_round_trip_even_with_zero_bytes() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let ks = Keystore::open(path, b"pw").unwrap();
        let name = [0x00, 0x10, 0x00, 0xff, 0x42];
        ks.store(KeyClass::IdentitySigning, &name, &[4u8; 32])
            .unwrap();
        assert_eq!(
            ks.load(KeyClass::IdentitySigning, &name).unwrap(),
            vec![4u8; 32]
        );
    }

    #[test]
    fn is_valid_format_checks_magic_and_minimum_length() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let ks = Keystore::open(path.clone(), b"pw").unwrap();
        ks.store(KeyClass::IdentitySigning, b"node-identity", &[1u8; 64])
            .unwrap();
        drop(ks);
        // A real keystore passes; garbage and missing files do not.
        assert!(Keystore::is_valid_format(&path));
        std::fs::write(&path, b"not a keystore").unwrap();
        assert!(!Keystore::is_valid_format(&path));
        assert!(!Keystore::is_valid_format(&path.with_extension("missing")));
    }

    #[test]
    fn truncated_header_is_not_a_valid_format() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, FILE_HEADER).unwrap();
        assert!(!Keystore::is_valid_format(&path));
    }

    #[test]
    fn repeated_plaintext_records_do_not_reuse_ciphertext_nonce() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let ks = Keystore::open(path.clone(), b"pw").unwrap();
        ks.store(KeyClass::Retry, b"same", &[7u8; 32]).unwrap();
        ks.store(KeyClass::Retry, b"same", &[7u8; 32]).unwrap();
        let file = std::fs::read(path).unwrap();
        let mut pos = CHECK_END;
        let mut records = Vec::new();
        for _ in 0..2 {
            let len = u32::from_be_bytes(file[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            records.push(&file[pos..pos + len]);
            pos += len;
        }
        assert_ne!(records[0], records[1]);
    }

    #[test]
    fn legacy_v2_keystore_migrates_before_use() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let password = b"legacy-password";
        let salt = legacy_derive_salt(password);
        let master = derive_master(password, &salt);
        let mut legacy = Vec::from(LEGACY_FILE_HEADER);
        legacy.extend_from_slice(&legacy_crypto_seal(&master, CHECK_BLOB));
        let mut payload = Vec::new();
        payload.extend_from_slice(KeyClass::Recovery.as_bytes());
        payload.push(0);
        payload.extend_from_slice(b"recovery-key");
        payload.push(0);
        payload.extend_from_slice(&[3u8; 32]);
        let sealed = legacy_crypto_seal(&master, &payload);
        legacy.extend_from_slice(&u32::try_from(sealed.len()).unwrap().to_be_bytes());
        legacy.extend_from_slice(&sealed);
        std::fs::write(&path, legacy).unwrap();

        let ks = Keystore::open(path.clone(), password).unwrap();
        assert_eq!(
            ks.load(KeyClass::Recovery, b"recovery-key").unwrap(),
            vec![3u8; 32]
        );
        let migrated = std::fs::read(path).unwrap();
        assert_eq!(&migrated[..HEADER_LEN], FILE_HEADER);
        assert_ne!(&migrated[..LEGACY_HEADER_LEN], LEGACY_FILE_HEADER);
    }

    #[test]
    fn truncated_record_fails_closed_without_panicking() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let ks = Keystore::open(path.clone(), b"pw").unwrap();
        ks.store(KeyClass::Retry, b"retry", &[8u8; 32]).unwrap();
        drop(ks);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.pop();
        std::fs::write(&path, bytes).unwrap();
        let ks = Keystore::open(path, b"pw").unwrap();
        let result = std::panic::catch_unwind(|| ks.load(KeyClass::Retry, b"retry"));
        assert!(result.is_ok(), "malformed storage must not panic");
        assert_eq!(result.unwrap(), Err(KeystoreError::Integrity));
    }
}
