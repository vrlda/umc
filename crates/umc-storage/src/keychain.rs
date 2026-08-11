//! Platform secure-secret storage.
//!
//! The protocol and export envelope code depends on [`SecretStore`] rather
//! than a particular platform. [`OsKeychain`] delegates to the native
//! credential store through `keyring`: Keychain on macOS, Credential Manager
//! on Windows, and the configured Secret Service/keyutils backend on Linux.
//! No plaintext secret is written to the UMC data directory by this module.

/// Service namespace used for all UMC keychain records. The caller-provided
/// reference is the credential account, keeping references scoped to UMC.
pub const KEYCHAIN_SERVICE: &str = "org.openmesh.umc.identity";
const MAX_REFERENCE_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainError {
    InvalidReference,
    Missing,
    Unavailable,
}

/// Minimal secret-store boundary used by recipient and OS-keychain exports.
/// Implementations must never log or expose the bytes returned by `get_secret`.
pub trait SecretStore: Send + Sync {
    /// Reads a secret by its platform-scoped reference.
    ///
    /// # Errors
    /// Returns [`KeychainError`] when the reference is invalid, the item is
    /// missing, or the platform store cannot be accessed.
    fn get_secret(&self, reference: &str) -> Result<Vec<u8>, KeychainError>;
    /// Stores or replaces a secret at a platform-scoped reference.
    ///
    /// # Errors
    /// Returns [`KeychainError`] when the reference is invalid or the
    /// platform store cannot be accessed.
    fn set_secret(&self, reference: &str, secret: &[u8]) -> Result<(), KeychainError>;
    /// Deletes a secret from a platform-scoped reference.
    ///
    /// # Errors
    /// Returns [`KeychainError`] when the reference is invalid, the item is
    /// missing, or the platform store cannot be accessed.
    fn delete_secret(&self, reference: &str) -> Result<(), KeychainError>;
}

/// Native platform-backed secret store.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsKeychain;

impl OsKeychain {
    fn entry(reference: &str) -> Result<keyring::Entry, KeychainError> {
        validate_reference(reference)?;
        keyring::Entry::new(KEYCHAIN_SERVICE, reference).map_err(|_| KeychainError::Unavailable)
    }
}

impl SecretStore for OsKeychain {
    fn get_secret(&self, reference: &str) -> Result<Vec<u8>, KeychainError> {
        let entry = Self::entry(reference)?;
        entry
            .get_secret()
            .map_err(|error| map_keyring_error(&error))
    }

    fn set_secret(&self, reference: &str, secret: &[u8]) -> Result<(), KeychainError> {
        let entry = Self::entry(reference)?;
        entry
            .set_secret(secret)
            .map_err(|error| map_keyring_error(&error))
    }

    fn delete_secret(&self, reference: &str) -> Result<(), KeychainError> {
        let entry = Self::entry(reference)?;
        entry
            .delete_credential()
            .map_err(|error| map_keyring_error(&error))
    }
}

fn validate_reference(reference: &str) -> Result<(), KeychainError> {
    if reference.is_empty()
        || reference.len() > MAX_REFERENCE_LEN
        || reference.bytes().any(|byte| byte == 0)
    {
        return Err(KeychainError::InvalidReference);
    }
    Ok(())
}

fn map_keyring_error(error: &keyring::Error) -> KeychainError {
    match error {
        keyring::Error::NoEntry => KeychainError::Missing,
        _ => KeychainError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_bounded_and_cannot_contain_nul() {
        assert_eq!(validate_reference(""), Err(KeychainError::InvalidReference));
        assert_eq!(
            validate_reference("bad\0reference"),
            Err(KeychainError::InvalidReference)
        );
        assert_eq!(
            validate_reference(&"x".repeat(MAX_REFERENCE_LEN + 1)),
            Err(KeychainError::InvalidReference)
        );
        assert!(validate_reference("umc/identity").is_ok());
    }
}
