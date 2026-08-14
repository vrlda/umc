//! Opt-in evidence for the real platform credential store.
//!
//! This test is intentionally ignored by the default workspace suite: Linux
//! Secret Service requires an interactive/session D-Bus and native stores
//! should never be touched by ordinary unit tests. Native CI runners invoke it
//! explicitly with `UMC_NATIVE_KEYCHAIN_TEST=1`.

use std::time::{SystemTime, UNIX_EPOCH};

use umc_storage::keychain::{KeychainError, OsKeychain, SecretStore};

fn unique_reference() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_nanos();
    format!("native-smoke/{}/{timestamp}", std::process::id())
}

struct Cleanup(String);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = OsKeychain.delete_secret(&self.0);
    }
}

#[test]
#[ignore = "requires an interactive native credential-store session"]
fn native_keychain_round_trip_is_real_and_ephemeral() {
    assert_eq!(
        std::env::var("UMC_NATIVE_KEYCHAIN_TEST").as_deref(),
        Ok("1"),
        "set UMC_NATIVE_KEYCHAIN_TEST=1 when invoking the native smoke test"
    );

    let keychain = OsKeychain;
    let reference = unique_reference();
    let _cleanup = Cleanup(reference.clone());
    let secret = b"umc-native-keychain-smoke-v1";

    match keychain.delete_secret(&reference) {
        Ok(()) | Err(KeychainError::Missing) => {}
        Err(error) => panic!("native keychain cleanup before test failed: {error:?}"),
    }
    keychain
        .set_secret(&reference, secret)
        .expect("native keychain write");
    let loaded = keychain
        .get_secret(&reference)
        .expect("native keychain read");
    assert_eq!(
        loaded, secret,
        "native keychain returned a different secret"
    );
    keychain
        .delete_secret(&reference)
        .expect("native keychain delete");
    assert_eq!(
        keychain.get_secret(&reference),
        Err(KeychainError::Missing),
        "native keychain item must be gone after cleanup"
    );
}
