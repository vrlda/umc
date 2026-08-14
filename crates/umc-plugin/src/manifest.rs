//! Signed external-plugin manifest verification.
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use std::path::Path;
use umc_crypto::signatures::{IdentityKeyPair, IdentityPublicKey, PUBLIC_KEY_LEN, SIGNATURE_LEN};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalPluginManifest {
    pub id: String,
    pub version: (u32, u32, u32),
    pub executable_digest: [u8; 32],
    pub capabilities: Vec<String>,
    pub sandbox_mode: String,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub signer: [u8; PUBLIC_KEY_LEN],
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    Malformed(String),
    SignatureInvalid,
    SignerUntrusted,
    DigestMismatch,
    CapabilityMismatch,
    Expired,
}

impl ExternalPluginManifest {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        version: (u32, u32, u32),
        executable_digest: [u8; 32],
        capabilities: Vec<String>,
        not_before_ms: u64,
        not_after_ms: u64,
    ) -> Self {
        Self {
            id: id.into(),
            version,
            executable_digest,
            capabilities,
            sandbox_mode: "disabled".into(),
            not_before_ms,
            not_after_ms,
            signer: [0; PUBLIC_KEY_LEN],
            signature: vec![0; SIGNATURE_LEN],
        }
    }

    /// # Errors
    ///
    /// This currently cannot fail; result is retained for future manifest
    /// validation additions.
    pub fn sign(&mut self, signer: &IdentityKeyPair) -> Result<(), ManifestError> {
        self.signer = signer.public().0;
        self.signature = signer.sign(&self.canonical_bytes()).to_vec();
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error when identity, signature, digest, capabilities, or
    /// validity interval does not match the launch policy.
    pub fn verify(
        &self,
        trusted_keys: &[IdentityPublicKey],
        expected_id: &str,
        executable_digest: [u8; 32],
        granted_capabilities: &[String],
        expected_sandbox_mode: &str,
        now_ms: u64,
    ) -> Result<(), ManifestError> {
        if self.id != expected_id
            || self.version == (0, 0, 0)
            || self.not_after_ms < self.not_before_ms
        {
            return Err(ManifestError::Malformed(
                "invalid identity or validity interval".into(),
            ));
        }
        if now_ms < self.not_before_ms || now_ms > self.not_after_ms {
            return Err(ManifestError::Expired);
        }
        if self.executable_digest != executable_digest {
            return Err(ManifestError::DigestMismatch);
        }
        if self.sandbox_mode != expected_sandbox_mode {
            return Err(ManifestError::CapabilityMismatch);
        }
        if self.capabilities.iter().any(|capability| {
            !granted_capabilities
                .iter()
                .any(|granted| granted == capability)
        }) {
            return Err(ManifestError::CapabilityMismatch);
        }
        let signer = IdentityPublicKey(self.signer);
        if !trusted_keys.iter().any(|trusted| trusted == &signer) {
            return Err(ManifestError::SignerUntrusted);
        }
        if !signer.verify(&self.canonical_bytes(), &self.signature) {
            return Err(ManifestError::SignatureInvalid);
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error when the executable cannot be read.
    pub fn executable_digest(path: &Path) -> Result<[u8; 32], ManifestError> {
        let bytes =
            std::fs::read(path).map_err(|error| ManifestError::Malformed(error.to_string()))?;
        Ok(Blake2s256::digest(bytes).into())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"UMC-PLUGIN-MANIFEST-v1\0");
        append_string(&mut bytes, &self.id);
        for component in [self.version.0, self.version.1, self.version.2] {
            bytes.extend_from_slice(&component.to_be_bytes());
        }
        bytes.extend_from_slice(&self.executable_digest);
        bytes.extend_from_slice(
            &u32::try_from(self.capabilities.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for capability in &self.capabilities {
            append_string(&mut bytes, capability);
        }
        append_string(&mut bytes, &self.sandbox_mode);
        bytes.extend_from_slice(&self.not_before_ms.to_be_bytes());
        bytes.extend_from_slice(&self.not_after_ms.to_be_bytes());
        bytes.extend_from_slice(&self.signer);
        bytes
    }
}

fn append_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_manifest_round_trips_and_detects_tampering() {
        let signer = IdentityKeyPair::from_seed([7; 32]);
        let mut manifest = ExternalPluginManifest::new(
            "plugin.test",
            (1, 2, 3),
            [9; 32],
            vec!["datagram".into()],
            1,
            10_000,
        );
        manifest.sign(&signer).expect("sign");
        manifest
            .verify(
                &[signer.public()],
                "plugin.test",
                [9; 32],
                &["datagram".into()],
                "disabled",
                100,
            )
            .expect("verify");
        manifest.id = "tampered".into();
        assert!(manifest
            .verify(
                &[signer.public()],
                "plugin.test",
                [9; 32],
                &["datagram".into()],
                "disabled",
                100
            )
            .is_err());
    }

    #[test]
    fn manifest_rejects_expiry_and_capability_mismatch() {
        let signer = IdentityKeyPair::from_seed([8; 32]);
        let mut manifest = ExternalPluginManifest::new(
            "plugin.test",
            (1, 0, 0),
            [1; 32],
            vec!["datagram".into()],
            10,
            20,
        );
        manifest.sign(&signer).expect("sign");
        assert_eq!(
            manifest.verify(
                &[signer.public()],
                "plugin.test",
                [1; 32],
                &["datagram".into()],
                "disabled",
                21
            ),
            Err(ManifestError::Expired)
        );
        assert_eq!(
            manifest.verify(
                &[signer.public()],
                "plugin.test",
                [1; 32],
                &[],
                "disabled",
                15
            ),
            Err(ManifestError::CapabilityMismatch)
        );
    }
}
