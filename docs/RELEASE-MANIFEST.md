# Release manifest

This file is the canonical template for the bytes signed for a UMC/UMP
release. The release job must render a concrete copy with no comments,
placeholder values, or uncommitted changes before signing. Sign the exact
UTF-8 bytes (including the final newline); do not reformat JSON after signing.

```json
{
  "manifest_version": 1,
  "release": "0.0.0",
  "git_commit": "<40-hex-commit>",
  "protocol_versions": [1],
  "storage_schema": 1,
  "artifacts": [
    {
      "name": "umcd-<target>",
      "sha256": "<64-lowercase-hex>"
    }
  ],
  "sbom": {
    "format": "cargo-metadata-v1",
    "sha256": "<64-lowercase-hex>"
  },
  "provenance": {
    "builder": "<ci-workflow-id>",
    "source": "<source-attestation-id>"
  },
  "signing": {
    "threshold": 2,
    "signatures": [
      { "key_id": "<maintainer-key-id>", "file": "manifest.sig" }
    ]
  }
}
```

## Signing and verification

The repository ships two small OpenSSL 3.x wrappers:

```text
scripts/sign-release-manifest.sh manifest.json maintainer-private.pem manifest.sig
scripts/verify-release-manifest.sh manifest.json maintainer-public.pem manifest.sig
```

The key must be an Ed25519 private/public key pair. The wrappers sign and
verify the manifest as raw bytes with `openssl pkeyutl`; a non-zero exit status
rejects the artifact. A release pipeline runs verification for every
signature and enforces the `signing.threshold` value (the initial policy is
2-of-3 maintainer keys). The single-signature wrapper is deliberately small so
that threshold policy stays in the reviewable release job rather than being
silently bypassed by a local helper.

## Key management and revocation

- Generate maintainer keys offline, keep private keys in separate hardware or
  encrypted offline storage, and never commit them or put them in CI logs.
- Publish only key IDs and Ed25519 public keys in the release metadata. A key
  ID is a stable hash of the canonical public-key bytes.
- Rotate keys before expiry or immediately after suspected compromise. A
  rotation release carries both the old and new key IDs while the old key is
  still valid, so consumers can update their trust store.
- Revoke a key by writing a revocation record for its key endpoint/ID in the
  UMC trust store (`RevocationStore`), including the revocation sequence and
  `not_after` cutoff. Distribution must use at least two independent channels;
  clients refuse manifests signed only by a revoked key.
- The signing threshold is a release policy, not a substitute for review:
  every signature covers the same manifest bytes, and the release job records
  the signer IDs and verification output alongside the artifacts.

## Reproducibility checklist

Before publication, the release owner records the commit, target, artifact
hashes, storage/protocol versions, SBOM hash, provenance, signer IDs, and key
revocation snapshot in the rendered manifest. Installation tooling verifies the
manifest signatures and all artifact hashes before unpacking.
