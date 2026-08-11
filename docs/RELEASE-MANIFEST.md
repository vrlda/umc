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
    "threshold": 1,
    "signatures": [
      { "key_id": "<operator-key-id>", "file": "manifest.sig" }
    ]
  }
}
```

## Signing and verification

The repository ships two small OpenSSL 3.x wrappers:

```text
scripts/sign-release-manifest.sh manifest.json operator-private.pem manifest.sig
scripts/verify-release-manifest.sh manifest.json operator-public.pem manifest.sig
```

The key must be an Ed25519 private/public key pair. The wrappers sign and
verify the manifest as raw bytes with `openssl pkeyutl`; a non-zero exit status
rejects the artifact. The v0.1 release policy is one operator-controlled
Ed25519 key and one signature (`1-of-1`). There is no council, quorum, or
multi-person signing ceremony. CI may verify the public key and signature but
never receives the private key.

The threshold enforcement command is:

```text
scripts/verify-release-threshold.sh manifest.json trusted-public-keys/
```

The trusted public key is named `<sha256(public-key-file-bytes)>.pem`. The
verifier requires exactly one signature, rejects unknown or duplicate key IDs,
rejects signature paths that escape the manifest directory, verifies the
signature over the exact manifest bytes, and emits a machine-readable result.

## Key management and revocation

- Generate the operator key offline, keep the private key in hardware or
  encrypted offline storage, and never commit it or put it in CI logs.
- Publish only the key ID and Ed25519 public key in release metadata. A key
  ID is a stable hash of the canonical public-key bytes.
- Rotate the key before expiry or immediately after suspected compromise. A
  rotation release publishes the new key ID and public key; operators update
  their trust store before accepting the next release.
- Revoke a key by writing a revocation record for its key endpoint/ID in the
  UMC trust store (`RevocationStore`), including the revocation sequence and
  `not_after` cutoff. Distribution must use at least two independent channels;
  clients refuse manifests signed only by a revoked key.
- The signature is a release authenticity check, not a substitute for review:
  the operator records the key ID and verification output alongside artifacts.

## Reproducibility checklist

Before publication, the release owner records the commit, target, artifact
hashes, storage/protocol versions, SBOM hash, provenance, signer IDs, and key
revocation snapshot in the rendered manifest. The release record also retains
the clean-tree `umc-platform-evidence-v1` artifact from
[`docs/PLATFORM-EVIDENCE.md`](PLATFORM-EVIDENCE.md) for every Tier-1 target.
Optional Tier-2 platform records may be retained alongside it. Installation
tooling verifies the manifest signatures and all artifact hashes before
unpacking.

The benchmark/soak evidence is generated with
[`scripts/release-baseline.sh`](../scripts/release-baseline.sh), which rejects
dirty trees, and must pass
[`scripts/verify-release-baseline.sh`](../scripts/verify-release-baseline.sh)
before the release record retains it.

Dependency evidence is generated with
[`scripts/dependency-audit.sh`](../scripts/dependency-audit.sh). It binds a
locked Cargo metadata SBOM, dependency tree, `cargo-audit` advisory result,
committed tree, and copied Cargo.lock digest into `dependency-report.json`; a
dirty tree or non-zero advisory count fails the command. Before retention,
[`scripts/verify-dependency-audit.sh`](../scripts/verify-dependency-audit.sh)
must validate the report and every evidence artifact.
