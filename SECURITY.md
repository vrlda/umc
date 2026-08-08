# Security Policy

**Universal Mesh Core (UMC) / Universal Mesh Protocol (UMP)**

This file is the public entry point for security reporting and handling. The full process, authority, timelines, and procedures are defined in [spec/security-operations.md](spec/security-operations.md).

## Reporting a vulnerability

Do NOT open a public issue for security vulnerabilities.

Report privately to the security team. The production reporting channel has
not yet been assigned; its owner must replace `TBD-contact` before a public
release:

- **Contact:** `TBD-contact`
- **Signing:** reports containing sensitive detail SHOULD be signed with the published security key
- **Response target:** acknowledgment within 3 business days; severity assessment within 7 days; a fix, mitigation, or agreed disclosure plan within the 90-day SLA

Include:

```text
Affected component and version
Vulnerability description
Reproduction steps
Impact assessment
Suggested fix if known
Disclosure constraints
```

## Handling

The security team triages reports using the severity classes in the threat model:

| Severity | Meaning |
| --- | --- |
| `CRITICAL` | Key or release compromise, remote code execution, cross-endpoint plaintext |
| `HIGH` | Impersonation, session compromise, persistent isolation, major denial of service |
| `MEDIUM` | Scoped metadata disclosure, route manipulation, bounded denial of service |
| `LOW` | Minor fingerprinting or local degradation |

Coordinated disclosure is the default: the 90-day disclosure SLA starts when
the report is confirmed. The security owner gives the reporter a status update
at least every 14 days, records the affected versions and remediation owner,
and requests an extension before the deadline when a fix needs more time.
Actively exploited critical issues are disclosed earlier, with the least
possible exploit detail.

## Supported versions

Security fixes are supported for Tier-1 platforms:

```text
Linux x86_64
Linux aarch64
macOS arm64
Windows x86_64
```

Tier-2 fixes are best-effort. Nightly and beta releases receive no security-support commitment.

## Verification

Releases are published with:

- Threshold maintainer signatures on release manifests
- Sigstore-compatible provenance
- SHA256SUMS and SBOM

Verify artifacts before installation. Revocation data is distributed through multiple channels.

## Related documents

- Threat model: [spec/threat-model.md](spec/threat-model.md)
- Security operations: [spec/security-operations.md](spec/security-operations.md)
- Release signing and governance: [spec/decisions.md](spec/decisions.md)
