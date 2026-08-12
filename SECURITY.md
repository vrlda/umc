# Security Policy

**Universal Mesh Core (UMC) / Universal Mesh Protocol (UMP)**

This file is the public entry point for security reporting and handling.

## Reporting a vulnerability

Do NOT open a public issue for security vulnerabilities.

Report privately through GitHub's private vulnerability reporting flow. Open
the repository's **Security** tab, choose **Advisories**, and select **Report a
vulnerability**. This routes the report to the project owner without exposing
it in the public issue tracker:

- **Contact:** [GitHub private vulnerability report](https://github.com/vrlda/umc/security/advisories/new)
- **Signing:** reports containing sensitive detail MAY be signed with the published operator key
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

The project owner triages reports using the severity classes in the threat model:

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
macOS arm64
Windows x86_64
```

Tier-2 fixes are best-effort. Nightly and beta releases receive no security-support commitment.

## Verification

Releases are published with:

- One operator Ed25519 signature on each release manifest
- Sigstore-compatible provenance
- SHA256SUMS and SBOM

Verify artifacts before installation. Revocation data is distributed through multiple channels.

## Repository evidence

Every published change runs the `Security evidence` CI job. It executes the
workspace regression suite, focused parser/handshake/storage checks, emergency
disablement checks, and a bounded source scan for shell-command construction.
The job uploads a machine-readable report with the commit and tree it checked.
This is solo-maintainer implementation evidence; it is not a third-party audit
or a formal protocol proof.
