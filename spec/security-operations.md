# Universal Mesh Core Security Operations Specification

**Status:** Draft
**Version:** 0.1
**Document:** Security Process and Incident Response
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines the security process for UMC: how vulnerabilities are reported, handled, disclosed, and fixed, and how the project responds to compromise of releases, keys, dependencies, and protocol features.

It specifies:

* Project-owner security authority
* Vulnerability reporting
* Triage and severity
* Embargo handling
* Disclosure process
* Security advisory format
* Supported versions
* CVE handling
* Release revocation
* Compromised signing-key procedure
* Dependency response
* Cryptographic deprecation
* Emergency protocol disablement
* Incident response
* Security review gates
* Audit and retention

This document does not define:

* Cryptographic algorithms
* The technical threat model
* Governance voting rules
* Application security

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

## Solo-maintainer v0.1 profile

UMC is currently maintained by one project owner. For v0.1, every reference to
the security team means the project owner, and every reference to the
maintainer council, quorum, or multiple reviewers is inactive future-governance
text. No second person or multi-person signing ceremony is required. Release
manifests use one operator-controlled Ed25519 key with `signing.threshold=1`.
CI verifies the public key and signature but never stores the private key. If
additional maintainers join, this profile must be replaced by an explicit
governance decision before changing the release policy.

---

# 3. Security team and authority

## 3.1 Membership

For the solo-maintainer v0.1 profile, the security authority is the project
owner:

* Owns the private contact channel
* Maintains the incident record
* Has clear escalation paths to GitHub and affected users

## 3.2 Authority

The project owner MAY:

* Triage and classify reports
* Coordinate embargoed fixes
* Approve emergency protocol or profile disablement
* Recommend release revocation
* Recommend emergency key rotation
* Act independently for time-critical containment

Emergency key rotation and permanent protocol changes are recorded by the
project owner. A future multi-maintainer governance decision may add review
requirements, but none are required for v0.1.

## 3.3 Conflict rules

A security-team member MUST recuse from:

* Their own security report
* Their employer's commercial dispute
* Enforcement involving themselves

---

# 4. Vulnerability reporting

## 4.1 Reporting channels

The project MUST publish:

* A private security contact
* A reporting format
* PGP or equivalent signing expectations for sensitive reports
* Expected response time

The public issue tracker MUST NOT be used for embargoed vulnerabilities.

## 4.2 Report contents

A report SHOULD include:

```text
Affected component and version
Vulnerability description
Reproduction steps
Impact assessment
Suggested fix if known
Disclosure constraints
```

## 4.3 Report handling

On receipt, the security team MUST:

1. Acknowledge within the response-time target.
2. Assign a tracking identifier.
3. Assess validity and severity.
4. Escalate `CRITICAL` findings immediately.
5. Keep the reporter informed.

---

# 5. Triage and severity

Severity follows the threat-model classification:

| Severity | Impact |
| --- | --- |
| `CRITICAL` | Broad key compromise, release compromise, undetected remote code execution, or cross-endpoint plaintext exposure |
| `HIGH` | Endpoint impersonation, session compromise, persistent isolation, or major remote denial of service |
| `MEDIUM` | Scoped metadata disclosure, route manipulation, bounded denial of service, or policy bypass with constraints |
| `LOW` | Minor fingerprinting, diagnostic disclosure, or recoverable local degradation |

Triage MUST consider:

* Attack surface exposure
* Exploitability
* Affected components
* Deployment impact
* Interaction with other weaknesses

---

# 6. Embargo handling

## 6.1 Embargo policy

The project SHOULD use coordinated disclosure:

* Default embargo of 90 days from confirmation
* Extensions by mutual agreement
* Shortened embargo for actively exploited `CRITICAL` issues
* Immediate public warning when exploitation is detected in the wild

## 6.2 Embargo rules

During an embargo, participants MUST NOT:

* Discuss the issue on public channels
* Commit visible fixes to public branches without coordination
* Publish exploit details
* Share details beyond the trusted list

The trusted list MUST be minimal and recorded.

## 6.3 Embargoed fixes

Embargoed fixes:

* Are prepared on private branches
* Receive review by at least two security-team members
* Are tested against regression suites
* Are released on a coordinated date

---

# 7. Disclosure process

On disclosure day, the project MUST publish:

1. A security advisory.
2. Patched releases for supported versions.
3. Verifiable patch and release signatures.
4. Update guidance.

The advisory MUST NOT disclose exploit details beyond what is needed for remediation when exploitation risk remains.

---

# 8. Security advisory format

Every advisory contains:

```text
Advisory ID
Severity
CVE identifier when assigned
Affected versions
Fixed versions
Summary
Impact
Attack conditions
Mitigations and workarounds
Timeline (reported, fixed, disclosed)
Credits
References
```

Advisories:

* Are signed or published through the release-signing workflow
* Are archived permanently
* Are machine-readable where tooling supports it
* Follow a stable numbering scheme

---

# 9. Supported versions

## 9.1 Support policy

Security fixes are supported for Tier-1 platforms:

```text
Linux x86_64
macOS arm64
Windows x86_64
```

Linux aarch64, macOS x86_64, Windows arm64, and FreeBSD x86_64 are Tier-2;
fixes for those platforms are best-effort.

## 9.2 Version policy

The project MUST document:

* Which release lines receive security fixes
* The supported protocol versions
* The supported storage schema versions
* The support window for each release
* The deprecation process for old versions

Nightly and beta releases receive no security-support commitment.

## 9.3 Update path

Users MUST be able to:

* Verify release signatures
* Detect version rollback
* Obtain security revocation data through several channels

---

# 10. CVE handling

The project SHOULD:

* Maintain CVE assignment capability through a CNA or equivalent
* Assign identifiers to qualifying vulnerabilities
* Include CVEs in advisories and release notes
* Reserve identifiers only for confirmed, disclosed issues

CVE assignment MUST NOT delay coordinated disclosure.

---

# 11. Release revocation

## 11.1 Revocation triggers

A release is revoked when:

* Its signing key is compromised
* Its artifacts are found malicious or corrupt
* A published binary does not match its manifest
* A critical vulnerability makes the release unsafe to run

## 11.2 Revocation procedure

On revocation, the project MUST:

1. Publish a revocation notice through the advisory channel.
2. Revoke or invalidate the release manifest signatures.
3. Remove or clearly mark affected artifacts.
4. Publish replacement releases.
5. Instruct users how to verify and replace installations.
6. Record the revocation in the audit log.

## 11.3 Offline users

Revocation data MUST be obtainable through several channels so disconnected users can still learn of revoked releases.

---

# 12. Compromised signing-key procedure

## 12.1 Detection

Compromise is suspected when:

* A signing key is lost or exposed
* An unexpected artifact appears under a valid signature
* A hardware token reports unauthorized use
* An audit reveals an unexplained signing operation

## 12.2 Response

The project owner MUST:

1. Stop signing with the affected key.
2. Publish a revocation statement.
3. Rotate the single operator signing key.
4. Publish the replacement public key and its key ID.
5. Re-issue release manifests under the new keys.
6. Instruct users to update their verification material.

## 12.3 Constraints

* CI MUST NOT possess the private signing key.
* Revocation documents MUST be prepared in advance.
* Emergency rotation MUST preserve the one-signature v0.1 policy.

# 13. Dependency response

## 13.1 Monitoring

The project MUST:

* Scan dependencies for advisories
* Review security-sensitive crates
* Use lockfiles and reproducible builds
* Generate an SBOM for releases
* Track license compatibility

## 13.2 Response

On a dependency vulnerability, the project MUST:

1. Assess exposure for the affected components.
2. Determine whether the dependency is reachable from network or local attack surfaces.
3. Apply an embargoed fix when the dependency fix is embargoed.
4. Pin or replace the dependency under emergency policy.
5. Publish a fix for supported release lines.
6. Record the exposure assessment.

## 13.3 Emergency replacement

When a dependency cannot be fixed quickly, the project MAY:

* Replace the dependency
* Vendor and audit a minimal implementation
* Disable the affected feature or carrier
* Issue an advisory with mitigation guidance

The project MUST NOT leave a known exploitable dependency unreachable to fixes in supported releases.

---

# 14. Cryptographic deprecation

## 14.1 Principles

Cryptographic profiles are versioned.

Deprecation MUST NOT permit silent downgrade: negotiation is bound into the handshake transcript.

A deprecated profile:

* Remains listed in the registry with a deprecated marker
* Loses support on a documented timeline
* MUST NOT be selected by new handshakes after its removal date
* May be retained for compatibility during migration

## 14.2 Deprecation procedure

The project MUST:

1. Announce deprecation with a timeline.
2. Publish the replacement profile.
3. Provide migration guidance and test vectors.
4. Keep both profiles during the overlap window.
5. Remove the deprecated profile only after the overlap window.

## 14.3 Emergency deprecation

When a profile is found cryptographically broken:

* The security team MAY disable it immediately.
* The project MUST publish an emergency advisory.
* The project MUST rotate affected keys and tickets where possible.
* The project MUST document the migration path.

Stable releases MUST exclude unreviewed experimental cryptography.

---

# 15. Emergency protocol disablement

## 15.1 Scope

Emergency disablement may cover:

* A protocol version
* A cryptographic profile
* A capability
* A carrier
* A relay service

## 15.2 Mechanism

The project MUST define a mechanism to:

* Disable a version or profile through configuration or update
* Revoke acceptance of the affected feature
* Notify users through supported update channels
* Preserve unaffected functionality

## 15.3 Constraints

Disablement:

* MUST NOT create an insecure fallback
* MUST NOT silently change protocol semantics
* MUST be reversible through an approved re-enablement when safe

---

# 16. Incident response

## 16.1 Phases

Incident response follows:

```text
Detect
Contain
Eradicate
Recover
Lessons
```

## 16.2 Containment actions

Containment MAY include:

* Blocking peers and revoking local credentials
* Disabling one carrier or plugin
* Disabling relay service
* Rotating handshake, ticket, Retry, invitation, and release keys
* Revoking endpoint bindings
* Disabling protocol versions or cryptographic profiles
* Rebuilding route and peer caches
* Restoring validated storage backups
* Exporting redacted diagnostics

Containment actions MUST state which security state survives and which becomes invalid.

## 16.3 Postmortem

After an incident, the project MUST:

* Publish a postmortem when appropriate
* Identify root causes
* Assign remediation owners
* Add regression tests
* Update the threat model and security process

---

# 17. Security review gates

For the current solo-maintainer v0.1 experimental profile, the project owner
MUST perform and record the following implementation reviews using source
tracing, independent vectors, adversarial tests, and dependency evidence:

1. Handshake and cryptographic implementation review.
2. Network parser and unsafe-code implementation audit.
3. Adversarial review of routing, relaying, and discovery.
4. Local API authorization review.
5. Storage and migration review.
6. Carrier/plugin boundary review.
7. Reproducible-build and release-signing review.

No human third-party sign-off is required for this profile because no second
maintainer or reviewer exists. The project MUST NOT describe this evidence as
a human audit or production-security certification. If additional maintainers
join or production-security claims become a goal, the owner MUST obtain the
corresponding external reviews before changing that claim.

The project MUST maintain:

* Wire and handshake test vectors
* Parser fuzz targets
* State-machine property tests
* Cross-implementation tests
* Adversarial network simulation
* Dependency audit and SBOM
* Unsafe-code inventory
* Cryptographic review record
* Security regression tests
* Release provenance and signature verification tests

A stable v0.1 release MUST NOT claim production security until the gates in `threat-model.md` complete.

---

# 18. Audit and retention

## 18.1 Audit records

The project MUST record:

* Vulnerability reports and handling
* Embargo participants
* Advisory publication
* Release revocation events
* Key rotation events
* Dependency incidents
* Incident postmortems

## 18.2 Retention

Retention follows operator policy and platform constraints.

Records MUST be:

* Redacted of secrets
* Access-controlled
* Expired on a documented schedule
* Preserved across release processes

---

# 19. Communication channels

The project MUST publish:

* A private security contact
* A public advisory feed
* Release and update channels
* Revocation distribution channels

Advisories MUST reach:

* Direct users
* Package managers and distribution channels
* Disconnected users through multiple offline-capable channels where feasible

---

# 20. Required tests

The security process MUST be tested through:

1. Simulated vulnerability report handling.
2. Embargo coordination drill.
3. Advisory publication dry run.
4. Release revocation exercise.
5. Emergency key rotation exercise.
6. Dependency incident response drill.
7. Cryptographic deprecation migration test.
8. Emergency protocol disablement test.
9. Incident containment drill.
10. Postmortem and remediation tracking.

---

# 21. Minimal v0.1 compliance

A compliant v0.1 project MUST have:

* A published private security contact
* A documented reporting process
* The project owner with a private reporting channel
* Severity classification
* Coordinated disclosure policy
* Advisory format
* Supported-version policy
* Release-signing verification
* Revocation procedure
* Dependency monitoring
* Cryptographic deprecation policy
* Emergency disablement mechanism
* Security review gate checklist

---

# 22. Open design decisions

The project must resolve:

1. Private contact email and key distribution.
2. Advisory numbering scheme.
3. CVE CNA relationship.
4. Response-time targets.
5. Default embargo duration.
6. Supported-release window length.
7. Audit retention period.
8. Postmortem publication policy.
9. Emergency disablement mechanism details.
10. Whether Tier-2 platforms receive backports.

---

# 23. Recommended implementation order

Implement security operations in this order:

1. Private contact and reporting template.
2. Severity classification.
3. Response-time targets.
4. Embargo workflow.
5. Advisory template.
6. Supported-version policy.
7. Release verification tooling.
8. Revocation procedure.
9. Key-rotation procedure.
10. Dependency monitoring.
11. Deprecation policy.
12. Emergency disablement mechanism.
13. Incident response playbook.
14. Security review gate checklist.

---

# 24. Core rule

UMC treats security as a process with defined authority, timelines, and records.

Reports are acknowledged, triaged, and disclosed under coordinated policy. Embargoes are minimal and enforced. Releases and keys are verifiable and revocable. Dependencies and cryptographic profiles have deprecation and emergency paths. Every incident produces containment, remediation, and lasting tests.
