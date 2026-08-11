# UMEP-0001: Universal Mesh Extension Proposal Process

- **Status:** Draft
- **Category:** Process
- **Author:** Project maintainers
- **Created:** August 2026
- **Requires:** None

---

# 1. Summary

This document defines the UMEP process: how the Universal Mesh Project proposes, reviews, and accepts changes to the Universal Mesh Protocol (UMP), the Universal Mesh Core (UMC) architecture, and project process itself.

UMEP stands for **Universal Mesh Extension Proposal**.

This document is itself a UMEP and is the first of the series.

---

# 2. Purpose

UMEPs give every protocol-affecting change a public, reviewable, and versioned path.

A UMEP:

* Documents motivation and design before implementation
* Forces explicit analysis of security, privacy, censorship, and resource impact
* Provides test vectors and migration plans
* Creates a public record of decisions
* Allows independent implementations to track protocol evolution

Protocol changes that skip the UMEP process are not eligible for stable release.

---

# 3. Scope

The UMEP process applies to changes affecting:

* UMP wire format
* Handshake and cryptography
* Session and transport semantics
* Routing and relaying
* Bundles
* Discovery
* Carrier interfaces and profiles
* Control API compatibility
* Storage schema
* SDK stability
* Project process and governance

Changes that do not alter protocol or compatibility semantics MAY skip the UMEP process at maintainer discretion.

---

# 4. Categories

Every UMEP has one category.

| Category | Purpose |
| --- | --- |
| Standards Track | Changes to protocol or interoperability requirements |
| Experimental | Optional features tested before stabilization |
| Informational | Records of decisions, analyses, or guidance |
| Process | Changes to project process or governance |

Standards Track and Experimental proposals may include normative requirements.

Informational and Process proposals describe or change the project itself.

---

# 5. States

A UMEP passes through these states:

```text
Draft
Review
Experimental
Accepted
Final
Withdrawn
Rejected
Superseded
```

## 5.1 Draft

The author is developing the proposal.

## 5.2 Review

The proposal is under public review.

## 5.3 Experimental

The proposal is implemented and deployed under an experimental marker, not part of the stable baseline.

## 5.4 Accepted

The proposal passed review and is approved for implementation toward the stable baseline.

## 5.5 Final

The proposal is part of the stable baseline.

## 5.6 Withdrawn

The author withdrew the proposal.

## 5.7 Rejected

The project declined the proposal.

## 5.8 Superseded

A later proposal replaced this one.

---

# 6. File and numbering conventions

## 6.1 Files

Proposal filenames:

```text
umeps/0001-process.md
umeps/0002-example-extension.md
```

## 6.2 Numbers

UMEP numbers:

* Are assigned in ascending order
* Are never reused
* Are permanent even after Withdrawn, Rejected, or Superseded

## 6.3 Header

Every UMEP begins with:

```text
# UMEP-<number>: <Title>

- **Status:** <state>
- **Category:** <category>
- **Author:** <author>
- **Created:** <date>
- **Updated:** <date>
- **Requires:** <UMEP numbers or none>
```

---

# 7. Required sections

Every Standards Track UMEP MUST contain:

1. Summary
2. Motivation
3. Detailed design
4. Wire-format impact
5. Security impact
6. Privacy impact
7. Censorship-resistance impact
8. Resource-exhaustion impact
9. Compatibility
10. Downgrade behavior
11. Migration plan
12. Test vectors
13. Alternatives
14. Unresolved questions

Experimental proposals SHOULD use the same sections, scaled to the feature.

Informational and Process proposals MUST include at least:

1. Summary
2. Motivation
3. Detailed design
4. Alternatives
5. Unresolved questions

---

# 8. Section guidance

## 8.1 Wire-format impact

State:

* New or changed frames, fields, or packet classes
* Encoding rules
* Parser behavior
* Versioning impact

## 8.2 Security impact

Analyze:

* New assets and trust boundaries
* New attacker capabilities
* Required defenses
* Explicit non-defenses
* Residual risk

## 8.3 Privacy impact

Analyze:

* New metadata exposure
* Linkability
* Enumeration surface
* Disclosure controls

## 8.4 Censorship-resistance impact

Analyze:

* Carrier-visible behavior changes
* Blocking surface
* Fallback behavior

## 8.5 Resource-exhaustion impact

Analyze:

* New state per peer, session, or packet
* CPU and memory bounds
* Rate limits
* Admission behavior

## 8.6 Compatibility

State:

* What breaks
* What remains compatible
* Version negotiation impact
* Registry allocations needed

## 8.7 Downgrade behavior

State:

* What happens when peers negotiate the old behavior
* Whether downgrade is authenticated
* Whether insecure fallback is possible

## 8.8 Test vectors

Standards Track proposals MUST include or reference test vectors before Final.

---

# 9. Review process

## 9.1 Sponsorship

Protocol-affecting proposals require:

```text
Two maintainer sponsors
```

## 9.2 Public review

Every proposal receives a public review period.

The review period:

* Is announced on project channels
* Has a stated duration
* Accepts comments from any participant
* Requires responses to substantive comments

## 9.3 Security review

Every protocol-affecting proposal receives security review.

Security-critical proposals MUST receive independent expert review before stabilization.

## 9.4 Cryptographic review

Cryptographic changes require independent expert review.

Custom cryptographic primitives are forbidden.

A cryptographic change MUST:

* Justify the change against the current profile
* Provide test vectors
* Document the deprecation path
* Follow the cryptographic-deprecation policy in `security-operations.md`

---

# 10. Acceptance requirements

A Standards Track proposal is Accepted when:

* Two maintainer sponsors support it
* At least one implementation exists or is committed
* Interoperability tests pass where relevant
* Security review completed
* Public review period completed
* No unresolved critical objection

The maintainer council makes the final decision under governance rules.

---

# 11. Implementation requirements

## 11.1 One implementation

A proposal MUST NOT become Final without:

* A working reference implementation
* Passing tests

## 11.2 Interoperability

Where relevant, a proposal MUST include:

* Interoperability tests between independent implementations
* Test vectors all implementations must pass

## 11.3 Experimental deployment

A proposal MAY be implemented and deployed as Experimental before Acceptance.

Experimental features:

* MUST be explicitly marked
* MUST NOT silently alter stable interoperability
* Receive no stability guarantee

---

# 12. Registries and identifier allocation

## 12.1 Registries

The repository maintains registries for:

```text
Protocol versions
Cryptographic profiles
Frame types
Capability identifiers
Carrier identifiers
Error codes
Control API versions
```

Registry assignment does not imply endorsement.

## 12.2 Allocation

Allocation rules:

* Stable identifiers require a UMEP or maintainer-approved allocation
* Private and experimental ranges exist without central approval
* Registry entries record the allocating proposal

## 12.3 Runtime independence

Registries MUST NOT create a dependency on an online central authority at runtime.

Registry coordination is a development process, not a network dependency.

---

# 13. Withdrawal, rejection, and supersession

## 13.1 Withdrawal

The author may withdraw a Draft or Review proposal at any time.

## 13.2 Rejection

A proposal is Rejected when the council declines it or a critical objection remains unresolved.

## 13.3 Supersession

A later proposal MAY supersede an earlier one.

The later proposal MUST:

* Reference the superseded UMEP
* Explain what changes
* Preserve compatibility or document the break

Supersession does not remove Final status from prior protocol versions in the field.

---

# 14. Relationship to other processes

## 14.1 Governance

The maintainer council:

* Approves maintainer sponsorships
* Makes acceptance decisions
* Resolves disputes

Voting follows `GOVERNANCE.md`.

## 14.2 Security

Security-critical issues follow `security-operations.md`.

An active embargo may delay public review of a related proposal.

## 14.3 Compatibility

Accepted and Final UMEPs interact with the compatibility policy in `compatibility.md`.

A proposal MUST state its compatibility class.

## 14.4 Releases

A UMEP becomes effective for a release when:

* The release includes the implementation
* The release manifest documents supported protocol versions

---

# 15. Timeline expectations

Realistic expectations:

* Draft: 1-4 weeks
* Review: 2-8 weeks
* Experimental: 1-6 months
* Accepted to Final: depends on implementation

Small process or informational UMEPs may move faster.

---

# 16. Required tests for this process

The process itself MUST be tested by:

1. Submitting a draft proposal.
2. Moving through review.
3. Incorporating security review.
4. Obtaining sponsors.
5. Allocating a registry entry.
6. Withdrawing a proposal cleanly.
7. Superseding a proposal.
8. Running the example extension UMEP-0002 through the lifecycle.

---

# 17. Open questions

1. Review-period default duration.
2. Whether GitHub discussions or issues host review.
3. Registry file format.
4. Whether Experimental features may ship in stable releases.
5. Post-quantum transition handling as a UMEP category.
6. Whether Informational UMEPs require sponsors.

---

# 18. Core rule

A UMEP is the public, reviewable, versioned path for every change that affects UMP, UMC compatibility, or project process.

Proposals state motivation, design, security, privacy, censorship, resource, compatibility, downgrade, migration, and test impact before implementation. Acceptance requires sponsors, review, an implementation, interoperability evidence, and no unresolved critical objection. Registry entries record allocations without creating runtime authority.
