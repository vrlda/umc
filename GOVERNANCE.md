# Universal Mesh Project Governance

**Status:** Draft — solo-maintainer v0.1 profile
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Overview

This document defines how the Universal Mesh Project is governed: who holds authority, how decisions are made, and how the project survives the departure or failure of any individual.

For the current v0.1 repository, the model is one project owner operating with
GitHub and CI. The owner holds release, security, and module authority. The
council, quorum, and succession sections below are future-governance notes and
do not create current requirements; there are no other maintainers today.

Release manifests use one operator-controlled Ed25519 key (`1-of-1`). CI only
verifies the public key and never receives the private key.

---

# 2. Principles

The project follows these principles:

1. Public governance.
2. Decisions by rough consensus, with defined fallbacks.
3. Separation of protocol, release, security, and module authority.
4. Keep the current operating model small and auditable.
5. Succession and removal procedures defined in advance.
6. Specification and protocol changes are public and reviewable.
7. No mandatory project-operated infrastructure.
8. A fork can continue the network without permission from the original maintainers.

---

# 3. Maintainer Council

## 3.1 Role

The Maintainer Council is responsible for:

* Project direction
* Stable releases
* Governance
* Specification acceptance
* Security policy
* Maintainer appointments

## 3.2 Size

Target size:

```text
3–7 maintainers
```

The council SHOULD NOT fall below three members.

## 3.3 Appointment

New council members are appointed by:

1. Nomination by a council member.
2. Consent of the existing council.
3. Demonstrated contribution to the project.

Appointment MUST NOT require:

* Corporate affiliation
* Employment by any organization
* Payment

## 3.4 Composition

The council SHOULD include members with:

* Protocol and cryptographic review experience
* Implementation experience
* Security operations experience
* Platform and packaging experience

Diversity of employment, geography, and conflict domains is encouraged.

---

# 4. Council responsibilities

## 4.1 Specification acceptance

The council:

* Accepts or rejects UMEPs
* Appoints UMEP sponsors
* Maintains the extension registries

## 4.2 Releases

The council:

* Authorizes stable releases
* Approves release manifests
* Manages release-signing thresholds

## 4.3 Security

The council:

* Appoints the security team
* Approves emergency key rotation
* Approves permanent protocol changes

## 4.4 Governance

The council:

* Amends this document
* Resolves disputes
* Removes inactive or harmful maintainers

---

# 5. Module maintainers

The council delegates module ownership:

| Module | Responsibility |
| --- | --- |
| Wire format | Packet and frame encoding, parser behavior |
| Cryptography | Handshake, key schedule, crypto profiles |
| Runtime | Session, streams, datagrams, congestion |
| Routing | Route discovery, cache, strategies |
| Storage | Database, keystore, migrations |
| Carriers | TCP, UDP, LAN, plugin protocol |
| SDK | Rust SDK, bindings, C ABI |
| Tooling | CLI, diagnostics, test tooling |

## 5.1 Authority

A module maintainer:

* Reviews and merges changes in their module
* Owns module-level technical decisions
* Reports to the council on breaking changes

## 5.2 Limits

A module maintainer MUST NOT:

* Change protocol semantics without a UMEP
* Change compatibility classes without council approval
* Bypass security review for security-sensitive modules
* Override a council decision within their module

---

# 6. Security team

The security team:

* Is appointed by the council
* Has a minimum of two members
* Has a private contact channel
* Handles embargoed vulnerabilities

## 6.1 Authority

The security team MAY:

* Triage and classify reports
* Coordinate embargoed fixes
* Approve emergency protocol or profile disablement
* Recommend release revocation
* Recommend emergency key rotation
* Act independently for time-critical containment

Emergency key rotation and permanent protocol changes require council approval.

## 6.2 Recusal

A security-team member MUST recuse from:

* Their own security report
* Their employer's commercial dispute
* Enforcement involving themselves

The security team follows `security-operations.md`.

---

# 7. Decision method

## 7.1 Normal decisions

Normal decisions use:

```text
rough consensus
```

## 7.2 Fallback

If consensus fails:

```text
simple majority of non-conflicted council members
```

## 7.3 Supermajority

Protocol-breaking or governance changes require:

```text
two-thirds majority
```

## 7.4 Quorum

A decision requires:

* A quorum of a majority of council members
* A recorded vote for fallback and supermajority decisions

## 7.5 No objection model

A decision MAY proceed when no council member objects after a stated period.

Objections MUST be substantive and recorded.

---

# 8. Voting procedures

## 8.1 Announcement

Votes are announced with:

* The question
* The proposal or change under vote
* The voting window
* The required threshold

## 8.2 Window

Default voting window:

```text
7 days
```

Emergency decisions MAY use a shorter window.

## 8.3 Recording

Votes and outcomes are recorded in public project records.

Recusals are recorded.

## 8.4 Absence

An absent member does not vote.

Absence does not block a decision when quorum exists.

---

# 9. Recusal and conflicts

A maintainer MUST recuse themselves from decisions involving:

* Their employer's commercial dispute
* Their own security report
* A personal financial conflict
* Enforcement involving themselves

## 9.1 Declaration

Conflicts are declared:

* Before the decision
* In writing
* Publicly where the decision is public

## 9.2 Effect

Recusal means:

* The member does not vote
* The member does not count toward quorum
* The member MAY participate in discussion when permitted

---

# 10. Release authority

## 10.1 Solo signing

For the current v0.1 repository, release manifests are signed by one
operator-controlled Ed25519 key (`1-of-1`). The key is kept offline and CI
only verifies the published public key. Multi-maintainer thresholds are future
governance, not a current release requirement.

## 10.2 Manifests

The release manifest contains:

```text
Version
Git commit
Source archive hashes
Binary hashes
Container hashes
SBOM hashes
Build metadata
Supported protocol versions
Storage schema version
```

## 10.3 Constraints

* CI MUST NOT possess the private signing key.
* The operator SHOULD use hardware-backed or encrypted offline storage.
* Revocation documents are prepared in advance.
* Emergency key rotation is recorded by the project owner.

## 10.4 Emergency release authority

In an emergency, the project owner MAY:

* Authorize a fast-track security release
* Perform an emergency key rotation
* Deputize a trusted release process

Emergency authority MUST preserve the one-signature policy and publish the
replacement public key before the next release.

---

# 11. Merge and specification authority

## 11.1 Merges

Merge authority:

* Module maintainers merge within their module
* Council members may veto a merge on governance or compatibility grounds
* Security-sensitive modules require security review before merge

## 11.2 Specifications

Specification changes follow the UMEP process.

The council:

* Confirms sponsors
* Approves acceptance
* Records registry allocations

---

# 12. Inactivity

## 12.1 Definition

A maintainer is inactive when, for a defined period (default 6 months):

* They do not participate in council decisions
* They do not review or merge in their modules
* They do not respond to direct contact

## 12.2 Process

Inactivity is handled by:

1. Private contact.
2. A notice period.
3. Council vote on removal or transition to emeritus status.

Emeritus status preserves recognition without voting authority.

---

# 13. Removal

## 13.1 Grounds

Removal grounds:

* Inactivity per the defined policy
* Repeated governance violations
* Abuse of authority
* Security compromise or harmful action
* Unresolved conflict of interest

## 13.2 Process

Removal requires:

1. A formal proposal.
2. Notice to the member.
3. A supermajority of non-conflicted council members.
4. A recorded vote.

Removal MUST NOT delete the member's historical contributions.

---

# 14. Succession

## 14.1 Appointment

Succession follows the appointment process.

## 14.2 Loss of maintainers

When the council falls below three members:

* Remaining members recruit replacements
* Existing module maintainers may be elevated
* The project may suspend stable releases until quorum returns

## 14.3 Loss of release keys

Loss of release keys triggers:

* Emergency key rotation
* A new threshold key set
* Re-issuance of verification material

## 14.4 Loss of all maintainers

If the council becomes empty, the project SHOULD:

* Allow fork continuity without permission
* Preserve protocol documentation and test vectors
* Leave the registries reproducible from repository history

---

# 15. Emergency authority

The security team and council MAY act on emergency timelines when:

* A critical vulnerability is exploited in the wild
* A release or key is compromised
* A protocol or profile must be disabled

Emergency actions MUST be:

* Recorded
* Reviewed by the council afterward
* Reversible where safe

---

# 16. Repository transfer

The repository MAY be transferred when:

* The council approves
* A successor organization exists
* The transfer preserves governance and history
* The protocol remains publicly specified

Transfers MUST NOT:

* Grant a single entity permanent control
* Remove public access to specifications
* Break fork continuity

---

# 17. Fork continuity

The project MUST remain forkable:

* Protocol specifications are public
* Test vectors are public
* Registries are in the repository
* No runtime dependency on project infrastructure
* No permission required to fork

A fork can continue the network without permission from the original maintainers.

---

# 18. Trademark ownership

The project name and protocol name require clearance before public launch.

Trademark and domain ownership:

* MAY be held by the project, a foundation, or an approved custodian
* MUST NOT create a blocker for protocol implementation
* MUST be transferable under governance

A branding conflict discovered before public release may change the human-facing name without changing protocol identifiers.

---

# 19. Foundation considerations

The project does not create a legal foundation during v0.1.

A foundation MAY become appropriate after:

* Multiple independent contributors
* Multiple implementations
* Meaningful funding
* Trademark or infrastructure ownership needs

Foundation creation requires a governance supermajority.

---

# 20. Amendments

This document is amended by:

1. A proposed change.
2. Public discussion.
3. A two-thirds majority of non-conflicted council members.
4. A recorded vote.

Amendment history is preserved.

---

# 21. Open questions

1. Default inactivity period.
2. Quorum exact definition.
3. Whether module maintainers are term-limited.
4. Emeritus status benefits.
5. Foundation selection criteria.
6. Repository transfer custodian rules.
7. Trademark custodian selection.
8. Voting platform and record format.

---

# 22. Core rule

For the current v0.1 repository, the project owner governs the codebase,
handles security reports, and signs releases with one operator-controlled
Ed25519 key (`1-of-1`). GitHub and CI provide review, history, and verification;
they never hold the private key. The council, quorum, succession, and
multi-maintainer procedures in this draft are future-governance notes and are
inactive until the project has additional maintainers.
