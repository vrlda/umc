# Universal Mesh Core Identity and Trust Specification

**Status:** Draft
**Version:** 0.1
**Document:** Identity Lifecycle and Trust State
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines the operational identity system for UMC endpoints and the local trust state that governs interaction between them.

The handshake specification defines cryptographic keys, identity bindings, and authentication. This document defines what happens around the handshake:

* Identity creation and storage
* Static-key rotation
* Signing-key rotation
* Delegation
* Revocation
* Trust states and transitions
* Trust-on-first-use
* Introductions
* Block lists
* Recovery
* Export and import
* Multiple devices
* Endpoint versus node identity
* Trust as a policy input

This document does not define:

* Handshake message flow
* Session encryption
* Routing algorithms
* Relay circuit construction
* Application authorization
* Global reputation systems

Those are defined in their respective specifications.

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

Trust decisions are local. This document defines the state model and transitions that local policy uses. It does not define a global reputation authority.

---

# 3. Identity model overview

UMP endpoints have a two-key identity model defined by `handshake.md`:

```text
Identity signing key:  Ed25519
Static handshake key:  X25519
```

The endpoint identifier is:

```text
EndpointID = BLAKE2s-256(
    "UMP-ENDPOINT-ID-v1" ||
    IdentityPublicKey
)
```

The static handshake key is bound to the identity key through a signed identity binding.

Identity proves key possession. It does not prove human identity, device integrity, honest behavior, or authorization for any application action.

---

# 4. Terminology

## 4.1 Identity

The long-term cryptographic identity of an endpoint, anchored by the Ed25519 identity signing key.

## 4.2 Identity binding

A signed record binding an endpoint identity to a static handshake key with validity and sequence information.

## 4.3 Endpoint

A cryptographic identity capable of sending or receiving UMP traffic.

## 4.4 Node

A running UMP implementation that hosts one or more endpoints.

## 4.5 Delegation certificate

A signed record authorizing an additional key to act for an identity within defined limits.

## 4.6 Revocation

A signed statement invalidating an identity, binding, delegation, or introduction.

## 4.7 Trust state

The local classification of an authenticated endpoint identity.

## 4.8 Introduction

A signed, scoped, expiring statement from an introducer about an endpoint.

## 4.9 Block list

A local list of endpoint identities the node refuses to interact with.

---

# 5. Endpoint versus node identity

## 5.1 Endpoint identity

An endpoint identity is the cryptographic identity used in UMP sessions.

A node MAY host multiple endpoints:

```text
Node
├── Node management identity
├── User endpoint
├── Service endpoint
├── Gateway endpoint
└── Temporary endpoint
```

Each endpoint has independent keys, bindings, and trust relationships.

## 5.2 Node management identity

A node SHOULD maintain a node management identity separate from user endpoints.

The node management identity:

* Identifies the daemon for administrative and diagnostic operations
* Is generated during node initialization
* MUST NOT be used for ordinary application sessions
* MUST NOT be treated as more trustworthy than any other endpoint identity

## 5.3 Identity handles

A local identity handle references one stored endpoint identity.

Identity handles and Endpoint IDs remain distinct. Handles are local, opaque, and MUST NOT appear on the network.

---

# 6. Identity creation

## 6.1 Requirements

Identity creation MUST:

* Generate a fresh Ed25519 identity key pair from a secure random source
* Generate a fresh X25519 static handshake key pair
* Compute the EndpointID from the identity public key
* Create an initial identity binding
* Store secret material in the protected keystore
* Return only public metadata to the caller

The SDK and Control API expose:

```text
IdentityService.CreateIdentity
```

## 6.2 Key separation

The identity signing key MUST NOT be used for:

* Diffie-Hellman
* Payload encryption
* Packet encryption
* Header protection
* Session-ticket encryption

The static handshake key MUST NOT be used for:

* Application signatures
* Persistent content signatures
* Human-readable identity claims

## 6.3 Local-only creation

Identity creation MUST NOT require:

* A central registry
* A network service
* A project-operated server
* Any other node's approval

---

# 7. Identity storage

## 7.1 Secret state

Secret identity material includes:

```text
Identity signing private keys
Static handshake private keys
Recovery keys
Pre-issued recovery statements
```

Secret state MUST be:

* Stored in operating-system key storage where available
* Otherwise stored in an encrypted keystore protected by a user-provided secret or local machine credential
* Kept in a separate format from ordinary metadata
* Protected by a memory-hard KDF when password-derived secrets protect it

## 7.2 Trusted state

Trusted identity state includes:

```text
Known endpoint bindings
Delegation certificates
Revocations
Trust-on-first-use records
Peer introductions
Trust state records
Block list entries
```

Trusted state SHOULD be stored in the SQLite metadata database with integrity validation.

## 7.3 Corruption handling

Storage corruption MUST NOT result in unsafe key reuse.

A node MUST fail closed when:

* Secret material cannot be validated
* Binding or revocation records conflict
* Required trust records are missing after restart

---

# 8. Identity binding lifecycle

## 8.1 Binding record

An identity binding contains:

```text
BindingVersion
EndpointID
IdentityPublicKey
HandshakeStaticPublicKey
NotBefore
NotAfter
Sequence
CapabilitiesHash
Signature
```

The binding signature is defined in `handshake.md`.

## 8.2 Binding validation

A node MUST verify before accepting a binding:

* `EndpointID` matches `IdentityPublicKey`
* The signature is valid
* The binding is within its validity window, subject to clock-skew policy
* The sequence is not older than a previously accepted binding
* The static handshake key matches the key used in the handshake
* The binding is permitted by local trust policy

## 8.3 Binding storage

A node MAY store bindings for authenticated endpoints.

Stored bindings MUST be attributed to:

```text
EndpointID
Source of the binding
Time first observed
Time last confirmed
Sequence
Trust state
```

---

# 9. Static handshake-key rotation

An endpoint rotates its static handshake key by issuing a new identity binding with a higher sequence number.

The identity signing key signs the new binding.

A peer that has stored an older binding MUST verify:

* Same identity signing key
* Higher sequence number
* Valid time range
* Valid signature

Static-key rotation:

* Does not change the EndpointID
* Does not require a new trust decision
* Does not reset session trust state
* SHOULD be supported through `IdentityService.RotateHandshakeKey`

A node MUST reject a binding with a sequence at or below a previously accepted binding from the same identity.

---

# 10. Identity signing-key rotation

Rotation of the identity signing key changes the EndpointID.

A rotation proof MUST be signed by both:

```text
The old identity key
The new identity key
```

The rotation proof MUST bind:

```text
Old identity public key
New identity public key
Old EndpointID
New EndpointID
Old static handshake key or its binding sequence
New binding sequence
Creation time
Expiration
```

A peer that accepts the rotation proof:

* Replaces its stored binding for the identity
* Preserves the trust state and relationship metadata
* MUST NOT treat the new EndpointID as a new untrusted identity

Identity signing-key rotation is an administrative operation requiring `IDENTITY_ROTATE` and an audit event.

---

# 11. Key compromise and recovery

## 11.1 Detected compromise

When an identity key is compromised:

* The operator MUST revoke the affected identity or binding
* The node MUST stop accepting sessions for revoked material
* Peers MUST invalidate cached evidence for revoked identities

## 11.2 Revocation after compromise

A revocation MUST be signed by:

* The identity key itself, when it remains available, or
* A designated recovery key with a pre-issued authority, or
* A higher-level trust-policy decision defined by local policy

An operator MUST NOT be able to revoke with a lost key unless recovery material was provisioned in advance.

## 11.3 Recovery keys

A node SHOULD support provisioning recovery keys at identity creation.

A recovery key:

* Is a separate Ed25519 key generated at creation
* Is stored in protected storage or with a recovery service
* MAY be authorized by a pre-issued recovery statement signed by the identity key
* CANNOT authenticate as the identity for sessions
* MAY issue revocations and recovery statements under the identity

## 11.4 Lost keys

When the identity signing key is lost and no recovery material exists:

* The identity cannot be revoked by its owner
* Peers with TOFU records detect the loss when a new identity appears
* Recovery becomes a higher-level trust-policy issue, defined locally

The node MUST document this limitation to the operator.

---

# 12. Delegation

## 12.1 Delegation certificates

An identity MAY authorize additional keys through signed delegation certificates.

A delegation certificate SHOULD include:

```text
Issuer EndpointID
Delegated public key
Allowed capabilities
Creation time
Expiration time
Certificate sequence
Signature
```

## 12.2 Chain rules

A delegation chain MUST be:

* Canonically encoded
* Signed at every link
* Bounded in length
* Bounded in total size
* Capability-restricted
* Time-limited

Recommended maximums:

```text
Chain length: 4 certificates
Encoded chain size: 8 KiB
```

A receiver MUST reject:

* Cycles
* Repeated keys in one chain
* A chain that grants capabilities beyond the issuer's own authority
* An expired link
* An invalid signature at any link

## 12.3 Delegated use

A delegated key:

* MAY authenticate a device or service endpoint
* MUST NOT rotate the identity signing key
* MUST NOT delegate beyond its granted capabilities
* MUST NOT revoke the root identity

Delegation is used for multiple-device operation.

---

# 13. Revocation

## 13.1 Revocation statements

A revocation is a signed statement that invalidates:

* A complete endpoint identity
* One identity binding
* One delegation certificate
* One introduction
* One recovery key

A revocation record MUST contain:

```text
RevocationVersion
Issuer EndpointID
Subject (identity, binding sequence, delegation, or introduction ID)
Revocation class
Sequence
IssuedAt
ExpiresAt or no expiry
Signature
```

## 13.2 Revocation validation

A node MUST verify:

* The signature is valid
* The issuer has authority over the subject
* The sequence is monotonic for the issuer and subject class
* The revocation is within its validity window, subject to clock-skew policy

A node MUST reject:

* Forged signatures
* Stale revocations with lower sequence than accepted state
* Revocations from unauthorized issuers
* Conflicting revocations with the same sequence

## 13.3 Distribution

Revocation delivery is best-effort.

A node MUST NOT assume revocation state is current:

* In disconnected networks
* Against new identities created after the last contact
* When the peer store was restored from an old backup

UMP/1 does not define a dedicated revocation frame. Revocation records are distributed through:

* Authenticated peer exchanges
* Introductions and peer hints
* Bootstrap bundles
* Out-of-band or application channels
* A future optional extension

## 13.4 Effect

A revoked identity MUST be treated as:

* `Blocked` for new interaction
* Invalid for route, relay, and bundle evidence
* Unable to establish new authenticated sessions

An endpoint that completes a handshake with an identity it has revoked MUST close the session with `IDENTITY_REVOKED`.

Revocation does not destroy records needed to detect replay of old state.

---

# 14. Trust model

## 14.1 Default policy

The default trust policy is:

```text
Authenticated but untrusted by default
```

A cryptographically valid endpoint begins in the state:

```text
Observed
```

Cryptographic authentication alone moves no peer above `Observed`.

## 14.2 Trust states

UMP/1 defines:

```text
Unknown
Observed
Introduced
Trusted
Restricted
Blocked
Revoked
```

| State | Meaning |
| --- | --- |
| `Unknown` | No authenticated observation |
| `Observed` | Valid authenticated identity; no trust granted |
| `Introduced` | Scoped context from a signed introduction |
| `Trusted` | Explicit local trust decision |
| `Restricted` | Explicit reduced scopes and rates |
| `Blocked` | Refuse interaction |
| `Revoked` | Identity revoked; invalidate affected evidence |

## 14.3 Trust is local

Trust decisions are local.

There is no global reputation authority.

A node MUST NOT treat:

* Peer-table position as trust
* Route success as trust
* Local presence as trust
* Identity count as trust
* Another node's trust state as its own

---

# 15. Trust state transitions

## 15.1 Transition matrix

| From | To | Trigger |
| --- | --- | --- |
| `Unknown` | `Observed` | Valid authenticated handshake |
| `Unknown`/`Observed` | `Introduced` | Valid signed introduction within scope and expiry |
| `Observed`/`Introduced` | `Trusted` | Explicit local user decision |
| Any | `Restricted` | Local policy decision |
| Any | `Blocked` | Explicit block or abuse policy |
| `Blocked`/`Restricted` | `Observed` | Explicit unblock or restriction expiry |
| Any | `Revoked` | Valid revocation record for the identity |

## 15.2 Promotion rules

Promotion to `Trusted` MUST:

* Be an explicit local action
* Be attributable to a principal with `TRUST_ADMIN`
* Produce an audit event
* Be reversible

Promotion MUST NOT occur:

* Automatically from successful sessions
* Automatically from route success
* From an unverified peer advertisement
* From a mere introduction

## 15.3 Demotion rules

Demotion to `Restricted` or `Blocked` MAY be:

* Explicit operator action
* Automatic abuse-policy response
* Time-limited or indefinite

A node MUST be able to block an endpoint without deleting:

* Its stored binding
* Its audit history
* Its relationship metadata

---

# 16. Trust as a policy input

Trust state affects, through local policy:

* Session acceptance
* Peer-hint exchange
* Relay access
* Bundle storage
* Route preference
* Service advertisement acceptance
* Resource quotas

## 16.1 Default trust behavior

`Unknown` and `Observed` endpoints MAY:

* Complete a cryptographic handshake
* Request supported public application protocols
* Exchange tightly rate-limited discovery information

They MAY NOT by default:

* Use the node as a relay
* Store bundles
* Receive private peer hints
* Access administrative services
* Cause trust promotion
* Trigger unlimited route queries

## 16.2 Routing defaults

| Trust state | Default routing behavior |
| --- | --- |
| `Unknown` | Reject or admit under strict public-query limits |
| `Observed` | Permit bounded public requests; no private hints |
| `Introduced` | Permit granted scopes until introduction expiry |
| `Trusted` | Permit configured scopes and higher quotas |
| `Restricted` | Apply explicit reduced scopes and rates |
| `Blocked` | Reject routing traffic |
| `Revoked` | Reject and invalidate affected cached evidence |

## 16.3 Resource multipliers

Default quota multipliers:

| Trust state | Rate multiplier | State multiplier |
| --- | ---: | ---: |
| `Unknown` | 0.25 | 0.25 |
| `Observed` | 1 | 1 |
| `Introduced` | 4 | 2 |
| `Trusted` | 10 | 4 |
| `Restricted` | explicit | explicit |
| `Blocked` | 0 | 0 |
| `Revoked` | 0 | 0 |

Multipliers MUST NOT exceed global or subsystem hard limits.

---

# 17. Trust-on-first-use

## 17.1 Definition

TOFU is a local policy option.

TOFU means:

> Remember the first authenticated binding and detect changes.

It does NOT mean:

> Grant the endpoint relay, storage, or private-discovery privileges.

## 17.2 Behavior

When TOFU is enabled for an endpoint:

1. The first valid identity binding is stored.
2. Future changes require:

   * A valid signed rotation proof, or
   * Explicit user approval, or
   * A configured expiry policy

3. Unexpected key changes produce a security warning or rejection.

## 17.3 TOFU records

A TOFU record MUST contain:

```text
EndpointID
Stored binding sequence and key material
First observed time
Last confirmed time
Policy
```

A node MUST preserve TOFU records across restart.

A TOFU record is trusted state. It MUST NOT be treated as a trust promotion.

---

# 18. Introductions

## 18.1 Introduction records

An introduction is a signed, scoped, expiring statement.

An introduction records:

```text
Introducer EndpointID
Subject EndpointID
Subject binding or static handshake key
Allowed use
Expiration
Delegated confidence
Sharing restrictions
Sequence
Signature
```

## 18.2 Semantics

```text
Introduced ≠ Trusted
```

An introduction:

* Increases context for an endpoint
* MAY grant scoped routing and relay privileges
* DOES NOT automatically produce full trust
* DOES NOT prove route quality or endpoint behavior

## 18.3 Expiry and revocation

An introduction:

* MUST expire
* MAY be revoked by its introducer
* MUST NOT outlive the introducer's own authority
* Loses effect when the subject identity is revoked

The node MUST record the introducer and remaining validity of every accepted introduction.

## 18.4 Use limits

Introductions MUST be bounded:

```text
Introduction records per peer: 8–32 by profile
Delegated confidence: scoped
Sharing restrictions: enforced
```

Ten identities introduced by one untrusted source MUST NOT count as ten independent trust domains.

---

# 19. Block lists

## 19.1 Entries

A block list entry contains:

```text
EndpointID or binding hash
Reason class
Added by
Added at
Expiry or indefinite
```

## 19.2 Behavior

A blocked endpoint:

* Cannot originate or forward routing messages except a minimal error required to end existing state
* Receives zero resource multipliers
* Cannot establish new sessions
* MAY receive an explicit close for existing sessions

## 19.3 Block-list properties

A block list:

* Is local state
* MUST NOT be presented as global reputation
* MUST survive restart
* MAY be shared only through explicit authenticated policy
* SHOULD support time-limited entries

---

# 20. Multiple devices

## 20.1 Model

One identity MAY operate on multiple devices through delegation.

The primary device:

* Holds the identity signing key
* Issues delegation certificates for additional devices
* Issues revocations for compromised devices

Each additional device:

* Has its own static handshake key
* Authenticates through a delegation certificate
* MUST NOT hold the identity signing key

## 20.2 Device lifecycle

Adding a device:

* The primary device creates a delegation certificate
* The new device imports identity public material and its delegation
* The device establishes sessions as the delegated identity

Removing a device:

* The primary device revokes the delegation
* Peers that received the revocation refuse the device
* Peers without the revocation may continue accepting until the revocation arrives

## 20.3 Device compromise

A compromised device:

* Can act as the delegated identity until its delegation is revoked
* Cannot rotate the identity signing key
* Cannot issue delegations beyond its grant
* CANNOT revoke the root identity

A node SHOULD expose per-delegation diagnostics so operators can identify which device acted.

---

# 21. Trust persistence

## 21.1 Persisted state

The node MUST persist:

```text
Trust state records
Stored bindings
TOFU records
Introductions
Revocations
Block list entries
Delegation certificates
```

## 21.2 Restart behavior

After restart, the node MUST restore trust state from validated storage.

The node MUST NOT:

* Reset `Blocked` or `Revoked` state on restart
* Forget introductions without expiry
* Forget stored bindings
* Restore live sessions from trust state

## 21.3 Rollback protection

The node SHOULD detect restoration of stale trust state through:

* Monotonic platform counters where available
* Explicit restore workflow
* Sequence regression checks against OS key-store metadata or trusted peers
* Rotation of ticket and Retry keys after restore

The node MUST warn when trust or revocation state may be stale.

---

# 22. Clock and validity handling

## 22.1 Skew tolerance

The default allowed clock skew is:

```text
5 minutes
```

## 22.2 Clock failures

A clock anomaly MUST NOT cause acceptance of an invalid signature.

A node with an unreliable clock MAY use:

* Previously authenticated peer time
* Relative validity windows
* Monotonic time after receipt
* Explicit local trust overrides

A node SHOULD detect large clock jumps and revalidate sensitive trust state after anomalies.

---

# 23. Export and import

## 23.1 Public export

The node provides:

```text
IdentityService.ExportPublicIdentity
```

Public export contains:

```text
Identity public key
Static handshake public key
Current binding
Validity
```

Public export requires `IDENTITY_EXPORT_PUBLIC`.

## 23.2 Secret export

The node provides:

```text
IdentityService.ExportSecretIdentity
```

Secret export:

* Requires `IDENTITY_EXPORT_SECRET`
* Requires explicit export protection
* Requires an audit event
* SHOULD require an operator confirmation mechanism
* MUST be a one-time operation returning protected material

The exported secret MUST be encrypted under a strong user-provided secret using a memory-hard KDF.

## 23.3 Import

The node provides:

```text
IdentityService.ImportIdentity
```

Import MUST treat the input as hostile:

* Enforce total and field-specific size limits
* Reject path traversal and unsafe file types
* Verify signatures, hashes, versions, and ownership
* Stage the import into an isolated location
* Validate before replacing active state
* Require explicit authorization for identity and trust changes

## 23.4 Backup

Backups:

* MUST protect secret material with the keystore encryption
* MUST include trust state for continuity
* MUST document restore behavior
* MUST NOT be loadable without explicit restore authorization

---

# 24. Control API and CLI surface

## 24.1 IdentityService

```text
ListIdentities
GetIdentity
CreateIdentity
RotateHandshakeKey
RotateIdentityKey
ExportPublicIdentity
ExportSecretIdentity
ImportIdentity
DeleteIdentity
```

Deletion MUST report dependent listeners, sessions, trust records, and bundles before commit.

## 24.2 PeerService

```text
ListPeers
GetPeer
AddPeerHint
RemovePeer
SetTrustState
BlockPeer
UnblockPeer
CreateInvitation
ImportInvitation
RevokeInvitation
```

Trust mutation requires `TRUST_ADMIN` and revision matching.

## 24.3 Capabilities

Identity and trust capabilities:

```text
IDENTITY_READ
IDENTITY_CREATE
IDENTITY_ROTATE
IDENTITY_EXPORT_PUBLIC
IDENTITY_EXPORT_SECRET
IDENTITY_DELETE
TRUST_ADMIN
```

`IDENTITY_EXPORT_SECRET` and `IDENTITY_DELETE` require explicit administrative grants and audit events.

## 24.4 CLI

The CLI exposes:

```text
umc identity create
umc identity list
umc identity inspect
umc identity rotate
umc identity export-public
umc peer add
umc peer remove
umc peer list
umc peer inspect
umc peer block
umc invite create
umc invite import
umc invite revoke
```

## 24.5 Audit events

The daemon MUST emit audit events for:

```text
Identity creation
Identity rotation
Identity import
Identity export
Identity deletion
Trust mutation
Block and unblock
Invitation creation and revocation
```

---

# 25. Resource limits

Identity and trust state MUST remain bounded.

Default limits:

| Resource | Default |
| --- | ---: |
| Stored bindings | bounded by peer-store profile |
| Introduction records per peer | 8–32 by profile |
| Delegation chain length | 4 certificates |
| Delegation chain size | 8 KiB |
| Pending recovery statements | explicit policy |
| Block list entries | configured hard limit |
| Revocation records | configured hard limit |

The node MUST reserve storage capacity for trust and revocation records.

Bundle or diagnostic growth MUST NOT prevent a critical trust transaction.

---

# 26. Security considerations

## 26.1 Forged bindings

Attackers may forge bindings, rotations, or revocations.

Nodes verify signatures, sequence monotonicity, issuer authority, and validity windows before accepting any identity statement.

## 26.2 Stale revocation state

Disconnected nodes may receive valid revocations late.

The node MUST account for potentially stale revocation state in its claims.

## 26.3 Stolen keys

A stolen identity key lets the attacker authenticate as the identity until revocation is distributed.

Recovery keys and pre-issued statements reduce recovery time but do not prevent it.

## 26.4 Rollback

A rollback attacker may restore old trust state.

Sequence checks, explicit restore workflows, and key rotation after restore limit the damage.

## 26.5 Sybil identities

Identity creation is cheap.

Trust state must separate identity count from trust. Introductions group identities by introducer.

## 26.6 Logging

Default logs MUST NOT contain:

* Identity private keys
* Static handshake private keys
* Recovery keys
* Full resumption tickets
* Invitation secrets

Default logs SHOULD avoid permanent endpoint identifiers.

---

# 27. Required tests

A compliant implementation MUST test:

1. Identity creation with fresh keys.
2. EndpointID derivation vectors.
3. Binding signing and validation.
4. Static handshake-key rotation with increasing sequence.
5. Rejection of stale or conflicting bindings.
6. Identity signing-key rotation proof with old and new signatures.
7. Delegation chain validation.
8. Rejection of cycles, repeated keys, and oversized chains.
9. Revocation validation, sequence monotonicity, and authority checks.
10. Revocation effect on sessions, routes, and relay evidence.
11. TOFU first-contact storage and key-change detection.
12. Introduction acceptance, scope enforcement, and expiry.
13. Block-list enforcement and restart persistence.
14. Trust-state transitions and audit events.
15. Resource multipliers by trust state.
16. Secret export protection and one-time semantics.
17. Hostile import rejection.
18. Recovery-key provisioning and use.
19. Lost-key recovery behavior.
20. Multi-device delegation lifecycle.
21. Rollback detection and stale-state warning.
22. Restart restoring trust state.
23. Clock skew and clock-jump handling.
24. Log and error redaction.

Property tests SHOULD verify:

```text
Accepted binding sequences never decrease for one identity.
Trust promotion never happens without an explicit local action.
Revocation invalidates all cached evidence for the subject.
Introduced never equals Trusted.
Blocked and Revoked receive zero quota multipliers.
Delegation chains never exceed authorized capabilities.
A delegated key cannot revoke or rotate the root identity.
```

---

# 28. Minimal v0.1 compliance

A compliant implementation MUST support:

* Ed25519 identity creation
* X25519 static handshake keys
* Identity binding creation and validation
* Static handshake-key rotation
* Trust states with local transitions
* Authenticated-but-untrusted default
* Trust-on-first-use as a policy option
* Signed introductions with scope and expiry
* Block lists
* Revocation records with validation
* Public identity export
* Protected secret export
* Hostile-safe identity import
* Trust-state persistence across restart
* Identity and trust audit events

An implementation MAY defer:

* Identity signing-key rotation
* Delegation chains
* Recovery keys
* Multi-device delegation workflows
* Automated rollback detection

An implementation MUST NOT claim delegation or recovery support it does not provide.

---

# 29. Open design decisions

The project must resolve these items before freezing UMP/1:

1. Revocation record canonical encoding.
2. Revocation distribution mechanism and whether a dedicated frame enters UMP/1.
3. Recovery-statement format and authority model.
4. Whether recovery keys are mandatory or optional at creation.
5. Introduction record canonical encoding.
6. Whether introductions are exchanged as PEER_HINT authenticators or a new extension.
7. Exact trust-state persistence schema.
8. Rollback detection anchor per platform.
9. Whether trust state is exported in backups by default.
10. Multi-device sync mechanism.
11. Identity binding validity defaults.
12. Whether bindings expire.
13. Block-list entry classes and default retention.
14. Audit event schema for trust mutations.
15. Whether `Restricted` supports time limits.
16. Invitation-to-identity binding rules.
17. Whether TOFU records are per-identity or per-binding.
18. Delegation capability registry.
19. Whether node management identity has special protocol treatment.
20. Trust-state migration across storage schema versions.

---

# 30. Recommended implementation order

Implement identity and trust in this order:

1. EndpointID derivation.
2. Identity key generation and keystore storage.
3. Identity binding creation and validation.
4. Binding storage and lookup.
5. Static handshake-key rotation.
6. Trust-state types and transitions.
7. Trust persistence.
8. Block lists.
9. TOFU records.
10. Introductions with scope and expiry.
11. Revocation records and validation.
12. Revocation effect on routing and relay evidence.
13. Public and secret export.
14. Hostile-safe import.
15. Delegation chains.
16. Identity signing-key rotation.
17. Recovery keys.
18. Multi-device workflows.
19. Rollback detection.
20. Audit events and tests.

---

# 31. Core rule

UMP identity is cryptographic key possession; UMC trust is a local, explicit, bounded classification of that identity.

Authentication never grants trust automatically. Introductions add scoped context, not trust. Revocation is best-effort and stale-state aware. Every identity statement is validated for signature, authority, sequence, and validity before it changes local state, and every trust change is attributable, reversible, and auditable.
