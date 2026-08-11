# Universal Mesh Core Compatibility Specification

**Status:** Draft
**Version:** 0.1
**Document:** Versioning and Compatibility Policy
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines compatibility and versioning policy for UMC and UMP.

It specifies:

* Compatibility model
* Versioning rules
* UMP protocol compatibility
* Control API compatibility
* Rust SDK compatibility
* Carrier plugin API compatibility
* Storage schema compatibility
* Release support windows
* Experimental feature behavior
* Feature negotiation and deferral
* Downgrade behavior
* Breaking-change policy
* Deprecation policy
* Security exceptions

Protocol compatibility and software compatibility are separate concerns. This document keeps them separate.

This document does not define:

* Protocol message encoding
* UMEP process
* Governance
* Security operations

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

---

# 3. Compatibility model

UMC maintains five explicit version axes:

```text
Protocol version
Core library version
Daemon API version
Storage schema version
Carrier plugin API version
```

Each version MUST be explicit.

A software release MUST document all supported versions:

```text
Supported protocol versions
Supported Control API versions
Supported SDK versions
Supported plugin API versions
Supported storage schema versions
```

Compatibility on one axis does not imply compatibility on another.

---

# 4. Versioning rules

## 4.1 Semantic versioning

Software releases use semantic versioning:

```text
major.minor.patch
```

## 4.2 Before 1.0

Before `1.0`:

* Breaking API changes are allowed
* Protocol changes must remain explicitly versioned
* Storage migrations must be tested
* Experimental features must be marked

## 4.3 After 1.0

After `1.0`:

* Stable APIs require deprecation periods
* Stable protocol versions require compatibility commitments
* Security-critical incompatibilities may override normal deprecation

---

# 5. UMP protocol compatibility

## 5.1 Protocol version

The protocol version controls network interoperability.

UMP v0.1 uses:

```text
Version = 0x00000001
```

## 5.2 Negotiation

Version negotiation:

* Is explicit in the long header
* Produces a version-negotiation packet for unsupported versions
* Authenticates the final negotiated version in the handshake transcript
* MUST NOT permit unauthenticated downgrade

A node MUST NOT attempt to interpret frames under an unknown version.

## 5.3 Extension rules

Extensions follow the wire-format extension rules:

* Unknown critical frames close the relevant protocol context
* Unknown optional length-delimited frames are skipped
* Unknown optional fixed-layout frames are rejected
* New optional extensions SHOULD use length-delimited frame types

## 5.4 Capability negotiation

A server MUST NOT select capabilities the client did not offer.

Security-sensitive capabilities MUST NOT be enabled unless explicitly negotiated.

Negotiated capabilities are bound into the handshake transcript.

## 5.5 Stable baseline

The stable baseline is defined by the minimal-compliance sections of:

```text
wire-format.md
handshake.md
session.md
routing.md
relay.md
```

An implementation MUST NOT advertise a deferred capability.

## 5.6 Registry allocations

Frame types, capabilities, cryptographic profiles, carrier identifiers, and error codes are allocated through the UMEP registries.

Registry assignment does not imply endorsement.

Private and experimental ranges exist without central approval.

---

# 6. Downgrade behavior

## 6.1 Authenticated downgrade

All negotiation is bound into the handshake transcript.

If a negotiation value is modified, Finished verification fails.

## 6.2 No silent fallback

A peer MUST NOT silently fall back after an authenticated negotiation failure.

Fallback requires a new handshake attempt under explicit local policy.

## 6.3 Weaker modes

A weaker carrier or handshake mode requires:

* A new policy-approved attempt
* Explicit operator or application consent

The node MUST NOT continue under a weaker mode without that consent.

## 6.4 Resource defaults

Local resource defaults do not affect UMP interoperability when a node:

* Advertises only limits it can honor
* Enforces protocol maxima
* Uses defined errors or backpressure
* Preserves state invariants
* Avoids insecure fallback

A compliant implementation MUST support peers that advertise smaller valid limits.

It MUST NOT assume local defaults represent remote capacity.

---

# 7. Control API compatibility

## 7.1 Versioning

The Control API uses:

```text
major.minor
```

UMP v0.1 Control API:

```text
major = 1
minor = 0
```

## 7.2 Rules

* Major changes may break wire or semantic compatibility
* Minor changes add backward-compatible fields, messages, methods, or enum values
* The client offers supported versions in preference order
* The server selects one exact version
* No common major version causes negotiation failure

## 7.3 Client and server duties

A client MUST:

* Tolerate unknown protobuf fields
* Reject unknown method names where safety requires it
* Reject unknown enum values where the operation cannot remain safe

A server MUST:

* Reject unknown methods
* Preserve existing field numbers and meanings
* Reserve removed field names and numbers
* Add fields with safe defaults
* Add enum values without changing prior values
* Keep service and method names stable within one major version

## 7.4 Evolution constraints

The schema MUST NOT:

* Change request idempotency semantics in one major version
* Widen authorization through absent fields
* Permit unknown fields to bypass method limits

## 7.5 Retirement

API version retirement uses `GoAway` where time permits.

Experimental methods use an `Experimental` namespace or explicit feature negotiation and receive no stable compatibility guarantee.

The Control API is local process interoperability. It does not affect peer interoperability.

---

# 8. Rust SDK compatibility

## 8.1 Stable surface

Stable v0.1 SDK surfaces:

```text
Rust umc-sdk
Python daemon client
```

## 8.2 Experimental surface

Experimental:

```text
C ABI
```

The C ABI is not covered by the v0.1 stability commitment.

## 8.3 Rules

SDK evolution MUST:

* Preserve existing public names and semantics within a major version
* Add features without breaking existing callers
* Mark breaking changes and require major version bumps
* Keep backend equivalence: embedded and daemon-backed semantics match
* Document observable backend differences

SDK methods MUST NOT:

* Change delivery or backpressure semantics between backends
* Expose private keys
* Grant cross-application access

---

# 9. Carrier plugin API compatibility

The v0.1 compatibility profile advertises no external Carrier Plugin API
version. Built-in carriers and trusted compiled-in plugin hooks are the only
supported carrier extension surface; the deferred external protocol is
specified in [`carrier-plugin-api.md`](carrier-plugin-api.md). A future release
may advertise a plugin API version only after private IPC, process lifecycle,
and sandbox controls are implemented behind the generation-scoped supervisor.

## 9.1 Versioning

The Carrier Plugin API uses:

```text
major.minor
```

## 9.2 Negotiation

* The plugin offers supported versions
* The daemon selects one exact version
* No common major version causes negotiation failure and process termination
* The daemon and plugin MUST NOT silently fall back to a weaker version

## 9.3 Evolution

Minor changes add backward-compatible fields, messages, methods, or enum values.

The daemon and plugin MUST tolerate unknown protobuf fields.

Unknown critical messages close the IPC.

---

# 10. Storage schema compatibility

## 10.1 Schema version

The database MUST store an explicit schema version.

The schema version:

* Controls persisted-state compatibility
* Appears in the release manifest
* Is validated at startup

## 10.2 Migrations

Migrations MUST:

* Be explicit, ordered, and idempotent
* Support upgrade and downgrade plans where applicable
* Validate the starting schema version
* Refuse to run against an unknown or newer version
* Preserve secret state independently of metadata migrations

## 10.3 Support

A release documents:

* The schema versions it can upgrade from
* The schema versions it writes
* The downgrade path, when one exists

An implementation MUST NOT silently read or write an unsupported schema version.

---

# 11. Release support windows

## 11.1 Channels

Release channels:

```text
Stable
Beta
Nightly
```

## 11.2 Rules

* Stable MUST exclude unreviewed experimental cryptography
* Nightly features MUST NOT silently connect to stable networks using incompatible semantics
* Experimental carriers MUST be explicitly marked
* Nightly and beta receive no security-support commitment

## 11.3 Support policy

Security fixes are supported for Tier-1 platforms:

```text
Linux x86_64
macOS arm64
Windows x86_64
```

Linux aarch64, macOS x86_64, Windows arm64, and FreeBSD x86_64 are Tier-2
platforms with best-effort fixes and optional release binaries.

The project MUST document:

* Which release lines receive security fixes
* The support window for each release
* The end-of-life process for old releases
* The supported version matrix per release

## 11.4 Release documentation

Each release MUST document:

```text
Supported protocol versions
Supported Control API versions
Supported SDK versions
Supported plugin API versions
Supported storage schema versions
Migration notes
Security notes
```

---

# 12. Experimental feature behavior

## 12.1 Marking

Experimental features MUST be:

* Explicitly marked in configuration and documentation
* Outside the stable compatibility commitment
* Separately negotiated where they affect protocol behavior
* Reported through feature negotiation or capability flags

## 12.2 Behavior

Experimental features MUST NOT:

* Silently alter stable interoperability
* Connect to stable networks with incompatible semantics
* Be advertised by nodes that do not enable them

## 12.3 Promotion

Promotion from experimental to stable requires:

* A UMEP where protocol-affecting
* Stability of behavior
* Compatibility analysis
* Test vectors
* Security review where applicable

## 12.4 Removal

Removal of an experimental feature:

* Is allowed without deprecation
* MUST be documented
* MUST NOT break stable features

---

# 13. Feature negotiation and deferral

## 13.1 Advertise only what you support

Every protocol, plugin, and SDK surface follows the rule:

```text
An implementation MUST NOT advertise a deferred capability.
```

## 13.2 Deferral

A feature may be deferred when:

* It is optional in the minimal baseline
* The node does not enable it
* Negotiation prevents misunderstanding

Deferred features receive no compatibility commitment until stabilized.

## 13.3 Peer limits

A compliant implementation MUST support peers that advertise smaller valid limits.

It MUST NOT assume its own defaults represent remote capacity.

---

# 14. Breaking-change policy

## 14.1 Protocol

A protocol-breaking change:

* Requires a UMEP
* MUST be explicitly versioned
* MUST define migration and downgrade behavior
* MUST NOT be introduced in a patch release

## 14.2 Control API

A Control API major change:

* Breaks old clients by design
* MUST be announced
* SHOULD provide a transition period through version negotiation

## 14.3 SDK

An SDK breaking change:

* Requires a major version bump
* MUST be announced
* SHOULD provide migration guidance

## 14.4 Storage

A storage-breaking change:

* Requires a schema migration
* MUST be tested
* MUST preserve a safe upgrade path

---

# 15. Deprecation policy

After `1.0`:

* Stable APIs require deprecation periods before removal
* Stable protocol versions require compatibility commitments
* Deprecated features remain functional during the period
* Deprecation is announced through release notes and advisories

Before `1.0`:

* Breaking changes are allowed
* They MUST be marked and documented
* They SHOULD be announced in advance

---

# 16. Security exceptions

Security-critical incompatibilities may override normal deprecation.

A security exception MUST:

* Follow `security-operations.md`
* Be announced as a security event
* Provide migration guidance
* Be reversible where safe

Emergency protocol disablement MUST NOT create an insecure fallback.

---

# 17. Compatibility testing

The project MUST test compatibility on:

1. Interoperability tests between independent implementations.
2. Differential tests between protocol versions.
3. Negative tests for downgrade attempts.
4. Test vectors for stable encodings.
5. Control API version-negotiation tests.
6. Plugin API version-negotiation tests.
7. Storage migration upgrade and downgrade tests.
8. SDK backend-equivalence tests.
9. CI matrix across Tier-1 platforms.

Test vectors MUST be public and versioned.

---

# 18. Required tests

A compliant implementation MUST test:

1. Unknown-critical-frame handling.
2. Unknown optional frame skipping.
3. Version-negotiation behavior.
4. Authenticated downgrade rejection.
5. Capability-offer restriction.
6. Control API major-version negotiation failure.
7. Control API unknown-field tolerance.
8. Plugin API version negotiation.
9. Storage schema version refusal.
10. Storage upgrade migration.
11. Storage downgrade behavior where supported.
12. Experimental feature isolation.
13. Deferred-capability non-advertisement.
14. Smaller-peer-limit support.
15. Release matrix documentation accuracy.

Property tests SHOULD verify:

```text
No unadvertised capability is used on the wire.
No silent fallback follows negotiation failure.
Stable encodings never change without version change.
Experimental features never alter stable semantics.
Schema versions never read or write unsupported state.
```

---

# 19. Minimal v0.1 compliance

A compliant v0.1 implementation MUST support:

* Explicit protocol versioning
* Authenticated negotiation
* Unknown-critical rejection
* Optional-extension skipping
* Capability offer/select rules
* Control API version negotiation
* Storage schema versioning
* Experimental feature marking
* Deferred-capability discipline
* Release version-matrix documentation

---

# 20. Open design decisions

The project must resolve:

1. Exact extension-registry file format.
2. Deprecation-period lengths after 1.0.
3. Whether protocol minor versions exist within UMP/1.
4. Support-window length for release lines.
5. Whether storage downgrade is ever supported.
6. Control API experimental namespace shape.
7. SDK stability guarantee details.
8. When plugin API freezes.
9. Whether beta releases may use experimental crypto.
10. Compatibility test matrix scope.

---

# 21. Recommended implementation order

Implement compatibility policy in this order:

1. Version types and negotiation.
2. Unknown-frame handling.
3. Capability negotiation.
4. Control API version negotiation.
5. Plugin API version negotiation.
6. Storage schema versioning.
7. Experimental feature gating.
8. Release version-matrix documentation.
9. Compatibility test suite.
10. Deprecation tooling.

---

# 22. Core rule

UMC keeps five explicit version axes and never blends them: protocol, core library, daemon API, storage schema, and plugin API each evolve under their own rules.

Negotiation is authenticated and silent fallback is forbidden. Implementations advertise only what they support and accept smaller peer limits without assuming their defaults are universal. Experimental features stay marked and isolated until a UMEP stabilizes them, and every release documents exactly which versions it supports.
