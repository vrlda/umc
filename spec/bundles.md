# Universal Mesh Core Bundle and Disruption-Tolerant Delivery Specification

**Status:** Draft
**Version:** 0.1
**Document:** Store-and-Forward Bundles
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines UMC's disruption-tolerant delivery subsystem: encrypted objects that may be stored and forwarded when no continuous route is available.

It specifies:

* Bundle model
* Bundle identifiers
* Bundle encryption
* Bundle frame encoding
* Bundle storage
* Quotas
* Expiration
* Duplicate handling
* Delivery and acknowledgements
* Custody
* Replication
* Forwarding
* Intermittent-route selection
* Offline clocks
* Eviction
* Abuse prevention
* Interaction with sessions, routing, and relaying

This document does not define:

* Live session semantics
* Route discovery
* Application payload formats
* Epidemic replication algorithms
* Payment or incentive systems

Those are defined in their respective specifications.

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

All quantities use binary byte units.

---

# 3. Status in v0.1

Bundle support is **experimental in v0.1** and a **mandatory candidate for v0.2**.

v0.1 supports:

> Live direct and relayed communication, with an experimental delayed-delivery subsystem.

v0.2 targets:

> Stable disruption-tolerant bundle interoperability.

## 3.1 v0.1 requirements

The v0.1 architecture MUST include:

* Bundle identifiers
* Bundle storage abstraction
* Bundle quotas
* Expiration model
* Experimental frame encoding
* Feature negotiation
* Basic one-hop delayed delivery tests

## 3.2 Not required for stable v0.1

* Epidemic replication
* Custody transfer
* Multi-carrier physical movement routing
* Sophisticated delivery prediction
* Global bundle routing
* Strong delivery receipts

A node that does not enable bundles MUST NOT advertise a bundle-storage grant.

---

# 4. Terminology

## 4.1 Bundle

An encrypted object that may be stored and forwarded when no continuous route is available.

## 4.2 Bundle ID

A value identifying one bundle for duplicate detection and reference.

## 4.3 Sender

The endpoint that created the bundle.

## 4.4 Destination

The endpoint for which the bundle is encrypted.

## 4.5 Storage node

A node that retains a bundle copy.

## 4.6 Custody

A commitment by a storage node to retain a bundle until delivery or expiry.

## 4.7 Replication

Copying a bundle to additional storage nodes.

## 4.8 Contact

An opportunity to forward a bundle through a newly available path.

---

# 5. Bundle model

A bundle contains:

```text
Bundle ID
Encrypted destination information
Creation time
Expiration time
Priority
Maximum replication count
Payload
Authentication data
```

A bundle is carried in the `BUNDLE` frame defined by `wire-format.md`.

A bundle:

* Is opaque to every node except its destination endpoint
* Is stored and forwarded without plaintext access
* Expires
* Is subject to storage policy at every hop

---

# 6. Bundle identifiers

## 6.1 Purpose

Bundle IDs enable:

* Duplicate detection
* Storage deduplication
* Acknowledgement correlation

Bundle IDs MUST allow duplicate detection without exposing application contents.

## 6.2 Derivation

The provisional construction is:

```text
BundleID = BLAKE2s-256(
    "UMP-BUNDLE-ID-v1" ||
    encrypted_payload_hash ||
    destination_hint_hash
)
```

The Bundle ID:

* MUST NOT contain plaintext payload
* MUST NOT contain plaintext destination identity
* MUST NOT be derivable from application data alone
* MAY be the same for identical payloads sent to the same destination

The final derivation is an open design decision.

## 6.3 Bounds

```text
Bundle ID Length <= 64 bytes
```

---

# 7. Bundle encryption

## 7.1 Requirement

Application payloads MUST be encrypted for the final destination before relay storage.

Storage nodes MUST NOT require plaintext access.

## 7.2 Envelope

The provisional bundle envelope:

```text
SenderEphemeralPublicKey (X25519)
EncryptedPayload (ChaCha20-Poly1305)
BundleAuth (signature or MAC)
```

The payload encryption key is derived from a Diffie-Hellman between a fresh sender ephemeral key and the destination's static handshake key, using domain-separated labels from the UMP-CRYPTO-1 profile.

The final envelope construction is an open design decision and MUST receive independent cryptographic review before v0.2.

## 7.3 Properties

Bundle encryption MUST provide:

* Confidentiality against storage nodes and relays
* Integrity for the stored payload
* Authenticated association with the sender
* Replay-resistant deduplication

Bundle encryption MUST NOT reuse session keys or session packet numbers.

---

# 8. Bundle frame

The `BUNDLE` frame contains:

```text
Bundle ID
Flags
Priority
Creation Time
Expiration Time
Replication Limit
Destination Hint
Encrypted Bundle Payload
Bundle Auth
```

Flags:

```text
CUSTODY_REQUESTED
DELIVERY_ACK_REQUESTED
DO_NOT_REPLICATE
LOCAL_SCOPE_ONLY
HIGH_SENSITIVITY
```

Limits:

```text
Bundle ID Length <= 64 bytes
Destination Hint Length <= 512 bytes
Bundle Auth Length <= 1,024 bytes
Payload Length <= local configured maximum
```

## 8.1 Admission before allocation

A node MUST apply storage policy before accepting a bundle.

A `BUNDLE` frame MUST NOT force immediate allocation of the declared payload size without validating configured limits.

## 8.2 Transfer

The maximum live `BUNDLE` frame is limited by the current UMP packet maximum minus headers and tags.

Bundles larger than that MUST be transferred through:

* A reliable stream using bounded chunks, or
* A future segmentation extension

The provisional stream-transfer chunk size is 256 KiB. The 256 KiB value in the current `wire-format.md` draft cannot describe one base frame and MUST receive correction before interoperability freeze.

---

# 9. Bundle storage

## 9.1 Layout

Bundle payloads are content-addressed objects as defined by `storage.md`.

The database records bundle metadata:

```text
Bundle ID
ObjectID
Owner endpoint
Sender scope
Destination hint
Size
Priority
Creation time
Expiration time
Replication count
Custody state
Delivery state
Reference count
Policy flags
```

## 9.2 Write path

A bundle write MUST:

1. Validate size and quota before allocation.
2. Write the object to a temporary file.
3. Validate the written bytes and hash.
4. Rename the object into place.
5. Commit the bundle metadata transaction.
6. Report success only after commit.

A failed write MUST NOT leave a committed metadata reference.

## 9.3 Read path

A bundle read MUST:

* Look up the metadata record
* Verify the object exists and its hash matches
* Return a structured error when the object is missing or corrupt

## 9.4 Deduplication

Content addressing deduplicates identical payloads.

Physical bytes are charged once.

Logical references are charged to each owner quota.

---

# 10. Quotas

Default standard-profile limits from `resource-limits.md`:

```text
Bundle storage: 1 GiB
Maximum bundle: 16 MiB
Bundles per sender: 1,000
Storage per Observed sender: 16 MiB
Storage per Introduced sender: 128 MiB
Storage per Trusted sender: 512 MiB
Maximum lifetime: 7 days
Default lifetime: 24 hours
Maximum replication count: 8
Concurrent bundle writes: 8
Concurrent bundle reads: 32
```

## 10.1 Admission

Before accepting a bundle, the node MUST validate:

* Declared size against configured limits
* Remaining storage quota
* Sender scope and trust
* Priority against the accepted maximum
* Expiration
* Replication count

## 10.2 Feature negotiation

A node that does not enable bundles:

* Advertises no bundle-storage grant
* Rejects bundle admission without allocating state

---

# 11. Expiration

A bundle expires at the earliest of:

* Its expiration time
* Policy invalidation
* Owner or sender revocation
* Storage-pressure eviction

## 11.1 Enforcement

The node MUST enforce expiration:

* At admission
* At forwarding opportunities
* At delivery attempts
* During garbage collection

## 11.2 Expired bundles

Expired bundles:

* Are not forwarded
* Are not acknowledged as delivered
* Are eligible for eviction
* MAY produce `BUNDLE_ACK` with status `Expired` when a sender queries

---

# 12. Duplicate handling

## 12.1 Deduplication

A node MUST deduplicate bundles with the same Bundle ID.

A duplicate:

* Does not consume new quota
* Refreshes neither creation nor expiration
* MAY return the stored status to the sender

## 12.2 Duplicate cache

The node MUST maintain a bounded duplicate cache:

```text
Bounded cardinality
Bounded retention
Expiry-aligned lifetime
```

A cache overflow MUST evict oldest entries before rejecting new storage.

## 12.3 Conflicts

A received bundle with the same ID but different encrypted bytes:

* MUST be rejected as a conflict
* SHOULD increase the sender's abuse score
* MUST NOT overwrite the stored copy

---

# 13. Delivery and acknowledgements

## 13.1 BUNDLE_ACK

The `BUNDLE_ACK` frame carries:

```text
Bundle ID
Status
Stored Until
Authentication
```

Status values:

| Value | Meaning |
| ---: | --- |
| 0 | Received |
| 1 | Custody accepted |
| 2 | Forwarded |
| 3 | Delivered |
| 4 | Rejected |
| 5 | Expired |
| 6 | Evicted |

## 13.2 Meaning

A `BUNDLE_ACK` does not necessarily prove final delivery unless authenticated by the destination endpoint.

- `Received` proves storage-node acceptance.
- `Forwarded` proves handoff to the next node.
- `Delivered` is authoritative only with destination authentication.

## 13.3 Delivery acknowledgement

When `DELIVERY_ACK_REQUESTED` is set, the destination SHOULD authenticate a delivery acknowledgement.

The delivery acknowledgement:

* Is signed by the destination identity
* Binds the Bundle ID
* Is returned through the reverse path or a future authenticated mechanism

A delivery receipt MUST NOT be treated as proof of application consumption.

---

# 14. Custody

## 14.1 Custody commitment

`CUSTODY_REQUESTED` asks the storage node to commit to retention until delivery or expiry.

A node MUST either:

* Accept custody with a `Custody accepted` acknowledgement, or
* Refuse custody before acceptance

A node MUST NOT silently accept custody it cannot honor.

## 14.2 Custody obligations

A custody node MUST:

* Retain the bundle until delivery, expiry, or explicit release
* Preserve the encrypted payload intact
* Not evict the bundle while it holds custody and has capacity
* Report eviction when forced by storage emergency

## 14.3 Custody transfer

Custody transfer is not required for stable v0.1.

When implemented, transfer MUST be explicit and authenticated.

---

# 15. Replication

## 15.1 Policy

Replication is controlled by:

```text
Maximum replication count
DO_NOT_REPLICATE flag
LOCAL_SCOPE_ONLY flag
Sender trust and quotas
Storage pressure
```

## 15.2 Rules

A node MUST NOT replicate a bundle marked `DO_NOT_REPLICATE`.

A node MUST NOT replicate beyond the maximum replication count.

A node SHOULD replicate only to nodes that:

* Accept bundle storage
* Are reachable and authenticated
* Have independent failure domains where diversity is desired

Replication counts consume the sender's storage quota at the receiving node.

## 15.3 Epidemic replication

Epidemic replication is not required for stable v0.1.

---

# 16. Forwarding

## 16.1 Trigger

A node forwards a stored bundle when:

* A contact for the destination appears
* A session carrying `ALLOW_STORE_FORWARD` opens
* The bundle is created and a live route is available
* Local policy selects a store-and-forward path

## 16.2 Behavior

Forwarding:

* Uses authenticated sessions only
* Carries the bundle in a `BUNDLE` frame
* Does not reserve relay or storage capacity
* Keeps the local copy until delivery, expiry, or policy release

## 16.3 Handoff

A forward MUST NOT apply live-route success semantics.

A successful handoff proves only that the next node accepted the bundle.

---

# 17. Intermittent-route selection

## 17.1 Contact hints

The routing engine MAY provide contact hints to the bundle subsystem.

A contact hint identifies:

```text
Destination hint match
Adjacent peer
Carrier class
Expiry
```

## 17.2 Selection

The bundle subsystem SHOULD select forwarding opportunities by:

* Destination hint match
* Remaining lifetime
* Sender and storage policy
* Quota availability
* Contact freshness

## 17.3 Separation from live routes

Delayed-delivery candidates MUST remain separate from live routes.

A `STORE_FORWARD_AVAILABLE` response cannot satisfy a request for a live session unless another response supplies a live path.

---

# 18. Offline clocks

## 18.1 Time fields

Absolute times are unsigned 64-bit integers:

```text
milliseconds since Unix epoch
```

## 18.2 Skew tolerance

The default clock-skew tolerance is:

```text
5 minutes
```

Nodes with unreliable clocks MUST avoid rejecting otherwise valid traffic solely because of small clock differences.

## 18.3 Offline behavior

A node operating offline MUST:

* Enforce bundle expiration with monotonic clocks after receipt where possible
* Not extend lifetimes through wall-clock manipulation
* Revalidate sensitive state after large clock jumps
* Document that absolute delivery timing is best-effort

## 18.4 Expiration checks

Security-sensitive expiration checks SHOULD use monotonic clocks after receipt.

Clock uncertainty MAY prevent exact enforcement.

---

# 19. Eviction

Eviction order:

1. Expired bundles.
2. Invalid or orphaned objects.
3. Delivered bundles past receipt-retention policy.
4. Unauthenticated or Observed-sender bundles.
5. Lowest priority.
6. Highest replication count.
7. Largest remaining storage cost.
8. Oldest eligible bundle.

## 19.1 Custody-aware eviction

The node MUST preserve custody commitments according to the bundle profile, or refuse custody before acceptance.

A custody node evicting under storage emergency MUST:

* Report the eviction
* Release the custody commitment explicitly

## 19.2 Pressure thresholds

```text
At 80 percent storage: reject new low-priority bundles.
At 90 percent: run eviction.
At 98 percent: reject all new bundles except bounded local administrative recovery objects.
```

---

# 20. Abuse prevention

A node MUST defend against:

* Storage fill through flood of bundles
* Quota evasion through new identities
* Deduplication-cache fill
* Priority abuse
* Replication abuse
* Declared-size lies

Defenses:

* Size and quota validation before allocation
* Per-sender, per-scope, and per-trust quotas
* Bounded duplicate cache
* Accepted-priority caps
* Replication-count caps
* Silent or generic rejection under pressure
* Abuse scoring for authenticated senders

A node MUST NOT let unauthenticated input force unbounded allocation or immediate durable writes per bundle.

---

# 21. Interaction with other subsystems

## 21.1 Sessions

Bundle transfer over live sessions uses reliable stream chunks or the `BUNDLE` frame within packet limits.

Live session failure does not destroy stored bundles.

## 21.2 Routing

`ALLOW_STORE_FORWARD` and `STORE_FORWARD_AVAILABLE` signal delayed-delivery capability.

The routing engine MAY provide contact hints.

The bundle subsystem MUST NOT apply live-route success semantics to stored handoffs.

## 21.3 Relaying

`STORE_FORWARD_ALLOWED` on relay circuits permits a relay to offer delayed-delivery mode.

It does not authorize storage by itself.

Stable live circuits MUST NOT store data after disconnection.

## 21.4 Storage

Bundle metadata and objects follow `storage.md`:

* Object writes before metadata commits
* Content-addressed validation on read
* Bounded garbage collection
* Quota recalculation after restart
* Reserved capacity for trust transactions

---

# 22. Control API and CLI

## 22.1 BundleService

```text
ListBundles
GetBundle
CreateBundle
DeleteBundle
```

Bundle support is experimental in v0.1.

Methods MAY return `UNIMPLEMENTED` while experimental bundle support is disabled.

## 22.2 Capabilities

```text
BUNDLE_READ
BUNDLE_CREATE
BUNDLE_DELETE
```

## 22.3 Visibility

Bundle metadata visibility follows local endpoint and application ownership.

Payload transfer uses bounded chunks or an application stream handle.

It does not enlarge the Control API envelope.

## 22.4 CLI

```text
umc bundle list
umc bundle inspect
umc bundle delete
```

---

# 23. Security considerations

## 23.1 Storage-node compromise

A storage node sees only ciphertext and metadata.

Compromise of a storage node does not reveal payloads while the bundle envelope holds.

## 23.2 Sender abuse

Senders can fill storage.

Quotas, priority caps, rate limits, and eviction preserve bounds.

## 23.3 Metadata exposure

Bundle metadata can reveal relationships.

Nodes minimize destination-hint disclosure and expire metadata with the bundle.

## 23.4 Clock attacks

Wall-clock manipulation can extend or shorten bundle lifetimes.

Monotonic enforcement after receipt limits the damage.

## 23.5 Replay

Replayed bundles are deduplicated.

The duplicate cache is bounded and expired.

## 23.6 Logging

Default logs MUST NOT contain:

* Bundle plaintext
* Full destination hints
* Sender identity where avoidable
* Delivery receipts

---

# 24. Required tests

A compliant implementation MUST test:

1. Bundle ID derivation and uniqueness.
2. Duplicate detection without content exposure.
3. Bundle envelope encryption and authentication.
4. Storage admission validation before allocation.
5. Quota enforcement per sender and trust class.
6. Expiration enforcement and eviction eligibility.
7. Deduplication cache bounds.
8. Conflict rejection for same ID with different bytes.
9. BUNDLE_ACK status correctness.
10. Destination-authenticated delivery receipts.
11. Custody acceptance and refusal.
12. Custody-aware eviction under pressure.
13. Replication limits and `DO_NOT_REPLICATE`.
14. Forwarding on contact and session open.
15. Handoff without live-route semantics.
16. Contact-hint selection.
17. Offline clock skew and monotonic expiry.
18. Storage-pressure thresholds.
19. One-hop delayed delivery with connectivity loss.
20. Restart preserving bundles and clearing live state.
21. Fuzz parsing of the BUNDLE frame.
22. Sender abuse and storage-fill defense.

Property tests SHOULD verify:

```text
Identical bundles deduplicate once.
Expired bundles never forward.
Custody commitments survive eviction policy or are refused.
Replication never exceeds the limit.
A bundle is never acknowledged Delivered without destination authentication.
No bundle forces allocation beyond declared validated limits.
```

---

# 25. Minimal v0.1 compliance

A compliant experimental v0.1 implementation MUST support:

* Bundle identifiers
* Bundle storage abstraction
* Bundle quotas
* Expiration model
* Experimental frame encoding
* Feature negotiation
* Content-addressed bundle payloads
* Duplicate detection
* Basic one-hop delayed delivery
* Sender and scope accounting

An implementation MAY defer:

* Custody transfer
* Epidemic replication
* Multi-carrier physical movement routing
* Strong delivery receipts
* Global bundle routing
* Intermittent-contact route selection

An implementation MUST NOT advertise deferred bundle capabilities.

---

# 26. Open design decisions

The project must resolve these items before v0.2:

1. Final Bundle ID derivation.
2. Bundle envelope construction and key schedule.
3. Delivery-receipt format and return path.
4. Custody transfer protocol.
5. Segmentation extension for bundles over packets.
6. Replication strategy and selection.
7. Contact-hint format from routing.
8. Intermittent-route selection algorithm.
9. Storage-node discovery for replication.
10. Offline-clock handling beyond skew tolerance.
11. Feature-negotiation encoding for bundle grants.
12. Whether HIGH_SENSITIVITY implies shorter retention.
13. Bundle prioritization and queueing.
14. Eviction ordering under custody conflicts.
15. Whether base-frame bundle transfer uses streams in v0.2.
16. Bundle status registry extension.

---

# 27. Recommended implementation order

Implement bundles in this order:

1. Bundle types and identifiers.
2. Envelope encryption.
3. `BUNDLE` frame parsing.
4. Storage admission validation.
5. Content-addressed storage.
6. Metadata lifecycle.
7. Quotas.
8. Expiration.
9. Deduplication.
10. `BUNDLE_ACK`.
11. Basic one-hop forwarding.
12. Delivery receipts.
13. Custody.
14. Replication.
15. Contact hints and route selection.
16. Eviction and pressure behavior.
17. Fuzzing and adversarial tests.

---

# 28. Core rule

A UMP bundle is an encrypted, expiring, quota-bounded object that storage nodes retain and forward without ever seeing its plaintext.

Bundle identifiers deduplicate without disclosure. Every acceptance validates policy before allocation. Every commitment is explicit. Every handoff is authenticated but proves nothing beyond acceptance. Offline clocks degrade gracefully, and eviction always preserves the promises the node actually made.
