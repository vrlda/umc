# Universal Mesh Core Discovery Specification

**Status:** Draft
**Version:** 0.1
**Document:** Peer Discovery and Candidate Handling
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines how UMC nodes discover other nodes and obtain peer candidates.

It specifies:

* Discovery provider model
* Candidate lifecycle
* Candidate fields and attributes
* Candidate freshness
* Static peers
* LAN discovery
* Peer exchange
* Invitations
* Bootstrap bundles
* Application introductions
* Provider merging and conflicts
* Sharing restrictions
* Peer-table bounds
* Enumeration resistance
* Private peer handling
* Trust interaction
* Service discovery
* Interaction with routing
* Resource limits

This document does not define:

* Route discovery
* Endpoint authentication
* Session establishment
* Relay circuit construction
* Global naming or DHT internals

Those are defined in their respective specifications.

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

Discovery returns candidates, not trusted peers.

A candidate is evidence that a node might be reachable. It is never an authentication result, a trust decision, or proof of endpoint identity.

---

# 3. Discovery goals

The discovery subsystem MUST:

1. Provide candidates from multiple independent providers.
2. Merge candidate results with source attribution.
3. Preserve freshness and sharing policy.
4. Enforce bounded state and rate limits.
5. Resist enumeration of the peer table.
6. Protect private peers from disclosure.
7. Support bootstrap without mandatory project infrastructure.
8. Feed routing without triggering unbounded discovery.

No single provider is mandatory for all deployments.

A node MUST be able to operate with one working provider.

---

# 4. Terminology

## 4.1 Discovery provider

A module that produces peer candidates from one source or medium.

## 4.2 Candidate

A scoped claim that a node may be reachable through a carrier context.

## 4.3 Hint

A candidate shared between nodes or through a provider.

## 4.4 Invitation

A scoped, expiring credential that introduces a node or grants private admission.

## 4.5 Bootstrap bundle

A signed set of initial candidates used for first contact.

## 4.6 Source

The provenance of a candidate.

## 4.7 Sharing policy

Rules controlling how a candidate may be reused and redistributed.

---

# 5. Discovery provider model

The reference implementation SHOULD define a discovery provider interface equivalent to:

```rust
trait DiscoveryProvider {
    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
    async fn candidates(&self) -> Result<Vec<PeerCandidate>>;
    async fn publish(&self, hint: PeerHint) -> Result<()>;
}
```

Possible providers:

```text
Static configuration
LAN broadcast
Local Bluetooth
Peer exchange
Signed invitation
Bootstrap file
DHT-like lookup
HTTPS-based optional bootstrap
Removable media
Application introduction
```

A provider MUST:

* Enforce its configured candidate maximum
* Stop on cancellation or deadline
* Validate native message sizes before allocation
* Mark source and authentication state on every candidate
* Avoid interpreting discovery as endpoint trust

A provider MAY:

* Emit a bounded stream of candidate events
* Report its own health and confidence
* Support scope-limited queries

---

# 6. Candidate lifecycle

A candidate uses these states:

```text
FOUND
UPDATED
EXPIRED
REMOVED
ERROR
COMPLETE
```

## 6.1 FOUND

A provider discovered or produced a candidate.

## 6.2 UPDATED

The candidate's attributes changed within its lifetime.

## 6.3 EXPIRED

The candidate's lifetime ended.

## 6.4 REMOVED

The provider removed the candidate before expiry.

## 6.5 ERROR

The provider reported an error for the candidate or operation.

## 6.6 COMPLETE

The provider finished its discovery operation.

UMC merges provider results into one bounded candidate table with source attribution.

---

# 7. Candidate fields

A candidate contains:

```text
candidate_id
carrier_type
carrier_profile
connection_hint
scope
source
created_at
expires_at
sharing_policy
authentication_state
capability_hints
priority_hint
```

## 7.1 Candidate ID

Candidate ID is an opaque local handle.

It MUST NOT act as endpoint identity.

## 7.2 Connection hint

Connection Hint contains carrier-specific dialing data.

The generic limit is 1,024 bytes.

## 7.3 Source

Source records how UMC obtained the candidate:

```text
STATIC
LOCAL_DISCOVERY
PEER_HINT
INVITATION
BOOTSTRAP
APPLICATION
CARRIER_NATIVE
```

## 7.4 Expiry

UMC MUST reject an expired candidate before dialing.

## 7.5 Authentication state

Candidate authentication records evidence about the hint, not the endpoint behind it:

```text
UNAUTHENTICATED
CARRIER_AUTHENTICATED
INTRODUCTION_AUTHENTICATED
INVITATION_AUTHENTICATED
PREVIOUS_SESSION_BOUND
```

## 7.6 Capability hints

Capability hints are advisory.

A candidate MUST NOT be trusted for a capability it does not advertise, and advertising does not prove capability.

---

# 8. Candidate freshness

## 8.1 Lifetime

A candidate MUST carry an expiration.

The default maximum candidate lifetime is provider-defined, capped at:

```text
24 hours without refresh
```

Static and pinned candidates MAY exceed this under explicit policy.

## 8.2 Refresh

A candidate MAY be refreshed by:

* Its provider reporting an update
* Successful authenticated contact
* A new authenticated peer hint
* A new invitation use

Refreshed candidates MUST:

* Reset their expiration
* Record the refresh time and source
* Preserve sharing policy

## 8.3 Stale handling

UMC MUST:

* Evict expired candidates
* Reject expired candidates before dialing
* Reduce ranking for stale-but-unexpired candidates
* Never persist stale candidates as live reachability

---

# 9. Sharing restrictions

## 9.1 Sharing policy

Every candidate carries a sharing policy:

```text
LOCAL_USE_ONLY
SHARE_SELECTED
SHARE_LOCAL_SCOPE
SHARE_GENERAL
DO_NOT_RESHARE
```

## 9.2 DO_NOT_RESHARE

A node MUST NOT automatically reshare hints marked `DO_NOT_RESHARE`.

Private peers MUST NOT be shared without authorization.

## 9.3 Sharing rules

UMC MUST:

* Preserve sharing policy on every merge and cache operation
* Not forward a candidate beyond its policy
* Not persist a candidate beyond its policy
* Charge disclosures to the authorizing scope

---

# 10. Peer-table bounds

Peer knowledge MUST remain bounded.

Profile defaults from `resource-limits.md`:

| Scope | `constrained` | `standard` | `relay` |
| --- | ---: | ---: | ---: |
| Total peer records | 2,048 | 50,000 | 250,000 |
| Direct and active peers reserved | 256 | 4,096 | 32,768 |
| New Observed peers per source | 64 | 256 | 1,024 |
| Carrier hints per peer | 8 | 16 | 32 |

Peer records receive classes:

```text
PINNED
ACTIVE
TRUSTED
INTRODUCED
SUCCESSFUL
OBSERVED
STALE
```

Eviction removes expired and stale records before active, pinned, or trusted records.

Trust does not bypass the global peer-record hard limit.

---

# 11. Static peers

## 11.1 Configuration

Static peers are configured locally:

```text
carrier type
connection hint
scope
sharing policy
priority
```

Static peers:

* Are not discovered dynamically
* MUST still authenticate endpoints after dialing
* MAY be pinned against eviction
* Are a valid sole bootstrap source

## 11.2 Behavior

Static peers MUST NOT be treated as trusted endpoints.

A static entry that fails authentication is reported and MAY be removed under policy.

---

# 12. LAN discovery

## 12.1 Role

LAN discovery provides:

* Peer announcements
* Candidate exchange
* Local scope awareness

It does NOT imply trust.

Actual LAN sessions use UDP or TCP carriers.

## 12.2 Behavior

The LAN discovery provider:

* Announces local presence
* Discovers neighboring announcements
* Produces candidates with source `LOCAL_DISCOVERY`
* Marks candidates with the `LOCAL` flag where applicable
* MUST be bounded and rate-limited
* MUST validate announcement sizes before allocation

## 12.3 Locality

A node MUST NOT infer trust from:

* Local presence
* Private IP space
* SSID
* Bluetooth name
* Link-layer address

The effective local-scope classification belongs to node policy, not the provider.

---

# 13. Peer exchange

## 13.1 PEER_HINT frame

Peer hints travel in the `PEER_HINT` frame defined by `wire-format.md`.

Frame limits:

```text
Hint Count <= 32
Temporary Peer ID Length <= 64 bytes
Carrier Type Length <= 64 bytes
Connection Hint Length <= 1,024 bytes
Authenticator Length <= 1,024 bytes
```

Flags:

```text
PUBLIC
INTRODUCED
LOCAL
EPHEMERAL
DO_NOT_RESHARE
```

## 13.2 Exchange rules

Peer exchange MUST be:

```text
Bounded
Randomized
Expiring
Access-controlled
Rate-limited
```

A node MUST NOT automatically disclose its complete peer table.

## 13.3 Selection

A node SHOULD select hints for sharing that:

* Are public or within sharing policy
* Are fresh
* Have successful contact history
* Differ in failure domains
* Exclude private or `DO_NOT_RESHARE` entries

## 13.4 Receiving

On receiving hints, a node MUST:

* Validate all field limits
* Preserve source, expiry, and sharing policy
* Rate-limit per sender
* Record the sender as the hint source
* Not promote the hinted endpoint to any trust state

---

# 14. Invitations

## 14.1 Purpose

An invitation:

* Introduces a node to a private or closed group
* Grants scoped admission
* Expires
* Can be revoked

## 14.2 Lifecycle

Invitation operations:

```text
CreateInvitation
ImportInvitation
RevokeInvitation
```

An invitation MUST be:

* Random
* Expiring
* Scope-limited
* Single-use or use-limited
* Bound to a responder or bridge group
* Revocable where practical
* Never derived from low-entropy passwords without a memory-hard KDF

## 14.3 Handling

Invitation secrets:

* Appear once at creation or import result
* MUST NOT appear in later list responses
* MUST NOT be logged
* Are used for PSK-XX admission as defined by `handshake.md`

## 14.4 Private bridge mode

Private bridge mode:

* Requires invitation authentication before recognizable UMP behavior
* Hides protocol behavior from unauthenticated probes
* Restricts peer sharing
* Limits public advertisements

---

# 15. Bootstrap

## 15.1 Bootstrap sources

A node MUST be able to bootstrap from:

* One known peer
* One invitation token
* One local peer
* One signed peer bundle

Additional sources MAY include:

* HTTPS-based optional bootstrap
* DHT-like lookup
* Removable media
* Application introductions

No mandatory global bootstrap server may be required by the protocol.

Reference deployments MAY provide optional public bootstrap peers.

## 15.2 Bootstrap bundles

A bootstrap bundle is a signed set of initial candidates.

A bootstrap bundle MUST include:

```text
Format version
Issuer
Validity
Candidate list with expirations
Sharing policy
Signature
```

UMC MUST treat bootstrap output as candidates:

* Bound candidate counts and sizes
* Preserve source attribution and expiry
* Authenticate endpoints after dialing
* Not grant trust from the bootstrap source

## 15.3 Compromised sources

A compromised bootstrap source may:

* Return attacker-controlled, stale, selective, or malformed candidates
* Log request origin and timing
* Withhold honest peers

Defenses:

* Several bootstrap methods
* Static, local, invitation, and removable-media bootstrap
* Source attribution and expiry
* Diversity checks
* No mandatory project bootstrap

---

# 16. Application introductions

An application MAY provide introductions.

Application introductions:

* Are scoped to the application's grant
* MUST be attributable
* MUST carry expiry and sharing policy
* MUST NOT bypass endpoint authentication
* MAY use the `APPLICATION` source

---

# 17. Provider merging and conflicts

## 17.1 Merging

UMC merges provider results into one bounded candidate table.

Merging MUST:

* Keep one record per candidate identity when attributes are compatible
* Preserve all sources when attributes conflict
* Keep the freshest attributes
* Preserve the strictest sharing policy
* Charge each candidate to the narrowest known scope

## 17.2 Conflicts

Discovery conflicts do not establish routing truth.

When two providers disagree:

* Keep both candidate records with their sources
* Probe several candidates under resource limits
* Record outcomes
* Let routing rank by evidence

## 17.3 Provider failure

A failing provider:

* MUST NOT corrupt other providers' candidates
* MUST be restartable under policy
* SHOULD report health through diagnostics

---

# 18. Enumeration resistance

A node MUST NOT answer broad queries with its peer list.

Defenses:

* Destination hints must target a bounded endpoint, service, gateway class, or lookup partition
* Rate limits on distinct hint queries
* Bounded randomized responses
* Silent drops for probing patterns
* Scope reduction under pressure
* Private hint withholding

Default rates:

```text
Discovery responses per peer: 20 per minute
Distinct hint queries per Observed peer: 10 per minute
Private hint disclosures: authorization-scoped
```

Repeated probing across a hint space MAY trigger:

* Silent drops
* Scope reduction
* Peer restriction

---

# 19. Private peer handling

Private peers:

* MUST NOT be shared without authorization
* MUST NOT appear in public peer exchange
* MUST NOT be included in general-scope responses
* MAY be pinned against eviction
* Are partitioned by policy and local identity

A node MUST keep private records separate from public bootstrap data.

Deletion after trust revocation or peer removal MUST remove:

* Private hints
* Derived route evidence
* Shared candidates

---

# 20. Trust interaction

## 20.1 Trust and discovery

Discovery results MUST NOT change trust state.

Unknown and Observed endpoints MAY:

* Complete a cryptographic handshake
* Exchange tightly rate-limited discovery information

They may NOT by default:

* Receive private peer hints
* Trigger unlimited discovery
* Cause trust promotion

## 20.2 Introductions

A signed introduction increases context but does not produce full trust.

Introduction-based hints carry the `INTRODUCED` flag and:

* Expire with the introduction
* Are scoped by the introduction
* MAY grant scoped sharing

## 20.3 Trust states and hints

| Trust state | Default discovery behavior |
| --- | --- |
| `Unknown` | Strict public-query limits; no private hints |
| `Observed` | Bounded public requests; no private hints |
| `Introduced` | Granted scopes until introduction expiry |
| `Trusted` | Configured scopes and higher quotas |
| `Restricted` | Explicit reduced scopes and rates |
| `Blocked` | Reject discovery traffic |
| `Revoked` | Reject and invalidate affected hints |

---

# 21. Service discovery

## 21.1 Service hints

The core MAY support opaque service hints.

A service hint contains:

```text
Protocol ID
Endpoint hint
Expiration
Opaque metadata
Signature
```

The core does not interpret application metadata.

## 21.2 Rules

Service discovery:

* MUST remain optional
* MUST NOT enumerate all services
* MUST respect sharing policy
* MUST rate-limit per query source
* Returns candidates, not trust

Applications may implement their own discovery protocols.

---

# 22. Interaction with routing

Discovery provides peer candidates and scoped hints.

Routing decides whether to use them for a destination.

A discovery hint MUST carry:

```text
Source
Freshness or expiry
Sharing policy
Carrier context
Authentication status
```

The router MUST preserve these attributes.

Routing MUST NOT trigger unbounded discovery.

One route request receives a fixed discovery budget under local policy.

---

# 23. Resource limits

Default standard-profile limits from `resource-limits.md`:

```text
Concurrent discovery operations: 16
Candidates per operation: 256
Candidate size: 1,024 bytes connection hint plus bounded metadata
Candidate lifetime: provider-defined, capped at 24 hours without refresh
Peer hints per frame: 32
Discovery responses per peer: 20 per minute
Distinct hint queries per Observed peer: 10 per minute
Private hint disclosures: authorization-scoped
```

## 23.1 Pressure behavior

At `HIGH` pressure:

* Disable background discovery
* Lower candidate caps to 32
* Keep static, local, invitation, and active-session recovery providers

At `CRITICAL`:

* Admit only explicit local or trusted recovery discovery

## 23.2 Unknown sources

Unknown-source aggregation follows `resource-limits.md`.

UMC MUST bound the number of detailed source buckets and fall back to aggregate accounting when cardinality grows.

---

# 24. Control API and CLI surface

## 24.1 PeerService

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

## 24.2 Capabilities

```text
DISCOVERY_READ
DISCOVERY_RUN
PEER_READ
PEER_ADMIN
TRUST_ADMIN
```

## 24.3 CLI

```text
umc peer add
umc peer remove
umc peer list
umc peer inspect
umc peer block
umc invite create
umc invite import
umc invite revoke
```

---

# 25. Security considerations

## 25.1 Compromised discovery peer

A peer can send false, stale, duplicated, or privacy-violating hints.

Defenses:

* Hint count and size limits
* Source, expiry, and sharing-policy preservation
* `DO_NOT_RESHARE` enforcement
* No complete peer-table disclosure
* Endpoint authentication after candidate use
* Rate limits on failed hints

## 25.2 Sybil influence

Many identities from one source must not count as independent.

Per-source and per-introduction quotas, failure-domain diversity, and bounded peer-table slots limit influence.

## 25.3 Eclipse

A node with one bootstrap source has no independent basis to detect a complete eclipse.

Multiple providers, pinned peers, local-mesh options, and signed invitations reduce risk.

## 25.4 Candidate poisoning

Discovery can inject false addresses.

Candidates retain source and authentication state.

UMP authenticates endpoints after dialing.

## 25.5 Logging

Default logs MUST NOT contain:

* Private peer hints
* Full candidate lists
* Invitation secrets
* Stable peer identifiers without redaction

---

# 26. Required tests

A compliant implementation MUST test:

1. Provider start, stop, and restart.
2. Candidate lifecycle transitions.
3. Candidate expiry and stale rejection.
4. Source and authentication-state preservation.
5. Sharing-policy enforcement including `DO_NOT_RESHARE`.
6. Peer-table bounds and eviction order.
7. Static-peer bootstrap.
8. LAN discovery announcements and validation.
9. Peer-hint frame limits.
10. Rate-limited exchange and randomized selection.
11. Invitation creation, import, expiry, and revocation.
12. Bootstrap bundle validation.
13. Malicious bootstrap source behavior.
14. Provider conflict handling.
15. Provider failure isolation.
16. Enumeration-resistance behavior under probing.
17. Private peer non-disclosure.
18. Trust-state interaction.
19. Service-hint optionality and validation.
20. Routing budget limits on discovery.
21. Pressure-state candidate caps.
22. Unknown-source aggregation.
23. Restart preserving sharing policy and revalidating candidates.

Property tests SHOULD verify:

```text
No candidate outlives its sharing policy.
No expired candidate is dialed.
DO_NOT_RESHARE hints never propagate.
Discovery never changes trust state.
One provider cannot evict pinned or trusted peers.
Candidate counts never exceed configured limits.
Private peers never appear in general-scope output.
```

---

# 27. Minimal v0.1 compliance

A compliant implementation MUST support:

* A discovery provider interface
* Static peers
* Peer exchange through `PEER_HINT`
* Invitation create, import, and revoke
* Bootstrap from one known peer or bundle
* Candidate lifecycle and expiry
* Source attribution
* Sharing-policy enforcement
* Bounded peer tables
* Enumeration resistance
* Private peer protection
* Rate limits
* Provider merging with conflict preservation

An implementation MAY defer:

* LAN discovery
* DHT-like lookup
* HTTPS bootstrap
* Bluetooth discovery
* Removable-media bootstrap
* Service discovery

An implementation MUST NOT advertise a deferred provider.

---

# 28. Open design decisions

The project must resolve these items before freezing UMP/1:

1. Invitation canonical encoding.
2. Bootstrap bundle format.
3. Whether PEER_HINT entries require per-hint signatures.
4. Randomized hint-selection parameters.
5. LAN announcement format and cadence.
6. Whether LAN discovery runs in the LAN carrier or a separate provider.
7. Service-hint distribution mechanism.
8. Candidate merging precedence rules.
9. Whether private peers persist by default.
10. Invitation-to-identity binding rules.
11. Bootstrap bundle trust anchor handling.
12. Peer-exchange fanout and selection strategy.
13. Unknown-source aggregation keys per carrier.
14. Whether hints are re-signed on refresh.
15. Enumeration-resistance thresholds per profile.
16. Whether discovery providers expose health metrics publicly.
17. Application introduction authorization model.
18. Candidate priority-hint trust rules.

---

# 29. Recommended implementation order

Implement discovery in this order:

1. Candidate types and lifecycle.
2. Provider interface.
3. Candidate table with bounds.
4. Source and sharing-policy preservation.
5. Static peers.
6. `PEER_HINT` parsing and exchange.
7. Rate limits and enumeration resistance.
8. Invitations.
9. Bootstrap bundles.
10. Provider merging and conflicts.
11. LAN discovery.
12. Private peer handling.
13. Trust interaction.
14. Service discovery.
15. Pressure behavior.
16. Fuzzing and adversarial tests.

---

# 30. Core rule

UMC discovery gathers bounded, expiring, source-attributed candidates from many providers without ever disclosing more peer knowledge than policy permits.

Candidates carry their source, freshness, authentication evidence, and sharing policy through every merge and cache operation. Discovery results never authenticate endpoints, never promote trust, and never outlive their policy.
