# Universal Mesh Protocol Routing Specification

**Status:** Draft
**Version:** 0.1
**Document:** Route Discovery and Path Construction
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines how UMP nodes discover, validate, rank, cache, and retire routes without a global topology database.

It specifies:

* Route discovery
* Request propagation
* Response construction and validation
* Hop limits and expiry
* Duplicate and loop prevention
* Route cache behavior
* Path construction
* Route scoring inputs
* Route failure handling
* Local and non-local routing scopes
* Privacy boundaries
* Malicious routing-message handling
* Routing resource limits

The relay specification defines relay-circuit establishment and forwarding. The discovery specification defines how nodes obtain peer candidates. The session specification defines path validation and migration after a route produces a usable path.

This document does not define:

* Global naming
* Carrier dialing
* Relay data forwarding
* Bundle-routing algorithms
* Application service semantics
* A mandatory route-scoring formula

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

Routing messages travel inside authenticated UMP sessions. Authentication identifies the adjacent sender. It does not prove that a route claim is correct.

---

# 3. Routing goals

UMP routing must let an endpoint find a usable path while keeping state, disclosure, and forwarding work bounded.

The routing layer MUST support:

1. Direct routes.
2. Single-relay routes.
3. Multi-hop routes within a configured hop limit.
4. Route discovery from partial peer knowledge.
5. Route expiry and failure recovery.
6. Local-scope operation without internet access.
7. Route diversity across peers and carriers.
8. Policy constraints from the application and node.
9. Protection against loops, floods, and forged claims.

UMP/1 does not guarantee that a discovered route works, stays available, or hides traffic relationships from participating nodes.

---

# 4. Terminology

## 4.1 Route

A route is a time-limited plan for reaching a destination through one or more adjacent peer relationships.

## 4.2 Path

A path is an instantiated route whose links and relay circuits can carry session packets.

## 4.3 Next hop

The next hop is the adjacent peer selected for one route step.

## 4.4 Route requester

The requester starts route discovery.

## 4.5 Route responder

A responder sends a route response because it can reach the requested destination or can offer a suitable service or gateway.

## 4.6 Forwarder

A forwarder propagates a bounded route request or response between adjacent peers.

## 4.7 Destination hint

A destination hint is an opaque value used to match a route target. It may contain an endpoint lookup token, routing hash, service selector, or gateway capability query.

## 4.8 Route scope

Scope limits where nodes may propagate or use a request.

UMP/1 defines:

```text
LINK_LOCAL
LOCAL_MESH
INTRODUCED
GENERAL
```

---

# 5. Routing architecture

Each node maintains bounded local state:

```text
Adjacent peers
Peer trust and sharing policy
Candidate routes
Active paths
Recent request cache
Reverse request state
Route failure history
Local service reachability
```

A node does not need a complete peer list or topology map.

The routing engine consumes candidates from discovery and link management. It produces path candidates for session and relay management.

The routing engine MUST keep these decisions separate:

```text
Discovery: which peer might be reachable
Routing: which sequence of hops might reach a destination
Relay: whether each hop grants forwarding resources
Session: whether the end-to-end path authenticates and works
```

---

# 6. Route state machine

A local route record uses these states:

```text
CANDIDATE
PROBING
USABLE
DEGRADED
FAILED
EXPIRED
RETIRED
```

## 6.1 CANDIDATE

The node has a route hint or response but has not instantiated the path.

## 6.2 PROBING

The node is dialing a next hop, opening relay circuits, or validating a path.

## 6.3 USABLE

The route produced a validated path or succeeded within a route-specific reachability test.

## 6.4 DEGRADED

The route still works, but loss, latency, policy, carrier health, or relay status reduced its rank.

## 6.5 FAILED

A route step failed. The node retains bounded failure metadata to avoid immediate retry loops.

## 6.6 EXPIRED

The route lifetime ended. The node MUST NOT use it for a new path without fresh validation or discovery.

## 6.7 RETIRED

Local policy removed the route and any retained state beyond failure suppression.

---

# 7. Route request identity

Each requester creates an unpredictable Request ID for every logical discovery operation.

Request IDs MUST:

* Contain at least 128 bits of entropy
* Remain unique within the requester's replay-retention window
* Avoid endpoint IDs, timestamps, addresses, or counters in plaintext form
* Remain stable across retransmissions of the same logical request

A node identifies a request by:

```text
Request ID
Authenticated adjacent sender
Request scope
Destination hint hash
```

Request ID alone does not authorize a response or reveal the requester identity.

---

# 8. ROUTE_REQUEST semantics

The wire-format `ROUTE_REQUEST` body contains:

```text
Request ID
Flags
Hop Limit
Expiration Delta
Destination Hint
Path Exclusions
Requester Auth
```

The frame MUST use a critical length-delimited frame type in the frozen UMP/1 registry.

## 8.1 Flags

UMP/1 uses:

```text
ALLOW_RELAY
ALLOW_STORE_FORWARD
REQUIRE_PRIVATE_RESPONSE
LOCAL_SCOPE_ONLY
GATEWAY_QUERY
```

A node MUST reject unknown critical flag bits.

`ALLOW_RELAY` permits live relayed paths. It does not compel a node to relay.

`ALLOW_STORE_FORWARD` permits a responder to advertise delayed delivery. Stable UMP/1 live-route selection MUST NOT treat such a response as a live path.

`REQUIRE_PRIVATE_RESPONSE` requires responses to follow protected reverse state or another authenticated return mechanism. A forwarder MUST NOT emit a public or broadly shared response.

`LOCAL_SCOPE_ONLY` restricts propagation to links classified as local by both carrier and node policy.

`GATEWAY_QUERY` asks for a gateway capability rather than an endpoint route. Gateway semantics remain outside the core.

## 8.2 Hop limit

The requester sets a Hop Limit from 1 through 32.

Each forwarder decrements Hop Limit before propagation. It MUST NOT forward a request whose resulting value is zero.

A node MUST NOT increase Hop Limit.

Recommended defaults:

```text
LINK_LOCAL: 1
LOCAL_MESH: 4
INTRODUCED: 6
GENERAL: 8
```

Nodes MAY apply lower local limits.

## 8.3 Expiration

Expiration Delta sets request lifetime relative to authenticated receipt by the first hop.

Each forwarder computes a local monotonic deadline and propagates no lifetime beyond its remaining deadline.

Recommended maximum request lifetime is 30 seconds. A node MUST reject values above 5 minutes.

Clock differences MUST NOT extend request lifetime.

## 8.4 Destination hint

The generic routing layer treats Destination Hint as opaque.

The selected lookup profile defines matching rules. A node MUST know the profile through authenticated capability or request context before interpreting the hint.

UMP/1 implementations MUST support an endpoint routing token profile. The final token construction remains an open cryptographic decision in this draft.

A requester SHOULD use a scoped or rotating token when it has one. It SHOULD avoid sending a permanent Endpoint ID through peers that do not need it.

## 8.5 Path exclusions

Path Exclusions contain opaque node, relay, carrier, or failure-domain selectors that the requester refuses to use.

An exclusion list MUST contain at most 32 entries. Each entry MUST be no more than 64 bytes in the frozen encoding.

A forwarder MUST honor exclusions it understands. It MUST reject the request when it cannot satisfy an exclusion marked critical by the lookup profile.

Nodes MUST NOT treat exclusions as proof that a listed node is malicious.

## 8.6 Requester authentication

Requester Auth proves request authorization when policy requires it. It may contain:

* An invitation-derived proof
* A signed introduction scope
* A blinded authorization token
* A local-mesh group authenticator

The adjacent UMP session already authenticates the forwarding peer. Requester Auth may authenticate an origin beyond that peer.

A node MUST verify required authorization before costly lookup or propagation.

---

# 9. Request creation

The requester MUST apply local policy before sending a request.

It selects:

* Destination hint profile
* Scope
* Hop limit
* Deadline
* Relay and delayed-delivery permissions
* Path exclusions
* Initial peers

The requester SHOULD send to a small set of high-ranked, diverse peers. Default fanout is three.

The initial peers SHOULD differ across available carrier, trust, network, or introduction domains.

The requester MUST cap concurrent requests for one destination. Default limit is two logical requests, each with a distinct strategy or scope.

---

# 10. Request admission

A node that receives `ROUTE_REQUEST` performs these checks before propagation:

1. Authenticate and parse the enclosing packet.
2. Enforce frame and field size limits.
3. Check request expiry and Hop Limit.
4. Consult duplicate and replay state.
5. Apply per-peer and global rate limits.
6. Validate scope and Requester Auth.
7. Check local sharing and routing policy.
8. Match local reachability or select forward peers.

The node MUST avoid route-cache scans, signature chains, broad peer searches, or relay allocation before cheap admission checks pass.

The node MAY silently drop a request. It SHOULD send `ROUTE_ERROR` only when the adjacent sender is authenticated and the error does not reveal protected topology or policy.

---

# 11. Duplicate suppression

Each node MUST keep a bounded cache of recent admitted requests.

The cache stores:

```text
Request identity
First-seen monotonic time
Best remaining hop limit
Previous hops
Forwarded peers
Response state
Expiry
```

A node MUST suppress an exact duplicate from the same adjacent peer.

The node MAY reconsider a duplicate when it arrives with:

* A greater remaining Hop Limit
* A stronger authenticated authorization scope
* A new previous hop that improves return-path diversity

It MUST NOT repeat propagation to the same peer for the same request identity.

Default request-cache retention is the request lifetime plus 30 seconds. The node MAY retain a compact hash for longer replay suppression.

---

# 12. Loop prevention

UMP combines:

* Hop limits
* Request IDs
* Duplicate suppression
* Previous-hop exclusion
* Optional path traces or accumulators

A node MUST NOT forward a request back to the peer from which it received that copy.

A node MUST NOT forward to a peer already named in an authenticated path accumulator.

UMP/1 does not require a plaintext full path in requests. Implementations may use privacy-preserving accumulators after an extension defines their encoding and security properties.

If a node detects a loop, it drops that branch. It MAY send `ROUTE_ERROR` with `ROUTE_LOOP` to the previous hop.

A loop on one branch MUST NOT invalidate independent branches.

---

# 13. Request propagation

A node forwards an admitted request only to peers allowed by:

* Request scope and flags
* Local trust policy
* Peer sharing restrictions
* Path exclusions
* Hop limit
* Rate and fanout budgets

Default forwarding fanout is three peers per node. A node MAY use smaller fanout under load and SHOULD NOT exceed eight in stable UMP/1 profiles.

Forwarders SHOULD select peers with evidence relevant to the destination hint. Evidence may include:

* Direct adjacency
* A fresh route cache entry
* A trusted introduction
* A scoped service or peer hint
* A matching local routing prefix or token partition

Blind flooding across the full peer table is prohibited.

Forwarders MUST preserve Request ID, destination hint, request flags, and requester authorization bytes unless a defined extension permits transformation.

They MUST decrement Hop Limit and remaining lifetime.

---

# 14. Routing scopes

## 14.1 LINK_LOCAL

The node evaluates direct adjacency and local services. It does not forward the request.

## 14.2 LOCAL_MESH

The node forwards only across carriers and links classified as local. Public internet relays and global bootstrap peers are excluded.

Carrier classification alone cannot prove physical locality. Node policy decides whether a link qualifies.

## 14.3 INTRODUCED

The node forwards through trusted or introduced peers that permit scoped sharing.

It MUST NOT cross into public peer exchange without explicit request and policy permission.

## 14.4 GENERAL

The node may use any permitted peer and carrier while respecting privacy, hop, and rate limits.

GENERAL scope does not permit global flooding or peer-table disclosure.

## 14.5 Scope reduction

A forwarder MAY narrow scope. It MUST NOT broaden it.

The route response MUST report the scope under which the route was found.

---

# 15. Destination matching

A node may answer a request when it has one of these forms of reachability:

```text
DIRECT_ENDPOINT
DIRECT_SERVICE
CACHED_ROUTE
AVAILABLE_RELAY_PATH
DELAYED_DELIVERY
GATEWAY_CAPABILITY
```

The response MUST identify the reachability class inside authenticated route metadata.

A direct endpoint or service match requires local proof that binds the destination hint to the endpoint or service.

A cached route match requires unexpired route state and local policy permission. The responding node MUST shorten the advertised lifetime to the remaining cached lifetime.

A relay-path match describes an available construction attempt, not reserved capacity, unless relay authorization already created a reservation.

A node MUST NOT answer based only on an unverified peer advertisement.

---

# 16. ROUTE_RESPONSE semantics

The wire-format `ROUTE_RESPONSE` body contains:

```text
Request ID
Response Sequence
Flags
Route Lifetime
Next-Hop Hint
Route Metadata
Authentication
```

The frame MUST use a critical length-delimited frame type in the frozen UMP/1 registry.

## 16.1 Response sequence

The responder assigns a monotonically increasing Response Sequence per Request ID.

Sequence zero is the first response. Later responses may replace or supplement earlier candidates.

Two responses from the same authenticated responder with the same sequence and different bytes are invalid.

## 16.2 Flags

UMP/1 uses:

```text
DIRECT
RELAY_REQUIRED
STORE_FORWARD_AVAILABLE
LOCAL_PATH
GATEWAY_PATH
```

Flags describe the candidate. They do not grant relay, storage, or gateway authorization.

`DIRECT` and `RELAY_REQUIRED` MUST NOT both be set for the same route leg.

`STORE_FORWARD_AVAILABLE` cannot satisfy a request for a live session unless another response supplies a live path.

## 16.3 Lifetime

Route Lifetime is relative and MUST NOT exceed:

* Request's remaining lifetime for reverse forwarding
* Earliest expiry among all route evidence
* Local maximum route lifetime

Recommended maximum cacheable lifetime is 10 minutes. Direct local routes may use a shorter link-bound lifetime.

## 16.4 Next-hop hint

Next-Hop Hint gives the previous node enough information to instantiate its next route step.

It may identify:

* An existing adjacent session
* A temporary peer candidate
* A relay endpoint and circuit offer
* A local carrier rendezvous token

The hint MUST be scoped to its intended recipient where the carrier or discovery system supports scoped hints.

It MUST NOT contain private peer data unrelated to the route.

## 16.5 Route metadata

Route Metadata is an authenticated, length-delimited structure. UMP/1 metadata SHOULD include:

```text
Metadata version
Reachability class
Route scope
Remaining hop count
Carrier classes
Relay count
Estimated MTU
Estimated latency class
Estimated bandwidth class
Cost class
Failure-domain tags
Privacy flags
Evidence expiry
```

Nodes treat metrics as advisory claims. They MUST NOT allocate resources or grant trust based on metrics alone.

## 16.6 Authentication

Every response receives hop-by-hop authentication from its enclosing session.

The final responder MUST also authenticate the response to Request ID, destination hint hash, response sequence, lifetime, next-hop hint hash, and metadata hash.

Authentication may use:

* Endpoint signature
* Session-bound MAC
* Invitation or introduction credential
* Destination-generated route proof

The lookup profile defines which proof the requester requires.

Forwarders MUST NOT remove or alter final-responder authentication.

---

# 17. Reverse-path state

Nodes create bounded reverse state when they propagate a request.

Reverse state maps:

```text
Request identity
Downstream peer that received request
Upstream peer or local requester
Expiry
Response budget
Privacy policy
```

A response travels toward the requester through this state.

The forwarder MUST send a response only to an upstream peer that supplied an admitted copy of the matching request.

The forwarder MUST NOT expose the full reverse path to the responder.

Reverse state expires with the request. A late response is discarded unless another authenticated return mechanism applies.

---

# 18. Response forwarding

A forwarder validates:

1. Enclosing peer authentication.
2. Request ID and reverse-state match.
3. Response sequence and replay state.
4. Lifetime and field limits.
5. Final-responder authentication when the profile permits local verification.
6. Route flags and metadata consistency.
7. Local privacy and route policy.

The forwarder may append a hop authentication record or wrap the response in hop-specific protected metadata.

It MUST NOT change final-responder fields covered by authentication.

The forwarder shortens lifetime to reflect elapsed time and its own route evidence.

Each reverse-state entry MUST cap forwarded responses. Default cap is eight responses per request branch.

---

# 19. Response validation by requester

The requester MUST validate:

* Request ID
* Destination hint binding
* Required final-responder proof
* Response sequence
* Route lifetime
* Required scope and flags
* Path exclusions
* Hop and relay limits
* Carrier and policy constraints
* Metadata bounds

The requester MUST treat an authenticated response as a claim until path construction and session authentication succeed.

It SHOULD retain the peer chain or protected hop attestations needed to attribute a failed claim without exposing them to applications.

A response that lacks required proof may remain a low-trust candidate only when local policy permits opportunistic probing. It MUST NOT bypass endpoint authentication.

---

# 20. Route construction

A route response may describe:

## 20.1 Direct path

The requester already has or can establish an adjacent link to the destination.

It dials the candidate, performs the UMP handshake, and validates the resulting session path.

## 20.2 Single-relay path

The requester reaches one relay that can forward toward the destination.

The requester asks the relay layer to open a circuit. Relay authorization and quota checks occur before the path becomes usable.

## 20.3 Multi-hop relay path

Each hop opens or extends a relay circuit according to `relay.md`.

The requester MUST enforce maximum hop and relay counts. Default maximum for GENERAL scope is eight hops, with no more than four relays in stable v0.1 policy.

## 20.4 Mixed path

A route may combine local and non-local carriers or direct and relayed legs.

Each leg must satisfy request policy. A `LOCAL_SCOPE_ONLY` request cannot produce a mixed path containing a non-local leg.

## 20.5 Path validation

After construction, the session layer validates end-to-end reachability under `session.md`.

A route becomes `USABLE` only after required link, relay, handshake, and path checks succeed.

---

# 21. Multi-hop path representation

UMP/1 routing implementations MUST represent a constructed path as an ordered list of local route legs.

Each leg contains:

```text
Adjacent peer handle
Carrier or relay handle
Temporary next-hop identifier
Authorization scope
Expiry
MTU contribution
Cost and failure-domain tags
```

Nodes SHOULD expose only the next required leg to each relay.

The requester MAY know the complete route when route construction requires it. UMP/1 does not promise onion-style path hiding.

A route with hidden segments MUST still provide enough authenticated information to enforce the requester's hop, carrier, and policy limits. Profiles that cannot prove those limits must disclose the uncertainty to local policy.

---

# 22. Route scoring

Implementations may use different scoring algorithms. They MUST enforce hard policy constraints before ranking.

## 22.1 Hard constraints

Hard constraints may include:

* Required destination authentication
* Allowed carriers
* Maximum hops and relays
* Trust threshold
* Local-only scope
* Cost ceiling
* Path exclusions
* Relay and delayed-delivery permission
* Minimum MTU

A candidate that violates a hard constraint is ineligible.

## 22.2 Ranking inputs

Eligible routes may use:

```text
Freshness
Previous success
Failure recency
Estimated latency
Estimated loss
Estimated bandwidth
Carrier cost
Energy cost
Relay count
Trust context
Path and carrier diversity
Censorship or filtering risk
Shared failure domains
```

Remote metric claims MUST receive less weight than local observations.

## 22.3 Stable comparison

A strategy SHOULD produce stable rankings for unchanged inputs. It MAY add bounded randomness among near-equal routes to avoid herd behavior and improve diversity.

## 22.4 First-party strategies

The accepted project decisions define these compiled strategies:

```text
balanced
low-latency
low-bandwidth
local-first
high-diversity
restricted-network
```

Applications provide constraints and preferences. They do not supply executable scoring code.

---

# 23. Route diversity

The routing engine SHOULD retain more than one eligible route when resources permit.

Two routes count as diverse when they differ in one or more meaningful failure domains:

* First-hop peer
* Relay operator or trust domain
* Carrier type
* Network prefix or local segment
* Introduction source
* Geographic or administrative tag supplied by local policy

Self-asserted diversity tags from untrusted peers do not prove independence.

The engine SHOULD avoid selecting backups that share every known relay or carrier with the primary route.

Default cache target is three eligible routes per destination and policy class.

---

# 24. Route cache

The route cache stores bounded, expiring candidates.

A cache key includes:

```text
Destination hint profile and hash
Request scope
Policy class
Local endpoint or identity partition
```

The cache MUST NOT share private routes across local endpoints or applications when policy forbids it.

Each entry records:

```text
Next hop
Route metadata
Proof status
Source peer
Creation and expiry
Last probe
Last success
Last failure
Failure count
Sharing policy
```

## 24.1 Admission

The node caches only responses that pass structural, authentication, and policy checks.

It MAY cache an unproven candidate for probing, marked as such. It MUST NOT export that candidate as verified reachability.

## 24.2 Expiry

An entry expires at the earliest of:

* Advertised route lifetime
* Underlying peer or carrier hint expiry
* Relay authorization expiry
* Revocation or trust-policy invalidation
* Local maximum lifetime

## 24.3 Refresh

The node may refresh a route before expiry when an application needs continuity. Refresh uses a new Request ID and must pass current policy.

## 24.4 Eviction

The cache evicts:

1. Expired entries.
2. Invalidated entries.
3. Failed low-trust entries.
4. Redundant entries from the same failure domain.
5. Least useful remaining entries under the active strategy.

Eviction MUST preserve per-destination and per-source bounds.

---

# 25. Route persistence

An implementation MAY persist route cache metadata.

After restart, every persisted route begins as `CANDIDATE`. The node MUST revalidate live next-hop and authorization state before use.

The storage layer MUST separate:

* Private routing hints
* Public bootstrap data
* Trust records
* Failure history

Persisted failure penalties SHOULD decay. A stale failure must not block rediscovery forever.

The node MUST purge routes affected by revocation, blocked peers, removed carriers, or incompatible protocol versions.

---

# 26. Route failure

A route may fail during dialing, relay construction, handshake, path validation, or active use.

The layer that observes failure reports:

```text
Route identifier
Failed leg
Failure class
Time
Retry guidance
Authenticated evidence, if any
```

Failure classes include:

```text
NO_REACHABILITY
CARRIER_FAILURE
RELAY_REFUSED
AUTHENTICATION_FAILED
POLICY_REJECTED
TIMEOUT
LOOP
RESOURCE_LIMIT
PROTOCOL_ERROR
```

The router MUST distinguish local failure from remote claims. A remote `ROUTE_ERROR` is evidence from its authenticated sender, not proof of the stated cause.

## 26.1 Penalties

The engine SHOULD penalize failed route and failure domain for a bounded period.

Recommended initial retry delays:

```text
Transient carrier failure: 1 second
Timeout: 5 seconds
Relay refusal: 30 seconds
Policy rejection: until policy or authorization changes
Authentication failure: until identity or trust state changes
```

Repeated transient failures use capped exponential backoff with jitter.

## 26.2 Alternate route

The engine SHOULD try an eligible diverse route after failure. It MUST obey application deadlines and resource limits.

An active session may migrate to a validated backup under `session.md`.

## 26.3 Failure propagation

A node MAY send `ROUTE_ERROR` toward the requester while reverse state exists.

It MUST minimize diagnostics and avoid disclosing unrelated topology.

---

# 27. ROUTE_ERROR semantics

`ROUTE_ERROR` contains:

```text
Request ID
Error Code
Failed-Hop Index
Diagnostic
```

The frame MUST use a critical length-delimited frame type in the frozen UMP/1 registry.

Failed-Hop Index uses zero for the first route leg known to the sender. A sender that cannot disclose or determine the leg uses the maximum varint value as `UNKNOWN` in the finalized encoding.

Diagnostics are untrusted UTF-8 and MUST remain within the wire-format limit. Senders SHOULD omit them across private or unauthenticated routing contexts.

An error affects one request branch unless authenticated evidence ties it to other candidates.

Recommended mappings:

| Condition | Error code |
| --- | --- |
| No eligible next hop | `ROUTE_NOT_FOUND` |
| Duplicate path or accumulator match | `ROUTE_LOOP` |
| Relay denied circuit | `RELAY_REFUSED` |
| Quota prevented processing | `RESOURCE_LIMIT` |
| Request expired | `EXPIRED` |
| Local policy denied request | `POLICY_REJECTED` |
| Carrier failed during construction | `CARRIER_FAILURE` |

---

# 28. Local versus non-local routing

Local routing favors direct and local-carrier reachability. It does not weaken endpoint authentication.

A local route may use:

* LAN-discovered peers
* Bluetooth or local radio peers
* Static peers on a private segment
* Local relay nodes

A node MUST NOT infer trust from local presence, private IP space, SSID, Bluetooth name, or link-layer address.

`LOCAL_SCOPE_ONLY` requests must stay on links that local policy marks as local. A forwarder must not bridge them onto general-scope paths.

A node bridging two local segments acts as a router or relay and must enforce hop, disclosure, and authorization policy.

General routing may include public bootstrap and internet peers. It remains bounded by request fanout and scope.

---

# 29. Privacy boundaries

## 29.1 Adjacent peers

An adjacent peer may observe:

* That a routing request occurred
* Request timing and size
* Request ID
* Hop limit and flags
* Destination hint bytes available to its lookup profile
* The previous and next adjacent peer for branches it forwards

## 29.2 Forwarders

A forwarder should learn only the information required to select next hops and return responses.

It MUST NOT disclose:

* Complete peer tables
* Private peer hints outside sharing policy
* Other request branches
* Unrelated destination or service state
* Local trust scores

## 29.3 Responder

The responder may learn a requester-scoped return token or authorization proof. `REQUIRE_PRIVATE_RESPONSE` should keep the requester's direct address and full reverse path hidden.

## 29.4 Requester

The requester may learn candidate next hops and route metadata. UMP/1 does not guarantee full-path disclosure or full-path hiding.

## 29.5 Applications

Applications receive policy-relevant route attributes and path events. They SHOULD NOT receive raw peer tables, private topology, or relay identities without permission.

---

# 30. Enumeration resistance

A node MUST NOT answer broad queries with its peer list.

Destination hints must target a bounded endpoint, service, gateway class, or lookup partition.

A node MUST rate-limit:

* Distinct destination hints per peer
* Failed lookups
* Gateway queries
* Requests that expand fanout
* Requests using unauthenticated authorization

A node SHOULD return the minimum response set needed for path construction.

Private and `DO_NOT_RESHARE` peer hints remain unavailable unless an authenticated policy grants disclosure for this request.

Repeated probing across a hint space may trigger silent drops, scope reduction, or peer restriction.

---

# 31. Malicious route advertisements

Route responses and peer hints are claims from authenticated senders.

A malicious peer may:

* Advertise nonexistent destinations
* Understate cost or latency
* Claim false diversity
* Create loops
* Return routes through colluding nodes
* Suppress good responses
* Redirect traffic toward observation points

Nodes defend through:

* End-to-end endpoint authentication
* Path validation
* Short route lifetimes
* Local performance observations
* Source attribution
* Route diversity
* Failure penalties
* Trust and sharing policy

A node MUST NOT promote endpoint trust because a route succeeds.

An invalid route proof, authenticated contradiction, or repeated false claim SHOULD reduce the sender's routing trust. Local policy decides whether to restrict or block it.

---

# 32. Sybil and eclipse resistance

UMP cannot prevent creation of cryptographic identities at low cost.

The router SHOULD limit influence by:

* Per-source and per-introduction quotas
* Failure-domain diversity
* Preference for prior successful peers
* Bounded peer-table slots for new identities
* Separation of trust from identity count
* Multiple discovery providers
* Local and private peer retention

Ten identities introduced by one untrusted source must not count as ten independent trust domains.

The router SHOULD reserve peer and route capacity for trusted, local, and previously successful paths so a burst of new peers cannot evict them.

---

# 33. Route poisoning and contradiction

A node MUST track the authenticated source of cached route evidence.

When two claims conflict, the node considers:

* Direct observation
* Cryptographic proof
* Freshness
* Trust context
* Independent corroboration

Direct authenticated reachability outweighs an indirect failure claim.

The node MUST NOT merge incompatible route metadata into one candidate.

It MAY retain conflicting candidates as separate records and probe them under resource limits.

A responder cannot revoke another responder's route without proof recognized by the destination or local trust policy.

---

# 34. Routing authorization

Nodes apply local policy to each routing action.

Policy may control:

* Who may ask for routes
* Which scopes a peer may use
* Which destinations or services it may query
* Request fanout and frequency
* Private hint disclosure
* Relay and gateway advertisement
* Cache sharing

Unknown or Observed peers SHOULD receive low request rates and no private peer data.

Introduced peers receive only the scope granted by the introduction.

Trusted status does not override destination, relay, or carrier policy.

Blocked or Revoked peers cannot originate or forward routing messages except a minimal error required to end existing state.

---

# 35. Routing and trust state

Routing uses trust as one input.

The accepted trust states have these default effects:

| Trust state | Default routing behavior |
| --- | --- |
| `Unknown` | Reject or admit under strict public-query limits |
| `Observed` | Permit bounded public requests; no private hints |
| `Introduced` | Permit granted scopes until introduction expiry |
| `Trusted` | Permit configured scopes and higher quotas |
| `Restricted` | Apply explicit reduced scopes and rates |
| `Blocked` | Reject routing traffic |
| `Revoked` | Reject and invalidate affected cached evidence |

Implementations MAY use stricter defaults.

An introduction provides context and scope. It does not prove route quality or endpoint behavior.

---

# 36. Route discovery retries

The requester starts with a narrow, low-cost search and may expand within policy.

Recommended stages:

```text
1. Existing direct and cached routes
2. Local and introduced peers
3. Diverse general peers
4. Wider hop limit or alternate hint profile
```

Each stage uses a new Request ID when it changes scope, authorization, destination hint, or Hop Limit in a way that alters request identity.

Retransmission to the same peer may retain Request ID. The requester SHOULD retry no more than twice per peer.

The requester stops when:

* A route satisfies policy and path construction succeeds
* Application deadline expires
* Request budget is exhausted
* Local cancellation occurs
* Policy forbids further expansion

---

# 37. Route cancellation

UMP/1 does not define a mandatory route-cancel frame.

Requesters stop local work and let reverse state expire. Forwarders may stop branches after producing enough responses or reaching resource limits.

A future optional length-delimited frame may add cancellation. It must authenticate Request ID and prevent one branch from cancelling unrelated branches.

Nodes MUST keep request lifetimes short enough that absent cancellation cannot retain substantial state.

---

# 38. Interaction with discovery

Discovery provides peer candidates and scoped hints. Routing decides whether to use them for a destination.

A discovery hint MUST carry:

* Source
* Freshness or expiry
* Sharing policy
* Carrier context
* Authentication status

The router MUST preserve these attributes.

Discovery conflicts do not establish routing truth. The router may probe several candidates and record outcomes.

Routing MUST NOT trigger unbounded discovery. One route request receives a fixed discovery budget under local policy.

---

# 39. Interaction with relay

A route marked `RELAY_REQUIRED` supplies candidate relay steps.

The relay layer decides:

* Circuit authorization
* Quotas
* Lifetime
* Next-hop forwarding
* Circuit failure

The routing layer does not treat a relay advertisement as reserved capacity.

A route lifetime cannot exceed the shortest relay circuit or authorization lifetime after construction.

Relay refusal affects that route branch. It does not prove the destination unreachable.

---

# 40. Interaction with sessions

The router returns ranked path candidates to the session manager.

The session manager:

* Performs endpoint handshake when needed
* Validates paths
* Maintains connection IDs
* Migrates active sessions
* Reports path outcomes

The router uses those outcomes to update cache and scores.

A valid route response cannot replace endpoint authentication. A successful handshake may invalidate route claims about destination identity.

---

# 41. Interaction with bundles

`ALLOW_STORE_FORWARD` and `STORE_FORWARD_AVAILABLE` signal delayed-delivery capability.

UMP/1 live routing keeps delayed-delivery candidates separate from live routes.

The bundle specification will define custody, replication, intermittent contact, and bundle-specific route selection.

The routing engine MAY provide contact hints to the bundle subsystem. It MUST NOT apply live-route success semantics to a stored bundle handoff.

---

# 42. Resource limits

Every node MUST bound routing work by peer, request origin, destination partition, and global budget.

Recommended defaults:

| Resource | Default |
| --- | ---: |
| Hop Limit | 8 |
| Maximum Hop Limit | 32 |
| Forward fanout | 3 |
| Maximum stable-profile fanout | 8 |
| Concurrent logical requests per destination | 2 |
| Responses per request branch | 8 |
| Path exclusions | 32 |
| Request lifetime | 30 seconds |
| Maximum accepted request lifetime | 5 minutes |
| Cached candidates per destination and policy class | 8 |
| Target diverse candidates | 3 |
| Recent request IDs per peer | 4,096 |
| Route requests per Observed peer | 10 per minute |
| Concurrent admitted requests per peer | 16 |

Deployments MAY lower these values. Higher values require explicit configuration and resource analysis.

When limits are reached, the node may:

* Drop low-trust requests
* Reduce fanout
* Return `RESOURCE_LIMIT`
* Evict expired reverse state
* Delay admitted work within request lifetime

It MUST NOT evict active session paths to process an unauthenticated route request.

---

# 43. Fairness

The routing scheduler MUST prevent one peer, destination partition, application, or trust class from consuming the full routing budget.

It SHOULD reserve capacity for:

* Active-session recovery
* Local mesh routing
* Trusted administrative probes
* New low-rate peers

Reserved capacity must remain bounded. A priority class cannot bypass global safety limits.

The node SHOULD charge forwarded work to both adjacent sender and authenticated requester scope when available.

---

# 44. Error handling

A node closes the UMP session only for routing-frame encoding errors, invalid authenticated state transitions, or sustained abuse that session policy treats as fatal.

Normal routing failures use `ROUTE_ERROR`, silent branch failure, or local timeout.

| Condition | Response |
| --- | --- |
| Malformed frame | Close with `FRAME_ENCODING_ERROR` |
| Invalid critical flag or field combination | Close with `PROTOCOL_VIOLATION` |
| Duplicate request | Suppress |
| Hop Limit exhausted | Drop or send `ROUTE_NOT_FOUND` |
| Loop detected | Drop branch; optional `ROUTE_LOOP` |
| No eligible next hop | Optional `ROUTE_NOT_FOUND` |
| Request rate exceeded | Drop or `RESOURCE_LIMIT` |
| Authorization denied | Drop or `POLICY_REJECTED` |
| Invalid final proof | Discard response; record sender evidence |
| Expired request or response | Discard |

Detailed errors SHOULD stay within trusted relationships. Private-routing profiles may require silent failure.

---

# 45. Logging and diagnostics

Default logs MUST NOT contain:

* Full private destination hints
* Requester authentication tokens
* Private next-hop hints
* Complete paths
* Private peer identities
* Application protocol metadata

Logs may contain:

* Short request hash
* Scope
* Hop count
* Outcome class
* Coarse latency
* Redacted next-hop handle
* Resource-limit event

Metrics SHOULD include:

```text
Requests admitted, forwarded, suppressed, and rejected
Responses accepted and rejected
Route construction success by class
Time to first candidate
Time to usable path
Failure classes
Cache hit rate
Route diversity
Per-scope resource use
```

Diagnostics must distinguish local observation from a remote claim.

---

# 46. Persistence and privacy

Persistent routing records contain sensitive relationship data.

The storage layer MUST:

* Partition private records by local identity and policy
* Encrypt sensitive metadata at rest when platform support exists
* Expire request and reverse-path state
* Avoid persisting requester authorization secrets unless required
* Support deletion after trust revocation or peer removal

Metrics and backups must not recreate a permanent global topology log by default.

---

# 47. Security considerations

## 47.1 Flooding

Attackers can vary Request IDs and destination hints to defeat simple duplicate caches. Nodes must combine per-peer, per-requester, destination-partition, and global rate limits.

## 47.2 Amplification

A small request can trigger fanout and many responses. Forwarders cap fanout, lifetime, response count, and total bytes. They should require stronger authorization for wider scope.

## 47.3 Route capture

Malicious nodes may steer traffic through themselves. Endpoints use diverse peers, short-lived routes, direct observations, and end-to-end authentication.

## 47.4 Topology disclosure

Requests and responses expose relationship data. Nodes share one next-hop hint per route need, retain reverse state, and enforce private-peer restrictions.

## 47.5 Timing correlation

An observer controlling several hops may correlate requests and responses. UMP/1 provides no full defense. Private carriers may add batching, delays, or cover behavior.

## 47.6 Destination probing

Attackers may enumerate destination hints. Rotating tokens, authorization proofs, rate limits, and silent failures reduce exposure. Public service profiles may choose discoverability.

## 47.7 Stale routes

Attackers may replay old authenticated responses. Request binding, response sequences, short lifetimes, and path validation prevent stale claims from becoming trusted live paths.

---

# 48. Required tests

A compliant implementation MUST test:

1. Request creation and field validation.
2. Hop-limit decrement and exhaustion.
3. Lifetime reduction across hops.
4. Duplicate suppression from same and different peers.
5. Loop detection without a plaintext full path.
6. Fanout and response-budget enforcement.
7. Scope reduction and local-only containment.
8. Requester authorization before costly work.
9. Response sequence conflict handling.
10. Final-responder proof validation.
11. Reverse-state creation, use, and expiry.
12. Direct, single-relay, and multi-hop construction.
13. Hard policy filtering before scoring.
14. Route diversity selection.
15. Cache expiry, refresh, and eviction.
16. Failure penalties and alternate route selection.
17. Malicious metric and false-route claims.
18. Sybil peers from one introduction source.
19. Private peer and destination-hint non-disclosure.
20. Restart with persisted candidates requiring revalidation.
21. Memory and CPU bounds under request floods.
22. Concurrent discovery for many destinations.

Property tests SHOULD verify:

```text
Hop Limit never increases.
Scope never broadens during forwarding.
No request returns to the same peer branch.
No response escapes matching reverse state without another authenticated return method.
Route expiry never exceeds underlying evidence expiry.
Ineligible routes never enter scoring.
One peer cannot exceed its routing quota through many endpoint identities on one session.
```

---

# 49. Interoperability requirements

A minimal UMP/1 routing implementation MUST support:

* Critical length-delimited `ROUTE_REQUEST`
* Critical length-delimited `ROUTE_RESPONSE`
* Critical length-delimited `ROUTE_ERROR`
* Unpredictable Request IDs
* Hop limits
* Relative request and route expiry
* Duplicate suppression
* Reverse-path response forwarding
* Direct route discovery
* Single-relay route discovery
* Multi-hop request propagation
* Final-responder authentication profile
* Local and GENERAL scopes
* Bounded cache and routing state
* Policy filtering
* Path construction handoff

An implementation MAY defer:

* Privacy-preserving path accumulators
* Distributed hash routing
* Hidden multi-hop route segments
* Gateway queries
* Bundle-route integration
* Dynamic external routing strategies

An implementation MUST NOT advertise a deferred capability.

---

# 50. Open design decisions

The project must resolve these items before freezing UMP/1 interoperability:

1. Exact frame-type values for length-delimited routing frames.
2. Request ID byte length and wire encoding.
3. Endpoint routing-token construction.
4. Destination-hint profile negotiation.
5. Requester Auth formats for public, introduced, and private routing.
6. Final-responder authentication format.
7. Route Metadata canonical encoding.
8. Path Exclusion entry encoding and criticality.
9. Whether Response Sequence starts at zero or one.
10. Exact `UNKNOWN` Failed-Hop Index encoding.
11. Whether route responses carry protected hop attestations.
12. Whether UMP/1 requires path accumulators.
13. Whether the requester may learn a complete multi-hop path.
14. Default maximum relay count.
15. Default maximum cache lifetime.
16. Whether GENERAL requests may cross private peer relationships.
17. Exact local-link classification rules.
18. Whether route cancellation enters UMP/1.
19. Routing error codes that need dedicated registry values.
20. Required scoring behavior for near-equal routes.

---

# 51. Recommended implementation order

Implement routing in this order:

1. Route types and bounded stores.
2. Request ID generation.
3. `ROUTE_REQUEST` parser and validator.
4. Duplicate and replay cache.
5. Hop limit, expiry, and scope enforcement.
6. Direct destination matching.
7. Reverse-path state.
8. `ROUTE_RESPONSE` creation and validation.
9. Bounded request propagation.
10. Route cache.
11. Policy filtering and simple ranking.
12. Direct path construction.
13. Single-relay construction.
14. Route failure and retry.
15. Multi-hop construction.
16. Diversity strategies.
17. Persistence.
18. Adversarial simulation and fuzzing.

---

# 52. Core rule

UMP routing discovers bounded, expiring path candidates from partial peer knowledge.

Each node authenticates adjacent senders, limits propagation, preserves request scope, and treats remote route data as claims. The requester validates destination binding and policy before path construction. Session authentication and path validation decide whether a candidate becomes usable.
