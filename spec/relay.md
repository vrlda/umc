# Universal Mesh Protocol Relay Specification

**Status:** Draft
**Version:** 0.1
**Document:** Relay Circuits and Forwarding
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines how UMP nodes establish, operate, and close relay circuits.

It specifies:

* Relay roles
* Circuit identifiers and lifecycle
* Circuit establishment
* Authorization and quotas
* Forwarding behavior
* Relay sequencing
* Backpressure and fairness
* Circuit expiry and failure
* Multi-hop circuit construction
* End-to-end encryption requirements
* Metadata visible to each relay
* Abuse controls
* Relay errors and diagnostics

The routing specification discovers candidate relay paths. The session specification manages end-to-end transport and path migration. The wire-format specification encodes relay frames.

This document does not define:

* Route discovery
* Carrier framing
* Application authorization at the destination
* Internet exit, VPN, DNS, or HTTP gateway behavior
* Bundle custody or persistent relay storage
* Payments or relay incentives

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

Relay frames travel inside authenticated UMP sessions between adjacent nodes. Each relay authenticates its adjacent peers. The inner endpoint session provides end-to-end authentication and encryption.

---

# 3. Relay goals

UMP relaying must provide bounded forwarding through nodes that endpoints do not need to trust with application plaintext.

The relay layer MUST support:

1. Single-relay circuits.
2. Multi-hop circuits.
3. Per-circuit authorization.
4. Byte, time, and concurrency quotas.
5. Opaque inner traffic.
6. Circuit failure reporting.
7. Backpressure to the circuit originator.
8. Fair scheduling among peers and circuits.
9. Path replacement without changing endpoint identity.

Relays may observe adjacent peers, timing, sizes, circuit identifiers, and traffic volume. UMP/1 does not provide metadata blindness or full path anonymity.

---

# 4. Terminology

## 4.1 Relay node

A relay node forwards opaque bytes between two adjacent UMP relationships under local policy.

## 4.2 Circuit originator

The originator requests the first relay circuit leg.

## 4.3 Upstream peer

The upstream peer sends a circuit request or relay data to the current relay.

## 4.4 Downstream peer

The downstream peer receives forwarded circuit data from the current relay.

## 4.5 Circuit leg

A circuit leg is one directional relay allocation between adjacent peers.

## 4.6 Relay circuit

A relay circuit is the paired forwarding state that connects one upstream leg to one downstream leg.

## 4.7 Multi-hop circuit

A multi-hop circuit joins relay circuits across two or more relay nodes.

## 4.8 Inner traffic

Inner traffic consists of bytes produced by the end-to-end UMP session or a nested relay construction message.

---

# 5. Security boundary

A relay belongs outside the end-to-end endpoint trust boundary.

The relay may access:

* Its adjacent peer identities or session handles
* Local circuit identifiers
* Requested and granted quotas
* Next-hop hint needed for its leg
* Relay frame sizes and timing
* Per-direction byte and sequence counters
* Local policy and authorization result

The relay MUST NOT require:

* Endpoint private keys
* End-to-end session traffic keys
* Application plaintext
* Full endpoint trust databases
* The complete multi-hop path

A relay MUST treat `RELAY_DATA` bytes as opaque unless it is also an endpoint of the encapsulated protocol.

---

# 6. Relay operating policy

Public relaying is disabled by default.

The accepted project presets are:

```text
DISABLED
FRIENDS_ONLY
COMMUNITY
PUBLIC
```

## 6.1 DISABLED

The node rejects remote relay requests. It may still originate circuits for local applications.

## 6.2 FRIENDS_ONLY

The node accepts requests from Trusted endpoints, explicit allow-list entries, and valid scoped invitations.

## 6.3 COMMUNITY

The node may accept Introduced endpoints under lower quotas and constrained destinations.

## 6.4 PUBLIC

The operator enables public relay service and sets explicit limits. Unknown and Observed peers remain subject to strict admission and abuse controls.

No preset overrides destination, carrier, legal, cost, or emergency-shutdown policy.

---

# 7. Relay capabilities

A relay advertises capabilities through authenticated routing metadata or a negotiated capability frame.

Capabilities may include:

```text
Relay protocol version
Maximum circuit lifetime
Maximum byte quota
Maximum concurrent circuits per peer
Supported next-hop carrier classes
Bidirectional support
Multi-hop extension support
Private-circuit support
Store-forward support
Maximum relay frame payload
```

An advertisement reports limits and availability. It does not reserve resources or authorize use.

A relay SHOULD avoid public advertisements when policy restricts service to private peers.

---

# 8. Circuit identifiers

Relay Circuit IDs are scoped to one adjacent authenticated session.

The upstream peer selects an identifier for the circuit request. The relay maps it to its local circuit state and, when needed, to a different identifier on the downstream session.

A Circuit ID MUST:

* Be an unsigned canonical varint
* Be unpredictable within the adjacent session
* Remain unique among live and draining circuits on that session
* Avoid endpoint IDs, addresses, route IDs, or timestamps

The originator SHOULD generate Circuit IDs with at least 62 bits from a cryptographic random source, restricted to the UMP varint range.

A node MUST NOT reuse a Circuit ID until the previous circuit leaves `DRAINING` and its replay-retention period expires.

Circuit IDs have no meaning outside one adjacent session.

---

# 9. Circuit state machine

Each circuit uses these states:

```text
OPENING
ACTIVE
HALF_CLOSED_UPSTREAM
HALF_CLOSED_DOWNSTREAM
CLOSING
DRAINING
CLOSED
```

## 9.1 OPENING

The relay validates authorization, quotas, destination scope, and next-hop reachability.

It MUST NOT forward application bytes until it accepts the circuit.

## 9.2 ACTIVE

Both directions may carry `RELAY_DATA` within granted quotas.

## 9.3 HALF_CLOSED_UPSTREAM

The upstream direction sent `FIN`. Downstream-to-upstream data may continue.

## 9.4 HALF_CLOSED_DOWNSTREAM

The downstream direction sent `FIN`. Upstream-to-downstream data may continue.

## 9.5 CLOSING

One side sent `RELAY_CLOSE`, policy revoked the circuit, or a permanent failure occurred.

The relay stops accepting new data and sends close notifications to both adjacent sides when possible.

## 9.6 DRAINING

The relay retains enough state to reject late data, suppress duplicate close frames, and map final errors.

The draining period is:

```text
max(3 * adjacent-session PTO, 1 second)
```

Local policy MAY cap it at 30 seconds.

## 9.7 CLOSED

The relay releases forwarding and queue state. It may retain compact abuse and accounting records under privacy policy.

---

# 10. Relay frame registry

UMP/1 uses:

| Frame | Purpose |
| --- | --- |
| `RELAY_OPEN` | Request a circuit or downstream leg |
| `RELAY_STATUS` | Accept, reject, or update circuit state |
| `RELAY_DATA` | Carry opaque circuit bytes |
| `RELAY_CLOSE` | Close a circuit direction or whole circuit |

The existing wire-format draft defines `RELAY_OPEN`, `RELAY_DATA`, and `RELAY_CLOSE`.

UMP/1 also requires a critical length-delimited `RELAY_STATUS` frame. Its provisional frame type is:

```text
0x82
```

The wire-format registry MUST add `RELAY_STATUS` before interoperability freeze.

Unknown critical relay frames close the adjacent UMP session with `UNSUPPORTED_FRAME` or `PROTOCOL_VIOLATION` according to parsing state.

---

# 11. RELAY_OPEN request

`RELAY_OPEN` contains:

```text
Relay Circuit ID
Flags
Requested Lifetime
Requested Byte Quota
Next-Hop Hint
Authorization
```

The frame MUST use a critical length-delimited encoding in the frozen UMP/1 registry.

## 11.1 Flags

UMP/1 defines:

```text
BIDIRECTIONAL
STORE_FORWARD_ALLOWED
PRIVATE_CIRCUIT
MULTIPATH_ALLOWED
```

Unknown critical flag bits cause rejection with `UNSUPPORTED_FLAGS` through `RELAY_STATUS`.

`BIDIRECTIONAL` requests data flow in both directions. A circuit without this flag carries upstream-to-downstream data and downstream control only.

`STORE_FORWARD_ALLOWED` permits the relay to offer a delayed-delivery mode. It does not authorize storage by itself. Stable live circuits MUST NOT store data after disconnection.

`PRIVATE_CIRCUIT` restricts disclosure, logging, and next-hop selection under an authorization profile.

`MULTIPATH_ALLOWED` permits the relay to use more than one downstream path for this circuit. It does not permit duplicate billing or quota accounting.

## 11.2 Requested lifetime

Requested Lifetime is a relative duration in milliseconds.

The value MUST be at least 1 second and no more than 24 hours. A relay MAY grant less.

Recommended defaults:

```text
Requested lifetime: 10 minutes
Maximum public grant: 30 minutes
Maximum trusted grant: local policy, capped at 24 hours
```

## 11.3 Requested byte quota

Requested Byte Quota limits total forwarded `RELAY_DATA` payload bytes in both directions unless the authorization profile defines separate directional quotas.

The relay MAY grant less. A zero request means the originator accepts the relay's policy default.

Quota accounting counts payload bytes once per accepted `RELAY_DATA` frame. Outer UMP retransmissions do not consume extra circuit quota. A new `RELAY_DATA` frame carrying duplicate inner bytes does consume quota because the relay cannot identify inner duplication.

## 11.4 Next-hop hint

Next-Hop Hint identifies the destination for this relay leg. It may reference:

* An adjacent peer session
* A scoped peer candidate
* A downstream relay offer
* A private rendezvous token
* A local endpoint on the relay node

The relay treats the hint as untrusted input and enforces field, dialing, scope, and policy limits before use.

The hint MUST disclose no more path information than the current relay needs.

## 11.5 Authorization

Authorization may contain:

* A scoped invitation proof
* An introduction credential
* A relay access token
* A local account or capability token bound to the adjacent session
* A public-service proof-of-work extension

The authorization profile MUST bind:

```text
Adjacent requester identity or session
Relay Circuit ID
Requested destination scope
Maximum lifetime
Maximum byte quota
Expiry
Nonce or replay identifier
```

The relay MUST validate authorization before dialing the next hop or allocating large buffers.

---

# 12. RELAY_STATUS frame

`RELAY_STATUS` provides an explicit result for opening and operating a circuit.

Its body is:

```text
Relay Circuit ID
Status Sequence
Status Code
Flags
Granted Lifetime
Granted Byte Quota
Maximum Relay Payload
Diagnostic Length
Diagnostic
Authentication Length
Authentication
```

All integer fields use canonical varints. Diagnostic and Authentication use length-prefixed byte strings.

Limits:

```text
Diagnostic Length <= 256 bytes
Authentication Length <= 1,024 bytes
```

## 12.1 Status sequence

The relay starts Status Sequence at zero and increases it for each state-changing status.

A recipient ignores an older sequence. It accepts an exact duplicate only when all bytes match.

Conflicting status bytes at one sequence cause `PROTOCOL_VIOLATION` on the adjacent session.

## 12.2 Status codes

UMP/1 defines:

| Code | Name | Meaning |
| ---: | --- | --- |
| `0` | `PENDING` | Admission or downstream construction continues |
| `1` | `ACCEPTED` | Circuit is active with granted limits |
| `2` | `REFUSED` | Policy refused the circuit |
| `3` | `NO_ROUTE` | Relay found no permitted next hop |
| `4` | `AUTH_FAILED` | Authorization failed |
| `5` | `RESOURCE_LIMIT` | Local quota prevented admission |
| `6` | `DESTINATION_REJECTED` | Downstream endpoint or relay rejected the leg |
| `7` | `DEGRADED` | Circuit remains active with impaired path |
| `8` | `QUOTA_WARNING` | Remaining quota crossed a warning threshold |
| `9` | `EXPIRING` | Circuit approaches its expiry |
| `10` | `CLOSED` | Circuit closed; no more data accepted |
| `11` | `UNSUPPORTED_FLAGS` | Request used unsupported relay flags |

## 12.3 Status flags

```text
BIDIRECTIONAL_GRANTED
PRIVATE_HANDLING_GRANTED
MULTIPATH_GRANTED
DOWNSTREAM_AUTHENTICATED
RETRYABLE
```

The relay MUST NOT set a grant flag for a capability it did not authorize.

## 12.4 Acceptance

`ACCEPTED` grants:

* Circuit lifetime from acceptance time
* Total byte quota
* Maximum `RELAY_DATA` payload
* Direction and privacy flags

The originator MUST enforce granted limits even if it requested more.

## 12.5 Authentication

The adjacent UMP session authenticates the status frame. Multi-hop construction MAY require Authentication to carry a downstream receipt or proof bound to the circuit construction transcript.

The relay MUST NOT expose downstream identities through Authentication unless route policy permits it.

---

# 13. Circuit opening procedure

The upstream peer opens a circuit through these steps:

1. Select an unused Circuit ID.
2. Validate route and local relay policy.
3. Send one `RELAY_OPEN`.
4. Start an open timeout.
5. Accept zero or more `PENDING` status frames.
6. Enter `ACTIVE` only after `ACCEPTED`.
7. Treat rejection, timeout, or adjacent-session failure as open failure.

The relay processes `RELAY_OPEN` through these steps:

1. Validate frame encoding and Circuit ID uniqueness.
2. Apply cheap rate and capacity checks.
3. Validate authorization.
4. Reserve bounded circuit state.
5. Resolve or validate the next-hop hint.
6. Establish the downstream leg when required.
7. Compute granted limits.
8. Send `ACCEPTED` or a terminal rejection.

The relay MAY send `PENDING` when downstream setup exceeds one adjacent-session PTO.

Default open timeout is:

```text
max(10 seconds, 3 * adjacent-session PTO)
```

Carrier and route policy MAY allow more, capped at the route request lifetime or 60 seconds for live UMP/1 circuits.

---

# 14. Duplicate RELAY_OPEN handling

A relay MUST handle duplicate open requests idempotently.

For the same adjacent session and Circuit ID:

* Identical `RELAY_OPEN` bytes receive the latest status again.
* Different bytes cause `PROTOCOL_VIOLATION`.
* A request received during `DRAINING` receives `CLOSED`.
* A request after replay-state expiry may create a new circuit only if the ID no longer conflicts with retained state.

The relay MUST NOT allocate another downstream leg for an identical duplicate.

---

# 15. Downstream leg establishment

The relay may satisfy Next-Hop Hint through:

* An active adjacent UMP session
* A new adjacent UMP session
* A local endpoint
* Another relay circuit

The relay applies routing and carrier policy before dialing.

A new downstream UMP session MUST authenticate before the relay forwards circuit data unless a private relay profile defines an authenticated pre-session tunnel.

The relay assigns a downstream Circuit ID when extending through another relay. It stores a private mapping:

```text
Upstream session and Circuit ID
Downstream session and Circuit ID
Direction mapping
Quota and expiry
```

It MUST NOT send the upstream Circuit ID unchanged when doing so would expose cross-hop correlation and a fresh downstream ID is available.

---

# 16. RELAY_DATA semantics

`RELAY_DATA` contains:

```text
Relay Circuit ID
Relay Sequence
Flags
Data Length
Data
```

## 16.1 Relay sequence

Each sender maintains an independent Relay Sequence per circuit direction.

The first sequence is zero. Each later `RELAY_DATA` frame increments it by one.

Sequence numbers MUST NOT reset during circuit lifetime, path migration, or adjacent-session key update.

The receiver uses Relay Sequence to:

* Reject exact duplicates
* Detect missing relay frames
* Attribute final close position

UMP/1 encodes Relay Sequence as a canonical varint up to `2^62 - 1`. Sequence exhaustion closes the circuit before wraparound.

## 16.2 Flags

UMP/1 defines:

```text
FIN
ACK_REQUESTED
HIGH_PRIORITY
```

Unknown critical bits close the circuit with `PROTOCOL_ERROR`.

`FIN` marks the final frame in one direction. Data may accompany FIN.

`ACK_REQUESTED` asks the adjacent session to acknowledge the containing packet without delay. It does not create end-to-end delivery proof.

`HIGH_PRIORITY` supplies a scheduling hint. The relay applies local priority and abuse policy.

## 16.3 Data

Data is opaque to the relay.

For an endpoint session transported through the circuit, Data contains one or more complete inner UMP packets under a circuit encapsulation profile.

UMP/1 live circuits MUST preserve inner packet boundaries. The default encapsulation is:

```text
Inner Packet Length: Varint
Inner Packet Bytes: Inner Packet Length bytes
```

One `RELAY_DATA` frame MAY contain several complete inner packets. An inner packet MUST NOT span multiple `RELAY_DATA` frames in the base profile.

The sender splits traffic at inner packet boundaries to fit granted Maximum Relay Payload.

## 16.4 Empty data

An empty `RELAY_DATA` frame is valid only with `FIN`. Other empty frames cause `PROTOCOL_VIOLATION` at the circuit scope.

---

# 17. Ordering and duplicates

The outer adjacent UMP session may deliver `RELAY_DATA` frames out of order across packets.

The relay MAY forward authenticated Data as it arrives. The inner endpoint session handles packet reordering and loss.

The relay MUST NOT hold later Relay Sequences without a fixed bound while waiting for a gap. It MAY reorder within its existing adjacent-session send queue when that does not delay traffic past local queue limits.

An exact duplicate sequence with identical flags and data is discarded.

A duplicate sequence with different bytes closes the circuit with `PROTOCOL_ERROR` and SHOULD increase the peer's abuse score.

A sequence gap does not close the circuit. The relay records it for diagnostics and continues forwarding later frames. Inner loss recovery decides whether to retransmit protected endpoint data.

---

# 18. Reliability model

Adjacent UMP sessions provide reliable delivery of retransmittable relay control frames.

`RELAY_DATA` is not retransmitted when the inner endpoint session supplies reliability. Loss of its outer packet appears as loss to the inner endpoint session, which retransmits protected endpoint information through a new inner packet.

The relay MUST retain an accepted frame until one of these conditions holds:

* The adjacent downstream session accepts ownership of it for transmission
* Circuit closure makes forwarding impossible
* The frame expires under a profile that permits expiry

Acceptance by the next adjacent session does not prove destination delivery.

Circuit control frames `RELAY_OPEN`, `RELAY_STATUS`, and `RELAY_CLOSE` are retransmittable until acknowledged or obsolete.

---

# 19. Backpressure

Backpressure must travel from downstream carrier and session queues to the circuit originator.

A relay MUST:

* Bound per-circuit queues
* Stop accepting more data when the downstream leg cannot accept it
* Avoid reading unbounded upstream relay payloads into memory
* Preserve control-frame capacity

The outer UMP session's stream or packet scheduler provides hop-by-hop backpressure. A relay implementation SHOULD expose circuit queue saturation to its adjacent session scheduler.

UMP/1 does not define a relay-window frame. The relay enforces a fixed queue grant derived from admission policy and Maximum Relay Payload.

Recommended defaults:

```text
Per-circuit queued payload: 256 KiB
Per-peer total relay queue: 2 MiB
Global relay queue: operator-configured hard limit
```

When a peer exceeds queue allowance, the relay pauses acceptance or closes the circuit with `RESOURCE_LIMIT`. It MUST NOT drop arbitrary bytes from an active ordered circuit and continue forwarding later bytes.

---

# 20. Quota accounting

Each circuit tracks:

```text
Granted lifetime
Accepted payload bytes upstream to downstream
Accepted payload bytes downstream to upstream
Queued bytes
Forwarded bytes
Dropped bytes before acceptance
Control-frame count
```

The relay charges quota when it accepts a new `RELAY_DATA` sequence, before queueing Data.

Duplicate outer retransmissions and exact duplicate relay sequences do not consume quota again.

The relay MUST reject a frame that would exceed the remaining byte quota. It closes with `QUOTA_EXHAUSTED` unless policy grants a renewal.

Quota renewal is outside base UMP/1. The originator opens a new circuit or uses a future authenticated extension.

A relay MAY send `QUOTA_WARNING` after 75 percent and 90 percent usage. Warning delivery does not extend quota.

---

# 21. Lifetime and idle limits

A circuit expires at the earliest of:

* Granted lifetime
* Authorization expiry
* Upstream session closure
* Downstream session closure without replacement
* Route or relay policy revocation
* Operator emergency shutdown deadline

Each relay also enforces an idle timeout.

Recommended default idle timeout is 2 minutes. It MUST NOT exceed granted lifetime.

Authenticated `RELAY_DATA` in either direction resets the circuit idle timer. `RELAY_STATUS` and `RELAY_CLOSE` do not keep an idle circuit alive.

The relay SHOULD send `EXPIRING` before planned lifetime expiry when time and policy permit.

At expiry, it sends `RELAY_CLOSE` with `EXPIRED` and enters `DRAINING`.

---

# 22. Half-close

`FIN` on `RELAY_DATA` declares the final Relay Sequence in one circuit direction.

The relay records and forwards FIN. During a drain window, it MAY accept missing lower sequences. It MUST reject any sequence above the final sequence.

Later data in the finished direction causes circuit-scoped `PROTOCOL_ERROR`.

A bidirectional circuit closes after:

* Both directions finish and queued data drains, or
* Either side sends `RELAY_CLOSE`, or
* Policy or failure terminates it

A unidirectional circuit closes after its data direction finishes and control state drains.

---

# 23. RELAY_CLOSE semantics

`RELAY_CLOSE` contains:

```text
Relay Circuit ID
Reason Code
Final Relay Sequence
```

The frame MUST use a critical length-delimited encoding in the frozen UMP/1 registry.

Final Relay Sequence identifies the last accepted sequence in the direction of the sender. If the sender accepted no data, it uses the maximum varint value as `NONE` in the finalized encoding.

The sender MUST send one stable reason and final sequence. A conflicting duplicate causes `PROTOCOL_VIOLATION` on the adjacent session.

The recipient stops sending new data and may process data through the declared final sequence when the reason permits draining.

The relay maps close to the paired leg. It MAY replace a sensitive downstream reason with a less detailed upstream reason.

---

# 24. Relay reason codes

UMP/1 requires circuit reason codes separate from transport errors:

| Code | Name | Meaning |
| ---: | --- | --- |
| `0` | `NO_ERROR` | Normal close |
| `1` | `REFUSED` | Admission denied |
| `2` | `AUTH_FAILED` | Authorization invalid or expired |
| `3` | `NO_ROUTE` | No permitted downstream route |
| `4` | `DOWNSTREAM_FAILED` | Downstream session or circuit failed |
| `5` | `UPSTREAM_FAILED` | Upstream session failed |
| `6` | `QUOTA_EXHAUSTED` | Byte quota reached |
| `7` | `EXPIRED` | Circuit lifetime ended |
| `8` | `IDLE_TIMEOUT` | Circuit idle limit ended |
| `9` | `RESOURCE_LIMIT` | Relay resource budget ended circuit |
| `10` | `POLICY_REVOKED` | Operator or authorization policy changed |
| `11` | `PROTOCOL_ERROR` | Invalid circuit state or data |
| `12` | `PAYLOAD_TOO_LARGE` | Data exceeded granted relay payload |
| `13` | `EMERGENCY_SHUTDOWN` | Operator disabled relay service |

The wire-format registry must define this relay reason-code namespace.

---

# 25. Circuit failure

A relay classifies failure as:

```text
TRANSIENT_PATH
PERMANENT_PATH
AUTHORIZATION
POLICY
RESOURCE
PROTOCOL
ADJACENT_SESSION
```

For a transient downstream path failure, the relay MAY recover through another route when:

* Circuit flags and policy permit path replacement
* Granted lifetime remains
* New path satisfies destination and privacy constraints
* Queued data stays within bounds

The relay sends `DEGRADED` while recovery proceeds.

It MUST NOT silently switch to a route that violates carrier, destination, trust, locality, or privacy constraints.

If recovery fails, it closes both legs with a mapped reason.

---

# 26. Circuit path migration

An adjacent UMP session may migrate between carriers under `session.md`. That migration does not change Circuit ID or Relay Sequence.

A relay may replace its downstream UMP path while preserving circuit state when path policy permits it.

The relay MUST preserve:

* Circuit authorization
* Byte accounting
* Expiry
* Direction state
* Relay sequences
* Ordered forwarding

It MUST NOT duplicate accepted Data onto old and new downstream paths unless `MULTIPATH_GRANTED` and duplication policy permit it.

Inner endpoint sessions perform their own path validation. Relay path migration does not authenticate the final endpoint.

---

# 27. Multi-hop construction

UMP/1 builds a multi-hop route as a chain of adjacent relay circuits.

## 27.1 Sequential extension

The originator or current relay extends the circuit one hop at a time:

1. Open the first relay leg.
2. Send a protected downstream `RELAY_OPEN` through that leg or ask the first relay to open its next leg.
3. Receive downstream status through the established circuit.
4. Repeat until the destination-facing leg accepts.
5. Start the end-to-end endpoint handshake through the completed chain.

The selected construction profile determines whether the originator or each relay sees downstream open details.

## 27.2 Hop-by-hop profile

The mandatory UMP/1 profile lets each relay receive the Next-Hop Hint for its immediate downstream peer.

Each relay knows:

* Its upstream peer
* Its downstream peer
* Its local position is neither proven first nor final unless request context reveals it
* Its local quotas and timing

The profile does not hide full route structure from an originator that selected all hops.

## 27.3 Nested-control protection

Control messages for a downstream relay MUST receive end-to-end protection between the circuit constructor and that downstream relay when an intermediate relay does not need their contents.

The mandatory hop-by-hop profile may expose each leg's `RELAY_OPEN` to the relay that creates that leg. It MUST NOT expose authorization secrets for later legs.

## 27.4 Hop limits

The originator enforces routing Hop Limit and relay-count policy.

Stable UMP/1 default maximum is four relay nodes. Protocol maximum is 16.

Each extension step decrements remaining relay count. A relay MUST reject construction with zero remaining count.

---

# 28. Nested encryption

End-to-end UMP session encryption is mandatory across relay circuits.

The inner endpoint handshake and protected packets remain opaque to relays. Each adjacent UMP session also encrypts its relay frames.

For a two-relay path:

```text
Endpoint A
  outer adjacent protection to Relay 1
    relay encapsulation
      adjacent protection between Relay 1 and Relay 2
        relay encapsulation
          end-to-end UMP packet for Endpoint B
```

Adjacent encryption protects each link. End-to-end encryption protects application and endpoint-session content from every relay.

UMP/1 does not require onion encryption that gives each relay one removable layer over a fixed full path. A future extension may define it.

Relays MUST NOT terminate the inner endpoint session unless they are the addressed endpoint.

---

# 29. Metadata visibility

## 29.1 First relay

The first relay can observe:

* Originator's adjacent node identity or session
* Circuit timing and volume
* Granted quotas
* Immediate next-hop hint
* Its own authorization result

It may infer that its upstream peer is near the origin, but nested relaying can make that inference wrong.

## 29.2 Middle relay

A middle relay can observe its adjacent upstream and downstream peers, local traffic patterns, and its circuit policy.

It should not receive originator identity, final destination identity, or full path unless the construction profile requires disclosure.

## 29.3 Final relay

The final relay may observe the destination-facing peer or rendezvous hint. It should not receive originator identity beyond what traffic correlation or authorization exposes.

## 29.4 Endpoints

The originator may know the selected relay chain. The destination may know only its adjacent relay unless route or application metadata reveals more.

## 29.5 Global observer

Packet encryption does not hide timing, sizes, carrier addresses, or traffic direction from a capable observer.

---

# 30. Private circuits

`PRIVATE_CIRCUIT` requests stricter metadata handling.

A relay granting private handling MUST:

* Avoid public circuit advertisement
* Avoid diagnostic strings containing peer or destination hints
* Use redacted circuit identifiers in logs
* Restrict metric labels that create per-circuit histories
* Follow authorization sharing limits

Private handling does not guarantee anonymity or traffic-analysis resistance.

A relay that cannot meet the requested profile must reject or accept without `PRIVATE_HANDLING_GRANTED`. The originator decides whether the weaker grant satisfies policy.

---

# 31. Multipath relay behavior

Multipath requires `MULTIPATH_ALLOWED` and `MULTIPATH_GRANTED`.

A relay may maintain several downstream paths for one circuit. It keeps one Relay Sequence space per direction across those paths.

The relay MUST preserve ordered delivery to the next circuit leg.

It MAY:

* Move future frames to another path
* Duplicate control traffic
* Duplicate selected Data when policy permits

Every duplicate consumes network and congestion budgets. Circuit byte quota counts a Relay Sequence once, even when the relay duplicates that sequence across its own downstream paths.

The relay must deduplicate before delivering to the paired leg.

---

# 32. Scheduling and fairness

The relay scheduler separates:

```text
Control
Interactive
Normal
Bulk
Background
```

`RELAY_OPEN`, `RELAY_STATUS`, and `RELAY_CLOSE` use Control priority.

`HIGH_PRIORITY` may request Interactive service. Local policy caps the share available to one peer or circuit.

The relay MUST prevent one circuit from starving control traffic or other admitted circuits.

Recommended scheduler uses weighted deficit round robin or another work-conserving fair algorithm with per-peer and per-circuit buckets.

Fairness applies after hard bandwidth and congestion limits.

---

# 33. Bandwidth limits

Each relay configuration MUST define:

* Per-circuit send rate
* Per-peer aggregate rate
* Global relay rate
* Burst allowance
* Carrier-specific limits

The relay enforces the lowest applicable limit.

Recommended public defaults:

```text
Per-circuit rate: 1 MiB/s
Per-peer aggregate rate: 4 MiB/s
Burst duration: 1 second
```

These values are deployment defaults, not interoperability requirements.

Rate limiting should delay traffic within queue and lifetime limits. When delay would exceed limits, the relay applies backpressure or closes the circuit.

---

# 34. Admission control

A relay evaluates admission in this order:

1. Frame size and canonical encoding.
2. Circuit ID collision and replay.
3. Per-peer request rate.
4. Global circuit capacity.
5. Authorization format and expiry.
6. Requested destination scope.
7. Requested lifetime and quota.
8. Next-hop resolution budget.
9. Operator and carrier policy.

The relay SHOULD perform expensive signature verification or dialing only after cheap limits pass.

Admission may reserve:

* One circuit-state record
* Small fixed control queue
* Downstream dial slot
* Granted bandwidth and byte quota accounting

It MUST NOT allocate the full requested byte quota as memory or storage.

---

# 35. Authorization policy

Relay authorization is separate from endpoint authentication.

Policy may constrain:

* Requester trust state
* Destination endpoint or class
* Next-hop peer or carrier
* Circuit direction
* Lifetime and bytes
* Concurrent circuits
* Time of day or operator state
* Local-only or community scope

An authenticated Unknown or Observed endpoint receives no relay access by default.

Introduced endpoints receive only the relay scope named by the introduction.

Trusted status does not grant public exit, arbitrary destination, or unlimited quota.

Authorization changes may revoke active circuits. The relay sends `POLICY_REVOKED` when disclosure is safe.

---

# 36. Destination restrictions

A relay MUST let operators restrict destinations by:

* Endpoint or trust class
* Carrier
* Local versus general scope
* Relay chain length
* Service class
* Network or legal policy

The core does not implement internet exit semantics. A request that asks the relay core to connect to an arbitrary IP, domain, TCP port, DNS name, or URL is invalid unless a separate gateway application and protocol handle it.

Relays MUST prevent Next-Hop Hint from bypassing carrier and destination allow lists.

---

# 37. Abuse controls

A relay MUST enforce:

* Open-request rate limits
* Concurrent-circuit limits
* Byte and bandwidth quotas
* Idle and lifetime limits
* Queue limits
* Next-hop dialing limits
* Failed-authorization limits
* Diagnostic suppression

It SHOULD maintain bounded abuse scores for authenticated adjacent peers.

Events that may increase abuse score include:

* Circuit ID conflicts
* Invalid authorization
* Repeated refused destinations
* Sequence conflicts
* Payloads above grant
* Excessive open churn
* Priority abuse

Responses may include lower quotas, temporary refusal, session restriction, or block-list action.

An abuse score is local operational state. Relays MUST NOT present it as global reputation.

---

# 38. Amplification controls

Before authorization, a relay MUST NOT:

* Dial many downstream peers
* Send large diagnostics
* Allocate payload-sized buffers
* Create nested circuits
* Forward requester-controlled bytes

The total pre-authorization response bytes SHOULD NOT exceed the admitted `RELAY_OPEN` size by more than a small fixed status envelope.

One request may create at most one downstream dial attempt at a time unless trusted policy permits parallel dialing.

The relay MUST cap downstream attempts per request. Default is three.

---

# 39. Circuit isolation

Each circuit has independent:

* Identifiers
* Quotas
* Queue state
* Sequences
* Expiry
* Close state

A protocol error on one circuit SHOULD close that circuit without closing the adjacent UMP session.

The relay closes the adjacent session when a peer sends malformed relay frames that prevent safe circuit demultiplexing, repeats authenticated state conflicts, or exceeds session-wide abuse thresholds.

One circuit MUST NOT access another circuit's queue, status, authorization, or next-hop mapping.

---

# 40. Session and carrier failure

If the upstream adjacent session closes, the relay closes paired downstream legs and releases state after draining.

If the downstream adjacent session closes, the relay may:

* Recover through another permitted path
* Report `DEGRADED`
* Close upstream with `DOWNSTREAM_FAILED`

The relay MUST bound recovery time and buffered data.

Carrier failure on one path does not close the circuit when the adjacent UMP session migrates or another authorized downstream path succeeds.

The relay must not keep a circuit alive past its original expiry during recovery.

---

# 41. Emergency shutdown

Operators need one action that stops relay service.

Emergency shutdown MUST:

1. Reject new `RELAY_OPEN` requests.
2. Stop downstream dialing.
3. Send `EMERGENCY_SHUTDOWN` close to active circuits when possible.
4. Apply a bounded drain period.
5. Release relay queues and circuit state.
6. Preserve no application plaintext.

The operator may choose immediate termination when continued forwarding creates risk.

Disabling relay service does not delete endpoint identities or unrelated session state.

---

# 42. Logging and metrics

Default relay logs MUST NOT include:

* Inner Data bytes
* End-to-end endpoint identities unless the relay needs them for policy
* Full Next-Hop Hints
* Authorization secrets
* Complete multi-hop paths
* Private circuit traffic samples

Logs may include:

* Redacted adjacent peer handle
* Redacted Circuit ID
* Status or reason code
* Granted quota class
* Byte counts
* Lifetime
* Carrier class

Metrics SHOULD include:

```text
Active and opening circuits
Accepted and refused opens
Refusal reasons
Forwarded bytes by direction and policy class
Queue occupancy
Circuit lifetime
Idle and quota closures
Downstream failures
Recovery success
Authorization failures
```

Public metrics MUST avoid per-circuit labels and stable peer identifiers.

---

# 43. Accounting and privacy

Relay accounting records may reveal communication relationships.

An implementation SHOULD aggregate counters and expire detailed records under operator policy.

The core MAY retain:

* Total bytes per authorization principal
* Quota usage
* Abuse events
* Billing-class records for an external policy system

The core MUST NOT define payment semantics or expose inner application content.

Private-circuit records receive shorter retention or stronger protection where policy supports it.

---

# 44. Persistence

Live circuit state is ephemeral in UMP/1.

After process restart, a relay MUST NOT reconstruct an active circuit from persisted sequences, traffic mappings, or queue data.

The relay may persist:

* Authorization revocation state
* Aggregate quota state
* Abuse counters
* Operator configuration

It MUST expire persisted authorization and accounting data according to their own lifetimes.

Peers observe restart as circuit failure and construct a new route or circuit.

---

# 45. Error handling

Circuit-scoped errors use `RELAY_STATUS` or `RELAY_CLOSE`.

Adjacent-session errors apply only when frame parsing or authenticated peer behavior compromises session safety.

| Condition | Response |
| --- | --- |
| Malformed relay frame | Close adjacent session with `FRAME_ENCODING_ERROR` |
| Unknown circuit ID in data | Drop; optional `CLOSED` status under rate limit |
| Conflicting Circuit ID open | Close adjacent session with `PROTOCOL_VIOLATION` |
| Invalid authorization | `AUTH_FAILED` status or silent refusal under private policy |
| No downstream route | `NO_ROUTE` status |
| Payload over grant | Circuit close with `PAYLOAD_TOO_LARGE` |
| Byte quota exceeded | Circuit close with `QUOTA_EXHAUSTED` |
| Sequence conflict | Circuit close with `PROTOCOL_ERROR` |
| Relay Sequence gap | Record and continue; inner session handles loss |
| Relay disabled | `REFUSED` or silent refusal |

Before authorization, the relay SHOULD minimize error detail.

---

# 46. Resource limits

Every relay MUST define hard limits for:

* Opening circuits
* Active circuits
* Circuits per peer
* Open requests per peer and time window
* Downstream dial attempts
* Payload per frame
* Queue bytes per circuit and peer
* Total queue bytes
* Circuit lifetime
* Byte quota
* Bandwidth
* Status and diagnostic size
* Draining circuits

Recommended defaults:

| Resource | Default |
| --- | ---: |
| Opening circuits per Observed peer | 2 |
| Active circuits per Observed peer | 4 |
| Active circuits per Trusted peer | 32 |
| Open requests per Observed peer | 10 per minute |
| Downstream attempts per open | 3 |
| Maximum relay nodes per route | 4 |
| Protocol maximum relay nodes | 16 |
| Maximum Relay Payload | 64 KiB |
| Per-circuit queue | 256 KiB |
| Per-peer relay queue | 2 MiB |
| Default lifetime | 10 minutes |
| Default idle timeout | 2 minutes |

The resource-limits specification may set deployment profiles. It must preserve these protocol invariants.

---

# 47. Security considerations

## 47.1 Malicious originator

An originator may churn circuits, inflate quotas, send sparse sequences, or target restricted peers. Relays apply admission order, bounded state, destination policy, and per-peer accounting.

## 47.2 Malicious relay

A relay may observe metadata, drop or delay traffic, reorder frames, lie about status, or redirect downstream construction. Endpoints use end-to-end authentication, sequence checks, timeouts, route diversity, and migration.

A relay cannot forge valid end-to-end endpoint packets without session keys.

## 47.3 Colluding relays

Relays that share timing and adjacency records may correlate a circuit across hops. UMP/1 does not prevent this. Private carriers, padding, batching, or onion extensions may reduce risk.

## 47.4 Replay

Adjacent sessions protect frame replay. Circuit IDs, status sequences, relay sequences, expiry, and draining state prevent accepted duplicates from creating new circuit effects.

## 47.5 Resource exhaustion

Relay service exposes CPU, memory, bandwidth, and dialing capacity. Nodes must enforce fixed admission and queue budgets before forwarding requester-controlled payload.

## 47.6 Destination scanning

Attackers may use relays to test reachability. Destination allow lists, scoped hints, authorization, rate limits, and generic errors reduce scanning value.

## 47.7 Traffic injection

The relay can inject or alter opaque Data, but inner endpoint AEAD rejects forged packets. The relay can still cause denial of service.

## 47.8 Quota evasion

Attackers may reconnect with new identities. Operators should group quotas by authorization principal, adjacent source context, introduction source, and trust domain where available.

---

# 48. Required tests

A compliant implementation MUST test:

1. Circuit ID generation and collision handling.
2. Open acceptance, refusal, timeout, and duplicate replay.
3. Authorization binding and expiry.
4. Granted lifetime, byte quota, and payload limits.
5. Status sequence ordering and conflicts.
6. Relay Sequence duplicates, gaps, final sequence, and exhaustion.
7. Opaque Data handling and inner packet boundaries.
8. Half-close in each direction.
9. Close propagation and draining.
10. Per-circuit, per-peer, and global backpressure.
11. Quota accounting across outer retransmissions.
12. Idle and lifetime expiry.
13. Downstream failure and permitted recovery.
14. Adjacent-session path migration.
15. Single-relay endpoint handshake and traffic.
16. Multi-hop construction through four relays.
17. Hop limit and per-hop authorization.
18. Metadata visible at first, middle, and final relays.
19. Private-circuit logging restrictions.
20. Admission under circuit-open floods.
21. Sequence-gap handling without relay retransmission.
22. Emergency shutdown.
23. Restart without circuit restoration.
24. Malicious relay injection, reordering, and delay.

Property tests SHOULD verify:

```text
Circuit IDs do not collide within one adjacent session's live set.
Granted limits never exceed requested or local policy limits.
Byte quota never increases without a new authorization event.
Each Relay Sequence reaches a paired leg at most once.
Relay sequences never reset or wrap.
FIN prevents later data in its direction.
Circuit expiry never exceeds authorization or route expiry.
One circuit cannot consume another circuit's queue or quota.
```

---

# 49. Interoperability requirements

A minimal UMP/1 relay implementation MUST support:

* Critical length-delimited `RELAY_OPEN`
* Critical length-delimited `RELAY_STATUS`
* `RELAY_DATA`
* Critical length-delimited `RELAY_CLOSE`
* Random circuit identifiers
* Explicit open acceptance and refusal
* Bidirectional circuits
* Per-direction Relay Sequence
* Opaque inner packet framing
* Byte and lifetime quotas
* Backpressure and bounded queues
* Half-close
* Circuit failure and close propagation
* Single-relay circuits
* Hop-by-hop multi-relay construction
* End-to-end inner UMP encryption
* Per-peer admission and abuse limits

An implementation MAY defer:

* Store-forward relay mode
* Relay multipath
* Onion-style circuit construction
* Payment or proof-of-work authorization extensions
* Quota renewal
* Persistent circuit restoration

An implementation MUST NOT advertise a deferred capability.

---

# 50. Open design decisions

The project must resolve these items before freezing UMP/1 interoperability:

1. Final frame type for `RELAY_STATUS`.
2. Length-delimited frame types for `RELAY_OPEN` and `RELAY_CLOSE`.
3. Relay status and reason-code registry placement.
4. Exact Circuit ID generation requirements.
5. Exact `NONE` encoding for Final Relay Sequence.
6. Whether Relay Sequence remains mandatory in `RELAY_DATA`.
7. Whether inner packets may span relay frames.
8. Whether one relay frame may carry several inner packets.
9. Exact relay authorization profiles.
10. Multi-hop circuit construction transcript.
11. Downstream receipt format in `RELAY_STATUS` Authentication.
12. Whether the originator or each relay selects later hops.
13. Whether UMP/1 defines an onion-style optional profile.
14. Default and maximum relay counts.
15. Whether quota splits by direction.
16. Whether UMP/1 needs a relay-window frame.
17. Exact open timeout and final-sequence drain window.
18. Whether private circuits require padding.
19. Whether `HIGH_PRIORITY` remains in the base frame.
20. Exact circuit recovery rules after downstream path replacement.

---

# 51. Recommended implementation order

Implement relaying in this order:

1. Circuit types and bounded stores.
2. Circuit ID generation.
3. `RELAY_OPEN` parsing and admission.
4. `RELAY_STATUS` encoding and state transitions.
5. Single-relay circuit establishment.
6. `RELAY_DATA` parsing and sequencing.
7. Queue bounds and backpressure.
8. Byte and lifetime quotas.
9. `RELAY_CLOSE`, half-close, and draining.
10. Failure propagation.
11. Path replacement.
12. Multi-hop construction.
13. Private-circuit metadata controls.
14. Fair scheduling.
15. Abuse simulation and fuzzing.

---

# 52. Core rule

A UMP relay forwards bounded opaque traffic between authenticated adjacent peers while endpoint sessions retain end-to-end security.

Each relay grants one explicit circuit with fixed authorization, lifetime, byte, queue, and destination limits. Circuit identifiers and sequences remain local to adjacent sessions. Relays may deny, delay, or drop traffic, but they cannot authenticate as the final endpoint or read protected application content.
