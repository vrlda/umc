# Universal Mesh Core Resource and Denial-of-Service Specification

**Status:** Draft
**Version:** 0.1
**Document:** Resource Limits and Admission Control
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines resource accounting, default limits, pressure behavior, fairness, and denial-of-service controls for UMC and UMP/1.

It specifies:

* Memory, CPU, storage, bandwidth, and handle budgets
* Accounting scopes
* Admission control
* Pending-handshake limits
* Session, stream, ACK, and reassembly limits
* Discovery, peer, and routing limits
* Relay limits
* Bundle-storage limits
* Carrier and plugin limits
* Local control API limits
* Logging and metrics limits
* Backpressure
* Eviction and load shedding
* Pressure states and recovery

Module specifications define protocol semantics. This document assigns deployment defaults and global interactions among their limits.

This document does not define:

* Congestion-control algorithms
* Operating-system service-manager limits
* Application-specific quotas
* Commercial relay or storage plans
* Guaranteed availability under attack

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

All quantities in this document use binary byte units:

```text
KiB = 1,024 bytes
MiB = 1,024 KiB
GiB = 1,024 MiB
```

Rates use monotonic time.

---

# 3. Security objectives

The resource system MUST:

1. Keep resource use within configured hard bounds.
2. Reject untrusted work before expensive allocation where possible.
3. Charge work to the narrowest known principal and broader enclosing scopes.
4. Preserve control and recovery capacity during load.
5. Apply backpressure before dropping accepted reliable data.
6. Prevent one peer, application, carrier, plugin, or destination from consuming the node.
7. Prefer established authenticated work over unauthenticated speculative work.
8. Keep accounting itself bounded.
9. Recover after pressure subsides.
10. Report rejection without leaking sensitive policy.

Hard limits preserve bounds. They do not guarantee service for honest clients during a distributed attack.

---

# 4. Limit hierarchy

UMC uses four limit classes.

## 4.1 Protocol maximum

A Protocol Maximum is the largest value UMP/1 syntax or interoperability permits.

Peers cannot negotiate above it. Configuration cannot raise it without selecting another protocol version or extension.

## 4.2 Configured hard limit

A Configured Hard Limit caps one node deployment. The resource manager rejects work that would exceed it.

Configuration MAY lower a hard limit. Raising it above a profile default requires explicit operator action.

## 4.3 Soft limit

A Soft Limit starts backpressure, reduced fanout, eviction, or lower admission before the hard limit.

Default soft limit is 80 percent of the corresponding hard limit unless a table specifies another threshold.

## 4.4 Negotiated or granted limit

A peer or local application receives a negotiated or granted limit no greater than every applicable local hard limit.

A remote advertised limit grants permission to the local sender. It does not force local allocation.

The effective limit is:

```text
min(protocol maximum,
    configured hard limit,
    principal quota,
    negotiated or granted value,
    remaining global budget)
```

---

# 5. Accounting scopes

UMC charges each admitted resource to all applicable scopes:

```text
Global node
Subsystem
Carrier Instance
Plugin process
Adjacent source context
Authenticated peer endpoint
Trust or authorization principal
Local application
Local endpoint
Session
Stream
Route request
Relay circuit
Bundle sender and owner
```

A source context may include IP prefix, local link identity, carrier account, invitation, process credential, or another bounded signal.

Source context is an accounting key. It does not authenticate endpoint identity.

When a peer creates many endpoint identities through one source or authorization, UMC SHOULD group them under the shared broader scope.

---

# 6. Resource classes

UMC accounts:

```text
Resident memory
Queued bytes
Persistent storage
CPU work
Cryptographic work
Network bytes
Open handles
Concurrent operations
Timers
Database write work
Log and metric events
```

Modules MUST register reservations before allocation or operation start.

The resource manager MUST release reservations on completion, cancellation, rejection, timeout, crash cleanup, and state eviction.

---

# 7. Resource profiles

UMC v0.1 defines three deployment profiles.

## 7.1 `constrained`

Target: small routers, mobile experiments, and low-memory devices.

```text
Managed memory hard budget: 128 MiB
Persistent operational storage: 512 MiB
Bundle storage: disabled by default
Active sessions: 128
Public relay: disabled
```

## 7.2 `standard`

Target: desktop and small server nodes.

```text
Managed memory hard budget: 512 MiB
Persistent operational storage: 4 GiB
Experimental bundle storage: 1 GiB
Active sessions: 1,024
Public relay: disabled
```

## 7.3 `relay`

Target: operator-managed relay nodes.

```text
Managed memory hard budget: 2 GiB
Persistent operational storage: 16 GiB
Experimental bundle storage: 10 GiB
Active sessions: 8,192
Active relay circuits: 16,384
Public relay: explicit opt-in
```

Managed memory covers UMC-accounted heap buffers, state objects, and queues. Runtime, allocator, code, mapped libraries, and OS buffers add process overhead. Operators must set an OS-level memory limit above the managed budget.

---

# 8. Pressure states

The resource manager exposes:

```text
NORMAL
ELEVATED
HIGH
CRITICAL
EMERGENCY
```

## 8.1 NORMAL

Usage remains below 70 percent of hard budget. Normal admission and cache targets apply.

## 8.2 ELEVATED

Usage reaches 70 percent. UMC reduces speculative work and starts early cleanup.

## 8.3 HIGH

Usage reaches 80 percent. Soft limits apply. UMC reduces discovery and routing fanout, withholds new stream credit where safe, and evicts low-value caches.

## 8.4 CRITICAL

Usage reaches 90 percent. UMC rejects most new unauthenticated and low-trust work, disables optional background activity, and preserves established control traffic.

## 8.5 EMERGENCY

Usage reaches 98 percent or the allocator, OS, filesystem, or database reports imminent exhaustion.

UMC stops new network admission, sheds optional authenticated work, closes low-priority relay circuits when required, and invokes bounded emergency cleanup.

Pressure leaves a state only after usage falls 5 percentage points below its entry threshold for at least 5 seconds. This hysteresis prevents rapid state changes.

---

# 9. Priority classes

UMC schedules resource work in these classes:

```text
P0 Emergency and shutdown
P1 Handshake confirmation, close, ACK, path recovery
P2 Established interactive sessions and local administration
P3 Established normal sessions and trusted routing
P4 New authenticated sessions, relay, and discovery
P5 Unauthenticated admission and speculative work
P6 Background maintenance, metrics export, and bundle replication
```

Priority affects admission and scheduling. It cannot bypass a hard limit.

The scheduler MUST reserve at least 10 percent of managed queue and operation capacity for P0 and P1 work. A module MAY define a larger control reserve.

P0 and P1 traffic must remain bounded by their own quotas so an attacker cannot relabel unlimited work as control traffic.

---

# 10. Admission sequence

Network-facing modules SHOULD admit work in this order:

1. Validate fixed outer bounds.
2. Classify source context.
3. Check global and subsystem pressure.
4. Apply source and peer rate limits.
5. Validate cheap tokens or cookies.
6. Reserve bounded state.
7. Perform cryptographic verification.
8. Apply authorization and policy.
9. Commit state and release temporary reservation.

A module MUST NOT perform a large allocation, database write, signature verification, Diffie-Hellman operation, downstream dial, or broad scan before the relevant earlier checks pass.

---

# 11. Rate-limit algorithm

UMC SHOULD implement rate limits with token buckets.

Each bucket defines:

```text
capacity
refill tokens per second
cost per operation
maximum debt, normally zero
idle expiry
```

The implementation uses monotonic time and saturating arithmetic.

A principal cannot gain tokens through clock rollback or integer overflow.

Buckets expire after bounded inactivity. The node MUST cap bucket count and aggregate unknown sources when cardinality grows.

---

# 12. Unknown-source aggregation

An attacker can vary addresses or identifiers to create accounting state.

UMC MUST bound unknown-source buckets through:

* Prefix or carrier-context aggregation
* Fixed-size approximate counting
* LRU expiry
* A global unknown-source bucket

Default maximum detailed unknown-source buckets:

| Profile | Buckets |
| --- | ---: |
| `constrained` | 1,024 |
| `standard` | 16,384 |
| `relay` | 65,536 |

After the limit, UMC uses aggregate buckets and creates no per-source state until capacity returns.

---

# 13. CPU work units

UMC accounts expensive operations with work units.

Default relative costs:

| Operation | Work units |
| --- | ---: |
| Parse one bounded packet or local API envelope | 1 |
| Verify Retry or invitation MAC | 2 |
| X25519 operation | 20 |
| Ed25519 verification | 25 |
| Ed25519 signing | 30 |
| Decrypt and validate one 64 KiB packet | 16 |
| SQLite write transaction | 10 plus size cost |
| Downstream dial attempt | 50 |
| Plugin process start | 500 |

Implementations SHOULD calibrate units through benchmarks while preserving relative protection.

The standard profile default global budget is 50,000 work units per second with a 100,000-unit burst. Per-peer authenticated default is 2,000 units per second. Unknown-source default is 100 units per second.

CPU budgets regulate admission. They do not replace OS CPU quotas.

---

# 14. Cryptographic operation limits

Before authentication, the node MUST cap:

```text
Concurrent Diffie-Hellman operations
Signature verifications
Signature chain length
Retry and invitation MAC checks
Session-ticket decryptions
```

Standard defaults:

| Resource | Global | Per source context |
| --- | ---: | ---: |
| Concurrent X25519 operations | 128 | 4 |
| Ed25519 verifications per second | 2,000 | 20 |
| Delegation certificates per chain | 4 | 4 |
| Encoded delegation chain | 8 KiB | 8 KiB |
| Ticket attempts per minute | 10,000 | 20 |
| Invitation MAC attempts per minute | 50,000 | 60 |

At `HIGH` pressure, UMC halves unauthenticated per-source rates. At `CRITICAL`, it requires valid Retry or private admission before public-key work.

---

# 15. Packet and parser limits

Protocol maxima from `wire-format.md` remain authoritative:

| Resource | Protocol maximum |
| --- | ---: |
| UMP packet | 65,535 bytes |
| Generic byte string | 16 MiB unless field limit is lower |
| Connection ID | 20 bytes |
| Token | 1,024 bytes |
| ACK ranges | 64 |
| Protocol ID | 255 bytes |
| Initial stream metadata | 4 KiB |
| Peer hints per frame | 32 |
| Capabilities per frame | 128 |
| Capability value | 4 KiB |
| Handshake transcript | 64 KiB |
| Handshake message | 16 KiB |

The generic byte-string maximum does not grant a 16 MiB allocation. Modules apply field and remaining-budget limits before allocation.

Parser loops MUST cap iterations from validated count fields and remaining packet length.

---

# 16. Packet-buffer budgets

Default standard-profile budgets:

```text
Global inbound packet buffers: 64 MiB
Global outbound packet buffers: 64 MiB
Per Link inbound queue: 2 MiB or 256 packets
Per Link outbound queue: 2 MiB or 256 packets
Per session packet metadata: 1 MiB
```

The lower byte or packet count wins.

At `HIGH` pressure, datagram carriers drop new low-priority inbound packets before allocation. Stream carriers stop reads where possible.

UMC MUST preserve bounded control receive capacity for active authenticated sessions.

---

# 17. Pending-handshake limits

Pending handshakes include Initial, Retry, and Handshake state before confirmation.

Default limits:

| Resource | `constrained` | `standard` | `relay` |
| --- | ---: | ---: | ---: |
| Global pending handshakes | 128 | 2,048 | 16,384 |
| Pending per source context | 2 | 8 | 16 |
| Pending per authenticated invitation | 4 | 32 | 128 |
| Buffered bytes per handshake | 64 KiB | 64 KiB | 64 KiB |
| Out-of-order handshake fragments | 32 | 64 | 64 |
| Initial response timeout | 3 s | 3 s | 3 s |
| Total handshake timeout | 15 s | 15 s | 15 s |
| Retransmissions | 5 | 5 | 5 |

Before Retry or private admission validation, standard profile reserves at most 4 KiB per pending source state.

At 50 percent global pending capacity, datagram listeners SHOULD require stateless Retry. At 80 percent, they MUST require it where the carrier supports Retry.

Private bridge failures follow anti-probing policy and may remain silent.

---

# 18. Amplification limits

Before validating return reachability, a datagram responder MUST send no more than three times the bytes received from one source context.

The node accounts received and sent bytes per address-validation context.

It MUST NOT transfer amplification credit across unrelated addresses, carriers, invitations, or connection IDs.

Version negotiation, Retry, errors, and close packets consume the same credit.

---

# 19. Established-session limits

Default active session limits:

| Scope | `constrained` | `standard` | `relay` |
| --- | ---: | ---: | ---: |
| Global active sessions | 128 | 1,024 | 8,192 |
| Per remote endpoint | 4 | 16 | 64 |
| Per local application | 32 | 256 | 2,048 |
| Per local endpoint | 64 | 512 | 4,096 |
| Simultaneous session opens per peer | 2 | 8 | 32 |

The node may permit more sessions for administrative or trusted service identities through explicit policy, within global hard limits.

At `CRITICAL` pressure, UMC rejects new sessions and preserves active sessions according to priority and recent authenticated use.

---

# 20. Stream-count limits

UMP negotiates stream counts. Local hard limits cap those grants.

Standard defaults:

```text
Initial peer bidirectional streams: 16
Initial peer unidirectional streams: 16
Hard streams per session: 1,024
Hard streams per peer across sessions: 8,192
Hard streams per local application: 16,384
```

At `HIGH` pressure, receivers withhold replacement `MAX_STREAMS` credit. They do not reduce an advertised limit.

Opening a stream reserves state before UMC accepts its first frame or local handle.

---

# 21. Stream reassembly limits

Each receive stream has:

```text
advertised flow-control window
buffered contiguous bytes
buffered out-of-order bytes
range-count limit
application-delivery queue
```

Standard defaults:

| Resource | Default |
| --- | ---: |
| Initial stream receive window | 256 KiB |
| Maximum automatic stream window | 16 MiB |
| Out-of-order bytes per stream | 1 MiB |
| Out-of-order ranges per stream | 256 |
| Buffered receive bytes per session | 16 MiB |
| Buffered send bytes per session | 16 MiB |
| Buffered bytes per application | 128 MiB |

An application may request another window within policy.

The receiver MUST NOT advertise credit that its combined memory and delivery policy cannot support.

When out-of-order limits fill while the sender remains within advertised credit, the receiver stops granting credit and may close the stream or session if it cannot preserve accepted reliable bytes. It MUST NOT discard accepted bytes and continue as if delivery could succeed.

Sparse offsets consume range metadata and highest-offset flow-control credit.

---

# 22. Connection flow-control limits

Standard defaults:

```text
Initial MAX_DATA: 4 MiB
Maximum automatic receive window per session: 64 MiB
Maximum unconsumed receive data per session: 16 MiB
Maximum pending application writes per session: 16 MiB
```

UMC may grow a window based on application consumption and RTT. Growth cannot exceed local memory reservation.

At `HIGH` pressure, UMC stops automatic growth. Advertised limits remain monotonic.

---

# 23. Datagram limits

Default standard-profile datagram limits:

```text
Maximum datagram payload: negotiated path limit
Queued datagrams per session: 256
Queued datagram bytes per session: 2 MiB
Queued datagram bytes per application: 16 MiB
Datagram contexts per session: 256
```

Datagrams receive no retransmission reservation.

When a queue reaches its limit, UMC drops or rejects datagrams according to application policy. It reports the local result without implying network delivery.

Expired datagrams leave queues before new admission.

---

# 24. ACK and sent-packet limits

Defaults:

```text
ACK ranges per frame: 64
Stored receive ranges per packet-number space: 256
Replay window per packet-number space: 4,096 packets
Outstanding sent-packet metadata per session: 16,384 packets
Retained packet metadata after acknowledgement: 0, except diagnostics counters
```

When receive ranges exceed storage:

* UMC merges adjacent ranges.
* UMC discards the oldest ranges outside replay need.
* UMC retains no claim that discarded packets were received.

A peer cannot force acknowledgement of unsent packets or allocation proportional to a packet-number gap.

---

# 25. Path and connection-ID limits

Defaults per session:

```text
Negotiated active paths: 1
Configured active-path hard limit: 8
Candidate paths beyond active limit: 2
Outstanding challenges per path: 3
Active peer-issued connection IDs: 4
Connection-ID protocol length: 20 bytes
Retained retired IDs: active limit plus 8
Retained traffic-key phases: 2
```

Path candidates reserve state before validation. At `HIGH` pressure, UMC rejects optional candidate paths and preserves the current path plus one recovery candidate.

Connection-ID retirement state expires after its protocol drain and replay period.

---

# 26. Peer-store limits

Default peer-record limits:

| Scope | `constrained` | `standard` | `relay` |
| --- | ---: | ---: | ---: |
| Total peer records | 2,048 | 50,000 | 250,000 |
| Direct and active peers reserved | 256 | 4,096 | 32,768 |
| New Observed peers per source | 64 | 256 | 1,024 |
| Carrier hints per peer | 8 | 16 | 32 |
| Introduction records per peer | 8 | 16 | 32 |

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

# 27. Discovery limits

Default standard-profile limits:

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

At `HIGH` pressure, UMC disables background discovery, lowers candidate caps to 32, and keeps static, local, invitation, and active-session recovery providers.

At `CRITICAL`, UMC admits only explicit local or trusted recovery discovery.

---

# 28. Routing limits

The defaults from `routing.md` are authoritative:

| Resource | Default | Hard maximum |
| --- | ---: | ---: |
| Hop Limit | 8 | 32 |
| Forward fanout | 3 | 8 in stable profile |
| Logical requests per destination | 2 | 4 |
| Responses per request branch | 8 | 16 |
| Path exclusions | 32 | 32 |
| Request lifetime | 30 s | 5 min |
| Cached candidates per destination and policy | 8 | 16 |
| Recent Request IDs per peer | 4,096 | 16,384 |
| Observed-peer requests | 10/min | configured hard rate |
| Concurrent admitted requests per peer | 16 | 64 |

Global standard-profile routing limits:

```text
Concurrent admitted requests: 4,096
Reverse-path records: 32,768
Recent request-cache records: 250,000
Route-cache records: 250,000
Routing managed memory: 64 MiB
```

At `HIGH` pressure, fanout becomes one for new low-trust requests and route-cache targets shrink. Active-session recovery keeps reserved capacity.

---

# 29. Routing work costs

Default token-bucket costs:

| Action | Tokens |
| --- | ---: |
| Admit structurally valid request | 1 |
| Forward one branch | 2 |
| Validate final response proof | 10 plus crypto work |
| Store one route candidate | 2 |
| Start one path construction | 20 |
| Dial one next hop | 50 |

One authenticated Observed peer receives 100 routing tokens per minute with a 200-token burst. Introduced and Trusted defaults are 500 and 2,000 tokens per minute.

Global pressure may lower refill without changing peer trust.

---

# 30. Relay limits

Default relay limits from `relay.md`:

| Resource | Standard endpoint profile | Relay profile |
| --- | ---: | ---: |
| Public relay | Disabled | Explicit opt-in |
| Opening circuits per Observed peer | 2 | 4 |
| Active circuits per Observed peer | 4 | 16 |
| Active circuits per Trusted peer | 32 | 256 |
| Global active circuits | 256 | 16,384 |
| Open requests per Observed peer | 10/min | 20/min |
| Downstream attempts per open | 3 | 3 |
| Default maximum relays in route | 4 | 4 |
| Protocol maximum relays | 16 | 16 |
| Maximum relay payload | 64 KiB | 64 KiB |
| Queue per circuit | 256 KiB | 256 KiB |
| Queue per peer | 2 MiB | 8 MiB |
| Global relay queue | 64 MiB | 1 GiB |
| Default lifetime | 10 min | 10 min |
| Default idle timeout | 2 min | 2 min |

Public relay default bandwidth:

```text
Per circuit: 1 MiB/s
Per peer: 4 MiB/s
Burst: 1 second
```

At `CRITICAL` memory pressure, the relay rejects new circuits and closes background or lowest-policy circuits only when queue cleanup and backpressure cannot restore safety.

Closing policy MUST preserve control capacity and send bounded close notifications where possible.

---

# 31. Relay fairness

Relay accounting applies by:

```text
Authorization principal
Authenticated endpoint
Adjacent source context
Circuit
Destination class
Carrier Instance
```

The scheduler SHOULD use weighted deficit round robin across peers, then circuits.

No peer receives more than 25 percent of configured global relay bandwidth by default, even when other quotas permit it. Operators may override this for private relay service.

`HIGH_PRIORITY` relay data cannot exceed 20 percent of one peer's bandwidth without explicit authorization.

---

# 32. Bundle limits

Bundles remain experimental in v0.1.

Default standard-profile limits:

```text
Bundle storage: 1 GiB
Maximum bundle: 16 MiB
Maximum live BUNDLE frame: current UMP packet limit minus headers and tags
Future segmented or stream-transfer chunk: 256 KiB
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

Nodes that do not enable bundles advertise no bundle-storage grant.

Declared payload size receives validation before database or file allocation.

A 16 MiB bundle requires a reliable stream or a negotiated segmentation extension. One base UMP packet, including its `BUNDLE` frame, remains within the 65,535-byte packet maximum. The 256 KiB value in the current `wire-format.md` draft cannot describe one base frame and must receive correction before interoperability freeze.

Content-addressed object storage charges physical bytes once and logical references to each owner quota.

---

# 33. Bundle eviction

Bundle eviction order is:

1. Expired bundles.
2. Invalid or orphaned objects.
3. Delivered bundles past receipt-retention policy.
4. Unauthenticated or Observed-sender bundles.
5. Lowest priority.
6. Highest replication count.
7. Largest remaining storage cost.
8. Oldest eligible bundle.

The node MUST preserve custody commitments according to the bundle profile or refuse custody before acceptance.

At 80 percent bundle storage, UMC rejects new low-priority bundles. At 90 percent, it runs eviction. At 98 percent, it rejects all new bundles except bounded local administrative recovery objects.

---

# 34. Persistent operational storage

The storage subsystem MUST define quotas for:

```text
Peer and route database
Trust and revocation records
Resumption tickets
Diagnostics
Bundle metadata
Content-addressed objects
Temporary migrations
Backups created by UMC
```

Secret and trust records receive reserved space. Bundle or diagnostic growth cannot prevent a critical trust or schema transaction.

Standard profile reserves 64 MiB of free database and filesystem budget for critical transactions.

When the reserve is unavailable, UMC enters `EMERGENCY`, rejects new persistent work, and reports storage failure.

---

# 35. Database write budgets

Default standard-profile limits:

```text
Concurrent write transactions: 1
Queued write operations: 10,000
Queued write bytes: 64 MiB
Single ordinary transaction: 16 MiB
Single migration transaction: explicit migration limit
Transaction wall deadline: 5 seconds for ordinary writes
```

SQLite supports one writer. UMC batches compatible operational writes within durability requirements.

Unauthenticated network input MUST NOT trigger an immediate durable write for each packet or request.

When write queues fill, UMC drops disposable metrics and route updates before trust, revocation, and accepted bundle metadata.

---

# 36. Carrier limits

Default standard-profile Carrier Instance limits:

```text
Listeners: 16
Pending accepts per listener: 128
Concurrent dials: 64
Discovery operations: 16
Candidates per discovery operation: 256
Active Links: 2,048
Send queue per Link: 256 packets or 2 MiB
Receive queue per Link: 256 packets or 2 MiB
Property events per Link: 100 per second
Generic packet: 65,535 bytes
```

One Carrier Instance may receive lower limits based on device, cost, or plugin policy.

At `HIGH` pressure, UMC cancels background discovery and speculative dials before active Links.

---

# 37. External plugin limits

Default per-plugin process limits:

```text
IPC message: 1 MiB
Outstanding IPC requests: 1,024
Handles: 65,536
Shared-memory packet bytes: 64 MiB
Log events: 100 per second with 1,000 burst
Property events: 10,000 per second global process cap
Startup deadline: 10 seconds
Operation default deadline: caller-defined, capped by operation class
Heartbeat interval: provisional 5 seconds
Heartbeat timeout: provisional 15 seconds
Restart burst: 3 attempts
Restart backoff cap: 5 minutes
```

Invalid framing, handle conflicts, or oversize messages close plugin IPC.

Plugin crash releases all reservations for its process generation after UMC invalidates Links and shared-memory slots.

Repeated restarts cannot bypass cumulative CPU, process-start, or log limits.

---

# 38. Process and handle limits

UMC accounts:

```text
File descriptors
Sockets
Named pipes
Threads
Async tasks
Timers
Child processes
Mapped files
Database statements
```

The standard profile SHOULD reserve at least 20 percent of the OS file-descriptor limit for control, storage, diagnostics, and recovery.

Network listeners and Links cannot consume the reserve.

Async task creation MUST follow operation admission. A packet or frame cannot create an unbounded detached task.

Timers SHOULD use bounded timer wheels or heaps with one timer record per admitted object, not per untrusted field.

---

# 39. Local control API limits

Until `control-api.md` freezes exact values, UMC v0.1 uses these defaults:

```text
Length-prefixed protobuf envelope: 4 MiB
Ordinary request payload: 1 MiB
Concurrent requests per client: 64
Queued requests per client: 256
Requests per local application: 1,000 per minute
Requests per administrator: 10,000 per minute
Event stream backlog per client: 1,024 events or 4 MiB
Open event streams per client: 8
Registered protocol listeners per application: 64
Local API capability tokens per application: 32
```

Administrative bulk operations use explicit streaming or file handles rather than larger envelopes.

OS peer credentials and local bearer capabilities identify accounting scopes.

At `HIGH` pressure, UMC preserves authenticated administrative health and shutdown calls while reducing diagnostic and bulk event work.

---

# 40. Local application limits

Each application receives quotas for:

```text
Endpoints
Protocol listeners
Sessions
Streams
Pending writes
Datagrams
Event backlog
Discovery operations
Route requests
Bundle storage
```

Standard defaults:

| Resource | Default per application |
| --- | ---: |
| Endpoint handles | 16 |
| Protocol listeners | 64 |
| Active sessions | 256 |
| Active streams | 4,096 |
| Pending reliable write bytes | 128 MiB |
| Queued datagram bytes | 16 MiB |
| Discovery operations | 8 |
| Route requests | 64 concurrent |
| Event backlog | 1,024 events or 4 MiB |

Applications with smaller grants receive the grant value. Applications cannot increase quotas through repeated reconnects; accounting binds to credential principal.

---

# 41. Logging limits

Logs consume CPU, memory, storage, and operator attention.

Default limits:

```text
Repeated identical event per source: 10 per minute
Structured diagnostic field: 1 KiB
Remote reason text: protocol field limit, truncated to 256 bytes in logs
Plugin log event: 4 KiB
In-memory log queue: 16 MiB
Default rotated local logs: 256 MiB total
```

UMC aggregates suppressed counts.

At `HIGH` pressure, it drops Debug and Trace first. At `CRITICAL`, it preserves bounded Error, security, and lifecycle events.

Logging failure MUST NOT block packet processing or allocate an unbounded retry queue.

---

# 42. Metrics limits

Metrics MUST avoid unbounded label cardinality.

Default caps:

```text
Metric series: 10,000
Histogram buckets per metric: 64
Per-Link public labels: prohibited
Per-peer public labels: prohibited
Exporter response: 8 MiB
Metrics snapshot frequency: 1 second minimum
```

When series capacity fills, UMC aggregates into subsystem and error-class metrics.

Metrics collection cannot retain packet, endpoint, route, or circuit objects past normal lifecycle.

---

# 43. Event bus limits

Internal and local-client event buses use bounded queues.

Each event type declares:

```text
priority
maximum encoded size
coalescing key
drop or disconnect policy
```

State snapshots may replace repeated property updates.

UMC MUST NOT drop security-critical revocation, key-store failure, or terminal session events without marking the consumer out of sync.

A slow local client loses low-priority events or receives stream closure. It cannot stall daemon operation.

---

# 44. Cache classes

UMC assigns cached state to:

```text
ESSENTIAL
RECOVERABLE
OPPORTUNISTIC
DISPOSABLE
```

Examples:

| Class | State |
| --- | --- |
| `ESSENTIAL` | Trust records, revocations, identity metadata, active session invariants |
| `RECOVERABLE` | Successful peer hints, active route candidates, resumption tickets |
| `OPPORTUNISTIC` | Extra diverse routes, discovery candidates, negative lookup cache |
| `DISPOSABLE` | Debug history, expired replay metadata, sampled diagnostics |

Pressure eviction removes `DISPOSABLE`, then `OPPORTUNISTIC`, then stale `RECOVERABLE` state.

UMC does not evict `ESSENTIAL` state to admit remote work. It rejects work or fails closed.

---

# 45. Memory eviction order

At memory pressure, UMC applies:

1. Expired timers, cache entries, and replay records.
2. Disposable diagnostics and metrics detail.
3. Expired datagrams and background packets.
4. Duplicate and low-value discovery candidates.
5. Failed and redundant route candidates.
6. Idle untrusted pending handshakes.
7. Optional candidate paths.
8. Background relay queues and circuits under policy.
9. Idle low-priority sessions through orderly close.

UMC MUST NOT discard accepted reliable stream bytes while keeping the stream active.

Before closing an established session, UMC SHOULD apply backpressure, withhold new credit, and release optional cache state.

---

# 46. Load shedding

Pressure states use these default actions:

| Subsystem | `ELEVATED` | `HIGH` | `CRITICAL` | `EMERGENCY` |
| --- | --- | --- | --- | --- |
| Handshake | Early Retry | Require Retry more often | Reject low-trust opens | Stop new opens |
| Session | Slow window growth | Withhold new credit | Reject new sessions | Close lowest-policy idle sessions if required |
| Discovery | Reduce background scans | Stop background scans | Trusted recovery only | Stop |
| Routing | Reduce fanout | Fanout one for low trust | Recovery requests only | Stop new requests |
| Relay | Reject low-trust opens | Reject new public opens | Stop all opens; shed background | Emergency close if required |
| Bundles | Reject low priority | Evict eligible bundles | Reject all new bundles | Stop bundle I/O except recovery |
| Plugins | Reduce discovery and logs | Stop speculative work | Disable unhealthy plugins | Terminate optional plugins |
| Control API | Reduce bulk diagnostics | Bound event detail | Health and admin recovery reserve | Shutdown and recovery only |

Actions may start sooner when one subsystem exhausts its own budget.

---

# 47. Fairness

UMC SHOULD schedule within a priority class using weighted fair queues or deficit round robin.

Fairness dimensions include:

```text
Local application
Authenticated peer
Source context
Session
Stream
Carrier
Relay circuit
Route destination partition
```

One principal's unused quota MAY serve others while global pressure stays below `HIGH`. Borrowed capacity creates no future entitlement.

At least 5 percent of new authenticated admission capacity SHOULD remain available to low-rate new peers so established peers cannot occupy every slot.

---

# 48. Trust and quota policy

Default trust multipliers apply to eligible work:

| Trust state | Rate multiplier | State multiplier |
| --- | ---: | ---: |
| `Unknown` | 0.25 | 0.25 |
| `Observed` | 1 | 1 |
| `Introduced` | 4 | 2 |
| `Trusted` | 10 | 4 |
| `Restricted` | explicit | explicit |
| `Blocked` | 0 | 0 |
| `Revoked` | 0 | 0 |

Multipliers do not exceed global or subsystem hard limits.

Cryptographic authentication alone moves no peer above `Observed`.

Introduction grants may define lower or narrower quotas than the default multiplier.

---

# 49. Policy conflicts

The resource manager resolves conflicting limits by choosing the smallest effective value.

Examples:

* Application requests 1,000 streams; peer negotiated 100; local session hard limit is 64. Effective limit is 64.
* Trusted peer receives fourfold state multiplier; global session capacity has ten slots. It can use at most ten additional slots.
* Relay authorization grants 1 GiB; circuit byte hard limit is 256 MiB. Granted circuit limit is 256 MiB.

UMC MUST report the effective local grant without exposing unrelated global usage or other principals' limits.

---

# 50. Rejection behavior

Before peer authentication, UMC SHOULD use silent drop, Retry, or generic errors according to handshake and private-carrier policy.

After authentication, modules may return:

```text
RESOURCE_LIMIT
FLOW_CONTROL_ERROR for peer violations
STORAGE_LIMIT
RELAY_REFUSED
POLICY_REJECTED
Local WOULD_BLOCK or QUEUE_FULL
```

Resource exhaustion caused by local pressure is not a peer protocol violation.

UMC MUST distinguish:

* Peer exceeded an advertised or granted protocol limit
* Local node declined new work within protocol rights
* Local system failed to honor work it had accepted

The third case requires explicit failure of the affected stream, session, circuit, or operation.

---

# 51. Configuration safety

Configuration exposes:

```text
profile selection
subsystem hard and soft limits
principal overrides
storage quotas
bandwidth rates
pressure actions
OS integration limits
```

UMC MUST validate:

* Soft limit below hard limit
* Reserved control capacity within hard budget
* Per-object maxima compatible with global budget
* Minimum protocol state sufficient for enabled features
* Storage reserve below filesystem quota
* Queue totals below managed memory budget

The daemon MUST refuse configuration that guarantees immediate hard-limit violation or removes required protocol safety bounds.

Runtime reductions may require graceful draining. UMC reports pending convergence and deadline.

---

# 52. Restart and persistence

Token buckets and abuse counters MAY persist across restart when policy needs resistance to restart evasion.

Persisted accounting MUST:

* Have bounded cardinality
* Include expiry
* Validate schema and values
* Avoid wall-clock extension after rollback
* Exclude packet-level and live-session reservations

Live memory, handle, queue, and operation reservations reset after restart because UMC does not restore live sessions or circuits.

Persistent storage quotas recalculate from validated database and object state before new bundle admission.

---

# 53. Observability

UMC MUST expose:

```text
Current and hard usage by resource class
Pressure state and duration
Admission, backpressure, eviction, and rejection counts
Top bounded subsystem consumers
Quota exhaustion by trust and operation class
Reserved control capacity
Storage reserve health
Plugin and carrier queue health
```

Diagnostics MUST avoid stable public peer or application labels.

`umc doctor` SHOULD detect:

* Limits below feature minimums
* Queues that remain above soft limits
* Leaked reservations
* Storage reserve loss
* Repeated pressure oscillation
* OS limits below configured needs

---

# 54. Security considerations

## 54.1 Limit-state exhaustion

Attackers may create many accounting identities. UMC bounds detailed buckets and falls back to aggregate unknown-source accounting.

## 54.2 Distributed low-rate attack

Per-peer limits do not stop many independent sources. Global and subsystem budgets preserve bounds; honest work may still fail.

## 54.3 Trust abuse

A compromised Trusted peer receives larger default quotas. Global limits, destination policy, and abuse response remain active.

## 54.4 Priority abuse

Remote priority fields are hints. UMC authorizes priority and caps each priority share.

## 54.5 Storage fill

Bundle, log, and cache quotas reserve capacity for trust, revocation, and migration transactions. Filesystem exhaustion outside UMC may still remove the reserve.

## 54.6 Accounting overflow

Counters use checked or saturating arithmetic. Overflow cannot reset usage or grant new capacity.

## 54.7 Cleanup attacks

Eviction and garbage collection consume CPU and database work. UMC budgets cleanup, batches deletions, and rejects new work before cleanup loops threaten availability.

## 54.8 Information leakage

Detailed quota errors can reveal load and policy. Network responses use coarse errors; local authorized diagnostics provide detail.

---

# 55. Required tests

A compliant implementation MUST test:

1. Limit hierarchy and smallest-value resolution.
2. Reservation commit, cancellation, timeout, and release.
3. Pressure entry, hysteresis, and recovery.
4. Control-capacity reservation under data flood.
5. Token-bucket refill, saturation, and clock changes.
6. Unknown-source bucket cardinality.
7. CPU and cryptographic work admission.
8. Pending-handshake Retry thresholds.
9. Amplification accounting.
10. Session and stream-count exhaustion.
11. Sparse stream-offset and reassembly pressure.
12. ACK-range and packet-number gaps.
13. Datagram queue overflow and expiry.
14. Path and connection-ID churn.
15. Peer-store and discovery eviction.
16. Routing request flood and fanout reduction.
17. Relay open, queue, byte, and bandwidth quotas.
18. Bundle storage fill and custody-aware eviction.
19. Database write-queue saturation.
20. Carrier and plugin queue exhaustion.
21. Plugin crash releasing reservations.
22. Local API request and event-stream flood.
23. Log and metric cardinality flood.
24. OS file-descriptor reserve.
25. Runtime configuration reduction and draining.
26. Restart with persisted quotas and cleared live reservations.
27. Combined cross-subsystem resource attack.
28. `EMERGENCY` operation with allocator and disk failures.

Property tests SHOULD verify:

```text
Usage never exceeds a configured hard limit through admitted allocations.
Every successful reservation receives one release.
Counters never wrap to a smaller value.
Remote grants never increase local hard limits.
Advertised flow-control limits never decrease.
Unauthenticated work cannot consume control reserve.
One principal cannot create unbounded accounting state.
Eviction never discards accepted reliable data while its stream stays active.
```

---

# 56. Interoperability requirements

Local resource defaults do not affect UMP interoperability when a node:

* Advertises only limits it can honor
* Enforces protocol maxima
* Uses defined errors or backpressure
* Preserves state invariants
* Avoids insecure fallback

A compliant UMP/1 implementation MUST support peers that advertise smaller valid limits.

It MUST NOT assume the defaults in this document represent remote capacity.

---

# 57. Open decisions

The project must resolve these items before stable v0.1:

1. Final managed-memory budgets for Tier-1 platforms.
2. Per-object memory accounting overhead method.
3. CPU work-unit calibration procedure.
4. OS CPU and memory enforcement integration.
5. Unknown-source aggregation keys per carrier.
6. Default Initial and maximum stream flow-control windows.
7. Maximum automatic connection receive window.
8. ACK-range retention beyond wire frame limit.
9. Default active connection-ID grant.
10. Final peer-store and route-cache sizes.
11. Relay-profile circuit and bandwidth defaults.
12. Bundle quotas and custody-aware eviction.
13. Database critical free-space reserve.
14. Control API envelope and per-client rates.
15. Plugin heartbeat and process-start costs.
16. Event-bus critical delivery behavior.
17. Trust multipliers and Sybil grouping.
18. Pressure actions that may close active sessions.
19. Mobile and battery-specific profile.
20. Metrics required to validate production limits.

---

# 58. Recommended implementation order

Implement resource control in this order:

1. Checked counters and reservation types.
2. Global and subsystem hard budgets.
3. Per-peer, source, and application scopes.
4. Token buckets and bounded bucket store.
5. Packet and handshake admission.
6. Session, stream, and queue accounting.
7. Routing and discovery accounting.
8. Relay accounting.
9. Carrier and plugin accounting.
10. Storage and bundle quotas.
11. Control API and event limits.
12. Pressure states and hysteresis.
13. Eviction and load shedding.
14. Metrics and `umc doctor` checks.
15. Fault injection and adversarial soak tests.

---

# 59. Core rule

UMC reserves resources before accepting work, charges each reservation to all applicable scopes, and rejects work before any hard limit would be exceeded.

Protocol maxima bound hostile syntax. Local quotas bound admitted state. Global budgets bound the node. Under pressure, UMC removes speculative work and applies backpressure before it sacrifices established reliable state or security-critical control capacity.
