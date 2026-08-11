# Universal Mesh Core Carrier API Specification

**Status:** Draft
**Version:** 0.1
**Document:** Carrier Interface and Link Contract
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines the interface between UMC and communication carriers.

It specifies:

* Carrier registration and lifecycle
* Carrier capabilities
* Peer candidates
* Discovery integration
* Listener, dial, and accept behavior
* Link lifecycle
* Packet send and receive contracts
* Reliable, unreliable, ordered, and unordered behavior
* MTU and framing
* Backpressure
* Error mapping
* Carrier binding
* Path identity
* Metrics and property updates
* Built-in and external carrier boundaries
* Plugin IPC requirements

Carrier profiles define protocol-specific behavior for TCP, UDP, LAN discovery, Bluetooth, radio, or other media.

This document does not define:

* UMP packet encoding
* Endpoint authentication
* Session retransmission or congestion control
* Route selection
* Application APIs
* Full external plugin message encoding

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

This document defines a UMC software boundary. Independent UMP implementations may use another language or API while preserving carrier-profile behavior visible on the network.

---

# 3. Carrier boundary

A carrier transfers complete UMP packets between adjacent nodes.

A carrier owns:

* Medium access
* Carrier-specific addressing
* Packet boundary restoration
* Listener and dialing mechanics
* Carrier-level authentication or encryption, when present
* Carrier errors
* Local delivery properties and measurements
* Optional discovery for its medium

UMC owns:

* Endpoint identities and private keys
* UMP handshakes
* Session encryption
* Packet numbers
* Streams and datagrams
* Routing and relaying
* End-to-end loss recovery
* Policy decisions

A carrier MUST NOT parse, alter, prioritize by, or log encrypted UMP frame contents.

Carrier encryption supplements UMP session encryption. It cannot replace it.

---

# 4. Terminology

## 4.1 Carrier type

A Carrier Type identifies a protocol or medium profile, such as `ump.tcp/1` or `ump.udp/1`.

## 4.2 Carrier instance

A Carrier Instance is one configured runtime object for a Carrier Type. Two instances may use different interfaces, accounts, devices, ports, or privacy policy.

## 4.3 Listener

A Listener accepts inbound carrier relationships.

## 4.4 Peer candidate

A Peer Candidate contains enough scoped information to attempt a carrier connection. It does not establish endpoint identity or trust.

## 4.5 Link

A Link transfers UMP packets between adjacent UMC nodes through one Carrier Instance.

## 4.6 Carrier packet

A Carrier Packet contains one complete UMP packet after the carrier restores boundaries.

## 4.7 Link property

A Link Property describes observed or configured delivery behavior, cost, scope, or capacity.

---

# 5. Stable identifiers

## 5.1 Carrier Type ID

A Carrier Type ID is a UTF-8 string from 1 through 64 bytes.

Recommended form:

```text
ump.tcp/1
ump.udp/1
ump.lan-discovery/1
org.example.radio/2
```

The identifier MUST use lowercase ASCII letters, digits, `.`, `-`, and `/` in stable profiles.

Private profiles may use:

```text
x-<organization>.<name>/<version>
```

The type version names carrier-profile compatibility. It does not name UMP protocol version.

The complete registry of carrier types, including planned and possible carriers, is defined in `carriers/registry.md`.

## 5.2 Carrier Instance ID

UMC assigns each configured instance an opaque local identifier.

An Instance ID:

* MUST remain unique within one node runtime
* MUST NOT appear on the network unless the carrier profile requires a scoped derivative
* MUST NOT contain secret configuration
* MAY change after restart

## 5.3 Link ID

UMC assigns each accepted or dialed link an opaque local Link ID.

Link IDs are unique among live and draining links. They have no protocol meaning and MUST NOT serve as endpoint identity.

---

# 6. Carrier lifecycle

A Carrier Instance uses these states:

```text
CREATED
STARTING
RUNNING
DEGRADED
STOPPING
STOPPED
FAILED
DISABLED
```

## 6.1 CREATED

UMC loaded and validated configuration but has not acquired carrier resources.

## 6.2 STARTING

The carrier acquires sockets, devices, credentials, or plugin process state.

## 6.3 RUNNING

The carrier may listen, dial, discover, and maintain links according to capabilities and policy.

## 6.4 DEGRADED

The carrier remains usable with reduced capacity or missing optional functions.

Examples include unavailable discovery, reduced MTU, or one failed network interface.

## 6.5 STOPPING

The carrier rejects new operations and closes listeners. Policy decides whether active links drain or close at once.

## 6.6 STOPPED

The carrier released runtime resources. UMC may start it again.

## 6.7 FAILED

An unrecoverable instance error stopped operations. UMC may restart it under policy.

## 6.8 DISABLED

Configuration or operator policy prohibits startup.

State changes MUST produce a structured event.

---

# 7. Carrier interface

The Rust reference implementation SHOULD expose an interface equivalent to:

```rust
pub trait Carrier: Send + Sync {
    fn type_id(&self) -> CarrierTypeId;
    fn instance_id(&self) -> CarrierInstanceId;
    fn capabilities(&self) -> CarrierCapabilities;

    async fn start(&self, ctx: StartContext) -> Result<(), CarrierError>;
    async fn stop(&self, mode: StopMode) -> Result<(), CarrierError>;

    async fn listen(&self, request: ListenRequest)
        -> Result<Box<dyn Listener>, CarrierError>;

    async fn dial(&self, request: DialRequest)
        -> Result<Box<dyn Link>, CarrierError>;

    async fn discover(&self, request: DiscoveryRequest)
        -> Result<Box<dyn CandidateStream>, CarrierError>;
}
```

An implementation may split discovery into a separate provider object.

Every asynchronous operation MUST support cancellation and a monotonic deadline.

Cancellation MUST leave the carrier in a defined state and release operation-specific resources.

---

# 8. Capabilities

`CarrierCapabilities` contains static or slowly changing type information:

```text
api_version
carrier_type
packet_mode
reliability
ordering
connection_model
supports_listen
supports_dial
supports_discovery
supports_broadcast
supports_multicast
supports_path_migration
supports_address_rebinding
supports_outer_encryption
supports_carrier_authentication
supports_anti_probing
supports_traffic_shaping
minimum_packet_size
maximum_packet_size
address_stability
scope_classes
cost_classes
```

The carrier MUST report unsupported features as false. It MUST NOT infer support from configuration that failed to start.

Link-specific values override type-level estimates for one link.

## 8.1 Packet mode

UMP/1 defines:

```text
DATAGRAM
STREAM_FRAMED
MESSAGE
RAW_FRAMED
```

## 8.2 Reliability

UMP/1 defines:

```text
UNRELIABLE
RELIABLE_UNTIL_LINK_FAILURE
PROFILE_DEFINED
```

`RELIABLE_UNTIL_LINK_FAILURE` means the carrier reports accepted packets in order without silent loss while the link remains healthy. It does not guarantee delivery after process, device, or link failure.

## 8.3 Ordering

UMP/1 defines:

```text
UNORDERED
ORDERED
PROFILE_DEFINED
```

Ordering applies only to packets accepted by one Link in one direction.

## 8.4 Connection model

UMP/1 defines:

```text
CONNECTED
CONNECTIONLESS_ASSOCIATION
SHARED_CHANNEL
INTERMITTENT
```

The model informs resource management. UMC still receives one Link object per adjacent communication context.

---

# 9. Link interface

The reference implementation SHOULD expose:

```rust
pub trait Link: Send + Sync {
    fn id(&self) -> LinkId;
    fn carrier_type(&self) -> CarrierTypeId;
    fn carrier_instance(&self) -> CarrierInstanceId;
    fn properties(&self) -> LinkProperties;
    fn binding_input(&self) -> CarrierBindingInput;

    async fn send(&self, packet: OutboundPacket)
        -> Result<SendReceipt, LinkError>;

    async fn recv(&self)
        -> Result<InboundPacket, LinkError>;

    async fn close(&self, reason: LinkCloseReason)
        -> Result<(), LinkError>;

    async fn events(&self)
        -> Result<Box<dyn LinkEventStream>, LinkError>;
}
```

The concrete API MAY use channels instead of `recv()` and `events()`. It must preserve ownership, ordering, cancellation, and close semantics.

---

# 10. Link lifecycle

A Link uses these states:

```text
CONNECTING
ACCEPTED
ACTIVE
DEGRADED
DRAINING
CLOSED
FAILED
```

## 10.1 CONNECTING

The carrier performs dialing or inbound setup. UMC has no packet-delivery guarantee.

## 10.2 ACCEPTED

Carrier setup succeeded and the Link object exists. UMP authentication has not completed.

## 10.3 ACTIVE

The carrier can send and receive complete UMP packets.

## 10.4 DEGRADED

The link remains active under reduced MTU, increased loss, backpressure, or another property change.

## 10.5 DRAINING

The link rejects new sends but may deliver accepted outbound packets and inbound packets already received.

## 10.6 CLOSED

The carrier completed an orderly close.

## 10.7 FAILED

An error ended packet delivery.

The carrier MUST emit one terminal event. Repeated close calls MUST be idempotent.

---

# 11. Listener contract

A Listener represents one bound inbound carrier endpoint.

```rust
pub trait Listener: Send + Sync {
    fn id(&self) -> ListenerId;
    fn local_hint(&self) -> Option<ScopedCarrierHint>;
    async fn accept(&self) -> Result<Box<dyn Link>, CarrierError>;
    async fn close(&self) -> Result<(), CarrierError>;
}
```

`accept()` returns one Link after carrier setup reaches `ACCEPTED`.

The carrier MUST apply listener-level rate, packet-size, and source-context limits before returning a Link.

An accepted Link does not imply:

* UMP endpoint authentication
* Authorization
* Trust
* Relay permission
* Shared node identity with another Link

The listener MUST support cancellation without leaking a pending Link.

---

# 12. Listen request

`ListenRequest` includes:

```text
local binding selector
carrier profile
scope
privacy mode
maximum pending links
deadline
policy handle
profile-specific options
```

UMC validates policy before the carrier sees the request.

The carrier validates profile-specific options and rejects unknown critical options.

Sensitive listener configuration MUST remain outside public peer hints.

---

# 13. Dial request

`DialRequest` includes:

```text
Peer Candidate
carrier profile
deadline
privacy mode
path policy handle
expected property constraints
profile-specific options
```

The carrier MUST bind the dial attempt to one candidate. It MUST NOT substitute another remote target without an authenticated redirect that the profile and UMC policy permit.

The carrier returns a Link after carrier-level setup. UMP performs endpoint authentication over that Link.

A successful dial proves carrier reachability to the candidate context. It does not prove the expected endpoint owns that context.

---

# 14. Peer candidates

A `PeerCandidate` contains:

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

## 14.1 Candidate ID

Candidate ID is an opaque local handle. It MUST NOT act as endpoint identity.

## 14.2 Connection hint

Connection Hint contains carrier-specific dialing data. The carrier profile defines its canonical encoding and maximum size.

The generic limit is 1,024 bytes.

## 14.3 Source

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

## 14.4 Expiry

UMC MUST reject an expired candidate before dialing. A carrier MAY reject it sooner when its addressing context changed.

## 14.5 Sharing policy

Sharing policy defines whether UMC may:

* Use candidate locally
* Share with selected peers
* Share within local scope
* Share in general scope
* Persist it

`DO_NOT_RESHARE` prohibits forwarding the connection hint.

## 14.6 Authentication state

Candidate authentication records evidence about the hint, not the endpoint behind it.

Values include:

```text
UNAUTHENTICATED
CARRIER_AUTHENTICATED
INTRODUCTION_AUTHENTICATED
INVITATION_AUTHENTICATED
PREVIOUS_SESSION_BOUND
```

---

# 15. Discovery interface

A carrier with native discovery MAY implement `discover()`.

`DiscoveryRequest` includes:

```text
scope
deadline
maximum_candidates
privacy mode
profile-specific selector
policy handle
```

The carrier emits a bounded stream of candidate events:

```text
FOUND
UPDATED
EXPIRED
REMOVED
ERROR
COMPLETE
```

Each event identifies one Candidate ID.

The carrier MUST:

* Enforce `maximum_candidates`
* Stop on cancellation or deadline
* Validate native message sizes before allocation
* Mark source and authentication state
* Avoid interpreting discovery as endpoint trust

UMC merges carrier results with other discovery providers.

---

# 16. Packet boundary contract

The carrier delivers one complete UMP packet in each `InboundPacket`.

It MUST NOT:

* Deliver partial UMP packets
* Concatenate packets without restoring boundaries
* Strip or alter UMP bytes
* Add carrier framing bytes to the delivered packet
* Deliver a packet above the active Link MTU

Datagram carriers map one datagram to one UMP packet unless their profile defines another authenticated encapsulation.

Stream carriers use a canonical packet-length prefix from `wire-format.md`.

Raw carriers define delimiting, escaping, integrity, and resynchronization in their profile.

---

# 17. Outbound packet ownership

`OutboundPacket` contains:

```text
immutable packet bytes
packet length
send class
deadline or no deadline
path handle
```

The packet buffer remains owned by UMC until `send()` returns.

A successful `send()` returns a `SendReceipt` and transfers responsibility for carrier delivery to the Link.

A successful receipt means:

* The Link accepted the complete packet
* The caller may release its input buffer
* The carrier will send it or report terminal Link failure through events

It does not mean the remote peer received, authenticated, or acknowledged the packet.

A failed send leaves ownership with the caller and MUST NOT send a partial packet.

---

# 18. Send receipts

`SendReceipt` contains:

```text
link_local_send_id
accepted_length
accepted_at_monotonic
queue_state
```

`link_local_send_id` supports diagnostics. It MUST NOT appear on the network or enter UMP retransmission logic.

Queue State values:

```text
SENT_TO_MEDIUM
QUEUED_BOUNDED
PROFILE_DEFINED
```

Reliable carriers SHOULD report delivery-to-medium or kernel acceptance through Link events when available. UMC must not interpret that event as peer delivery.

---

# 19. Receive contract

`InboundPacket` contains:

```text
immutable packet bytes
received_at_monotonic
link_id
observed_path_context
explicit congestion indication
profile metadata
```

The carrier MUST validate carrier framing and profile limits before delivery.

UMC owns the received buffer after `recv()` returns or after the callback completes according to the concrete API.

Profile Metadata MUST contain only registered, bounded fields. It MUST NOT contain secret carrier credentials.

The carrier may deliver duplicate or reordered packets according to declared properties. UMP handles replay and packet ordering.

---

# 20. Backpressure

The Link MUST provide bounded send acceptance.

`send()` may:

* Await capacity until deadline
* Return `WOULD_BLOCK`
* Return `QUEUE_FULL`
* Return a terminal error

It MUST NOT accept an unbounded number of packets or bytes.

Each Carrier Instance defines:

```text
maximum queued packets per link
maximum queued bytes per link
maximum queued bytes per instance
control-reserve capacity
```

UMC assigns control traffic to the reserved class. The carrier still enforces hard bounds.

When queue capacity returns, the Link emits `WRITABLE` or wakes blocked send operations.

A Link MUST preserve acceptance order when it declares `ORDERED`. It may schedule control packets ahead of application packets only when its carrier profile preserves UMP packet semantics and documents the behavior.

---

# 21. Receive backpressure

UMC MUST bound inbound queues. The carrier interface must let UMC pause or limit receive delivery when the concrete medium permits it.

For flow-controlled stream carriers, the carrier SHOULD stop reading from the medium when inbound capacity ends.

For datagram or broadcast carriers, the carrier MAY drop packets before UMC accepts them. It MUST report drop counters and MUST NOT allocate beyond configured receive budgets.

The carrier SHOULD preserve capacity for handshake, ACK, close, and path-control packets when it can classify them without decrypting payload. It MUST NOT inspect encrypted frames to do so.

---

# 22. MTU

Each active Link reports:

```text
minimum_packet_size
current_maximum_packet_size
maximum_supported_packet_size
mtu_confidence
```

These sizes cover the complete UMP packet passed through the API and exclude carrier framing.

`current_maximum_packet_size` is the largest packet the Link accepts at that time.

The carrier MUST reject larger packets with `PACKET_TOO_LARGE` before ownership transfer.

## 22.1 MTU changes

The Link emits `MTU_CHANGED` before accepting only the new limit when the limit decreases.

Packets accepted under the previous limit remain the carrier's responsibility. If the medium can no longer send them, the Link reports their loss through a property or failure event and preserves packet atomicity.

An MTU increase becomes usable after the event.

## 22.2 Path MTU discovery

Carrier profiles may perform native path MTU discovery. UMP may also probe packet size.

The carrier MUST distinguish:

* Configured interface MTU
* Profile framing limit
* Measured path limit
* Unknown limit

For UDP, the initial maximum is 1,200 bytes until profile rules permit an increase.

---

# 23. Link properties

`LinkProperties` contains bounded observations:

```text
reliability
ordering
scope
address_stability
estimated_rtt
estimated_loss
estimated_bandwidth
current_mtu
queue_bytes
queue_capacity
energy_cost
monetary_cost
metered
broadcast
outer_encryption
carrier_authentication
local_interface_class
```

Every property records:

```text
value
source
confidence
observed_at
valid_until or no expiry
```

Property Source values include:

```text
PROFILE
CONFIGURATION
OPERATING_SYSTEM
MEASUREMENT
REMOTE_CLAIM
```

Routing and congestion logic MUST treat remote claims as untrusted.

---

# 24. Property events

The Link emits:

```text
ACTIVE
WRITABLE
MTU_CHANGED
QUALITY_CHANGED
ADDRESS_REBOUND
LOCAL_INTERFACE_CHANGED
REMOTE_CONTEXT_CHANGED
DEGRADED
CLOSING
CLOSED
FAILED
```

Each event includes a monotonic sequence number. Sequence starts at zero and increases by one.

UMC MUST reject or log a plugin event that reuses a sequence with different content.

Property events are advisory except terminal state, MTU acceptance limit, and explicit backpressure state.

---

# 25. Reliable and ordered carriers

A carrier that declares `RELIABLE_UNTIL_LINK_FAILURE` MUST:

* Preserve each accepted packet without silent loss while the Link remains healthy
* Report terminal failure when it cannot meet that guarantee
* Bound its queues
* Preserve packet boundaries

An `ORDERED` carrier delivers accepted packets in send order for one direction unless Link failure interrupts delivery.

UMP retains packet numbers, ACKs, flow control, replay defense, and end-to-end probe timeouts over these carriers.

The carrier MUST NOT suppress UMP packets because it believes them redundant.

---

# 26. Unreliable and unordered carriers

An `UNRELIABLE` carrier may lose accepted packets without a per-packet failure event.

An `UNORDERED` carrier may deliver packets in any order.

The carrier SHOULD report aggregate loss, queue drops, and medium errors when available.

It MUST preserve packet atomicity. Partial delivery appears as packet loss.

The carrier MAY duplicate packets. UMP rejects duplicates through packet-number replay state.

---

# 27. Carrier-level congestion and pacing

The carrier reports medium backpressure and queue state. UMP controls network-safe send allowance under the congestion specification.

A carrier MAY pace packets when its medium requires it. It MUST expose pacing delay and queue capacity so UMP avoids hidden, unbounded queues.

Shared-channel carriers MUST enforce access rules and per-Link fairness before medium transmission.

The carrier MUST NOT interpret UMP congestion state or forge congestion feedback.

---

# 28. Carrier binding

The handshake binds its initial exchange to carrier context as defined in `handshake.md`.

The carrier returns `CarrierBindingInput`:

```text
binding_version
carrier_type_id
profile_id
binding_kind
instance_data
security_properties
```

UMC computes:

```text
CarrierBinding = BLAKE2s-256(
    "UMP-CARRIER-BINDING-v1" ||
    canonical(CarrierBindingInput)
)
```

## 28.1 Binding kinds

UMP/1 defines:

```text
PROFILE_ONLY
CHANNEL_EXPORTER
LOCAL_LINK_CONTEXT
PRIVATE_ADMISSION_CONTEXT
NONE
```

`PROFILE_ONLY` binds the handshake to carrier type and profile.

`CHANNEL_EXPORTER` includes a carrier security exporter, such as a TLS exporter.

`LOCAL_LINK_CONTEXT` includes a stable link-layer context permitted by the carrier profile.

`PRIVATE_ADMISSION_CONTEXT` binds private bridge or invitation admission.

`NONE` uses zero-length Instance Data and reports that the carrier supplies no secure instance binding.

## 28.2 Stability

Binding Input MUST remain stable for the initial handshake.

It MUST exclude transient values that would prevent valid UMP path migration, including current queue size, measured RTT, and local ephemeral Link ID.

New paths perform session path validation and may use a path-specific binding without repeating endpoint identity authentication.

## 28.3 Secrets

The carrier MUST NOT return exporter master secrets or long-term credentials. It returns only derived binding bytes intended for UMP transcript use.

---

# 29. Path identity

The carrier supplies a `PathContext` for each Link.

```text
carrier_type
carrier_instance
local_context
remote_context
channel_context
scope
generation
```

The fields are opaque to UMP modules that do not need carrier policy.

`generation` increases when carrier rebinding changes the delivery context while preserving the Link object.

Path Context MUST NOT contain endpoint identity or become a trust anchor.

UMC derives a local Path Handle from Link ID and generation. Path Handle never appears on the network.

The session layer assigns UMP Path IDs and validates reachability. Carrier Path Context cannot replace `PATH_CHALLENGE` and `PATH_RESPONSE`.

---

# 30. Address rebinding

Connectionless carriers may observe a new remote address for authenticated UMP packets.

The carrier reports `REMOTE_CONTEXT_CHANGED` and a new generation. It MUST NOT accept unauthenticated address changes as peer identity changes.

The session layer decides whether to validate and adopt the new path.

Before validation, the carrier and session enforce anti-amplification limits for the new source context.

A stream carrier that reconnects creates a new Link. It does not rebind an old Link unless its carrier profile defines continuity with secure channel binding.

---

# 31. Scope classification

Carrier scope values include:

```text
LOOPBACK
LINK_LOCAL
LOCAL_NETWORK
PRIVATE_OVERLAY
GENERAL_NETWORK
UNKNOWN
```

Scope is a policy input. It does not establish trust or physical location.

The carrier reports its evidence and confidence. UMC may override or narrow scope through configuration.

A carrier MUST NOT classify a path as local based only on a private IP address, SSID name, Bluetooth device name, or remote claim.

`LOCAL_SCOPE_ONLY` routing uses the effective UMC policy classification.

---

# 32. Cost reporting

The carrier reports cost classes:

```text
UNMETERED
METERED
EXPENSIVE
ENERGY_CONSTRAINED
OPERATOR_DEFINED
UNKNOWN
```

It may also report bounded numeric estimates with units and expiry.

Cost data informs policy and ranking. It does not alter UMP protocol semantics.

A remote peer cannot set local monetary or energy cost.

---

# 33. Error model

Carrier operations return structured errors:

```text
category
code
operation
retryability
scope
message
source_error
retry_after
```

## 33.1 Categories

UMP/1 Carrier API defines:

| Category | Meaning |
| --- | --- |
| `CANCELLED` | Caller cancelled operation |
| `DEADLINE_EXCEEDED` | Monotonic deadline ended |
| `INVALID_ARGUMENT` | Request or option failed validation |
| `UNSUPPORTED` | Carrier lacks requested feature |
| `POLICY_DENIED` | Local policy rejected operation |
| `NOT_RUNNING` | Carrier Instance cannot serve operation |
| `ADDRESS_INVALID` | Connection hint or bind selector is invalid |
| `ADDRESS_IN_USE` | Listener resource conflicts |
| `UNREACHABLE` | Carrier cannot reach candidate |
| `AUTHENTICATION_FAILED` | Carrier-level authentication failed |
| `PACKET_TOO_LARGE` | Packet exceeds current limit |
| `WOULD_BLOCK` | Link has no send capacity |
| `QUEUE_FULL` | Bounded queue reached hard limit |
| `LINK_CLOSED` | Operation targeted a closed Link |
| `LINK_FAILED` | Carrier failure ended Link |
| `DEVICE_UNAVAILABLE` | Required interface or device is unavailable |
| `PERMISSION_DENIED` | Operating system denied required access |
| `PROTOCOL_ERROR` | Carrier-profile peer behavior is invalid |
| `RESOURCE_LIMIT` | Instance or global carrier quota ended operation |
| `INTERNAL` | Carrier implementation failed |

## 33.2 Retryability

Retryability values:

```text
NO
SAME_LINK
NEW_LINK
AFTER_DELAY
AFTER_CONFIGURATION_CHANGE
UNKNOWN
```

UMC combines retryability with policy and deadlines. The carrier does not schedule unbounded retries by itself.

## 33.3 Source errors

Source Error may contain a bounded operating-system or library code for diagnostics. It MUST NOT cross the network or expose secrets.

---

# 34. Error mapping to UMP

Carrier errors do not map one-to-one to UMP transport errors.

UMC handles:

| Carrier result | UMC behavior |
| --- | --- |
| Dial `UNREACHABLE` | Mark route leg failed; try policy-permitted candidate |
| `PACKET_TOO_LARGE` | Reduce packet size or fail path probe |
| `WOULD_BLOCK` | Apply backpressure and wait for writable event |
| `QUEUE_FULL` | Apply backpressure; penalize path when persistent |
| Link terminal failure | Mark path failed; migrate session if possible |
| Carrier auth failure | Reject candidate; update scoped evidence |
| Profile protocol error | Close Link; do not expose raw error before UMP auth |
| Instance failure | Fail affected Links and restart under policy |

A carrier error MUST NOT authenticate a remote endpoint or revoke endpoint identity.

Diagnostics must distinguish carrier observation from remote UMP claims.

---

# 35. Timeouts and cancellation

UMC passes monotonic deadlines to listen setup, dial, discovery, send, close, and plugin requests.

The carrier MUST stop operation-specific work after cancellation or deadline.

It MAY finish a non-cancellable operating-system call in the background, but it MUST prevent late success from creating an unowned Listener or Link.

A cancelled dial that later connects must close the carrier connection.

A cancelled send returns failure only when ownership did not transfer. If ownership transferred before cancellation, it returns success and the Link remains responsible.

---

# 36. Concurrency

The API permits concurrent:

* Sends on one Link
* One receive consumer and one event consumer per Link
* Dials and listener accepts on one Carrier Instance
* Discovery with other operations

The carrier MUST serialize externally visible state transitions.

For an `ORDERED` Link, concurrent sends use acceptance order assigned by the Link.

The concrete API MUST prevent two receive consumers from consuming the same packet unless it defines explicit fanout outside the Carrier API.

Close may race with send and receive. Each operation returns one stable result under the ownership rules.

---

# 37. Configuration

Carrier configuration separates:

```text
public options
sensitive options
runtime overrides
profile defaults
```

Public options may include bind selectors, packet limits, and scope policy.

Sensitive options include credentials, private bridge secrets, device access tokens, and proxy authentication.

The carrier receives only configuration for its own instance.

Configuration validation MUST:

* Reject unknown critical fields
* Enforce sizes and types
* Avoid network access unless validation mode permits it
* Redact sensitive values from errors and logs

Runtime changes report whether they require listener restart, new Links, or full instance restart.

---

# 38. Built-in carriers

Trusted first-party carriers may run in the daemon process.

UMP/1 stable built-in carrier profiles are:

```text
TCP
UDP
LAN discovery
```

Built-in carriers use the same logical contract as external carriers.

The stable carrier profiles are documented in `carriers/tcp.md`, `carriers/udp.md`, and `carriers/lan-discovery.md`. The experimental TLS profile is documented in `carriers/tls-stream.md`.

They MUST NOT access endpoint private keys or decrypted application payloads through the Carrier API.

The LAN discovery carrier supplies candidates. It does not create application Links unless its profile later defines that function.

---

# 39. External carrier boundary

Third-party and experimental carriers run as separate processes in UMC v0.1.

UMC MUST NOT load arbitrary carrier dynamic libraries into the daemon.

An external carrier receives:

* Opaque UMP packet bytes
* Scoped candidates
* Link operations
* Its own configuration
* Bounded property and policy inputs

It MUST NOT receive:

* Endpoint private keys
* UMP session keys
* Decrypted application payloads
* Full peer or trust stores
* Bundle plaintext
* Administrative control credentials

Process isolation limits direct memory compromise. Operating-system sandboxing adds another boundary where available.

---

# 40. Plugin IPC overview

External carriers implement the Carrier Plugin Protocol over a local socket or pipe.

The process flow is:

```text
Spawn
IPC transport setup
Protocol hello
Version and capability negotiation
Configuration transfer
Start acknowledgement
Carrier operations
Health monitoring
Drain
Shutdown
```

`carrier-plugin-api.md` will define exact message encoding and state transitions.

This document requires these IPC properties:

* Length-prefixed messages
* Explicit API version
* Request and operation IDs
* Maximum message size
* Cancellation
* Bounded packet transfer
* Link and listener handles scoped to one plugin process
* Structured errors
* Heartbeats or health checks
* Crash detection
* No ambient daemon credentials

---

# 41. Plugin process lifecycle

UMC starts one plugin process per configured isolation unit. Policy may group instances from one trusted package.

The daemon MUST:

1. Create a private IPC endpoint.
2. Start the process with minimal arguments and environment.
3. Authenticate the process through an inherited handle or launch token.
4. Negotiate one compatible API version.
5. Send scoped configuration.
6. Apply startup deadline and message limits.
7. Monitor process and protocol health.
8. Close all plugin-owned Links after crash or protocol failure.

The plugin MUST NOT connect to an arbitrary daemon IPC endpoint discovered from the filesystem.

Repeated crashes cause backoff and disablement under operator policy.

---

# 42. Plugin handles

Plugin IPC uses opaque handles for:

```text
Carrier Instance
Listener
Discovery Operation
Candidate
Link
Send Operation
```

Handles are unique within one plugin process generation.

After process restart, old handles are invalid. The daemon MUST NOT bind old Link or send state to a new process.

The daemon and plugin reject unknown, expired, or cross-type handles without allocating new state.

---

# 43. Plugin packet transfer

Packet transfer may use:

* Bounded inline bytes
* Shared-memory regions with explicit ownership
* Platform message buffers

The negotiated method MUST preserve packet atomicity and ownership.

For shared memory:

* Each region has fixed size and generation
* One side owns a slot at a time
* Length is validated before access
* Slot reuse requires explicit release
* Process crash invalidates all slots

The plugin MUST NOT retain daemon-owned packet memory after release.

Default maximum IPC message is 1 MiB. Carrier packet limits remain smaller when the profile requires it.

---

# 44. Plugin health and crash behavior

The daemon marks a plugin unhealthy after:

* Process exit
* IPC closure
* Heartbeat timeout
* Invalid message framing
* Handle conflict
* Repeated deadline violation
* Declared fatal error

On failure, the daemon:

1. Rejects new operations.
2. Marks plugin Links failed.
3. Notifies session and routing layers.
4. Releases shared memory and handles.
5. Restarts under policy or disables the instance.

Plugin crash MUST NOT corrupt endpoint key, session, route, or storage state.

Sessions may migrate through another Carrier Instance.

---

# 45. Sandboxing expectations

UMC SHOULD apply platform controls:

```text
Linux: namespaces, seccomp, restricted filesystem and capabilities
macOS: sandbox profile where supported
Windows: restricted token, job object, and scoped filesystem access
```

The plugin receives only network, device, and filesystem access required by its carrier.

A carrier that provides unrestricted network access may need broad network permission. The daemon still withholds keys, stores, and administrative IPC.

Sandbox failure should prevent startup when configuration requires strict isolation. Best-effort mode must report reduced isolation.

---

# 46. Anti-probing and traffic shaping

Carrier profiles may implement:

* Private admission
* Observable-format transformation
* Padding
* Timing shaping
* Cover traffic
* Carrier-consistent failure behavior

The carrier reports these as capabilities and accepts policy through profile-specific bounded options.

The carrier MUST NOT claim active-probing resistance unless unauthenticated probes receive behavior defined by a reviewed private-admission profile.

Traffic shaping remains outside stable UMP packet semantics. The carrier must restore exact UMP packet bytes before inbound delivery.

---

# 47. Outer encryption and authentication

A carrier may use TLS, Bluetooth security, radio link keys, or another outer mechanism.

It reports:

```text
mechanism identifier
peer-authentication class
binding exporter availability
security state
```

UMC treats outer peer identity as carrier evidence. It MUST NOT equate it with UMP Endpoint ID without an authenticated binding defined by a profile.

Outer security failure closes the Link. UMP does not fall back to an insecure carrier mode inside the same Link.

---

# 48. Logging

Default carrier logs MUST NOT contain:

* UMP packet payload bytes
* Endpoint or session keys
* Private carrier credentials
* Invitation or bridge secrets
* Full private candidates
* Shared-memory contents

Logs may contain:

* Carrier Type and redacted Instance ID
* Redacted Link ID
* Operation and error category
* Packet length
* Queue and MTU state
* Coarse address class under policy

Carrier plugins send structured logs through bounded IPC or write to an operator-approved sink.

The daemon rate-limits plugin logs.

---

# 49. Metrics

Carrier metrics SHOULD include:

```text
Instance state
Listeners
Dial attempts and outcomes
Accepted links
Active links
Bytes and packets sent and received
Queue occupancy
Receive drops
MTU changes
Property changes
Link failures by category
Discovery candidates and expiry
Plugin restarts and health failures
```

Public metrics MUST avoid full addresses, candidates, stable peer identifiers, or unbounded per-Link labels.

---

# 50. Resource limits

Every Carrier Instance MUST define hard limits for:

* Listeners
* Pending accepts
* Concurrent dials
* Discovery operations
* Candidates
* Active Links
* Send packets and bytes per Link
* Receive packets and bytes per Link
* Total queued bytes
* Packet size
* Property-event rate
* Error and log rate
* Plugin message size
* Plugin handles and shared-memory slots

Recommended defaults:

| Resource | Default |
| --- | ---: |
| Pending accepts per listener | 128 |
| Concurrent dials per instance | 64 |
| Discovery candidates per operation | 256 |
| Send queue per Link | 256 packets or 2 MiB |
| Receive queue per Link | 256 packets or 2 MiB |
| Generic UMP packet maximum | 65,535 bytes |
| External plugin IPC message | 1 MiB |
| Property events per Link | 100 per second |
| Plugin restart burst | 3 attempts |

Carrier profiles and the resource-limits specification may set smaller values.

---

# 51. Security considerations

## 51.1 Malicious remote carrier peer

A peer may send malformed framing, oversized packets, connection churn, or forged carrier metadata. Carriers validate framing before allocation and rate-limit setup before UMP authentication.

## 51.2 Malicious plugin

A plugin may forge candidates, alter packets, lie about properties, retain shared buffers, or exhaust IPC. UMC isolates the process, validates every message, bounds handles and bytes, and treats properties as hints.

A malicious plugin can deny service or observe traffic sent through its carrier. End-to-end AEAD detects packet alteration and protects payload content.

## 51.3 Candidate injection

Carrier discovery can inject false addresses. Candidates retain source and authentication state, and UMP authenticates endpoints after dialing.

## 51.4 Address confusion

Addresses do not identify endpoints. Link and path contexts remain separate from Endpoint IDs.

## 51.5 Queue exhaustion

Send and receive ownership changes occur only after bounded acceptance. Carriers reject excess work instead of buffering it without limit.

## 51.6 Binding confusion

Canonical Carrier Binding includes type, profile, kind, and scoped instance data. UMC rejects binding-kind or profile mismatches during handshake.

## 51.7 Downgrade

A carrier MUST report effective properties after setup. If requested outer security or private admission is absent, setup fails. It cannot continue under a weaker mode without a new policy-approved dial.

## 51.8 Local privilege

Device and network permissions can exceed daemon needs. Built-in carriers minimize privileges; external plugins receive platform sandboxing and no endpoint secrets.

---

# 52. Required tests

A compliant reference implementation MUST test:

1. Carrier lifecycle and restart.
2. Listener cancellation and pending accept limits.
3. Dial success, timeout, cancellation, and late completion.
4. Candidate expiry and sharing policy.
5. Packet-boundary preservation.
6. Send ownership on success, failure, and cancellation races.
7. Bounded send and receive backpressure.
8. Reliable and unreliable property behavior.
9. Ordered concurrent sends.
10. MTU decrease with accepted packets in flight.
11. Link terminal-event uniqueness.
12. Property event sequencing.
13. Address rebinding and path generation.
14. Carrier Binding canonical vectors.
15. Scope and cost evidence handling.
16. Structured error mapping.
17. Plugin version negotiation.
18. Invalid IPC length, handle, and message type.
19. Shared-memory ownership and crash cleanup.
20. Plugin heartbeat timeout and restart backoff.
21. Plugin attempts to access unauthorized state.
22. Log and metric redaction.
23. Resource bounds under accept, dial, packet, and event floods.
24. Session migration after Carrier Instance failure.

Property tests SHOULD verify:

```text
Each successful send transfers one complete packet exactly once to carrier ownership.
Each failed send leaves packet ownership with the caller.
No delivered packet exceeds the Link's active MTU.
One Link emits one terminal event.
Property event sequences never decrease or conflict.
Candidate and path identity never authenticate an endpoint.
Plugin handles cannot cross process generations or types.
Queued bytes never exceed configured hard limits.
```

---

# 53. Carrier profile requirements

Each carrier profile MUST define:

1. Carrier Type ID and version.
2. Packet mode and framing.
3. Reliability and ordering.
4. Connection model.
5. Listen and dial hints.
6. Packet-size bounds and initial MTU.
7. Carrier Binding kind and Instance Data.
8. Path Context fields.
9. Address rebinding behavior.
10. Discovery behavior, if any.
11. Outer security and authentication.
12. Anti-probing behavior, if claimed.
13. Error mapping.
14. Backpressure behavior.
15. Scope and cost classification evidence.
16. Resource-limit defaults.
17. Privacy exposure.
18. Required interoperability tests.

A profile MUST reject ambiguity in packet boundaries, binding input, or target selection.

---

# 54. Minimal UMC v0.1 compliance

A compliant Carrier API implementation MUST support:

* Versioned Carrier Type IDs
* Carrier Instance lifecycle
* Capability reporting
* Listener and dial operations
* Peer Candidates
* Link lifecycle
* Complete packet send and receive
* Explicit buffer ownership
* Bounded backpressure
* MTU reporting and changes
* Link properties and events
* Structured errors
* Carrier Binding
* Path Context
* Cancellation and deadlines
* TCP and UDP built-in adapters
* Discovery-only LAN adapter
* Out-of-process external carrier boundary

An implementation MAY defer:

* Shared-memory plugin packet transfer
* Strict OS sandboxing on unsupported platforms
* Broadcast data Links
* Intermittent carrier Links
* Traffic shaping
* Private mimicry profiles

An implementation MUST NOT advertise a deferred capability.

---

# 55. Open design decisions

The project must resolve these items before freezing the v0.1 Carrier API:

1. Exact Rust trait ownership and cancellation types.
2. Whether discovery stays on `Carrier` or uses a separate trait.
3. Canonical encoding for Carrier Capabilities.
4. Canonical Peer Candidate envelope.
5. Carrier Binding Input encoding.
6. Registered Binding Kind values.
7. Path Context privacy and persistence rules.
8. Whether reliable carriers provide per-packet delivery events.
9. Exact send receipt semantics for kernel-buffer acceptance.
10. Receive pause interface for datagram carriers.
11. Link property confidence representation.
12. Carrier Type registry and private range process.
13. Maximum generic profile-option size.
14. Plugin IPC message encoding.
15. Plugin process authentication mechanism per platform.
16. Heartbeat interval and timeout.
17. Shared-memory layout and ownership protocol.
18. Minimum sandbox requirements for stable external plugins.
19. Whether one plugin process may host several instances.
20. Which Carrier API parts receive stability guarantees in v0.1.

---

# 56. Recommended implementation order

Implement the Carrier API in this order:

1. Identifier and capability types.
2. Link properties and structured errors.
3. Packet ownership and bounded queues.
4. Link interface and lifecycle.
5. Carrier Instance lifecycle.
6. Listener and dial interfaces.
7. Candidate and discovery types.
8. Carrier Binding and Path Context.
9. TCP adapter.
10. UDP adapter.
11. LAN discovery adapter.
12. Metrics and diagnostics.
13. Plugin framing and version negotiation.
14. External Link and packet operations.
15. Plugin health and restart.
16. Platform sandboxing.
17. Fault injection and interoperability tests.

---

# 57. Core rule

A UMC carrier transfers bounded, complete UMP packets across one communication medium and reports the properties needed for policy and path management.

The carrier controls framing, addressing, and medium access. UMC controls identity, security, routing, reliability, and applications. Candidates, addresses, Link IDs, and carrier authentication remain evidence about adjacency and never become endpoint identity.
