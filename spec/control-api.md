# Universal Mesh Core Local Control API Specification

**Status:** Draft
**Version:** 0.1
**Document:** Local Daemon Control and Application API
**Project:** Universal Mesh Core, UMC
**Schema:** `api/umc.proto`

---

# 1. Purpose

This document defines the local API between `umcd` and administrative clients, application SDKs, diagnostic tools, and test programs.

It specifies:

* Local transports and framing
* API version negotiation
* Connection authentication
* Capability-scoped authorization
* RPC request and response handling
* Cancellation and deadlines
* Errors
* Event streams
* Pagination and snapshots
* Administrative and application permissions
* Local application registration
* Message and resource limits
* Compatibility rules

The canonical protobuf schema lives at `api/umc.proto`.

This API is local process interoperability. It does not use the UMP wire format and does not affect peer interoperability.

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

The protobuf schema and this document form one contract. This document controls lifecycle and security semantics. The schema controls field numbers, types, and service payloads.

---

# 3. Design objectives

The Control API MUST provide:

1. Local client authentication.
2. Capability-scoped authorization.
3. Separation between administration, applications, and diagnostics.
4. Versioned schemas and compatible evolution.
5. Multiplexed concurrent requests.
6. Cancellation and deadlines.
7. Bounded messages and event queues.
8. Explicit ownership of endpoint, listener, session, stream, and subscription handles.
9. Structured errors without secret leakage.
10. Recovery after client disconnect.

The API MUST NOT expose endpoint private keys, session keys, or another application's traffic through ordinary operations.

---

# 4. Local transports

UMC v0.1 uses:

```text
Linux and macOS: Unix domain stream socket
Windows: named pipe in byte-stream mode
```

An authenticated loopback TCP transport MAY support development and interoperability testing. It is disabled by default.

The daemon MUST set local transport permissions before accepting clients.

Unix sockets SHOULD use a user-private runtime directory and mode `0600` by default. Shared deployments use an explicit group and permission policy.

Windows named pipes MUST use a restrictive security descriptor.

The daemon MUST NOT listen on a non-loopback TCP address through the Control API implementation.

---

# 5. Stream framing

Each Control API message uses:

```text
MessageLength: unsigned 32-bit big-endian
Envelope: MessageLength bytes of canonical protobuf encoding
```

`MessageLength` excludes its own four bytes.

The receiver MUST:

1. Read exactly four length bytes.
2. Reject zero length.
3. Reject length above the negotiated envelope maximum before allocation.
4. Read exactly `MessageLength` bytes.
5. Parse one `umc.api.v1.Envelope`.
6. Reject missing or invalid body fields.

Default maximum envelope is 4 MiB. The hard v0.1 maximum is 16 MiB.

The protobuf decoder MUST enforce recursion and field-count limits.

---

# 6. Connection state machine

Each local connection uses:

```text
CONNECTED
NEGOTIATING
AUTHENTICATED
DRAINING
CLOSED
```

## 6.1 CONNECTED

The transport accepted a client. No API request may run.

## 6.2 NEGOTIATING

The client sends `ClientHello`. The server authenticates transport context and credential, then returns `ServerHello` or closes.

## 6.3 AUTHENTICATED

The connection may exchange requests, responses, cancellation, and events within granted capabilities.

## 6.4 DRAINING

The server or client sent `GoAway`. New requests fail. Existing operations may finish before the drain deadline.

## 6.5 CLOSED

The transport closed. The daemon cancels connection-owned operations and releases ephemeral handles according to service rules.

---

# 7. Envelope

Every message is an `Envelope` with:

```text
api_version
sequence
body
```

The body is one of:

```text
ClientHello
ServerHello
Request
Response
Cancel
Event
EventAck
GoAway
```

`sequence` is a per-sender unsigned 64-bit counter. It starts at one and increases by one for each envelope.

The receiver MUST reject zero, reuse, decrease, or gaps above a configurable diagnostic threshold. A sequence conflict closes the connection.

Sequence numbers detect stream and implementation errors. They do not replace transport integrity or request IDs.

---

# 8. API versioning

`ApiVersion` contains:

```text
major
minor
```

UMP v0.1 Control API uses:

```text
major = 1
minor = 0
```

Major changes may break wire or semantic compatibility. Minor changes add backward-compatible fields, messages, methods, or enum values.

The client offers supported versions in preference order. The server selects one exact version.

No common major version causes negotiation failure.

A client MUST tolerate unknown protobuf fields. It MUST reject unknown method names and unknown enum values where the operation cannot remain safe.

---

# 9. ClientHello

The first envelope from the client MUST contain `ClientHello`.

It includes:

```text
supported_versions
client_name
client_instance_id
client_kind
authentication
requested_envelope_size
requested_features
```

`client_name` is diagnostic text, limited to 128 bytes. It grants no permission.

`client_instance_id` is 16 random bytes and identifies one process run for audit correlation. It is not an authentication credential.

Client Kind values:

```text
ADMIN
APPLICATION
DIAGNOSTIC
TEST
```

A client cannot gain permission by choosing a kind.

---

# 10. ServerHello

The server returns one `ServerHello` after successful negotiation.

It includes:

```text
selected_version
server_instance_id
node_state
connection_id
principal_id
granted_capabilities
negotiated_envelope_size
enabled_features
limits
```

`server_instance_id` changes after daemon restart.

`connection_id` is an opaque local audit handle.

`principal_id` identifies the authenticated local authorization principal. Clients MUST treat it as opaque.

The daemon MUST NOT include bearer tokens or secret policy details in `ServerHello`.

---

# 11. Authentication methods

`ClientAuthentication` supports:

```text
OS_PEER
BEARER_CAPABILITY
DEVELOPMENT_TOKEN
```

## 11.1 OS_PEER

The daemon reads peer credentials from the Unix socket or named pipe.

OS identity provides an authentication input. Authorization policy maps it to capabilities.

For the v0.1 Unix/macOS daemon, the socket is created with mode `0600` and the
daemon accepts only a peer with the daemon's uid before reading `ClientHello`.
That validated peer is the local-operator authentication mode when no bearer
credential is presented; it is not anonymous access. The proof is carried into
the connection authorization state and MUST be required again at hello and
request dispatch. A bearer credential MUST NOT bypass a failed OS-peer check.
The local-operator policy is intentionally separate from token grants:
`TokenService` requires a bearer capability or enabled development token, and
application clients use bearer grants for principal- and resource-scoped
access. The current `ServerHello` uses the reserved eight-byte zero
`principal_id` and an empty grant list for this implicit OS-peer operator;
clients MUST treat that reserved representation as the transport-bound local
operator rather than as an unauthenticated client. Zero is never allocated to
a bearer principal.

## 11.2 BEARER_CAPABILITY

The client sends an opaque random capability token in `ClientHello`.

Tokens MUST:

* Contain at least 256 bits of entropy
* Be stored through protected local credential mechanisms
* Bind to one authorization principal
* Have an expiry or explicit long-lived policy
* Support revocation
* Never appear in logs or errors

The daemon stores a keyed hash or protected token record, not a plaintext token when avoidable.

## 11.3 DEVELOPMENT_TOKEN

Development tokens work only when the daemon enables development mode. They MUST NOT be accepted on production profiles.

## 11.4 Combined authentication

Policy MAY require both OS peer identity and bearer capability.

Authentication failure SHOULD close the connection without detailed policy disclosure.

---

# 12. Authorization model

Authorization uses grants. Each grant contains:

```text
capability
resource constraints
operation constraints
expiry
grant_id
```

The daemon evaluates every request against the current grant set. A grant may expire or be revoked while the connection remains open.

Capability possession does not bypass resource limits or object ownership.

---

# 13. Capability registry

UMC v0.1 defines:

```text
NODE_READ
NODE_ADMIN
NODE_SHUTDOWN
IDENTITY_READ
IDENTITY_CREATE
IDENTITY_ROTATE
IDENTITY_EXPORT_PUBLIC
IDENTITY_EXPORT_SECRET
IDENTITY_DELETE
CARRIER_READ
CARRIER_ADMIN
PEER_READ
PEER_ADMIN
TRUST_ADMIN
ROUTE_READ
ROUTE_PROBE
SESSION_READ
SESSION_CLOSE
BUNDLE_READ
BUNDLE_CREATE
BUNDLE_DELETE
RELAY_READ
RELAY_ADMIN
APPLICATION_REGISTER
APPLICATION_CONNECT
APPLICATION_LISTEN
APPLICATION_STREAM
APPLICATION_DATAGRAM
DISCOVERY_READ
DISCOVERY_RUN
DIAGNOSTICS_READ
DIAGNOSTICS_SENSITIVE
EVENT_SUBSCRIBE
TOKEN_ADMIN
```

Unknown capabilities grant no authority.

`IDENTITY_EXPORT_SECRET`, `IDENTITY_DELETE`, `NODE_SHUTDOWN`, and `TOKEN_ADMIN` require explicit administrative grants and audit events.

---

# 14. Resource constraints

A grant may constrain:

```text
endpoint_ids
protocol_ids
destination_endpoint_ids
carrier_type_ids
peer_endpoint_ids
trust_states
maximum_sessions
maximum_streams
maximum_pending_bytes
maximum_datagram_size
route_scopes
relay_modes
bundle_bytes
```

An empty repeated constraint means no resources unless the grant sets `all_resources = true`.

This rule prevents an omitted list from becoming a wildcard.

The daemon intersects all applicable constraints with node policy and global limits.

---

# 15. Administrative separation

The daemon treats these as separate authority classes:

```text
Read-only node diagnostics
Operational administration
Identity administration
Secret export and recovery
Local application data
Capability-token administration
```

A client with `NODE_ADMIN` does not receive `IDENTITY_EXPORT_SECRET` or application traffic access unless policy grants them.

An application grant does not receive peer tables, route topology, other sessions, daemon configuration, or bundle-store contents.

---

# 16. Requests

`Request` contains:

```text
request_id
service
method
deadline_unix_ms
idempotency_key
payload
```

`request_id` is a non-zero client-selected unsigned 64-bit value unique among in-flight requests on one connection.

`service` and `method` use exact names declared in `api/umc.proto`.

`payload` contains the serialized protobuf request type for that method.

The server MUST reject:

* Unknown service or method
* Wrong payload type
* Duplicate in-flight request ID
* Payload above method limit
* Invalid or expired deadline
* Missing required capability

---

# 17. Deadlines

`deadline_unix_ms` is an absolute Unix time for cross-process representation.

On receipt, the daemon converts it to a monotonic deadline using current clock state. Later wall-clock changes do not extend it.

Zero means the method default deadline.

The server caps deadlines by operation class:

```text
Read RPC: 30 seconds
Mutation RPC: 60 seconds
Dial or route probe: 60 seconds
Streaming read or write operation: handle lifetime policy
Administrative migration or backup: explicit operation object
```

An expired request receives `DEADLINE_EXCEEDED` unless connection closure prevents a response.

---

# 18. Idempotency

Mutation methods declare one of:

```text
IDEMPOTENT
IDEMPOTENT_WITH_KEY
NON_IDEMPOTENT
```

Methods marked `IDEMPOTENT_WITH_KEY` require a 16-to-64-byte idempotency key.

The daemon scopes keys to principal, service, and method. It retains the result for 24 hours by default within bounded storage.

A repeated key with a different payload returns `IDEMPOTENCY_CONFLICT`.

Clients MUST NOT retry non-idempotent requests after an ambiguous disconnect unless they reconcile state first.

---

# 19. Responses

`Response` contains:

```text
request_id
status
payload
completed_at_unix_ms
```

Exactly one terminal Response exists for each accepted Request unless the connection closes first.

A successful payload uses the protobuf response type declared for the method.

An error response carries no success payload unless the method documents partial results.

The server may respond out of request order. Request ID performs correlation.

---

# 20. Status and error model

`Status` contains:

```text
code
message
details
retry_after_ms
```

UMC v0.1 status codes include:

| Code | Meaning |
| --- | --- |
| `OK` | Operation succeeded |
| `CANCELLED` | Client or server cancelled operation |
| `UNKNOWN` | Unclassified failure |
| `INVALID_ARGUMENT` | Request failed validation |
| `DEADLINE_EXCEEDED` | Deadline ended |
| `NOT_FOUND` | Resource does not exist or is hidden by policy |
| `ALREADY_EXISTS` | Resource conflicts with existing state |
| `PERMISSION_DENIED` | Principal lacks authorization |
| `UNAUTHENTICATED` | Connection authentication is absent or invalid |
| `RESOURCE_EXHAUSTED` | Quota or hard limit rejected work |
| `FAILED_PRECONDITION` | Current state cannot perform method |
| `ABORTED` | Concurrent state change aborted operation |
| `OUT_OF_RANGE` | Numeric or pagination range is invalid |
| `UNIMPLEMENTED` | Method or feature is unsupported |
| `INTERNAL` | Daemon failed |
| `UNAVAILABLE` | Subsystem or carrier is unavailable |
| `DATA_LOSS` | Persistent or protocol state is corrupt |
| `CONFLICT` | Version, state, or idempotency conflict |

Messages are diagnostic, bounded to 1 KiB, and safe for the authorized client class.

Details use registered protobuf messages. Clients ignore unknown detail types.

---

# 21. Cancellation

The client sends `Cancel` with a live request ID.

Cancellation is idempotent.

The server:

* Stops work when cancellation remains safe
* Releases temporary reservations
* Returns `CANCELLED` when the operation had not committed
* Returns the committed result when cancellation arrived after commit

Cancellation cannot roll back a completed key rotation, trust change, sent datagram, accepted stream write, or other committed side effect.

Unknown Request IDs receive no response or a bounded diagnostic event.

---

# 22. GoAway

Either side may send `GoAway`.

It contains:

```text
reason
last_accepted_request_id
drain_deadline_unix_ms
```

The receiver stops new requests. Requests above `last_accepted_request_id` may be retried on another connection according to idempotency rules.

Daemon shutdown, configuration reload, and API version retirement use `GoAway` where time permits.

---

# 23. Service registry

The canonical schema declares:

```text
NodeAdmin
IdentityService
CarrierService
PeerService
RouteService
SessionService
RelayService
BundleService
ApplicationService
DiagnosticsService
EventService
TokenService
```

Service declarations define method names and request and response types. The custom local transport does not require HTTP/2 or gRPC.

Generated clients may build stubs from the service descriptors.

---

# 24. NodeAdmin

`NodeAdmin` provides:

```text
GetStatus
GetConfig
UpdateConfig
ReloadConfig
Shutdown
GetResourceUsage
```

`GetStatus` requires `NODE_READ`.

Configuration mutation requires `NODE_ADMIN`, optimistic revision matching, validation before commit, and an audit event.

Shutdown requires `NODE_SHUTDOWN` and an explicit drain mode.

The API MUST redact sensitive configuration values. Secret configuration uses separate write-only fields or credential references.

---

# 25. IdentityService

`IdentityService` provides:

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

Identity handles and Endpoint IDs remain distinct.

Secret export requires `IDENTITY_EXPORT_SECRET`, explicit export protection, and an audit event. The daemon SHOULD require an operator confirmation mechanism outside ordinary application grants.

Deletion must report dependent listeners, sessions, trust records, and bundles before commit. The final API may require a two-step plan token.

---

# 26. CarrierService

`CarrierService` provides:

```text
ListCarrierTypes
ListCarrierInstances
GetCarrierInstance
CreateCarrierInstance
UpdateCarrierInstance
StartCarrier
StopCarrier
DeleteCarrierInstance
Dial
ListLinks
CloseLink
```

`Dial` acquires an outbound link from a running carrier instance. It returns
an opaque link handle and the negotiated carrier properties; the daemon owns
the link until `CloseLink`, carrier stop, or daemon shutdown. A raw carrier
link is not an application session and carries no application authorization
until a higher-level session operation adopts it.

Read methods require `CARRIER_READ`; mutation requires `CARRIER_ADMIN`.

Sensitive carrier options are write-only and return redacted presence markers.

External plugin health and isolation state appear as bounded diagnostics.

---

# 27. PeerService

`PeerService` provides:

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

Peer list results obey capability and privacy scope. Application clients do not receive this service by default.

Trust mutation requires `TRUST_ADMIN` and revision matching.

Invitation secrets appear once at creation or import result and MUST NOT appear in later list responses.

---

# 28. RouteService

`RouteService` provides:

```text
ListRoutes
GetRoute
ProbeRoute
InvalidateRoute
```

Read methods require `ROUTE_READ`; active probes require `ROUTE_PROBE`.

Routes expose policy-relevant attributes and redacted hop data according to the principal grant.

ProbeRoute returns an operation handle or bounded result. It must obey routing resource limits and cancellation.

---

# 29. SessionService

`SessionService` provides administrative inspection:

```text
ListSessions
GetSession
CloseSession
MigrateSession
ListStreams
```

Application-owned session data flows through `ApplicationService`.

Administrative inspection returns metadata, not stream plaintext, unless a separate debugging build and explicit sensitive grant define it. Stable production v0.1 exposes no plaintext inspection method.

---

# 30. Relay and bundle services

## 30.1 RelayService

`RelayService` provides:

```text
GetRelayStatus
UpdateRelayPolicy
ListRelayCircuits
CloseRelayCircuit
```

Read methods require `RELAY_READ`; mutation and circuit closure require `RELAY_ADMIN`.

Relay policy uses optimistic revision matching. Public mode requires explicit enablement and returns the effective circuit, bandwidth, lifetime, destination, and trust limits.

Circuit inspection exposes adjacent and destination metadata only under sensitive administrative policy. Ordinary output uses redacted peer and route identifiers.

## 30.2 BundleService

`BundleService` provides:

```text
ListBundles
GetBundle
CreateBundle
DeleteBundle
```

Bundle support is experimental in v0.1.

Metadata visibility follows local endpoint and application ownership. Payload transfer uses bounded chunks or an application stream handle. It does not enlarge the Control API envelope.

Delete requires ownership or administrative `BUNDLE_DELETE`.

---

# 31. Application registration

An application calls `ApplicationService.RegisterApplication` after connection authentication.

The request includes:

```text
application_name
application_instance_id
requested_endpoint_ids
requested_protocol_ids
requested_operations
```

The daemon returns an `ApplicationHandle` and effective grant subset.

Registration cannot expand connection capabilities. It creates an ownership scope for listeners, sessions, streams, datagrams, and events.

Application handles expire when the connection closes unless the registration declares a resumable principal and policy permits reconnection.

---

# 32. Application listeners

`ApplicationService.OpenListener` binds:

```text
ApplicationHandle
Endpoint ID
Protocol ID
Listen policy
```

The daemon returns a `ListenerHandle`.

Incoming sessions or streams produce events scoped to that listener. The application accepts or rejects them through explicit methods.

Two applications cannot bind the same endpoint and protocol tuple unless policy and the protocol registration mode permit sharing.

Listener closure is idempotent and does not close accepted sessions unless requested.

---

# 33. Application sessions

`ApplicationService.Connect` requests an endpoint session and application protocol.

The request includes destination, endpoint, protocol, connection policy, deadline, and idempotency key.

The daemon returns a `SessionHandle` after endpoint authentication and application-protocol acceptance, or an operation handle when asynchronous progress is requested.

Application Session Handles expose only sessions owned by that application registration.

Path migration keeps the same handle.

---

# 34. Application streams

`ApplicationService` provides:

```text
OpenStream
AcceptStream
RejectStream
ReadStream
WriteStream
CloseStreamSend
ResetStream
StopStream
```

Stream data uses chunk messages bounded to 256 KiB, with a default 64 KiB chunk.

`WriteStream` success means the daemon accepted ownership under `session.md`; it does not prove peer application consumption.

`ReadStream` returns ordered bytes, EOF, or reset status.

At most one read and one write operation may remain in flight per Stream Handle unless the SDK serializes them.

Client disconnect cancels pending operations and applies application registration cleanup policy.

---

# 35. Application datagrams

`ApplicationService` provides:

```text
SendDatagram
ReceiveDatagram
```

A successful SendDatagram response means local acceptance. It provides no network-delivery guarantee.

ReceiveDatagram preserves one complete datagram and exposes source session handle, context ID, and expiry status.

Datagrams must fit negotiated session and Control API chunk limits.

---

# 36. Handle model

API handles are opaque 16-byte random values.

Handle classes include:

```text
Application
Listener
Operation
Session
Stream
Subscription
Carrier Instance
Link
```

A handle binds to:

* Server instance
* Authorization principal
* Resource type
* Owning application registration when applicable
* Generation

The daemon MUST reject cross-principal, cross-type, expired, or previous-server-instance handles.

Handles are not secrets by themselves, but clients and logs should treat them as sensitive metadata.

---

# 37. Pagination

List methods use:

```text
page_size
page_token
snapshot_token
```

Default page size is 100. Hard maximum is 1,000.

Page tokens are opaque, authenticated, principal-bound, method-bound, and expire after 5 minutes by default.

Snapshot Token keeps one bounded logical view across pages. The daemon may return `ABORTED` when the snapshot expires or resource pressure removes it.

Clients MUST NOT parse tokens.

---

# 38. Event subscriptions

`EventService.Subscribe` creates a Subscription Handle.

The request selects:

```text
event types
owned resources
endpoint IDs
minimum severity
include initial snapshot
resume cursor
```

The daemon intersects filters with the principal grant.

Events arrive as `Event` envelopes, each with:

```text
subscription_id
event_sequence
event_type
occurred_at_unix_ms
resource handle or redacted ID
payload
```

Event Sequence starts at one per subscription.

---

# 39. Event delivery and loss

Event streams use bounded queues.

Default backlog per client is 1,024 events or 4 MiB. The lower limit wins.

Events declare:

```text
CRITICAL
STATE
EDGE
SAMPLE
```

`STATE` events may coalesce by resource. `SAMPLE` events may drop under pressure.

The daemon MUST NOT silently drop `CRITICAL` or terminal ownership events. If it cannot deliver them, it marks the subscription out of sync and closes it with a resume cursor or snapshot requirement.

An `EVENT_GAP` event identifies the first and last unavailable sequence.

---

# 40. Event acknowledgements

The client sends `EventAck` with Subscription Handle and highest contiguous Event Sequence processed.

Acknowledgement releases backlog retention when the server retains events.

EventAck does not acknowledge network delivery or application data. It controls local event flow.

The daemon may close a subscription whose client does not acknowledge within its retention and pressure limits.

---

# 41. Resumption

A subscription may expose an opaque Resume Cursor.

Resume cursors bind to principal, filters, server instance or persisted event journal generation, and expiry.

The server returns `OUT_OF_RANGE` with snapshot guidance when requested events no longer exist.

UMC v0.1 does not require event persistence across daemon restart. Server Instance change may invalidate every cursor.

---

# 42. DiagnosticsService

`DiagnosticsService` provides:

```text
RunDoctor
GetMetricsSnapshot
GetRecentErrors
GetSubsystemHealth
```

Ordinary diagnostics require `DIAGNOSTICS_READ` and return redacted identifiers.

Sensitive carrier addresses, endpoint identifiers, and policy explanations require `DIAGNOSTICS_SENSITIVE`.

Diagnostics MUST NOT return private keys, session keys, invitation secrets, bearer tokens, application plaintext, or full private peer tables.

Long diagnostics create an Operation Handle and emit progress events.

---

# 43. TokenService

`TokenService` provides:

```text
ListGrants
CreateToken
RevokeToken
InspectCurrentGrant
```

Token administration requires `TOKEN_ADMIN`.

CreateToken returns plaintext token bytes once. The daemon never returns them again.

Grant creation validates that the issuing principal may delegate every capability and resource constraint. Delegated expiry cannot exceed issuer authority.

Revocation affects new requests and may terminate active resources when policy requires it.

---

# 44. Audit events

The daemon emits audit events for:

```text
Authentication success and failure class
Capability-token creation and revocation
Configuration mutation
Identity creation, rotation, import, export, and deletion
Trust mutation
Carrier administration
Relay administration
Bundle deletion by administrator
Node shutdown
Permission denial for sensitive methods
```

Audit events record principal, method, target class, outcome, and time. They MUST redact bearer tokens, private keys, and application plaintext.

Audit storage and retention follow security-operations policy.

---

# 45. Message limits

Defaults from `resource-limits.md`:

| Resource | Default | Hard maximum |
| --- | ---: | ---: |
| Envelope | 4 MiB | 16 MiB |
| Ordinary request payload | 1 MiB | method-specific |
| Stream data chunk | 64 KiB | 256 KiB |
| Status message | 1 KiB | 4 KiB |
| Status details | 16 KiB | 64 KiB |
| Page size | 100 | 1,000 |
| Concurrent requests per client | 64 | 256 |
| Queued requests per client | 256 | 1,024 |
| Event backlog | 1,024 events or 4 MiB | configured hard limit |
| Event streams per client | 8 | 32 |

Bulk data uses chunks or operation handles. Clients MUST NOT use unknown fields to bypass method limits.

---

# 46. Rate limits

Default rates:

```text
Application principal: 1,000 requests per minute
Administrative principal: 10,000 requests per minute
Authentication failures per source context: 10 per minute
Token creation: 100 per hour
Route probes per application: 60 per minute
Diagnostic runs per client: 10 per minute
```

The daemon charges requests by principal across reconnects.

Method-specific subsystem quotas also apply.

At resource pressure, the daemon preserves health, shutdown, credential revocation, and recovery capacity.

---

# 47. Connection closure

Connection closure:

* Cancels in-flight read-only and uncommitted operations
* Releases connection-scoped handles
* Closes event subscriptions
* Applies application listener and session cleanup policy
* Does not roll back committed mutations

Administrative resources such as Carrier Instances and node configuration outlive the connection.

Application listeners and sessions may outlive a connection only when registration and policy mark them resumable. The daemon binds them to the principal, not a new unauthenticated client.

---

# 48. Security considerations

## 48.1 Credential theft

Bearer-token theft grants its scoped authority until expiry or revocation. Tokens need strong entropy, protected storage, narrow grants, and short lifetime where practical.

## 48.2 Confused deputy

The daemon authorizes the principal, resource constraint, handle owner, and method on every request. A valid handle cannot expand a grant.

## 48.3 Cross-application access

Handles and event filters bind to application registration and principal. List and diagnostics methods apply privacy filters.

## 48.4 Parser attacks

The daemon validates length before allocation, limits protobuf recursion and unknown-field size, and fuzzes Envelope and method payload parsers.

## 48.5 Resource exhaustion

Connections, requests, payloads, events, pages, operations, and handles receive per-principal and global bounds.

## 48.6 Error leakage

Unauthenticated failures remain generic. Authorized errors reveal no other principal, private policy, key, or hidden resource state.

## 48.7 Loopback TCP

Loopback TCP lacks Unix peer credentials and named-pipe access control. It requires bearer authentication and explicit development configuration.

## 48.8 Protobuf ambiguity

The schema prohibits `map` fields in signed or idempotency-hashed request material unless canonicalization defines ordering. Servers reject duplicate semantic fields and malformed enum use.

---

# 49. Compatibility

Schema evolution MUST:

* Preserve existing field numbers and meanings
* Reserve removed field names and numbers
* Add fields with safe defaults
* Add enum values without changing prior values
* Avoid changing request idempotency semantics in one major version
* Avoid widening authorization through absent fields
* Keep service and method names stable within one major version

Clients ignore unknown fields. Servers reject unknown methods.

Experimental methods use an `Experimental` namespace or explicit feature negotiation and receive no stable compatibility guarantee.

---

# 50. Required tests

A compliant implementation MUST test:

1. Length-prefix parsing and oversize rejection.
2. Hello ordering and version negotiation.
3. OS peer and bearer authentication.
4. Capability and resource-constraint intersection.
5. Empty constraints granting no wildcard.
6. Administrative and application separation.
7. Concurrent out-of-order responses.
8. Request ID collision.
9. Deadline conversion and wall-clock changes.
10. Cancellation before and after commit.
11. Idempotency replay and conflict.
12. Error redaction.
13. Handle type, owner, generation, and restart validation.
14. Pagination token binding and expiry.
15. Event ordering, coalescing, gap, and acknowledgement.
16. Slow event consumer behavior.
17. Application listener ownership.
18. Session and stream data isolation.
19. Stream write ownership and disconnect races.
20. Datagram local-acceptance semantics.
21. One-time token and secret export.
22. Runtime grant revocation.
23. Rate and message limits.
24. Protobuf unknown-field and enum compatibility.
25. Fuzzing of Envelope and every request message.
26. Daemon restart invalidating ephemeral handles.

---

# 51. Open decisions

The project must resolve these items before freezing Control API v1:

1. Exact protobuf package and language options.
2. Whether service descriptors or a separate method registry drive dispatch.
3. Canonical payload type-name representation.
4. Bearer-token hashing and local storage.
5. Combined OS peer and token policy.
6. Capability delegation rules.
7. Identity deletion two-step workflow.
8. Resumable application registration semantics.
9. Session Connect synchronous versus operation-handle default.
10. Stream read and write chunking API.
11. Event persistence across restart.
12. Audit storage and retention.
13. Sensitive diagnostics schema.
14. Configuration secret-write format.
15. Backup and restore API placement.
16. Loopback TCP test profile.
17. Protobuf deterministic serialization requirements for idempotency hashes.
18. Python client transport implementation.
19. Buf compatibility policy and CI rules.
20. Experimental method namespace.

---

# 52. Minimal v0.1 compliance

A compliant UMC v0.1 daemon MUST support:

* Unix socket or Windows named pipe transport
* Length-prefixed protobuf Envelope
* API version negotiation
* OS peer or bearer authentication
* Capability-scoped authorization
* Request, response, cancel, and GoAway
* Structured errors
* Bounded event subscriptions
* Node, Identity, Carrier, Peer, Route, Session, Application, Diagnostics, Event, and Token services
* Handle ownership and generation checks
* Pagination
* Message and rate limits
* Audit events for sensitive mutations

Bundle methods MAY return `UNIMPLEMENTED` while experimental bundle support is disabled.

---

# 53. Core rule

The UMC Control API gives each authenticated local principal the smallest explicit capability set needed for its work.

Every request binds to a principal, method, resource constraints, deadline, and bounded payload. Opaque handles preserve ownership without exposing internal pointers or secrets. Administrative authority, application data access, diagnostics, and token delegation remain separate grants.
