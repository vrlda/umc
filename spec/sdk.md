# Universal Mesh Core Application SDK Specification

**Status:** Draft
**Version:** 0.1
**Document:** Application SDK Contract
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines the stable application-facing SDK for UMC.

It specifies:

* SDK role and boundaries
* Layering and backends
* Language bindings
* Common API surface
* Runtime and async behavior
* Thread-safety and concurrency
* Handle model
* Endpoint API
* Protocol registration
* Listener lifecycle
* Session establishment and lifecycle
* Stream API
* Datagram API
* Delivery events
* Path events
* Service discovery and hints
* Policy API
* Cancellation and deadlines
* Backpressure
* Error model
* Embedded backend behavior
* Daemon-backed backend behavior
* C ABI expectations
* Resource limits
* Security considerations

The SDK is the layer applications program against. It must present one stable contract regardless of whether the application embeds the core library or connects to a running daemon.

This document does not define:

* UMP wire-format encoding
* Endpoint authentication or session cryptography
* Control API framing or protobuf schema details
* Application payload formats
* User interfaces
* Routing algorithms
* Carrier implementations

Those are defined in their respective specifications.

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

The SDK is a UMC software boundary. Independent UMP implementations may provide other APIs while preserving the network behavior defined by the protocol specifications.

---

# 3. SDK role

The SDK gives applications:

* Endpoint creation and loading
* Protocol registration
* Listener and accept operations
* Session establishment
* Stream open, accept, read, write, and close operations
* Datagram send and receive
* Delivery, path, and lifecycle events
* Service discovery and hint publication
* Communication policy requests
* Cancellation and deadlines
* Structured errors and backpressure

The SDK MUST NOT provide:

* Access to endpoint private keys through ordinary operations
* Direct manipulation of routing tables
* Direct manipulation of peer trust state
* Access to other applications' sessions, streams, or events
* Administrative configuration except through explicitly granted administrative capabilities
* Raw carrier or relay internals
* Executable routing-strategy code

The core treats application protocol identifiers as opaque selectors. The SDK must not impose application semantics.

---

# 4. Terminology

## 4.1 SDK

The application-facing library that exposes UMC capabilities through a stable API.

## 4.2 Backend

One execution mode of the SDK: embedded core or daemon connection.

## 4.3 Endpoint handle

An opaque local reference to a UMC endpoint identity and its configuration.

## 4.4 Protocol ID

An application-defined identifier used to select application protocols.

Example:

```text
org.example.echo/1
```

## 4.5 Listener

A bound endpoint and protocol tuple that accepts incoming sessions.

## 4.6 Session handle

An opaque local reference to one endpoint session.

## 4.7 Stream handle

An opaque local reference to one reliable byte stream inside a session.

## 4.8 Operation handle

An opaque local reference to asynchronous work that may outlive one request.

## 4.9 Policy

A structured set of constraints and preferences for a communication operation.

## 4.10 Delivery event

An event reporting transport-level outcome for application data.

---

# 5. SDK layering

The SDK sits above the endpoint and session services and below the application.

```text
Application
    ↓
SDK
    ↓
Embedded core OR Control API
    ↓
Protocol runtime
```

The SDK MUST expose the same semantic contract over both backends. Applications SHOULD be able to switch backends without rewriting application logic.

The SDK is not part of UMP interoperability. Two applications using different SDK backends still communicate through the same UMP sessions.

---

# 6. Backends

## 6.1 Embedded backend

The application links the core library in-process.

The embedded backend:

* Runs the protocol runtime inside the application process
* Owns endpoint keys and persistent state through the storage layer
* Requires the application to provide runtime integration (clock, entropy, storage, task spawning) through the core abstractions
* Fails when the application process fails

## 6.2 Daemon backend

The application connects to a local `umcd` daemon through the Control API.

The daemon backend:

* Runs the protocol runtime in the daemon process
* Owns endpoint keys, identity, and persistent state
* Uses the Control API transport defined by `control-api.md`
* Authenticates through OS peer credentials or bearer capabilities
* Survives application process restarts when registration is resumable
* Fails when the daemon is unavailable

## 6.3 Backend selection

The SDK MUST support explicit backend selection at construction.

The SDK MUST NOT silently switch backends during operation.

An application that requires private keys in-process MUST use the embedded backend. An application that requires key separation from its process MUST use the daemon backend.

---

# 7. Language bindings

## 7.1 Rust

The stable v0.1 SDK is the Rust crate `umc-sdk`.

It supports both backends:

* Embedded: links `umc-core`
* Daemon: speaks the Control API over the local transport

The Rust SDK MUST NOT depend on Tokio types in its public API where the core boundary already abstracts the runtime. Runtime-specific types MAY appear in backend adapters.

## 7.2 Python

Python is the first non-Rust daemon client binding.

The Python SDK:

* Uses generated Protocol Buffer messages over the Control API
* Supports the daemon backend only
* Preserves the same semantics as the Rust daemon-backed SDK
* MUST NOT expose private keys

## 7.3 C ABI

The C ABI is experimental in v0.1.

It MUST follow the stable ABI rules:

* Opaque handles
* Explicit allocation ownership
* Versioned functions
* Stable integer and byte-buffer types
* No unwinding across FFI

The C ABI is not part of the v0.1 stability commitment.

## 7.4 Other languages

Later stable bindings include C, Kotlin, Swift, TypeScript/Node.js, and Go.

They MUST use generated Control API messages or a stable C ABI and MUST preserve the semantics in this document.

---

# 8. Common API surface

The SDK SHOULD expose an interface equivalent to the conceptual API in `core.md`:

```rust
let core = Core::daemon("org.example.app")?;
let endpoint = core.load_endpoint("default")?;

let listener = core.listen(
    &endpoint,
    "org.example.echo/1",
    ListenPolicy::default()
).await?;

let session = core.connect(
    destination,
    "org.example.echo/1",
    ConnectionPolicy::default()
).await?;

let stream = session.open_stream().await?;
stream.write(b"hello").await?;
```

The API MUST provide:

```rust
core.create_endpoint(config)
core.load_endpoint(name)
core.listen(endpoint, protocol_id, policy)
core.connect(destination, protocol_id, policy)
core.discover_peers()
core.discover_services(protocol_id)
core.list_paths(destination)
core.list_carriers()
core.publish_endpoint_hint()
core.export_invitation()
core.import_invitation()
session.open_stream()
session.send_datagram()
listener.accept_session()
```

The SDK MUST NOT expose raw private keys by default.

---

# 9. Runtime model

SDK operations are asynchronous.

Every SDK operation that can block MUST:

* Accept a monotonic deadline
* Support cancellation
* Return a structured error on timeout, cancellation, or failure
* Release operation-specific resources on completion or cancellation

The SDK MUST NOT expose unbounded blocking operations.

The SDK SHOULD expose:

* A task or future type per backend
* A way to wait for events
* A way to await operations with deadlines

---

# 10. Thread-safety and concurrency

The Rust SDK MUST be `Send + Sync` where the backend permits it.

The SDK MUST document per-object thread-safety:

```text
Core:       Send + Sync, shared across threads
Endpoint:   Send + Sync, shared across threads
Listener:   Send + Sync, accept calls serialized per listener
Session:    Send + Sync, state transitions serialized
Stream:     Send + Sync, at most one read and one write in flight
```

The SDK MUST serialize state transitions that affect one session or stream. It MUST NOT expose a way for two threads to open the same stream ID or corrupt stream state.

Cancellation races MUST produce one stable externally visible result. A successful write MUST NOT later report rejection of the same bytes.

---

# 11. Handle model

SDK handles are opaque.

Handle classes include:

```text
Application
Listener
Operation
Session
Stream
Subscription
Endpoint
```

Each handle binds to:

* Server instance or embedded core instance
* Authorization principal
* Resource type
* Owning application registration where applicable
* Generation

The SDK MUST reject:

* Cross-principal handles
* Cross-type handles
* Expired handles
* Handles from a previous daemon instance

Handles are not secrets by themselves, but applications and logs SHOULD treat them as sensitive metadata.

The SDK MUST NOT require applications to parse handle contents.

---

# 12. Endpoint API

## 12.1 Endpoint creation

The SDK provides:

```text
create_endpoint(config)
```

The embedded backend creates the endpoint through the core identity manager.

The daemon backend requires the `IDENTITY_CREATE` capability or an administrative grant.

The SDK MUST NOT return endpoint private keys through this API.

## 12.2 Endpoint loading

The SDK provides:

```text
load_endpoint(name)
```

The embedded backend loads identity from the storage layer.

The daemon backend requires an administrative or application grant scoped to that endpoint.

## 12.3 Endpoint metadata

The SDK provides read access to:

```text
Endpoint ID
Identity binding summary
Validity
Capabilities
```

It MUST NOT expose private keys or secret handshake state.

## 12.4 Endpoint handles

An endpoint handle references one endpoint identity.

The SDK MUST NOT treat endpoint handles as transport or trust state.

---

# 13. Protocol registration

## 13.1 Protocol IDs

Protocol IDs:

* Are application-defined opaque selectors
* MUST use lowercase ASCII-compatible names when generated by the SDK
* SHOULD follow a collision-resistant naming convention

Examples:

```text
org.example.chat/1
com.company.service/2
mesh.community.files/1
```

The SDK MUST NOT require a runtime registry lookup.

## 13.2 Registration

The SDK provides:

```text
register_protocol(protocol_id, handler)
```

Registration:

* Binds a protocol ID to a local handler for incoming sessions
* Is scoped to one endpoint
* Is required before a listener may accept that protocol
* MUST be authenticated and authorized by the backend

The core treats protocol IDs as opaque. The SDK MUST NOT parse or interpret them.

---

# 14. Listener lifecycle

A listener binds one endpoint and one protocol ID.

Listener states:

```text
REGISTERED
LISTENING
CLOSING
CLOSED
```

## 14.1 Opening

The SDK provides:

```text
listen(endpoint, protocol_id, policy)
```

Opening a listener:

* Requires the `APPLICATION_LISTEN` capability on the daemon backend
* Requires the protocol to be registered
* Returns a `ListenerHandle`
* MUST fail if another application already binds the same endpoint and protocol tuple unless sharing is explicitly permitted

## 14.2 Accepting

The SDK provides:

```text
listener.accept_session()
```

Accepting:

* Waits for an incoming session request scoped to the listener
* Returns a session handle and protocol context
* MUST let the application accept or reject the session explicitly
* MUST NOT accept sessions for unregistered protocols

## 14.3 Rejecting

The SDK provides:

```text
listener.reject_session(session_handle, reason)
```

Rejecting a session:

* Sends `STOP_SENDING` and `RESET_STREAM` for pending streams where applicable
* MUST NOT close unrelated sessions
* MUST report rejection to the peer without leaking internal state

## 14.4 Closing

The SDK provides:

```text
listener.close()
```

Closing a listener:

* Stops accepting new sessions
* MUST be idempotent
* MUST NOT close already accepted sessions unless requested

---

# 15. Session establishment

## 15.1 Connecting

The SDK provides:

```text
connect(destination, protocol_id, policy)
```

Connecting:

* Requires the `APPLICATION_CONNECT` capability on the daemon backend
* Performs endpoint authentication and application-protocol acceptance
* Returns a `SessionHandle` on success
* MAY return an `OperationHandle` when asynchronous progress is requested

## 15.2 Session acceptance

Incoming sessions produce an event on the owning listener.

The application accepts or rejects the session explicitly.

The SDK MUST NOT deliver application data before authentication and authorization complete.

## 15.3 Session handles

A session handle:

* References one endpoint session
* MUST NOT change on path migration
* MUST NOT change on connection-ID rotation
* MUST NOT change on carrier replacement
* Exposes session metadata permitted by the grant

---

# 16. Session lifecycle

Sessions use the abstract states from `session.md`:

```text
CONNECTING
ACTIVE
SUSPENDED
CLOSING
CLOSED
```

## 16.1 CONNECTING

The handshake and protocol acceptance are in progress.

The SDK MUST NOT deliver application data in this state.

## 16.2 ACTIVE

The session may open streams and send datagrams within negotiated limits.

## 16.3 SUSPENDED

No live path exists but the session remains open.

In `SUSPENDED`:

* Streams remain open
* Writes apply backpressure
* Datagrams may be dropped
* The idle timer continues unless a disruption-tolerant profile negotiated suspension behavior

The SDK MUST report suspension through a session event.

## 16.4 CLOSING

The session received or sent `CONNECTION_CLOSE`.

The SDK:

* Stops accepting new application writes
* Cancels pending stream opens
* Notifies each local stream owner

## 16.5 CLOSED

The session released transport state.

The SDK MUST report:

* Clean peer closure
* Transport error
* Local cancellation
* Idle timeout
* Resource-limit closure

---

# 17. Stream API

## 17.1 Opening streams

The SDK provides:

```text
session.open_stream()
session.open_unidirectional_stream()
```

Opening a stream:

* Requires the `APPLICATION_STREAM` capability on the daemon backend
* Enforces negotiated stream limits
* Returns a `StreamHandle`

## 17.2 Accepting streams

The SDK provides:

```text
session.accept_stream()
```

Accepting:

* Returns peer-initiated streams in opening order
* MUST enforce the negotiated stream count before allocating state

## 17.3 Reading

The SDK provides:

```text
stream.read(buffer, deadline)
```

Reading:

* Returns ordered bytes
* Returns EOF when the final size is reached
* Returns reset status when the peer resets the stream
* MUST deliver each byte at most once
* MUST NOT reorder bytes
* MUST support cancellation and deadlines

## 17.4 Writing

The SDK provides:

```text
stream.write(bytes, deadline)
stream.write_all(bytes, deadline)
```

Writing:

* Accepts bytes for reliable delivery
* Applies backpressure when flow-control credit or congestion control blocks
* Returns success when the backend accepts ownership of the bytes
* Does NOT prove peer application consumption
* MUST NOT buffer unbounded application output

## 17.5 Half-close

The SDK provides:

```text
stream.close_send()
```

Half-closing:

* Sends FIN
* Declares the final size
* Lets the receive direction continue

## 17.6 Reset

The SDK provides:

```text
stream.reset(reason)
```

Resetting:

* Terminates one send direction
* Declares the final size
* Is not session closure

## 17.7 Stop

The SDK provides:

```text
stream.stop_sending(reason)
```

Stopping:

* Requests the peer stop transmitting on the stream
* MUST report the peer's resulting reset or closure

## 17.8 In-flight operations

The SDK MUST allow at most one read and one write operation in flight per stream handle unless the SDK serializes them internally.

The SDK MUST document this limitation.

---

# 18. Datagram API

## 18.1 Sending

The SDK provides:

```text
session.send_datagram(bytes, options)
```

A successful datagram send means local acceptance only.

It does NOT prove:

* Network delivery
* Peer application receipt
* Peer application consumption

## 18.2 Receiving

The SDK provides:

```text
session.receive_datagram()
```

Receiving:

* Preserves one complete datagram
* Returns the source session handle
* Returns the context ID
* Returns the expiry status
* MUST deliver one complete datagram or none

## 18.3 Size

The SDK MUST reject an oversized datagram without truncation.

The maximum datagram size is the negotiated session `maximum_datagram_size`.

## 18.4 Expiration

When the application supplies an expiration:

* The SDK MUST remove expired datagrams from queues before transmission
* The SDK MUST describe expiration as a freshness hint, not a proof
* The receiver may discard expired datagrams

## 18.5 Duplicate suppression

When the application requests duplicate suppression:

* The payload MUST begin with an application-defined deduplication identifier
* The SDK MUST describe the limitation: UMP/1 does not guarantee generic duplicate suppression from Context ID alone

---

# 19. Delivery events

The SDK provides delivery events for reliable stream data.

A delivery event means the backend released ownership of the bytes.

It does NOT mean:

* The peer application received the bytes
* The peer application processed the bytes
* The peer application accepted them

The SDK MUST expose distinct events for:

```text
ACKNOWLEDGED
LOST
RESET
CANCELLED
```

The SDK MUST NOT present delivery events as application-level receipts.

---

# 20. Path events

The SDK provides path events:

```text
PATH_ADDED
PATH_VALIDATED
PATH_DEGRADED
PATH_FAILED
PATH_RETIRED
PATH_MIGRATED
CARRIER_CHANGED
```

Path events MUST NOT change the session handle.

Applications SHOULD receive migration events but MUST NOT be required to reconnect.

The SDK MUST NOT expose raw peer tables, private topology, or relay identities without permission.

---

# 21. Service discovery and hints

## 21.1 Publishing hints

The SDK provides:

```text
publish_endpoint_hint(hint)
```

A hint contains:

```text
Protocol ID
Endpoint hint
Expiration
Opaque metadata
Signature
```

The SDK MUST NOT interpret application metadata.

## 21.2 Discovering services

The SDK provides:

```text
discover_services(protocol_id)
```

Discovery:

* Returns candidates, not trusted peers
* Honors scope and sharing policy
* MUST NOT enumerate complete peer tables
* MUST respect `DO_NOT_RESHARE` hints

## 21.3 Discovered endpoints

The SDK MUST NOT treat a discovered candidate as a trusted endpoint.

Endpoint authentication happens at session establishment.

---

# 22. Policy API

## 22.1 Connection policy

The SDK provides a policy structure for connection requests.

The policy MUST support at least:

```text
require_end_to_end_encryption
allow_relay
allow_store_and_forward
allow_local_carriers
allow_internet_carriers
maximum_hops
maximum_latency
maximum_bundle_lifetime
minimum_trust
prefer_low_cost
prefer_low_energy
path_strategy
```

## 22.2 Constraints, not implementations

Applications specify constraints and preferences.

They MUST NOT:

* Supply executable route-scoring code
* Directly manipulate internal routing tables
* Select relay circuits manually
* Bypass policy through raw protocol access

## 22.3 Strategy selection

The SDK MAY expose a `path_strategy` preference.

Valid values are the compiled strategies from the accepted decisions:

```text
balanced
low-latency
low-bandwidth
local-first
high-diversity
restricted-network
```

The backend selects the compiled strategy. The application does not implement strategies.

## 22.4 Policy failures

When no path satisfies the policy:

* The SDK MUST return a structured error
* The SDK MUST NOT fall back to a weaker policy without explicit application consent
* The SDK MUST NOT expose internal route state in the error

---

# 23. Cancellation and deadlines

Every SDK operation accepts a monotonic deadline.

The SDK provides:

```text
operation.cancel()
operation.await_result()
```

Cancellation:

* Stops work when cancellation remains safe
* Releases temporary reservations
* Returns `CANCELLED` when the operation had not committed
* Returns the committed result when cancellation arrived after commit
* MUST NOT roll back completed side effects

Cancellation MUST NOT:

* Roll back a sent datagram
* Roll back an accepted stream write
* Roll back an endpoint creation
* Roll back a trust or configuration change

The SDK MUST document that cancelled operations may still complete in the backend.

---

# 24. Backpressure

Backpressure MUST propagate from the network to the application.

The SDK provides:

* Blocking or pending stream writes
* Explicit resource errors
* Datagram drop or rejection according to policy
* Backpressure events

The SDK MUST NOT buffer unbounded application output.

When flow-control credit is exhausted:

* Stream writes return pending or block until credit or deadline
* The SDK MUST report the backpressure condition explicitly

When session credit is exhausted:

* New stream data is rejected or blocked
* The SDK MUST report `RESOURCE_EXHAUSTED` or a backpressure error

---

# 25. Error model

## 25.1 Categories

The SDK error model MUST distinguish:

```text
AUTHENTICATION_ERROR
PERMISSION_DENIED
INVALID_ARGUMENT
NOT_FOUND
ALREADY_EXISTS
DEADLINE_EXCEEDED
CANCELLED
RESOURCE_EXHAUSTED
FLOW_CONTROL
STREAM_RESET
STREAM_CLOSED
SESSION_CLOSED
SESSION_SUSPENDED
TRANSPORT_ERROR
UNIMPLEMENTED
UNAVAILABLE
DATA_LOSS
CONFLICT
INTERNAL
```

## 25.2 Mapping to transport conditions

The SDK MUST map session conditions to SDK errors:

| Condition | SDK error |
| --- | --- |
| Clean peer closure | `SESSION_CLOSED` |
| Transport error | `TRANSPORT_ERROR` |
| Stream reset | `STREAM_RESET` |
| Local cancellation | `CANCELLED` |
| Flow-control backpressure | `FLOW_CONTROL` |
| Carrier or path suspension | `SESSION_SUSPENDED` |
| Deadline expiry | `DEADLINE_EXCEEDED` |
| Datagram rejected for size or queue limits | `INVALID_ARGUMENT` or `RESOURCE_EXHAUSTED` |
| Peer protocol violation | `TRANSPORT_ERROR` |
| Resource quota exhausted | `RESOURCE_EXHAUSTED` |

## 25.3 Error details

SDK errors:

* MUST be structured
* MUST NOT contain private keys, session keys, tokens, or application plaintext
* MUST NOT expose other applications' state
* MUST be safe for display to authorized application users

The SDK MUST document that error details from remote peers are untrusted data.

---

# 26. Embedded backend

The embedded backend:

* Links `umc-core`
* Runs the protocol runtime in-process
* Uses the core's storage, identity, and crypto modules
* Requires the application to provide runtime integration through the core abstractions:

```text
Clock
EntropySource
TaskSpawner
AsyncStore
Link
```

The embedded SDK:

* MUST initialize the core before creating endpoints
* MUST handle process crash without live-session restoration
* MUST persist identity and trust state through the storage layer
* MUST NOT share secrets across processes

Embedded operation MUST follow `session.md` crash-and-restart behavior: live sessions are ephemeral; applications reopen operations after restart.

---

# 27. Daemon-backed backend

The daemon backend:

* Connects to `umcd` through the Control API transport
* Uses the protobuf schema in `api/umc.proto`
* Authenticates through OS peer credentials or bearer capabilities
* Exchanges `Envelope` messages with bounded sizes

The SDK MUST:

* Register an application through `ApplicationService.RegisterApplication`
* Use `ApplicationHandle` scoping for listeners, sessions, streams, datagrams, and events
* Handle `GoAway` and daemon restart
* Reconnect only with resumable registration and policy permission
* Enforce the Control API message limits

The SDK MUST NOT connect to an arbitrary daemon endpoint discovered from the filesystem without authentication.

The SDK MUST treat daemon unavailability as `UNAVAILABLE` and MUST NOT silently fall back to the embedded backend.

## 27.1 Stream transport

Over the daemon backend, stream data uses bounded chunk messages:

```text
Default chunk: 64 KiB
Maximum chunk: 256 KiB
```

The SDK MUST chunk large writes and reassemble reads.

## 27.2 In-flight operations

Over the daemon backend, the SDK MUST respect the Control API limit of at most one read and one write in flight per stream handle unless serialized.

---

# 28. Backend equivalence

The SDK MUST provide the same semantics over both backends.

Observable differences MUST be limited to:

```text
Latency
Resource isolation
Process failure behavior
Restart behavior
Identity storage location
```

The SDK MUST document these differences.

The SDK MUST NOT document different delivery or backpressure semantics between backends.

---

# 29. C ABI

The C ABI is experimental.

It MUST provide:

* Opaque handles for every resource
* Explicit ownership rules for buffers and handles
* Versioned entry points
* Stable integer and byte-buffer types
* No unwinding across FFI

The C ABI MUST NOT expose Rust structs directly.

The C ABI MUST support both backends where practical.

The C ABI is not covered by the v0.1 stability commitment.

---

# 30. Resource limits

The SDK MUST enforce and surface the per-application limits from `resource-limits.md`:

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

The SDK MUST report quota exhaustion with `RESOURCE_EXHAUSTED`.

The SDK MUST NOT let applications increase quotas by reconnecting; accounting binds to the credential principal.

The SDK SHOULD expose:

```text
Current usage
Hard limits
Pressure state
```

---

# 31. Security considerations

## 31.1 Compromised application

A compromised application controls its granted credentials and operations.

The SDK MUST:

* Restrict operations to granted capabilities
* Prevent access to other applications' handles and events
* Prevent private-key export by default
* Bind permissions to selected endpoints and protocol IDs
* Enforce request, stream, session, and byte quotas

## 31.2 Credential handling

Bearer tokens:

* MUST NOT be logged
* MUST NOT appear in errors
* MUST be stored through protected local mechanisms
* SHOULD have expiry and revocation

## 31.3 Confused deputy

The SDK MUST authorize every operation against the principal and resource constraints.

A valid handle MUST NOT expand a grant.

## 31.4 Handle leakage

The SDK MUST document that handles are sensitive metadata.

Logs MUST redact handle values by default.

## 31.5 Remote data

All remote error details, metadata, and events are untrusted.

The SDK MUST validate before display or use.

---

# 32. Required tests

A compliant SDK MUST test:

1. Backend equivalence for core operations.
2. Endpoint creation and loading.
3. Protocol registration and listener binding conflicts.
4. Listener accept and reject semantics.
5. Session connect, accept, and closure.
6. Session suspension and recovery events.
7. Stream open, accept, read, write, and half-close.
8. Stream reset and stop-sending.
9. Stream byte ordering and at-most-once delivery.
10. Datagram size rejection, expiry, and duplicate-suppression limitations.
11. Delivery event semantics.
12. Path event semantics and handle stability across migration.
13. Cancellation before and after commit.
14. Deadline enforcement.
15. Backpressure propagation.
16. Error mapping to SDK categories.
17. Quota exhaustion reporting.
18. Handle type, owner, generation, and restart validation.
19. Chunking over the daemon backend.
20. Daemon restart and reconnect behavior.
21. In-flight operation limits.
22. Cross-application isolation.
23. Log and error redaction.
24. Embedded crash without live-session restoration.

Property tests SHOULD verify:

```text
Each reliable stream byte reaches the application at most once.
Session handles never change on path migration.
Successful writes never later report rejection.
Cancellation produces one stable result.
Quotas never exceed configured limits.
No SDK operation exposes private keys.
```

---

# 33. Minimal v0.1 compliance

A compliant v0.1 SDK MUST support:

* Rust `umc-sdk`
* Embedded backend
* Daemon-backed backend
* Endpoint creation and loading
* Protocol registration
* Listeners with accept and reject
* Session connect and accept
* Bidirectional streams
* Stream reset and half-close
* Datagrams
* Delivery events
* Path events
* Policy constraints
* Deadlines and cancellation
* Backpressure
* Structured errors
* Handle ownership and validation
* Resource-limit reporting

An implementation MAY defer:

* Unidirectional application streams
* Resumable application registration
* C ABI
* Python binding
* Service discovery APIs
* Event resume cursors

An SDK MUST NOT advertise a deferred feature.

---

# 34. Open design decisions

The project must resolve these items before freezing the v0.1 SDK:

1. Exact Rust API signatures and trait names.
2. Whether `Core` is one facade or split by service.
3. Chunk size defaults for daemon stream transport.
4. Operation-handle versus synchronous defaults for `Connect`.
5. Resumable application registration semantics.
6. Event resume cursor support.
7. Whether the SDK exposes session tickets.
8. Exact delivery-event granularity.
9. Policy serialization format.
10. Error-code mapping table finalization.
11. C ABI entry-point list.
12. Python binding packaging and distribution.
13. Whether embedded and daemon backends share one public API or two.
14. Listener sharing policy for same endpoint and protocol tuples.
15. Service discovery API shape.
16. Whether SDK exposes bundle status events in v0.1.
17. Idle-timeout keepalive policy API.
18. Whether SDK permits datagram duplicate-suppression requests.
19. Diagnostics and metrics API in the SDK.
20. Stability guarantees for SDK surface in v0.1.

---

# 35. Recommended implementation order

Implement the SDK in this order:

1. Handle types and ownership rules.
2. Error model and mapping table.
3. Policy structures.
4. Endpoint API.
5. Listener API.
6. Session API.
7. Stream API.
8. Datagram API.
9. Events and delivery notifications.
10. Path events.
11. Deadlines and cancellation.
12. Backpressure.
13. Daemon-backed transport and chunking.
14. Embedded backend integration.
15. Backend equivalence tests.
16. Service discovery APIs.
17. C ABI.
18. Python binding.
19. Resource-limit reporting and tests.
20. Adversarial and fuzz tests.

---

# 36. Core rule

The UMC SDK gives applications one stable contract for endpoints, sessions, streams, datagrams, events, and policy over both embedded and daemon-backed execution.

Applications state constraints. The core chooses paths and enforces security. Handles preserve ownership without exposing secrets. Delivery events report transport outcome, never application receipt. Path migration never changes the application's session handle.
