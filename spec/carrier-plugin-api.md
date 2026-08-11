# Universal Mesh Core Carrier Plugin API Specification

**Status:** Draft / deferred extension (not advertised in v0.1)
**Version:** 0.1
**Document:** External Carrier Plugin Protocol
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

## v0.1 implementation profile

This document reserves the external Carrier Plugin Protocol for a future
subprocess loader. UMC v0.1 does not advertise or launch external carrier
plugins: the daemon exposes only built-in carriers and the trusted,
compiled-in `umc-plugin` registry. The registry uses the same daemon-side
generation, quota, crash-cleanup, and restart policy represented by
`PluginSupervisor`; an external loader MUST adopt that contract before it is
enabled. The process-start, IPC, and sandbox requirements below apply when
that extension is activated and are not claims about the current v0.1 binary.

# 1. Purpose

This document defines the Carrier Plugin Protocol between `umcd` and external carrier plugins that run as separate processes.

It specifies:

* Plugin model and boundary
* Process startup
* IPC transport
* Protocol handshake
* Version negotiation
* Capability negotiation
* Message framing and encoding
* Handles
* Configuration transfer
* Link creation
* Packet transfer
* Discovery
* Backpressure
* Health checks
* Crash behavior
* Shutdown and drain
* Restart policy
* Sandboxing expectations
* Logging
* Error model
* Resource limits

The carrier API specification defines the logical carrier contract. This document defines how external carriers speak that contract across a process boundary.

This document does not define:

* UMP wire format
* Endpoint authentication
* Session semantics
* Carrier profile media details
* Built-in carrier behavior

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

---

# 3. Plugin model

UMC uses two plugin classes.

## 3.1 Built-in carriers

Trusted first-party carriers are compiled into the daemon:

```text
TCP
UDP
LAN discovery
```

## 3.2 External carriers

Third-party and experimental carriers run as separate processes.

Communication uses the Carrier Plugin Protocol over a local socket or pipe.

## 3.3 No dynamic library loading

UMC v0.1 MUST NOT load arbitrary `.so`, `.dylib`, or `.dll` carrier plugins into the daemon.

The process boundary is mandatory.

---

# 4. Security boundary

## 4.1 What a plugin receives

A carrier plugin receives:

```text
Opaque UMP packet bytes
Temporary peer candidates
Link properties
Commands to listen, dial, send, and close
Its own configuration
Bounded property and policy inputs
```

## 4.2 What a plugin never receives

A carrier plugin MUST NOT receive:

```text
Endpoint private keys
UMP session keys
Decrypted application payloads
Full peer database
Trust database
Bundle plaintext
Administrative control credentials
```

## 4.3 Untrusted input

The daemon MUST treat all plugin output as untrusted input:

```text
Packet bytes
Candidates
Metrics
Errors
Lifecycle events
```

A plugin crash MUST NOT corrupt endpoint key, session, route, or storage state.

---

# 5. Terminology

## 5.1 Plugin

An external carrier process.

## 5.2 Daemon

The `umcd` process hosting the core.

## 5.3 Plugin generation

One process run of a plugin, identified by its launch.

## 5.4 IPC message

One framed protocol unit between daemon and plugin.

## 5.5 Handle

An opaque identifier for a plugin-scoped resource.

## 5.6 Launch token

A secret authenticating the plugin process to the daemon.

---

# 6. Process startup

## 6.1 Startup sequence

The daemon MUST:

1. Create a private IPC endpoint.
2. Start the plugin process with minimal arguments and environment.
3. Authenticate the process through an inherited handle or launch token.
4. Negotiate one compatible API version.
5. Send scoped configuration.
6. Apply a startup deadline and message limits.
7. Monitor process and protocol health.
8. Close all plugin-owned Links after crash or protocol failure.

## 6.2 Environment

The daemon MUST start the plugin with:

* Minimal arguments
* Minimal environment
* No ambient daemon credentials
* No access to daemon configuration or key material

## 6.3 Launch token

The launch token:

* Is generated per launch
* Is delivered through an inherited handle or private mechanism
* MUST NOT be discoverable from the filesystem
* Expires with the process generation

The plugin MUST NOT connect to an arbitrary daemon IPC endpoint discovered from the filesystem.

---

# 7. IPC transport

The plugin IPC runs over:

```text
Linux and macOS: Unix domain socket
Windows: named pipe
```

The IPC endpoint:

* MUST be private to the daemon and plugin process
* MUST be created with restrictive permissions
* MUST NOT be shared across plugin generations
* MUST NOT be reachable by other local processes without authorization

---

# 8. Protocol handshake

## 8.1 Flow

The protocol handshake:

```text
Daemon spawns plugin
Plugin connects to private IPC endpoint
Plugin sends PLUGIN_HELLO
Daemon verifies launch token
Daemon sends DAEMON_HELLO
Both negotiate API version and capabilities
Daemon sends CONFIG
Plugin applies configuration
Plugin sends START_ACK
Operations begin
```

## 8.2 PLUGIN_HELLO

`PLUGIN_HELLO` contains:

```text
Plugin API version
Plugin name
Supported protocol versions
Capabilities
Launch token proof
```

## 8.3 DAEMON_HELLO

`DAEMON_HELLO` contains:

```text
Selected API version
Daemon identity
Granted capabilities
Limits
```

The daemon MUST close the connection when:

* The launch token proof fails
* No compatible API version exists
* Required capabilities are absent
* The startup deadline expires

---

# 9. Version negotiation

## 9.1 Versioning

The Carrier Plugin API uses:

```text
major
minor
```

Major changes may break wire or semantic compatibility.

Minor changes add backward-compatible fields, messages, methods, or enum values.

## 9.2 Negotiation

The plugin offers supported versions in preference order.

The daemon selects one exact version.

No common major version causes negotiation failure and process termination.

The daemon and plugin MUST:

* Tolerate unknown protobuf fields
* Reject unknown critical messages
* Reject unknown critical enum values
* Never silently fall back to a weaker API version

---

# 10. Capability negotiation

Capabilities cover:

```text
Packet mode (DATAGRAM, STREAM_FRAMED, MESSAGE, RAW_FRAMED)
Reliability (UNRELIABLE, RELIABLE_UNTIL_LINK_FAILURE, PROFILE_DEFINED)
Ordering (UNORDERED, ORDERED, PROFILE_DEFINED)
Connection model
Listen and dial support
Discovery support
Shared-memory packet transfer
Outer encryption
Carrier authentication
Anti-probing
Traffic shaping
MTU bounds
```

Negotiation rules:

* The plugin MUST report unsupported features as false
* The daemon MUST NOT grant capabilities the plugin did not offer
* Capabilities are advisory until confirmed by actual behavior
* The daemon MUST NOT advertise a capability to UMP peers that the plugin cannot honor

---

# 11. Message framing

## 11.1 Frame format

Each IPC message uses:

```text
MessageLength: unsigned 32-bit big-endian
Envelope: MessageLength bytes of canonical protobuf encoding
```

`MessageLength` excludes its own four bytes.

## 11.2 Parsing rules

The receiver MUST:

1. Read exactly four length bytes.
2. Reject zero length.
3. Reject length above the negotiated maximum before allocation.
4. Read exactly `MessageLength` bytes.
5. Parse one envelope.
6. Reject missing or invalid body fields.

## 11.3 Maximum sizes

```text
Default IPC message: 1 MiB
Hard IPC message maximum: negotiated, never above the hard limit
Inline packet bytes: bounded by the carrier packet limit
```

## 11.4 Canonical schema

The canonical protobuf schema lives at:

```text
api/carrier-plugin.proto
```

The schema and this document form one contract.

---

# 12. Message registry

The protocol defines these message classes:

```text
PLUGIN_HELLO
DAEMON_HELLO
CONFIG
START_ACK
OP_REQ
OP_RESP
CANCEL
EVENT
HEARTBEAT
HEARTBEAT_ACK
LOG
GOAWAY
SHUTDOWN
ERROR
```

## 12.1 OP_REQ and OP_RESP

Operations:

```text
Listen
Dial
CloseListener
Send
CloseLink
Discover
Cancel
```

Each operation carries:

```text
operation_id
handle
arguments
deadline
```

Each response carries:

```text
operation_id
status
payload
```

## 12.2 EVENTS

Event types:

```text
LINK_ACCEPTED
LINK_ACTIVE
LINK_DEGRADED
WRITABLE
MTU_CHANGED
QUALITY_CHANGED
ADDRESS_REBOUND
CANDIDATE_FOUND
CANDIDATE_UPDATED
CANDIDATE_EXPIRED
CANDIDATE_REMOVED
DISCOVERY_COMPLETE
HEALTH
CLOSING
CLOSED
FAILED
```

## 12.3 Unknown messages

An unknown critical message closes the IPC.

An unknown optional length-delimited message is skipped.

---

# 13. Handles

## 13.1 Classes

Handles:

```text
Carrier Instance
Listener
Discovery Operation
Candidate
Link
Send Operation
```

## 13.2 Rules

Handles:

* Are unique within one plugin process generation
* MUST NOT cross process generations
* MUST NOT cross resource types
* Are invalid after process restart

The daemon and plugin MUST reject:

* Unknown handles
* Expired handles
* Cross-type handles
* Handles from a previous generation

Rejection MUST NOT allocate new state.

---

# 14. Configuration transfer

The daemon sends scoped configuration after handshake.

Configuration MUST:

* Contain only the plugin's own options
* Separate public and sensitive options
* Reject unknown critical fields
* Enforce sizes and types
* Redact sensitive values from errors and logs

The plugin MUST:

* Validate configuration before applying it
* Report effective configuration in `START_ACK`
* Refuse to start when required options are invalid

---

# 15. Link creation

## 15.1 Listen

The daemon sends `OP_REQ` with operation `Listen`.

The plugin:

* Binds the requested local context
* Returns a Listener handle
* Reports pending-link limits
* Emits `LINK_ACCEPTED` events for inbound carrier connections

## 15.2 Dial

The daemon sends `OP_REQ` with operation `Dial`.

The plugin:

* Binds the dial to one candidate
* Must not substitute another remote target without an authenticated, permitted redirect
* Returns a Link handle on carrier-level setup

A successful dial proves carrier reachability only.

## 15.3 Accept

Accepted Links are delivered as events with a Link handle.

The daemon performs UMP authentication over the Link.

An accepted Link does not imply endpoint authentication, authorization, or trust.

---

# 16. Packet transfer

## 16.1 Methods

Packet transfer uses one of:

```text
Bounded inline bytes
Shared-memory regions with explicit ownership
Platform message buffers
```

The negotiated method MUST preserve packet atomicity and ownership.

## 16.2 Inline

Inline packets are carried inside IPC messages.

The inline maximum is bounded by the carrier packet limit.

## 16.3 Shared memory

Shared-memory transfer rules:

```text
Each region has fixed size and generation
One side owns a slot at a time
Length is validated before access
Slot reuse requires explicit release
Process crash invalidates all slots
```

The plugin MUST NOT retain daemon-owned packet memory after release.

## 16.4 Ownership

A successful send:

* Transfers responsibility for carrier delivery to the plugin
* Lets the daemon release its input buffer
* Does not prove remote peer receipt

A failed send leaves ownership with the caller.

The daemon MUST NOT interpret plugin delivery events as peer delivery.

---

# 17. Discovery

The plugin MAY implement discovery.

Discovery messages:

```text
Discover request with scope, deadline, maximum candidates
Candidate events with source and authentication state
Discovery complete or error
```

The plugin MUST:

* Enforce the candidate maximum
* Stop on cancellation or deadline
* Validate native message sizes before allocation
* Mark source and authentication state
* Avoid interpreting discovery as endpoint trust

---

# 18. Backpressure

## 18.1 Send results

A send operation may return:

```text
ACCEPTED
WOULD_BLOCK
QUEUE_FULL
ERROR
```

## 18.2 Behavior

The plugin MUST provide bounded send acceptance.

When capacity returns, the plugin emits `WRITABLE`.

The daemon:

* Applies backpressure and waits for `WRITABLE`
* Penalizes a path only when backpressure is persistent
* Never buffers unbounded output

The plugin MUST NOT accept an unbounded number of packets or bytes.

---

# 19. Health checks

## 19.1 Heartbeats

The plugin and daemon exchange heartbeats:

```text
Heartbeat interval: 5 seconds (provisional)
Heartbeat timeout: 15 seconds (provisional)
```

## 19.2 Operation deadlines

Every operation carries a monotonic deadline.

The plugin MUST stop operation-specific work after cancellation or deadline.

A cancelled dial that later connects MUST close the carrier connection.

## 19.3 Unhealthy state

The daemon marks a plugin unhealthy after:

```text
Process exit
IPC closure
Heartbeat timeout
Invalid message framing
Handle conflict
Repeated deadline violation
Declared fatal error
```

---

# 20. Crash behavior

On plugin failure, the daemon MUST:

1. Reject new operations.
2. Mark plugin Links failed.
3. Notify session and routing layers.
4. Release shared memory and handles.
5. Restart under policy or disable the instance.

The daemon MUST NOT:

* Bind old Link or send state to a new process
* Restore live carrier state from a crashed generation
* Allow sessions to depend on the failed carrier

Sessions MAY migrate through another Carrier Instance.

---

# 21. Shutdown and drain

The daemon initiates shutdown through `GOAWAY` then `SHUTDOWN`.

During drain:

* New operations are rejected
* Existing operations may finish before the drain deadline
* The plugin flushes accepted sends where the medium permits

The plugin MUST:

* Close listeners
* Close Links with their terminal events
* Release shared-memory slots
* Exit cleanly within the deadline

The daemon terminates the process if the plugin fails to exit.

---

# 22. Restart policy

Repeated crashes cause backoff and disablement under operator policy.

```text
Restart burst: 3 attempts
Restart backoff cap: 5 minutes
```

The daemon MUST:

* Apply exponential backoff with jitter
* Disable repeatedly crashing plugins
* Report plugin health in diagnostics
* Charge process starts against CPU budgets

Repeated restarts MUST NOT bypass cumulative CPU, process-start, or log limits.

---

# 23. Sandboxing expectations

UMC SHOULD apply platform controls:

```text
Linux: namespaces, seccomp, restricted filesystem and capabilities
macOS: sandbox profile where supported
Windows: restricted token, job object, and scoped filesystem access
```

The plugin receives only the network, device, and filesystem access required by its carrier.

Sandboxing behavior:

* Strict mode: sandbox failure prevents startup
* Best-effort mode: reduced isolation is reported

Sandboxing MUST NOT delay the initial protocol implementation.

The process boundary is mandatory; stronger OS confinement matures incrementally.

---

# 24. Logging

Plugin logs:

* Travel through bounded IPC or an operator-approved sink
* MUST NOT contain UMP packet payload bytes
* MUST NOT contain keys, credentials, or invitation secrets
* MUST NOT contain full private candidates
* Are rate-limited by the daemon

Default limits:

```text
Plugin log event: 4 KiB
Log events: 100 per second with 1,000 burst
```

---

# 25. Error model

Plugin errors mirror the carrier error categories:

```text
CANCELLED
DEADLINE_EXCEEDED
INVALID_ARGUMENT
UNSUPPORTED
POLICY_DENIED
NOT_RUNNING
ADDRESS_INVALID
ADDRESS_IN_USE
UNREACHABLE
AUTHENTICATION_FAILED
PACKET_TOO_LARGE
WOULD_BLOCK
QUEUE_FULL
LINK_CLOSED
LINK_FAILED
DEVICE_UNAVAILABLE
PERMISSION_DENIED
PROTOCOL_ERROR
RESOURCE_LIMIT
INTERNAL
```

Errors carry:

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

Source errors MUST NOT cross the network or expose secrets.

---

# 26. Resource limits

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
Heartbeat interval: 5 seconds (provisional)
Heartbeat timeout: 15 seconds (provisional)
Restart burst: 3 attempts
Restart backoff cap: 5 minutes
```

Invalid framing, handle conflicts, or oversize messages close plugin IPC.

---

# 27. Security considerations

## 27.1 Malicious plugin

A plugin can:

* Forge candidates
* Alter or drop packets
* Lie about properties
* Retain shared buffers
* Exhaust IPC

Defenses:

* Process isolation
* Authenticated private IPC created at launch
* Message length, handle, generation, and state validation
* Bounded queues, shared memory, logs, and operation counts
* Key, store, and plaintext withholding
* Link invalidation after crash
* Restart backoff and disablement
* OS sandboxing where available
* Properties treated as untrusted hints

A malicious plugin can deny service or observe traffic sent through its carrier. End-to-end AEAD detects packet alteration and protects payload content.

## 27.2 IPC hijacking

Another local process must not impersonate the plugin or daemon.

The launch token, private endpoint, and generation-scoped handles prevent substitution.

## 27.3 Shared-memory abuse

Slot ownership, generation, and length validation bound shared-memory abuse.

Crash invalidates all slots.

## 27.4 Log abuse

Bounded log rates and sizes prevent log flooding.

---

# 28. Required tests

A compliant implementation MUST test:

1. Process startup with minimal environment.
2. Launch-token authentication.
3. Version negotiation failure.
4. Capability negotiation.
5. Message framing and oversize rejection.
6. Unknown message handling.
7. Handle type, generation, and expiry validation.
8. Listen and dial operations.
9. Accepted Link events.
10. Inline packet transfer ownership.
11. Shared-memory slot ownership and release.
12. Discovery candidate bounds.
13. Backpressure and `WRITABLE` events.
14. Heartbeat timeout.
15. Crash during packet ownership transfer.
16. Crash invalidation of Links and slots.
17. Restart backoff and disablement.
18. Clean shutdown and drain.
19. Sandbox failure in strict mode.
20. Log and error redaction.
21. Resource bounds under message floods.
22. Session migration after plugin failure.
23. Fuzzing of framing and messages.

Property tests SHOULD verify:

```text
Every successful send transfers ownership exactly once.
No packet crosses process generations.
Handles never cross types or generations.
Queued bytes never exceed hard limits.
One plugin generation cannot reuse another's state.
Plugin crashes never corrupt core state.
```

---

# 29. Minimal v0.1 compliance

A compliant implementation MUST support:

* Out-of-process plugin execution
* Private IPC endpoint
* Launch-token authentication
* Protocol handshake
* API version negotiation
* Capability negotiation
* Length-prefixed framing
* Listen, dial, send, and close operations
* Link lifecycle events
* Bounded inline packet transfer
* Discovery operations where advertised
* Backpressure
* Heartbeats
* Crash detection and Link invalidation
* Restart backoff and disablement
* Bounded logs
* Structured errors

An implementation MAY defer:

* Shared-memory packet transfer
* Strict OS sandboxing on unsupported platforms
* Traffic shaping
* Private mimicry profiles

An implementation MUST NOT advertise a deferred capability.

---

# 30. Open design decisions

The project must resolve these items before freezing the plugin API:

1. Canonical protobuf schema layout.
2. Shared-memory layout and ownership protocol.
3. Launch-token delivery per platform.
4. Heartbeat interval finalization.
5. Whether one plugin process hosts several instances.
6. Minimum sandbox requirements for stable external plugins.
7. Property-event rate finalization.
8. Whether inline packets use a dedicated transfer message.
9. Plugin-to-plugin communication policy.
10. Diagnostics access for plugins.
11. Whether plugins may run on loopback TCP in development.
12. Exact operation deadline classes.
13. Plugin capability registry.
14. Whether plugins can be upgraded without restart.
15. Crash-report policy for plugins.

---

# 31. Recommended implementation order

Implement the plugin protocol in this order:

1. Message types and framing.
2. Handles.
3. Handshake and launch authentication.
4. Version negotiation.
5. Capability negotiation.
6. Configuration transfer.
7. Listen and dial operations.
8. Link events.
9. Inline packet transfer.
10. Backpressure.
11. Discovery.
12. Heartbeats.
13. Crash detection and invalidation.
14. Restart policy.
15. Shutdown and drain.
16. Shared-memory transfer.
17. Sandboxing.
18. Fuzzing and adversarial tests.

---

# 32. Core rule

External UMP carriers run in isolated processes and speak one framed, versioned, authenticated protocol to the daemon.

The plugin sees only opaque packets, scoped candidates, and its own configuration. Every message is validated for size, type, handle, generation, and state before it affects core behavior. A plugin crash invalidates only its own links and state, and the daemon restarts or disables it without ever exposing keys, plaintext, or core state.
