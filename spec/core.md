# Universal Mesh Core Project Specification

**Status:** Draft
**Version:** 0.1
**Project type:** Open-source networking core
**Working name:** Universal Mesh Core, UMC
**Protocol family:** Universal Mesh Protocol, UMP

---

# 1. Purpose

Universal Mesh Core is a small, portable, open-source networking runtime for secure communication between cryptographic endpoints across arbitrary communication media.

The project provides:

* A reusable core networking library
* A standalone node daemon
* A command-line control interface
* Carrier adapters
* Local persistence
* Routing and relay functionality
* Store-and-forward delivery
* Developer APIs
* Test and simulation tools
* Small reference applications
* Open protocol specifications

The project does not provide a complete consumer application.

Messaging, websites, payments, internet gateways, file sharing, AI services and other products are expected to be implemented above the core.

---

# 2. Project mission

The project exists to provide:

> A minimal, robust and transport-independent foundation on which decentralized applications can communicate without mandatory central infrastructure.

The core should continue functioning when:

* Some peers disappear
* Network paths change
* Internet access is restricted
* Only local communication is available
* Some relays are malicious
* Some discovery methods fail
* A device moves between networks
* A live path temporarily does not exist
* The original project maintainers no longer operate infrastructure

---

# 3. Relationship between UMC and UMP

The project consists of two related but separate concepts.

## 3.1 UMP

Universal Mesh Protocol defines interoperable network behavior.

It includes specifications for:

* Wire format
* Handshake
* Cryptographic sessions
* Streams
* Datagrams
* Routing
* Relaying
* Discovery
* Store-and-forward
* Carrier interfaces

## 3.2 UMC

Universal Mesh Core is the reference software implementation and reusable runtime.

It includes:

* Protocol implementation
* Runtime services
* Storage
* Scheduling
* Carrier management
* Policy
* APIs
* CLI
* Diagnostics
* Testing tools

UMP is the protocol.

UMC is the software project implementing the protocol.

Independent UMP implementations are explicitly allowed and encouraged.

---

# 4. Core principles

The project MUST follow these principles:

1. No mandatory central server.
2. No mandatory organization-controlled account.
3. No globally privileged node type.
4. No mandatory carrier.
5. No dependency on a complete global node list.
6. No application semantics inside the core.
7. Endpoint identity is independent of location.
8. Session state is independent of a specific socket or carrier.
9. Relays are treated as untrusted.
10. Security does not depend on protocol secrecy.
11. Resource exhaustion is treated as a security problem.
12. Every network-facing parser is fuzz-tested.
13. Protocol specifications are public.
14. Independent implementations are supported.
15. Optional infrastructure must be replaceable.
16. The project must remain usable without project-operated services.
17. The core must be small in responsibility, not necessarily small in code.
18. Platform-specific behavior must not leak into protocol semantics.
19. Experimental features must not silently alter stable interoperability.
20. The project must prefer explicit failure over insecure fallback.

---

# 5. Scope

UMC is responsible for:

* Endpoint identity management
* Secure session establishment
* Carrier abstraction
* Link management
* Peer discovery
* Route discovery
* Packet forwarding
* Relay circuits
* Streams
* Datagrams
* Path migration
* Store-and-forward bundles
* Resource quotas
* Local policy enforcement
* Local application APIs
* Persistent node state
* Diagnostics
* Metrics
* Protocol version negotiation
* Extension loading

UMC is not responsible for:

* User interfaces beyond CLI diagnostics and control
* Contact management
* Social graphs
* Message formats
* Web rendering
* Payment consensus
* Blockchain logic
* Domain naming
* Search
* Application moderation
* Application databases
* User identity verification
* Incentive systems
* Content recommendation
* Application-specific encryption above the transport layer

---

# 6. Product forms

The project SHOULD provide the following outputs.

## 6.1 Core library

A portable library containing:

* Identity
* Cryptography
* Sessions
* Routing
* Relay logic
* Bundle handling
* Carrier abstraction
* Policy
* Persistence interfaces

The library SHOULD be embeddable in other applications.

## 6.2 Node daemon

A long-running process that:

* Owns endpoint keys
* Manages carriers
* Accepts peer connections
* Maintains routes
* Relays traffic
* Stores bundles
* Exposes a local control API
* Hosts application protocol listeners
* Emits diagnostics and metrics

## 6.3 Command-line interface

A CLI used to:

* Initialize a node
* Create identities
* Add peers
* Configure carriers
* Inspect routes
* Open sessions
* Run diagnostics
* Start test services
* Export and import invitations
* Inspect storage and relay state

## 6.4 Development SDK

A developer-facing API used to:

* Register application protocols
* Listen on endpoints
* Connect to endpoints
* Open streams
* Send datagrams
* Publish local service hints
* Receive lifecycle events
* Request communication policies

## 6.5 Test utilities

The project SHOULD include:

* Packet generator
* Protocol decoder
* Network simulator
* Fault injector
* Carrier emulator
* Interoperability runner
* Fuzz targets
* Benchmark suite
* Adversarial node simulator

---

# 7. Runtime model

A UMC node is one running instance of the core.

One node MAY host multiple endpoints.

```text
Node
├── Node management identity
├── User endpoint
├── Service endpoint
├── Gateway endpoint
└── Temporary endpoint
```

A node may operate as:

* Endpoint only
* Relay
* Discovery participant
* Bundle carrier
* Gateway host
* Local bridge
* Any combination of the above

All roles are policy-controlled.

No role is globally privileged.

---

# 8. High-level architecture

```text
Applications
    ↓
Application SDK
    ↓
Local Core API
    ↓
Endpoint Manager
    ↓
Session Manager
    ↓
Routing / Relay / Bundle Layer
    ↓
Link Manager
    ↓
Carrier Manager
    ↓
TCP / UDP / Bluetooth / Wi-Fi / Radio / Other
```

Supporting components:

```text
Identity Store
Policy Engine
Peer Store
Route Cache
Bundle Store
Metrics
Logging
Configuration
Plugin Registry
```

---

# 9. Core modules

The reference implementation SHOULD contain the following modules.

## 9.1 Identity manager

Responsibilities:

* Generate endpoint keys
* Load endpoint keys
* Store identity bindings
* Manage delegation certificates
* Rotate handshake keys
* Process revocations
* Provide signing operations
* Provide endpoint metadata to authorized local applications

The identity manager MUST NOT expose private keys to external applications by default.

## 9.2 Cryptography module

Responsibilities:

* Handshake primitives
* Session key derivation
* Packet encryption
* Header protection
* Signatures
* Key updates
* Secure random generation
* Secret zeroization where supported

The cryptography module MUST use audited libraries.

## 9.3 Carrier manager

Responsibilities:

* Register carrier implementations
* Enable and disable carriers
* Start listeners
* Discover peer candidates
* Dial candidates
* Accept links
* Report carrier metrics
* Apply carrier-specific policy

## 9.4 Link manager

Responsibilities:

* Track adjacent peer links
* Authenticate link-level context where available
* Monitor link health
* Report latency and loss
* Enforce link quotas
* Deduplicate parallel links
* Close unhealthy or unauthorized links

## 9.5 Session manager

Responsibilities:

* Establish secure endpoint sessions
* Track packet-number spaces
* Manage streams
* Manage datagrams
* Perform retransmission
* Enforce flow control
* Perform key updates
* Support path migration
* Resume sessions where allowed

## 9.6 Routing engine

Responsibilities:

* Maintain bounded peer knowledge
* Accept route hints
* Discover routes
* Rank paths
* Prevent loops
* Expire routes
* Maintain route diversity
* Respond to route failures
* Coordinate with relays and bundle storage

## 9.7 Relay engine

Responsibilities:

* Open relay circuits
* Forward opaque traffic
* Enforce quotas
* Maintain circuit state
* Reject unauthorized relay requests
* Tear down expired circuits
* Avoid inspecting inner application data

## 9.8 Bundle manager

Responsibilities:

* Accept store-and-forward bundles
* Enforce storage quotas
* Track expiration
* Deduplicate bundles
* Replicate according to policy
* Forward bundles when routes appear
* Evict bundles safely
* Produce delivery or custody acknowledgements

## 9.9 Discovery manager

Responsibilities:

* Run discovery providers
* Merge candidate results
* Score candidate freshness
* Avoid global enumeration
* Enforce sharing restrictions
* Process invitations
* Import bootstrap bundles
* Discover local peers

## 9.10 Policy engine

Responsibilities:

* Evaluate communication requests
* Select allowed carriers
* Limit relay use
* Limit bundle storage
* Apply trust requirements
* Enforce cost and energy preferences
* Apply censorship-sensitive behavior
* Reject insecure fallback

## 9.11 Persistence layer

Responsibilities:

* Store node configuration
* Store endpoint metadata
* Store peer hints
* Store trusted bindings
* Store route cache
* Store bundles
* Store resumption tickets
* Store revocation state
* Recover after process restart

## 9.12 Control API

Responsibilities:

* Expose local administrative operations
* Authenticate local clients
* Report node state
* Accept configuration changes
* Start and stop listeners
* Provide diagnostics
* Stream events

## 9.13 Metrics and diagnostics

Responsibilities:

* Report performance
* Report carrier health
* Report route success
* Report bundle state
* Report protocol errors
* Report resource usage
* Support debugging without leaking secrets

---

# 10. Core library boundaries

The core library SHOULD be split into two layers.

## 10.1 Protocol-pure layer

Contains deterministic protocol logic:

* Packet parsing
* Frame encoding
* Handshake state machine
* Routing message processing
* Stream state
* Congestion state
* Bundle validation
* Cryptographic transcript logic

This layer SHOULD avoid direct operating-system calls.

## 10.2 Runtime integration layer

Contains:

* Sockets
* Filesystem
* Timers
* Threads or async runtime
* Secure key storage
* Platform integration
* Process control
* Plugin loading

This separation supports:

* Deterministic tests
* Simulation
* Embedded builds
* Alternate runtimes
* Formal state-machine analysis

---

# 11. Programming language

The reference implementation SHOULD use Rust.

Reasons include:

* Memory safety
* Strong type system
* Async support
* Cross-platform compilation
* FFI support
* Embedded potential
* Mature cryptographic ecosystem
* Good fuzzing support

Unsafe Rust MUST be:

* Minimized
* Isolated
* Documented
* Reviewed
* Covered by tests

Protocol interoperability MUST not depend on Rust-specific serialization.

---

# 12. Async runtime

The reference daemon MAY use an async runtime.

Runtime-specific types MUST NOT appear in stable public protocol APIs where avoidable.

The core SHOULD define internal abstractions for:

* Clock
* Timer
* Random source
* Storage
* Task spawning
* Network I/O

This enables deterministic simulation and testing.

---

# 13. Local application API

Applications SHOULD communicate with the core through either:

* Embedded library calls
* Local Unix socket
* Named pipe
* Authenticated loopback socket

The local API MUST distinguish:

* Administrative operations
* Application data operations
* Read-only diagnostics

Administrative access MUST require stronger authorization.

---

# 14. Application programming model

Applications work with endpoints and protocol identifiers.

Example conceptual API:

```rust
let endpoint = core.create_endpoint(config)?;

let listener = core.listen(
    endpoint,
    "org.example.echo/1",
    listen_policy
).await?;

let session = core.connect(
    destination,
    "org.example.echo/1",
    connect_policy
).await?;

let stream = session.open_stream().await?;
stream.write(b"hello").await?;
```

The SDK SHOULD expose:

* Endpoint creation
* Endpoint loading
* Protocol registration
* Session establishment
* Stream open and accept
* Datagram send and receive
* Session events
* Path events
* Delivery events
* Bundle status
* Service discovery events

The SDK MUST NOT expose raw private keys by default.

---

# 15. Local API security

The daemon control interface MUST support:

* Local client authentication
* Permission separation
* Capability-scoped tokens
* Request limits
* Audit logging
* Revocation of local API credentials

A local application MAY be granted permission to:

* Use one endpoint
* Listen on selected protocol identifiers
* Connect to selected destinations
* Send datagrams
* Publish service hints
* Inspect limited session metadata

A local application MUST NOT automatically gain:

* Access to all endpoint identities
* Access to private keys
* Administrative configuration
* Full peer tables
* Other applications’ traffic
* Bundle store contents

---

# 16. Carrier plugin model

Carriers SHOULD be replaceable modules.

A carrier plugin implements:

```rust
trait Carrier {
    fn id(&self) -> CarrierId;
    fn capabilities(&self) -> CarrierCapabilities;
    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
    async fn discover(&self) -> Result<Vec<PeerCandidate>>;
    async fn dial(&self, candidate: PeerCandidate) -> Result<Box<dyn Link>>;
    async fn accept(&self) -> Result<Box<dyn Link>>;
}
```

Carrier plugins MUST NOT:

* Access endpoint private keys
* Bypass session encryption
* Modify application payloads
* Alter protocol semantics
* Access unrelated carrier configuration

Carrier plugins MAY:

* Perform outer encryption
* Perform traffic shaping
* Perform packet framing
* Perform local discovery
* Supply connection metadata
* Bind to external libraries or hardware

---

# 17. Carrier execution isolation

Third-party carrier plugins SHOULD be capable of running:

* In-process for trusted plugins
* Out-of-process for untrusted plugins
* Under restricted filesystem and network permissions
* Through a stable carrier IPC protocol

The project SHOULD eventually support process isolation for censorship-oriented or experimental carriers.

A carrier crash MUST NOT corrupt core state.

---

# 18. Configuration model

Configuration SHOULD be layered:

```text
Built-in defaults
    ↓
System configuration
    ↓
User configuration
    ↓
Environment overrides
    ↓
CLI overrides
    ↓
Runtime API changes
```

Configuration categories include:

* Node identity
* Enabled carriers
* Listener addresses
* Peer bootstrap
* Relay policy
* Storage quotas
* Route limits
* Trust policy
* Logging
* Metrics
* Plugin paths
* Censorship mode
* Resource limits

Sensitive configuration SHOULD be stored separately from ordinary configuration.

---

# 19. Node initialization

The initialization flow SHOULD be:

1. Create node data directory.
2. Generate node management identity.
3. Create default endpoint.
4. Create local API credentials.
5. Initialize encrypted identity store.
6. Initialize peer and route databases.
7. Initialize bundle store.
8. Generate default configuration.
9. Disable public relay behavior by default.
10. Enable only explicitly selected carriers.
11. Print recovery and backup guidance.

No external registration is required.

---

# 20. Persistent state

Persistent state is divided by sensitivity.

## 20.1 Secret state

Includes:

* Private identity keys
* Private handshake keys
* Ticket keys
* Retry keys
* Invitation secrets
* Local API credentials

Secret state MUST be encrypted at rest where the platform supports secure protection.

## 20.2 Trusted state

Includes:

* Known endpoint bindings
* Delegation certificates
* Revocations
* Trust-on-first-use records
* Peer introductions

## 20.3 Operational state

Includes:

* Peer hints
* Route cache
* Link history
* Bundle metadata
* Resumption tickets
* Carrier metrics

## 20.4 Disposable state

Includes:

* Temporary diagnostics
* Cached route failures
* Expired packet history
* Short-term replay filters

Disposable state may be deleted without identity loss.

---

# 21. Storage backend

The reference implementation SHOULD define a storage abstraction.

```rust
trait Store {
    async fn get(&self, namespace: &str, key: &[u8]) -> Result<Option<Vec<u8>>>;
    async fn put(&self, namespace: &str, key: &[u8], value: &[u8]) -> Result<()>;
    async fn delete(&self, namespace: &str, key: &[u8]) -> Result<()>;
    async fn scan(&self, namespace: &str) -> Result<Box<dyn Iterator<Item = Entry>>>;
}
```

The default backend MAY use SQLite or another transactional embedded database.

Large bundle payloads MAY be stored in content-addressed files with metadata in the database.

Storage corruption MUST not result in unsafe key reuse.

---

# 22. Process lifecycle

The daemon SHOULD support:

* Clean start
* Clean shutdown
* Crash recovery
* Configuration reload
* Carrier restart
* Key rotation
* Database migration
* Safe update
* State backup
* State restore

On shutdown, the daemon SHOULD:

* Stop accepting new local requests
* Stop opening new sessions
* Flush critical state
* Persist bundle metadata
* Close carriers
* Erase ephemeral secrets
* Exit within a bounded time

---

# 23. Node operating modes

The daemon MAY expose predefined operating profiles.

## 23.1 Endpoint mode

* No public relaying
* Limited discovery
* Standard local storage
* Normal outgoing connections

## 23.2 Relay mode

* Allows bounded relay circuits
* Enforces bandwidth quotas
* Exposes relay capability
* Stores no application plaintext

## 23.3 Local mesh mode

* Prioritizes local carriers
* Enables LAN discovery
* Allows disconnected bundles
* Avoids internet assumptions

## 23.4 Private bridge mode

* Requires invitation authentication
* Hides protocol behavior from unauthenticated probes
* Restricts peer sharing
* Limits public advertisements

## 23.5 Gateway host mode

* Allows a separate gateway application
* Advertises gateway service
* Does not implement gateway semantics in the core

Profiles are configuration presets, not separate protocol variants.

---

# 24. Routing subsystem

The routing engine MUST maintain bounded state.

A node SHOULD track:

* Direct peers
* Recently successful next hops
* Trusted introductions
* Expiring route hints
* Failed route history
* Candidate gateway paths
* Local-only paths

A node MUST NOT require a complete node list.

Routing decisions SHOULD consider:

* Reachability
* Trust
* Latency
* Loss
* Bandwidth
* Energy cost
* Monetary cost
* Path diversity
* Carrier diversity
* Censorship risk
* Relay policy
* Application policy

---

# 25. Routing strategy interface

The routing engine SHOULD support pluggable route-selection strategies.

```rust
trait RouteStrategy {
    fn select_paths(
        &self,
        destination: &EndpointHint,
        candidates: &[PathCandidate],
        policy: &ConnectionPolicy,
    ) -> Vec<PathCandidate>;
}
```

The first implementation MAY use a simple weighted strategy.

The protocol MUST not require all implementations to use identical internal scoring.

Interoperability depends on message behavior, not route-scoring algorithms.

---

# 26. Peer knowledge model

Peer knowledge SHOULD be divided into:

* Direct peers
* Introduced peers
* Public bootstrap peers
* Private peers
* Local peers
* Ephemeral peers
* Recently observed peers

Each peer record SHOULD contain:

* Temporary identifiers
* Carrier hints
* Introduction source
* Last successful contact
* Last failure
* Expiration
* Sharing policy
* Local trust score
* Observed capabilities

Peer records MUST NOT be interpreted as identity trust.

---

# 27. Trust model

UMC provides cryptographic authentication but not universal human trust.

The core SHOULD support local trust states:

```text
Unknown
Observed
Introduced
Trusted
Restricted
Blocked
Revoked
```

Trust may affect:

* Session acceptance
* Peer-hint exchange
* Relay access
* Bundle storage
* Route preference
* Service advertisement acceptance

Trust decisions are local.

There is no global reputation authority.

---

# 28. Relay policy

Relay operation MUST be opt-in.

Relay policy SHOULD support:

* Maximum concurrent circuits
* Maximum bytes per circuit
* Maximum lifetime
* Maximum hops
* Allowed trust levels
* Allowed carriers
* Allowed destination classes
* Per-peer quotas
* Global quotas
* Rate limits
* Emergency disablement

The default installation SHOULD not become an unrestricted public relay.

---

# 29. Bundle policy

Bundle storage MUST be opt-in or conservatively enabled.

Policy SHOULD define:

* Maximum bundle size
* Maximum total storage
* Maximum per-peer storage
* Maximum lifetime
* Maximum replication count
* Accepted priorities
* Trusted senders
* Eviction order
* Local-only storage
* Custody behavior

Bundles MUST remain encrypted for their final endpoints.

---

# 30. Resource management

Every node MUST enforce hard limits.

Required limits include:

* Open links
* Pending handshakes
* Established sessions
* Streams per session
* Total buffered stream bytes
* Datagram queue size
* Route requests per peer
* Peer records
* Relay circuits
* Relay bandwidth
* Bundle storage
* Discovery responses
* Fuzz-resistant parser allocation
* Logging volume
* Plugin resource usage

No network message may force unbounded allocation.

---

# 31. Scheduling and fairness

The runtime SHOULD use fair scheduling across:

* Applications
* Sessions
* Peers
* Relays
* Bundles
* Carriers

Priority classes MAY include:

```text
Control
Interactive
Normal
Bulk
Background
Bundle
```

Control traffic must not be starved by bulk traffic.

A single peer or application must not monopolize the node.

---

# 32. Backpressure

Backpressure MUST propagate from carriers to applications.

If the network cannot accept more data:

* Stream writes SHOULD block or return pending.
* Datagram sends MAY be dropped according to policy.
* Bundle creation MAY be rejected.
* Local applications SHOULD receive explicit resource errors.

The core MUST NOT indefinitely buffer unbounded application output.

---

# 33. Congestion control

Congestion control belongs to the session and path layers.

The implementation SHOULD:

* Maintain per-path congestion state
* Adapt to loss and delay
* Avoid flooding low-bandwidth carriers
* Distinguish carrier backpressure from path loss
* Avoid duplicating excessive traffic over multiple paths

Congestion-control algorithms SHOULD be replaceable.

---

# 34. Path migration

The core SHOULD treat a session as independent of its current path.

A session may move between:

* Network interfaces
* IP addresses
* Relays
* Carriers
* Local and global connectivity

Path migration MUST preserve:

* Authentication
* Stream state
* Flow control
* Packet ordering
* Application session identity

Applications SHOULD receive migration events but should not need to reconnect.

---

# 35. Discovery providers

The reference implementation SHOULD define a discovery provider interface.

```rust
trait DiscoveryProvider {
    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
    async fn candidates(&self) -> Result<Vec<PeerCandidate>>;
    async fn publish(&self, hint: PeerHint) -> Result<()>;
}
```

Possible providers:

* Static configuration
* LAN broadcast
* Local Bluetooth
* Peer exchange
* Signed invitation
* Bootstrap file
* DHT-like lookup
* HTTPS-based optional bootstrap
* Removable media
* Application introduction

No single provider is mandatory for all deployments.

---

# 36. Service discovery

The core MAY support opaque service hints.

A service hint contains:

* Protocol identifier
* Endpoint hint
* Expiration
* Opaque metadata
* Signature

The core does not interpret application metadata.

Service discovery MUST remain optional.

Applications may implement their own discovery protocols.

---

# 37. Censorship-resilience subsystem

Censorship resilience is a cross-cutting property, not one transport.

The project SHOULD support:

* Carrier plugins
* Private invitations
* Non-enumerable peers
* Address rotation
* Session migration
* Multiple discovery paths
* Anti-probing modes
* Traffic-shaping plugins
* Local continuity
* Rapid carrier replacement

The stable core MUST not assume that one carrier remains available.

---

# 38. Threat model

The project assumes adversaries may:

* Observe traffic
* Block addresses and ports
* Use deep packet inspection
* Actively probe nodes
* Operate malicious peers
* Create Sybil nodes
* Poison routing information
* Attempt eclipse attacks
* Flood handshakes
* Flood route discovery
* Exhaust relay resources
* Exhaust storage
* Corrupt packets
* Drop packets
* Delay packets
* Modify peer hints
* Compromise some relays
* Remove public bootstrap infrastructure

The project does not assume protection against:

* Compromised endpoint devices
* Broken cryptographic primitives
* Full shutdown of every communication medium
* Global compromise of all peers
* Physical coercion
* Unrestricted global traffic analysis

---

# 39. Security architecture

Security responsibilities are divided as follows:

## Core

* Identity
* Handshake
* Session encryption
* Replay protection
* Routing validation
* Resource limits
* Key lifecycle
* Plugin boundaries

## Carriers

* Byte delivery
* Optional outer encryption
* Optional obfuscation
* Carrier-specific authentication
* Carrier-specific framing

## Applications

* Application authorization
* Application data formats
* End-user trust
* Content validation
* Payment semantics
* Group membership

The core MUST not imply that transport encryption alone solves application trust.

---

# 40. Security process

The project MUST maintain:

* Threat model
* Security policy
* Vulnerability reporting process
* Supported-version policy
* Dependency audit process
* Release-signing process
* Security review checklist
* Cryptographic review record
* Incident-response procedure

Before production claims, the project SHOULD undergo:

* Independent protocol review
* Cryptographic review
* Parser audit
* Fuzzing campaign
* Adversarial testing
* Dependency review
* Reproducible-build review

---

# 41. Logging

Logs MUST be structured and leveled.

Recommended levels:

```text
Error
Warn
Info
Debug
Trace
```

Default logs MUST NOT include:

* Private keys
* Session keys
* Invitation secrets
* Application plaintext
* Full private peer tables
* Full bundle payloads
* Full resumption tickets

Sensitive endpoint identifiers SHOULD be redacted or shortened by default.

---

# 42. Metrics

Metrics SHOULD include:

* Active links
* Active sessions
* Active streams
* Carrier success rates
* Route success rates
* Handshake failures
* Relay throughput
* Bundle counts
* Bundle delivery latency
* Storage usage
* Packet loss
* Retransmissions
* Path migrations
* Resource-limit rejections

Metrics MUST not expose secret material.

Public metric endpoints SHOULD be disabled by default.

---

# 43. Diagnostics

The CLI SHOULD provide:

```text
umc status
umc doctor
umc carriers
umc peers
umc routes
umc sessions
umc storage
umc identity
umc ping
umc trace
umc benchmark
```

`umc doctor` SHOULD inspect:

* Key-store health
* Database health
* Carrier availability
* Clock anomalies
* Port conflicts
* Route failures
* Quota exhaustion
* Version compatibility
* Plugin failures

Diagnostics SHOULD distinguish local failure from remote censorship only when evidence supports that conclusion.

---

# 44. CLI specification

The initial CLI SHOULD include:

```text
umc init
umc run
umc stop
umc status

umc identity create
umc identity list
umc identity inspect
umc identity rotate
umc identity export-public

umc peer add
umc peer remove
umc peer list
umc peer inspect
umc peer block

umc invite create
umc invite import
umc invite revoke

umc carrier list
umc carrier enable
umc carrier disable
umc carrier configure

umc route list
umc route inspect
umc route probe

umc session list
umc session inspect
umc session close

umc bundle list
umc bundle inspect
umc bundle delete

umc relay status
umc relay enable
umc relay disable

umc listen
umc connect
umc ping
umc doctor
```

The CLI is for control and testing, not the primary application platform.

---

# 45. Reference applications

The repository SHOULD include very small applications.

## Echo

Tests:

* Handshake
* Stream establishment
* Relay
* Migration

## Terminal chat

Tests:

* Interactive streams
* Local connectivity
* Store-and-forward

## File transfer

Tests:

* Flow control
* Large streams
* Integrity
* Resumption

## Static content server

Tests:

* Protocol registration
* Service hints
* Multiple clients

## Carrier-switch test

Tests:

* Path validation
* Live migration
* Stream continuity

## Relay test

Tests:

* Relay authorization
* Quotas
* Multi-hop traffic

Reference applications MUST remain outside the core library.

---

# 46. Repository structure

```text
/
├── Cargo.toml
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── GOVERNANCE.md
├── CODE_OF_CONDUCT.md
│
├── crates/
│   ├── umc-core/
│   ├── umc-wire/
│   ├── umc-crypto/
│   ├── umc-handshake/
│   ├── umc-session/
│   ├── umc-routing/
│   ├── umc-relay/
│   ├── umc-bundles/
│   ├── umc-discovery/
│   ├── umc-policy/
│   ├── umc-storage/
│   ├── umc-sdk/
│   └── umc-control-api/
│
├── carriers/
│   ├── tcp/
│   ├── udp/
│   ├── lan/
│   └── carrier-sdk/
│
├── daemon/
├── cli/
│
├── examples/
│   ├── echo/
│   ├── chat/
│   ├── file-transfer/
│   ├── static-service/
│   ├── relay-test/
│   └── carrier-switch/
│
├── spec/
│   ├── project.md
│   ├── core.md
│   ├── protocol.md
│   ├── wire-format.md
│   ├── handshake.md
│   ├── routing.md
│   ├── relay.md
│   ├── discovery.md
│   ├── bundles.md
│   ├── carrier-api.md
│   ├── local-api.md
│   ├── threat-model.md
│   └── security.md
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── interoperability/
│   ├── simulation/
│   ├── adversarial/
│   └── fuzz/
│
├── tools/
│   ├── packet-inspector/
│   ├── network-simulator/
│   ├── interop-runner/
│   └── test-vector-generator/
│
└── docs/
```

---

# 47. Testing strategy

The project MUST include several distinct test classes.

## Unit tests

Test isolated logic.

## Integration tests

Test modules together.

## Interoperability tests

Test independent implementations or protocol versions.

## Simulation tests

Test large virtual networks.

## Adversarial tests

Test malicious and censored conditions.

## Fuzz tests

Test all network-facing parsers.

## Property tests

Test invariants such as:

* Packet numbers never repeat under one key
* Route loops are rejected
* Flow-control limits never decrease
* Duplicate bundles are not stored twice
* Invalid signatures never authenticate
* Session state survives valid path migration
* Resource limits remain bounded

## Long-running tests

Test:

* Memory leaks
* Route churn
* Key updates
* Carrier reconnects
* Database growth
* Bundle expiration
* Repeated process restart

---

# 48. Network simulator

The project SHOULD include a deterministic simulator capable of modeling:

* Nodes
* Links
* Latency
* Packet loss
* Bandwidth
* Partitions
* Mobility
* Carrier availability
* Malicious peers
* Sybil populations
* Eclipse attempts
* Route poisoning
* Censorship filters
* Active probing
* Intermittent contact

The simulator SHOULD use the same protocol state machines as the production implementation where practical.

---

# 49. Fuzzing requirements

Fuzz targets MUST include:

* Varint decoder
* Packet parser
* Frame parser
* Handshake parser
* Identity binding parser
* Route parser
* Relay parser
* Bundle parser
* Carrier framing parser
* Local control API parser
* Database recovery logic

Fuzzing SHOULD run continuously in CI or dedicated infrastructure.

---

# 50. Compatibility policy

Protocol compatibility and software compatibility are separate.

## Protocol version

Controls network interoperability.

## Core library version

Controls developer API compatibility.

## Daemon API version

Controls local control clients.

## Storage schema version

Controls persisted state.

## Carrier plugin API version

Controls plugin compatibility.

Each version MUST be explicit.

A software release MUST document all supported versions.

---

# 51. Versioning

The project SHOULD use semantic versioning for software releases.

Before `1.0`:

* Breaking API changes are allowed.
* Protocol changes must remain explicitly versioned.
* Storage migrations must be tested.
* Experimental features must be marked.

After `1.0`:

* Stable APIs require deprecation periods.
* Stable protocol versions require compatibility commitments.
* Security-critical incompatibilities may override normal deprecation.

---

# 52. Release channels

The project MAY provide:

* Stable
* Beta
* Nightly

Stable MUST exclude unreviewed experimental cryptography.

Nightly features MUST not silently connect to stable networks using incompatible semantics.

Experimental carriers SHOULD be explicitly marked.

---

# 53. Release security

Official releases SHOULD provide:

* Signed source tags
* Signed binaries
* Checksums
* Reproducible build instructions
* Dependency lockfiles
* Software bill of materials
* Security notes
* Migration notes

Release signing keys MUST be protected and rotatable.

No network functionality should require binaries signed by one organization.

---

# 54. Governance

The project SHOULD have public governance.

Governance SHOULD define:

* Maintainer roles
* Merge authority
* Specification change process
* Security embargo process
* Release authority
* Conflict resolution
* Maintainer succession
* Removal of inactive maintainers
* Protocol extension registry management

No single maintainer should permanently control the protocol.

---

# 55. Specification change process

Protocol changes SHOULD use proposal documents.

A proposal SHOULD contain:

* Motivation
* Threat-model impact
* Wire-format impact
* Compatibility impact
* Privacy impact
* Resource impact
* Alternatives
* Migration plan
* Test plan

Security-critical protocol changes require independent review before stabilization.

---

# 56. Extension registries

The project SHOULD maintain public registries for:

* Protocol versions
* Cryptographic profiles
* Frame types
* Capability identifiers
* Carrier identifiers
* Error codes
* Application protocol identifier recommendations

The registry MUST not create dependency on an online central authority at runtime.

Registry coordination is a development process, not a network dependency.

Private and experimental ranges SHOULD exist.

---

# 57. Application protocol identifiers

Applications SHOULD use names such as:

```text
org.example.chat/1
com.company.service/2
mesh.community.files/1
```

The core treats protocol identifiers as opaque selectors.

The project SHOULD recommend collision-resistant naming but MUST NOT require runtime registry lookup.

---

# 58. Documentation

Required documentation includes:

* Project overview
* Architecture
* Protocol specifications
* API reference
* Carrier development guide
* Application development guide
* Security model
* Threat model
* Deployment guide
* Troubleshooting guide
* Interoperability guide
* Contribution guide

Documentation examples MUST not imply guarantees the protocol does not provide.

---

# 59. Licensing

The core SHOULD use a permissive open-source license or a widely accepted reciprocal license.

The license should permit:

* Independent implementations
* Commercial use
* Academic research
* Forks
* Alternative distributions
* Security audits

Cryptographic and dependency licenses MUST be reviewed for compatibility.

---

# 60. Dependency policy

Dependencies SHOULD be:

* Minimal
* Maintained
* Auditable
* License-compatible
* Pinned for releases

Security-sensitive dependencies require stricter review.

The project SHOULD avoid:

* Unnecessary web frameworks
* Heavy application dependencies
* Unmaintained cryptography
* Runtime dependency on external cloud services
* Automatic telemetry dependencies

---

# 61. Telemetry

UMC MUST NOT send telemetry by default.

Optional telemetry MUST be:

* Explicitly enabled
* Documented
* Minimized
* Anonymous where possible
* Independently hostable
* Disableable
* Unnecessary for core operation

Crash reports MUST not include secret material.

---

# 62. Build targets

The reference implementation SHOULD initially target:

* Linux
* macOS
* Windows

Later targets MAY include:

* Android
* iOS library integration
* OpenWrt
* FreeBSD
* Embedded Linux
* WASI
* Microcontroller environments

The first release should prioritize correctness and portability over maximum platform coverage.

---

# 63. Minimal v0.1 project deliverable

The first meaningful release SHOULD include:

1. Core Rust library.
2. Node daemon.
3. CLI.
4. Persistent endpoint identity.
5. UMP v0.1 handshake.
6. UMP packet parser and encoder.
7. Reliable streams.
8. Unreliable datagrams.
9. TCP carrier.
10. UDP carrier.
11. LAN discovery.
12. Direct sessions.
13. Single-relay sessions.
14. Basic route discovery.
15. Basic path migration.
16. Resource quotas.
17. Echo application.
18. Terminal chat.
19. File-transfer example.
20. Fuzz targets.
21. Interoperability vectors.
22. Threat-model document.
23. Security policy.
24. Public protocol specifications.

Store-and-forward MAY be included in v0.1 or delivered in v0.2 if implementation risk becomes too high.

---

# 64. Development phases

## Phase 0: Foundations

Deliver:

* Repository
* Build system
* Coding standards
* CI
* Wire parser
* Test vectors
* Threat model

## Phase 1: Secure direct communication

Deliver:

* Identity
* Handshake
* Session encryption
* Streams
* Datagrams
* TCP and UDP carriers
* CLI echo test

## Phase 2: Node runtime

Deliver:

* Daemon
* Local API
* Persistence
* Configuration
* Metrics
* Diagnostics

## Phase 3: Routing and relaying

Deliver:

* Peer exchange
* Route discovery
* Single relay
* Route expiry
* Relay quotas

## Phase 4: Mobility

Deliver:

* Multiple paths
* Path validation
* Carrier migration
* Session resumption

## Phase 5: Local mesh

Deliver:

* LAN discovery
* Local peer preference
* Local carrier adapter
* Disconnected operation tests

## Phase 6: Store-and-forward

Deliver:

* Bundle storage
* Expiration
* Replication limits
* Intermittent delivery

## Phase 7: Adversarial resilience

Deliver:

* Private invitations
* Anti-probing mode
* Peer-table privacy
* Sybil mitigations
* Experimental censorship-resistant carriers

---

# 65. Success criteria

The project is successful at the core level when:

1. Two nodes can create identities without external services.
2. Two nodes can establish an encrypted session.
3. Applications can exchange streams and datagrams.
4. A session can route through an untrusted relay.
5. A session can survive a carrier change.
6. Nodes can discover one another locally.
7. Nodes can operate without global internet access.
8. A delayed bundle can be delivered after connectivity returns.
9. Independent applications can use the same core.
10. Independent implementations can interoperate.
11. No project-operated server is required.
12. Resource use remains bounded under malicious input.
13. Protocol parsers survive sustained fuzzing.
14. Blocking one carrier does not disable the architecture.
15. A fork can continue the network without permission from the original maintainers.

---

# 66. Explicit non-success criteria

The project should not measure success by:

* Number of built-in applications
* Number of features in the daemon
* Inclusion of payments
* Inclusion of a browser
* Inclusion of a social network
* Inclusion of a token
* Number of project-operated nodes
* Dependence on one public bootstrap service
* Claims of complete anonymity
* Claims of being permanently unblockable

The core is successful when it enables others to build those systems independently.

---

# 67. Open project decisions

The following remain unresolved:

1. Final project name.
2. Final protocol name.
3. License.
4. Rust workspace structure.
5. Async runtime choice.
6. Default storage backend.
7. Local control API encoding.
8. Plugin isolation mechanism.
9. Whether bundle support ships in v0.1.
10. Default trust policy.
11. Default relay policy.
12. Default carrier set.
13. Stable SDK language bindings.
14. Extension proposal process.
15. Governance model.
16. Release-signing process.
17. Supported operating systems for first release.
18. Whether mobile bindings belong in the main repository.
19. Whether routing strategies are dynamically pluggable.
20. Whether congestion control is internal or plugin-based.

---

# 68. Core project statement

Universal Mesh Core is the reference implementation of an open, transport-independent networking system for authenticated, encrypted and disruption-tolerant communication between cryptographic endpoints.

The project provides a portable core library, node daemon, CLI, carrier system, local application API, routing, relaying and bounded persistent storage.

It does not define the products built above it.

The architecture is designed so that identities, sessions, routes, carriers, applications and project governance remain separate.

No specific company, server, application, carrier or maintainer is required for the network to continue operating.
