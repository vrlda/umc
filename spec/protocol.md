# Universal Mesh Core Protocol Specification

**Status:** Draft
**Version:** 0.1
**Working name:** Universal Mesh Protocol, UMP
**Purpose:** Open, transport-independent, decentralized communication between cryptographic endpoints.

---

# 1. Overview

UMP is a networking protocol and software core for exchanging application data between cryptographic endpoints over arbitrary communication media.

UMP does not require:

* Central servers
* Central identity providers
* Central naming authorities
* A globally available internet connection
* A specific transport protocol
* A complete global node list
* A blockchain
* A specific application

UMP may operate over:

* UDP
* TCP
* Raw Ethernet
* Local Wi-Fi
* Wi-Fi Direct
* Bluetooth
* Serial links
* Packet radio
* WebSocket
* WebRTC
* HTTP-compatible carriers
* Future carrier implementations

UMP defines its own:

* Endpoint identity model
* Secure session protocol
* Frame format
* Stream and datagram semantics
* Relay protocol
* Route discovery model
* Path migration model
* Store-and-forward model
* Carrier abstraction
* Resource-control mechanisms

Applications built on UMP exchange opaque application payloads. The core does not interpret application semantics.

---

# 2. Design goals

UMP MUST provide:

1. Cryptographic endpoint identity.
2. Mutual authentication.
3. End-to-end encryption.
4. Forward secrecy.
5. Direct and relayed communication.
6. Carrier independence.
7. Path migration.
8. Multi-hop routing.
9. Local-network operation without internet access.
10. Store-and-forward delivery.
11. Partial and decentralized peer discovery.
12. Protection against replay, spoofing and route manipulation.
13. Resistance to node enumeration.
14. Resistance to active protocol probing.
15. Strict resource limits.
16. Extensibility without mandatory central coordination.
17. Support for independent implementations.

UMP SHOULD provide:

1. Multipath communication.
2. Traffic padding.
3. Carrier negotiation.
4. Gateway discovery.
5. Intermittent-contact routing.
6. Optional anonymous source addressing.
7. Pluggable anti-censorship carriers.

UMP does not guarantee:

* Availability under complete communication shutdown
* Perfect anonymity
* Protection from compromised endpoints
* Protection from global traffic analysis
* Guaranteed delivery
* Guaranteed low latency
* Offline financial finality
* Universal censorship resistance

---

# 3. Non-goals

The UMP core MUST NOT define:

* User accounts
* Usernames
* Contact lists
* Social graphs
* Messaging formats
* Website formats
* Search engines
* Payment systems
* Blockchains
* Application-level moderation
* Application-specific databases
* Content recommendation systems
* Human-readable global naming

These MAY be implemented by applications or optional protocols above UMP.

---

# 4. Terminology

## 4.1 Endpoint

A cryptographic identity capable of sending or receiving UMP traffic.

An endpoint may represent:

* A device
* A user
* A service
* A gateway
* A temporary process
* An application instance

UMP does not assign semantic meaning to endpoints.

## 4.2 Node

A running UMP implementation that participates in communication, routing, relaying, storage or discovery.

A node MAY host multiple endpoints.

## 4.3 Peer

A node with which another node has established or may establish a direct carrier link.

## 4.4 Carrier

A mechanism that transfers bytes or datagrams between adjacent peers.

Examples include UDP, Bluetooth and TCP.

## 4.5 Link

An active carrier connection between two adjacent peers.

## 4.6 Session

An authenticated encrypted relationship between endpoints.

A session is independent of any individual link, path or carrier.

## 4.7 Path

An ordered sequence of nodes and links through which session traffic travels.

## 4.8 Relay

A node that forwards encrypted UMP traffic without accessing its application payload.

## 4.9 Bundle

An encrypted object that may be stored and forwarded when no continuous route is available.

## 4.10 Protocol identifier

An application-defined identifier used to distinguish application protocols carried over UMP.

Example:

```text
org.example.chat/1
```

---

# 5. Architectural model

UMP is divided into six logical layers.

```text
Application protocol
        ↓
Endpoint API
        ↓
Secure session layer
        ↓
Routing and relay layer
        ↓
Carrier abstraction
        ↓
Physical or virtual communication medium
```

## 5.1 Application layer

Applications exchange opaque messages, streams or datagrams.

## 5.2 Endpoint layer

The endpoint layer manages:

* Endpoint identities
* Protocol registration
* Session requests
* Authorization
* Application delivery

## 5.3 Session layer

The session layer manages:

* Authentication
* Encryption
* Multiplexing
* Reliability
* Replay protection
* Path migration
* Flow control

## 5.4 Routing layer

The routing layer manages:

* Peer discovery
* Route discovery
* Relaying
* Loop prevention
* Route expiry
* Gateway advertisements
* Store-and-forward decisions

## 5.5 Carrier layer

The carrier layer exchanges frames between adjacent nodes.

## 5.6 Medium layer

The medium may be:

* Internet
* LAN
* Bluetooth
* Radio
* Serial
* Any future communication channel

---

# 6. Endpoint identity

## 6.1 Key-based identity

Every persistent endpoint MUST possess a long-term asymmetric identity key pair.

```text
EndpointID = HASH(identity_public_key)
```

Endpoint identifiers MUST NOT directly contain:

* IP addresses
* Device serial numbers
* Usernames
* Geographic information
* Transport details

## 6.2 Identity algorithms

Version 0.1 SHOULD support one mandatory identity-signature suite.

Recommended initial suite:

```text
Ed25519 signatures
SHA-256 or BLAKE3 identifiers
```

The algorithm suite MUST be versioned.

## 6.3 Session keys

Long-term identity keys MUST NOT directly encrypt application traffic.

Each session MUST use ephemeral session keys established through an authenticated key exchange.

## 6.4 Device delegation

A persistent identity MAY authorize additional endpoint keys through signed delegation certificates.

A delegation certificate SHOULD include:

```text
issuer endpoint ID
delegated public key
allowed capabilities
creation time
expiration time
certificate sequence
signature
```

## 6.5 Revocation

UMP SHOULD support signed revocation statements.

Revocation delivery is best-effort and MAY be delayed in disconnected networks.

Applications MUST account for potentially stale revocation state.

---

# 7. Carrier abstraction

UMP MUST NOT depend on a specific carrier.

Every carrier implementation MUST expose a common logical interface.

```rust
trait Carrier {
    async fn discover(&self) -> Result<Vec<PeerCandidate>>;
    async fn dial(&self, candidate: &PeerCandidate) -> Result<Box<dyn Link>>;
    async fn accept(&self) -> Result<Box<dyn Link>>;
    fn capabilities(&self) -> CarrierCapabilities;
}
```

Each active link MUST provide:

```rust
trait Link {
    async fn send(&mut self, frame: &[u8]) -> Result<()>;
    async fn receive(&mut self) -> Result<Vec<u8>>;
    async fn close(&mut self) -> Result<()>;
    fn properties(&self) -> LinkProperties;
}
```

## 7.1 Carrier capabilities

A carrier SHOULD report:

```text
maximum frame size
reliable or unreliable
ordered or unordered
stream or datagram
estimated bandwidth
estimated latency
monetary cost
energy cost
broadcast capability
local-only status
metered status
address stability
```

## 7.2 Mandatory carriers

A v0.1 reference implementation SHOULD provide:

* UDP carrier
* TCP carrier
* LAN discovery carrier

At least one local non-internet carrier SHOULD be added after the core protocol stabilizes.

## 7.3 Carrier independence

The same UMP session MUST be able to migrate between different carriers.

Example:

```text
UDP → TCP → Bluetooth → Wi-Fi
```

Applications MUST NOT be required to reconnect when migration succeeds.

---

# 8. Link protocol

A link exists only between adjacent peers.

A link MUST NOT imply endpoint trust.

The link layer provides:

* Framing
* Peer-level authentication where available
* Link keepalive
* Link metrics
* Link error reporting
* Optional link encryption

End-to-end session encryption remains mandatory even when link encryption exists.

## 8.1 Link identifiers

Each link MUST have a locally unique identifier.

Link identifiers MUST NOT be globally stable.

## 8.2 Link establishment

A carrier MAY establish a physical connection before UMP authentication.

UMP MUST avoid revealing a recognizable protocol response to unauthenticated active probes when anti-probing mode is enabled.

## 8.3 Link keepalive

Keepalive behavior MUST be configurable by carrier.

Long-lived keepalives SHOULD be avoided on:

* Battery-constrained devices
* Metered networks
* Intermittent carriers
* Censored networks where timing fingerprints matter

---

# 9. Core frame format

UMP frames MUST be compact, versioned and independently parseable.

A conceptual frame header:

```text
version
frame type
flags
connection-local identifier
packet number
payload length
encrypted payload
authentication tag
```

The exact binary encoding MUST be separately specified.

## 9.1 Requirements

Frame parsing MUST:

* Reject malformed lengths.
* Reject unsupported versions.
* Avoid unbounded memory allocation.
* Avoid recursive parsing.
* Avoid expensive work before authentication.
* Support fuzz testing.
* Support forward-compatible extensions.

## 9.2 Frame types

Version 0.1 SHOULD define:

```text
INIT
RETRY
HANDSHAKE
SESSION
STREAM
DATAGRAM
ACK
PING
CLOSE
ROUTE_REQUEST
ROUTE_RESPONSE
RELAY
BUNDLE
PATH_CHALLENGE
PATH_RESPONSE
MIGRATE
ERROR
```

Externally visible error details SHOULD be minimized before authentication.

---

# 10. Secure handshake

The handshake establishes an authenticated encrypted session.

## 10.1 Handshake goals

The handshake MUST provide:

* Mutual authentication
* Forward secrecy
* Replay resistance
* Downgrade resistance
* Key confirmation
* Transcript integrity
* Algorithm negotiation
* Minimal unauthenticated processing
* Optional identity hiding
* Optional active-probing resistance

## 10.2 Recommended construction

Version 0.1 SHOULD use an established authenticated key-exchange framework such as a Noise Protocol Framework pattern.

UMP MUST NOT invent new cryptographic primitives.

A suitable pattern SHOULD support:

* Static endpoint identity keys
* Ephemeral Diffie–Hellman keys
* Encrypted transmission of long-term identity
* Pre-shared secret support for private bridges

## 10.3 Handshake phases

Conceptually:

```text
1. Initiator sends a minimal initiation frame.
2. Responder validates a cookie or hidden authenticator.
3. Both sides exchange ephemeral keys.
4. Endpoint identities are authenticated.
5. Capabilities and versions are negotiated.
6. Session traffic keys are derived.
7. Both sides confirm the transcript.
```

## 10.4 Denial-of-service protection

Before successful authentication, a responder SHOULD:

* Avoid large memory allocations.
* Avoid maintaining long-lived state.
* Use stateless retry cookies where appropriate.
* Rate-limit source addresses or carrier identities.
* Avoid expensive signature verification when possible.
* Cap handshake message sizes.

## 10.5 Identity protection

Long-term endpoint identifiers SHOULD NOT appear in plaintext in the first handshake message.

Private-entry nodes MAY require a pre-shared bridge secret before revealing UMP behavior.

---

# 11. Session model

A session exists between two endpoints.

A session MUST NOT be permanently associated with:

* An IP address
* A socket
* A carrier
* A relay
* A single route

## 11.1 Session identifier

Each session MUST have an unpredictable temporary session identifier.

Session identifiers MUST NOT be derived directly from endpoint identifiers.

## 11.2 Session capabilities

Peers MAY negotiate:

* Reliable streams
* Unreliable datagrams
* Ordered messages
* Unordered messages
* Multipath support
* Store-and-forward support
* Compression
* Padding
* Maximum frame size
* Maximum stream count

## 11.3 Session resumption

UMP SHOULD support short-lived encrypted resumption tokens.

Resumption tokens MUST:

* Expire
* Be bound to the endpoint identities
* Be protected from modification
* Not expose long-term identity in plaintext
* Be revocable through key rotation

---

# 12. Streams and datagrams

## 12.1 Streams

A session MAY contain multiple bidirectional or unidirectional streams.

Each stream MUST have:

```text
stream ID
protocol identifier
flow-control state
priority
open/closed state
```

Streams SHOULD support:

* Ordered reliable bytes
* Independent flow control
* Independent cancellation
* Half-close
* Backpressure

## 12.2 Datagrams

Sessions MAY support unreliable datagrams.

Datagrams SHOULD support:

* Application-defined expiration
* Priority
* Maximum size
* Duplicate suppression where requested

Datagrams MUST NOT be retransmitted unless requested by the application or session policy.

## 12.3 Protocol identifiers

When opening a stream, an initiator MUST identify the application protocol.

Example:

```text
org.example.echo/1
org.example.chat/1
org.example.files/1
```

The receiving endpoint MAY reject unsupported protocols.

---

# 13. Reliability and acknowledgements

UMP MUST implement reliability independently of the carrier when reliable delivery is requested.

Reliable delivery MAY use:

* Packet numbers
* Selective acknowledgements
* Retransmission timers
* Duplicate detection
* Reordering buffers

UMP MUST avoid assuming the underlying carrier is reliable.

Reliable carriers MAY reduce redundant retransmission behavior, but session correctness MUST NOT depend on carrier guarantees.

---

# 14. Congestion control

UMP MUST implement congestion control for internet-scale carriers.

A sender MUST NOT transmit unlimited traffic based only on application demand.

The congestion-control subsystem SHOULD be modular.

Initial implementations MAY adapt an established congestion-control algorithm.

Different paths MAY require separate congestion state.

Carrier metrics SHOULD influence:

* Send rate
* Retransmission timing
* Path preference
* Replication decisions
* Migration decisions

---

# 15. Path management

## 15.1 Path abstraction

A path is an ordered sequence of links and relays.

A session MAY have:

* One active path
* Multiple active paths
* Backup paths
* Store-and-forward paths

## 15.2 Path validation

Before sending significant traffic over a new path, endpoints SHOULD perform a challenge-response validation.

## 15.3 Path migration

A session SHOULD migrate when:

* The active path fails.
* A lower-cost path becomes available.
* A safer path becomes available.
* The active carrier is blocked.
* The device changes networks.
* A local direct route appears.

Migration MUST preserve:

* Session authentication
* Stream state
* Packet ordering information
* Replay protection
* Flow-control state

## 15.4 Multipath

Multipath support is OPTIONAL in v0.1.

When enabled, it MAY be used for:

* Redundancy
* Bandwidth aggregation
* Censorship resistance
* Latency reduction
* Route diversity

---

# 16. Routing

UMP routing MUST work without a complete global topology database.

## 16.1 Routing principles

Nodes SHOULD maintain:

* A bounded peer table
* Recently successful routes
* Trusted introductions
* Diverse network paths
* Expiring routing hints

Nodes MUST NOT require knowledge of every node.

## 16.2 Route discovery

Possible route-discovery mechanisms include:

* Direct peer knowledge
* Bounded peer queries
* Distributed hash routing
* Trusted introductions
* Local broadcast discovery
* Cached route hints
* Gateway advertisements

The initial implementation MAY use a simple bounded query mechanism.

## 16.3 Route request

A route request SHOULD contain:

```text
temporary request ID
destination hint
hop limit
expiration
path exclusions
request authentication
```

Route requests SHOULD avoid exposing the final endpoint identity when privacy-preserving lookup is available.

## 16.4 Loop prevention

Routing messages MUST contain:

* Hop limits
* Request identifiers
* Duplicate suppression
* Route expiry

A node MUST reject routing loops.

## 16.5 Route advertisements

Advertisements MUST be:

* Signed or authenticated
* Expiring
* Rate-limited
* Scope-limited
* Non-authoritative

No node may declare itself globally trusted.

## 16.6 Route diversity

Nodes SHOULD avoid depending exclusively on:

* One network prefix
* One carrier
* One discovery provider
* One organization
* Newly observed nodes
* One geographic region

---

# 17. Relaying

Relays forward encrypted traffic.

## 17.1 Relay properties

A relay MUST NOT require access to application plaintext.

A relay MAY observe:

* Adjacent peers
* Packet timing
* Packet sizes
* Local route identifiers
* Traffic volume

UMP MUST NOT claim that relays are metadata-blind.

## 17.2 Relay authorization

A node MAY configure:

* Who may use it as a relay
* Maximum bandwidth
* Maximum sessions
* Maximum path length
* Allowed carriers
* Allowed destinations
* Time limits
* Cost policy

## 17.3 Relay frames

A relay envelope SHOULD contain only the information needed for the next hop.

Multi-hop routes SHOULD avoid revealing the complete path to every relay.

## 17.4 Internet gateways

An internet gateway is an application or service above the relay layer.

The core MAY advertise gateway capability but MUST NOT implement HTTP, DNS or VPN semantics directly.

---

# 18. Discovery

Discovery MUST be modular.

Supported discovery providers MAY include:

* Static configuration
* Local LAN discovery
* Bluetooth discovery
* Peer exchange
* Invitation tokens
* QR codes
* Distributed lookup
* Application-provided introductions
* Removable-media bootstrap files

## 18.1 Peer candidates

Discovery returns candidates, not trusted peers.

A candidate MAY contain:

```text
temporary peer identifier
carrier type
connection hint
expiration
introduction source
capability hints
signature or authenticator
```

## 18.2 Enumeration resistance

Nodes MUST NOT automatically disclose their complete peer tables.

Peer exchange SHOULD be:

* Bounded
* Randomized
* Expiring
* Access-controlled
* Rate-limited

Private peers MUST NOT be shared without authorization.

## 18.3 Bootstrap

A node SHOULD be able to bootstrap from:

* One known peer
* One invitation token
* One local peer
* One signed peer bundle

No mandatory global bootstrap server may be required by the protocol.

Reference deployments MAY provide optional public bootstrap peers.

---

# 19. Store-and-forward

UMP MUST support disruption-tolerant delivery through bundles.

## 19.1 Bundle properties

A bundle SHOULD contain:

```text
bundle ID
encrypted destination information
creation time
expiration time
priority
maximum replication count
payload
authentication data
```

## 19.2 Bundle encryption

Application payloads MUST be encrypted for the final destination before relay storage.

Storage nodes MUST NOT require plaintext access.

## 19.3 Bundle forwarding

A node MAY:

* Store a bundle
* Forward it immediately
* Replicate it
* Reject it
* Delete it after expiry

## 19.4 Resource controls

Every node MUST enforce:

* Maximum bundle size
* Maximum total storage
* Maximum storage per peer
* Maximum lifetime
* Maximum replication count
* Maximum accepted priority
* Eviction policy

## 19.5 Duplicate suppression

Bundle identifiers MUST allow duplicate detection without exposing application contents.

---

# 20. Traffic policy

Applications SHOULD be able to specify communication policy.

Example policy:

```text
require_end_to_end_encryption = true
allow_relay = true
allow_store_and_forward = true
allow_local_carriers = true
allow_internet_carriers = true
maximum_hops = 8
maximum_latency = 30s
maximum_bundle_lifetime = 24h
minimum_trust = introduced
prefer_low_cost = true
prefer_low_energy = false
```

The core determines paths that satisfy policy constraints.

Applications MUST NOT directly manipulate internal routing tables.

---

# 21. Censorship-resistance architecture

UMP MUST separate stable protocol semantics from observable carrier behavior.

## 21.1 Inner protocol

The inner protocol defines:

* Identity
* Sessions
* Encryption
* Streams
* Datagrams
* Routing
* Relay behavior
* Bundles

## 21.2 Carrier behavior

Carriers define:

* Connection establishment
* Packet representation
* Framing
* Timing
* Padding
* Address discovery
* Network appearance

## 21.3 Requirements

UMP SHOULD support:

* Multiple unrelated carriers
* Runtime carrier selection
* Carrier migration
* Private bridge carriers
* Authenticated probing resistance
* Short-lived peer addresses
* Replaceable obfuscation modules

UMP MUST NOT depend on a permanent public list of all entry nodes.

## 21.4 Blocking-cost objective

UMP aims to make targeted blocking progressively more expensive by requiring an adversary to block:

* Many changing peers
* Multiple carrier types
* Private introductions
* Local communication channels
* Widely used underlying infrastructure

UMP does not guarantee that every carrier will remain available.

---

# 22. Threat model

UMP assumes an adversary may:

* Observe traffic
* Block IP addresses
* Block ports
* Inspect packet contents
* Perform traffic classification
* Perform active probing
* Operate malicious nodes
* Create many Sybil nodes
* Poison routing information
* Attempt eclipse attacks
* Flood nodes with requests
* Fill relay storage
* Disrupt known bootstrap nodes
* Compromise some relays
* Modify or drop packets

UMP assumes the adversary does not always:

* Control every physical communication channel
* Compromise every endpoint
* Break standard cryptographic primitives
* Disable all network connectivity
* Control every node simultaneously

---

# 23. Security requirements

The core MUST protect against:

* Packet forgery
* Replay
* Session hijacking
* Identity spoofing
* Downgrade attacks
* Malformed frame attacks
* Routing loops
* Unbounded memory allocation
* Unbounded storage consumption
* Excessive unauthenticated computation
* Peer-table flooding
* Route-advertisement flooding

The core SHOULD reduce exposure to:

* Sybil attacks
* Eclipse attacks
* Route poisoning
* Active probing
* Traffic fingerprinting
* Peer enumeration
* Correlation attacks

## 23.1 Implementation safety

The reference implementation SHOULD use a memory-safe language.

Rust is recommended.

## 23.2 Parsing

All network parsers MUST be fuzz-tested.

## 23.3 Cryptography

Cryptographic code SHOULD use audited libraries.

Custom cryptographic primitives are forbidden.

## 23.4 Logging

Sensitive material MUST NOT appear in logs by default.

Logs MUST NOT include:

* Private keys
* Session keys
* Plaintext application payloads
* Full private peer tables
* Long-lived bridge secrets

---

# 24. Versioning and extensibility

Every protocol message MUST contain or inherit a protocol version.

Extensions SHOULD use:

* Explicit capability negotiation
* Length-prefixed fields
* Ignorable optional fields
* Reserved namespaces
* Clear failure behavior

Peers MUST reject security-critical unknown semantics.

Peers MAY ignore non-critical optional extensions.

Downgrade negotiation MUST be authenticated.

---

# 25. Core application interface

The portable core SHOULD expose an API similar to:

```rust
let identity = core.create_endpoint(config)?;

core.listen(
    &identity,
    "org.example.echo/1",
    handler
).await?;

let session = core.connect(
    destination,
    "org.example.echo/1",
    policy
).await?;

let stream = session.open_stream().await?;
stream.send(b"hello").await?;
```

Additional operations MAY include:

```rust
core.discover_peers();
core.discover_services(protocol_id);
core.list_paths(destination);
core.list_carriers();
core.export_invitation();
core.import_invitation();
core.publish_endpoint_hint();
```

---

# 26. Daemon architecture

The reference node daemon SHOULD contain:

```text
identity manager
carrier manager
link manager
session manager
routing engine
relay engine
bundle store
policy engine
control API
metrics subsystem
```

The daemon SHOULD expose a local authenticated control socket.

Applications SHOULD communicate with the daemon through:

* Unix-domain socket
* Named pipe
* Local TCP socket with authentication
* Embedded library API

---

# 27. CLI requirements

The initial CLI SHOULD support:

```text
ump init
ump status
ump identity list
ump identity create
ump peer list
ump peer add
ump peer remove
ump carrier list
ump carrier enable
ump carrier disable
ump route list
ump session list
ump bundle list
ump invite create
ump invite import
ump listen
ump connect
ump ping
ump diagnostics
```

Example:

```text
ump init
ump carrier enable udp
ump carrier enable lan
ump invite create
ump ping <endpoint-id>
```

---

# 28. Reference test applications

The repository SHOULD include small applications that validate the core.

## 28.1 Echo

Tests:

* Stream establishment
* Datagram exchange
* Authentication
* Relay routing

## 28.2 Terminal chat

Tests:

* Interactive streams
* Endpoint discovery
* Store-and-forward
* Path migration

## 28.3 File transfer

Tests:

* Large payloads
* Flow control
* Resumption
* Integrity verification

## 28.4 Static service

Tests:

* Protocol registration
* Multiple clients
* Local service discovery
* Relayed access

## 28.5 Carrier-switch test

Tests migration between two carriers without terminating the logical session.

---

# 29. v0.1 interoperability profile

A v0.1-compliant implementation MUST support:

1. Persistent endpoint identities.
2. One mandatory cryptographic suite.
3. Authenticated encrypted sessions.
4. Reliable bidirectional streams.
5. Unreliable datagrams.
6. TCP or UDP carrier.
7. Direct peer connections.
8. Single-relay forwarding.
9. Bounded peer discovery.
10. Session packet numbering.
11. Replay protection.
12. Flow control.
13. Resource quotas.
14. Basic path migration.
15. Protocol identifiers.
16. CLI or equivalent diagnostic interface.

A v0.1 implementation MAY defer:

* Multipath aggregation
* Onion-style relay encryption
* Advanced anonymity
* Traffic morphing
* Global distributed lookup
* Bluetooth
* Wi-Fi Direct
* Payment integrations
* Incentive systems
* Sophisticated reputation
* Fully anonymous discovery

---

# 30. Development phases

## Phase 1: Local secure core

Implement:

* Identity
* Handshake
* Encryption
* Streams
* Datagrams
* TCP and UDP carriers
* CLI
* Echo application

## Phase 2: Relaying

Implement:

* Relay frames
* Route discovery
* Hop limits
* Route expiry
* Basic peer exchange

## Phase 3: Mobility

Implement:

* Session resumption
* Path validation
* Carrier migration
* Network-change handling

## Phase 4: Disconnected operation

Implement:

* Bundles
* Storage quotas
* Expiration
* Local discovery
* Intermittent delivery

## Phase 5: Adversarial resilience

Implement:

* Private introductions
* Anti-probing handshake modes
* Peer-table privacy
* Sybil mitigations
* Carrier plugins
* Obfuscation experiments

---

# 31. Repository structure

```text
/core
    /identity
    /crypto
    /handshake
    /session
    /streams
    /datagrams
    /routing
    /relay
    /bundles
    /policy

/carriers
    /tcp
    /udp
    /lan

/daemon
/cli

/examples
    /echo
    /chat
    /files
    /static-service
    /carrier-switch

/spec
    protocol.md
    threat-model.md
    wire-format.md
    handshake.md
    carrier-api.md
    routing.md
    security.md

/tests
    /interop
    /fuzz
    /simulation
    /adversarial
```

---

# 32. Project principles

The project MUST follow these principles:

1. The protocol is public.
2. No mandatory server is privileged.
3. No mandatory company account exists.
4. No transport is permanent or required.
5. No node needs complete network knowledge.
6. Applications remain outside the core.
7. Cryptographic identities remain independent of location.
8. Sessions remain independent of carriers.
9. Relays are treated as untrusted.
10. Security does not depend on obscurity.
11. Censorship resistance depends on adaptability.
12. Resource limits are part of protocol security.
13. Independent implementations are encouraged.
14. Installed nodes must continue functioning if the original maintainers disappear.

---

# 33. Core protocol statement

UMP is an open, transport-independent protocol for authenticated, encrypted and disruption-tolerant communication between cryptographic endpoints.

It allows endpoints to communicate directly or through untrusted relays across local, global and intermittently connected networks.

Its sessions are independent of addresses, sockets, routes and carriers.

Its observable transport may change without changing endpoint identity or application state.

The protocol requires no mandatory central server, registry, identity provider or globally available infrastructure.
