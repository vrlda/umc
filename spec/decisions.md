# UMC Project Decisions

**Status:** Accepted for v0.1
**Decision set:** Project architecture and governance
**Date:** August 2026

---

## 1. Final project name

### Decision

**Universal Mesh Core**

Abbreviation:

```text
UMC
```

Primary executable names:

```text
umcd    node daemon
umc     command-line client
```

Rust crate prefix:

```text
umc-
```

Examples:

```text
umc-core
umc-wire
umc-routing
umc-sdk
```

### Rationale

The name describes the project accurately:

* Universal: independent of application and carrier
* Mesh: peer-to-peer and multi-hop communication
* Core: infrastructure rather than a complete product

It also keeps the implementation name separate from the protocol name.

### Qualification

The name is technically final for the specification and repository structure. A proper trademark, package-registry, repository, and domain-name clearance should still occur before a public launch.

A branding conflict discovered before public release may change the human-facing name without changing protocol identifiers.

---

## 2. Final protocol name

### Decision

**Universal Mesh Protocol**

Abbreviation:

```text
UMP
```

Protocol version notation:

```text
UMP/1
```

Protocol-specific terminology:

```text
UMP packet
UMP frame
UMP session
UMP endpoint
UMP carrier
```

Internal protocol identifiers:

```text
ump/1
ump-handshake/1
ump-carrier/1
```

### Rationale

UMC describes the software implementation.

UMP describes the interoperable protocol.

This distinction allows other implementations to support UMP without using UMC.

---

## 3. License

### Decision

Use dual licensing:

```text
Apache License 2.0
OR
MIT License
```

Every original source file and crate should be available under either license at the user’s choice.

Specifications should use:

```text
Creative Commons Attribution 4.0 International
```

Documentation and diagrams may also use CC BY 4.0.

### Rationale

MIT/Apache-2.0 is common in the Rust ecosystem and permits:

* Commercial use
* Independent implementations
* Forking
* Integration into open and proprietary applications
* Broad operating-system adoption

Apache-2.0 adds an explicit patent grant. MIT keeps compatibility simple.

The protocol specification must remain freely implementable independently of the reference code.

### Required repository notice

```text
Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
```

### Patent policy

Contributors to protocol-level changes should agree that any patent claims necessarily infringed by implementing their accepted contribution are licensed under Apache-2.0 terms.

---

## 4. Rust workspace structure

### Decision

Use a Cargo workspace divided into narrowly scoped crates.

```text
/
├── Cargo.toml
├── crates/
│   ├── umc-types/
│   ├── umc-wire/
│   ├── umc-crypto/
│   ├── umc-handshake/
│   ├── umc-session/
│   ├── umc-routing/
│   ├── umc-relay/
│   ├── umc-bundle/
│   ├── umc-discovery/
│   ├── umc-policy/
│   ├── umc-storage/
│   ├── umc-carrier/
│   ├── umc-core/
│   ├── umc-sdk/
│   └── umc-control/
│
├── carriers/
│   ├── umc-carrier-tcp/
│   ├── umc-carrier-udp/
│   └── umc-carrier-lan/
│
├── bins/
│   ├── umcd/
│   └── umc/
│
├── examples/
├── fuzz/
├── simulation/
├── interop/
├── spec/
└── tools/
```

### Dependency direction

Dependencies must generally point downward:

```text
umc-types
    ↓
umc-wire / umc-crypto
    ↓
umc-handshake / umc-session
    ↓
umc-routing / umc-relay / umc-bundle
    ↓
umc-core
    ↓
umc-sdk / umcd
```

### Rules

`umc-wire` must not depend on:

* Tokio
* Filesystem APIs
* SQLite
* Network sockets
* CLI libraries

`umc-crypto` must not depend on:

* Routing
* Storage
* Daemon code
* Carrier implementations

`umc-core` coordinates modules but should not contain implementations that clearly belong in lower crates.

### Rationale

This structure supports:

* Deterministic testing
* Protocol fuzzing
* Embedded use
* Independent replacement of modules
* Reduced dependency exposure
* Easier security review

Avoid creating one crate per tiny type. A crate should represent a meaningful security, compatibility, or runtime boundary.

---

## 5. Async runtime choice

### Decision

Use **Tokio** for the reference daemon and first-party carriers.

Tokio provides the networking, scheduling, timers, synchronization, and async I/O needed for a network daemon.

### Architectural constraint

Protocol-pure crates must remain runtime-independent.

The following crates should not directly depend on Tokio:

```text
umc-types
umc-wire
umc-crypto
most of umc-handshake
routing state algorithms
bundle validation
```

Runtime-dependent interfaces should use project abstractions:

```rust
trait Clock {}
trait EntropySource {}
trait TaskSpawner {}
trait AsyncStore {}
trait Link {}
```

Tokio adapters implement those abstractions in the reference runtime.

### Rationale

Tokio is the pragmatic choice for:

* Desktop operating systems
* Network daemons
* UDP and TCP
* Timers
* Cancellation
* Structured concurrent tasks

But making the protocol state machines directly dependent on Tokio would make simulation, embedded use, and alternate implementations unnecessarily difficult.

### Rejected alternative

Do not attempt runtime neutrality throughout every public Rust API in v0.1. That would add considerable generic and trait complexity before the core works.

---

## 6. Default storage backend

### Decision

Use:

```text
SQLite for metadata and small records
Content-addressed files for large bundle bodies
```

SQLite mode:

```text
WAL mode
foreign keys enabled
explicit schema migrations
bounded transactions
```

SQLite provides transactional embedded storage in a portable database file. WAL mode supports concurrent readers while a writer is active, although SQLite still permits only one simultaneous writer.

### SQLite contents

Store:

* Endpoint metadata
* Public identity bindings
* Peer hints
* Trust records
* Route cache
* Bundle metadata
* Resumption-ticket metadata
* Revocations
* Carrier configuration
* Local API permissions
* Schema version

### Filesystem contents

Store large opaque payloads under hashes:

```text
data/
└── objects/
    ├── ab/
    │   └── abcdef...
    └── f1/
        └── f12345...
```

SQLite records ownership, expiration, reference count, and policy.

### Secrets

Secret keys should not be stored as ordinary plaintext SQLite fields.

Use:

1. Operating-system key storage where available.
2. Otherwise, an encrypted keystore protected by a user-provided secret or local machine credential.
3. A separate format and migration path from ordinary metadata.

### Rationale

Placing large bundles directly in SQLite would complicate database growth and transaction behavior. SQLite’s own WAL guidance warns that very large transactions require care.

### Storage abstraction

SQLite is the default implementation, not part of UMP interoperability.

Alternative backends remain possible through the storage trait.

---

## 7. Local control API encoding

### Decision

Use:

```text
Protocol Buffers over length-prefixed local streams
```

Transport:

```text
Unix domain socket on Linux and macOS
Named pipe on Windows
```

Optional development fallback:

```text
authenticated loopback TCP
```

### API structure

Separate services:

```text
NodeAdmin
IdentityService
CarrierService
PeerService
RouteService
SessionService
BundleService
ApplicationService
DiagnosticsService
EventService
```

### Why Protocol Buffers

Protocol Buffers provide:

* Explicit schemas
* Generated clients
* Unknown-field handling
* Broad language support
* Binary efficiency
* Compatibility tooling

Buf can check schema changes for client- or server-breaking modifications.

### Important restriction

The local control API must not use the UMP wire format.

They have different security and evolution requirements:

```text
UMP = peer interoperability
Control API = local process interoperability
```

### Framing

```text
MessageLength: unsigned 32-bit big-endian
Envelope: protobuf bytes
```

The envelope includes:

```text
api_version
request_id
message_type
payload
```

### Authentication

Unix sockets should use operating-system peer credentials where supported.

The API must additionally support scoped bearer capabilities for applications.

Administrative and application-level operations must use separate permission sets.

### Rejected choices

JSON is acceptable for debug export but not the canonical control protocol.

gRPC is not required in v0.1 because full HTTP/2 machinery is unnecessary for a local daemon interface.

---

## 8. Plugin isolation mechanism

### Decision

Use two plugin classes.

#### Built-in carriers

Trusted first-party carriers are compiled into the daemon.

```text
TCP
UDP
LAN discovery
```

#### External carriers

Third-party and experimental carriers run as separate processes.

Communication uses:

```text
Carrier Plugin Protocol over a local socket or pipe
```

### No dynamic library loading in v0.1

Do not load arbitrary `.so`, `.dylib`, or `.dll` carrier plugins into the daemon.

### v0.1 implementation profile

The core v0.1 release does not advertise or launch external carrier plugin
processes. Its carrier surface is the built-in TCP/UDP/LAN/TLS set plus the
trusted, compiled-in `Plugin` trait used by `umc-plugin`. This keeps the solo
maintainer release honest: no external process is accepted until the private
IPC handshake and platform launcher exist.

The generation-scoped `PluginSupervisor` is implemented now as the stable
daemon-side contract. It enforces startup/heartbeat deadlines, message,
outstanding-operation, handle, shared-memory, log, property-event, and restart
budgets; invalidates all generation state on failure; and disables repeated
crashes. A future
subprocess loader MUST use this contract before it advertises external
plugins.

### Plugin permissions

A carrier plugin receives:

* Opaque packet bytes
* Temporary peer candidates
* Link properties
* Commands to listen, dial, send, and close

It does not receive:

* Endpoint private keys
* Session keys
* Decrypted application payloads
* Full peer database
* Trust database
* Bundle plaintext
* Administrative control credentials

### Plugin process lifecycle

An external loader, when enabled, must:

* Start the process
* Negotiate plugin API version
* Apply timeouts
* Apply message-size limits
* Restart on policy
* Disable repeatedly crashing plugins
* Report health
* Terminate the plugin cleanly

### Sandboxing

Best-effort operating-system sandboxing should be added per platform:

```text
Linux: namespaces, seccomp, restricted filesystem
macOS: sandbox profiles where practical
Windows: restricted token and job object
```

Sandboxing should not delay the initial protocol implementation. The process boundary is mandatory; stronger OS confinement can mature incrementally.

### Rationale

An external carrier may contain experimental obfuscation code, third-party protocol stacks, or rapidly changing dependencies. A process crash or memory-safety bug should not compromise endpoint keys or core state.

---

## 9. Bundle support in v0.1

### Decision

**Do not include full bundle routing in the v0.1 interoperability baseline.**

Ship bundle support as:

```text
experimental in v0.1
mandatory candidate for v0.2
```

### v0.1 requirements

The architecture must include:

* Bundle identifiers
* Bundle storage abstraction
* Bundle quotas
* Expiration model
* Experimental frame encoding
* Feature negotiation
* Basic one-hop delayed delivery tests

### Not required for stable v0.1

* Epidemic replication
* Custody transfer
* Multi-carrier physical movement routing
* Sophisticated delivery prediction
* Global bundle routing
* Strong delivery receipts

### Rationale

Store-and-forward is fundamental to the long-term vision but introduces a large second system involving:

* Persistent untrusted data
* Replication policy
* Abuse resistance
* Eviction
* Clock handling
* Delivery acknowledgements
* Routing without simultaneous connectivity

It should not jeopardize the correctness of direct sessions, relaying, or migration in the first stable release.

### Release language

v0.1 supports:

> Live direct and relayed communication, with an experimental delayed-delivery subsystem.

v0.2 should target:

> Stable disruption-tolerant bundle interoperability.

---

## 10. Default trust policy

### Decision

Use:

```text
Authenticated but untrusted by default
```

A cryptographically valid endpoint begins in the state:

```text
Observed
```

Trust states:

```text
Unknown
Observed
Introduced
Trusted
Restricted
Blocked
Revoked
```

### Default behavior

Unknown or observed endpoints may:

* Complete a cryptographic handshake
* Request supported public application protocols
* Exchange tightly rate-limited discovery information

They may not by default:

* Use the node as a relay
* Store bundles
* Receive private peer hints
* Access administrative services
* Cause trust promotion
* Trigger unlimited route queries

### Introductions

A signed introduction increases context but does not automatically produce full trust.

```text
Introduced ≠ Trusted
```

An introduction records:

* Introducer
* Subject endpoint
* Allowed use
* Expiration
* Delegated confidence
* Sharing restrictions

### Trust-on-first-use

TOFU may be enabled for endpoint key continuity.

TOFU means:

> Remember the first authenticated binding and detect changes.

It does not mean:

> Grant the endpoint relay, storage, or private-discovery privileges.

### Rationale

Cryptographic identity proves key possession, not good behavior.

The default policy must allow open networking without turning every node into free infrastructure for arbitrary newly created identities.

---

## 11. Default relay policy

### Decision

Public relaying is **disabled by default**.

Default installation:

```text
outbound relay use: allowed
relay for trusted local applications: allowed
relay for remote peers: disabled
internet exit behavior: absent from core
```

### User-enabled relay presets

#### Friends-only relay

Accept relay requests from:

```text
Trusted endpoints
Explicitly allowed endpoints
Valid scoped invitations
```

#### Community relay

Accept bounded requests from introduced peers.

#### Public relay

Explicit opt-in with strict quotas and a warning.

### Mandatory relay limits

Every relay configuration must define:

* Maximum circuits
* Maximum bytes per circuit
* Maximum total throughput
* Maximum lifetime
* Maximum idle time
* Allowed destination scope
* Allowed carriers
* Allowed trust classes
* Per-peer request rate
* Emergency shutdown

### Rationale

Enabling public relaying automatically would produce:

* Immediate abuse risk
* Unexpected bandwidth use
* Legal exposure
* Easy denial-of-service targets
* Poor user trust

Decentralization does not require every participant to relay for everyone.

---

## 12. Default carrier set

### Decision

Stable v0.1 carriers:

```text
TCP
UDP
LAN discovery
```

Experimental v0.1 carrier:

```text
TLS stream carrier
```

Planned later:

```text
Bluetooth
Wi-Fi peer-to-peer
WebSocket
WebRTC
HTTP-shaped carriers
Serial and radio
```

### Carrier roles

#### UDP

Primary native transport for:

* Efficient packet delivery
* Loss recovery testing
* Congestion control
* Path migration
* NAT traversal experiments

#### TCP

Compatibility transport for:

* Networks where UDP is unavailable
* Early development
* Reliable carrier testing
* Easier debugging

#### LAN discovery

Discovery only at first:

* Peer announcements
* Candidate exchange
* No trust implication

Actual LAN sessions use UDP or TCP.

#### TLS stream carrier

Used experimentally to validate carrier encapsulation and outer-protocol integration.

It is not marketed as censorship-resistant merely because it uses TLS.

### Rationale

Bluetooth and WebRTC would add platform and dependency complexity before the stable core is proven.

The first carrier set must validate that UMP sessions are independent from carrier reliability and packet semantics.

---

## 13. Stable SDK language bindings

### Decision

Stable v0.1 SDK:

```text
Rust
```

Stable local daemon client bindings targeted for v0.1:

```text
Rust
Python
```

C ABI status:

```text
experimental
```

Later stable bindings:

```text
C
Kotlin
Swift
TypeScript/Node.js
Go
```

### SDK layering

#### Native Rust SDK

Can embed the core or connect to the daemon.

#### Daemon client SDKs

Use generated Protocol Buffer messages over the local control API.

Python should be the first non-Rust SDK because it supports:

* Rapid experiments
* Test applications
* Network simulations
* LLM and automation integrations

### Stable ABI rule

Do not expose Rust structs directly through FFI.

Future C bindings must use:

* Opaque handles
* Explicit allocation ownership
* Versioned functions
* Stable integer and byte-buffer types
* No unwinding across FFI

### Rationale

Attempting to stabilize many language bindings before the local API settles would multiply compatibility obligations and slow protocol work.

---

## 14. Extension proposal process

### Decision

Create:

```text
UMEP — Universal Mesh Extension Proposal
```

Proposal filenames:

```text
umeps/0001-process.md
umeps/0002-example-extension.md
```

### Proposal categories

```text
Standards Track
Experimental
Informational
Process
```

### Required sections

Every Standards Track proposal must include:

1. Summary
2. Motivation
3. Detailed design
4. Wire-format impact
5. Security impact
6. Privacy impact
7. Censorship-resistance impact
8. Resource-exhaustion impact
9. Compatibility
10. Downgrade behavior
11. Migration plan
12. Test vectors
13. Alternatives
14. Unresolved questions

### Proposal states

```text
Draft
Review
Experimental
Accepted
Final
Withdrawn
Rejected
Superseded
```

### Acceptance requirements

Protocol-affecting proposals require:

* Two maintainer sponsors
* One implementation
* Interoperability tests where relevant
* Security review
* Public review period
* No unresolved critical objection

Cryptographic changes require independent expert review.

### Extension allocation

Maintain registries in the repository for:

* Frame types
* Capabilities
* Cryptographic profiles
* Carrier identifiers
* Error codes
* Control API versions

Registry assignment does not imply endorsement.

Experimental identifier ranges should be available without central approval.

---

## 15. Governance model

### Decision

Use a **maintainer council with delegated module ownership**.

### Initial structure

#### Maintainer Council

Responsible for:

* Project direction
* Stable releases
* Governance
* Specification acceptance
* Security policy
* Maintainer appointments

Target size:

```text
3–7 maintainers
```

#### Module maintainers

Responsible for defined areas:

```text
wire format
cryptography
runtime
routing
storage
carriers
SDK
tooling
```

#### Security team

A smaller private-contact group handles embargoed vulnerabilities.

### Decision method

Normal decisions:

```text
rough consensus
```

If consensus fails:

```text
simple majority of non-conflicted council members
```

Protocol-breaking or governance changes require:

```text
two-thirds majority
```

### Conflict rules

A maintainer must recuse themselves from decisions involving:

* Their employer’s commercial dispute
* Their own security report
* A personal financial conflict
* Enforcement involving themselves

### Succession

The governance document must define:

* Adding maintainers
* Removing inactive maintainers
* Emergency release authority
* Loss of release keys
* Repository transfer
* Fork continuity

### No foundation initially

Do not create a legal foundation during v0.1.

A foundation may become appropriate after:

* Multiple independent contributors
* Multiple implementations
* Meaningful funding
* Trademark or infrastructure ownership needs

### Rationale

A single-founder model is fast but conflicts with the project’s long-term goal of surviving its original maintainer.

A complex foundation is premature before a working core and community exist.

---

## 16. Release-signing process (historical multi-maintainer plan)

The multi-maintainer text in this section is retained as design history. It is
superseded for the current v0.1 repository by Decision 65 below: one project
owner, one Ed25519 signing key, and `signing.threshold=1`.

### Decision

Use two complementary signing mechanisms.

#### Maintainer threshold signatures

Release manifests are signed by multiple long-lived maintainer keys.

Historical initial policy (not active for v0.1):

```text
2-of-3 release approval (historical; superseded for v0.1)
```

As the council grows:

```text
3-of-5
```

The manifest contains:

* Version
* Git commit
* Source archive hashes
* Binary hashes
* Container hashes
* SBOM hashes
* Build metadata
* Supported protocol versions
* Storage schema version

#### Sigstore attestations

CI-produced artifacts should additionally be signed with Cosign and recorded using Sigstore-compatible provenance where available. Cosign is the Sigstore-recommended command-line tool for signing and verifying artifacts.

### Why not Sigstore alone

The project should not make verification depend exclusively on:

* One OIDC provider
* One transparency service
* One CI platform
* Continuous internet connectivity

Historical threshold maintainer signatures provided an offline-verifiable
project trust root; v0.1 uses the solo operator signature defined in Decision 65.

Sigstore adds:

* Build identity
* CI provenance
* Transparency
* Artifact attestations

### Required outputs

Each release should publish:

```text
SHA256SUMS
SHA256SUMS.sig
release-manifest.json
release-manifest.sig
SBOM
provenance attestation
source archive
reproducible-build instructions
```

### Key management

* Release keys must not be stored in normal developer laptops without hardware protection.
* Keys should use hardware tokens where possible.
* Revocation documents should be prepared in advance.
* Emergency key rotation requires council approval.
* CI must never possess enough long-lived keys to satisfy the threshold alone.

---

## 17. Supported operating systems for first release

### Decision

Tier 1:

```text
Linux x86_64
macOS arm64
Windows x86_64
```

Tier 2:

```text
Linux aarch64
macOS x86_64
Windows arm64
FreeBSD x86_64
```

Tier 1 means:

* CI runs on every change.
* Release binaries are published.
* Integration tests are required.
* Security fixes are supported.
* Local API integration is maintained.

Tier 2 means:

* Builds are expected to work.
* CI may be less comprehensive.
* Release binaries are optional.
* Fixes are best-effort.

### Linux reference environment

Linux is the primary development and deployment environment.

First-class Linux support should include:

* systemd example unit
* Unix-domain control socket
* Standard filesystem layout
* Optional seccomp profile
* Container-compatible operation

### Rationale

These targets cover development laptops, routers and servers without introducing mobile lifecycle and radio restrictions into the initial runtime.

---

## 18. Mobile bindings in the main repository

### Decision

Do **not** place production mobile bindings in the main repository during v0.1.

The main repository may contain:

```text
mobile architecture notes
FFI experiments
cross-compilation checks
minimal proof-of-concept wrappers
```

Production bindings should initially live in separate repositories:

```text
umc-android
umc-apple
```

### Shared artifacts remain in the main repository

The main repository owns:

* Stable C ABI design
* Mobile-neutral SDK semantics
* Protocol test vectors
* Cross-compilation support
* FFI safety rules
* Core static-library build profiles

### Rationale

Mobile projects add:

* Platform build systems
* Lifecycle behavior
* Background execution
* Radio permissions
* Store packaging
* UI concerns
* Large generated project files

Those concerns would overwhelm the core repository before the runtime is stable.

Once the ABI and mobile integrations mature, the governance council may convert them into a coordinated monorepo or official workspace.

---

## 19. Dynamically pluggable routing strategies

### Decision

Routing strategies are pluggable **at compile time and configuration time**, but not dynamically loadable third-party code in v0.1.

Define an internal strategy trait:

```rust
pub trait RouteStrategy: Send + Sync {
    fn rank_paths(
        &self,
        request: &RouteRequest,
        candidates: &[PathCandidate],
        context: &RouteContext,
    ) -> Vec<RankedPath>;
}
```

First-party strategies:

```text
balanced
low-latency
low-bandwidth
local-first
high-diversity
restricted-network
```

### Runtime selection

Users may select a compiled strategy through configuration.

Applications specify policy constraints, not strategy implementations.

### External routing plugin status

Deferred.

Future external routing plugins must run out of process and receive sanitized topology information.

### Rationale

Routing algorithms will require experimentation, but giving third-party in-process code access to full peer and topology state would create:

* Privacy risk
* Crash risk
* Manipulation risk
* API stabilization burden

The trait boundary gives architectural flexibility without creating an unsafe plugin ecosystem immediately.

---

## 20. Congestion control placement

### Decision

Congestion control is an **internal mandatory subsystem with replaceable algorithms**.

It is not an external plugin.

Define:

```rust
pub trait CongestionController: Send {
    fn on_packet_sent(&mut self, event: PacketSent);
    fn on_ack(&mut self, event: AckReceived);
    fn on_loss(&mut self, event: PacketLost);
    fn on_rtt_update(&mut self, event: RttUpdate);
    fn send_allowance(&self, now: Instant) -> SendAllowance;
}
```

### Initial algorithms

Ship one stable conservative controller.

Recommended initial approach:

```text
NewReno-like loss-based controller
with pacing
```

A second experimental implementation may later add:

```text
BBR-like model-based control
```

### State scope

Congestion state should normally be maintained per path.

The session scheduler coordinates traffic across paths.

### Carrier interaction

Carriers report:

* Backpressure
* Estimated MTU
* Delivery behavior
* Reliability
* Cost
* Link-level queue state where available

Congestion control remains responsible for network-safe send rates.

### Why internal

A faulty congestion controller can:

* Flood networks
* Collapse performance
* Cause unfairness
* Trigger filtering
* Exhaust relay buffers
* Harm unrelated traffic

It belongs inside the audited core security and performance boundary.

### Extensibility

Researchers may compile alternate controllers or use feature-gated experimental builds.

External runtime loading is prohibited in stable releases.

---

# Final accepted stack

```text
Project:
    Universal Mesh Core — UMC

Protocol:
    Universal Mesh Protocol — UMP/1

License:
    MIT OR Apache-2.0
    Specifications under CC BY 4.0

Implementation:
    Rust workspace
    Tokio reference runtime

Storage:
    SQLite metadata
    Content-addressed bundle files
    Separate protected keystore

Local API:
    Protocol Buffers
    Unix sockets / Windows named pipes

Plugins:
    Built-in trusted carriers
    External carriers isolated as processes

v0.1 bundles:
    Experimental, not baseline interoperable

Trust:
    Authenticated but untrusted by default

Relay:
    Public relay disabled by default

Stable carriers:
    UDP, TCP, LAN discovery

SDK:
    Stable Rust
    Stable Python daemon client
    Experimental C ABI

Extensions:
    UMEP process

Governance:
    Maintainer council
    Module maintainers
    Separate security team

Releases:
    Historical threshold maintainer signatures (superseded for v0.1)
    Plus Sigstore attestations

Tier-1 systems:
    Linux x86_64/aarch64
    macOS arm64
    Windows x86_64

Mobile:
    Separate integration repositories initially

Routing:
    Internal pluggable trait
    No dynamic routing plugins in v0.1

Congestion:
    Internal mandatory subsystem
    Replaceable compiled algorithms
```

# Architectural consequence

These decisions establish a clear project boundary:

* Stable protocol logic remains runtime-independent.
* The reference daemon uses practical production components.
* Potentially dangerous extensions run outside the trusted process.
* Community experimentation remains possible through carriers, SDKs, routing algorithms, and UMEPs.
* Neither storage, the control API, Tokio, SQLite, nor the reference daemon becomes part of UMP interoperability.
* The first release remains narrow enough to build and audit.

---

## 21. Gap-closure implementation decisions (2026-08-08)

The following decisions resolve the implementation questions recorded by the
A–K gap-closure plan:

1. **Fixed-layout dispatch.** Wire frames that do not carry a length prefix
   keep their fixed layout; known length-delimited relay status frames decode
   by their declared length, unknown optional frames are skipped using that
   length, and unknown critical length-delimited frames fail closed.
2. **Protected session transition.** Initial packets protect the early
   handshake, while the daemon uses directional handshake traffic keys for
   the authenticated continuation. The transcript still binds the real
   identity binding and finished messages.
3. **Bus protection.** Session-bus payloads are frame payloads, not carrier
   packets; the destination session encrypts them with its own traffic keys
   before sending them on the link.
4. **Relay authorization compatibility.** Signed HMAC-BLAKE2s authorization
   is validated when present. Empty authorization remains accepted only for
   legacy phase-12 fixtures and is a tracked hardening item.
5. **Envelope sealing.** A 32-byte destination hint is treated as the
   destination public key and receives a sealed bundle envelope. Opaque or
   legacy hints retain the old payload behavior for compatibility.
6. **TLS experimental status.** `ump.tls-stream/1` uses TLS 1.3, a channel
   exporter helper, bounded queues, and the TCP varint framing profile. The
   daemon creates an ephemeral localhost self-signed certificate only when no
   deployment material is configured; `tls_certificate`, `tls_private_key`,
   `tls_trust_roots`, and `tls_server_name` load explicit DER trust material
   for independent deployments. The solo implementation security review is
   recorded; no human third-party sign-off is claimed for the experimental
   profile.
7. **SDK bindings.** Python is a pure-stdlib local client with a small
   dependency-free protobuf subset. The C ABI is experimental and uses opaque
   generation-tagged handles plus explicit buffer/status ownership.
8. **PSK-XX.** PSK mixing is HKDF extract over the PSK and ephemeral DH, then
   the existing UMC labeled expansion. It is a helper API, not a silent
   downgrade from XX.
9. **Privacy ladder.** P0 is the default and P2/P3 mechanisms remain opt-in
   future work; no release may claim anonymity from encryption alone.
10. **Deferred capabilities.** 0-RTT, internet-scale discovery, dynamic
    process plugins, multi-hop relay construction, anonymous credentials,
    PSI/PIR, and mix modes remain explicit non-goals for v0.1.
11. **Privacy negotiation.** `ClientHello` carries a minimum profile whose
    `privacy-min` capability is transcript-bound. The v1 daemon advertises
    and selects at most P1; requests above P1 fail explicitly and are never
    silently downgraded. P0 remains the default request.
12. **Onion route envelope.** P2 route layers use independent UMP packet-key
    derivations with a fixed `UMP-PRIVACY-ROUTE-v1` AAD and bounded opaque
    transition descriptors. The relay primitive exposes only the next layer
    or terminal destination context; direct-path and rendezvous wiring remain
    deferred until the route policy is complete.
13. **Traffic padding scope.** The first K7 implementation is an explicit
    session/config opt-in that pads non-control payloads below 1,024 bytes to
    that target before AEAD protection. ACK/PING control packets and payloads
    already at or above the target are unchanged; the target is provisional
    and does not claim timing privacy, cover traffic, or MTU-aware P3
    conformance.
14. **Connection-ID privacy rotation.** The daemon advertises a fresh bounded
    8-byte connection ID every ten minutes after session establishment. A
    peer adopts a received `NEW_CONNECTION_ID` only after authenticated frame
    processing; the endpoint's identity is never encoded in the ID. Rotation
    is transport metadata only and does not claim full route or timing
    anonymity.
15. **Privacy visibility shape.** `SessionService.GetSession` carries a
    `SessionPrivacyInfo` with requested/effective profile labels, direct-path
    policy, padding opt-in, and a deliberately coarse hop count. The initial
    shape used the configured policy; the registry now persists the negotiated
    profile and per-session flags, while route-state snapshots remain coarse
    until daemon route wiring is complete.
16. **Mesh hint membership.** When `mesh_secret` is configured, each
    `PEER_HINT` entry carries an HMAC-BLAKE2s tag over a canonical, bounded
    entry encoding and the `UMP-MESH-HINT-v1` domain. Receivers without the
    secret reject authenticated frames; receivers with the secret reject any
    entry whose tag does not validate. The secret is never returned by
    `GetConfig`.
17. **J5/J6 CI artifacts.** The main CI workflow publishes a locked
    `cargo metadata` SBOM artifact on every event. A scheduled/manual job
    runs `cargo-llvm-cov` over `umc-wire`, `umc-crypto`, `umc-handshake`, and
    `umc-session` with a 70% line threshold; local runs remain authoritative
    until the hosted runner produces its first report.

18. **Per-session privacy reporting.** `SessionService.GetSession` reports the
    negotiated profile, direct-path policy, and traffic-padding state captured
    at session registration. The hop count remains deliberately coarse: one
    for an allowed direct path and zero when a private route is required but
    not yet wired into the daemon registry. This avoids exposing route
    topology while preventing the control API from silently substituting the
    node's current configuration for a live session's negotiated state.

19. **Retry-token nonce separation.** Retry tokens carry a clear 16-byte
    random nonce prefix and seal the payload with a key derived from the
    retry key and that nonce. The nonce is authenticated as both prefix and
    payload, so every token uses a distinct AEAD key and nonce pair; the token
    remains opaque and authenticated to callers.

20. **Protected XX continuation and opt-in Retry.** Live XX continuation
    messages are carried in encrypted Handshake packets with directional
    handshake traffic secrets. Stateless Retry is an explicit `require_retry`
    opt-in: the daemon issues a bounded single-use token, binds it to the
    original Initial/hello and carrier, and includes a synthetic Retry context
    in the XX transcript. The current Retry integrity tag and header shape are
    project-provisional until the final wire/vector review; PSK-XX,
    private-mode policy, and independent vectors remain open.

21. **Control page-token authentication.** Daemon-issued page tokens carry a
    keyed BLAKE2s/HMAC tag derived from the node's protected ticket key, in
    addition to their method, principal, offset, and expiry fields. The
    server verifies the tag before applying principal/method checks, so local
    clients cannot forge offsets or cross-page tokens by editing the opaque
    bytes.

22. **Control authorization boundary.** The live Unix-socket dispatcher owns
    the capability check; service implementations remain callable by
    protocol-focused unit tests without a synthetic credential. Same-user
    Unix peer authorization remains the fallback when no bearer is presented;
    a presented bearer must authenticate and carry the method capability.
    Resource constraints, ownership, delegation, persistence, and connection
    revocation are subsequent authorization layers, not implied by this first
    method-capability gate.

22. **Daemon modularity boundary.** Keep `umcd` as one deployable daemon and
    one composition root, but do not keep its control plane as one source
    file. Extract transport/connection state, authorization, service handlers,
    and application data-plane state into modules with narrow interfaces over
    `RuntimeState`; keep protocol, storage, carrier, and crypto policy in the
    existing library crates. This preserves shared-state performance while
    making each service independently testable and preventing a broad,
    risky process split before the v0.1 data plane is stable.

23. **Control hello metadata and delegation.** A successful control hello
    receives a fresh per-process `server_instance_id`, a fresh per-connection
    identifier, negotiated envelope limits, and the bearer principal's
    effective grants. Version negotiation selects an exact offered `1.0`
    version; an offered major/minor with no exact match closes the connection.
    `TokenService.CreateToken` may delegate only a
    `delegable` issuer grant, never a broader resource scope or later expiry;
    invalid and under-scoped requests fail closed. Token records persist only
    a domain-separated hash, principal, expiry, and effective protobuf grants
    under a control-token key; raw bearer material is returned once and never
    stored. Revocation removes the persisted record before removing the live
    entry, and a persisted principal-id high-water mark prevents reuse after
    revocation, so a failed storage delete fails closed. Secret export/import
    uses the authenticated protection adapters recorded in decision 28:
    passphrase, X25519 recipient-key, and native OS-keychain envelopes are
    all bounded and fail closed on malformed or unavailable key material.

24. **Incremental control-plane extraction.** `umcd` remains one deployable
    daemon and keeps `server.rs` as the composition root for control services,
    but transport state and EventService behavior are now separate modules.
    `control_transport.rs` owns envelope sequencing, hello negotiation, and
    per-connection replay state; `control_events.rs` owns subscription
    lifecycle, filtering, acknowledgement, and event delivery; `control_application.rs` owns
    the implemented application registration/listener state transitions.
    New service modules should use the same status/payload boundary and avoid
    reaching into transport framing.

25. **Fail-closed live resource checks.** Bearer grants with endpoint/resource
    constraints are checked at the live dispatcher before service execution.
    Explicit peer, route, session, event, and application endpoint targets
    must be covered; list/object methods without a durable ownership model are
    denied for constrained grants rather than returning an unfiltered view.
    Token administration is principal-owned: cross-principal list/revoke
    requires an explicit `TOKEN_ADMIN` grant with `all_resources`, and
    application handles reject other principals and are cleaned up when their
    owning live control connection closes.

26. **Carrier instance lifecycle boundary.** `CarrierService` instance
    List/Get/Create/Update/Start/Stop/Delete methods use a daemon-local
    registry with random 16-byte opaque handles, optimistic resource
    revisions, redacted sensitive options, and structured lifecycle events.
    Startup-wired built-in carrier types receive running records; control
    creates are validated against the registered type set. The current
    `umc-carrier::Carrier` trait has no generic instance factory or lifecycle
    resource handle, so dynamic socket/device/plugin acquisition, per-instance
    listener/link ownership, Dial, and CloseLink remain explicit follow-up
    work rather than being reported as complete.

27. **Control feature negotiation boundary.** The daemon accepts a bounded
    `ClientHello` diagnostic name, an empty legacy instance id or a 16-byte
    instance id, and at most 64 non-empty feature names of at most 128 bytes.
    `ServerHello.enabled_features` is the stable intersection of the client's
    requested names and the daemon's implemented control features, preserving
    first-request order and removing duplicates; unknown names are omitted.
    Malformed bounds close the connection before authentication completes.
    A zero envelope request selects the 4 MiB daemon default; valid smaller
    requests are applied to the live decoder and encoder after hello, while
    requests below 1 KiB are rejected. Persisted grants/revocation and
    deferred data-plane features are not advertised by this negotiation.

28. **Protected secret identity exports.** `IdentityService.ExportSecretIdentity`
    is disabled unless local policy enables it and the request carries the
    exact `EXPORT` operator confirmation plus a non-empty passphrase
    protection. The daemon wraps the 64-byte identity seed material in an
    `UMC-IDENTITY-EXPORT-v1` envelope using Argon2id and
    ChaCha20-Poly1305 with random salt/nonce, and imports decrypt only that
    authenticated envelope. Legacy raw seed bytes are rejected, successful
    export/import operations emit audit events. Recipient-public-key exports
    use an ephemeral-X25519/ChaCha20-Poly1305 envelope, while OS-keychain
    exports use a random wrapping key stored through the native platform
    credential backend. Keychain references are authenticated as local AAD;
    missing, malformed, or unavailable keychain entries fail closed.

29. **Revocation freshness is an explicit qualification.** Persisted
    revocation records expose `Unknown`, `Fresh`, or `Stale` relative to a
    bounded seven-day local evidence window. The daemon emits a stale-state
    audit event and diagnostics gauge when evidence is old or unreadable, but
    it never treats local freshness as proof that disconnected peers have
    received every revocation.

30. **Introducer authority is scoped and transitive only within bounds.** A
    new introduction edge is accepted only when the introducer is locally
    `Trusted` or already has an unexpired `Introduced` path for the requested
    scope. The graph remains depth- and cardinality-bounded; signed
    introduction statements use the canonical bounded encoding in decision
    36, while distributed delegation/revocation remain follow-up work.

31. **Bootstrap authenticates the source, not the endpoint.** Bootstrap
    bundles use a bounded canonical `UMP-BOOTSTRAP-v1` encoding signed by an
    issuer identity, verify issuer/validity/candidate expiry before admission,
    and mark admitted candidates as `SignedBootstrap`. Dialed endpoints still
    require the normal handshake; provider lifecycle, diversity, and TLS
    deployment trust remain separate concerns.

32. **Discovery providers are independently restartable.** The provider
    interface keeps compatibility-friendly bounded candidate collection while
    adding default start/stop hooks and a fallible collection hook. The
    bounded `ProviderManager` starts and stops providers independently,
    isolates failures, rejects candidates whose source attribution disagrees
    with the provider, enforces per-provider candidate limits, and reports the
    number of distinct contributing sources. A configured minimum source count
    is diagnostic policy; one healthy provider remains sufficient for basic
    operation, while higher-diversity deployments can fail closed at their
    own admission boundary.

33. **Sample-based short-header protection.** Short-header packet protection
    derives `HeaderProtectionKey` with the wire label `header protection` and
    derives the five-byte ChaCha20 mask from the packet sample (counter plus
    nonce), not from a key-only stream. The sample is taken from ciphertext
    after the packet number so the receiver can remove protection before
    packet-number reconstruction. Long-header protection, Retry vectors, and
    independent interop vectors remain separate conformance work.

34. **Unknown critical frame handling.** The frame decoder rejects unknown
    critical fixed and length-delimited types, while unknown optional
    length-delimited types are skipped only after their bounded declared body
    is validated. This keeps extension evolution forward-compatible without
    silently ignoring semantics a peer marked critical.

35. **Static discovery is an explicit local provider.** Configured static
    peers are exposed through a read-only provider with restartable lifecycle,
    stable hashed candidate handles, `LOCAL_USE_ONLY` sharing, and an explicit
    non-expiring local policy. The daemon starts and refreshes that provider at
    runtime startup, while authenticated endpoint identity still comes only
    from the normal static-peer handshake/dial path.

36. **Signed introductions use a bounded canonical statement.** The
    `UMP-INTRODUCTION-v1` statement signs a fixed-order encoding of the
    introducer and subject EndpointIDs, subject binding digest or static
    handshake key, allowed scope, expiry, scoped confidence, sharing
    restrictions, and monotonic sequence with the introducer Ed25519 key. The
    issuer public key is carried by the authenticated binding and persisted
    beside accepted statements for restart-time verification. Statements are
    rejected when malformed, expired, forged, out of scope, or sequence-
    regressed; an accepted introduction still yields `Introduced`, never
    `Trusted`. Delegation chains and distributed revocation are not implied by
    this statement type.

37. **Signed revocations use a bounded canonical statement.** The
    `UMP-REVOCATION-v1` statement encodes the issuer EndpointID, a tagged
    identity/binding/delegation/introduction/recovery-key subject, sequence,
    issuance and optional expiry times, and an Ed25519 signature in fixed
    order. The local store accepts only self-authorized identity and binding
    statements, rejects forged or regressed records, persists the issuer key
    for restart-time verification, and applies active records during binding
    admission. Recovery/delegation authority and authenticated distribution
    require a separate policy and propagation design.

38. **Path construction is bounded before live handoff.** The routing core
    builds opaque adjacent-hop sequences while rejecting excluded or repeated
    peers, scope broadening, hop/relay/byte-limit violations, and insufficient
    explicitly supplied failure-domain diversity. Direct paths remain allowed
    by default; multi-hop forwarding and relay authorization still require the
    live session wiring described by the routing and relay specifications.

39. **TLS deployment trust is explicit in daemon configuration.** The TLS
    carrier retains its ephemeral localhost certificate only when no material
    is configured. If any deployment certificate, PKCS#8 key, trust-root list,
    or non-localhost server name is supplied, startup requires all certificate
    and trust inputs, reads DER files without exposing contents, and fails
    closed on missing or invalid material. Status reports only presence of
    sensitive paths; the independent live interoperability check and solo
    implementation security review are recorded, while TLS remains
    experimental and no human third-party sign-off is claimed.

40. **Delegation certificates are canonical and narrowing.** `UMP-DELEGATION-v1`
    certificates bind an issuer EndpointID to a delegated Ed25519 key and a
    sorted, bounded capability set. A bounded chain verifier checks every
    signature and validity interval, requires each child capability set to be
    a subset of its issuer, prevents key cycles, and requires child expiry to
    remain within the parent interval. Multi-device persistence, recovery
    authority, and authenticated distribution remain follow-up work.

41. **Handshake confirmation is an explicit key gate.** A shared,
    runtime-independent state machine models the ten handshake states and
    rejects invalid message ordering. Handshake traffic keys may be installed
    during negotiation, but application traffic keys are usable only after
    authenticated peer evidence and key confirmation transition the machine
    to `CONFIRMED`; this guard does not alter the wire version.

42. **Stream IDs are role- and direction-checked at the session boundary.**
    Local bidirectional and unidirectional sequence spaces encode the endpoint
    role in bit 0 and direction in bit 1. Inbound frames reject malformed
    low-bit combinations, local unidirectional streams cannot receive peer
    data, and reordered data may be buffered before its `OPEN` frame;
    established bidirectional streams remain usable in both directions for
    echo and request/response traffic.

43. **Relay queue accounting is hierarchical.** Per-circuit admission remains
    capped at 256 KiB, while a shared queue account aggregates each
    authenticated peer's circuits and rejects the eighth-plus allocation once
    the 2 MiB peer bound or the bounded peer-entry count is reached. Legacy
    single-circuit callers use the same accounting path with an empty peer
    key.

44. **PSK-XX admission is a bounded pre-DH gate.** `PskAdmissionContext`
    verifies the 16-byte `UMP-INVITE-AUTH-v1` authenticator over the client
    random, client ephemeral key, destination connection ID, and carrier
    binding before deriving `PSKExtract` and `HandshakeExtract1`. The
    invitation key never enters `ClientHello`; expiry, scope, replay, and
    source rate policy remain caller-owned until the daemon's live PSK mode is
    enabled.

45. **Delegation chains persist as re-verifiable trust records.** Accepted
    `UMP-DELEGATION-v1` chains are stored under the trust namespace with the
    root public key and canonical capability set. Restart reads decode and
    re-verify every certificate, omit expired chains, fail closed on malformed
    rows, and reject leaf sequence rollback. Recovery-key authority and
    authenticated distribution remain separate policy work.

46. **Route hard constraints fail closed on missing evidence.** Carrier,
    minimum-trust, and hop-count constraints read only bounded NUL-separated
    `carrier=`, `trust=`, and `hops=` metadata fields retained from a response
    that carries authentication bytes. A route lacking the requested policy
    evidence is ineligible; missing evidence is never treated as a match.

47. **Control-plane route probes use the live session bus.**
    `RouteService.ProbeRoute` returns cached candidates immediately while
    fanning out at most the stable default fanout of three policy-eligible
    `ROUTE_REQUEST` frames. Each probe uses a bounded 62-bit wire request ID
    and local reverse state so authenticated session responses follow the
    normal route-response validation path; response cache insertion binds the
    destination hash and scope from bounded local request context rather than
    the next-hop hint, and scoped `GetRoute` lookup searches every scope.
    Default probe hop limits follow the frozen scope guidance (1/4/6/8), and a
    branch with no remaining hop is rejected rather than reported as direct.
    Unsupported trust requirements fail closed because session entries carry
    observation-only evidence. Full multi-hop topology remains future work.

48. **All encrypted packet spaces share sample-based header protection.**
    `PacketKeys` derives and retains the labelled header-protection key beside
    the packet key and IV. Initial and Handshake builders mask their packet
    number after sealing, and parsers restore the unprotected header before
    AEAD authentication. The pre-header-protection layouts are rejected at
    the parser boundary; no legacy network dialect is retained.

49. **Embedded identity import uses the shared passphrase envelope.** The
    in-process SDK accepts only the same Argon2id/ChaCha20-Poly1305 secret
    export envelope as the daemon, requires an exact 64-byte seed payload, and
    stores imported material as a secondary endpoint without exposing keys.
    Wrong passphrases and malformed envelopes fail closed; validate-only
    imports do not mutate the endpoint table. Recipient envelopes are opened
    with a 32-byte X25519 private key held by the referenced native keychain
    item; keychain-wrapped envelopes use the same item as a random symmetric
    wrapping key. The shared `umc-storage::SecretStore` boundary keeps the
    embedded and daemon paths on the same envelope implementation.

50. **PSK-XX mode is selected only after invitation admission.** The daemon
    checks a bounded `ClientHello` PSK authenticator against active invitation
    keys before allocating responder handshake state; single-use invitations
    are consumed on a match and unmatched PSK offers fail with a generic
    admission error. The selected mode changes the transcript label and
    derives `HandshakeExtract1` from the invitation-bound `PSKExtract` on both
    sides. XX clients remain on the public fallback path, while private-mode
    policy selection and independent vectors remain follow-up work.

51. **Release performance evidence uses opt-in, reproducible harnesses.**
    Criterion benches cover representative wire varint/packet parsing,
    cryptographic seal/open, and session send/receive paths without changing
    protocol behavior. The simulation package exposes an ignored wall-clock
    two-node stream/datagram soak with a ten-minute default and an explicit
    `UMC_SOAK_DURATION_MS` override for local smoke runs. Benchmark baselines,
    resource trends, and Tier-1 platform results are evidence artifacts rather
    than claims implied by compilation or unit-test success. The
    `release-baseline` harness refuses tracked or untracked changes before it
    runs, records the committed tree id, and archives benchmark logs, a
    portable resource summary, and SHA-256 metadata for the complete evidence
    directory. `verify-release-baseline.sh` rejects dirty, short, out-of-bound,
    missing, or tampered evidence.

52. **Event acknowledgement owns bounded delivery retention.** The daemon
    event bus moves sent events into a lightweight in-flight sequence/byte
    ledger instead of treating transport delivery as acknowledgement. The
    ledger remains charged against the per-subscription event and byte caps
    until the client acknowledges a contiguous sequence; overflow therefore
    reports an event gap rather than silently discarding unacknowledged state.
    The embedded SDK mirrors the same ledger, gap, filter, and acknowledgement
    semantics; backend differences are limited to its local execution and
    restart/storage boundary.

53. **Conformance checks stay protocol-pure and bounded.** Phase-14 tests live
    in a dedicated workspace package and exercise handshake/relay state
    machines, canonical varint and flow-control properties, duplicate-packet
    rejection, and truncated-input fail-closed behavior. They do not add
    production behavior or depend on wall-clock timing, so they can run in the
    ordinary workspace gate while the longer simulator soak remains opt-in.

54. **The deterministic XX driver uses the same client binding layout as the
    live responder.** `run_xx_handshake` now signs an `IdentityBinding` for the
    client static key and serializes its signed bytes and binding signature in
    `CLIENT_AUTH`; it no longer reuses the server binding as a placeholder.
    This keeps vector/driver coverage aligned with the authenticated daemon
    path without changing the wire format.

55. **Control request validation fails closed at the dispatch boundary.** A
    zero request ID or negative `deadline_unix_ms` is invalid, and a positive
    deadline at or before the current epoch is rejected with
    `DEADLINE_EXCEEDED` before authorization, rate accounting, or service
    mutation. Zero retains the method default. Accepted deadlines are then
    converted once to the daemon's monotonic clock and capped by operation
    class (30 seconds for reads, 60 seconds for mutations, dialing, and route
    probes); asynchronous work must use that receipt-time deadline.

56. **Daemon SDK waits honor the same absolute deadline.** Before sending a
    request, the SDK rejects negative or already-expired deadlines locally; for
    a future deadline it wraps the response read in a bounded Tokio timeout and
    returns `DeadlineExceeded` if the peer does not answer. Zero and absent
    deadlines retain the legacy method-default behavior.

57. **SDK receive queues are explicitly bounded.** Pending responses and
    decoded envelopes are capped at 1,024 entries, while unrelated pending
    events are capped at 100 entries to match the control event backlog. A
    full queue returns `RESOURCE_EXHAUSTED`; it never silently drops an event
    or allocates unbounded client memory.

58. **Encrypted long-header parsing has one authenticated wire layout.** The
    daemon accepts only header-protected Initial packets and the handshake
    packet parser accepts only the matching protected layout. The retired
    pre-header-protection forms are rejected before hello/authentication
    processing, so compatibility fixtures cannot create a second
    unauthenticated network dialect.

59. **Live control requests enforce ordinary message bounds before dispatch.**
    The connection boundary rejects request payloads above the 1 MiB ordinary
    limit with `RESOURCE_EXHAUSTED` and requires non-empty idempotency keys to
    be 16–64 bytes. Protocol-focused service tests may still use synthetic
    payloads directly; live Unix-socket requests cannot bypass these limits.
    Idempotency entries retain a payload digest for 24 hours within the
    bounded per-connection cache; reusing a key with different payload bytes
    returns `IDEMPOTENCY_CONFLICT` without dispatch.

60. **Native v0.1 session registration requires an eight-byte Initial DCID.**
    Long-header parsing still accepts the wire format's bounded variable CID
    lengths, but the daemon rejects any Initial that cannot be represented by
    the fixed eight-byte session demultiplexer; it never derives a replacement
    identifier from unauthenticated hello material.

61. **Idempotent control replays re-check live authorization.** Cached response
    bytes are consulted only after request validation and current capability,
    resource-ownership, expiry, and revocation checks; a replay cannot retain
    access after its bearer grant or owned handle is no longer valid.

62. **SDK deadline expiry emits an explicit cancellation envelope.** When a
    daemon-backed SDK request reaches its absolute wall-clock deadline before
    receiving a response, the client sends a `Cancel` envelope for the live
    request ID (best effort) and returns `DeadlineExceeded`. Live control
    connections now maintain an authenticated in-flight table, process
    cancellation concurrently with request workers, reject request-ID
    collisions, and interrupt safe outbound connects before commit. Unknown
    IDs remain no-ops, and cancellation never rolls back a committed mutation.

63. **Idempotency replay scope is the authenticated principal.** The bounded
    24-hour replay cache is owned by `RuntimeState`, not a control connection,
    and keys include principal, service, method, and client key. Reconnects
    under the same bearer grant therefore replay or conflict without
    redispatch; unauthenticated clients are scoped to their connection ID.
    Entries are encrypted at rest with the stable ticket key before being
    written to the API namespace; a ticket-key rotation safely discards old
    entries. Replay responses rebind the current request ID while retaining
    the stored status and payload.

64. **Linux aarch64 is Tier-2 for v0.1.** The first release keeps Linux
    x86_64, macOS arm64, and Windows x86_64 as Tier-1 targets. Linux aarch64
    remains a supported, portable build target with optional hosted-ARM CI
    evidence, but its artifacts and integration runs are not release blockers
    or a prerequisite for v0.1 security-fix support.

65. **Solo-maintainer release governance for v0.1.** UMC is maintained by one
    project owner. The owner performs release, security, and module-approval
    duties until additional maintainers actually exist. Release manifests use
    exactly one operator-controlled Ed25519 signature (`signing.threshold=1`);
    no council, quorum, second reviewer, or multi-person signing ceremony is
    assumed. CI verifies the published public key but never receives the
    private key. This decision supersedes the earlier multi-maintainer and
    earlier multi-maintainer planning text until a new explicit governance
    decision is accepted.

66. **Dependency evidence is clean-tree and self-verifying.** The locked
    dependency audit refuses tracked or untracked changes before it runs,
    records both the committed tree and the Cargo.lock digest, and copies the
    exact lockfile beside the SBOM, dependency tree, and RustSec JSON result.
    `verify-dependency-audit.sh` validates every recorded size and SHA-256,
    re-parses the SBOM package count and advisory list, and rejects any report
    that is dirty, incomplete, tampered, or contains a vulnerability before CI
    retains the evidence.

67. **Fuzz evidence is clean-tree and target-complete.** The corpus smoke
    harness refuses tracked or untracked changes, records the committed tree,
    and emits per-target logs, resource evidence, corpus inventories, and
    SHA-256 records. `verify-fuzz-report.sh` requires exactly the twelve
    declared targets, matching positive run counts and progress markers, and
    rejects missing, incomplete, or tampered evidence before CI upload.

68. **Recovery authority is root-signed and bounded.** A recovery Ed25519 key
    never authenticates a session as the root identity. It receives a
    sequence-bound, expiry-bounded, class-scoped authority signed by the root;
    recovery revocations bind the root and recovery EndpointIDs and are
    re-verified after restart. Signed revocation batches may be exchanged over
    authenticated application/session channels, but every statement is
    independently verified and imports are parsed before atomic persistence.
