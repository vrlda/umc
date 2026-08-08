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

The daemon must:

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

## 16. Release-signing process

### Decision

Use two complementary signing mechanisms.

#### Maintainer threshold signatures

Release manifests are signed by multiple long-lived maintainer keys.

Initial policy:

```text
2-of-3 release approval
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

Threshold maintainer signatures provide an offline-verifiable project trust root.

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
Linux aarch64
macOS arm64
Windows x86_64
```

Tier 2:

```text
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
    Threshold maintainer signatures
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
   keep their fixed layout; length-delimited relay status and unknown optional
   frames are skipped using their declared length.
2. **Protected session transition.** Initial packets protect the early
   handshake, while the current daemon uses a provisional header-protection
   continuation until the authenticated session keys are established. The
   transcript still binds the real identity binding and finished messages.
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
   reference daemon currently creates an ephemeral self-signed certificate;
   independent deployments must provide a trust configuration before using
   it between separate daemons.
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
