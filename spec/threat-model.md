# Universal Mesh Core Threat Model

**Status:** Draft
**Version:** 0.1
**Document:** Security Threat Model
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines the security threats, trust boundaries, protected assets, defenses, non-defenses, and residual risks for UMC and UMP/1.

It covers:

* Passive observers
* Local network attackers
* Malicious peers
* Malicious relays
* Sybil and eclipse attackers
* Censors using traffic inspection and blocking
* Active probing authorities
* Compromised discovery and bootstrap sources
* Compromised carrier plugins
* Compromised local applications
* Device theft and endpoint compromise
* Database corruption
* Dependency and build compromise
* Operator error and resource exhaustion

This document guides protocol design, implementation review, tests, deployment guidance, and security claims.

It does not replace:

* Cryptographic review
* Source-code audit
* Deployment-specific risk analysis
* Application threat models
* Security operations and incident response

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

Security claims in project documentation MUST stay within this threat model. A deployment may claim stronger properties only after it defines and reviews the added assumptions and controls.

---

# 3. Security objectives

UMC and UMP/1 aim to protect:

1. Endpoint identity authenticity.
2. Session confidentiality and integrity.
3. Forward secrecy for completed handshakes.
4. Replay and downgrade resistance.
5. Session continuity across path changes.
6. Private keys and traffic secrets at rest and in memory.
7. Peer, route, and relationship metadata according to policy.
8. Bounded CPU, memory, storage, bandwidth, and process use.
9. Correct separation between applications, carriers, relays, and administration.
10. Operation without mandatory project infrastructure.
11. Recovery from loss of optional bootstrap, carrier, or relay services.
12. Detectable failure instead of insecure fallback.

Availability remains conditional on at least one usable communication medium, enough honest or usable peers, and uncompromised endpoints.

---

# 4. Security properties

## 4.1 Authentication

An authenticated UMP session proves that each endpoint controls the private keys required by its accepted identity binding and handshake transcript.

Authentication does not prove:

* Human identity
* Device integrity
* Honest behavior
* Authorization for an application action
* Trustworthiness of route or relay claims

## 4.2 Confidentiality

UMP session encryption protects application and inner protocol content from parties without session traffic keys.

It does not hide packet timing, size, direction, carrier addresses, or communication duration from observers of the carrier.

## 4.3 Integrity

UMP packet protection detects unauthorized changes to authenticated headers and encrypted payloads.

An attacker can still drop, delay, duplicate, reorder, or block packets.

## 4.4 Forward secrecy

Fresh ephemeral key agreement protects past completed sessions after later compromise of long-term endpoint keys, subject to secure erasure and cryptographic assumptions.

Forward secrecy does not protect plaintext, session keys, or application state captured from a device during the session.

## 4.5 Availability

Carrier diversity, routing diversity, relays, local networking, and migration improve recovery from partial failures and blocking.

UMP does not guarantee availability against an attacker who blocks all usable media, controls all reachable routes, or exhausts the endpoint device.

---

# 5. Protected assets

## 5.1 Critical secrets

```text
Identity signing private keys
Static handshake private keys
Ephemeral private keys
Handshake and session traffic secrets
Ticket, Retry, invitation, and reset keys
Carrier private-admission secrets
Local API capability tokens
Keystore unlock material
Release-signing private keys
```

Disclosure may permit impersonation, traffic decryption, admission bypass, or release compromise depending on the key.

## 5.2 Sensitive content

```text
Application plaintext
Stream and datagram content
Bundle plaintext before endpoint encryption
Local application requests
Administrative configuration
Security reports before disclosure
```

## 5.3 Sensitive metadata

```text
Endpoint relationships
Peer and trust stores
Private peer candidates
Routes and relay chains
Connection times and volumes
Application protocol identifiers
Discovery and invitation context
Bundle destination and custody metadata
Device and carrier addresses
```

Metadata sensitivity depends on deployment and application context.

## 5.4 Integrity-sensitive state

```text
Identity bindings and rotation sequence
Revocations and block lists
Packet numbers and replay windows
Flow-control and stream final-size state
Route and relay authorization
Storage schema and migration state
Release manifests and dependency locks
```

## 5.5 Availability assets

```text
CPU time
Memory
Disk and bundle storage
Network bandwidth
Battery and radio time
File descriptors and sockets
Plugin process slots
Routing, relay, and handshake capacity
Operator attention
```

---

# 6. Trust boundaries

## 6.1 Remote network boundary

All carrier input, UMP packets, discovery messages, route claims, relay data, and peer-provided diagnostics are hostile until validation establishes a narrower context.

## 6.2 Adjacent peer boundary

An authenticated adjacent UMP session identifies a peer endpoint. It does not make routing, metrics, relay, or discovery claims trustworthy.

## 6.3 End-to-end endpoint boundary

The endpoint handshake establishes the strongest network trust boundary in UMP. Applications still perform their own authorization and content validation.

## 6.4 Relay boundary

Relays receive opaque inner traffic and local forwarding metadata. Endpoints assume relays may observe, delay, drop, reorder, or collude.

## 6.5 Carrier boundary

Built-in carriers run in the daemon trust domain but retain no need for endpoint keys or application plaintext.

External carriers run across an IPC and process boundary. UMC treats their packet bytes, candidates, metrics, errors, and lifecycle events as untrusted input.

## 6.6 Local application boundary

Local applications authenticate to the control or SDK boundary and receive scoped capabilities. A local process identity alone does not grant administration or access to every endpoint.

## 6.7 Persistence boundary

Database rows, object files, backups, migration inputs, and recovered state may contain corruption or attacker-controlled bytes.

## 6.8 Build and dependency boundary

Compilers, package registries, CI systems, dependencies, release tooling, and update channels can alter shipped code or artifacts.

## 6.9 Operator boundary

Operators control configuration, trust policy, carriers, relay service, backups, and updates. Unsafe operator choices can remove protocol protections or expose metadata.

---

# 7. Assumptions

UMC and UMP/1 assume:

* Mandatory cryptographic primitives remain secure.
* Audited implementations of those primitives behave as specified.
* Endpoint devices can obtain secure randomness.
* Honest endpoints protect private keys within platform limits.
* At least one permitted path exists for availability claims.
* Local policy and application authorization receive correct configuration.
* Operating-system process and permission boundaries provide their documented isolation when relied upon.
* Users obtain authentic software or source through a trusted verification path.

A deployment that cannot satisfy an assumption must reduce its claims or add controls.

---

# 8. Explicit non-defenses

UMC and UMP/1 do not defend against:

* Full compromise of an active endpoint device
* Extraction of keys from a process that currently uses them
* Broken mandatory cryptographic primitives
* A global observer with enough coverage to correlate all paths
* An attacker who blocks every usable communication medium
* Physical coercion
* Malicious application semantics above UMP
* Human identity fraud outside endpoint-key possession
* Traffic analysis from timing and size alone
* Guaranteed message delivery or relay honesty
* Universal detection of database corruption before use
* A compiler or build system that subverts every independent verification path

Project material MUST NOT describe UMP/1 as anonymous, unblockable, metadata-free, or secure after full endpoint compromise.

---

# 9. Risk classification

This document uses four severity levels:

| Severity | Impact |
| --- | --- |
| `CRITICAL` | Broad key compromise, release compromise, undetected remote code execution, or cross-endpoint plaintext exposure |
| `HIGH` | Endpoint impersonation, session compromise, persistent isolation, or major remote denial of service |
| `MEDIUM` | Scoped metadata disclosure, route manipulation, bounded denial of service, or policy bypass with constraints |
| `LOW` | Minor fingerprinting, diagnostic disclosure, or recoverable local degradation |

Likelihood depends on deployment. Tests and design reviews prioritize severity and exposed attack surface.

Residual risk records describe harm that remains after required defenses.

---

# 10. Passive observer

## 10.1 Assets at risk

* Communication relationships
* Endpoint and service metadata
* Application content
* Carrier addresses
* Route timing and path changes
* Session duration and volume

## 10.2 Capabilities

A passive observer can capture packets on one or more carrier links. It may record addresses, timing, sizes, direction, duration, public headers, and carrier framing.

It does not modify traffic or possess endpoint keys under this model.

## 10.3 Required defenses

UMC and UMP MUST:

* Encrypt and authenticate endpoint-session payloads
* Hide permanent endpoint identity from the first public handshake message where the handshake profile permits it
* Use temporary connection IDs
* Keep application protocol identifiers inside encryption
* Avoid plaintext private peer tables and route contents
* Rotate connection IDs under privacy policy
* Permit carrier padding and shaping profiles

## 10.4 Explicit non-defenses

Base UMP/1 does not hide:

* Packet lengths
* Packet timing
* Traffic direction
* Carrier addresses
* Session duration
* Native UMP fingerprint on native carrier profiles

## 10.5 Residual risk

An observer may infer relationships, application class, mobility, or activity through traffic analysis. Several observers may correlate migration and relayed paths. Risk ranges from `MEDIUM` to `HIGH` for sensitive deployments.

---

# 11. Local network attacker

## 11.1 Assets at risk

* Session establishment
* Local peer discovery
* Carrier addresses
* Availability
* Endpoint identity continuity

## 11.2 Capabilities

The attacker can observe, inject, replay, modify, redirect, and drop traffic on a local network. It may spoof LAN discovery, ARP or neighbor state, local DNS, DHCP, Wi-Fi access points, or Bluetooth advertisements.

## 11.3 Required defenses

UMC and UMP MUST:

* Authenticate endpoint handshakes independently of the local carrier
* Treat discovery results as candidates
* Reject packet forgery through AEAD
* Enforce replay windows
* Bind handshakes to carrier profile and available secure context
* Validate migrated paths
* Limit unauthenticated Initial and discovery work
* Avoid granting trust from local IP, SSID, Bluetooth name, or link-layer identity

## 11.4 Explicit non-defenses

UMP cannot stop a local attacker from jamming radio, dropping all packets, disconnecting links, or observing local carrier addresses.

## 11.5 Residual risk

The attacker can cause denial of service, fingerprint native profiles, and steer nodes toward attacker-controlled candidates. End-to-end authentication prevents silent endpoint substitution when trust records are correct. Residual risk is `MEDIUM`; total local-medium control raises availability risk to `HIGH`.

---

# 12. Malicious peer

## 12.1 Assets at risk

* CPU and memory
* Stream and session state
* Peer and route tables
* Relay and bundle quotas
* Application attack surface
* Metadata shared after authentication

## 12.2 Capabilities

The attacker owns valid endpoint keys and completes UMP authentication. It can send validly encrypted malformed state transitions, sparse stream offsets, ACK attacks, route floods, false hints, relay churn, and application payloads.

## 12.3 Required defenses

UMC MUST:

* Separate authentication from authorization
* Apply per-peer and global resource limits
* Validate complete frames before state changes
* Enforce flow-control, stream, and ACK invariants
* Bound replay, reassembly, and request state
* Attribute routing and relay claims to their sender
* Limit peer-hint disclosure
* Isolate application protocols and permissions
* Support restriction and blocking

## 12.4 Explicit non-defenses

Cryptographic identity does not prevent abusive behavior or make remote data safe for applications.

## 12.5 Residual risk

A malicious peer can consume its granted quota, trigger application bugs, infer allowed services, and degrade routes. Distributed low-rate abuse may evade per-peer limits. Residual risk is `HIGH` for exposed public services and `MEDIUM` for invitation-scoped deployments.

---

# 13. Malicious relay

## 13.1 Assets at risk

* Traffic availability
* Timing and volume metadata
* Route confidentiality
* Path integrity
* Endpoint reachability

## 13.2 Capabilities

A relay can observe adjacent peers, circuit timing, packet sizes, local circuit identifiers, and traffic volume. It can drop, delay, reorder, duplicate, or inject relay data. Several relays may collude.

## 13.3 Required defenses

UMP MUST:

* Protect inner endpoint traffic with end-to-end AEAD
* Authenticate final endpoints independently of relays
* Validate session paths
* Detect duplicates and forged inner packets
* Bound relay circuits and route lifetimes
* Support diverse routes and migration
* Minimize next-hop and full-path disclosure

## 13.4 Explicit non-defenses

UMP/1 does not hide timing or volume from the relay. It does not guarantee forwarding, honest metrics, or onion-style path anonymity.

## 13.5 Residual risk

A relay can deny service, perform selective dropping, correlate traffic with colluding relays, and lie about route quality. Endpoints may detect failure but may not identify intent. Residual availability and metadata risk is `HIGH`; plaintext risk remains `LOW` while endpoint keys and cryptography hold.

---

# 14. Sybil attacker

## 14.1 Assets at risk

* Peer-table diversity
* Route selection
* Discovery capacity
* Relay quotas
* Reputation and trust inputs

## 14.2 Capabilities

The attacker creates many endpoint identities and candidates at low cost. It may coordinate them through one network, carrier, introduction source, or operator.

## 14.3 Required defenses

UMC MUST or SHOULD:

* Keep peer and route state bounded
* Separate identity count from trust
* Group quotas by source context and introduction domain where available
* Preserve slots for trusted, local, and successful peers
* Rank failure-domain diversity
* Rate-limit introductions and discovery
* Require scoped authorization for relay and storage
* Avoid global reputation based on unsigned identity claims

## 14.4 Explicit non-defenses

UMP does not impose identity cost, proof of personhood, stake, or a global membership authority.

## 14.5 Residual risk

Attackers can occupy capacity when the node lacks reliable failure-domain evidence. They can distribute abuse across networks and credentials. Residual risk is `HIGH` for open discovery and `MEDIUM` for curated peer sets.

---

# 15. Eclipse attacker

## 15.1 Assets at risk

* Route availability
* View of peers and services
* Software update reachability
* Revocation freshness
* Application communication choices

## 15.2 Capabilities

The attacker controls or impersonates enough discovery, bootstrap, and routing peers to surround a node's observed topology. It may combine Sybil identities, candidate poisoning, selective forwarding, and censorship.

## 15.3 Required defenses

UMC SHOULD:

* Use several discovery providers
* Preserve configured and previously successful peers
* Prefer route and carrier diversity
* Retain local-mesh options
* Detect abrupt peer-table replacement
* Bound one source's influence
* Support signed invitations and bootstrap bundles
* Compare route outcomes across failure domains
* Expose eclipse indicators through diagnostics without claiming proof

## 15.4 Explicit non-defenses

A node with one bootstrap source and no trusted peer has no independent basis to detect a complete eclipse.

## 15.5 Residual risk

A patient attacker can isolate new or poorly connected nodes, delay revocations, and present a consistent false network view. End-to-end authentication prevents impersonation of known endpoints but cannot make them reachable. Residual risk is `HIGH`.

---

# 16. Censor with deep packet inspection

## 16.1 Assets at risk

* Availability
* Carrier reachability
* Peer and bridge addresses
* User safety through protocol identification

## 16.2 Capabilities

The censor observes and blocks addresses, ports, protocols, packet patterns, timing, and traffic destinations. It may throttle, reset, delay, or selectively permit traffic. It can update classifiers and compel network operators.

## 16.3 Required defenses

UMC SHOULD:

* Support replaceable carriers
* Keep sessions independent of one carrier
* Support path migration
* Avoid mandatory public entry lists
* Support private invitations and rotating hints
* Permit carrier-specific framing, padding, and shaping
* Preserve local communication without internet access
* Avoid project-service dependencies

## 16.4 Explicit non-defenses

Native TCP and UDP profiles expose recognizable UMP behavior. TLS alone does not make a carrier censorship-resistant. UMP cannot force access through a medium the censor controls.

## 16.5 Residual risk

The censor may identify and block active carriers, discover public peers, or impose collateral damage that users cannot tolerate. Adaptation raises blocking cost but provides no permanence. Residual risk is `HIGH`.

---

# 17. Active probing authority

## 17.1 Assets at risk

* Private bridge addresses
* Protocol presence
* Endpoint identity disclosure
* Invitation capacity
* Operator and user safety

## 17.2 Capabilities

The attacker connects to suspected nodes, sends chosen inputs, compares timing and errors, replays observations, and obtains public client software. It may probe from many source addresses.

## 17.3 Required defenses

Private or anti-probing deployments MUST:

* Require PSK-gated or equivalent admission before recognizable UMP behavior
* Validate admission before expensive public-key work
* Use carrier-consistent silent or cover failures
* Avoid version negotiation and detailed errors before admission
* Rate-limit by several source contexts
* Rotate and revoke invitation secrets
* Avoid plaintext endpoint identity in initial messages

## 17.4 Explicit non-defenses

Public native UMP listeners do not resist protocol identification. Timing and implementation bugs may distinguish private listeners. The base protocol does not require impersonation of another protocol.

## 17.5 Residual risk

Invitation leakage, side channels, client compromise, and repeated statistical probing may reveal private nodes. Active-probing resistance requires carrier-specific review. Residual risk is `HIGH` for targeted authorities.

---

# 18. Compromised bootstrap source

## 18.1 Assets at risk

* Initial peer selection
* Route diversity
* Availability
* Metadata about new nodes

## 18.2 Capabilities

A compromised source returns attacker-controlled, stale, selective, or malformed candidates. It may log request origin and timing or withhold honest peers.

## 18.3 Required defenses

UMC MUST or SHOULD:

* Treat bootstrap output as candidates
* Authenticate endpoints after dialing
* Bound candidate counts and sizes
* Support several bootstrap methods
* Permit static, local, invitation, and removable-media bootstrap
* Preserve source attribution and expiry
* Avoid mandatory project bootstrap
* Detect source conflicts and poor outcomes

## 18.4 Explicit non-defenses

Endpoint authentication does not reveal omitted honest peers. A sole compromised bootstrap can eclipse a new node.

## 18.5 Residual risk

The source can steer traffic, collect metadata, and delay network entry. Diversity reduces but does not remove this risk. Residual risk is `HIGH` for first contact and `MEDIUM` after a node builds independent peer history.

---

# 19. Compromised discovery peer

## 19.1 Assets at risk

* Private peer hints
* Peer-table capacity
* Route selection
* Node enumeration resistance

## 19.2 Capabilities

The peer can send validly authenticated false, stale, duplicated, or privacy-violating hints. It may query destination tokens and correlate responses.

## 19.3 Required defenses

UMC MUST:

* Enforce hint count and size limits
* Preserve source, expiry, and sharing policy
* Honor `DO_NOT_RESHARE`
* Avoid complete peer-table disclosure
* Authenticate final endpoints after candidate use
* Rate-limit failed hints and enumeration attempts
* Keep private peers partitioned by policy

## 19.4 Explicit non-defenses

A source-authenticated hint may still lie about reachability or carrier properties.

## 19.5 Residual risk

The attacker can waste dial and route budgets and infer some policy from acceptance behavior. Residual risk is `MEDIUM`.

---

# 20. Compromised carrier plugin

## 20.1 Assets at risk

* Packet metadata and ciphertext
* Carrier credentials and addresses
* Availability
* Daemon memory and secrets
* Peer candidates and path properties

## 20.2 Capabilities

The plugin controls one carrier process. It can alter, drop, replay, delay, or log packets; forge candidates and metrics; abuse network or device permission; send malformed IPC; and crash.

## 20.3 Required defenses

UMC MUST:

* Run external plugins out of process
* Use authenticated private IPC created at launch
* Validate message lengths, handles, generations, and state
* Bound queues, shared memory, logs, and operation counts
* Withhold endpoint private keys and session keys
* Withhold application plaintext and unrelated stores
* Invalidate plugin Links after crash
* Support restart backoff and disablement
* Apply OS sandboxing where available
* Treat candidates and metrics as untrusted hints

## 20.4 Explicit non-defenses

A plugin can observe addresses, timing, sizes, and ciphertext sent through its carrier. A plugin with broad network or device permission can misuse that permission within OS limits.

## 20.5 Residual risk

The plugin can deny service, leak carrier metadata, and target kernel or driver attack surfaces. Process isolation reduces daemon compromise but cannot guarantee containment against OS sandbox escapes. Residual risk is `HIGH`.

---

# 21. Compromised built-in carrier

## 21.1 Assets at risk

Built-in carrier compromise risks daemon process memory, including session keys and endpoint operations available in that process.

## 21.2 Capabilities

A memory-safety flaw, unsafe code defect, or malicious dependency in an in-process carrier may execute within daemon privilege.

## 21.3 Required defenses

UMC MUST or SHOULD:

* Keep built-in carriers small
* Use memory-safe Rust where possible
* Minimize and review unsafe code
* Restrict dependencies
* Fuzz carrier framing
* Separate carrier modules from key APIs
* Offer process isolation for complex or experimental carriers

## 21.4 Explicit non-defenses

Language-level module boundaries do not contain arbitrary code execution inside the daemon process.

## 21.5 Residual risk

An in-process compromise can expose active secrets and control node behavior. Residual severity is `CRITICAL`; likelihood depends on code and dependency quality.

---

# 22. Compromised local application

## 22.1 Assets at risk

* Endpoint use permissions
* Other applications' traffic
* Administrative state
* Peer and route metadata
* Local resource quotas

## 22.2 Capabilities

The attacker controls one local application process and its granted credentials. It may send arbitrary API requests, race cancellation, open sessions, exhaust quotas, and probe permission boundaries.

## 22.3 Required defenses

UMC MUST:

* Authenticate local clients
* Use capability-scoped tokens
* Separate administration, diagnostics, and application data services
* Bind permissions to selected endpoints and protocol IDs
* Enforce request, stream, session, and byte quotas
* Prevent private-key export by default
* Partition event streams and handles
* Validate every local message
* Support credential revocation and audit events

## 22.4 Explicit non-defenses

UMC cannot protect data that the application receives under a valid grant. The OS may permit a same-user process to inspect another process unless platform isolation prevents it.

## 22.5 Residual risk

A compromised application can abuse its authorized endpoint, leak received plaintext, and infer policy through errors. Overbroad grants raise risk to `HIGH`; narrow grants leave `MEDIUM` residual risk.

---

# 23. Compromised administrative client

## 23.1 Assets at risk

All node configuration, identities, policies, carriers, routes, relay state, and shutdown control may be at risk.

## 23.2 Capabilities

The attacker controls a valid administrative credential or process.

## 23.3 Required defenses

UMC SHOULD:

* Separate high-risk operations into narrow permissions
* Require reauthentication or operator confirmation for key export, trust reset, and destructive state changes
* Audit administrative changes
* Support rapid credential revocation
* Restrict control transport to local authenticated channels

## 23.4 Explicit non-defenses

A fully authorized administrator can disable security controls, delete state, enable public relay, or expose metadata.

## 23.5 Residual risk

Administrative compromise is `CRITICAL`. Capability separation reduces the effect of partial administrative roles but cannot contain a root-equivalent grant.

---

# 24. Device theft while powered off

## 24.1 Assets at risk

* Long-term endpoint keys
* Trust and peer stores
* Invitations and tickets
* Application and bundle metadata
* Backups

## 24.2 Capabilities

The attacker possesses storage media and may copy files, perform offline guessing, and inspect unencrypted logs or backups. The process does not hold active secrets in memory.

## 24.3 Required defenses

UMC MUST or SHOULD:

* Use OS key storage where available
* Encrypt fallback keystores with a strong user or machine secret
* Separate secret state from metadata
* Avoid secrets in logs
* Protect backups and export files
* Support key revocation and rotation
* Use memory-hard password derivation for password-protected secrets

## 24.4 Explicit non-defenses

Weak user secrets, unlocked full-disk encryption, copied recovery material, or insecure backups can defeat at-rest protection.

## 24.5 Residual risk

Metadata may remain visible when only secret keys receive encryption. Offline guessing remains possible against weak secrets. Residual risk ranges from `MEDIUM` to `CRITICAL` by platform and configuration.

---

# 25. Device theft while unlocked

## 25.1 Assets at risk

Active keys, plaintext, local API credentials, and application data may be available.

## 25.2 Capabilities

The attacker can operate the unlocked device, inspect user files, invoke local APIs, and install or run code within granted OS permissions.

## 25.3 Required defenses

UMC MAY reduce harm through:

* OS-backed non-exportable keys
* Local API capability separation
* Idle lock and credential expiry
* User-triggered emergency shutdown
* Short-lived invitations and tickets
* Minimal plaintext retention

## 25.4 Explicit non-defenses

An attacker with code execution in the active daemon or user session may use keys without exporting them and read application plaintext.

## 25.5 Residual risk

This scenario approaches endpoint compromise. Residual risk is `CRITICAL`.

---

# 26. Full endpoint compromise

## 26.1 Assets at risk

All secrets, plaintext, identity actions, local policy, peer metadata, and current sessions on the endpoint are at risk.

## 26.2 Capabilities

The attacker executes code with daemon privilege, reads process memory, intercepts API calls, changes binaries or configuration, and uses endpoint keys.

## 26.3 Expected containment

End-to-end encryption may still protect other uncompromised endpoints and unrelated sessions that never share keys or plaintext with the compromised node.

Forward secrecy may protect completed past sessions if the attacker did not capture their ephemeral or traffic secrets and secure erasure worked.

## 26.4 Explicit non-defenses

UMC does not protect the compromised endpoint's active sessions, plaintext, keys, or actions.

## 26.5 Residual risk

The attacker can impersonate the endpoint until peers receive and enforce revocation or rotation. In disconnected networks, that delay may be long. Risk is `CRITICAL`.

---

# 27. Database corruption

## 27.1 Assets at risk

* Identity continuity
* Trust and revocation state
* Packet and ticket safety
* Route and peer correctness
* Bundle accounting
* Availability

## 27.2 Capabilities

Corruption may come from storage failure, crash, software defect, operator action, rollback, or attacker write access. It can alter, truncate, duplicate, reorder, or replace records and object files.

## 27.3 Required defenses

UMC MUST:

* Use transactions and explicit migrations
* Validate schemas, lengths, versions, and cryptographic records on read
* Keep secret-key formats separate from ordinary metadata
* Prevent corruption from causing nonce, packet-number, or key reuse
* Treat persisted live-session state as unusable after restart
* Revalidate cached routes and candidates
* Verify content-addressed object hashes
* Detect missing or conflicting references
* Provide integrity checks, backup, and recovery procedures

## 27.4 Explicit non-defenses

SQLite transactions do not prove that stored values are semantically correct or prevent malicious rollback. Filesystem and hardware faults may affect database and backup copies.

## 27.5 Residual risk

Corruption can cause data loss, trust rollback, stale revocation, or node unavailability. Secret-state corruption must fail closed, but recovery may require user action. Residual risk is `HIGH`.

---

# 28. Database rollback attacker

## 28.1 Assets at risk

* Key rotation sequence
* Revocation freshness
* TOFU continuity
* Ticket and invitation replay state
* Storage quotas

## 28.2 Capabilities

The attacker replaces current storage with an older valid snapshot without forging record cryptography.

## 28.3 Required defenses

UMC SHOULD:

* Use monotonic platform counters where available
* Bind backups to explicit generation and restore workflow
* Detect sequence regression against OS key-store metadata or trusted peers
* Rotate ticket and Retry keys after restore
* Invalidate replay-sensitive operational state
* Warn users when trust or revocation state may be stale

## 28.4 Explicit non-defenses

Platforms without a trusted monotonic anchor cannot detect every offline rollback.

## 28.5 Residual risk

Rollback may resurrect trust, invitations, or stale bindings until peers reject them. Residual risk is `HIGH` for identity state and `MEDIUM` for route state.

---

# 29. Malicious backup or import file

## 29.1 Assets at risk

Parser safety, identity state, trust policy, and storage integrity are at risk.

## 29.2 Capabilities

The attacker provides a crafted invitation, bootstrap bundle, identity export, backup, or restore archive.

## 29.3 Required defenses

UMC MUST:

* Parse imports as hostile input
* Enforce total and field-specific size limits
* Reject path traversal and unsafe file types
* Verify signatures, hashes, versions, and ownership
* Stage restore into an isolated location
* Validate before replacing active state
* Require explicit authorization for identity and trust changes

## 29.4 Explicit non-defenses

A user may authorize import of a valid but malicious peer or policy set.

## 29.5 Residual risk

Imports can poison trust and availability through social engineering even when parsers remain safe. Residual risk is `MEDIUM`.

---

# 30. Dependency compromise

## 30.1 Assets at risk

All assets reachable by the affected dependency may be exposed.

## 30.2 Capabilities

An attacker publishes a malicious package version, compromises a maintainer or registry, takes over an abandoned dependency, or inserts a vulnerable transitive dependency.

## 30.3 Required defenses

The project MUST or SHOULD:

* Minimize dependencies
* Pin release dependency versions and hashes
* Review security-sensitive crates
* Use lockfiles and reproducible builds
* Generate an SBOM
* Scan advisories and licenses
* Restrict build-script and procedural-macro use
* Separate high-risk carrier dependencies into plugin processes
* Review dependency updates before release
* Support emergency dependency replacement

## 30.4 Explicit non-defenses

Automated scanners miss unknown or hidden malicious behavior. Pinning preserves a compromised version until maintainers respond.

## 30.5 Residual risk

A compromised cryptographic, parsing, async-runtime, database, or build dependency may produce `CRITICAL` impact. Independent review and reproducibility reduce but do not remove supply-chain risk.

---

# 31. Build and CI compromise

## 31.1 Assets at risk

* Release binaries
* Source archives
* SBOM and provenance
* Signing workflows
* User update trust

## 31.2 Capabilities

The attacker controls CI jobs, runners, artifact storage, workflow configuration, or one signing identity.

## 31.3 Required defenses

The project MUST or SHOULD:

* Require reviewed workflow changes
* Use least-privilege CI credentials
* Isolate untrusted pull-request jobs from release secrets
* Publish reproducible-build instructions
* Sign release manifests with maintainer threshold keys
* Add Sigstore-compatible provenance
* Keep enough long-lived signing keys outside CI
* Verify source commit and artifact hashes before threshold approval
* Publish revocation procedures

## 31.4 Explicit non-defenses

Sigstore or one CI signature alone cannot protect against compromise of its identity, runner, and verification path.

## 31.5 Residual risk

Compromise may ship malicious binaries under valid automation identity. Threshold review and independent reproduction reduce risk. Residual severity is `CRITICAL`.

---

# 32. Release-signing key compromise

## 32.1 Assets at risk

Artifact authenticity and update trust are at risk.

## 32.2 Capabilities

The attacker controls one or more long-lived maintainer keys or their hardware-token authorization.

## 32.3 Required defenses

The project MUST:

* Use threshold release approval
* Protect keys with hardware where possible
* Separate key holders and conflict domains
* Prepare revocation statements
* Publish signed release manifests
* Support emergency key rotation
* Keep CI below signing threshold

## 32.4 Explicit non-defenses

Compromise of enough threshold keys can authorize a malicious release.

## 32.5 Residual risk

Users who receive revocation late may install compromised artifacts. Offline and disconnected environments lengthen recovery. Residual risk is `CRITICAL`.

---

# 33. Malicious update or downgrade source

## 33.1 Assets at risk

Software integrity, security fixes, and protocol compatibility are at risk.

## 33.2 Capabilities

The attacker controls a mirror, network path, package feed, or local update cache. It serves modified, stale, or vulnerable releases.

## 33.3 Required defenses

Update clients and operators MUST:

* Verify threshold signatures and hashes
* Enforce supported-version policy
* Reject unsigned metadata
* Detect version rollback unless operator authorizes it
* Keep security revocation data available through several channels

## 33.4 Explicit non-defenses

An operator can authorize an old or unsupported version. Offline nodes may lack current revocation data.

## 33.5 Residual risk

Attackers can delay updates or exploit stale clients even without forging signatures. Residual risk is `HIGH`.

---

# 34. Parser attacker

## 34.1 Assets at risk

Process integrity, memory safety, CPU, and availability are at risk.

## 34.2 Capabilities

The attacker supplies arbitrary packet, frame, handshake, discovery, route, relay, carrier, control API, database, and import bytes.

## 34.3 Required defenses

All parsers MUST:

* Validate outer length before nested fields
* Enforce canonical encoding
* Use field-specific maximums
* Prevent integer overflow and unsafe conversions
* Avoid recursion and unbounded loops
* Avoid allocation from raw untrusted lengths
* Validate complete units before state changes
* Reject invalid contexts and state transitions
* Receive fuzzing and adversarial tests
* Use memory-safe code where possible

## 34.4 Explicit non-defenses

Fuzzing does not prove absence of parser defects. Unsafe dependencies and logic bugs remain possible.

## 34.5 Residual risk

Network-facing parser bugs may lead to denial of service or code execution. Residual severity is `CRITICAL`; required engineering aims to reduce likelihood.

---

# 35. Cryptographic protocol attacker

## 35.1 Assets at risk

Endpoint authentication, session keys, transcript integrity, forward secrecy, and downgrade resistance are at risk.

## 35.2 Capabilities

The attacker controls network messages, starts concurrent handshakes, replays transcripts, substitutes keys, manipulates negotiation, and obtains chosen-protocol interactions.

## 35.3 Required defenses

UMP MUST:

* Use reviewed standard primitives
* Apply domain separation to signatures, MACs, and KDF labels
* Canonically encode signed and transcript data
* Bind versions, profiles, capabilities, identities, connection IDs, retry, and carrier context into the transcript
* Use fresh ephemeral keys and randoms
* Confirm derived keys
* Reject invalid state transitions
* Separate Initial, Handshake, session, ticket, Retry, and exporter keys
* Erase obsolete secrets where supported
* Publish vectors and undergo independent review

## 35.4 Explicit non-defenses

Use of standard primitives does not prove the composed handshake secure. The current draft has not received the required independent cryptographic and formal review.

## 35.5 Residual risk

A design or implementation flaw may break authentication or confidentiality across deployments. Until review and vectors stabilize, residual risk is `CRITICAL`.

---

# 36. Randomness failure

## 36.1 Assets at risk

Keys, nonces, connection IDs, tokens, path challenges, and replay protection are at risk.

## 36.2 Capabilities

The attacker predicts or influences random output, or the platform returns repeated values after boot, snapshot, fork, or entropy failure.

## 36.3 Required defenses

UMC MUST:

* Use an OS CSPRNG or equivalent
* Fail closed when secure randomness is unavailable
* Avoid production deterministic RNG modes
* Generate fresh handshake randoms and ephemeral keys
* Prevent process-fork state duplication where applicable
* Test duplicate-detection invariants

## 36.4 Explicit non-defenses

Software may not detect a compromised OS random generator that returns plausible output.

## 36.5 Residual risk

Randomness failure can cause identity compromise, nonce reuse, and session breakage. Severity is `CRITICAL`.

---

# 37. Clock attacker and clock failure

## 37.1 Assets at risk

Binding validity, revocations, tickets, invitations, route expiry, bundle expiry, and logs are at risk.

## 37.2 Capabilities

The attacker changes system wall clock through local compromise, network time manipulation, restore, or hardware failure.

## 37.3 Required defenses

UMC SHOULD:

* Use monotonic clocks for durations after receipt
* Apply bounded wall-clock skew policy
* Detect large jumps
* Avoid extending remote lifetimes through clock changes
* Revalidate sensitive state after anomalies
* Provide explicit operator recovery for unreliable clocks

## 37.4 Explicit non-defenses

Nodes without trusted time cannot prove absolute certificate or revocation freshness in disconnected operation.

## 37.5 Residual risk

Clock manipulation can cause false expiry, stale-state acceptance, denial of service, or misleading logs. Residual risk is `MEDIUM` to `HIGH`.

---

# 38. Resource-exhaustion attacker

## 38.1 Assets at risk

CPU, memory, disk, bandwidth, battery, file descriptors, database write capacity, and operator attention are at risk.

## 38.2 Capabilities

The attacker sends many valid or invalid handshakes, streams, sparse offsets, ACK ranges, route requests, relay opens, candidates, bundles, plugin messages, control requests, or log-triggering errors.

## 38.3 Required defenses

UMC MUST:

* Set hard global and scoped limits
* Validate cheaply before expensive work
* Use stateless Retry where required
* Apply quotas by peer, source context, application, and trust class
* Bound queues and parser loops
* Apply backpressure
* Reserve capacity for control and recovery
* Rate-limit logs and diagnostics
* Evict through documented policy
* Expose resource metrics

## 38.4 Explicit non-defenses

Any admitted work consumes resources. Distributed attacks can exceed one device's capacity despite fair limits.

## 38.5 Residual risk

Attackers can reduce service quality or force rejection of honest work. Hard limits preserve process bounds but cannot guarantee availability. Residual risk is `HIGH`.

---

# 39. Malicious route advertiser

## 39.1 Assets at risk

Route integrity, privacy, availability, and failure-domain diversity are at risk.

## 39.2 Capabilities

The attacker sends authenticated false reachability, cost, latency, diversity, scope, or failure claims.

## 39.3 Required defenses

UMC MUST:

* Treat advertisements as claims
* Bind responses to requests and destination hints
* Authenticate final responders where the profile requires it
* Expire and attribute route evidence
* Enforce hard policy before scoring
* Prefer local observations over remote metrics
* Validate constructed paths and endpoint identity
* Retain diverse alternatives

## 39.4 Explicit non-defenses

An authenticated peer can lie. Path success does not prove future availability or route independence.

## 39.5 Residual risk

The attacker can waste path construction, attract traffic, and cause selective failure. Residual risk is `HIGH`.

---

# 40. Malicious application endpoint

## 40.1 Assets at risk

Application state, user data, business logic, and user trust are at risk.

## 40.2 Capabilities

The remote endpoint completes UMP authentication and speaks an advertised application protocol with malicious content or semantics.

## 40.3 Required defenses

Applications MUST:

* Authenticate and authorize application actions
* Validate payloads and state transitions
* Apply application quotas
* Treat endpoint key possession as one identity signal
* Avoid unsafe assumptions about transport trust

UMC SHOULD isolate protocol listeners and expose endpoint identity and trust context without making the application accept it.

## 40.4 Explicit non-defenses

UMP does not define messaging safety, payments, content moderation, user verification, or application data validation.

## 40.5 Residual risk

Application vulnerabilities remain outside transport guarantees. Risk depends on the application and may be `CRITICAL`.

---

# 41. Privacy failures from logging and telemetry

## 41.1 Assets at risk

Keys, addresses, peer relationships, route history, application identifiers, and usage patterns are at risk.

## 41.2 Capabilities

An attacker reads logs, metrics, crash reports, backups, or optional telemetry. Operators or plugins may enable debug output.

## 41.3 Required defenses

UMC MUST:

* Disable telemetry by default
* Exclude secrets and plaintext from default logs
* Redact stable endpoint and address identifiers
* Bound diagnostic text from peers and plugins
* Avoid per-peer labels on public metrics
* Require explicit opt-in for sensitive debug output
* Document retention and export behavior

## 41.4 Explicit non-defenses

Operators can enable or add unsafe logging. OS and third-party crash systems may capture process state outside UMC control.

## 41.5 Residual risk

Metadata aggregation can reconstruct topology and behavior even without payloads. Residual risk is `MEDIUM` to `HIGH`.

---

# 42. Operator misconfiguration

## 42.1 Assets at risk

Trust, relay exposure, private peers, costs, keys, storage, and availability are at risk.

## 42.2 Capabilities

The operator sets unsafe policy, exposes control sockets, enables public relay, weakens admission, imports untrusted state, or disables limits.

## 42.3 Required defenses

UMC SHOULD:

* Ship conservative defaults
* Disable public relay and telemetry by default
* Require explicit carrier and listener enablement
* Validate dangerous combinations
* Warn before exposing private or costly services
* Provide `umc doctor` checks
* Keep secure limits even when soft policy expands
* Record auditable configuration changes

## 42.4 Explicit non-defenses

An authorized operator can choose insecure settings. The core cannot infer legal, social, or physical risk for every deployment.

## 42.5 Residual risk

Misconfiguration remains a common path to exposure and denial of service. Residual risk is `HIGH`.

---

# 43. Cross-protocol and downgrade attacker

## 43.1 Assets at risk

Authentication context, algorithm choice, carrier security, and protocol parsing are at risk.

## 43.2 Capabilities

The attacker reflects UMP messages into another protocol, alters version or capability offers, strips security options, or induces fallback.

## 43.3 Required defenses

UMP MUST:

* Use protocol-specific domain labels
* Authenticate negotiated versions, profiles, modes, and capabilities
* Bind carrier context
* Reject unknown critical semantics
* Avoid fallback after authenticated negotiation failure
* Require a new policy-approved attempt for weaker carrier or handshake modes

## 43.4 Explicit non-defenses

An operator may initiate a weaker profile under explicit policy. Traffic fingerprinting may still identify the protocol.

## 43.5 Residual risk

Implementation differences and optional profiles can create downgrade edges. Residual risk is `HIGH` until interoperability and negative tests stabilize.

---

# 44. Malicious revocation or rotation input

## 44.1 Assets at risk

Endpoint continuity and trust are at risk.

## 44.2 Capabilities

The attacker sends forged, stale, reordered, or conflicting bindings, delegation chains, rotations, or revocations.

## 44.3 Required defenses

UMC MUST:

* Verify signatures and endpoint binding
* Enforce sequence monotonicity
* Bound chain length and size
* Reject cycles and duplicate keys
* Apply validity and clock policy
* Preserve accepted trust state across restart
* Require stronger recovery policy when old signing keys are unavailable

## 44.4 Explicit non-defenses

Disconnected nodes may receive valid revocations late. Compromise of the authorized signing key permits valid malicious statements until recovery policy intervenes.

## 44.5 Residual risk

Peers may diverge in accepted identity state during partitions. Residual risk is `HIGH`.

---

# 45. Threat composition

Attackers may combine roles.

Examples include:

* A censor operates Sybil peers and active probes.
* A malicious bootstrap source feeds only malicious relays.
* A compromised plugin logs metadata and steers route metrics.
* A stolen unlocked device authorizes malicious local applications.
* A CI attacker ships a parser backdoor through a signed automation artifact.
* A rollback attacker restores invitations and stale trust state after device theft.

Security review MUST analyze combined paths rather than treating each threat as isolated.

The strongest residual risks come from combinations that remove independent trust or diversity assumptions.

---

# 46. Security invariants

Implementations MUST preserve these invariants:

```text
Private keys never cross carrier or remote protocol boundaries.
Endpoint authentication never derives from address, route, relay, or discovery identity.
Application plaintext never reaches relays or carrier plugins through their defined APIs.
Packet numbers never repeat under one key and packet-number space.
Unauthenticated input cannot force unbounded allocation or computation.
Flow-control, stream, route, relay, and storage limits never increase from remote claims alone.
Unknown critical protocol semantics fail closed.
Path migration never changes authenticated endpoint identity.
Restored storage never resumes live cryptographic session state.
One local application cannot access another application's handles or events without a grant.
One plugin process generation cannot reuse another generation's handles or memory slots.
Public relay and telemetry remain disabled until explicit operator action.
```

Tests must map each invariant to unit, property, fuzz, integration, or adversarial coverage.

---

# 47. Security claims matrix

| Property | Base UMP/1 claim | Main limitation |
| --- | --- | --- |
| Endpoint authentication | Mutual key-possession authentication after confirmed handshake | No human identity or device integrity |
| Content confidentiality | End-to-end AEAD between endpoints | Endpoint compromise and traffic metadata |
| Forward secrecy | Fresh ephemeral contribution in full handshake | Active endpoint memory compromise |
| Replay resistance | Packet numbers, replay windows, fresh handshake state | Bounded windows and restored application operations |
| Downgrade resistance | Negotiation bound into transcript | Explicit operator-selected weak profile |
| Relay confidentiality | Relays see opaque inner packets | Timing, size, adjacency metadata |
| Route integrity | Authenticated claims plus endpoint and path validation | Malicious claims and selective failure |
| Censorship resilience | Carrier and path diversity | Total blocking and classifier adaptation |
| Active-probing resistance | PSK-gated private profiles only | Side channels and invitation compromise |
| Storage confidentiality | Protected keystore; metadata policy | Platform and backup quality |
| Resource safety | Hard bounded limits | Honest work may be rejected under attack |
| Supply-chain authenticity | Threshold manifests and reproducibility target | Threshold-key or verifier compromise |

---

# 48. Verification requirements

The project MUST maintain:

* Wire and handshake test vectors
* Parser fuzz targets
* State-machine property tests
* Cross-implementation tests
* Adversarial network simulation
* Dependency audit and SBOM
* Unsafe-code inventory
* Cryptographic review record
* Security regression tests
* Release provenance and signature verification tests

Before production security claims, the project MUST obtain:

1. Independent handshake and cryptographic review.
2. Network parser and unsafe-code audit.
3. Adversarial review of routing, relaying, and discovery.
4. Local API authorization review.
5. Storage and migration review.
6. Carrier plugin boundary review.
7. Reproducible-build and release-signing review.

---

# 49. Adversarial test scenarios

The test suite SHOULD include:

1. Passive capture across direct and relayed sessions.
2. Local man-in-the-middle with forged discovery.
3. Authenticated peer sending valid-state floods.
4. Relay selective loss and timing correlation.
5. Sybil population from one and several source domains.
6. Complete and partial eclipse attempts.
7. DPI blocking one carrier during an active session.
8. Active probing of public and PSK-gated listeners.
9. Compromised bootstrap returning only malicious candidates.
10. Plugin forging MTU, scope, and quality events.
11. Plugin crash during packet ownership transfer.
12. Local application crossing endpoint and event permissions.
13. Administrative credential abuse.
14. Stolen-disk keystore and backup analysis.
15. Database truncation, row mutation, and rollback.
16. Malicious import archive and invitation.
17. Dependency or build artifact substitution.
18. Release-signing threshold and revocation exercise.
19. Clock rollback and forward jump.
20. Randomness-source failure injection.
21. Combined censor, Sybil, and malicious-relay attack.
22. Resource flood across handshake, stream, routing, relay, plugin, and local API boundaries.

Tests must verify both security outcome and resource bound.

---

# 50. Operational detection

UMC SHOULD expose evidence for:

```text
Handshake failure spikes
Invalid packet and frame rates
Peer quota exhaustion
Abrupt peer-table replacement
Route diversity loss
Relay refusal and selective failure
Carrier-specific blocking patterns
Plugin crashes and protocol violations
Database integrity failures
Clock anomalies
Credential and trust changes
Unsupported or revoked software versions
```

Diagnostics MUST label observations and remote claims. They MUST avoid declaring censorship, compromise, eclipse, or malicious intent without enough evidence.

Detection output must preserve the logging and metadata rules in this model.

---

# 51. Incident containment expectations

UMC architecture must support:

* Blocking peers and revoking local credentials
* Disabling one carrier or plugin
* Disabling relay service
* Rotating handshake, ticket, Retry, invitation, and release keys
* Revoking endpoint bindings
* Disabling protocol versions or cryptographic profiles
* Rebuilding route and peer caches
* Restoring validated storage backups
* Exporting redacted diagnostics

The security-operations specification will define authority, timelines, disclosure, and release procedures.

Containment actions must state which security state survives and which state becomes invalid.

---

# 52. Threat-model maintenance

Every protocol or architecture proposal MUST assess:

* New assets
* New trust boundaries
* New attacker capabilities
* Required defenses
* Explicit non-defenses
* Resource impact
* Privacy impact
* Residual risk
* Verification plan

Maintainers must update this document when a change alters a security claim or adds a network, local, storage, plugin, or build boundary.

Security review should assign an owner and status to each unresolved `HIGH` or `CRITICAL` risk.

---

# 53. Open security decisions

The project must resolve these items before production claims:

1. Formal handshake model and review method.
2. Final mandatory hash and cryptographic profile.
3. Post-quantum migration timing.
4. Endpoint routing-token privacy construction.
5. Route-response and relay authorization formats.
6. Minimum anti-probing carrier requirements.
7. Default Sybil grouping and diversity signals.
8. Persistent rollback detection per platform.
9. Fallback keystore KDF and parameters.
10. OS key-store support matrix.
11. Local API capability-token format and storage.
12. Minimum plugin sandbox for Tier-1 systems.
13. Shared-memory plugin threat controls.
14. Release threshold bootstrap and key-recovery process.
15. Supported-version and emergency-disable mechanism.
16. Security log retention and redaction profiles.
17. Crash-report policy.
18. Mobile endpoint threat model.
19. Bundle metadata and custody threat model.
20. Criteria for censorship-resistance claims.

---

# 54. Minimal v0.1 security gate

Implementation may begin while this threat model remains Draft. A stable v0.1 release MUST NOT claim production security until the project completes these gates:

* Final wire and handshake vectors
* Independent cryptographic review
* Fuzzing of every network and local parser
* Enforced resource-limit profiles
* Local API permission tests
* Plugin process-isolation tests
* Storage corruption and rollback tests
* Dependency audit and SBOM
* Signed release manifest workflow
* Published vulnerability-reporting process
* Documented residual risks and unsupported claims

Experimental releases must identify incomplete gates.

---

# 55. Core rule

UMC treats network peers, relays, discovery, carrier plugins, local applications, persisted bytes, and software dependencies as separate attack surfaces.

Cryptography protects endpoint identity and content within its reviewed assumptions. Bounded state protects the node from hostile input. Diversity supports recovery from partial blocking and malicious paths. Full endpoint compromise, global traffic analysis, and loss of every communication medium remain outside UMP/1 protection.
