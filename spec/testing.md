# Universal Mesh Core Testing and Interoperability Specification

**Status:** Draft
**Version:** 0.1
**Document:** Test Strategy and Requirements
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines the testing strategy and mandatory test classes for UMC and UMP/1.

It specifies:

* Testing objectives
* Test classes
* Unit tests
* Integration tests
* State-machine tests
* Property tests
* Test vectors
* Interoperability tests
* Fuzzing
* Simulation
* Adversarial tests
* Fault-injection tests
* Performance baselines
* Long-running soak tests
* Cross-platform requirements
* CI requirements
* Test tooling
* Coverage requirements
* Security testing gates

Every module specification in this project defines its own required tests. This document defines the shared framework, tooling, and gates they all use.

This document does not define:

* Application testing
* Formal verification proofs
* Marketing claims

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

---

# 3. Testing objectives

Testing MUST verify:

1. Protocol correctness against the specifications.
2. State-machine invariants under all transitions.
3. Interoperability between independent implementations.
4. Security behavior under hostile input.
5. Resource bounds under load and attack.
6. Crash and restart behavior.
7. Performance baselines.
8. Long-run stability.
9. Cross-platform behavior.
10. That documented claims match observed behavior.

Tests MUST encode WHY behavior matters, not just WHAT it does.

A test that cannot fail when business logic changes is wrong.

---

# 4. Test classes

The project MUST include:

```text
Unit tests
Integration tests
State-machine tests
Property tests
Test vectors
Interoperability tests
Fuzz tests
Simulation tests
Adversarial tests
Fault-injection tests
Performance baselines
Long-running soak tests
```

---

# 5. Unit tests

Unit tests:

* Test isolated logic
* Run fast
* Require no network
* Cover parsers, encoders, state transitions, and accounting

Every module MUST have unit tests for its public and internal logic.

Protocol-pure code MUST be testable without a runtime or operating system.

---

# 6. Integration tests

Integration tests:

* Test modules together
* Run real carriers where practical
* Test daemon, SDK, and storage integration
* Test configuration and lifecycle
* Test restart behavior

Integration tests MUST run on Tier-1 platforms.

---

# 7. State-machine tests

State-machine tests cover:

* Session states
* Stream states
* Path states
* Circuit states
* Route states
* Handshake states
* Trust states
* Carrier and link states
* Plugin states
* Connection states

For each state machine, tests MUST cover:

* Every defined transition
* Invalid transitions
* Duplicate events
* Out-of-order events
* Cancellation races
* Timeout behavior
* Reset and restart

State-machine tests SHOULD be table-driven or generated from explicit transition tables.

---

# 8. Property tests

Property tests verify invariants under randomized input.

Mandatory invariants include:

```text
Packet numbers never repeat under one key and packet-number space
Route loops are rejected
Flow-control limits never decrease
Duplicate bundles are not stored twice
Invalid signatures never authenticate
Session state survives valid path migration
Resource limits remain bounded
Applications receive each reliable stream byte at most once
One stream direction has one final size
Unvalidated paths never exceed amplification limits
Migration never changes endpoint identity or stream state
```

Each module specification lists its own property-test invariants.

Property tests MUST run with a deterministic seed and record failing seeds.

---

# 9. Test vectors

## 9.1 Purpose

Test vectors:

* Lock stable encodings
* Enable cross-implementation testing
* Detect accidental format changes
* Are the basis of differential testing

## 9.2 Required vectors

The finalized specification MUST publish vectors for:

Wire format:

```text
Varint encoding
Long-header parsing
Short-header parsing
Header protection
Packet-number reconstruction
AEAD associated-data construction
STREAM frames
ACK frames
ROUTE_REQUEST
RELAY_DATA
BUNDLE
Unknown optional frames
Malformed length handling
```

Handshake:

```text
Endpoint ID derivation
Identity binding signing
Initial secret derivation
Initial packet keys
XX ClientHello
XX ServerHello encryption
Client authentication encryption
All Diffie-Hellman intermediate secrets
Handshake traffic secrets
Client signature input
Server signature input
Finished MACs
Session traffic secrets
Packet-key derivation
Retry-token validation
PSK-XX admission authentication
Session-ticket derivation
Key update
Invalid transcript rejection
Downgrade rejection
```

Carrier:

```text
Carrier Binding canonical vectors
TCP and UDP framing
Plugin framing
```

Storage:

```text
Schema migration vectors
Keystore integrity vectors
Object hash vectors
```

## 9.3 Rules

* Test vectors are public and versioned
* Private keys in vectors are clearly marked test-only
* Every official implementation MUST pass the same interoperability vectors
* Vectors change only with the version they describe

---

# 10. Interoperability tests

Interoperability tests verify independent implementations.

Requirements:

* Test vectors all implementations must pass
* Cross-implementation sessions
* Cross-implementation routing and relaying
* Version negotiation between versions
* Downgrade-attempt rejection
* Protocol version coexistence

The interoperability runner MUST:

* Run a matrix of implementation pairs
* Report pass, fail, and skip per test
* Record wire captures for failures
* Run in CI on release candidates

A second independent implementation SHOULD exist for interoperability testing.

---

# 11. Fuzzing

## 11.1 Mandatory targets

Fuzz targets MUST include:

```text
Varint decoder
Packet parser
Frame parser
Handshake parser
Identity binding parser
Route parser
Relay parser
Bundle parser
Carrier framing parser
Local control API parser
Plugin protocol parser
Database recovery logic
```

## 11.2 Corpus

The project MUST maintain a public fuzzing corpus containing:

```text
Empty packets
Truncated headers
Oversized connection IDs
Malformed varints
Non-canonical varints
Maximum legal values
Duplicate frames
Invalid frame contexts
Nested length inconsistencies
Huge ACK range counts
Conflicting stream final sizes
Invalid route hop limits
Oversized bundle declarations
Unknown critical frames
Unknown optional frames
Corrupted authentication tags
```

## 11.3 Operation

Fuzzing MUST:

* Run continuously in CI or dedicated infrastructure
* Restart on sanitizer failures
* Track crashes against the issue tracker
* Minimize and archive reproducers
* Cover both parsing and state-machine inputs

---

# 12. Simulation

## 12.1 Deterministic simulator

The project MUST include a deterministic simulator capable of modeling:

```text
Nodes
Links
Latency
Packet loss
Bandwidth
Partitions
Mobility
Carrier availability
Malicious peers
Sybil populations
Eclipse attempts
Route poisoning
Censorship filters
Active probing
Intermittent contact
```

## 12.2 Same state machines

The simulator SHOULD use the same protocol state machines as the production implementation where practical.

Deterministic simulation requires:

* Injected clocks
* Injected entropy
* Injected scheduling
* No wall-clock or network dependence

## 12.3 Simulation tests

Simulation tests cover:

* Large virtual networks
* Partition and heal cycles
* Route convergence
* Relay chains
* Bundle delivery after disconnection
* Censorship scenarios
* Resource pressure

---

# 13. Adversarial tests

The adversarial suite SHOULD include:

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
18. Release-signature and revocation exercise.
19. Clock rollback and forward jump.
20. Randomness-source failure injection.
21. Combined censor, Sybil, and malicious-relay attack.
22. Resource flood across handshake, stream, routing, relay, plugin, and local API boundaries.

Tests MUST verify both security outcome and resource bound.

---

# 14. Fault-injection tests

Fault injection covers:

* Packet loss, duplication, reordering, delay
* Carrier failure mid-session
* Plugin crash and restart
* Daemon crash at every persistence point
* Storage corruption and truncation
* Disk-full conditions
* Database write failures
* Timers firing late or early
* Cancellation races
* Clock jumps
* Randomness failure
* Migrations failing mid-way

Fault injection MUST be deterministic and repeatable.

---

# 15. Performance baselines

The project MUST maintain benchmarks for:

* Packet parse throughput
* Frame encode and decode
* Handshake completion
* Stream throughput
* Datagram throughput
* Relay forwarding
* Route discovery latency
* Database write latency
* Memory per session and per stream
* CPU per packet

Baselines:

* Are recorded per release
* Run on fixed hardware or containers
* Track regressions in CI
* Report p50, p95, and p99 where applicable

Performance tests MUST NOT replace correctness tests.

---

# 16. Long-running soak tests

Soak tests run for extended periods and verify:

```text
Memory leaks
Route churn
Key updates
Carrier reconnects
Database growth
Bundle expiration
Repeated process restart
Timer drift
Handle leaks
Quota accounting drift
```

Soak tests MUST:

* Run on a schedule or in dedicated infrastructure
* Report resource trends over time
* Fail on unbounded growth
* Cover at least one full key-update and migration cycle

---

# 17. Cross-platform requirements

## 17.1 Tier-1

Tier-1 platforms:

```text
Linux x86_64
macOS arm64
Windows x86_64
```

Tier-1 requires:

* CI runs on every change
* Integration tests run
* Local API integration maintained
* Release binaries published
* Security fixes supported

## 17.2 Tier-2

Tier-2 platforms:

```text
Linux aarch64
macOS x86_64
Windows arm64
FreeBSD x86_64
```

Tier-2 requires:

* Builds expected to work
* CI may be less comprehensive
* Fixes best-effort

---

# 18. CI requirements

CI MUST:

* Run on every change
* Run the full fast suite (unit, property, vector)
* Run integration tests on Tier-1 platforms
* Run fuzzing continuously
* Run interop on release candidates
* Fail on warnings in security-sensitive crates
* Verify reproducible builds where configured
* Publish coverage reports

CI MUST NOT:

* Possess the operator release-signing key
* Run unreviewed pull-request code with release secrets
* Gate security fixes on unrelated platform flakiness

---

# 19. Test tooling

The project SHOULD include:

```text
Packet generator
Protocol decoder
Network simulator
Fault injector
Carrier emulator
Interoperability runner
Fuzz targets
Benchmark suite
Adversarial node simulator
Test-vector generator
```

Test tooling MUST be deterministic and scriptable.

---

# 20. Coverage requirements

The project MUST track coverage:

* Line coverage for protocol-pure code
* Branch coverage for parsers
* State-transition coverage for state machines
* Fuzz-target coverage per parser

Coverage targets:

* Protocol-pure code: high line and branch coverage
* Parsers: fuzz coverage maintained per release
* Security-sensitive code: mandatory review of uncovered paths

Coverage reports MUST distinguish:

* Tested and passing
* Tested and skipped
* Untested

---

# 21. Security testing gates

Before production security claims, the project MUST complete:

1. Final wire and handshake vectors.
2. Independent cryptographic review.
3. Fuzzing of every network and local parser.
4. Enforced resource-limit profiles.
5. Local API permission tests.
6. Plugin process-isolation tests.
7. Storage corruption and rollback tests.
8. Dependency audit and SBOM.
9. Signed release-manifest workflow.
10. Published vulnerability-reporting process.
11. Documented residual risks and unsupported claims.

Local API permission coverage MUST include the Unix/named-pipe permission
boundary, peer-credential authentication before hello, bearer non-bypass of a
failed peer check, capability/resource intersection, empty-constraint
fail-closed behavior, administrative/application separation, and
principal-owned handles and event streams. The Unix v0.1 suite covers the
mode-`0600`/same-uid gate and the fail-closed transport-proof regressions;
named-pipe coverage remains a platform-specific follow-up when that daemon
transport is implemented.

The final handshake design SHOULD be modeled using a formal protocol-analysis tool before v1.0:

* Symbolic protocol verification
* State-machine model checking
* Transcript consistency testing
* Cryptographic composition review

---

# 22. Test data and corpora

The project MUST maintain:

* Versioned test-vector files
* Fuzz corpus with seeds
* Reproducers for all fixed bugs
* Simulation scenario files
* Benchmark definitions

Test data MUST NOT contain:

* Real private keys
* Real user data
* Unredacted addresses of actual deployments

---

# 23. Module test requirements

Each module specification defines its own required tests:

| Module | Required tests |
| --- | --- |
| Wire format | Parser, vectors, fuzz corpus |
| Handshake | State machine, vectors, formal analysis |
| Session | State machine, property, restart |
| Routing | Request/response, loops, cache |
| Relay | Circuits, quotas, failure |
| Carrier API | Lifecycle, ownership, MTU |
| Plugin API | Framing, handles, crash |
| Discovery | Candidates, sharing, enumeration |
| Bundles | Dedup, custody, eviction |
| Congestion | RTT, loss, pacing |
| Storage | Migrations, corruption, restore |
| Identity and trust | Rotation, revocation, TOFU |
| Resource limits | Pressure, eviction, budgets |
| Control API | Auth, handles, events |
| SDK | Backend equivalence, cancellation |
| Compatibility | Downgrade, negotiation, versions |

A module MUST NOT claim completion without its required tests passing.

---

# 24. Open design decisions

The project must resolve:

1. Coverage targets per module.
2. Soak-test duration and schedule.
3. Benchmark hardware baseline.
4. Whether a second independent implementation is in-repo or external.
5. Interop matrix scope per release.
6. Fuzzing infrastructure budget.
7. Formal-analysis tool selection.
8. Whether simulation shares crates with production.
9. Reproducer archiving policy.
10. Adversarial-suite release cadence.

---

# 25. Recommended implementation order

Implement testing in this order:

1. Test framework and CI skeleton.
2. Unit tests for protocol-pure code.
3. Test vectors for wire format.
4. Fuzz targets for parsers.
5. Property-test harness.
6. State-machine tests.
7. Integration tests.
8. Fault-injection harness.
9. Deterministic simulator.
10. Interop runner.
11. Adversarial suite.
12. Benchmarks.
13. Soak tests.
14. Coverage enforcement.
15. Formal-analysis integration.

---

# 26. Core rule

UMC is tested at every level: units, state machines, properties, vectors, interoperability, fuzzing, simulation, adversarial scenarios, faults, performance, and long-run stability.

Protocol-pure logic is deterministic and runtime-independent so simulation shares its state machines. Every parser is fuzzed, every invariant is property-tested, every vector is public and versioned, and no module claims completion until its required tests pass. Security claims require the documented gates, and CI enforces the matrix on Tier-1 platforms continuously.
