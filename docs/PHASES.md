# A–K implementation status

The phase plan that records the work is [`docs/superpowers/plans/2026-08-07-gap-closure.md`](superpowers/plans/2026-08-07-gap-closure.md). It is the clearest surviving record of the A–K sequence; the older `docs/superpowers/plans/phase*.md` files describe the original numbered phases.

This status is based on the code and tests in this checkout (2026-08-11), not on the checkboxes in the original plan:

Closure update (2026-08-11): the earlier H/K qualifications about full
multi-hop selection and route diversity are superseded for the UMP/1 bounded
profile. P2 relay construction now carries an opaque destination token,
resolves only the authenticated adjacent leg at each relay, stores only the
local adjacent path metadata, resolves the destination at the terminal hop,
and retries a bounded diverse route after failure. P3 keeps its negotiated
padding, jitter, identifier rotation, and optional budgeted cover controls.
Anonymous credentials, rendezvous, and global-passive anonymity remain separate
release qualifications.

| Phase | Status | Evidence / qualification |
| --- | --- | --- |
| A | Complete | Runtime session enforcement, timers, loss/PTO, flow control, amplification limits, and bundle eviction are wired. |
| B | Complete | Keystore identity persistence, peer/route/bundle/event persistence, and backup/restore are present. SQLite schema is v2. |
| C | Complete | Reno-style congestion control and pacing are part of the session send path. |
| D | Protected XX, independent compatibility, and solo implementation security review complete | Protected XX `CLIENT_AUTH`/`SERVER_FINISHED`/`CLIENT_FINISHED` continuation, version negotiation, key discard, and the opt-in stateless Retry path are exercised, including a live two-process Retry test. A shared handshake state machine now rejects invalid message/key transitions and exposes confirmation as the application-key gate. Initial and Handshake long-header packet numbers now use the same sample-based header-protection key as short-header traffic; retired pre-protection Initial and Handshake layouts fail closed. Short-header traffic now uses the spec-labelled sample-based header-protection construction with round-trip and live-session coverage. Session stream IDs now encode role/direction and inbound control handling covers flow updates, key updates, migration, and path challenge/response. The deterministic XX driver now carries a client-signed identity binding in `CLIENT_AUTH`, matching the live responder layout. PSK-XX now selects a matched, expiring invitation in the daemon admission path, consumes single-use invitations at the bounded gate, derives the PSK-bound first extract on both responder and client continuation helpers, and fails closed for unmatched PSK offers. Versioned independent identity/X25519/Initial/binding/protected-short-packet/Finished-MAC vectors plus an independent canonical XX transcript vector are published under `interop/vectors/` and checked by both Rust conformance tests and the independent Python `cryptography` verifier. The independent Python live peer now exercises refusal, authentication, stream/datagram data paths, and restart identity over TCP, UDP, and TLS-stream. The implementation security review is recorded in `docs/security-review-2026-08-11.md`; no human audit or formal proof is claimed under the solo-maintainer profile. |
| E | Complete | Metrics, redacted logging, health/status, and event surfaces are wired. |
| F | Core control/SDK surfaces and bounded application data plane implemented; backend breadth remains partial | F4’s multi-protocol unregister cleanup is in `8431eb6`; dead session-bus receivers are cleaned by the watcher in `05a79a4`, and the session lifecycle coordinator now keeps the bus entry alive until the reader and writer actually terminate. Framing, sequencing, principal-scoped idempotency across reconnects and encrypted daemon restarts, pagination, page-token authentication, local-socket permissions, rate limits, config writes, typed daemon helpers, and connection/server identifiers are covered. Live bearer requests require mapped capabilities, exact token inspection authorization, fail-closed endpoint/resource checks, principal-owned application handles that expire with their connection, and bounded cross-principal token administration; delegated grants cannot expand an issuer scope, and `ServerHello` reports grants and limits. Transport/connection state is isolated in `bins/umcd/src/control_transport.rs`, EventService delivery/acknowledgement in `bins/umcd/src/control_events.rs`, the ApplicationService registry/listener lifecycle and bounded stream/datagram queues in `bins/umcd/src/control_application.rs` and `bins/umcd/src/application_data.rs`, and the CarrierService instance registry/lifecycle surface in `bins/umcd/src/control_carriers.rs` while the daemon remains one composition root. Application Connect now resolves authenticated configured static-peer hints, completes a live outbound handshake, registers the transport with the session coordinator, and returns an owned session handle; stream open/read/write/FIN/reset/stop, datagram send/receive, listener/session ownership, CloseLink, shutdown cleanup, and SDK chunk/generation checks are covered. `RouteService.ProbeRoute` now fans out bounded, policy-filtered route requests over live session-bus peers and retains reverse state for responses. Real TCP/UDP carrier dial/listen paths avoid nested runtime blocking and UDP preserves the first handshake datagram. The SDK now has an explicit in-process backend with core-owned identity/runtime state, passphrase-, recipient-key-, and OS-keychain-protected identity import/export adapters, persistent encrypted embedded identity/trust storage, bounded carrier-backed stream/datagram transport through the `Link` contract, terminal-link loss events, accept/reject parity, and typed delivery/path/session event/deadline behavior; daemon and embedded handle generations are validated through the same typed API. Carrier instances with a public `bind_address`/`address`/`listen` option now own concrete listener resources through Start/Stop, and stop can close their links; metadata-only instances remain explicit for discovery/plugin profiles. The hello path validates bounded client metadata, negotiates the intersection of implemented feature identifiers in client order with unknown features omitted, and applies the requested envelope limit (zero uses the 4 MiB default, valid smaller limits are honored, and limits below 1 KiB are rejected). Live dispatch also rejects ordinary request payloads above 1 MiB and non-empty idempotency keys outside 16–64 bytes. Hashed bearer-token metadata, expiry, effective grants, and revocation now persist across daemon restarts. Secret identity export/import requires explicit `EXPORT` confirmation, rejects raw seed transport, audits successful operations, and now supports authenticated X25519 recipient envelopes plus native platform keychain wrapping. Logical carrier-instance creation, generic CarrierService Dial, concrete listener ownership, and established-session carrier migration are implemented for daemon and embedded backends; broader backend equivalence beyond the bounded transport contract remains a documented compatibility boundary. |
| G | Complete with trust-freshness qualification | Trust states, revocation/TOFU, emergency disablement, release-manifest tooling, and the threat-model assessment are present. Revocation evidence now reports `Unknown`/`Fresh`/`Stale` over a bounded local window, with stale-state audit/diagnostics. Introduction edges fail closed unless the introducer has active trusted/scoped authority for the requested scope, signed introductions use bounded canonical Ed25519 statements with restart-time signature verification and scope/expiry enforcement, self-authorized identity/binding revocations are persisted and enforced, and bounded canonical delegation chains verify issuer binding, capability narrowing, expiry nesting, and cycle limits. Delegation chains now persist with root authority and re-verify across restart, reject malformed/rolled-back rows, and omit expired records. Recovery authority is now root-signed, class-scoped, sequence-bound, persisted and restart-verified; recovery revocations and bounded signed revocation batches are authenticated before atomic import and enforced during binding admission. The external restore-generation file is cross-checked with a native OS-keychain generation when available; platform monotonic-anchor evidence is tracked with the platform work item. |
| H | Complete with compatibility notes | Live route forwarding, relay authorization, custody/chunked bundles, sealed envelopes, peer hints, static peers, invitations, and signed bounded bootstrap-bundle admission are implemented. Bootstrap signatures authenticate the source, not endpoint identity. The discovery provider interface now exposes restartable start/stop and fallible collection hooks; `ProviderManager` isolates provider failures, rejects source-attribution mismatches, enforces per-provider candidate bounds, and reports source diversity. Configured static peers are registered and refreshed through that manager at daemon startup as local-only candidates, while authenticated static dialing remains the session path. A bounded multi-hop path-construction layer now enforces exclusions, loop prevention, scope narrowing, hop/relay/byte caps, and opt-in failure-domain diversity before session/relay handoff; route responses now carry canonical bounded path metadata, reverse forwarders prepend their local leg, and every learned candidate is validated against the originating hop/relay policy before cache insertion. ProbeRoute now applies the same hard hop/relay/scope/privacy checks to cached candidates and fails closed when a caller's carrier allow-list has no authenticated carrier evidence. Direct matches identify the destination peer as the next hop, and carrier/trust/hop hard constraints fail closed when evidence is absent. Relay forwarding now preserves FIN/ACK-request/priority flags, translates peer-scoped wire circuit IDs to local circuit state, pairs reciprocal legs explicitly so concurrent circuits cannot cross-deliver, enforces upstream half-close state, authenticates close ownership, propagates paired-leg close notifications, closes both local legs on either-leg shutdown, and closes the upstream leg with `DOWNSTREAM_FAILED` instead of silently dropping data when its destination disappears, while queue accounting aggregates per-peer usage across circuit IDs under the 2 MiB peer cap. Relay lifetime and idle deadlines are now swept from the live session timer; paired legs emit peer-scoped `RELAY_CLOSE` notifications, drain through CLOSING/DRAINING, and purge bounded state. `RELAY_STATUS` now emits the defined `AUTH_FAILED` and retryable `RESOURCE_LIMIT` codes, inbound status sequences are idempotently replay-checked instead of ignored, and peer-scoped `RELAY_OPEN` duplicates replay their stable status without allocating a second circuit while conflicting bodies are rejected before allocation; invalid authorization is rejected before allocation, and rejected first data cannot activate an opening circuit. One-hop relay-backed application-session handoff is implemented under an explicit P2 relay route policy; bounded multi-hop route selection/hop negotiation is implemented, and independent TCP/UDP/TLS carrier interoperability is exercised by the live Python peer; daemon TLS certificate/key/root/server-name provisioning is explicit and fail-closed when configured. Empty relay authorization remains accepted for legacy phase-12 fixtures; peer-hint exchange is triggered by session traffic rather than a standalone timer. |
| I | Implemented, experimental pieces | TLS-stream (varint framing), carrier registry, PSK-XX derivation, Sybil-group admission, Python stdlib bindings, and the experimental C ABI are present. TLS uses an ephemeral self-signed certificate only when no deployment material is configured; `tls_certificate`, `tls_private_key`, `tls_trust_roots`, and `tls_server_name` provide explicit DER trust provisioning for independent daemons. The independent live peer covers all three built-in carrier profiles; TLS remains experimental pending independent carrier/security review. The v0.1 profile does not advertise external carrier processes; the trusted plugin registry now enforces strict capabilities and generation-scoped message/request/handle/shared-memory/log/property/restart limits with crash cleanup and disablement. |

F closure update: established-session carrier migration is now implemented in
the daemon and embedded SDK. `SessionService.MigrateSession` attaches a
protected candidate path, validates it with PATH_CHALLENGE/PATH_RESPONSE,
sends monotonic MIGRATE on the old path, and preserves one application session
handle while switching carriers.

| J | J1/J2/J3 implemented; J4/J5/J6 release harnesses implemented | All 12 stable fuzz targets have seed corpora, bounded parser/recovery inputs, and a smoke/nightly workflow; `scripts/fuzz-report.sh` emits per-target corpus, RSS, progress, and digest evidence. `tests/phase13/tests/adversarial_matrix.rs` covers 22 bounded hostile-input scenarios, and `tests/phase14` adds state-machine, property, duplicate/replay, and truncation conformance checks. `umc-simulation` runs both a 256-message deterministic fault soak and an ignored, duration-configurable two-node stream/datagram soak (`UMC_SOAK_DURATION_MS`, ten-minute default). Criterion benches now cover wire varints/packet parsing, crypto seal/open, and session send/receive paths. CI emits a locked Cargo metadata SBOM on every run, has a scheduled/manual LLVM coverage gate for the protocol crates, retains optional Tier-2 Linux aarch64 platform evidence tooling, and packages benchmark/soak logs, resource summaries, committed-tree ids, and digests through `scripts/release-baseline.sh`; the clean-tree preflight and `scripts/verify-release-baseline.sh` reject dirty or tampered evidence before CI retention. |
| K | K1–K8 bounded core mechanisms implemented | Privacy profiles are ordered and fail-safe by default (`p0`); a local policy may raise the effective profile and GetStatus/GetConfig expose the configured surface. ClientHello binds a requested minimum into the capabilities hash and UMP/1 now negotiates through P3. Each registered session records negotiated profile/direct-path/padding state; P3 forces fixed 1,024-byte application padding, applies bounded configurable send jitter, rotates privacy identifiers on a session-preserving schedule, and optionally emits authenticated cover packets under a per-session byte budget. Control candidate enumeration has a per-principal budget, optional local-mesh hints use per-entry HMAC-BLAKE2s membership tags, `umc-relay` builds/opens authenticated one-layer-at-a-time route envelopes, the routing path builder enforces bounded exclusions/scope/diversity before handoff, cached route selection prefers independent authenticated failure domains and keeps bounded failover alternatives, ProbeRoute filters cached candidates by hard path/privacy policy before returning them, P2/P3 outbound Connect and cached direct route claims fail closed with explicit policy events, direct static Connect honors a caller carrier allow-list, bounded one-hop and chained multi-hop P2 Connect negotiates fresh downstream circuit IDs and gates data on acceptance, and sessions reject direct paths for negotiated P2+. Anonymous credentials, rendezvous/replica privacy, and global-passive anonymity remain explicitly outside the bounded UMP/1 profile rather than advertised capabilities. |

The H/K row wording above is retained as historical phase-plan context. The
2026-08-11 closure update supersedes its multi-hop and route-diversity
qualification for the bounded UMP/1 profile; only the separately listed
extensions and release gates remain open.

Multi-hop update (2026-08-10): the H/K qualifications above predate the bounded
relay-chain implementation. Each relay now selects a live adjacent next hop from
validated canonical route metadata, allocates a fresh peer-scoped downstream
Circuit ID, sends a nested `RELAY_OPEN`, remaps downstream `RELAY_STATUS` back to
the upstream wire scope, and queues accepted `RELAY_DATA` until downstream
`ACCEPTED`. One-hop and chained two-relay negotiation/data/status paths are
covered by daemon tests. Full global topology discovery, unrestricted
multipath/store-forward, and anonymous network authorization remain intentionally
outside the bounded profile; topology-aware replacement and bounded multipath
candidate selection are implemented. The 2026-08-11 independent Python peer now covers the live TCP, UDP, and
TLS-stream carrier gate. P3 traffic defenses are now live but cover traffic
stays optional and locally budgeted.

Routing integration note: live probe responses now retain the originating
destination/scope and hop/relay policy before cache insertion; canonical path
metadata is propagated over reverse branches and validated by the bounded path
builder, and `GetRoute` searches all scopes. Scope defaults use the protocol
hop budgets and exhausted branches return `ROUTE_EXPIRED` instead of claiming
direct reachability. `ProbeRoute` applies the same hard path/privacy checks to
cached candidates and rejects carrier-constrained candidates when the route
evidence does not authenticate a carrier class. One-hop relay-backed
application-session handoff is implemented for P2 under an explicit relay
route policy; it requires a usable cached canonical path and live authenticated
next-hop session, failing closed when either is absent. Bounded multi-hop
selection, topology-aware replacement, and independent carrier interoperability
are now covered; a global topology database remains intentionally absent.
Cached route records now
retain the authenticated next-hop hint (binary endpoint ids are represented as
reversible lowercase hex labels) instead of an internal session number.

The multi-hop extension now consumes that authenticated next-hop hint at every
relay boundary. Bounded route selection, hop extension, status propagation,
admission-gated data forwarding, and independent carrier interoperability are
implemented and tested; a global topology database remains a separate
extension rather than a v0.1 requirement.

The latest F SDK slice also adds typed `EventFilter`, `Event`, and
`SubscriptionHandle` APIs over both backends. Daemon responses and unsolicited
event envelopes are retained separately when they arrive interleaved; the
embedded backend applies the same filter, sequence, bounded-backlog, and
acknowledgement rules to its local lifecycle events. Event delivery now keeps
transported sequence/byte metadata charged until a contiguous acknowledgement,
so an unacknowledged client cannot silently reset the backlog budget. Both
backends map acknowledged/reset/cancelled delivery outcomes and the complete
typed path-event vocabulary; embedded connect emits stable path-added and
path-validated events without changing the session handle, and embedded event
waits honor future deadlines. Opt-in persistent embedded construction now restores
the encrypted node/endpoint keystore and SQLite trust state, and embedded
accept/reject operations have the same ownership/error behavior as the daemon.
Embedded stream/datagram delivery now runs through a bounded carrier `Link`,
with caller-supplied carriers supported by `Client::embedded_with_carrier` and
terminal accepted-byte loss reported as typed `LOST` events. Embedded carrier
type/instance/link lifecycle operations now have the same bounded request shape
as the daemon; link quality, rebound, retirement, and terminal failure map to
the SDK's typed path/session events. Stream and datagram waits now return
`DEADLINE_EXCEEDED` at the requested operation deadline and are cancellation-safe
when their futures are dropped. Logical carrier-instance creation and generic
outbound CarrierService Dial now have daemon/embedded parity, including owned
raw-link cleanup. Authenticated migration of an established session remains
separate carrier/topology work.
The F summary row's older “full backend equivalence” wording now refers only
to that migration capability; the stable bounded embedded/daemon SDK and
carrier/link lifecycle are covered by parity tests. Daemon control deadlines
also bound synchronous carrier Dial/Listen calls and outbound static-peer
handshake dialing; carrier workers are detached only after the response boundary
when an uncooperative third-party implementation cannot be force-stopped.
Daemon request deadlines are converted once to the monotonic node clock and capped at 30
seconds for reads or 60 seconds for mutations/dial/route probes; SDK deadline
expiry emits a best-effort `Cancel`. Live control connections now dispatch
requests through a bounded authenticated in-flight table, process cancellation
while another request is running, reject request-ID collisions, and interrupt
safe outbound connects before commit. The common dispatch boundary checks
cancellation and the receipt-time monotonic deadline before admission,
authorization, and service work, then applies a post-dispatch result check
without replacing a committed `OK`. Unknown cancellation IDs remain a
no-op, and cancellation cannot roll back a committed mutation. Operation-specific
deadline policies are now enforced for embedded stream, datagram, and event
waits; established-session carrier migration is implemented with bounded path
validation and one-handle continuity.

Daemon control dispatch now rejects zero request IDs plus malformed or
already-expired request deadlines before authorization, rate accounting, or
service mutation; accepted deadlines use receipt-time monotonic conversion
and operation-class caps. The SDK sends a cancellation envelope when its
bounded wait expires. Unknown cancellation IDs are ignored to prevent request
ID poisoning. Synchronous service methods retain a committed `OK` result when
cancellation races after completion; long-running operation-specific waits
remain individually responsible for finer-grained interruption.

The daemon SDK also bounds its response wait from the same absolute deadline,
returning `DeadlineExceeded` locally when the peer does not answer in time.
Its pending response, event, and decoded-envelope queues are capped and return
`ResourceExhausted` instead of growing without bound.

The workspace’s authoritative verification commands are:

```text
rtk cargo fmt --all
rtk cargo clippy --workspace --all-targets -- -D warnings
rtk cargo test --workspace --all-targets
```

The phase integration packages (`phase1-tests` through `phase9-tests`, `phase12-tests`, and `phase13-tests`) pass independently. The monolithic `cargo test --workspace` command includes the 211-test `umcd` binary suite and can run for several minutes; run it separately when doing a release gate.

Final H/K closure note (2026-08-11): the bounded UMP/1 multi-hop/P2/P3 gap is
closed. The live path uses opaque destination tokens, relay-local adjacent
metadata, terminal-only destination resolution, fresh downstream circuit
identifiers, acceptance-gated forwarding, bounded diverse-route selection,
and failure failover. The remaining items named above are deliberately
separate protocol extensions or independent release gates, not missing pieces
of the bounded core path.

Carrier closure note (2026-08-11): daemon and embedded CarrierService now
support logical per-instance create/update/start/stop/delete, versioned `Dial`,
owned raw outbound link handles with ListLinks/CloseLink cleanup, and
authenticated migration of an established session between carrier links;
raw-link dialing is complete and tracked separately. This note supersedes the
older F-row tail that listed dynamic factories, generic Dial, and migration as
open.

Security-operations closure note (2026-08-11): `scripts/security-operations-drill.sh`
passes all ten required v0.1 exercises and emits hashed evidence for report
intake, embargo, advisory, revocation, key rotation, dependency response,
crypto deprecation, emergency disablement, containment, and postmortem
tracking. The repository now directs reports to GitHub private vulnerability
reporting and uses a single operator signing key; enabling the GitHub setting
and protecting that key remain release-owner setup actions. No council is
assumed.

Carrier/plugin closure note (2026-08-11): the bounded v0.1 carrier/plugin gap
is closed. Built-in carrier framing remains bounded; `umc-plugin` now owns a
generation-scoped supervisor that rejects work before quota growth, clears all
permits, handles, and shared-memory reservations on failure, applies capped
exponential restart backoff, enforces startup/heartbeat deadlines, and
disables repeated crashes. Registry init and shutdown use the same lifecycle
contract. External subprocess IPC and
platform sandboxing are deliberately not advertised in v0.1; a future loader
must adopt this supervisor contract before it is enabled.

Dependency-evidence closure note (2026-08-11): the locked SBOM/RustSec audit
now rejects dirty trees, records the committed tree and exact Cargo.lock
digest, and copies the audited lockfile beside its evidence. The companion
verifier re-parses the SBOM and advisory JSON and rejects missing, tampered, or
vulnerable evidence before CI retention. Comparing retained reports across
releases remains an operator workflow, not a repository implementation gap.

Fuzz-evidence closure note (2026-08-11): the twelve-target corpus smoke
harness now rejects dirty trees, records the committed tree, and has a
companion verifier for target coverage, progress markers, resource logs,
corpus inventories, and artifact digests before CI upload. Nightly ten-minute
campaigns remain unchanged.
