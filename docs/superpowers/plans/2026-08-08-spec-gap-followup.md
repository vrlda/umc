# Spec-gap follow-up plan

**Audit date:** 2026-08-09  
**Scope:** every file under `spec/` and `spec/carriers/`, plus the A–K
gap-closure status in [`docs/PHASES.md`](../../PHASES.md).

The current checkout has a strong protocol-pure and test foundation, but it is
not yet a compliant production v0.1 implementation. The items below are the
remaining work after the J3 matrix, bounded simulator soak, privacy recording,
page-token authentication, control rate limiting, and F4 fixes landed.

The latest verification after the application-data-plane, transport,
carrier-instance resource, listener-close, SDK-deadline, embedded-import,
PSK-admission, event-retention, Phase-14 conformance, deterministic-XX
binding, and profile-enforcement slices is recorded with the current gate run
(`1163` passed, `1` ignored across `83` suites). Criterion benchmark
harnesses, an ignored, duration-configurable two-node stream/datagram soak,
the bounded Phase-14 state/property/fault package, and structured
resource-trend artifacts are now present; clean-tree artifact retention and
the Tier-1 Linux-aarch64 result remain release evidence. The release gate remains
`rtk cargo clippy --workspace --all-targets -- -D warnings`, `rtk cargo fmt
--all --check`, and `rtk git diff --check`.

## Priority 0 — release and local-API blockers

1. **Complete Control API authentication and authorization** (`control-api.md`
   §§6–15, 48; `storage.md` §§8, 10). A first slice now maps live methods to
   capabilities, rejects invalid/under-granted bearer requests, rejects
   non-delegable scope expansion, and reports bearer grants and limits plus
   unique instance/connection identifiers in `ServerHello`. The transport and
   EventService and implemented ApplicationService state machines now live in
   `umcd` modules rather than the service dispatcher. Live requests now also
   enforce mapped capabilities, explicit resource constraints, principal- and
   connection-owned application handles, and cross-principal token-admin
   boundaries. Secret identity export/import now uses an authenticated
   Argon2id/ChaCha20-Poly1305 passphrase envelope, requires explicit operator
   confirmation, emits audit events, and rejects legacy raw seed material;
   recipient-key and OS-keychain protection now use authenticated X25519 and
   native credential-store adapters. Finish the real
   connection state machine and enforce every request against the current
   grant, resource constraints,
   ownership, expiry, and revocation. Hashed token metadata, expiry, effective
   grants, and revocation now persist across daemon restarts; negative tests
   cover cross-principal list/revoke/delegate operations. The bounded hello
   negotiation is now wired: only
   implemented, explicitly requested features are returned in client order
   with duplicates removed, malformed metadata is rejected, and the live
   decoder/encoder switches to the negotiated envelope limit after hello.
   Zero requests retain the 4 MiB default; limits below 1 KiB are rejected.
   Live request dispatch now also rejects ordinary payloads above 1 MiB and
   malformed non-empty idempotency keys (outside 16–64 bytes) before rate,
   authorization, or service mutation. The bounded replay cache fingerprints
   payload bytes for 24 hours, returns `IDEMPOTENCY_CONFLICT` on key reuse with
   different bytes, and re-checks current authorization before replay. Accepted
   deadlines are converted once to the daemon monotonic clock and capped by
   operation class; the SDK emits a best-effort `Cancel` when its deadline wait
   expires. Live connections now maintain an authenticated in-flight table,
   process cancellation concurrently with request workers, reject request-ID
   collisions, and interrupt safe outbound connects before commit. Unknown
   cancellation IDs remain no-ops and committed mutations are never rolled
   back. Replay
   state is now daemon-runtime scoped and principal-bound across reconnects;
   encrypted API-namespace persistence protects cached responses across daemon
   restarts, and replays rebind the current request ID so correlation remains
   correct after reconnect.
2. **Finish stable local services** (`control-api.md` §§26–35, 52). The
   CarrierService instance registry now covers List/Get/Create/Update/Start/
   Stop/Delete with opaque handles, optimistic revisions, redacted options,
   and lifecycle events. Application listener handles now have explicit
   open/close ownership state and cleanup. Session lifecycle now waits for
   both reader and writer tasks before removing a live session-bus entry.
   The bounded ApplicationService data plane now covers pending-session
   queues, session ownership, streams, datagrams, cancellation-safe cleanup,
   bounded chunks, generation checks, and authenticated static-peer outbound
   Connect; CloseLink and session shutdown release live transports. Carrier
   instances with a public `bind_address`/`address`/`listen` option now acquire
   and release concrete listener resources through Start/Stop, and stop can
   close their links; metadata-only instances remain explicit for
   discovery/plugin profiles. Add a generic CarrierService Dial RPC only where
   a versioned API surface defines it. Keep unsupported experimental methods
   explicitly `UNIMPLEMENTED`.
3. **Make the SDK contract real** (`sdk.md` §§5–19, 32). The daemon backend
   now exposes endpoint/application/listener/session/stream/datagram handles,
   local generation validation, bounded chunking, and deadline-bearing
   Connect. An explicit embedded backend now owns core identity/runtime state
   and provides loopback endpoint/application/stream/datagram semantics with a
   backend-equivalence regression. Both backends now expose typed event filters,
   subscription handles, bounded event delivery, acknowledgements, and
   deadline-aware next-event waits; daemon request dispatch now rejects
   malformed or already-expired deadlines before side effects, and delivery
   keeps unacknowledged sequence/byte metadata charged against the bounded
   subscription budget.
   Persistent embedded identity/trust storage, accept/reject parity, typed
   delivery/path/session events, including daemon migration notifications, and
   deadline-aware embedded waits are now covered. Embedded stream/datagram
   frames now pass through a bounded carrier `Link`; accepted bytes that are
   abandoned by a terminal link produce typed loss events. Remaining SDK parity
   is full equivalence beyond this bounded adapter, dynamic carrier migration,
   and broader live data-plane coverage. The
   daemon decoder now preserves coalesced envelopes and retains
   responses/events that arrive interleaved; retain those regression tests.
4. **Close security-process gates** (`security-operations.md` §§9–21,
   `threat-model.md` §48). Replace `TBD-contact`, publish supported-release
   and advisory channels, run the reporting/revocation/key-rotation drills,
   and obtain the seven independent reviews before making production-security
   claims.
5. **Finish the release test gate** (`testing.md` §§9–21). Criterion
   baselines, the 10-minute continuous two-node stream/datagram soak with
   structured resource trends, and published fuzz/resource reports are now
   implemented; public interop vectors and a second implementation, hosted
   coverage thresholds, and the Linux-aarch64 Tier-1 result remain separate
   release evidence.

## Priority 1 — protocol/runtime completeness

6. **Handshake and wire conformance** (`handshake.md` §§5, 18–24, 35;
   `wire-format.md` §§13, 18, 20–22). Protected XX `CLIENT_AUTH`/`SERVER_FINISHED`/
   `CLIENT_FINISHED` continuation is now live, and an opt-in stateless Retry
   gate (`require_retry`) issues authenticated, single-use tokens with a
   transcript context and live two-process coverage. Short-header traffic now
   uses the spec-labelled sample-based header-protection construction with
   live-session coverage. Unknown critical frame types now fail closed while
   unknown optional length-delimited extensions are bounded and skipped. PSK-
   XX offers are now matched against active invitation keys before responder
   state allocation, and both responder and client continuation helpers use
   the invitation-bound first extract. Initial and Handshake parsers now
   reject the retired pre-header-protection layouts, leaving one authenticated
   encrypted long-header dialect. The daemon also rejects Initial DCIDs that do
   not match its fixed eight-byte session demultiplexer. Finish private-mode
   policy selection, align long-header/Retry construction with the final wire
   profile, and publish
   independent handshake/wire vectors. Keep 0-RTT explicitly deferred until
   its anti-replay policy is implemented.
7. **Routing, relay, and privacy paths** (`routing.md` §§13, 23, 27;
   `relay.md` §§27–29; `privacy.md` §§41–58). A bounded path-construction
   layer now enforces path exclusions, loop prevention, scope narrowing,
   hop/relay/byte caps, and explicit failure-domain diversity before session
   or relay handoff. Wire multi-hop route-request forwarding, reverse state,
   rendezvous/introduction points, and relay authorization into live sessions.
   Enforce P2 route selection end to end; add P3 timing/cover-traffic policy
   and diagnostics.
   The live probe/cache boundary now binds responses to the originating
   destination and scope, while P2/P3 now reject direct Connect attempts and
   direct route claims before cache insertion. This still does not complete
   multi-hop topology, relay-backed session handoff, rendezvous, or end-to-end
   P2 route selection.
8. **Trust and persistence hardening** (`identity-trust.md` §§13–24;
   `storage.md` §§9, 20–27). A bounded external restore-generation anchor now
   persists the highest observed generation, cross-checks a native OS-keychain
   generation when available, and emits a startup warning/audit event on
   mismatch; hardware monotonic anchoring and restore campaigns remain open.
   Revocation records now expose an explicit
   `Unknown`/`Fresh`/`Stale` classification over a seven-day local window;
   the daemon emits a stale-state audit event and diagnostics gauge without
   pretending disconnected peers are synchronized. Introduction creation now
   requires the introducer to have active `Trusted` or scoped `Introduced`
   authority for the requested scope; bounded canonical signed introductions
   now verify issuer keys, evidence, scope, expiry, and monotonic sequence
   across restart. Self-authorized identity/binding revocations now use a
   canonical bounded statement and are enforced after restart; bounded
   delegation certificates now verify issuer binding, capability narrowing,
   nested expiry, and cycles. Recovery/delegation persistence and authority,
   and distributed propagation remain open. Complete the remaining
   introducer/delegation scope checks, bind/validate encrypted backups and
   objects,
   and run corruption/crash/restore campaigns. Persist grants, quotas, and
   abuse counters where restart resistance is required.
9. **Discovery and carrier interoperability** (`discovery.md` §§15, 24;
   `carrier-api.md`; `carriers/*.md`). Signed, bounded bootstrap bundles now
   have canonical encoding, issuer verification, candidate expiry checks,
   persistence wiring, and a distinct `SignedBootstrap` source/auth state.
   The provider interface now has restartable start/stop hooks, fallible
   collection, and a bounded `ProviderManager` with failure isolation,
   source-attribution checks, and explicit diversity reporting; configured
   static peers are registered and refreshed through it at daemon startup as
   local-only candidates. PEER_HINT exchange coverage and independent
   TCP/UDP/TLS interoperability tests remain; daemon TLS certificate/key/root
   and server-name provisioning is now explicit and fail-closed when any
   deployment material is configured. LAN discovery
   remains an intentional discovery-only profile until a separate carrier is
   specified.

## Priority 2 — explicitly deferred/experimental work

10. **Plugin boundary** (`carrier-plugin-api.md`, `docs/plugin-security.md`):
    signed manifests, dynamic loading, process isolation, crash/restart
    supervision, and per-plugin quotas. Do not advertise these capabilities
    while they remain deferred.
11. **Advanced privacy and storage backends** (`privacy.md` §77,
    `storage.md` §28): anonymous credentials/PSI/PIR/mix modes, encrypted
    whole-backup units, and alternative storage backends remain opt-in future
    work with explicit compatibility markings.

## Acceptance rule

Update [`docs/PHASES.md`](../../PHASES.md), `docs/PRIVACY.md`,
`docs/COMPATIBILITY.md`, and the threat assessment only when the corresponding
tests and evidence exist. No release documentation may describe an item as
stable while it returns `UNIMPLEMENTED`, uses a transitional wire path, lacks
capability enforcement, or has an open required security review.
