# Compatibility and release matrix

This document turns `spec/compatibility.md` into the v0.1 implementation
matrix. Experimental entries are deliberately outside the stable commitment.

| Surface | v0.1 state | Compatibility promise |
| --- | --- | --- |
| UMP wire protocol | `UMP/1` | Stable protocol version; authenticated negotiation rejects unsupported versions. |
| Local Control API | `1.0` | Protobuf additive evolution within major version 1; bounded idempotency is principal-scoped across reconnects and encrypted in the daemon API store across restarts. |
| Rust SDK | `umc-sdk 0.1` | Stable typed daemon client plus an explicit in-process backend; endpoint/application/data-plane handles, persistent encrypted embedded identity/trust storage (via `Client::embedded_with_storage`), bounded event subscriptions, typed delivery/path/session events, accept/reject operations, deadline-bearing waits, and established-session carrier migration are implemented. Embedded stream/datagram delivery uses bounded carrier links, caller-supplied carriers are accepted through `Client::embedded_with_carrier`, terminal accepted-byte loss is surfaced as `LOST`, and carrier type/instance/link lifecycle operations—including logical instance creation, raw outbound `Dial`, and `SessionService.MigrateSession`—are available through the same typed request boundary. Migration keeps one session handle, validates the candidate path, and switches the primary carrier without repeating identity handshake. |
| Python binding | stdlib client in `bindings/python` | Stable local daemon client; the handwritten protobuf subset follows `api/umc.proto`. |
| C ABI | `umc-sdk-c 0.1` | Experimental; ABI may change before a stable release. |
| TCP / UDP / LAN discovery | `ump.tcp/1`, `ump.udp/1`, `ump.lan-discovery/1` | Stable carrier profiles. |
| TLS stream | `ump.tls-stream/1` | Experimental; daemon config can provision DER certificate/key/trust-root paths and a server name, while absent material retains the ephemeral localhost development certificate. The independent live runner covers framing, refusal, XX authentication, and data exchange; TLS security review remains required before promotion. |
| Storage metadata | SQLite schema v2; protected keystore v3 (v2 migrates once at open) | Backups carry node identity, storage generation, and BLAKE2s-256 file hashes; restore accepts v2/v3 keystores only after hostile-path, hash, schema, identity, and generation validation. |
| Tier-1 platform evidence | Native macOS arm64 coverage plus the Linux x86_64/Windows x86_64 CI matrix | Each release retains locked workspace-test, release-build, toolchain, lockfile, commit, and binary-digest evidence for Tier-1 targets; Linux aarch64 evidence is optional Tier-2 portability evidence. |
| Secret identity export/import | Authenticated envelope v1 | Requires local opt-in and `EXPORT` confirmation. Passphrase (Argon2id/ChaCha20-Poly1305), X25519 recipient-key, and native OS-keychain wrapping are supported; raw seeds are rejected. |
| Application registration/listeners | Control API v1 registry and bounded data-plane surface | Registration, principal/connection ownership, listener open/close, static-peer Connect, session/stream/datagram operations, generation checks, CloseLink, cleanup, typed bounded event subscriptions, and established-session carrier migration are implemented for the daemon backend; carrier instances with public bind options acquire/release concrete listeners through Start/Stop, and running instances own raw outbound links returned by `CarrierService.Dial`. The embedded backend additionally restores encrypted endpoint/trust storage, exposes carrier type/instance/link lifecycle state, creates logical carrier instances, routes stream/datagram frames through bounded carrier links, supports accept/reject, translates link transitions into the typed path/session vocabulary, reports terminal accepted-byte loss, enforces matching operation deadlines, and migrates an existing session across carrier paths without changing its handle. |
| Bundles | UMP bundle frames and custody | Experimental store-and-forward behavior; large-transfer and envelope details may evolve. |
| Signed bootstrap bundles | `UMP-BOOTSTRAP-v1` | Bounded issuer-signed candidate bundles are accepted as discovery candidates; endpoint identity still requires a handshake. Provider lifecycle hooks and the bounded `ProviderManager` (failure isolation, source-attribution checks, and diversity reporting) are available; configured static peers are registered through it at daemon startup, while other provider/carrier interoperability remains experimental. |
| Signed introductions | `UMP-INTRODUCTION-v1` | Bounded canonical Ed25519 statements support scoped, expiring introductions with binding/static-key evidence, sequence checks, and restart-time signature verification. Delegation chains and distributed revocation propagation remain outside the stable commitment. |
| Signed revocations | `UMP-REVOCATION-v1` | Canonical self-authorized identity/binding revocations are validated, sequence-bounded, persisted, and enforced locally. Recovery/delegation authority and authenticated distribution remain outside the stable commitment. |
| Signed delegations | `UMP-DELEGATION-v1` | Bounded canonical Ed25519 delegation certificates and chains verify issuer binding, capability narrowing, expiry nesting, cycle prevention, aggregate size limits, and persisted restart-time revalidation with leaf sequence rollback rejection. Recovery authority and authenticated distribution remain outside the stable commitment. |

The daemon's `require_retry` configuration opt-in enables the protected XX
stateless Retry gate. It is disabled by default; enabling it requires a
protected Initial packet. Short-header traffic uses the sample-based
header-protection construction, and PSK-XX offers are matched against the
live invitation store and derive the same context-bound first extract on the
responder and client continuation helpers. Unmatched PSK offers fail closed;
private-mode policy selection remains open. Versioned independent
identity/Initial/X25519, canonical XX transcript, and Finished HMAC-BLAKE2s
vectors are published under `interop/vectors/` and checked by both the Rust
handshake suite and the independent Python `cryptography` verifier. The retired
pre-header-protection Initial and Handshake layouts are rejected.

There is intentionally no raw-Initial compatibility mode. A raw hello is not
an Initial packet under `wire-format.md` §13 and would create an unauthenticated
second dialect; legacy harnesses must migrate to the protected builder. The
rejection is covered by `legacy_unprotected_initial_layout_is_rejected`.

The runtime-independent handshake state machine is shared by daemon and
embedded drivers. It rejects invalid message ordering and does not permit
application traffic keys before the `CONFIRMED` state; this is an internal
conformance guard and does not change the wire version.

Control API hello negotiation returns only explicitly requested, implemented
features (`control.events-v1`, `control.idempotency-v1`, and
`control.page-tokens-v1`), preserving first-request order and omitting unknown
or deferred names. A zero requested envelope size selects the daemon's 4 MiB
default; valid smaller requests are enforced after hello, with 1 KiB as the
implementation floor.

Closure update (2026-08-11): bounded P2 multi-hop is now implemented with
opaque route tokens, relay-local adjacent metadata, terminal-only destination
resolution, and diverse-route failover. The deferred list below does not
include that bounded profile; it describes extensions outside UMP/1.

Deferred capabilities are not advertised as stable features: 0-RTT early
data, unbounded topology discovery beyond the bounded validated UMP/1 route
profile, relay multipath/store-forward mode, DHT or internet bootstrap,
process-isolated
dynamic plugins, anonymous credentials, PSI/PIR,
rendezvous/replica privacy, and mix-network cover traffic. P3 application
padding, bounded timing jitter, session-preserving privacy-identifier rotation,
and optional budgeted authenticated cover packets are implemented policy
controls, not a claim of global traffic-analysis resistance.

Release notes MUST include the UMP version, Control API version, SDK versions,
carrier allocation/status, storage schema, migration notes, and security
notes. Promotion of the TLS carrier or the C ABI requires independent
interoperability and security review.
