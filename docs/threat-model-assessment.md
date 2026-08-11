# Threat-model assessment

**Assessment date:** 2026-08-08  
**Threat-model version:** `spec/threat-model.md` v0.1 (Draft)  
**Release posture:** experimental; the required production-security gates are
not complete.

This assessment maps the current implementation to the threat model. “Partial”
means a bounded or tested defense exists but the specification requires more
coverage, independent review, or a missing integration. “Open” means the
implementation is intentionally deferred or has no evidence in this tree.

## Component assessment

| Component / boundary | Threats | Current defenses and evidence | Residual status |
| --- | --- | --- | --- |
| Handshake and identity | Local MITM, cryptographic attacker, downgrade, probing | XX responder verifies binding, transcript signatures, capabilities, endpoint/static-key consistency, revocation and TOFU before session registration (`bins/umcd/src/handshake_responder.rs`, `state.rs`); version and crypto kill-switches fail closed; published vectors now pass both the Rust suite and the independent Python verifier; the solo implementation review is recorded in `docs/security-review-2026-08-11.md` | Partial / High; no human audit or production-security claim |
| Crypto primitives | Key theft, nonce misuse, randomness failure, protocol composition | Ed25519 identity signatures, X25519 DH, ChaCha20-Poly1305, HKDF-BLAKE2s, domain-separated labels; seed round trips and primitive tests exist (`crates/umc-crypto`); no external cryptographic audit or formal model | Partial / Critical |
| Wire and session parsers | Parser attacker, forged frames, replay, resource exhaustion | Length-bounded wire decoding, replay/packet-number state, stream and queue caps, proptest and parser smoke tests (`crates/umc-wire`, `crates/umc-session`); the 22-case adversarial J3 matrix, twelve-target cargo-fuzz corpus/resource report, and solo unsafe/parser review are landed | Partial / High; no human third-party audit or formal proof |
| Session admission and limits | Malicious peer, amplification, handshake flood | Handshake tracker, trust/block/revocation/TOFU admission, shared constrained/standard/relay profile caps for bundle storage, active sessions, and relay circuits, bounded control/event/token state, anti-abuse metrics, and deterministic/live resource-trend tests; OS-level process quotas and loss/PTO behavior remain deployment/reliability concerns | Partial / High |
| Trust, revocation, TOFU | Forged rotation/revocation, rollback, malicious peer | Seven-state trust transitions, bounded introductions with fail-closed introducer scope authority, canonical Ed25519 signed introductions with evidence/sequence/expiry checks and restart-time verification, self-authorized canonical identity/binding revocations with sequence/expiry checks enforced by admission, bounded canonical delegation-chain verification with issuer/capability/expiry/cycle checks, persisted revocation records, sequence-aware binding checks, persisted first-seen TOFU, root-signed class-scoped recovery authorities and recovery revocations with restart-time verification, and bounded signed revocation batch propagation (`crates/umc-core`); an external restore-generation anchor is cross-checked with a native OS-keychain generation when available, while hardware monotonic anchoring and disconnected revocation campaigns remain platform/operations evidence items | Partial / High |
| Routing and discovery | Sybil/eclipse, malicious route advertiser, compromised bootstrap/discovery | Candidate TTL/policy filtering, bounded tables, signed bootstrap-bundle issuer verification, persisted route/candidate restoration as candidates, bounded path construction with exclusions/loop/scope/relay limits and explicit failure-domain diversity, invitation validation and route cache tests; the bounded `ProviderManager` adds restartable provider hooks, failure isolation, source-attribution checks, and explicit diversity reporting | Partial / High |
| Relay and bundles | Malicious relay, resource exhaustion, replay, metadata disclosure | Circuit admission quotas, bounded relay payloads, event/audit transitions, bundle object store, metadata restore and expiry; onion privacy, relay authorization, custody/large-transfer replay defenses are incomplete | Partial / High |
| Built-in and external carriers | Censor, carrier compromise, plugin abuse | TCP/UDP/TLS framing is bounded; the independent Python peer runs live refusal, XX authentication, stream/datagram exchange, and restart checks against all three built-in carriers; TLS deployment can load explicit DER certificate/key/trust roots and server name, while absent material remains an ephemeral development profile; disabled-carrier kill-switch prevents bind/listen and stops accept loops; external plugins are not advertised in v0.1; the trusted plugin registry has strict capabilities plus generation-scoped quota, crash cleanup, restart backoff, and disablement tests | Mitigated for bounded v0.1; external subprocess IPC and OS sandboxing are deferred extensions |
| Local control API and SDK | Compromised application/admin, handle confusion, secret export | Capability/token registry, scoped grants, typed SDK handles, deadline/error mapping, event filters, passphrase/X25519/native-keychain authenticated secret export/import with explicit confirmation and audit events; Unix socket mode `0600`, same-UID peer credentials checked before hello, fail-closed peer-proof propagation through connection state, bearer capability checks, and cross-application handle/event isolation regressions | Implemented for the bounded Unix/macOS v0.1 daemon; Windows named-pipe policy and third-party review are outside this repository claim |
| Persistence and recovery | Database corruption/rollback, malicious backup, device theft | SQLite WAL/FULL-synchronous schema/migrations with bounded busy timeout, v3 random-salt/random-nonce protected keystore with atomic v2 migration, content-hash-checked/fsynced objects, persistent identity/trust/route/bundle/event records, and staged backup/restore validation covering hostile paths, symlinks, hashes, schema, node identity, generation, and rollback; an external restore-generation anchor is cross-checked with native OS-keychain state when available | Partial / High; hardware monotonic anchoring and a long-duration power-loss campaign remain outside the bounded core |
| Telemetry and diagnostics | Privacy leakage, operator error | Telemetry is off by default, addresses and endpoint identifiers are redacted, event rings are bounded, emergency controls are exposed in config; retention/export review and crash-report policy are open | Partial / Medium–High |
| Build and release | Dependency/CI compromise, malicious update, signing-key compromise | Lockfile, SBOM/provenance fields in the manifest template, solo-operator Ed25519 sign/verify workflow, trust-store revocation procedure, and the machine-readable Tier-1 platform-evidence workflow; reproducible-build review and key provisioning remain release-owner checks | Partial / Critical |

## Security invariants and evidence

The implementation currently has direct tests for identity persistence, binding
validation, trust refusal, revocation/TOFU, event cleanup, token lifecycle,
application channel cleanup, config emergency disablement, and release
manifest signing. The following invariants still require explicit matrix
coverage: no application plaintext to relays/plugins, no live cryptographic
session restoration after rollback, no cross-application handles/events, no
plugin-generation handle reuse, and no unbounded work from every network and
local parser.

## Residual-risk register

Owners are role names rather than individuals until the project assigns named
maintainers.

| ID | Risk | Severity | Owner | Status / next evidence |
| --- | --- | --- | --- | --- |
| R-01 | Handshake composition or downgrade flaw | Critical | Project owner | Partial; the 2026-08-11 solo implementation review fixed HKDF label truncation and keyed-BLAKE2s/HMAC mismatches, and published Finished-MAC vectors now have Rust/Python differential evidence; no human audit or formal proof is claimed |
| R-02 | Network/control parser defect | Critical | Project owner | Mitigated for bounded v0.1: the 22 J3 scenarios, twelve-target corpus/resource report, shared carrier framing, incremental control framing, and checked relay length arithmetic pass; retain minimized reproducers and re-run the scheduled campaign |
| R-03 | Resource exhaustion across session/routing/relay/plugin boundaries | High | Runtime maintainer | Mitigated for bounded v0.1: one shared profile matrix now gates bundle storage, active sessions, and relay circuits; deterministic profile/cap tests and the ten-minute soak emit bounded queue trend evidence. OS-level memory/CPU/file-descriptor quotas and retaining CI artifacts remain deployment checks |
| R-04 | Stale trust/revocation state after storage rollback | High | Storage/trust maintainer | Partial; generation-bound manifests, staged restore, external file/OS-keychain mismatch detection, and bounded stale revocation evidence emit operator-visible warnings; hardware monotonic anchoring, signed distribution, and a long-duration rollback campaign remain open |
| R-05 | Malicious or compromised release artifact | Critical | Project owner | Mitigated for bounded repository evidence: wrapper, 1-of-1 verifier, clean-tree and self-verifying dependency/SBOM audit, platform-evidence/release-baseline digests, clean-tree preflight/verifier, and the ten-exercise security-operations drill (including signature tamper rejection and key rotation) pass; retaining artifacts and operator key provisioning remain release-owner operations |
| R-06 | External carrier/plugin compromise reaches daemon | High | Carrier maintainer | Mitigated for bounded v0.1 by not advertising external plugins and enforcing strict capabilities plus generation-scoped quota/crash/restart supervision for trusted hooks; a future subprocess loader must retain this contract and add private IPC/OS sandbox evidence |
| R-07 | Eclipse/Sybil route or discovery poisoning | High | Routing maintainer | Partial; bounded candidates and persistence exist; source grouping/diversity and multi-node simulation open |
| R-08 | Relay metadata correlation or selective forwarding | High | Relay maintainer | Partial; endpoint encryption and quotas exist; onion/multipath privacy mechanisms are deferred |
| R-09 | Local application or administrator overreach | High/Critical | API maintainer | Mitigated for bounded Unix/macOS v0.1: mode `0600`, same-UID peer credentials, explicit peer-proof authorization, bearer grants, principal-owned handles/events, audit, and secret-export confirmation are regression-tested; Windows named-pipe policy and third-party review remain outside the repository claim |
| R-10 | Keystore/backup exposure on stolen device | High/Critical | Platform maintainer | Partial; v3 random-salt/random-nonce encrypted keystore, one-time v2 migration, Argon2id, owner-only atomic writes, native keychain wrapping, and hash/identity-bound restore validation are covered; platform-specific keychain policy and production credential handling remain open |
| R-11 | Telemetry/log metadata reconstruction | Medium–High | Privacy maintainer | Partial; opt-in telemetry and redaction exist; retention, crash reports and P1–P3 privacy work open |
| R-12 | No operational vulnerability contact | High | Project owner | Mitigated for the repository: `SECURITY.md` names GitHub private vulnerability reporting and the offline intake/embargo/advisory drills pass; enable the GitHub repository setting before public release |

No row is a production-security sign-off. Any Critical row remains a release
blocker under `spec/threat-model.md` §54.

## Unsafe-code inventory

On 2026-08-11 the repository search below found intentional `unsafe` only at
the experimental C ABI boundary:

```text
rg -n --glob '*.rs' '\bunsafe\b' crates/
→ crates/umc-sdk-c/src/lib.rs
```

The protocol and daemon crates remain free of `unsafe`; the C ABI's pointer
contracts, ownership transfers, and generated-buffer frees are reviewed in
FFI-001/FFI-002 in [`docs/security-review-2026-08-11.md`](security-review-2026-08-11.md).
This is an inventory of first-party source only, not an audit of unsafe code in
dependencies, generated code, build scripts, or the operating system. Repeat
it for each release alongside the dependency/SBOM report.

## Cryptographic review notes

The code uses `ed25519-dalek` for identity signatures, `x25519-dalek` for
handshake DH, `ChaCha20-Poly1305` for packet AEAD, `ChaCha20` for header
protection, and HKDF-BLAKE2s for traffic/key derivation. Protocol labels and
transcript domains include values such as `UMP-HANDSHAKE-v1`,
`UMP-CLIENT-AUTH-v1`, `UMP-SERVER-AUTH-v1`, `UMP-SESSION-TICKET-v1`, and
`UMP-TOFU-v1`. The implementation has unit/property tests for symmetry,
round trips, wrong-key rejection, domain separation, and handshake
continuations.

The 2026-08-11 implementation review is recorded in
[`docs/security-review-2026-08-11.md`](security-review-2026-08-11.md). It fixed
an HKDF label-length truncation and corrected Finished, PSK invitation, relay,
and mesh tags to the RFC 2104 HMAC-BLAKE2s construction. This record is not an
independent human audit or formal protocol analysis.

The following are optional strengthening work, not missing solo-maintainer
implementation evidence:

1. Independently model the XX/IK transcript and key schedule, including the
   provisional client-static substitution and resumption ticket path.
2. Check nonce construction, packet-number spaces, key discard/rotation, and
   replay behavior across restart and migration.
3. Review binding canonicalization, sequence/expiry arithmetic, revocation
   cutoffs, and TOFU behavior under rollback or concurrent updates.
4. Review the solo-operator Ed25519 release-signing and key-revocation workflow;
   the local scripts intentionally implement one signature at a time.

The project must continue to describe the cryptography as experimental
implementation work, not a production guarantee.

## Adversarial-simulation status

The current tree has phase-specific adversarial tests in
[`tests/phase7/tests/adversarial.rs`](../tests/phase7/tests/adversarial.rs),
resource/DoS tests in `tests/phase13`, and resumption/migration/two-node flows
in `tests/phase12`. Wire and session property tests cover deterministic edge
cases.

The J3 matrix is now landed in
[`tests/phase13/tests/adversarial_matrix.rs`](../tests/phase13/tests/adversarial_matrix.rs)
and covers the 22 refusal/resource-bound scenarios listed in the plan,
including forged ACKs, Initial replay, oversized/fragmented frames, handshake
and encrypted-garbage floods, amplification, malformed bindings, stream/path
confusion, bundle replay, relay authorization, route loops, control-API
flooding, plugin manifests, and telemetry misuse. The deterministic simulator
also runs a bounded 256-message loss/duplicate/reorder/delay soak. A release
baseline harness now combines the continuous-session soak and protocol
benchmarks into hashed, machine-readable evidence. Its clean-tree preflight
rejects tracked or untracked changes, and the companion verifier checks the
committed-tree ids, ten-minute duration, resource bounds, and every recorded
artifact digest. The isolated native 2026-08-11 clean snapshot passed 600,000
ms with 3,713,455 iterations, 92,836,375 stream bytes, 100,263,285 datagram
bytes, and peak bounded-link queue depth 1 of 128 while exercising the normal
bounded stream-credit window. CI retains the evidence directory; the fuzz
corpus/resource report is generated and uploaded by the smoke/nightly workflow
rather than reduced to a pass count.

## Required next actions

1. Enable GitHub private vulnerability reporting and exercise the 90-day
   reporting process with a real report before public release.
2. Retain the successful clean-tree `release-baseline` artifact from the J4
   harness and compare it with the previous release. The J1/J5 fuzz
   corpus/resource report is generated by `scripts/fuzz-report.sh` and uploaded
   by CI.
3. Re-run the solo implementation review and record evidence for every
   Critical/High residual-risk row after protocol or boundary changes. Human
   third-party review remains outside the current solo-maintainer profile.
4. Re-run this assessment whenever a protocol, persistence, carrier, local
   API, release, or privacy boundary changes.
