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
| Handshake and identity | Local MITM, cryptographic attacker, downgrade, probing | XX responder verifies binding, transcript signatures, capabilities, endpoint/static-key consistency, revocation and TOFU before session registration (`bins/umcd/src/handshake_responder.rs`, `state.rs`); version and crypto kill-switches fail closed; vectors and independent review are still missing | Partial / High until review |
| Crypto primitives | Key theft, nonce misuse, randomness failure, protocol composition | Ed25519 identity signatures, X25519 DH, ChaCha20-Poly1305, HKDF-BLAKE2s, domain-separated labels; seed round trips and primitive tests exist (`crates/umc-crypto`); no external cryptographic audit or formal model | Partial / Critical |
| Wire and session parsers | Parser attacker, forged frames, replay, resource exhaustion | Length-bounded wire decoding, replay/packet-number state, stream and queue caps, proptest and parser smoke tests (`crates/umc-wire`, `crates/umc-session`); the complete network parser fuzz matrix and adversarial J3 suite are not present | Partial / High |
| Session admission and limits | Malicious peer, amplification, handshake flood | Handshake tracker, trust/block/revocation/TOFU admission, bounded control/event/token state, anti-abuse metrics; loss/PTO, full resource profiles, and all session-path enforcement remain incomplete | Partial / High |
| Trust, revocation, TOFU | Forged rotation/revocation, rollback, malicious peer | Seven-state trust transitions, bounded introductions, persisted revocation records, sequence-aware binding checks, persisted first-seen TOFU (`crates/umc-core`, `bins/umcd/src/state.rs`); rollback detection and disconnected revocation freshness are open | Partial / High |
| Routing and discovery | Sybil/eclipse, malicious route advertiser, compromised bootstrap/discovery | Candidate TTL/policy filtering, bounded tables, persisted route/candidate restoration as candidates, invitation validation and route cache tests; multi-hop forwarding, source grouping, diversity signals, and enumeration adversarial coverage remain open | Partial / High |
| Relay and bundles | Malicious relay, resource exhaustion, replay, metadata disclosure | Circuit admission quotas, bounded relay payloads, event/audit transitions, bundle object store, metadata restore and expiry; onion privacy, relay authorization, custody/large-transfer replay defenses are incomplete | Partial / High |
| Built-in and external carriers | Censor, carrier compromise, plugin abuse | TCP/UDP carrier framing is bounded; disabled-carrier kill-switch prevents bind/listen and stops accept loops; external plugin capability model exists, but process isolation and per-plugin quotas are deferred | Partial / High |
| Local control API and SDK | Compromised application/admin, handle confusion, secret export | Capability/token registry, scoped grants, typed SDK handles, deadline/error mapping, event filters, secret export opt-in, audit events; OS permission review, complete cross-application isolation tests, and production credential storage are open | Partial / High |
| Persistence and recovery | Database corruption/rollback, malicious backup, device theft | SQLite schema/migrations, protected keystore, persistent identity/trust/route/bundle/event records, backup/restore commands and validation; monotonic rollback anchors, OS keychain integration, and corruption campaign are open | Partial / High–Critical |
| Telemetry and diagnostics | Privacy leakage, operator error | Telemetry is off by default, addresses and endpoint identifiers are redacted, event rings are bounded, emergency controls are exposed in config; retention/export review and crash-report policy are open | Partial / Medium–High |
| Build and release | Dependency/CI compromise, malicious update, signing-key compromise | Lockfile, SBOM/provenance fields in the manifest template, Ed25519 sign/verify wrappers, documented 2-of-3 policy and trust-store revocation procedure; threshold workflow, reproducible-build review, and key provisioning are open | Partial / Critical |

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
| R-01 | Handshake composition or downgrade flaw | Critical | Crypto maintainer | Open; independent handshake review, final vectors, and formal analysis required |
| R-02 | Network/control parser defect | Critical | Protocol maintainer | Partial; add the remaining fuzz targets and J3 scenarios, then publish corpus results |
| R-03 | Resource exhaustion across session/routing/relay/plugin boundaries | High | Runtime maintainer | Partial; complete profile-enforcement tests, deterministic loss simulator, and soak limits |
| R-04 | Stale trust/revocation state after storage rollback | High | Storage/trust maintainer | Open; add monotonic anchor or explicit restore-generation warning and rollback campaign |
| R-05 | Malicious or compromised release artifact | Critical | Release maintainer | Partial; wrapper and policy landed; threshold CI, reproducibility, SBOM, and revocation drill open |
| R-06 | External carrier/plugin compromise reaches daemon | High | Carrier maintainer | Partial; capability boundary exists; process sandbox and crash/restart adversarial tests open |
| R-07 | Eclipse/Sybil route or discovery poisoning | High | Routing maintainer | Partial; bounded candidates and persistence exist; source grouping/diversity and multi-node simulation open |
| R-08 | Relay metadata correlation or selective forwarding | High | Relay maintainer | Partial; endpoint encryption and quotas exist; onion/multipath privacy mechanisms are deferred |
| R-09 | Local application or administrator overreach | High/Critical | API maintainer | Partial; grants, tokens, handles, audit and secret-export gate exist; OS permission review open |
| R-10 | Keystore/backup exposure on stolen device | High/Critical | Platform maintainer | Partial; encrypted keystore and backup path exist; OS keychain, memory-hard KDF review, and restore policy open |
| R-11 | Telemetry/log metadata reconstruction | Medium–High | Privacy maintainer | Partial; opt-in telemetry and redaction exist; retention, crash reports and P1–P3 privacy work open |
| R-12 | No operational vulnerability contact | High | Security operations owner | Open; `SECURITY.md` is explicit `TBD-contact` and must be replaced before publication |

No row is a production-security sign-off. Any Critical row remains a release
blocker under `spec/threat-model.md` §54.

## Unsafe-code inventory

On 2026-08-08 the repository search below found no `unsafe` token in Rust
source under `crates/`:

```text
rg -n --glob '*.rs' '\bunsafe\b' crates/
→ no matches
```

This is an inventory of first-party source only. It is not an audit of unsafe
code in dependencies, generated code, build scripts, or the operating system.
The command must be repeated for each release and reviewed alongside the
dependency/SBOM report.

## Cryptographic review notes

The code uses `ed25519-dalek` for identity signatures, `x25519-dalek` for
handshake DH, `ChaCha20-Poly1305` for packet AEAD, `ChaCha20` for header
protection, and HKDF-BLAKE2s for traffic/key derivation. Protocol labels and
transcript domains include values such as `UMP-HANDSHAKE-v1`,
`UMP-CLIENT-AUTH-v1`, `UMP-SERVER-AUTH-v1`, `UMP-SESSION-TICKET-v1`, and
`UMP-TOFU-v1`. The implementation has unit/property tests for symmetry,
round trips, wrong-key rejection, domain separation, and handshake
continuations.

The following are review requirements, not completed claims:

1. Independently model the XX/IK transcript and key schedule, including the
   provisional client-static substitution and resumption ticket path.
2. Check nonce construction, packet-number spaces, key discard/rotation, and
   replay behavior across restart and migration.
3. Review binding canonicalization, sequence/expiry arithmetic, revocation
   cutoffs, and TOFU behavior under rollback or concurrent updates.
4. Review the Ed25519 release-signing threshold and key-revocation workflow;
   the local scripts intentionally implement one signature at a time.

Until these reviews and final vectors land, the project must describe the
cryptography as experimental implementation work, not a production guarantee.

## Adversarial-simulation status

The current tree has phase-specific adversarial tests in
[`tests/phase7/tests/adversarial.rs`](../tests/phase7/tests/adversarial.rs),
resource/DoS tests in `tests/phase13`, and resumption/migration/two-node flows
in `tests/phase12`. Wire and session property tests cover deterministic edge
cases.

The planned J3 suite is **not yet landed**. Its 22 scenarios are tracked in
[`docs/superpowers/plans/2026-08-07-gap-closure.md`](superpowers/plans/2026-08-07-gap-closure.md)
under “Task J3: Adversarial suite”; it must cover forged ACKs, Initial replay,
oversized/fragmented frames, handshake and encrypted-garbage floods,
amplification, malformed bindings, stream/path confusion, bundle replay,
relay authorization, route loops, control-API flooding, plugin manifests, and
telemetry misuse. A release gate should report each scenario's refusal result
and resource bound rather than only a pass count.

## Required next actions

1. Replace `TBD-contact` and exercise the 90-day reporting process.
2. Land J1–J5 parser fuzzing, deterministic simulation, adversarial tests,
   soak, coverage, and SBOM gates.
3. Obtain the seven independent reviews required by `spec/threat-model.md`
   §48 and record evidence for every Critical/High residual-risk row.
4. Re-run this assessment whenever a protocol, persistence, carrier, local
   API, release, or privacy boundary changes.
