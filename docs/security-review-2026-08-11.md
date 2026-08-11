# Security review record — 2026-08-11

This is an implementation-level security review of the UMP/1 cryptographic
boundaries. It is evidence for the repository security gates, not a production
security sign-off or a human third-party audit. Under the solo-maintainer v0.1
profile, this source/vector/test review is the required review record.

## Scope and method

The review cross-checked the handshake and wire specifications against:

- HKDF-BLAKE2s, label encoding, AEAD, nonce construction, and header
  protection in `crates/umc-crypto`;
- XX Finished/confirmation, PSK-XX invitation admission, and transcript use in
  `crates/umc-handshake`;
- relay authorization and discovery mesh membership tags in `bins/umcd` and
  `crates/umc-discovery`;
- the experimental C ABI ownership and allocation boundary in `crates/umc-sdk-c`;
- fixed-address initialization in the LAN discovery carrier; and
- the independent Python vector verifier and live TCP/UDP/TLS peer; and
- parser/resource/authorization regression coverage in the workspace suite,
  including the Unix control-socket peer-credential boundary.
- the shared resource-profile matrix, live session/relay admission caps, and
  structured queue-trend evidence emitted by the release baseline harness.
- the twelve-target cargo-fuzz corpus/resource report, including the shared
  carrier framing parser, incremental control framing, and UMC storage
  recovery target.
- the generation-scoped carrier/plugin supervisor, including quota admission,
  crash cleanup, restart backoff, disablement, and registry lifecycle wiring.

The review used specification-to-source tracing, fixed-vector checks, targeted
red regressions, the full Rust test suite, clippy, formatting, and the
independent live carrier runner. No deployment secrets or private material were
used.

## Solo review coverage

| Boundary | Evidence | Residual qualification |
| --- | --- | --- |
| Handshake and cryptography | Rust/Python vector agreement, source tracing, Finished-MAC checks, and the four cryptographic findings below | No human audit or formal proof claimed |
| Network parsers and unsafe code | Phase-13 adversarial matrix, Phase-14 state machines, checked relay arithmetic, C ABI inventory and bound regression | Dependency/generated-code audit remains outside first-party source review |
| Routing, relay, and discovery | Route/relay/provider tests, multi-hop path checks, and the Phase-13 hostile-input suite | Global topology/privacy resistance remains out of scope |
| Local API authorization | Full workspace authorization, token, ownership, deadline, handle-generation, Unix mode `0600`, same-UID peer, fail-closed transport-proof, and cross-application isolation tests | No human third-party review is claimed; Windows named-pipe policy is outside the Unix/macOS daemon target |
| Storage and migration | SQLite WAL/FULL-synchronous and busy-timeout checks, transactional migration rollback, v3 random-salt/random-nonce keystore with v2 migration, fail-closed truncation tests, fsynced/hash-checked object writes, and hostile restore manifest/hash/identity/generation tests | Hardware monotonic anchors and a long-duration power-loss campaign remain optional platform work |
| Carriers and plugins | Independent Python TCP/UDP/TLS live peer, bounded framing tests, capability checks, and generation-scoped supervisor quota/crash/restart tests | External plugin process isolation and OS sandboxing are intentionally not advertised in the bounded core |
| Release and dependencies | 1-of-1 manifest verifier, 10-drill report, locked SBOM, and zero-advisory `cargo-audit` report | Real release-key provisioning remains an operator action |

## Findings and remediation

### CRYPTO-001 — HKDF label context length was silently truncated

`HKDF-Expand-Label` encoded `context.len()` as a 16-bit value without checking
the bound. An oversized context could therefore derive from a different
canonical input than the caller supplied. `expand_label` now rejects contexts
larger than `u16::MAX` with `HkdfError::ContextTooLong`, and the regression test
`rejects_context_that_cannot_be_canonically_encoded` locks the behavior down.

### CRYPTO-002 — Protocol HMACs used BLAKE2 keyed mode

Finished MACs, PSK invitation authenticators, and relay authorization tags were
labelled HMAC-BLAKE2s but used BLAKE2s' distinct keyed mode. This produced
non-spec wire values and would prevent an independent conforming peer from
validating those messages. All three paths now use the shared RFC 2104
`umc_crypto::hkdf::hmac_blake2s` primitive. The fixed Finished-MAC vector is
published in `interop/vectors/ump1-v0.1.json`, consumed by both Rust and Python,
and the live runner passes all three built-in carriers after the correction.

### CRYPTO-003 — Duplicate mesh-tag HMAC implementation

Discovery mesh membership had a second hand-written HMAC implementation. It
was byte-equivalent, but duplicated security-sensitive code. It now calls the
shared HMAC primitive, reducing construction drift and leaving one reviewed
implementation for all protocol HMAC-BLAKE2s uses.

### PARSER-001 — Length-delimited relay status used unchecked range arithmetic

The relay status decoder formed a slice end with `used + len` directly. The
wire varint is bounded, but this still left the parser's arithmetic contract
implicit across target architectures. It now uses `checked_add` and returns a
bounded `FrameError`; an oversized/truncated length regression covers the
refusal path without panicking.

### FFI-001 — C ABI request length was not bounded before allocation

`umc_client_request` copied the caller-provided `payload_len` into a `Vec`
before applying the Control API's ordinary-request limit. A local C caller
could therefore force an unnecessarily large allocation in the binding. The
ABI now rejects lengths above 1 MiB before dereferencing the payload, and
`request_rejects_oversized_payload_before_dereference` covers the refusal path.
The C ABI remains experimental and its pointer-validity contracts are still
documented as caller obligations.

### FFI-002 — First-party unsafe inventory omitted the experimental C ABI

The previous inventory only described the protocol crates and incorrectly
implied that the workspace contained no `unsafe` Rust. The C ABI is the one
intentional first-party unsafe boundary; its opaque-handle, allocation/free,
null-check, and generation checks were reviewed explicitly. The inventory and
gate documentation now name that boundary rather than hiding it.

### CARRIER-001 — LAN carrier used panic-based fixed-address parsing

The LAN discovery carrier parsed compile-time addresses with `unwrap`. Those
values were fixed constants, but the panic was unnecessary in a carrier
constructor. It now constructs the multicast and unspecified addresses with
typed `Ipv4Addr` values, preserving behavior while removing the panic path.

### STORAGE-001 — Keystore envelopes reused a fixed AEAD nonce

The provisional v2 keystore used the same `KSV1` nonce for its check blob and
every record, and derived one deterministic salt per password. Repeated
plaintext records therefore produced identical ciphertext and violated the
ChaCha20-Poly1305 nonce-uniqueness requirement. v3 now uses a random per-file
salt and a fresh OS-random 96-bit nonce for every check/record envelope. Open
performs an atomic v2-to-v3 migration after authenticating and validating every
legacy record; malformed or unauthenticated input is rejected without writing
the legacy file. Focused tests cover ciphertext non-reuse, migration, wrong
passwords, and truncated-record fail-closed behavior.

### STORAGE-002 — Persistence writes lacked durability and restore integrity

SQLite now configures WAL, `synchronous=FULL`, and a bounded busy timeout. The
content-addressed object store validates the requested hash before writing and
fsyncs both the object and parent directory. Backup manifests now bind copied
files to BLAKE2s hashes, node identity, and an external restore generation;
restore rejects unsafe paths/symlinks, hash or identity mismatches, schema
downgrades, and generations older than the target anchor, while retaining the
staged rollback path. Migration failure, manifest tampering, identity mismatch,
and generation rollback each have regressions.

### STORAGE-003 — Binary key identifiers were incorrectly treated as text

Embedded endpoint records use raw 32-byte endpoint IDs as keystore names. A
NUL-delimited parser could truncate an identifier containing `0x00`, causing a
restart to report a missing endpoint secret. Record matching now uses the
requested name's exact byte length while validating the class separator, and a
zero-containing identifier regression covers the boundary.

### AUTH-001 — Local authorization did not carry the OS-peer proof

The live socket checked the peer uid, but the authorization helper previously
treated a missing bearer token as an implicit anonymous mode. That made the
same-user policy implicit and left future transports or in-process callers
without a fail-closed proof boundary. The listener now forces mode `0600`,
checks the peer uid before reading `ClientHello` and before consuming a live
connection permit, constructs a connection only through the authenticated-peer
path, and carries that proof into both hello
and request authorization. Missing peer proof rejects the hello and every
request, even when a bearer token is supplied; the validated same-uid peer is
the explicit local-operator mode, while `TokenService` still requires a bearer
or development credential. The regressions
`anonymous_request_without_authenticated_os_peer_is_rejected`,
`control_authorization_requires_os_peer_before_bearer_or_hello`, and
`os_peer_authorized_matches_daemon_uid` cover the boundary.

### PROFILE-001 — Profile defaults were not shared by admission paths

The daemon previously hardcoded the standard bundle quota and did not apply a
profile-wide cap to active sessions or relay circuits. The shared
`ResourceProfileLimits` table now carries the constrained, standard, and relay
matrix; runtime construction selects the configured profile, session admission
rejects before allocation at its active-session cap, and relay admission gates
both direct and nested circuit allocation. Profile, live-cap, and bounded-link
trend tests cover the behavior. The release baseline records the soak trend in
`resource-trend.json` and `baseline.json`. OS-level memory/CPU/file-descriptor
limits remain deployment controls, as required by the resource specification's
managed-budget qualification.

### PLUGIN-001 — Carrier/plugin lifecycle had no bounded generation contract

The trusted plugin registry previously enforced only manifest capabilities. A
failed hook could leave lifecycle ownership and future resource accounting to
callers, with no explicit generation invalidation or restart budget. The new
`umc_plugin::supervisor::PluginSupervisor` assigns fresh generations, rejects
oversized or over-quota operations before reservation, clears operation
permits, handles, and shared-memory bytes on failure, applies capped
exponential backoff, enforces startup and heartbeat deadlines, and disables a
plugin after the three-attempt burst.
Registry init/shutdown transitions use the same state machine. External
subprocess IPC and platform sandboxing remain a deliberately deferred
extension, consistent with the v0.1 implementation decision; they cannot be
advertised without reusing this contract.

### RELEASE-001 — Release baseline accepted dirty evidence

The baseline harness previously recorded a dirty flag but did not reject a
dirty checkout, leaving clean-tree reproducibility to operator discipline. It
now fails before benchmarks when tracked or untracked changes are present,
records the committed tree id, and has a companion verifier that checks the
ten-minute soak, resource bounds, artifact sizes, and SHA-256 digests. The
isolated native arm64 snapshot passed the full 600,000 ms run; a tampered
artifact is rejected by the verifier.

## Verification evidence

The corrected tree passed:

- `cargo test --workspace --locked` — 1,173 passed, 1 ignored;
- `cargo clippy --workspace --all-targets -- -D warnings`;
- `cargo fmt --all --check` and `git diff --check`;
- the independent Python vector verifier and four Python tests;
- Phase-13 adversarial matrix (23 tests) and Phase-14 conformance tests (6
  tests); and
- the twelve-target native cargo-fuzz smoke report with per-target corpus and
  RSS evidence; and
- independent live refusal/authentication/stream/datagram/restart scenarios
  over `ump.tcp/1`, `ump.udp/1`, and `ump.tls-stream/1`.
- the carrier/plugin supervisor lifecycle and quota regression suite.
- the clean-snapshot release baseline and its tamper-rejection verifier.

## Residual qualification

The implementation findings in this record are closed. No human cryptographic
audit or formal/semi-formal protocol proof is claimed; production-security
claims remain out of scope for the solo-maintainer experimental profile. TLS
remains experimental under the compatibility matrix.
