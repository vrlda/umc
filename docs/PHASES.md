# A–K implementation status

The phase plan that records the work is [`docs/superpowers/plans/2026-08-07-gap-closure.md`](superpowers/plans/2026-08-07-gap-closure.md). It is the clearest surviving record of the A–K sequence; the older `docs/superpowers/plans/phase*.md` files describe the original numbered phases.

This status is based on the code and tests in this checkout (2026-08-08), not on the checkboxes in the original plan:

| Phase | Status | Evidence / qualification |
| --- | --- | --- |
| A | Complete | Runtime session enforcement, timers, loss/PTO, flow control, amplification limits, and bundle eviction are wired. |
| B | Complete | Keystore identity persistence, peer/route/bundle/event persistence, and backup/restore are present. SQLite schema is v2. |
| C | Complete | Reno-style congestion control and pacing are part of the session send path. |
| D | Complete | Protected handshake continuation, version negotiation, resumption, and key-discard behavior are exercised. |
| E | Complete | Metrics, redacted logging, health/status, and event surfaces are wired. |
| F | Complete | Control API and SDK surface are implemented. F4’s multi-protocol unregister cleanup is in `8431eb6`; dead session-bus receivers are cleaned by the watcher in `05a79a4`. |
| G | Complete | Trust states, revocation/TOFU, emergency disablement, release-manifest tooling, and the threat-model assessment are present. |
| H | Complete with compatibility notes | Live route forwarding, relay authorization, custody/chunked bundles, sealed envelopes, peer hints, static peers, and invitations are implemented. Empty relay authorization remains accepted for legacy phase-12 fixtures; peer-hint exchange is triggered by session traffic rather than a standalone timer. |
| I | Implemented, experimental pieces | TLS-stream (varint framing), carrier registry, PSK-XX derivation, Sybil-group admission, Python stdlib bindings, and the experimental C ABI are present. TLS currently uses an ephemeral self-signed certificate per carrier instance; deployment trust configuration is still required for independent daemons. |
| J | J1 implemented; J2 deterministic primitives implemented; J5/J6 CI scaffolding added; J3/J4 and release-grade verification remain pending | All 11 stable fuzz targets now have seed corpora and a smoke/nightly workflow. `umc-simulation` provides a deterministic clock/entropy source, bounded loss/duplicate/reorder/delay link, and a retransmission harness. CI now emits a locked Cargo metadata SBOM on every run and has a scheduled/manual LLVM coverage gate for the protocol crates; the full 22-case adversarial suite, soak/bench coverage, and release artifact/provenance review remain open. |
| K | K1 implemented; K2 handshake core, K3 DCID rotation, K4 enumeration guard and mesh-secret hints, K5 onion primitive, K6 path policy primitive, K7 opt-in padding, and the K8 privacy-info shape implemented; exact per-session reporting remains pending | Privacy profiles are ordered and fail-safe by default (`p0`); a local policy may raise the effective profile and GetStatus/GetConfig/GetSession expose the configured privacy surface. ClientHello now binds a requested minimum into the capabilities hash, and the daemon rejects requests above its p1 maximum rather than downgrading. Control candidate enumeration now has a per-principal budget, optional local-mesh hints use per-entry HMAC-BLAKE2s membership tags, `umc-relay` can build/open authenticated one-layer-at-a-time route envelopes, sessions can reject direct paths when a private route policy is selected, data packets can opt into a fixed 1,024-byte payload target, and the daemon rotates advertised connection IDs on a ten-minute schedule. Daemon route wiring, exact negotiated session state, timing hygiene, cover traffic, and the remaining P3 work are future work. |

The workspace’s authoritative verification commands are:

```text
rtk cargo fmt --all
rtk cargo clippy --workspace --all-targets -- -D warnings
rtk cargo test --workspace --lib
```

The phase integration packages (`phase1-tests` through `phase9-tests`, `phase12-tests`, and `phase13-tests`) pass independently. The monolithic `cargo test --workspace` command includes the 211-test `umcd` binary suite and can run for several minutes; run it separately when doing a release gate.
