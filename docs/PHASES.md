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
| J | Partial / next gate | Existing parser and relay fuzzing plus deterministic smoke tests exist. The full 11-target fuzz corpus, simulator, 22-case adversarial suite, soak/bench/coverage CI, and SBOM job remain to be added. |
| K | Documentation only / next gate | The privacy specification is present and the implementation has P0 protections plus several P1 building blocks. Privacy profiles, P2 onion routing, P3 padding, mesh-secret hints, and the privacy control surface remain future work. |

The workspace’s authoritative verification commands are:

```text
rtk cargo fmt --all
rtk cargo clippy --workspace --all-targets -- -D warnings
rtk cargo test --workspace --lib
```

The phase integration packages (`phase1-tests` through `phase9-tests`, `phase12-tests`, and `phase13-tests`) pass independently. The monolithic `cargo test --workspace` command includes the 211-test `umcd` binary suite and can run for several minutes; run it separately when doing a release gate.
