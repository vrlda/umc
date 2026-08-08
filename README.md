# Universal Mesh Core (UMC)

Reference implementation of the Universal Mesh Protocol (UMP/1).
Specifications live in `spec/`. See `spec/decisions.md` for the accepted stack.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.

Specifications are licensed under Creative Commons Attribution 4.0 International.

## Status

- [x] Phase 0: foundations — workspace, wire parser, vectors, fuzzing, CI
- [x] Phase 1: secure direct communication — crypto, handshake, session, TCP/UDP, echo
- [x] Phase 2: node runtime — daemon, Control API, storage, config, diagnostics
- [x] Phase 3: routing and relaying — route discovery, single relay, quotas
- [x] Phase 4: mobility — paths, migration, connection IDs, key update, resumption
- [x] Phase 5: local mesh — LAN discovery, local preference, disconnected tests
- [x] Phase 6: store-and-forward — experimental bundles, one-hop delayed delivery
- [x] Phase 7: adversarial resilience — enumeration, trust, rate limits, blocklist, abuse
- [x] Phase 8: daemon loop — sessions, handshake responder, services, control API
- [x] Phase 9: application layer — application registry, well-known protocol IDs, stream dispatch, echo application over live sessions
- [x] Phase 10: SDK bindings — Rust daemon client and CLI surfaces
- [x] Phase 11: plugin contract — manifest, registry, in-process lifecycle, and capability-based security model (see `docs/plugin-security.md`; dynamic loading remains deferred pending a sandboxed host)
- [x] Phase 12: protocol completion over sessions — relay, bundle store/forward, and route requests over live sessions; config persistence; key rotation; CLIENT_AUTH continuation; two-daemon integration
- [x] Phase 13: hardening — property tests, relay-frame fuzzing, resource limits, and DoS-resilience tests
- [x] Phase 14: conformance — wire errata, hostile-input bounds, stream-id reuse, relay status/sequence rules, identity binding, and control-connection caps

The A–K gap-closure status is tracked in [`docs/PHASES.md`](docs/PHASES.md).
Phase J’s full fuzz/simulator/adversarial/coverage gate and Phase K’s P1–P3
privacy mechanisms are not claimed complete yet; K1 only exposes the secure
profile default and policy floor.
