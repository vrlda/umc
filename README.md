# Universal Mesh Core (UMC)

Universal Mesh Core is an open-source, identity-addressed networking runtime
for building decentralized applications that operate across direct links,
relays, local networks, the internet, and future transports without mandatory
central infrastructure.

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
- [x] Phase 10: SDK bindings — Rust daemon client and CLI surfaces; Python is stable and the C ABI is experimental
- [x] Phase 11: plugin contract — manifest, registry, in-process lifecycle, and capability-based security model; process isolation remains deferred (see `docs/plugin-security.md`)
- [x] Phase 12: protocol completion over sessions — relay, bundle store/forward, route requests, config persistence, key rotation, CLIENT_AUTH continuation, and two-daemon integration
- [x] Phase 13: hardening — property tests, relay-frame fuzzing, resource limits, DoS-resilience tests, and the 22-case adversarial matrix
- [x] Phase 14: conformance — wire errata, hostile-input bounds, stream-id reuse, relay status/sequence rules, identity binding, and control-connection caps

The A–K gap-closure status is tracked in [`docs/PHASES.md`](docs/PHASES.md).
The bounded UMP/1 migration, recovery, evidence, topology, and privacy
mechanisms are implemented and verified. Global topology databases,
unrestricted multipath, anonymous credentials/rendezvous, and
global-passive anonymity remain outside this bounded profile; implemented
mechanisms are not a claim of production security.
