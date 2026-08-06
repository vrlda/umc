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
- [x] Phase 10: SDK bindings — daemon, config, and status clients; CLI config get/set and events commands
- [x] Phase 11: plugin contract — manifest, registry, and in-process plugin lifecycle (dynamic loading deferred until the security model is spec-frozen)
- [x] Phase 12: protocol completion over sessions — relay, bundle store/forward, and route requests over live sessions; config persistence; key rotation; CLIENT_AUTH continuation; two-daemon integration
