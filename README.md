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
- [x] Phase 11: plugin contract — manifest, registry, in-process lifecycle, and capability-based security model (see `docs/plugin-security.md`; dynamic loading remains deferred pending a sandboxed host)
- [x] Phase 12: protocol completion over sessions — relay, bundle store/forward, and route requests over live sessions; config persistence; key rotation; CLIENT_AUTH continuation; two-daemon integration
- [x] Phase 13: hardening — property tests for the varint and replay window, relay-frame fuzz target, resource-limit enforcement, and DoS-resilience tests
- [x] Phase 14: conformance — errata E1-E13, hostile-input bounds for the initial parser and frame decode, padding and length-delimited skipping, stream-id reuse rejection, relay status-code table and per-direction sequences, identity-binding validation at session establishment, and control-connection caps
