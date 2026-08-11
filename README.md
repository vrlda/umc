# Universal Mesh Core

Universal Mesh Core (UMC) is a lightweight, identity-addressed networking
runtime for decentralized applications. It gives applications secure,
portable communication across direct links, local networks, relays, and
intermittent transports without requiring a central service.

UMC is the reusable core. Applications, browsers, websites, and VPN products
build on it but remain separate projects.

## What it provides

- **Cryptographic identities and trust** — stable endpoint identities,
  authenticated bindings, invitations, trust delegation, revocation, recovery
  authorities, and bounded replay protection.
- **Secure sessions** — authenticated handshakes, encrypted packet protection,
  key updates, connection IDs, path validation, migration, and resumable
  sessions.
- **Multiple carriers** — TCP streams, TLS streams, UDP datagrams, and LAN
  discovery through a small carrier interface that can be extended by plugins.
- **Routing and relaying** — route discovery, bounded multi-hop paths,
  relay circuits, onion-wrapped hop transitions, path diversity, loop and
  duplicate suppression, and per-peer forwarding quotas.
- **Disconnected operation** — local-first mesh routing, bounded route caches,
  encrypted store-and-forward bundles, custody limits, expiry, and delayed
  delivery when peers reconnect.
- **Application transport** — registered application protocols, stream and
  datagram dispatch, bounded flow control, typed delivery/path/session events,
  pagination, deadlines, cancellation, and idempotent control requests.
- **Node administration** — the `umcd` daemon, a versioned local Control API,
  persistent configuration and state, diagnostics, event inspection, peer and
  route management, and invitation lifecycle commands.
- **Developer interfaces** — Rust daemon-backed and embedded SDKs, a stable C
  ABI, a pure-stdlib asynchronous Python client, and the `umc` command-line
  client.
- **Resource and abuse controls** — bounded queues and caches, rate limits,
  amplification protection, stream and packet size limits, trust-aware policy,
  blocklists, and fail-closed malformed-input handling.

## Components

| Component | Purpose |
| --- | --- |
| `umcd` | Runs a UMC node and its carriers. |
| `umc` | Controls and diagnoses a local node. |
| Rust crates | Wire formats, cryptography, sessions, routing, relay, discovery, storage, SDK, and plugins. |
| C SDK | Byte-oriented ABI for applications in C-compatible languages. |
| Python binding | Async local Control API client. |
| `examples/echo` | Minimal client/server example using the runtime. |

## Quick start

Build the workspace:

```bash
cargo build --workspace
```

Initialize a node and inspect its commands:

```bash
cargo run -p umc -- init
cargo run -p umc -- --help
cargo run -p umcd -- --help
```

The Rust SDK can run against a daemon or entirely in-process through its
embedded backend. The C and Python interfaces speak the local Control API.

## Platform status

The Unix daemon uses a protected Unix-domain control socket. Windows builds
compile the libraries and CLI, while named-pipe daemon control is not yet
available. TCP, TLS, UDP, LAN, embedded transport, storage, routing, and
security behavior are covered by the implementation and automated checks.

UMC's privacy and topology mechanisms are bounded: it does not claim a global
topology database, unrestricted multipath, anonymous credentials, or
global-passive adversary protection. Deployments should review their threat
model before treating the runtime as production-secure.

## License

Licensed under the Apache License, Version 2.0.
