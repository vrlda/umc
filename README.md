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

Install the CLI and daemon on Unix/macOS:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://raw.githubusercontent.com/vrlda/umc/main/install.sh | sh
```

The installer clones the selected GitHub revision and runs Cargo, so it needs
Git and a Rust toolchain. By default it installs the latest `main` revision to
`~/.cargo/bin`. Pin another branch or tag by replacing `main` in `UMC_REF`:

```sh
UMC_REF=main sh -c 'curl --proto "=https" --tlsv1.2 -LsSf https://raw.githubusercontent.com/vrlda/umc/main/install.sh | sh'
```

Initialize and start a local node:

```sh
umc init
umcd &
umc status
```

### Automatic Internet discovery

Internet discovery needs an initial rendezvous address, but it does not keep
the rendezvous node in a privileged role. Configure one or more temporary seed
contacts and advertise the addresses on which this node is reachable:

```json
{
  "tcp_listen": "0.0.0.0:9001",
  "bootstrap_peers": [
    {"carrier": "ump.tcp/1", "address": "seed.example:9001"}
  ],
  "advertised_endpoints": [
    {"carrier": "ump.tcp/1", "address": "node.example:9001"}
  ]
}
```

After the first authenticated session, nodes exchange bounded `PEER_HINT`
frames. Learned and persisted candidates are dialed automatically with
backoff, and each explicitly advertised node becomes another bootstrap point.
`bootstrap_peers` is only a fallback for a node that has no live session;
`static_peers` remains a private, endpoint-pinned operator override. A node
behind NAT or a firewall must advertise a relay-reachable address or use a
separate relay configuration; the core does not guess public addresses.

### Optional Prometheus metrics

Metrics are disabled unless explicitly configured. To expose the bounded
global counters on the loopback interface, add this to the node JSON:

```json
{
  "metrics_listen": "127.0.0.1:9464"
}
```

Prometheus can then scrape `http://127.0.0.1:9464/metrics`. The endpoint uses
Prometheus text format and publishes only fixed, unlabeled daemon counters and
gauges. It never exports peer identifiers, addresses, route data, secrets, or
user-controlled labels. For a remote scrape, bind to an explicit non-loopback
address and configure a non-whitespace bearer token:

```json
{
  "metrics_listen": "0.0.0.0:9464",
  "metrics_bearer_token": "replace-with-a-long-random-token"
}
```

Send `Authorization: Bearer <token>` with the scrape. Prefer an SSH tunnel or
TLS reverse proxy for remote access; the exporter itself is intentionally a
small HTTP listener without TLS. Requests and responses are bounded and the
daemon does not log the token.

To build from a checkout instead:

```sh
git clone https://github.com/vrlda/umc.git
cd umc
cargo build --workspace
```

The Rust SDK can run against a daemon or entirely in-process through its
embedded backend. The C and Python interfaces speak the local Control API.

## Platform status

The Unix daemon uses a protected Unix-domain control socket. Windows uses a
local-only named pipe with the same framed control API and handshake. TCP, TLS,
UDP, LAN, embedded transport, storage, routing, and security behavior are
covered by the implementation and automated checks.

UMC's privacy and topology mechanisms are bounded: it does not claim a global
topology database, unrestricted multipath, anonymous credentials, or
global-passive adversary protection. Deployments should review their threat
model before treating the runtime as production-secure.

## License

Licensed under the Apache License, Version 2.0.
