# Universal Mesh Core

Universal Mesh Core (UMC) is a lightweight, identity-addressed networking
runtime for decentralized applications. It gives applications secure,
portable communication across direct links, local networks, relays, and
intermittent transports without requiring a central service.

UMC provides a shared protocol, identity, transport, and routing foundation for
decentralized applications and network services.

UMC is one interoperable ecosystem with three editions: `lite` for constrained
devices, `standard` for normal nodes (the current baseline), and `extended` for
additional bundle, relay, plugin, privacy, and SDK capabilities as they become
production-ready. Edition differences never create separate meshes: all
editions share UMP/1, identities, realm admission, and compatible carriers.
Set `"edition": "lite"`, `"standard"`, or `"extended"` in the node config;
unsupported Extended capabilities stay unadvertised until implemented.

The current release is `0.2.3`. It includes the Rust SDK plus dependency-free
local Control API bindings for Python, TypeScript/Node.js, Go, Kotlin/JVM, and
Swift. These bindings use the same versioned protobuf envelope and local
authorization boundary as the daemon; they do not create parallel protocols or
separate meshes.

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
- **Developer interfaces** — Rust daemon-backed and embedded SDKs, an
  experimental byte-oriented C ABI, dependency-free Python, TypeScript/Node,
  Go, Kotlin/JVM, and Swift Control API clients, plus the `umc` command-line
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
| C SDK | Experimental byte-oriented ABI for applications in C-compatible languages. |
| Python binding | Dependency-free async local Control API client with typed application/session/stream helpers. |
| TypeScript binding | Node.js local Control API client with typed framing/status helpers. |
| Go binding | Dependency-free Unix Control API client with request correlation and status handling. |
| Kotlin binding | Kotlin/JVM Unix Control API client using the JDK Unix-domain socket API. |
| Swift binding | Synchronous Swift Unix Control API client using the native POSIX socket API. |
| `examples/echo` | Minimal client/server carrier example. |
| `examples/chat` | Interactive terminal chat over a reliable UMC stream (embedded loopback demo). |
| `examples/file-transfer` | Bounded chunked file transfer with BLAKE2s-256 integrity verification. |

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

The same exchange carries a bounded decentralized lookup overlay. Nodes share
short-lived, endpoint-signed records, retain only the closest records needed
for a lookup, replicate them across authenticated peers, and expire them from
memory and disk. No node is authoritative and no complete peer table is sent;
the original seed can disappear after the mesh has learned enough peers.

### Private corporate meshes

Nodes join the open public mesh by default. To create a separate corporate
mesh, give every participating node the same private `network_id` and a
high-entropy `mesh_secret`:

```json
{
  "network_mode": "private",
  "network_id": "acme-production",
  "mesh_secret": "replace-with-a-long-random-membership-secret",
  "bootstrap_peers": [
    {"carrier": "ump.tcp/1", "address": "corp-seed.example:9001"}
  ],
  "advertised_endpoints": [
    {"carrier": "ump.tcp/1", "address": "corp-node.example:9001"}
  ]
}
```

The secret is never sent on the wire. Both hellos carry only a
transcript-bound commitment, and a node rejects a mismatched or missing
private marker before doing public-key work. Public and private realms cannot
handshake, exchange hints, or participate in one another's discovery overlay.
Private discovery records are also namespaced in persistent storage. Keep the
secret out of source control and distribute it through your normal corporate
secret-management process. A daemon instance belongs to one realm; run a
second instance with a separate data directory if a host must serve both.

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

Try the application examples locally without a running daemon:

```sh
cargo run -p umc-chat
cargo run -p umc-file-transfer -- ./source.bin ./received.bin
```

Both examples use the embedded SDK backend for a deterministic local demo.
The same application calls can use a daemon-backed `umc_sdk::Client` by
connecting to its local Control API endpoint.

The Rust SDK can run against a daemon or entirely in-process through its
embedded backend. The C and Python interfaces speak the local Control API.

## Platform status

The Unix daemon uses a protected Unix-domain control socket. Windows uses a
local-only named pipe with the same framed control API and handshake; the
stdlib Python client accepts either endpoint (for example,
`r"\\.\pipe\umc"` on Windows). TCP, TLS, UDP, LAN, embedded transport,
storage, routing, and security behavior are covered by the implementation and
automated checks.

Network peers cannot use UMP sessions to browse, open, read, or modify arbitrary
host-filesystem paths. Session and relay frames carry authenticated opaque
application bytes only; they do not contain a path-open, path-read, or
path-write operation. The daemon may persist bounded protocol state—such as
encrypted bundle ciphertext—in its own object store, but a peer cannot choose a
host path or retrieve arbitrary local file bytes. Administrative operations
(configuration, identity-secret export, bundle management, and carrier/plugin
management) remain behind the local Control API, OS transport gate, and API
capability checks. The file-transfer example is an application that the
operator runs and authorizes; it is not a daemon filesystem service.

UMC's privacy and topology mechanisms are bounded: it does not claim a global
topology database or unrestricted multipath (the supported profile provides
authenticated bounded multipath), anonymous credentials, or
global-passive adversary protection. Deployments should review their threat
model before treating the runtime as production-secure.

## Roadmap

The following items are intentionally outside the current `0.2.3` baseline.
They are planned extensions, not advertised capabilities, and are designed to
remain wire-compatible with the existing UMP/1 mesh:

- Built-in broadcast data, intermittent-contact, and shared-memory carriers.
- Full epidemic replication and multi-hop store-and-forward custody.
- Global privacy routing, mix-network anonymity, and rendezvous/replica privacy.
- Resistance to a global passive traffic-analysis adversary.
- Anonymous credentials, zero-knowledge proofs, PSI, and PIR.
- Caller-controlled export/import of opaque session tickets and resumption
  secrets for backup or migration. Automatic daemon ticket persistence and
  resumption already work without this API.
- Typed bundle-status convenience methods in each high-level SDK. The daemon
  Control API and generic bundle-state event stream already expose bundle data.
- Formal protocol proofs and model-checking artifacts.

Additional language bindings are part of this release and live under
`bindings/typescript`, `bindings/go`, `bindings/kotlin`, and `bindings/swift`.

## License

Licensed under the Apache License, Version 2.0.
