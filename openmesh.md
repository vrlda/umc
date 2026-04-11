# OpenMesh — Full Technical Specification

### Version 0.1 | Censorship Circumvention P2P Network

### For: AI agent implementation (Codex / Claude)

-----

## MISSION

Build a decentralized, peer-to-peer censorship circumvention network where users worldwide install a lightweight client that simultaneously acts as a consumer and a relay/exit node. No central servers. No blockable infrastructure. Anyone can access the open internet regardless of their country’s censorship apparatus.

-----

## CORE PRINCIPLES

1. Zero config — install and go, no technical knowledge required
1. Lightweight — invisible when idle, minimal battery/CPU/RAM impact
1. Decentralized — no single point of failure or control
1. Unblockable transport — resistant to DPI, fingerprinting, active probing
1. Open source — MIT license, community-driven

-----

## HIGH-LEVEL ARCHITECTURE
[Client - censored country]
    │
    │  Polymorphic QUIC/WebSocket transport
    │  (looks like normal HTTPS traffic)
    │
    ▼
[Peer 1 - any country]  ← relay node (optional, 2-3 hop mode)
    │
    ▼
[Peer 2 - free country]  ← exit node
    │
    ▼
[Destination website]

Routing modes (user choice):

- 1 hop: Client → Exit → Internet (fastest)
- 2 hops: Client → Relay → Exit → Internet (balanced, default)
- 3 hops: Client → Entry → Relay → Exit → Internet (max privacy)

Node roles (same binary):

- client — originates traffic only
- relay — forwards encrypted traffic, no exit (default for desktop/mobile)
- exit — connects to destination internet (opt-in, server installs)
- full — relay + exit (default for server installs)

-----

## REPOSITORY STRUCTURE
openmesh/
├── core/                  # Go — daemon, all networking logic
│   ├── cmd/
│   │   └── openmeshd/    # CLI daemon entrypoint
│   ├── transport/        # QUIC + WebSocket transport layer
│   ├── handshake/        # Noise_XX protocol + obfuscation
│   ├── probe/            # Active probe resistance + decoy server
│   ├── dht/              # Kademlia peer discovery
│   ├── routing/          # Circuit building, onion encryption
│   ├── node/             # Node capabilities, peer selection
│   └── config/           # Config loading, defaults, key management
├── mobile/               # Flutter — Android + iOS UI (iOS deferred)
│   ├── android/          # Kotlin VPN service wrapper
│   └── lib/              # Flutter UI
├── desktop/              # Flutter — macOS, Windows, Linux tray app
├── scripts/
│   └── install.sh        # One-line server installer
└── docs/
    └── operator.md       # Exit node legal notice template

-----

## COMPONENT SPECIFICATIONS

-----

### COMPONENT 1: Transport Layer (`core/transport/`)

Goal: Make all traffic look like normal HTTPS/HTTP3. Undetectable by DPI.

#### 1.1 Primary transport: QUIC over UDP 443

- Use quic-go library
- Mimic HTTP/3 TLS fingerprint
- ALPN: h3 (standard HTTP/3 value)
- Random-length padding appended to every packet
- Packet sizes normalized to: 256, 512, 1024, or 1400 bytes (random selection per packet)
- Inter-packet jitter: 1–30ms random delay injected

#### 1.2 Fallback transport: WebSocket over TCP 443

- Triggered automatically if QUIC fails after 3 seconds
- WebSocket upgrade request mimics a real browser (randomized User-Agent, standard headers)
- Payload framed as binary WebSocket frames

#### 1.3 Fallback 2: Raw TCP 443

- Plain TCP with obfuscated stream
- Used only if both QUIC and WS fail

#### 1.4 Transport selection algorithm
try QUIC(443) for 3s
  → success: use QUIC
  → fail: try WebSocket(443) for 3s
      → success: use WebSocket
      → fail: use TCP(443)

Selection is cached per peer for the session.

#### Implementation notes

- All transports implement a common Transport interface: Dial(), Listen(), Send(), Recv(), Close()
- Transport layer is unaware of routing/crypto above it

-----

### COMPONENT 2: Handshake & Encryption (`core/handshake/`)

Goal: Mutually authenticated, forward-secret session establishment that looks like random bytes.

#### 2.1 Protocol: Noise_XX with obfuscation wrapper

- Use flynn/noise Go library
- Pattern: Noise_XX_25519_ChaChaPoly_BLAKE2s
- Key exchange: X25519
- Cipher: ChaCha20-Poly1305
- Hash: BLAKE2s

#### 2.2 Obfuscation wrapper

The raw Noise handshake is wrapped to eliminate static byte patterns:
[First packet from client to server]:
  Bytes 0–31:   random padding (crypto/rand)
  Bytes 32–63:  HMAC-SHA256 probe token (see Component 3)
  Bytes 64+:    Noise_XX prologue + ephemeral key
                XOR'd with BLAKE2s(random_padding)

- No magic bytes, no static header, no version field visible
- Every handshake looks unique
- Server verifies probe token before proceeding (see Component 3)

#### 2.3 Session keys

After Noise_XX completes:

- Separate send/recv ChaCha20-Poly1305 keys derived
- Keys rotate every 10 minutes (rekeying via Noise rehandshake)
- Perfect forward secrecy: compromise of long-term key doesn’t expose past sessions

#### 2.4 Node identity

- Each node has an X25519 long-term keypair
- Generated on first run, stored in OS keychain (keyring library)
- Node ID = SHA-256(public_key), hex-encoded
- Public key distributed via DHT

-----

### COMPONENT 3: Active Probe Resistance (`core/probe/`)

Goal: Server reveals nothing to anyone who doesn’t know the network secret. Looks like a normal website to probers.

#### 3.1 Probe token
network_secret = 32-byte secret hardcoded in binary (rotated per release)
token = HMAC-SHA256(network_secret, floor(unix_timestamp / 3600))

- Token changes every hour
- Valid window: current hour ± 1 (handles clock skew)
- Embedded in first handshake packet bytes 32–63

#### 3.2 Server decision logic
incoming connection
    │
    ├─ extract bytes 32–63
    ├─ verify HMAC token
    │
    ├─ valid token ──► proceed with Noise handshake
    │
    └─ invalid/missing ──► hand off to decoy server

#### 3.3 Built-in decoy server

- Minimal HTTP/HTTPS server built into the binary (no nginx, no external deps)
- Serves a generic static page: blank portfolio / minimal “hello” page
- TLS cert: auto-generated self-signed, OR ACME (Let’s Encrypt) if domain is configured
- Default: self-signed (zero config required)
- Optional: user can set DECOY_DOMAIN=example.com env var to enable ACME

#### 3.4 Decoy page content

Baked into binary as a Go embed:
<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body>
  <p>This site is under construction.</p>
</body>
</html>

Simple, unremarkable, returns 200 OK to all GET requests.

-----

### COMPONENT 4: Peer Discovery — DHT (`core/dht/`)

Goal: Fully decentralized peer table. No directory servers. Self-healing.

#### 4.1 Protocol: Kademlia DHT

- Use or adapt libp2p/go-libp2p-kad-dht or implement minimal Kademlia
- Node ID space: 256-bit (SHA-256 of public key)
- k-bucket size: 20
- Alpha (concurrent lookups): 3

#### 4.2 Bootstrap

Hardcoded bootstrap nodes baked into binary:
var bootstrapNodes = []string{
    "bootstrap1.openmesh.net:443",
    "bootstrap2.openmesh.net:443",
    // ... 20-30 nodes across diverse ASNs and countries
}

- Bootstrap nodes are regular full nodes run by project maintainers
- After first connection, peer table persisted to disk (JSON file in data dir)
- On restart: load from disk first, then refresh via DHT
- App updates not required to discover new peers

#### 4.3 Peer record structure
{
  "id": "sha256hex",
  "pubkey": "base64_x25519_pubkey",
  "addrs": ["1.2.3.4:443", "hostname.example:443"],
  "relay": true,
  "exit": false,
  "exit_policy": {
    "ports": [443, 80],
    "blocklist": "default"
  },
  "country": "DE",
  "asn": 12345,
  "bandwidth_mbps": 10,
  "uptime_score": 0.95,
  "last_seen": 1712000000
}

#### 4.4 Peer scoring
score = (uptime_score * 0.4) + (bandwidth_score * 0.3) + (latency_score * 0.3)

- Uptime: rolling 7-day availability ratio
- Bandwidth: self-reported, verified by occasional probe
- Latency: measured at circuit build time

#### 4.5 Peer selection rules for circuit building

- Exit node: must be in different country than client
- No two hops in same ASN
- No two hops with same /24 IP subnet
- Prefer peers with uptime_score > 0.8
- Blacklist peers that fail 3 consecutive connection attempts

-----

### COMPONENT 5: Routing & Onion Encryption (`core/routing/`)

Goal: Multi-hop circuit with layered encryption. No single node sees both source and destination.

#### 5.1 Circuit establishment

1-hop:
Client generates:
  session_key_exit = X25519(client_ephemeral, exit_pubkey)

Sends to exit:
  CONNECT <destination> <port>
  (encrypted with session_key_exit via Noise)

2-hop:
Client establishes Noise session with Relay.
Through that session, client sends:
  EXTEND <exit_id> <exit_addr> <client_ephemeral_for_exit>
Relay connects to Exit, forwards ephemeral.
Exit responds with its ephemeral.
Client derives session_key_exit directly (relay never sees this key).
Client sends CONNECT <destination> encrypted for exit only.

3-hop: Same pattern extended one more level.

This is telescoping circuit construction — same approach as Tor.

#### 5.2 Onion packet format
struct OnionPacket {
    hop_count   uint8
    circuit_id  [16]byte  // random, per circuit
    payload     []byte    // encrypted, layer peeled at each hop
}

Each node decrypts its layer using the session key negotiated during circuit build. Passes remainder to next hop.

#### 5.3 Circuit lifecycle

- New circuit built on connect
- Circuit rotated every: 10 minutes OR 50MB transferred (whichever first)
- Failed circuit: rebuild immediately, max 3 retries before error shown to user
- Idle circuit kept alive with 30-second keepalive packets

#### 5.4 Stream multiplexing

- Multiple TCP streams (browser tabs, etc.) multiplexed over one circuit
- Stream ID: random 4-byte identifier
- Stream open/close/data messages over circuit

-----

### COMPONENT 6: Node Daemon (`core/cmd/openmeshd/`)

Goal: Single binary, cross-platform, minimal resource use.

#### 6.1 CLI interface
# Start as client (default)
openmeshd start --mode client --hops 2

# Start as relay
openmeshd start --mode relay --bandwidth 10

# Start as exit+relay
openmeshd start --mode exit --bandwidth 20

# Status
openmeshd status

# Peer list
openmeshd peers

#### 6.2 Config (auto-generated on first run, ~/.openmesh/config.json)
{
  "mode": "relay",
  "hops": 2,
  "bandwidth_limit_mbps": 10,
  "exit_policy": {
    "ports": [443],
    "blocklist": "default"
  },
  "data_dir": "~/.openmesh",
  "log_level": "warn"
}

User never needs to touch this file. All values have sane defaults.

#### 6.3 Key management

- Keys auto-generated on first run using crypto/rand
- Stored in OS keychain via 99designs/keyring library
- Fallback: encrypted file in data dir (password derived from machine ID)

#### 6.4 Resource limits

- RAM target: < 50MB idle, < 100MB under load
- CPU: 0% when idle (event-driven, no polling loops)
- Relay bandwidth: throttled to configured limit via token bucket
- Relay suspended automatically if: battery < 20% (mobile), system under high load

#### 6.5 Logging

- Default log level: WARN (almost silent in normal operation)
- No user traffic logged ever (not even metadata)
- Logs written to ~/.openmesh/daemon.log, rotated at 10MB

-----

### COMPONENT 7: Server Installer (`scripts/install.sh`)

Goal: One command to deploy a full/relay node on any Linux server.

#### 7.1 Script behavior
curl -sSL https://get.openmesh.net | sh

Script does:

1. Detect OS (Ubuntu/Debian/CentOS/Alpine)
1. Download correct binary for arch (amd64/arm64)
1. Verify SHA-256 checksum
1. Ask two questions interactively:
- “Relay only, or relay + exit? [relay/exit]”
- “Bandwidth limit in Mbps? [default: 10]”
1. Write config to /etc/openmesh/config.json
1. Install systemd service (or OpenRC for Alpine)
1. Enable and start service
1. Print: “OpenMesh node is running. Node ID: <id>”

Total time: ~30 seconds. No other input required.

#### 7.2 Systemd service file
[Unit]
Description=OpenMesh Node
After=network-online.target

[Service]
ExecStart=/usr/bin/openmeshd start
Restart=always
RestartSec=5
User=openmesh
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target

-----
### COMPONENT 8: Android Client (`mobile/android/`)

Goal: Dead-simple Android app. One toggle. Runs in background silently.

#### 8.1 VPN service

- Implements android.net.VpnService
- Routes all device traffic through OpenMesh circuit
- Foreground service with minimal notification: “OpenMesh active”
- Go core compiled to .aar via gomobile bind

#### 8.2 UI (Flutter)

Single screen:
┌─────────────────────────┐
│  OpenMesh               │
│                         │
│     [  O  ]  ← toggle  │
│                         │
│  ○ 1 hop  ● 2 hops  ○ 3│
│                         │
│  Contribute:            │
│  ● Relay  ○ Exit  ○ Off │
│                         │
│  [▲ 1.2 MB  ▼ 8.4 MB]  │
└─────────────────────────┘

Nothing else. No settings screen needed for basic use.

#### 8.3 Battery optimization

- When relay: suspend if battery < 20%
- Use JobScheduler for periodic DHT refresh (not constant background work)
- Active relay work is purely reactive (event-driven), zero CPU when no traffic

-----

### COMPONENT 9: Desktop App (`desktop/`)

Goal: System tray app, invisible when idle.

#### 9.1 Platforms: macOS, Windows, Linux

#### 9.2 Behavior

- Lives in system tray
- Left click: toggle on/off
- Right click menu:
  
   ● Connected (DE → exit)
  ─────────────────
  Hops: 1 | 2 | 3
  Mode: Relay | Exit | Off
  ─────────────────
  Status...
  Quit
  - No main window needed
- macOS: uses tray_manager Flutter plugin
- Windows: same
- Linux: AppIndicator

#### 9.3 Go core integration

- Desktop app shells the openmeshd daemon
- Communicates via local Unix socket / named pipe
- Daemon can also run standalone without the UI

-----

## IMPLEMENTATION TASKS FOR AI AGENT

Execute in order. Each task is independently completable.

-----

### TASK 1: Go module scaffold

File: core/go.mod, directory structure

- Init Go module github.com/openmesh/core
- Go version: 1.22+
- Create all package directories per repo structure above
- Add dependencies:
  - github.com/quic-go/quic-go
  - github.com/flynn/noise
  - github.com/gorilla/websocket
  - github.com/99designs/keyring
  - golang.org/x/crypto
- Create stub files with package declarations in each directory

-----

### TASK 2: Transport interface + QUIC implementation

Package: core/transport/

- Define Transport interface: Dial(addr string) (Conn, error), Listen(addr string) (Listener, error)
- Define Conn interface: Send([]byte) error, Recv() ([]byte, error), Close() error
- Implement QUICTransport using quic-go
  - ALPN: h3
  - TLS config mimicking Chrome HTTP/3 fingerprint
  - Packet padding to 256/512/1024/1400 bytes
  - Jitter: random 1–30ms delay on send
- Unit tests: dial/listen loopback, verify padding applied

-----

### TASK 3: WebSocket transport (fallback)

Package: core/transport/

- Implement WebSocketTransport
  - Browser-like upgrade headers
  - Binary frame mode
  - Same Transport interface as Task 2
- Implement AutoTransport: tries QUIC, falls back to WS, falls back to TCP
- Unit tests: fallback triggers correctly on connection failure

-----

### TASK 4: Noise handshake + obfuscation

Package: core/handshake/

- Implement Handshaker struct
- Client side: Initiate(conn Transport.Conn, serverPubkey []byte) (Session, error)
- Server side: Accept(conn Transport.Conn, privkey []byte) (Session, error)
- Obfuscation wrapper:
  - Prepend 32 random bytes
  - Embed probe token at bytes 32–63
  - XOR Noise prologue with BLAKE2s(random_bytes)
- Session struct: Encrypt([]byte) []byte, Decrypt([]byte) ([]byte, error), Rekey()
- Rekey every 10 minutes automatically
- Unit tests: full handshake roundtrip, verify no static bytes in output

-----

### TASK 5: Probe token + decoy server

Package: core/probe/

- Implement TokenValidator:
  - GenerateToken(networkSecret []byte) []byte
  - ValidateToken(token []byte, networkSecret []byte) bool
  - Valid window: current hour ± 1
- Implement DecoyServer:
  - HTTP/HTTPS server using net/http
  - Serves embedded HTML (use `//go:embed decoy/index.html`)
  - Auto-generates self-signed TLS cert on first run (stored in data dir)
  - Optional ACME via golang.org/x/crypto/acme/autocert if domain configured
- Implement ProbeGuard:
  - Wraps a listener
  - Inspects first packet bytes 32–63
  - Routes to Noise handshake or DecoyServer accordingly
- Unit tests: valid token routes correctly, invalid token gets decoy response

-----

### TASK 6: Key management + config

Package: core/config/

- Implement KeyStore:
  - Generate X25519 keypair on first run
  - Store via 99designs/keyring, fallback to encrypted file
  - GetPrivateKey() []byte, GetPublicKey() []byte, GetNodeID() string
- Implement Config struct (matches JSON schema in spec section 6.2)
- LoadConfig(path string) (*Config, error) — creates default if not exists
- SaveConfig(cfg *Config, path string) error
- All fields have defaults; empty config file is valid
- Unit tests: roundtrip load/save, key generation idempotent

-----

### TASK 7: Kademlia DHT

Package: core/dht/

- Implement minimal Kademlia:
  - Node struct with 256-bit ID, k-buckets (k=20)
  - Put(id, record), Get(id) record, FindNode(id) []PeerRecord
  - Iterative lookup with alpha=3
- PeerRecord struct (matches JSON schema in spec section 4.3)
- Bootstrap: connect to hardcoded nodes, populate initial table
- Persistence: save/load peer table to JSON file in data dir
- Peer scoring: implement score formula from spec section 4.4
- Unit tests: put/get roundtrip, node lookup converges, persistence

-----

### TASK 8: Peer selection

Package: core/node/

- Implement PeerSelector:
  - SelectCircuit(hops int, clientCountry string) ([]PeerRecord, error)
  - Enforces: different country for exit, no same ASN, no same /24
  - Prefers uptime_score > 0.8
  - Blacklists peers after 3 consecutive failures
- PeerAnnouncer: announces this node to DHT on startup, refreshes every 30 minutes
- Unit tests: selection respects all constraints, blacklist works

-----

### TASK 9: Circuit builder + onion routing

Package: core/routing/

- Implement CircuitBuilder:
  - Build(peers []PeerRecord, hops int) (*Circuit, error)
  - Telescoping construction per spec section 5.1
  - Each hop: establish Noise session, send EXTEND command
- Implement Circuit:
  - OpenStream(dst string, port int) (*Stream, error)
  - Close() error
  - Auto-rotate after 10 min or 50MB
- Implement Stream: Read([]byte), Write([]byte), Close()
- Stream multiplexing: multiple streams over one circuit with stream IDs
- Keepalive: 30-second ping packets on idle circuit
- Unit tests: build 1/2/3 hop circuits in loopback, stream data through

-----

### TASK 10: Relay/exit node logic

Package: core/routing/

- Implement RelayNode:
  - Accepts circuits from clients
  - Decrypts one onion layer
  - Forwards to next hop (relay or exit)
  - Never logs source, destination, or payload
- Implement ExitNode:
  - Accepts final hop circuits
  - Connects to destination via HTTPS (port 443 by default)
  - Exit policy enforcement: allowed ports, blocklist check
  - Default blocklist: fetch from public malware domain list on startup
- Bandwidth throttling: token bucket per connection, respects configured limit
- Unit tests: relay correctly forwards, exit connects to mock destination

-----

### TASK 11: Daemon entrypoint + CLI

Package: core/cmd/openmeshd/

- Wire all components together
- CLI using cobra:
  - openmeshd start [--mode client|relay|exit|full] [--hops 1|2|3] [--bandwidth N]
  - openmeshd status — print connected peers, circuit info, bandwidth used
  - openmeshd peers — list known peers with scores
  - openmeshd stop
- IPC: Unix socket (Linux/macOS) / named pipe (Windows) for GUI communication
- Signal handling: SIGTERM → graceful shutdown (close circuits, announce departure to DHT)
- Syslog-compatible structured logging via zerolog

-----

### TASK 12: Android integration

Directory: mobile/android/

- gomobile bind setup for core package → .aar
- OpenMeshVpnService.kt: extends VpnService, routes all traffic through Go core
- Start/stop via Flutter method channel
- Foreground notification: minimal, no sensitive info
- Battery check: pause relay below 20%

-----
### TASK 13: Flutter UI — Android

Directory: mobile/lib/

- Single screen per spec section 8.2
- State: connected/disconnected, hop count, mode, bytes transferred
- Toggle: calls VPN service start/stop
- Hop selector: 1/2/3 radio buttons
- Mode selector: Relay / Exit / Off
- Live bandwidth display: update every second
- No onboarding screen, no tutorial, no account required

-----

### TASK 14: Desktop tray app

Directory: desktop/

- Flutter desktop app
- System tray only — no main window
- Right-click menu per spec section 9.2
- Shells openmeshd daemon, communicates via IPC socket
- macOS/Windows/Linux support via tray_manager plugin

-----

### TASK 15: Server install script

File: scripts/install.sh

- Bash script per spec section 7.1
- Detects OS, downloads binary, verifies checksum
- Two interactive prompts only
- Installs systemd/OpenRC service
- Prints node ID on completion
- Test on: Ubuntu 22.04, Debian 12, CentOS 9, Alpine 3.19

-----

### TASK 16: Integration tests + CI

Directory: core/tests/integration/

- Spin up 5 test nodes in-process
- Test: 1-hop, 2-hop, 3-hop circuit establishment
- Test: probe resistance (invalid token gets decoy)
- Test: circuit rotation
- Test: node failure mid-circuit (should rebuild)
- Test: bandwidth throttling respected
- GitHub Actions workflow: run on PR, build all platforms

-----

## TECHNOLOGY DECISIONS SUMMARY

|Component        |Choice             |Reason                                            |
|-----------------|-------------------|--------------------------------------------------|
|Core language    |Go 1.22            |Cross-platform, small binary, excellent networking|
|QUIC             |quic-go            |Mature, well-maintained                           |
|Noise protocol   |flynn/noise        |Audited, simple API                               |
|DHT              |Custom Kademlia    |Control over peer record format                   |
|Crypto primitives|golang.org/x/crypto|Standard, audited                                 |
|Key storage      |99designs/keyring  |OS keychain integration                           |
|CLI              |cobra              |Standard Go CLI framework                         |
|Logging          |zerolog            |Zero-alloc, structured                            |
|Mobile UI        |Flutter            |Cross-platform, existing skill                    |
|Android VPN      |VpnService API     |Required by Android                               |

-----

## EXPLICITLY OUT OF SCOPE (v1)

- iOS client (deferred — requires Apple developer account + App Store submission)
- Incentive/credit system (pure altruism model)
- Web UI for node management
- Analytics or telemetry of any kind
- Accounts or authentication for users
- Payment or subscription system

-----

## BOOTSTRAP NODE REQUIREMENTS

Operators need ~5-10 always-on nodes at launch:

- Diverse countries (minimum 3 different countries)
- Diverse ASNs (no two on same provider)
- 1 Gbps unmetered preferred
- Run openmeshd start --mode full via install script
- These are regular nodes, not special — DHT does the rest

-----

## EXIT NODE OPERATOR NOTICE (built-in)

The decoy server automatically serves this notice at /.well-known/openmesh:
This server is a node in the OpenMesh network, a volunteer-operated
censorship circumvention network. This server forwards encrypted traffic
on behalf of users seeking access to the open internet. The operator of
this server does not select, initiate, or store any of the content or
connections passing through it. For more information: openmesh.net

This notice reduces law enforcement confusion and establishes conduit status.

-----

*End of specification v0.1*