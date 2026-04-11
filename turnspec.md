- This registration uses the same call link credentials

-----

## TRAFFIC SHAPING (avoiding detection by behavioral analysis)

Raw OpenMesh traffic through TURN would look suspicious — bursty, asymmetric,
non-audio/video shaped. Add realistic shaping:

- Bitrate mimicry: traffic rate follows a realistic video call bitrate curve
  (300-800 kbps baseline with natural variance)
- Packet sizing: normalize to WebRTC-typical packet sizes (1200-1400 bytes)
- Silence padding: when no real data, send dummy packets at audio-call rate (~50 pps)
  to mimic “call ongoing” pattern
- Session duration: rotate TURN channel every 30-60 minutes (natural call length)

-----

## AUTO-DETECTION AND FALLBACK

TURN transport is not always needed. Activate automatically:
Normal startup:
  try standard QUIC transport
    → success: use standard transport (faster, lower latency)
    → fail after 5s: whitelist likely active

Whitelist fallback:
  try VK TURN provider
    → success: use VK TURN
    → fail after 10s:
  try Yandex TURN provider
    → success: use Yandex TURN
    → fail after 10s:
  try Mail.ru TURN provider
    → success: use Mail.ru TURN
    → fail: show error "no transport available"

User sees in UI: normal connected indicator, or “Limited mode (via relay)” — nothing more.

-----

## RESILIENCE ANALYSIS

|Attack                               |Result                                                        |
|-------------------------------------|--------------------------------------------------------------|
|Block VK TURN IPs                    |VK video calls break for all Russians — politically impossible|
|Block Yandex TURN IPs                |Yandex Meet breaks — same                                     |
|Block all STUN/TURN ports            |All WebRTC breaks (Zoom, Teams, etc) — unacceptable           |
|Inspect DTLS payload                 |Encrypted — nothing visible                                   |
|Rate-limit TURN relay traffic        |Degrades video calls for everyone — unacceptable              |
|VK changes TURN auth algorithm       |Fallback to Yandex/Mail.ru, update binary                     |
|All 3 providers change simultaneously|Extremely unlikely, binary update fixes it                    |

-----

## LIMITATIONS

- Latency: adds ~20-60ms vs direct connection (TURN relay hop)
- Bandwidth: TURN servers may throttle at ~5-10 Mbps (per VK repo observations)
  — sufficient for browsing and most use cases, not ideal for large downloads
- Provider dependency: requires at least one working TURN provider with valid creds
- Not applicable to WiFi: standard transport works fine on WiFi, this is mobile-only fallback

-----

## IMPLEMENTATION TASKS

-----

### TASK T1: TURN provider interface + VK implementation

Package: core/transport/turn/

- Define TurnProvider interface (see above)
- Implement VKTurnProvider:
  - Parse VK call link, extract token
  - Derive TURN credentials via HMAC (reverse-engineer from vk-turn-proxy source)
  - Return list of VK TURN server addresses
  - Support both TCP and UDP modes
- Hardcode pool of 10 valid VK call links in binary
- Unit tests: credential generation, TURN addr resolution

Reference implementation to study:
github.com/cacggghp/vk-turn-proxy (Go, MIT-compatible for study)

-----

### TASK T2: Yandex Telemost TURN provider

Package: core/transport/turn/

- Implement YandexTurnProvider
- Reverse-engineer Yandex Telemost WebRTC credential flow:
  - Create a Telemost meeting, capture WebRTC ICE candidates via browser devtools
  - Extract TURN server addresses and credential derivation
- Hardcode pool of 10 valid Telemost meeting links
- Unit tests: same as T1

-----

### TASK T3: Mail.ru TURN provider

Package: core/transport/turn/

- Implement MailRuTurnProvider
- Same approach as T2 — capture via browser devtools during a Mail.ru call
- Hardcode credential pool
- Unit tests: same as T1

-----

### TASK T4: DTLS transport wrapper

Package: core/transport/turn/

- Implement DTLS 1.2 framing around OpenMesh packets
- Use pion/dtls Go library
# OpenMesh — TURN Whitelist Bypass Transport

### Spec v0.1 | Addendum to core OpenMesh spec

### Component: core/transport/turn/

-----

## PROBLEM

When a Russian mobile carrier activates IP whitelist mode, only government-approved IP
ranges are routable. All direct connections to foreign OpenMesh peers are dropped at the
carrier routing layer before they arrive. Standard transports (QUIC, WebSocket, TCP) all
fail because the destination IP is not whitelisted.

## SOLUTION

Route OpenMesh traffic through Russian WebRTC TURN servers operated by whitelisted
Russian services (VK, Yandex, Mail.ru, etc). These TURN servers act as unwitting relays
— they are designed to forward arbitrary encrypted UDP between WebRTC peers, and they
will never be blocked because doing so would break video calling for millions of Russian
users.

-----

## HOW TURN RELAYING WORKS

TURN (Traversal Using Relays around NAT) is standard WebRTC infrastructure. When two
WebRTC peers can’t connect directly, a TURN server relays packets between them:
Peer A ──[DTLS encrypted]──► TURN server ──[DTLS encrypted]──► Peer B

The TURN server forwards raw encrypted bytes. It cannot inspect content. It was designed
exactly for this — general-purpose relay of encrypted UDP. OpenMesh exploits this by
being “Peer B” abroad.

Traffic on the wire looks identical to a VK/Yandex video call. Indistinguishable.

-----

## ARCHITECTURE
[OpenMesh client - Russia, whitelist active]
    │
    │  DTLS 1.2 (standard WebRTC)
    │  STUN ChannelData framing
    │
    ▼
[VK / Yandex / Mail.ru TURN server]
    │  (whitelisted IP, can't be blocked)
    │
    │  UDP relay (standard TURN behavior)
    │
    ▼
[OpenMesh relay node - abroad]
    │
    ▼
[Internet]

The TURN server sees: two WebRTC peers exchanging encrypted data.
The carrier sees: traffic to a whitelisted Russian IP.
Nobody sees: that this is OpenMesh traffic.

-----

## TURN PROVIDER REGISTRY

Multiple providers implemented for resilience. If one changes auth or rate-limits,
others take over automatically.

### Provider 1: VK Calls

- TURN server: turn.zingaya.com and related VK infrastructure
- Auth: HMAC-derived credentials from a VK call link
- Call link format: https://vk.com/call/join/<token>
- Link validity: permanent unless “end call for all” is pressed
- Protocol: STUN ChannelData over TCP or UDP
- Proven by: github.com/cacggghp/vk-turn-proxy

### Provider 2: Yandex Telemost

- TURN server: Yandex WebRTC infrastructure
- Auth: derived from Telemost meeting link
- Same STUN/TURN protocol

### Provider 3: Mail.ru TrueConf / Calls

- Same VK holding company, different TURN cluster
- Redundancy for VK

### Provider interface (Go):
type TurnProvider interface {
    Name() string
    GetCredentials() (username, password string, err error)
    TurnAddrs() []string   // list of TURN server addresses
    Protocol() string      // "tcp" or "udp"
}

New providers can be added without changing core logic.

-----

## CREDENTIAL MANAGEMENT

Each provider needs a call/meeting link to derive TURN credentials from.

For the user this is invisible. The client ships with:

- A pool of pre-generated, permanently valid call links per provider
- Links hardcoded in binary (like bootstrap nodes)
- Rotated via binary update if a provider invalidates them
- Multiple links per provider for redundancy

User never needs to create a VK account or generate a link themselves.

-----

## TRANSPORT IMPLEMENTATION

### Packet flow (client side)
OpenMesh onion packet
    │
    └─ wrapped in DTLS 1.2 record
         └─ framed as STUN ChannelData message
              └─ sent to TURN server via TCP/UDP
                   └─ TURN server relays to OpenMesh node abroad

### Packet flow (server side - OpenMesh node abroad)
TURN server sends UDP packet to node's public IP:port
    │
    └─ unwrap STUN ChannelData
         └─ unwrap DTLS
              └─ standard OpenMesh onion packet processing

The abroad node must:

- Listen on a UDP port reachable from TURN server
- Register with the TURN server as the other peer in the channel
- Input: raw OpenMesh onion packet bytes
- Output: DTLS record ready for STUN ChannelData wrapping
- Must be compatible with TURN server expectations (standard DTLS)
- Unit tests: encode/decode roundtrip

-----

### TASK T5: STUN ChannelData framing

Package: core/transport/turn/

- Implement STUN ChannelData message encoding/decoding per RFC 5766
- Channel number negotiation with TURN server (TURN ALLOCATE + CHANNEL-BIND)
- Maintain channel lifecycle (refresh every 10 minutes per RFC)
- Support both TCP framing (4-byte length prefix) and UDP
- Use pion/stun Go library for base STUN primitives
- Unit tests: encode/decode, channel refresh

-----

### TASK T6: TURN session manager

Package: core/transport/turn/

- Implement TurnSession:
  - Dial(provider TurnProvider, peerAddr string) (*TurnConn, error)
  - Handles: ALLOCATE → CHANNEL-BIND → data relay
  - TurnConn implements standard transport.Conn interface
    (same interface as QUIC/WebSocket transports)
  - Session rotation every 30-60 minutes (random, mimics natural call length)
- Implement TurnListener for the abroad node side:
  - Registers with TURN server as second peer
  - Receives relayed packets
  - Also implements transport.Listener interface
- Unit tests: full dial/listen loopback via mock TURN server

-----

### TASK T7: Traffic shaping

Package: core/transport/turn/

- Implement ShapedTurnConn wrapping TurnConn:
  - Token bucket rate limiter: target 300-800 kbps baseline
  - Packet size normalization: pad to 1200-1400 bytes
  - Keepalive dummy packets when idle: ~50 packets/sec at small size
  - Natural variance: ±20% bitrate jitter using Gaussian distribution
- This wrapper is applied automatically when using TURN transport
- Unit tests: verify output bitrate within expected range, verify padding

-----

### TASK T8: Auto-detection and fallback integration

Package: core/transport/

- Extend existing AutoTransport (from core Task 3):
  - Add TURN providers as final fallback tier
  - Detection: QUIC/WS both fail within 5s → activate TURN fallback
  - Try providers in order: VK → Yandex → Mail.ru
  - Cache which provider worked, retry others on failure
- UI signal: expose transport mode via IPC so UI can show “Limited mode”
- Unit tests: fallback triggers correctly, provider rotation works

-----

### TASK T9: Abroad node TURN registration

Package: core/node/

- Abroad OpenMesh nodes that want to accept TURN-relayed connections must:
  - Maintain active TURN allocations on all configured providers
  - Advertise in DHT peer record: "turn_capable": true, "turn_providers": ["vk", "yandex"]
  - Keep TURN allocations alive (refresh every 10 min)
- TurnCapableNode struct handles this lifecycle
- Only exit/full nodes need this — relay-only nodes skip it
- Unit tests: allocation refresh, DHT advertisement

-----

### TASK T10: Integration test — full whitelist simulation

Directory: core/tests/integration/

- Spin up mock TURN server (pion/turn has a test server)
- Simulate whitelist: iptables rules blocking all non-TURN traffic
- Test: client connects to abroad node exclusively via TURN relay
- Test: auto-detection triggers correctly when direct fails
- Test: provider fallback when primary TURN fails
- Test: traffic shaping output matches expected bitrate profile
- Test: full HTTP request through TURN-relayed OpenMesh circuit

-----

## DEPENDENCIES TO ADD
github.com/pion/dtls/v2     — DTLS 1.2
github.com/pion/stun        — STUN protocol
github.com/pion/turn/v2     — TURN client + test server

All from the pion WebRTC family — well-maintained, production-grade, used by major
WebRTC implementations.

-----

## FILES TO CREATE
core/transport/turn/
├── provider.go          — TurnProvider interface
├── vk.go               — VK provider implementation
├── yandex.go           — Yandex provider implementation  
├── mailru.go           — Mail.ru provider implementation
├── dtls.go             — DTLS framing
├── stun.go             — STUN ChannelData framing
├── session.go          — TurnSession + TurnConn + TurnListener
├── shaping.go          — Traffic shaping wrapper
├── credentials.go      — Hardcoded call link pool + credential derivation
└── turn_test.go        — All unit + integration tests

-----

*End of TURN transport spec v0.1*