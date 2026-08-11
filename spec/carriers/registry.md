# Universal Mesh Carrier Registry

**Status:** Draft
**Version:** 0.1
**Document:** Complete Carrier Type Registry
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document is the canonical registry of every UMP carrier type: carriers that exist, carriers planned, and carriers possible to route through.

A carrier is a mechanism that transfers complete UMP packets between adjacent peers. Any carrier in this registry MAY carry sessions, relays, routing messages, or discovery traffic according to its capabilities.

This document does not define the Carrier API (that is `carrier-api.md`). It defines the catalog of Carrier Type IDs and their profile requirements.

---

# 2. Registry rules

## 2.1 Allocation

Carrier Type IDs are allocated through the UMEP registries.

Registry assignment does not imply endorsement.

Stable allocations require a UMEP or maintainer-approved allocation.

## 2.2 Private range

Private profiles use:

```text
x-<organization>.<name>/<version>
```

Private ranges are available without central approval.

## 2.3 Status classes

| Status | Meaning |
| --- | --- |
| `stable` | Interoperable v0.1 baseline; full normative profile |
| `experimental` | Shipped but not stable; marked; may change |
| `planned` | Committed roadmap carrier; profile to be written |
| `possible` | Registry-reserved for future media; no commitment |
| `discovery-only` | Produces candidates; does not carry UMP data packets |

## 2.4 Lifecycle

Promotion from `experimental` to `stable` requires:

* A UMEP where protocol-affecting
* A completed normative profile
* Interoperability tests
* Security review
* Resource-exhaustion analysis

---

# 3. Master table

| Type ID | Status | Medium | Packet mode | Reliable | Ordered | Connection model | Route-through |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ump.tcp/1` | stable | Internet TCP | STREAM_FRAMED | Yes | Yes | CONNECTED | Yes |
| `ump.udp/1` | stable | Internet UDP | DATAGRAM | No | No | CONNECTIONLESS_ASSOCIATION | Yes |
| `ump.lan-discovery/1` | stable | LAN multicast | MESSAGE | No | No | SHARED_CHANNEL | Discovery only |
| `ump.tls-stream/1` | experimental | TCP + TLS 1.3 | STREAM_FRAMED | Yes | Yes | CONNECTED | Yes |
| `ump.bluetooth/1` | planned | Bluetooth BR/EDR RFCOMM | STREAM_FRAMED | Yes | Yes | CONNECTED | Yes |
| `ump.bluetooth-le/1` | planned | Bluetooth LE GATT | MESSAGE | No | No | CONNECTIONLESS_ASSOCIATION | Yes |
| `ump.wifi-direct/1` | planned | Wi-Fi P2P | DATAGRAM or STREAM_FRAMED | profile | profile | CONNECTED | Yes |
| `ump.local-wifi/1` | planned | Infrastructure Wi-Fi L2/L3 | profile | profile | profile | SHARED_CHANNEL | Yes |
| `ump.websocket/1` | planned | WebSocket over TCP/TLS | MESSAGE | Yes | Yes | CONNECTED | Yes |
| `ump.webrtc/1` | planned | WebRTC data channel | DATAGRAM | No | No | CONNECTED | Yes |
| `ump.http/1` | planned | HTTP-shaped family (h1/h2/h3) | MESSAGE | Yes | Yes | CONNECTED | Yes |
| `ump.serial/1` | planned | Serial links | RAW_FRAMED | profile | Yes | CONNECTED | Yes |
| `ump.radio/1` | planned | Packet radio family (AX.25, LoRa) | RAW_FRAMED | No | profile | SHARED_CHANNEL | Yes |
| `ump.ethernet/1` | possible | Raw Ethernet L2 | RAW_FRAMED | No | No | SHARED_CHANNEL | Yes |
| `ump.quic/1` | possible | QUIC streams | STREAM_FRAMED | Yes | Yes | CONNECTED | Yes |
| `ump.sctp/1` | possible | SCTP | STREAM_FRAMED | Yes | Yes | CONNECTED | Yes |
| `ump.usb/1` | possible | USB bulk transport | STREAM_FRAMED | Yes | Yes | CONNECTED | Yes |
| `ump.loopback/1` | possible | Shared memory / local socket | STREAM_FRAMED | Yes | Yes | CONNECTED | Yes |
| `ump.nfc/1` | possible | NFC | MESSAGE | No | No | INTERMITTENT | Bootstrap/admission |
| `ump.infrared/1` | possible | IrDA | MESSAGE | No | No | INTERMITTENT | Yes |
| `ump.satellite/1` | possible | Satellite links | DATAGRAM or RAW_FRAMED | No | No | INTERMITTENT | Yes |
| `ump.acoustic/1` | possible | Acoustic / sound | MESSAGE | No | No | SHARED_CHANNEL | Yes |
| `ump.bp/1` | possible | Bundle Protocol (BPv7) encapsulation | MESSAGE | No | No | INTERMITTENT | Yes |
| `x-<org>.<name>/<version>` | private | Operator-defined | profile | profile | profile | profile | profile |

---

# 4. Stable carriers

## 4.1 `ump.tcp/1` — TCP stream carrier

Profile document: `spec/carriers/tcp.md`

* Packet mode: STREAM_FRAMED (varint length prefix)
* Reliability: RELIABLE_UNTIL_LINK_FAILURE
* Ordering: ORDERED
* Connection model: CONNECTED
* Initial MTU: generic packet maximum
* Binding: PROFILE_ONLY
* Discovery: none
* Route-through: full session, relay, and routing traffic

## 4.2 `ump.udp/1` — UDP datagram carrier

Profile document: `spec/carriers/udp.md`

* Packet mode: DATAGRAM (one datagram, one packet)
* Reliability: UNRELIABLE
* Ordering: UNORDERED
* Connection model: CONNECTIONLESS_ASSOCIATION
* Initial MTU: 1,200 bytes until path MTU discovery
* Binding: PROFILE_ONLY
* Discovery: none
* Route-through: full session, relay, and routing traffic

## 4.3 `ump.lan-discovery/1` — LAN discovery carrier

Profile document: `spec/carriers/lan-discovery.md`

* Packet mode: MESSAGE
* Reliability: UNRELIABLE
* Ordering: UNORDERED
* Connection model: SHARED_CHANNEL
* Discovery: native announcements
* Route-through: discovery only; sessions use UDP or TCP
* Binding: PROFILE_ONLY

---

# 5. Experimental carriers

## 5.1 `ump.tls-stream/1` — TLS stream carrier

Profile document: `spec/carriers/tls-stream.md`

* Packet mode: STREAM_FRAMED
* Reliability: RELIABLE_UNTIL_LINK_FAILURE
* Ordering: ORDERED
* Connection model: CONNECTED
* Outer encryption: TLS 1.3
* Binding: CHANNEL_EXPORTER
* Route-through: full session and relay traffic
* Status note: validates outer-encryption integration. Not marketed as censorship-resistant merely because it uses TLS.

---

# 6. Planned carriers

## 6.1 `ump.bluetooth/1` — Bluetooth BR/EDR

* Packet mode: STREAM_FRAMED (RFCOMM) or MESSAGE (L2CAP PSM) by profile
* Reliability: RELIABLE_UNTIL_LINK_FAILURE
* Ordering: ORDERED
* Connection model: CONNECTED
* Discovery: native inquiry and service discovery
* Outer security: link-layer pairing keys; binding kind LOCAL_LINK_CONTEXT or CHANNEL_EXPORTER
* Scope: LINK_LOCAL
* Power: ENERGY_CONSTRAINED typical
* Route-through: local sessions and relays

## 6.2 `ump.bluetooth-le/1` — Bluetooth LE

* Packet mode: MESSAGE (GATT notifications / L2CAP CoC)
* Reliability: UNRELIABLE (notification) or reliable (CoC) by profile
* Ordering: UNORDERED
* Connection model: CONNECTIONLESS_ASSOCIATION or CONNECTED by profile
* Discovery: GATT advertisement scanning
* MTU: small (negotiated ATT MTU)
* Scope: LINK_LOCAL
* Route-through: small local sessions, bundle handoff

## 6.3 `ump.wifi-direct/1` — Wi-Fi P2P

* Packet mode: profile-defined (UDP-like datagrams or TCP-like streams over P2P)
* Connection model: CONNECTED
* Discovery: P2P service discovery
* Scope: LOCAL_NETWORK
* Route-through: local sessions and relays

## 6.4 `ump.local-wifi/1` — Infrastructure Wi-Fi

* Packet mode: profile-defined (L2 frames or L3 UDP/TCP reuse)
* Connection model: SHARED_CHANNEL
* Scope: LOCAL_NETWORK
* Route-through: local sessions; must not infer trust from SSID

## 6.5 `ump.websocket/1` — WebSocket

* Packet mode: MESSAGE (one UMP packet per WebSocket message)
* Reliability: RELIABLE_UNTIL_LINK_FAILURE
* Ordering: ORDERED
* Connection model: CONNECTED
* Outer security: TLS when wss://
* Binding: CHANNEL_EXPORTER when TLS
* Scope: GENERAL_NETWORK
* Route-through: browser-accessible sessions and relays

## 6.6 `ump.webrtc/1` — WebRTC data channel

* Packet mode: DATAGRAM (unordered) or MESSAGE (ordered) per data-channel type
* Reliability: UNRELIABLE by default; ordered mode available
* Ordering: UNORDERED or ORDERED by negotiated channel type
* Connection model: CONNECTED
* Discovery: signaling via application (out of core)
* Binding: CHANNEL_EXPORTER (DTLS)
* Scope: GENERAL_NETWORK
* Route-through: browser sessions; NAT traversal helper

## 6.7 `ump.http/1` — HTTP-shaped carrier family

* Packet mode: MESSAGE (HTTP/1.1 chunked, HTTP/2 streams, HTTP/3 QUIC streams)
* Reliability: RELIABLE_UNTIL_LINK_FAILURE
* Ordering: ORDERED
* Connection model: CONNECTED
* Framing: HTTP message boundaries; one UMP packet per request/response payload
* Outer security: TLS mandatory for https-shaped profiles
* Binding: CHANNEL_EXPORTER
* Anti-probing: carrier-consistent HTTP behavior for unauthenticated probes (profile-defined)
* Scope: GENERAL_NETWORK
* Route-through: full sessions; primary mimicry family

## 6.8 `ump.serial/1` — Serial links

* Packet mode: RAW_FRAMED (delimiting, escaping, resynchronization)
* Reliability: PROFILE_DEFINED (no flow control → lossy; hardware flow control → reliable)
* Ordering: ORDERED
* Connection model: CONNECTED
* MTU: small, profile-defined
* Scope: LINK_LOCAL
* Route-through: local sessions, bundle handoff

## 6.9 `ump.radio/1` — Packet radio family

* Packet mode: RAW_FRAMED
* Reliability: UNRELIABLE
* Ordering: PROFILE_DEFINED (AX.25 sequential; LoRa unordered)
* Connection model: SHARED_CHANNEL or INTERMITTENT
* MTU: small
* Scope: LINK_LOCAL
* Route-through: local mesh sessions, bundle handoff; primary local non-internet candidate

---

# 7. Possible carriers

Reserved for future media. No implementation commitment.

## 7.1 `ump.ethernet/1` — Raw Ethernet L2

* RAW_FRAMED, UNRELIABLE, UNORDERED, SHARED_CHANNEL
* Ethernet type field encapsulation; MTU 1,500 typical
* Scope: LOCAL_NETWORK

## 7.2 `ump.quic/1` — QUIC transport

* STREAM_FRAMED over QUIC streams; RELIABLE_UNTIL_LINK_FAILURE, ORDERED, CONNECTED
* Outer encryption: QUIC TLS 1.3; CHANNEL_EXPORTER binding
* Scope: GENERAL_NETWORK

## 7.3 `ump.sctp/1` — SCTP

* STREAM_FRAMED over SCTP streams; RELIABLE, ORDERED, CONNECTED
* Scope: GENERAL_NETWORK

## 7.4 `ump.usb/1` — USB bulk transport

* STREAM_FRAMED; RELIABLE_UNTIL_LINK_FAILURE, ORDERED, CONNECTED
* Scope: LINK_LOCAL

## 7.5 `ump.loopback/1` — Shared memory or local socket

* STREAM_FRAMED over Unix socket / shared memory
* RELIABLE_UNTIL_LINK_FAILURE, ORDERED, CONNECTED
* Scope: LOOPBACK
* Route-through: same-host application and daemon separation

## 7.6 `ump.nfc/1` — NFC

* MESSAGE, UNRELIABLE, UNORDERED, INTERMITTENT
* Tiny MTU; used for bootstrap, invitation, and admission, not bulk traffic
* Scope: LINK_LOCAL

## 7.7 `ump.infrared/1` — IrDA

* MESSAGE, UNRELIABLE, UNORDERED, INTERMITTENT
* Scope: LINK_LOCAL

## 7.8 `ump.satellite/1` — Satellite links

* DATAGRAM or RAW_FRAMED; UNRELIABLE, UNORDERED, INTERMITTENT
* High latency; large PTO profile
* Scope: GENERAL_NETWORK or LOCAL per deployment

## 7.9 `ump.acoustic/1` — Acoustic

* MESSAGE, UNRELIABLE, UNORDERED, SHARED_CHANNEL
* Very small MTU; scope LINK_LOCAL

## 7.10 `ump.bp/1` — Bundle Protocol encapsulation

* Encapsulates UMP packets inside BPv7 bundles
* MESSAGE, UNRELIABLE, UNORDERED, INTERMITTENT
* Lets UMP route through existing DTN infrastructure
* Scope: profile-defined

---

# 8. Route-through capability

## 8.1 Transport carriers

Transport carriers carry UMP packets between adjacent peers:

```text
TCP, UDP, TLS, Bluetooth, Wi-Fi variants, WebSocket, WebRTC, HTTP family,
serial, radio, Ethernet, QUIC, SCTP, USB, loopback, satellite, acoustic, BP
```

Sessions, relays, routing frames, and bundles MAY route through them according to policy.

## 8.2 Discovery-only carriers

Discovery-only carriers produce candidates:

```text
LAN discovery
```

They do not carry UMP data packets. Sessions use a transport carrier.

## 8.3 Bridge and admission carriers

Bridge or admission carriers transfer small payloads for bootstrap and admission:

```text
NFC, invitation QR channels, removable media
```

They are not general session carriers.

## 8.4 Intermittent carriers

Intermittent carriers (radio, satellite, acoustic, BP, NFC) support:

* Bundle handoff
* Delayed delivery
* Contact hints
* Migration between connectivity windows

They MUST use the bundle and disruption-tolerant semantics from `bundles.md`.

---

# 9. Local non-internet requirement

At least one local non-internet carrier SHOULD be added after the core protocol stabilizes.

Candidates in the registry:

```text
ump.bluetooth/1
ump.radio/1
ump.serial/1
ump.ethernet/1
```

Local carriers MUST NOT infer trust from:

* Local presence
* SSID
* Bluetooth name
* Link-layer address

---

# 10. Profile requirements

Every carrier profile (stable or experimental) MUST define the 18 items from `carrier-api.md` section 53:

1. Carrier Type ID and version.
2. Packet mode and framing.
3. Reliability and ordering.
4. Connection model.
5. Listen and dial hints.
6. Packet-size bounds and initial MTU.
7. Carrier Binding kind and Instance Data.
8. Path Context fields.
9. Address rebinding behavior.
10. Discovery behavior, if any.
11. Outer security and authentication.
12. Anti-probing behavior, if claimed.
13. Error mapping.
14. Backpressure behavior.
15. Scope and cost classification evidence.
16. Resource-limit defaults.
17. Privacy exposure.
18. Required interoperability tests.

A profile MUST reject ambiguity in packet boundaries, binding input, or target selection.

---

# 11. Open decisions

1. Whether Bluetooth BR/EDR and BLE share one profile.
2. HTTP-shaped profile variants (h1/h2/h3) as one family or separate IDs.
3. Radio family sub-profiles (AX.25, LoRa, Meshtastic-style).
4. Whether `ump.loopback/1` ships in v0.1 for testing.
5. BP encapsulation framing.
6. Satellite PTO and idle-timeout profile.
7. Whether NFC is a carrier or an invitation channel.
8. Promotion order for planned carriers.

---

# 12. Core rule

The carrier registry catalogs every medium UMP can route through, from the stable TCP, UDP, and LAN-discovery baseline to planned Bluetooth, Wi-Fi, WebSocket, WebRTC, HTTP-shaped, serial, and radio carriers, and possible future media.

Every entry records packet mode, reliability, ordering, connection model, binding, discovery, and scope so implementers know what each carrier can carry. Transport carriers carry sessions and relays, discovery-only carriers produce candidates, intermittent carriers support bundles, and private ranges let any operator add a medium without central approval.
