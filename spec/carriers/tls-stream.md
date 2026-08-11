# TLS Stream Carrier Profile

**Status:** Draft
**Version:** 0.1
**Document:** Carrier Profile `ump.tls-stream/1`
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines the experimental TLS stream carrier profile for UMP.

It validates carrier encapsulation and outer-protocol integration: a UMP session running inside TLS.

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

---

# 3. Status

**Experimental in v0.1.**

It is not marketed as censorship-resistant merely because it uses TLS.

---

# 4. Profile requirements

## 4.1 Carrier Type ID

```text
ump.tls-stream/1
```

## 4.2 Packet mode and framing

* Packet mode: `STREAM_FRAMED`
* Framing: varint packet length followed by packet bytes, inside the TLS record stream

```text
Packet Length: Varint
Packet Bytes: Packet Length bytes
```

## 4.3 Reliability and ordering

* Reliability: `RELIABLE_UNTIL_LINK_FAILURE`
* Ordering: `ORDERED`

## 4.4 Connection model

* Connection model: `CONNECTED`

## 4.5 Listen and dial hints

* Listen hint: `host:port` binding selector with TLS server configuration
* Dial hint: `host:port` connection target with TLS client configuration

## 4.6 Packet-size bounds and initial MTU

* Generic UMP packet maximum: 65,535 bytes
* Initial MTU: generic packet maximum

## 4.7 Carrier Binding

* Binding kind: `CHANNEL_EXPORTER`
* Instance Data: TLS 1.3 exporter value bound to the connection
* The exporter is derived for UMP transcript use and MUST NOT expose the TLS master secret

## 4.8 Path Context

```text
carrier_type: ump.tls-stream/1
local_context: local address, port, and TLS identity context
remote_context: remote address, port, and TLS peer identity
scope
generation
```

## 4.9 Address rebinding

A TLS connection that reconnects creates a new Link.

Continuity requires channel-binding validation in the new handshake.

## 4.10 Discovery

None. TLS does not provide native discovery.

## 4.11 Outer security and authentication

* Outer encryption: TLS 1.3
* Peer authentication: TLS certificates or PSK as configured
* TLS peer identity is carrier evidence, NOT a UMP endpoint identity
* UMC MUST NOT equate TLS peer identity with Endpoint ID without an authenticated binding

## 4.12 Anti-probing

None claimed beyond TLS itself.

An unauthenticated probe sees TLS handshake behavior, not UMP. The profile does not claim indistinguishability from arbitrary TLS traffic.

## 4.13 Error mapping

| Condition | Carrier error |
| --- | --- |
| TLS handshake failure | `AUTHENTICATION_FAILED` |
| Certificate validation failure | `AUTHENTICATION_FAILED` |
| Connection refused | `UNREACHABLE` |
| Reset by peer | `LINK_FAILED` |
| Packet above limit | `PACKET_TOO_LARGE` |
| Send capacity exhausted | `WOULD_BLOCK` |

Outer security failure closes the Link.

UMP does not fall back to an insecure carrier mode inside the same Link.

## 4.14 Backpressure

* Bounded send and receive queues per Link
* TLS record and TCP queue state feed carrier backpressure
* UMP SHOULD keep carrier write queues short

## 4.15 Scope and cost classification

* Scope evidence: address classes and configuration
* Cost: `UNMETERED` or `METERED` by configuration

## 4.16 Resource-limit defaults

```text
Pending accepts per listener: 128
Concurrent dials per instance: 64
Send queue per Link: 256 packets or 2 MiB
Receive queue per Link: 256 packets or 2 MiB
```

## 4.17 Privacy exposure

* TLS hides UMP payload from passive observers of the connection
* Addresses, timing, sizes, and connection duration remain visible
* The profile is identifiable as TLS traffic
* Endpoint identity stays inside UMP encryption

## 4.18 Required interoperability tests

1. TLS 1.3 handshake with exporter binding.
2. Channel-binding vector validation.
3. TLS peer identity not treated as endpoint identity.
4. Outer security failure closing the Link without fallback.
5. UMP session over TLS with migration to TCP or UDP.
6. Framing inside TLS record streams.
7. Certificate and PSK authentication modes.

---

# 5. Session interaction

The session layer behaves as over any reliable ordered carrier:

* Packet numbers, ACKs, flow control, and key updates remain active
* Rapid packet-threshold retransmission MAY be suppressed
* An end-to-end probe timeout MUST remain

---

# 6. Core rule

The TLS stream carrier runs UMP inside TLS 1.3 with the connection exporter bound into the handshake transcript.

It validates outer-encryption integration without claiming censorship resistance. TLS peer identity remains carrier evidence, outer failure never falls back to insecure mode, and the UMP session remains independent of the TLS connection.
