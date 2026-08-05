# TCP Carrier Profile

**Status:** Draft
**Version:** 0.1
**Document:** Carrier Profile `ump.tcp/1`
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines the native TCP carrier profile for UMP.

It is one of the three stable v0.1 carriers.

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

The carrier API specification (`carrier-api.md`) defines the interface. This profile defines the medium behavior.

---

# 3. Profile requirements

## 3.1 Carrier Type ID

```text
ump.tcp/1
```

## 3.2 Packet mode and framing

* Packet mode: `STREAM_FRAMED`
* Framing: varint packet length followed by packet bytes

```text
Packet Length: Varint
Packet Bytes: Packet Length bytes
```

* The packet length excludes the length prefix itself
* One TCP connection MAY carry packets for one or more sessions depending on negotiated multiplexing
* The stream parser MUST enforce a maximum packet length before allocation

## 3.3 Reliability and ordering

* Reliability: `RELIABLE_UNTIL_LINK_FAILURE`
* Ordering: `ORDERED`

The carrier preserves each accepted packet without silent loss while the Link remains healthy.

## 3.4 Connection model

* Connection model: `CONNECTED`

## 3.5 Listen and dial hints

* Listen hint: `host:port` binding selector
* Dial hint: `host:port` connection target
* Ports MUST NOT be fixed by the protocol
* Nodes SHOULD support random or configured ports

## 3.6 Packet-size bounds and initial MTU

* Generic UMP packet maximum: 65,535 bytes
* Stream-carrier maximum packet length: enforced before allocation
* Initial MTU: generic packet maximum

## 3.7 Carrier Binding

* Binding kind: `PROFILE_ONLY`
* Instance Data: carrier profile identifier and negotiated connection context
* Plain TCP has no channel exporter

## 3.8 Path Context

```text
carrier_type: ump.tcp/1
local_context: local address and port
remote_context: remote address and port
scope
generation
```

## 3.9 Address rebinding

A TCP connection that reconnects creates a new Link.

It does not rebind an old Link unless the profile defines continuity with secure channel binding.

## 3.10 Discovery

None. TCP does not provide native discovery.

## 3.11 Outer security and authentication

* None by default
* The TLS variant is a separate carrier: `ump.tls-stream/1`

## 3.12 Anti-probing

None claimed.

The native TCP profile is recognizable as UMP to an observer (optional `UMP1` magic and framed packets).

## 3.13 Error mapping

| Condition | Carrier error |
| --- | --- |
| Connection refused | `UNREACHABLE` |
| Timeout | `DEADLINE_EXCEEDED` |
| Reset by peer | `LINK_FAILED` |
| Packet above limit | `PACKET_TOO_LARGE` |
| Send capacity exhausted | `WOULD_BLOCK` |
| Port in use | `ADDRESS_IN_USE` |

## 3.14 Backpressure

* Bounded send and receive queues per Link
* The carrier MUST NOT accept an unbounded number of packets or bytes
* UMP SHOULD avoid building a large queue above the carrier's send buffer
* UMP MUST retain an end-to-end probe timeout so a stalled carrier cannot block recovery forever

## 3.15 Scope and cost classification

* Scope evidence: local or remote address classes and configuration
* Scope MUST NOT be inferred from a private IP address alone
* Cost: `UNMETERED`, `METERED`, or `OPERATOR_DEFINED` by configuration

## 3.16 Resource-limit defaults

```text
Pending accepts per listener: 128
Concurrent dials per instance: 64
Send queue per Link: 256 packets or 2 MiB
Receive queue per Link: 256 packets or 2 MiB
```

## 3.17 Privacy exposure

* TCP connection closure MUST NOT automatically destroy a UMP session if another validated path exists
* A TCP connection exposes addresses, timing, sizes, and connection duration
* The native profile is identifiable as UMP

## 3.18 Required interoperability tests

1. Framing round-trip with boundary lengths.
2. Oversize packet-length rejection before allocation.
3. Truncated packet rejection.
4. Session migration TCP to UDP without session loss.
5. TCP failure with session survival through another path.
6. Bounded backpressure under saturation.
7. Multiplexing multiple sessions over one connection where negotiated.

---

# 4. Session interaction

* The session layer still uses packet numbers, ACKs, flow control, and key updates over TCP
* The sender MAY suppress rapid packet-threshold retransmission when TCP guarantees ordered delivery
* The sender MUST retain an end-to-end probe timeout

---

# 5. Core rule

The TCP carrier transfers length-prefixed UMP packets over ordered, reliable, connected byte streams.

It is a compatibility transport for networks where UDP is unavailable, an early-development transport, and a reliable-carrier test bed. It never authenticates endpoints, never implies trust, and TCP closure never ends a UMP session that has another validated path.
