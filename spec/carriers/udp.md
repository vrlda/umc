# UDP Carrier Profile

**Status:** Draft
**Version:** 0.1
**Document:** Carrier Profile `ump.udp/1`
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines the native UDP carrier profile for UMP.

It is one of the three stable v0.1 carriers and the primary native transport for loss recovery, congestion control, path migration, and NAT traversal experiments.

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

The carrier API specification (`carrier-api.md`) defines the interface. This profile defines the medium behavior.

---

# 3. Profile requirements

## 3.1 Carrier Type ID

```text
ump.udp/1
```

## 3.2 Packet mode and framing

* Packet mode: `DATAGRAM`
* Framing: one UDP datagram equals one UMP packet

```text
One carrier datagram = one UMP packet
```

* Multiple UMP packets MUST NOT be concatenated into one datagram in v0.1
* A truncated datagram MUST be discarded

## 3.3 Reliability and ordering

* Reliability: `UNRELIABLE`
* Ordering: `UNORDERED`

Packets may be lost, reordered, or duplicated. UMP handles replay and packet ordering.

## 3.4 Connection model

* Connection model: `CONNECTIONLESS_ASSOCIATION`

The carrier maintains an address association per Link.

## 3.5 Listen and dial hints

* Listen hint: `host:port` binding selector
* Dial hint: `host:port` connection target
* Ports MUST NOT be fixed by the protocol
* Nodes SHOULD support random or configured ports

## 3.6 Packet-size bounds and initial MTU

* Generic UMP packet maximum: 65,535 bytes
* Initial maximum datagram size: 1,200 bytes
* Minimum Initial packet size: 1,200 bytes (padding required)
* Larger sizes require path MTU discovery or configured increase

## 3.7 Carrier Binding

* Binding kind: `PROFILE_ONLY`
* Instance Data: carrier profile identifier
* Private admission MAY use `PRIVATE_ADMISSION_CONTEXT` when invitation-gated

## 3.8 Path Context

```text
carrier_type: ump.udp/1
local_context: local address and port
remote_context: remote address and port
scope
generation
```

## 3.9 Address rebinding

* A new remote address for authenticated UMP packets is reported as `REMOTE_CONTEXT_CHANGED` with a new generation
* The carrier MUST NOT accept unauthenticated address changes as peer identity changes
* The session layer validates and adopts the new path

## 3.10 Discovery

None. UDP does not provide native discovery.

## 3.11 Outer security and authentication

None by default.

## 3.12 Anti-probing

None claimed for the native profile.

PSK-XX gated listeners MAY silently discard unauthenticated probes under private-admission profiles.

## 3.13 Error mapping

| Condition | Carrier error |
| --- | --- |
| ICMP port unreachable | `UNREACHABLE` |
| Packet above path limit | `PACKET_TOO_LARGE` |
| Send capacity exhausted | `WOULD_BLOCK` or `QUEUE_FULL` |
| Port in use | `ADDRESS_IN_USE` |
| Medium errors | `LINK_FAILED` or drop counters |

## 3.14 Backpressure

* Bounded send and receive queues per Link
* Datagram carriers MAY drop packets before UMC accepts them
* The carrier MUST report drop counters
* The carrier MUST NOT allocate beyond configured receive budgets

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

* UDP exposes addresses, timing, sizes, and packet direction
* The native profile is recognizable as UMP (optional `UMP1` magic)
* An Initial packet at 1,200 bytes reduces amplification risk and supports path validation

## 3.18 Required interoperability tests

1. Datagram boundary preservation.
2. Truncated datagram rejection.
3. Packet loss, reordering, and duplication handling.
4. Minimum Initial size and padding.
5. Amplification-limit enforcement before validation.
6. Stateless Retry over UDP.
7. Session migration UDP to TCP without session loss.
8. Address rebinding and path validation.
9. Bounded receive drop behavior under saturation.

---

# 4. Session interaction

* Full UMP congestion control, loss detection, PTO, pacing, and window control apply
* The responder MUST NOT transmit more than three times the bytes received from one source context before validating return reachability
* Amplification credit MUST NOT transfer across unrelated addresses, carriers, invitations, or connection IDs

---

# 5. Core rule

The UDP carrier transfers one UMP packet per datagram with no delivery guarantees.

It is the efficiency, mobility, and loss-recovery test bed for UMP: full congestion control runs above it, amplification is bounded before reachability validation, and address changes become validated paths rather than identity changes.
