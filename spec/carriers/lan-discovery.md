# LAN Discovery Carrier Profile

**Status:** Draft
**Version:** 0.1
**Document:** Carrier Profile `ump.lan-discovery/1`
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines the LAN discovery carrier profile for UMP.

It is one of the three stable v0.1 carriers. It is discovery-only: it produces peer candidates and does not carry UMP data packets.

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

The carrier API specification (`carrier-api.md`) defines the interface. This profile defines the medium behavior.

---

# 3. Role

The LAN discovery carrier provides:

* Peer announcements
* Candidate exchange
* Local scope awareness

It does NOT:

* Carry UMP data packets
* Imply trust
* Authenticate endpoints

Actual LAN sessions use the UDP or TCP carriers.

---

# 4. Profile requirements

## 4.1 Carrier Type ID

```text
ump.lan-discovery/1
```

## 4.2 Packet mode and framing

* Packet mode: `MESSAGE`
* One announcement or response per message
* Message size validated before allocation

## 4.3 Reliability and ordering

* Reliability: `UNRELIABLE`
* Ordering: `UNORDERED`

## 4.4 Connection model

* Connection model: `SHARED_CHANNEL`

The medium is a shared local channel.

## 4.5 Listen and dial hints

* Listen hint: local interface and multicast group or broadcast domain
* Dial hint: not applicable; candidates are discovered, not dialed

## 4.6 Packet-size bounds and initial MTU

* Announcement size: bounded, profile-defined
* Default announcement maximum: 1,024 bytes
* Candidate connection hints remain within the generic 1,024-byte limit

## 4.7 Carrier Binding

* Binding kind: `PROFILE_ONLY`
* Instance Data: profile identifier and local scope context

## 4.8 Path Context

```text
carrier_type: ump.lan-discovery/1
local_context: local interface
remote_context: source link context
scope: LINK_LOCAL or LOCAL_NETWORK
generation
```

## 4.9 Address rebinding

* Source context changes are reported as `REMOTE_CONTEXT_CHANGED`
* Announcements are never trusted as endpoint identity

## 4.10 Discovery behavior

Native discovery:

* Periodic local presence announcements
* Responses to announcement queries
* Bounded candidate emission
* Source marked `LOCAL_DISCOVERY`
* `LOCAL` flag where applicable

The provider MUST:

* Enforce the candidate maximum
* Rate-limit announcements and responses
* Validate announcement sizes before allocation
* Mark source and authentication state
* Stop on cancellation or deadline

## 4.11 Outer security and authentication

* None by default
* Carrier-level authentication MAY be added by a future profile extension

## 4.12 Anti-probing

None claimed.

The native LAN profile is recognizable as UMP on the local segment.

## 4.13 Error mapping

| Condition | Carrier error |
| --- | --- |
| Interface unavailable | `DEVICE_UNAVAILABLE` |
| Permission denied | `PERMISSION_DENIED` |
| Medium errors | `INTERNAL` or drop counters |
| Capacity exhausted | `RESOURCE_LIMIT` |

## 4.14 Backpressure

* Bounded emission queues
* Announcements MAY be dropped under pressure
* Drop counters MUST be reported

## 4.15 Scope and cost classification

* Scope: `LINK_LOCAL` or `LOCAL_NETWORK`
* The carrier MUST NOT classify a path as local based only on a private IP address, SSID name, or remote claim
* Effective local-scope classification belongs to node policy
* Cost: `UNMETERED` typically, `ENERGY_CONSTRAINED` where configured

## 4.16 Resource-limit defaults

```text
Candidates per discovery operation: 256
Announcement interval: profile-defined
Discovery responses per peer: 20 per minute
Announcement size: 1,024 bytes
```

## 4.17 Privacy exposure

* Announcements reveal local presence, timing, and candidate hints
* The carrier MUST NOT disclose private peers
* `DO_NOT_RESHARE` hints MUST NOT be forwarded
* Peer-table enumeration is prohibited

## 4.18 Required interoperability tests

1. Announcement and response exchange.
2. Announcement size validation.
3. Candidate source and authentication marking.
4. Rate-limited responses under flooding.
5. Candidate-maximum enforcement.
6. Drop counters under pressure.
7. Private peer non-disclosure.
8. No data-packet acceptance.
9. Interface failure reporting.

---

# 5. Trust interaction

A node MUST NOT infer trust from:

* Local presence
* Private IP space
* SSID
* Bluetooth name
* Link-layer address

LAN-discovered candidates authenticate through UMP after dialing over UDP or TCP.

---

# 6. Core rule

The LAN discovery carrier announces local presence and exchanges bounded, source-attributed candidates over a shared local channel.

It never carries UMP data packets, never authenticates endpoints, and never implies trust. Local presence is evidence of adjacency, and effective locality is decided by node policy, not by the medium.
