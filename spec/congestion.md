# Universal Mesh Core Congestion and Loss-Recovery Specification

**Status:** Draft
**Version:** 0.1
**Document:** Congestion Control and Pacing
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines UMC's congestion-control subsystem: how senders limit network load, detect loss, and pace traffic on every path.

It specifies:

* Subsystem role and placement
* Replaceable algorithm interface
* Sender-side model
* ACK generation interaction
* Loss detection
* Retransmission timers
* RTT calculation
* Persistent congestion
* Pacing
* Per-path state
* Initial conservative algorithm
* Carrier backpressure
* TCP-carrier behavior
* UDP-carrier behavior
* Flow-control interaction
* Multipath and migration between paths
* Fairness
* Resource limits

The session specification defines transport semantics. This document defines how senders avoid flooding networks while preserving reliability.

This document does not define:

* Stream and datagram semantics
* Flow-control credit rules
* Route selection
* Carrier queue internals

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

---

# 3. Role and placement

Congestion control is an **internal mandatory subsystem with replaceable algorithms**.

It is not an external plugin.

A faulty congestion controller can:

* Flood networks
* Collapse performance
* Cause unfairness
* Trigger filtering
* Exhaust relay buffers
* Harm unrelated traffic

It therefore belongs inside the audited core security and performance boundary.

Researchers MAY compile alternate controllers or use feature-gated experimental builds. External runtime loading is prohibited in stable releases.

---

# 4. Terminology

## 4.1 Congestion controller

The replaceable algorithm that computes send allowances.

## 4.2 Send allowance

The rate or window the controller grants.

## 4.3 In-flight bytes

Bytes sent, not yet acknowledged or declared lost.

## 4.4 Congestion window

The controller's byte allowance for in-flight traffic.

## 4.5 Pacing

Spreading packets over time to avoid bursts.

## 4.6 Path

One session-visible route over one carrier and zero or more relays.

## 4.7 Carrier backpressure

A carrier-side signal that the medium or queue cannot accept more data.

---

# 5. Scope and boundaries

Congestion control MUST:

* Limit network-safe send rates on every path that can contribute to shared-network congestion
* Adapt to loss and delay
* Avoid flooding low-bandwidth carriers
* Distinguish carrier backpressure from path loss
* Avoid duplicating excessive traffic over multiple paths
* Respect carrier queue state

Congestion control MUST NOT:

* Replace flow control
* Replace carrier backpressure
* Suppress ACKs
* Reduce below protocol-minimum send capacity
* Grant unlimited sends based on application demand

A sender MUST NOT transmit unlimited traffic based only on application demand.

---

# 6. Algorithm interface

The reference implementation SHOULD define an interface equivalent to:

```rust
pub trait CongestionController: Send {
    fn on_packet_sent(&mut self, event: PacketSent);
    fn on_ack(&mut self, event: AckReceived);
    fn on_loss(&mut self, event: PacketLost);
    fn on_rtt_update(&mut self, event: RttUpdate);
    fn send_allowance(&self, now: Instant) -> SendAllowance;
}
```

The interface MUST:

* Keep state scoped to one path
* Consume monotonic time
* Remain deterministic for identical inputs
* Support cancellation and reset
* Expose bounded state

---

# 7. Sender-side model

## 7.1 Send limits

Every send MUST obey all three limits:

```text
congestion-controller allowance
carrier backpressure
peer flow-control credit
```

The effective send is the most restrictive.

## 7.2 In-flight tracking

A sender MUST track per path:

```text
Sent bytes
Acknowledged bytes
Declared-lost bytes
In-flight bytes
Retransmitted bytes
Ack-eliciting status
```

In-flight bytes are sent bytes minus acknowledged and declared-lost bytes.

A reliable carrier does not remove this requirement.

## 7.3 Control reserve

The session scheduler SHOULD reserve capacity for:

```text
ACK
Close
Path-validation
Flow-control frames
```

Control traffic must not be starved by bulk traffic.

---

# 8. ACK generation interaction

ACK generation rules are defined by `session.md`.

For congestion control, a sender MUST:

* Derive RTT samples only from newly acknowledged ack-eliciting packets
* Ignore ACK delay when calculating minimum RTT
* Subtract at most the peer's negotiated `maximum_ack_delay` from later RTT samples after handshake confirmation
* Process ACKs only inside authenticated packets
* Reject acknowledgements for unsent packets

ACK-only packets are not ack-eliciting.

---

# 9. RTT calculation

Each validated path maintains separate RTT state:

```text
latest_rtt
min_rtt
smoothed_rtt
rtt_variance
```

## 9.1 Initialization

The first valid sample initializes:

```text
smoothed_rtt = latest_rtt
rtt_variance = latest_rtt / 2
min_rtt = latest_rtt
```

## 9.2 Update

Later samples update:

```text
rtt_variance = 3/4 * rtt_variance + 1/4 * abs(smoothed_rtt - adjusted_rtt)
smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
min_rtt = min(min_rtt, latest_rtt)
```

RTT state MUST NOT be shared across paths.

---

# 10. Loss detection

## 10.1 Packet threshold

A packet is lost when a peer acknowledges a packet in the same space at least three packet numbers higher.

## 10.2 Time threshold

A packet is lost when both conditions hold:

```text
a higher packet has been acknowledged
elapsed time >= 9/8 * max(latest_rtt, smoothed_rtt)
```

The sender applies the path's timer to packets sent on that path.

## 10.3 Probe timeout

When ack-eliciting packets remain outstanding and no loss timer expires first, the sender arms a probe timeout:

```text
PTO = smoothed_rtt + max(4 * rtt_variance, timer_granularity) + maximum_ack_delay
```

Initial and Handshake spaces omit peer ACK delay from PTO.

Before an RTT sample exists, default PTO is 1 second.

Each consecutive PTO expiry doubles the timeout.

On PTO expiry, the sender SHOULD send one or two probe packets containing pending retransmittable data or `PING`.

## 10.4 Loss response

The congestion controller defines the window response to loss.

The session layer declares loss; the controller reacts.

---

# 11. Persistent congestion

A path is persistently congested when all ack-eliciting packets sent over a continuous interval of at least three PTO durations become lost.

On persistent congestion, the controller MUST reduce its window to a conservative level.

The session layer MUST:

* Mark the path degraded
* Consider validated alternatives
* Not close the session while another usable path exists

---

# 12. Pacing

## 12.1 Requirement

A sender MUST pace traffic on internet-scale carriers.

Pacing spreads packets according to the controller's rate:

```text
pacing_rate = congestion_window / smoothed_rtt
packet_spacing = packet_size / pacing_rate
```

## 12.2 Rules

Pacing MUST:

* Use the timer granularity as a floor for spacing
* Limit bursts to the configured initial burst
* Not delay control traffic beyond scheduler policy
* Expose pacing delay and queue state to carrier and diagnostics

A carrier MAY pace packets when its medium requires it.

Pacing MUST NOT be used to hide unbounded queues.

---

# 13. Per-path state

Each path owns:

```text
RTT state
Congestion window
Pacing state
In-flight accounting
Loss history
Validation state
MTU
```

Per-path state is created when a path is admitted and destroyed when the path retires.

A sender MUST NOT copy a congestion window from another path.

---

# 14. Initial algorithm: NewReno-like with pacing

The initial stable controller is a conservative NewReno-like loss-based controller with pacing.

## 14.1 Window

```text
initial_cwnd = 10 * initial_max_packet_size (default 12,000 bytes)
minimum_cwnd = 2 * current_max_packet_size
ssthresh = unlimited at start (slow start)
```

## 14.2 Slow start

In slow start, the window grows by one maximum packet per acknowledged packet, bounded by application and flow-control limits.

## 14.3 Congestion avoidance

After `ssthresh`, the window grows by one maximum packet per round trip.

## 14.4 Loss response

On packet-threshold or time-threshold loss:

```text
ssthresh = max(cwnd / 2, minimum_cwnd)
cwnd = ssthresh
```

On persistent congestion:

```text
ssthresh = max(cwnd / 2, minimum_cwnd)
cwnd = minimum_cwnd
```

PTO expiry alone does not reduce the window.

## 14.5 Pacing gain

The initial controller uses a conservative pacing gain of 1.0.

The controller SHOULD NOT exceed the window during a burst beyond the configured burst limit.

---

# 15. Alternative algorithms

A second experimental implementation MAY add a BBR-like model-based controller.

An alternative controller MUST:

* Keep state per path
* Respect carrier backpressure
* Respect flow-control credit
* Preserve protocol invariants
* Be feature-gated and marked experimental

The algorithm interface MUST NOT change protocol semantics.

---

# 16. Carrier backpressure

## 16.1 Reporting

Carriers report:

```text
Backpressure
Estimated MTU
Delivery behavior
Reliability
Cost
Link-level queue state where available
```

Carrier properties record source and confidence.

Remote claims are untrusted.

## 16.2 Behavior

A sender MUST:

* Treat carrier backpressure as a real limit
* Hold sends while the carrier reports no capacity
* NOT reduce the congestion window solely because of carrier backpressure
* Distinguish medium backpressure from path loss
* Penalize a path only when backpressure is persistent

A carrier MUST NOT interpret UMP congestion state or forge congestion feedback.

---

# 17. TCP-carrier behavior

On a reliable, ordered carrier such as TCP:

* The carrier provides its own delivery and congestion behavior at the medium level
* The session layer still uses packet numbers, ACKs, and end-to-end probe timeouts
* The sender MAY suppress rapid packet-threshold retransmission when the carrier guarantees ordered delivery
* The sender MUST retain an end-to-end probe timeout so a stalled carrier cannot block recovery forever
* The sender SHOULD avoid building a large UMP queue above the carrier's send buffer
* The sender SHOULD keep carrier write queues short so migration and backpressure remain effective

Congestion control remains active but SHOULD weight carrier queue state more heavily than loss-based signals.

---

# 18. UDP-carrier behavior

On an unreliable carrier such as UDP:

* Full UMP congestion control applies
* Loss detection, PTO, pacing, and window control operate on every packet
* Initial packet sizes follow the carrier's path-safe maximum until path MTU discovery succeeds
* Anti-amplification limits apply before return-reachability validation

---

# 19. Flow-control interaction

Congestion control and flow control are separate.

Flow control protects receiver memory and application capacity.

Congestion control protects the network.

A sender MUST obey both.

Flow-control credit exhaustion blocks sends even when the congestion window is open.

Congestion limits block sends even when credit is available.

---

# 20. Multipath and migration between paths

## 20.1 Multipath

Each path retains separate:

```text
RTT estimates
Congestion state
Validation state
MTU
Failure state
```

The sender MAY distribute packets across validated paths.

It MUST obey each path's congestion and carrier limits.

It SHOULD avoid moving ordered stream data across paths when RTT differences would create excessive reordering.

Duplicated packets MUST be counted against congestion and carrier budgets on every path that carries them.

## 20.2 Migration

Migration creates fresh per-path RTT and congestion state.

A sender MUST NOT copy a congestion window from another path.

A new path MUST reach `VALIDATED` before carrying unrestricted application traffic.

A migrated session re-enters slow start on the new path.

---

# 21. Fairness

The runtime SHOULD use fair scheduling across sessions, streams, and applications.

The sender SHOULD schedule classes from highest to lowest urgency:

```text
Close and handshake confirmation
ACK and path validation
Flow control and connection-ID management
Interactive stream data
Normal stream data and datagrams
Bulk stream data
Background traffic
```

Priority does not permit starvation.

A single peer or application MUST NOT monopolize the node.

Priority classes MUST NOT bypass global safety limits.

---

# 22. Resource limits

Congestion state MUST remain bounded.

Defaults from `resource-limits.md`:

```text
Outstanding sent-packet metadata per session: 16,384 packets
Retained packet metadata after acknowledgement: 0 (except diagnostics)
ACK ranges per frame: 64
Stored receive ranges per packet-number space: 256
```

Timers MUST use bounded timer structures with one timer record per admitted object, not per untrusted field.

Pacing and probe timers MUST NOT be creatable by remote input alone.

---

# 23. Security considerations

## 23.1 Forged ACKs

Forged ACKs can corrupt congestion and loss state.

ACKs are processed only inside authenticated packets.

Acknowledgements for unsent packets are rejected.

## 23.2 ACK flooding

An attacker may flood ACKs to inflate the window.

The receiver's advertised credit and per-peer quotas bound the effect.

## 23.3 Loss-trigger abuse

A peer that acknowledges nothing can force persistent-congestion reduction.

End-to-end probe timeouts bound recovery; the session may migrate to another path.

## 23.4 Backpressure spoofing

A carrier or plugin can lie about queue state.

Carrier properties are hints with source and confidence.

Session correctness does not depend on their accuracy.

---

# 24. Required tests

A compliant implementation MUST test:

1. RTT sample collection and filtering.
2. Packet-threshold loss detection.
3. Time-threshold loss detection.
4. PTO computation and doubling.
5. Probe packet behavior.
6. Persistent congestion detection and response.
7. Slow start and congestion avoidance.
8. Loss-driven window reduction.
9. Pacing spacing and burst limits.
10. Per-path state isolation.
11. Carrier backpressure hold without window reduction.
12. TCP-carrier queue-bounding behavior.
13. UDP-carrier full control behavior.
14. Flow-control and congestion limit intersection.
15. Multipath per-path accounting.
16. Duplicate packets counted per path.
17. Migration creating fresh congestion state.
18. Control-traffic reserve under bulk load.
19. Fairness across sessions.
20. Forged-ACK rejection.
21. Restart clearing congestion state.

Property tests SHOULD verify:

```text
In-flight bytes never exceed the congestion window.
Congestion state never crosses paths.
Window never exceeds flow-control credit.
PTO never exceeds bounds after negotiation.
Persistent congestion reduces the window.
Migration never copies another path's window.
Control traffic always has reserved capacity.
```

---

# 25. Minimal v0.1 compliance

A compliant v0.1 implementation MUST support:

* One internal congestion controller
* Per-path state
* ACK processing from authenticated packets
* Packet- and time-threshold loss detection
* Probe timeout with backoff
* Persistent congestion detection
* Pacing
* Carrier backpressure respect
* TCP and UDP carrier behavior profiles
* Flow-control intersection
* Migration with fresh per-path state
* Bounded congestion state

An implementation MAY defer:

* BBR-like model-based control
* Multipath aggregation
* Explicit congestion-notification integration

An implementation MUST NOT advertise a deferred capability.

---

# 26. Open design decisions

The project must resolve these items before freezing UMP/1:

1. Final initial window value.
2. Minimum window formula.
3. Pacing gain and burst allowance.
4. Whether loss response uses halving or another reduction.
5. Persistent-congestion window floor.
6. Whether reliable carriers suppress packet-threshold loss detection by default.
7. ACK delay exponent default.
8. Explicit congestion-notification support.
9. Timer granularity default.
10. Whether pacing applies on local carriers.
11. Multipath scheduler policy.
12. Fairness weighting between priority classes.
13. Whether carrier queue state feeds the window.
14. Migration slow-start policy.
15. Default PTO per carrier profile.

---

# 27. Recommended implementation order

Implement congestion control in this order:

1. Per-path state types.
2. In-flight accounting.
3. RTT estimation.
4. Loss detection thresholds.
5. PTO and probes.
6. Persistent congestion detection.
7. Congestion window control.
8. Slow start and avoidance.
9. Pacing.
10. Carrier backpressure integration.
11. TCP and UDP behavior profiles.
12. Flow-control intersection.
13. Multipath accounting.
14. Migration handling.
15. Fairness scheduling.
16. Fault injection and soak tests.

---

# 28. Core rule

UMC senders are always bounded by the most restrictive of congestion allowance, carrier backpressure, and peer credit.

Every path owns its own RTT, window, pacing, and loss state. Loss is detected by authenticated ACKs and bounded timers. Under persistent congestion the path degrades and the session migrates, while control traffic keeps reserved capacity and no untrusted input can inflate the window.
