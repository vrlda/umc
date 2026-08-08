# Universal Mesh Protocol Session and Transport Specification

**Status:** Draft
**Version:** 0.1
**Document:** Session and Transport Semantics
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines UMP session behavior after two endpoints begin a handshake.

It specifies:

* Session lifecycle
* Packet-number spaces
* Stream lifecycle and data delivery
* Datagram delivery
* Flow control
* Acknowledgements
* Loss detection and retransmission
* Idle timeout and closure
* Key updates
* Path validation and migration
* Multipath behavior
* Connection-ID lifecycle
* Transport errors
* Resource bounds

The handshake specification defines endpoint authentication and traffic-key derivation. The wire-format specification defines packet and frame encoding. This document defines how endpoints use those packets and frames to provide transport services.

This document does not define:

* Cryptographic algorithms
* Carrier framing
* Route discovery
* Relay circuit construction
* Application payload formats
* Local SDK method signatures

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

An endpoint violates the protocol when it breaks a `MUST` or `MUST NOT` rule. Its peer MUST close the affected session unless this document assigns a narrower response.

---

# 3. Transport model

A session is an authenticated, encrypted relationship between two endpoints. Each endpoint owns one side of the session.

A session may use:

* One or more carrier links
* Direct paths
* Relayed paths
* Reliable or unreliable carriers
* Ordered or unordered carriers

The session layer provides the same stream semantics across those choices.

A session retains its identity and transport state when its path changes. A carrier connection, address, route, relay circuit, or connection ID does not identify the session by itself.

Each session contains:

```text
Endpoint identities
Negotiated parameters
Packet-number spaces
Traffic-key state
Stream state
Datagram state
Connection-level flow control
Path state
Connection-ID state
Loss-recovery state
Closure state
```

---

# 4. Roles

The endpoint that sends the first `CLIENT_HELLO` is the originator. The peer is the responder.

Roles remain fixed for the session lifetime. Path migration and resumption do not change them.

Stream-ID initiator bits use these roles:

```text
0 = originator
1 = responder
```

---

# 5. Session identifiers

Each endpoint MUST assign an opaque local session handle. Local handles never appear on the wire.

The protocol uses connection IDs to map packets to session state. Connection IDs are temporary routing tokens, not session identifiers.

An implementation MAY derive a stable diagnostic session label from the final handshake transcript. It MUST NOT transmit that label or expose it to unauthenticated parties.

---

# 6. Session lifecycle

A session uses these abstract states:

```text
IDLE
HANDSHAKING
ACTIVE
DRAINING
CLOSED
```

Implementations MAY use finer internal states.

## 6.1 IDLE

No handshake state exists.

An outbound connection request or accepted Initial packet moves the session to `HANDSHAKING` after local admission checks succeed.

## 6.2 HANDSHAKING

The endpoints exchange Initial and Handshake packets.

During this state:

* Each endpoint MUST follow the handshake state machine.
* Each endpoint MUST keep Initial, Handshake, and application packet-number state separate.
* An endpoint MUST NOT deliver application data before authentication and authorization permit it.
* An endpoint MAY buffer permitted early data within negotiated and local limits.

The session moves to `ACTIVE` after the local endpoint completes the confirmation conditions from `handshake.md`.

## 6.3 ACTIVE

The endpoints may exchange protected session traffic.

Each endpoint may:

* Open streams
* Send datagrams
* Validate paths
* Rotate connection IDs
* Update keys
* Close the session

## 6.4 DRAINING

An endpoint enters `DRAINING` after sending or receiving `CONNECTION_CLOSE`.

During draining, an endpoint:

* MUST NOT open streams.
* MUST NOT send application data.
* MUST NOT initiate path migration or key updates.
* MAY retransmit `CONNECTION_CLOSE` in response to packets.
* MAY process enough header information to demultiplex and discard packets.

The draining period MUST last at least three times the current probe timeout and SHOULD have a 1-second minimum. Local policy MAY cap it at 30 seconds.

## 6.5 CLOSED

The endpoint releases transport state after the draining period.

It MAY retain:

* Stateless-reset tokens
* Bounded replay metadata
* Resumption tickets
* Diagnostic counters

It MUST erase obsolete traffic secrets and retransmission buffers.

---

# 7. Negotiated transport parameters

The handshake authenticates transport parameters. Each endpoint MUST validate every received value before storing session state.

UMP/1 defines these parameters:

```text
initial_max_data
initial_max_stream_data_bidi_local
initial_max_stream_data_bidi_remote
initial_max_stream_data_uni
initial_max_bidirectional_streams
initial_max_unidirectional_streams
maximum_datagram_size
idle_timeout
maximum_ack_delay
ack_delay_exponent
active_connection_id_limit
maximum_paths
disable_active_migration
```

An endpoint MUST reject:

* Non-canonical encodings
* Duplicate parameters
* Values above protocol field limits
* Unknown critical parameters
* Parameter combinations that violate negotiated capabilities

A received limit grants permission to send. It does not require allocation by the receiver.

---

# 8. Packet-number spaces

UMP/1 uses independent packet-number spaces for:

```text
Initial
Handshake
Session data
Path control
Relay data
```

Each sender maintains one monotonically increasing counter per active space.

A sender MUST NOT reuse a packet number in the same space under the same packet protection keys.

Packet numbers do not reset after:

* Path migration
* Connection-ID rotation
* Key update
* Carrier replacement

A new full handshake creates new packet-number spaces. Session resumption also creates a new session and new spaces.

## 8.1 Packet-number reconstruction

The receiver reconstructs a truncated packet number by selecting the value nearest to the next expected packet number within the encoded packet-number window.

Given:

```text
expected = largest_received + 1
window = 2 ^ encoded_bits
half_window = window / 2
candidate = (expected & ~(window - 1)) | truncated
```

The receiver adjusts `candidate` by one window when another representable candidate lies closer to `expected`.

The receiver MUST reject reconstructed values above `2^62 - 1`.

## 8.2 Replay window

Each endpoint MUST maintain a bounded replay window for each packet-number space.

The default replay window is 4,096 packet numbers. An implementation MAY use a larger window.

The endpoint MUST discard a packet before frame processing when its packet number:

* Already appears in the replay window
* Falls below the retained window
* Cannot be reconstructed without overflow

Duplicate packets do not trigger a transport error.

---

# 9. Packet processing order

A receiver processes a packet in this order:

1. Validate carrier packet boundaries and public-header limits.
2. Locate candidate session and key state through the destination connection ID.
3. Remove header protection.
4. Reconstruct the packet number.
5. Reject known duplicates and values outside the replay window.
6. Authenticate and decrypt the payload.
7. Parse every frame without applying state changes.
8. Validate frame context and cross-frame invariants.
9. Commit state changes.
10. Update acknowledgement and path state.

Authentication failure MUST NOT change session state except bounded failure counters.

A malformed frame MUST NOT cause partial application of earlier frames from the same packet.

---

# 10. Ack-eliciting packets

A packet is ack-eliciting when it contains any frame other than:

* `ACK`
* `PADDING`
* `CONNECTION_CLOSE`

An endpoint MAY classify `PATH_STATUS` as non-ack-eliciting when it carries no state transition.

An endpoint MUST NOT send an ACK solely because it received an ACK-only packet.

---

# 11. ACK generation

Each packet-number space has independent acknowledgement state.

## 11.1 Immediate acknowledgements

A receiver MUST send an ACK without intentional delay after receiving:

* An Initial or Handshake packet
* A packet that fills a detected packet-number gap
* A packet more than one number above the largest received packet
* A `PATH_CHALLENGE`
* A packet carrying transport control that blocks peer progress

## 11.2 Delayed acknowledgements

For Session data, Path control, and Relay data, a receiver MAY delay an ACK until either:

* It receives two ack-eliciting packets, or
* `maximum_ack_delay` expires

Default `maximum_ack_delay` is 25 milliseconds on interactive IP carriers.

Carrier profiles MAY recommend another default. The negotiated value MUST NOT exceed 1 second for live sessions.

## 11.3 ACK ranges

An endpoint MUST encode ACK ranges from highest to lowest packet number.

It MUST NOT acknowledge packets it has not authenticated.

It MUST limit an ACK frame to 64 ranges. When more ranges exist, it SHOULD retain the newest ranges and ranges that cover retransmittable traffic.

An endpoint MUST reject an ACK frame that:

* Acknowledges an unsent packet number
* Underflows while decoding a gap
* Contains overlapping ranges
* Exceeds the range-count limit

Acknowledging an unsent packet is an `ACK_ERROR` protocol violation, encoded as `PROTOCOL_VIOLATION` until a dedicated error code is assigned.

## 11.4 ACK delay

The sender decodes ACK Delay using the negotiated exponent.

The sender MUST ignore ACK delay when calculating the minimum RTT. It MAY subtract at most the peer's negotiated `maximum_ack_delay` from later RTT samples after handshake confirmation.

---

# 12. Sent-packet tracking

A sender MUST retain enough metadata to determine:

* Packet number and space
* Send time
* Packet size
* Ack-eliciting status
* In-flight status
* Path
* Key phase
* Retransmittable frame references

The sender SHOULD retain frame data independently from packet encoding. Retransmission uses new packets and packet numbers.

The sender MAY discard sent-packet metadata after acknowledgement, declared loss, or expiry of all contained data.

---

# 13. RTT estimation

Each validated path maintains separate RTT state:

```text
latest_rtt
min_rtt
smoothed_rtt
rtt_variance
```

The first valid sample initializes:

```text
smoothed_rtt = latest_rtt
rtt_variance = latest_rtt / 2
min_rtt = latest_rtt
```

Later samples update:

```text
rtt_variance = 3/4 * rtt_variance + 1/4 * abs(smoothed_rtt - adjusted_rtt)
smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
min_rtt = min(min_rtt, latest_rtt)
```

An endpoint MUST derive RTT samples only from newly acknowledged ack-eliciting packets.

---

# 14. Loss detection

An endpoint declares an unacknowledged packet lost through packet-threshold or time-threshold detection.

## 14.1 Packet threshold

A packet is lost when a peer acknowledges a packet in the same space at least three packet numbers higher.

## 14.2 Time threshold

A packet is lost when both conditions hold:

```text
a higher packet has been acknowledged
elapsed time >= 9/8 * max(latest_rtt, smoothed_rtt)
```

The sender applies the path's timer to packets sent on that path.

## 14.3 Probe timeout

When ack-eliciting packets remain outstanding and no loss timer expires first, the sender arms a probe timeout:

```text
PTO = smoothed_rtt + max(4 * rtt_variance, timer_granularity) + maximum_ack_delay
```

Initial and Handshake spaces omit peer ACK delay from PTO.

Before an RTT sample exists, default PTO is 1 second. Carrier profiles MAY provide a larger initial value for high-latency media.

Each consecutive PTO expiry doubles the timeout.

On PTO expiry, the endpoint SHOULD send one or two probe packets containing pending retransmittable data or `PING`.

## 14.4 Persistent congestion

An implementation SHOULD treat a path as persistently congested when all ack-eliciting packets sent over a continuous interval of at least three PTO durations become lost.

Congestion-controller response belongs to `congestion.md`. The session layer MUST mark the path degraded and consider validated alternatives.

---

# 15. Retransmission

Loss recovery retransmits information, not packets.

A retransmission:

* MUST use a new packet number.
* MAY use another validated path.
* MUST use current packet protection keys.
* MUST preserve stream offsets and final-size semantics.
* MUST preserve handshake-stream offsets.

The sender MUST NOT retransmit:

* `ACK`
* `PADDING`
* Expired datagrams
* `PATH_RESPONSE` without a current challenge
* Obsolete flow-control updates
* Data acknowledged through another transmission

The sender MAY coalesce data from several lost packets into one new packet.

---

# 16. Congestion and pacing boundary

Every path MUST use congestion control when its carrier can contribute to shared-network congestion.

The sender MUST obey all three limits:

```text
congestion-controller allowance
carrier backpressure
peer flow-control credit
```

A reliable carrier does not remove this requirement. A TCP carrier SHOULD avoid building a large UMP queue above the carrier's send buffer.

The session scheduler SHOULD reserve capacity for ACK, close, path-validation, and flow-control frames.

---

# 17. Stream types and identifiers

UMP supports:

* Bidirectional streams
* Unidirectional streams

The low two Stream ID bits encode initiator and direction as specified in `wire-format.md`. Higher bits form a zero-based sequence number.

An endpoint opens streams of one type in ascending sequence order. It MUST NOT skip a sequence number and later open the skipped stream.

Receiving stream `N` implicitly opens all lower-numbered peer-initiated streams of the same type. The receiver MUST enforce the negotiated stream count before allocating state.

---

# 18. Stream lifecycle

Each direction of a stream has independent send and receive state.

Send states:

```text
READY
SEND
DATA_SENT
RESET_SENT
DATA_ACKED
RESET_ACKED
```

Receive states:

```text
RECV
SIZE_KNOWN
DATA_RECVD
RESET_RECVD
DATA_READ
RESET_READ
```

Implementations MAY merge states that have identical externally visible behavior.

## 18.1 Opening

The first `STREAM` frame on a stream MUST set `OPEN` and carry:

* Protocol ID
* Initial stream metadata
* Direction matching the Stream ID

Later frames MUST clear `OPEN` and omit those fields.

Duplicate copies of the opening frame MUST contain identical protocol ID and metadata bytes. A conflict is a `PROTOCOL_VIOLATION`.

The receiver MUST authorize the protocol before delivering stream data to an application.

If the protocol is unsupported or unauthorized, the receiver SHOULD send `STOP_SENDING` and `RESET_STREAM` with an application error. It MUST continue processing unrelated session traffic.

## 18.2 Sending data

The sender assigns each byte an absolute stream offset. Retransmissions use the same offset.

The sender MUST NOT transmit data above:

* The stream's `MAX_STREAM_DATA` limit
* The session's `MAX_DATA` limit
* The final size, once known

## 18.3 Receiving data

The receiver MAY receive stream data out of order.

It MUST deliver bytes to the application once, in increasing offset order.

Overlapping ranges are valid when their bytes match. Conflicting bytes are a `PROTOCOL_VIOLATION`.

The receiver MUST bound out-of-order storage. When the sender remains within advertised credit but local memory is exhausted, the receiver MAY stop increasing credit. It MUST NOT discard accepted reliable bytes and continue the stream as if delivery could succeed.

## 18.4 Graceful closure

The sender sets `FIN` on a `STREAM` frame to declare the final size:

```text
final_size = offset + data_length
```

A FIN-only frame may contain zero data.

Once declared, final size cannot change. Data beyond it or another FIN with a different value causes `FINAL_SIZE_ERROR`, encoded as `PROTOCOL_VIOLATION` until assigned a dedicated code.

The receive direction completes after all bytes below final size arrive.

## 18.5 Reset

`RESET_STREAM` terminates one send direction and declares its final size.

The receiver accounts the reset final size against connection-level flow control. It MUST reject a final size below any received byte offset or different from an earlier final size.

`STOP_SENDING` requests a reset. The recipient SHOULD answer with `RESET_STREAM` unless its send direction has reached `DATA_ACKED` or `RESET_ACKED`.

## 18.6 Stream state retirement

An endpoint may release send state after all data or the reset has been acknowledged.

It may release receive state after:

* The application consumes all data through final size, or observes the reset
* The endpoint no longer needs duplicate-consistency metadata

The endpoint MUST retain enough final-size state to reject conflicting late frames during the session's replay horizon.

---

# 19. Stream limits

Each endpoint grants separate limits for peer-initiated bidirectional and unidirectional streams.

`MAX_STREAMS` carries an absolute count. A sender MUST NOT reduce the value.

An endpoint that receives a stream above its granted count MUST close the session with `STREAM_LIMIT_ERROR`.

The receiver SHOULD grant replacement stream credit after an application finishes or rejects a peer-initiated stream. It MAY withhold credit under resource pressure.

The default initial limit is 16 bidirectional and 16 unidirectional streams unless an application profile sets another value.

---

# 20. Flow control

UMP uses byte-based flow control at stream and session levels.

Flow control protects receiver memory and application capacity. It does not replace congestion control.

## 20.1 Stream credit

`MAX_STREAM_DATA` grants the highest stream offset the sender may reach.

The sender counts the final offset, not retransmitted bytes. Duplicate transmissions consume no extra credit.

## 20.2 Session credit

`MAX_DATA` limits the sum of highest transmitted offsets across all streams, including bytes abandoned by reset.

The sender counts each stream byte once.

## 20.3 Credit updates

The receiver sends new credit after the application consumes enough data to justify it.

An implementation SHOULD send an update before remaining credit falls below half of the receive window. It MAY tune this threshold through measured RTT and consumption rate.

Flow-control limits MUST NOT decrease. A receiver ignores duplicate or lower values.

## 20.4 Blocked senders

UMP/1 has no mandatory blocked-status frame. A blocked sender waits for credit or applies an application deadline.

The sender MUST propagate sustained backpressure to the local application. It MUST NOT buffer unbounded output.

## 20.5 Violations

Data above stream credit causes `FLOW_CONTROL_ERROR`.

Aggregate new stream data above session credit also causes `FLOW_CONTROL_ERROR`.

---

# 21. Datagram semantics

Datagrams provide message boundaries without reliable delivery.

A sender MUST NOT fragment a UMP datagram across `DATAGRAM` frames. Applications may define segmentation above UMP.

A datagram may be:

* Lost
* Reordered
* Duplicated
* Delivered after a later datagram

The receiver MUST deliver one complete datagram or none of it.

## 21.1 Size

The encoded frame and payload MUST fit the current path packet size and negotiated `maximum_datagram_size`.

An API MUST reject an oversized datagram without truncation.

## 21.2 Expiration

When `EXPIRATION_PRESENT` is set, the sender supplies a relative lifetime.

The receiver SHOULD discard an expired datagram. Clock uncertainty MAY prevent exact enforcement, so applications MUST treat expiration as a freshness hint rather than proof.

The sender MUST remove an expired datagram from queues before transmission.

## 21.3 Duplicate suppression

When `DUPLICATE_SUPPRESSION` is set, the Context ID identifies a bounded application context. The datagram payload MUST begin with an application-defined deduplication identifier unless a future extension adds a transport sequence field.

UMP/1 does not guarantee generic duplicate suppression from Context ID alone. An SDK MUST describe this limitation.

## 21.4 Acknowledgement request

`ACK_REQUESTED` requests packet acknowledgement. It does not make datagram delivery reliable and does not prove application consumption.

The session layer MUST NOT retransmit a datagram because its packet was lost.

---

# 22. Idle timeout

Peers negotiate an idle timeout. The effective timeout is the smaller non-zero value offered by either endpoint.

A zero value disables negotiated idle timeout. Local policy MAY still impose a lifetime or resource timeout.

The effective live-session timeout MUST be at least 3 seconds.

Each endpoint resets its idle timer when it:

* Receives and authenticates an ack-eliciting packet, or
* Receives an ACK for one of its ack-eliciting packets

An endpoint MUST NOT reset the timer for unauthenticated traffic, duplicate packets, or padding-only packets.

On expiry, the endpoint closes locally with `IDLE_TIMEOUT`. It MAY send one `CONNECTION_CLOSE` when a path appears usable.

Applications that need keepalive request it through local policy. The session layer SHOULD send `PING` no more often than needed to preserve the session or carrier mapping.

---

# 23. Session closure

Either endpoint may close an active session.

`CONNECTION_CLOSE` contains a transport or application error code, triggering frame type, and bounded reason text.

The sender MUST:

* Stop accepting new application writes
* Cancel pending stream opens
* Enter `DRAINING`
* Retransmit close only in response to later packets or loss policy

The receiver MUST:

* Stop delivering new application data
* Notify each local stream and session owner
* Enter `DRAINING`

Before authentication, endpoints SHOULD use generic errors or silent discard as required by the handshake profile.

Application cancellation of one stream MUST use stream reset semantics, not session closure.

---

# 24. Key updates

Either endpoint may initiate a key update after handshake confirmation.

An endpoint MUST NOT initiate another update until it has received an authenticated packet in response to the current key phase.

## 24.1 Sending

The initiator:

1. Derives the next traffic secret as defined in `handshake.md`.
2. Increments its key-update sequence.
3. Toggles the short-header key-phase bit.
4. Sends packets with the next keys.
5. Retains old keys for a bounded reordering period.

`KEY_UPDATE` communicates sequence and peer-update request. The key-phase bit controls decryption state.

## 24.2 Receiving

On a new key phase, the receiver derives candidate next keys and attempts authenticated decryption.

After successful decryption, it installs the next receive keys and retains previous keys for:

```text
max(3 * PTO, reordering window duration)
```

The receiver MUST NOT roll back after accepting the next phase. It discards late old-phase packets after the retention window.

## 24.3 Interaction with loss recovery

Packet numbers continue across key updates.

The sender retransmits lost information with current keys. It never recreates the old packet ciphertext.

ACK frames may acknowledge packets from both key phases because both belong to the same packet-number space.

## 24.4 Failure

An endpoint closes with `KEY_UPDATE_ERROR` after authenticated evidence of an invalid update sequence or repeated key-phase transitions without confirmation.

Undecryptable packets alone do not prove a key-update error.

---

# 25. Path model

A path is a session-visible route over one carrier and zero or more relays.

Each path has a local state:

```text
NEW
VALIDATING
VALIDATED
DEGRADED
FAILED
RETIRED
```

Each endpoint maps peer-provided Path IDs to local path objects. Path IDs are scoped to one session direction and MUST NOT serve as global identifiers.

A path record includes:

* Carrier and link reference
* Local and remote addressing context
* Relay circuit references
* Validation state
* MTU
* RTT and congestion state
* Last authenticated activity
* Cost and policy attributes

---

# 26. Path validation

An endpoint MUST validate a new path before sending more than limited probe traffic.

Validation uses an unpredictable 8-byte `PATH_CHALLENGE` and matching `PATH_RESPONSE` on the candidate path.

The endpoint:

1. Sends `PATH_CHALLENGE` on the candidate path.
2. Records the challenge, path, and expiry.
3. Accepts a matching `PATH_RESPONSE` only on that path.
4. Marks the path `VALIDATED` after authenticating the response.

A response on another path does not validate the candidate.

Challenges expire after three PTO durations, with a 1-second minimum. An endpoint SHOULD retry at most three times before marking the path `FAILED`.

Before validation, an endpoint MUST limit bytes sent on the path to three times the authenticated bytes received on it. It MAY send less under local policy.

Path validation proves bidirectional reachability and session-key possession. It does not establish route trust.

---

# 27. Path migration

Migration changes the primary path while preserving session state.

An endpoint may migrate after:

* Current path failure
* Carrier or address change
* Policy change
* Discovery of a better validated path
* Peer `MIGRATE` request

The new path MUST reach `VALIDATED` before carrying unrestricted application traffic.

`MIGRATE` identifies old and new path IDs and a monotonically increasing migration sequence.

The receiver MUST ignore an old or duplicate migration sequence. It MUST reject a sequence that reuses the same value with different fields.

Migration does not reset:

* Packet numbers
* Stream offsets
* Flow-control limits
* Traffic-key phase
* Connection-level loss history

The endpoint creates fresh per-path RTT and congestion state. It MUST NOT copy a congestion window from another path.

An endpoint MAY retain the old path as backup. It SHOULD retire a failed or policy-forbidden path.

If `disable_active_migration` was negotiated, the peer MUST NOT initiate migration based only on a new direct address. Carrier rebinding that preserves the validated path context MAY continue after a reachability check. Relay-directed or locally initiated recovery remains subject to policy.

---

# 28. Path failure

An endpoint may mark a path `DEGRADED` after repeated loss, carrier backpressure, or rising latency.

It marks a path `FAILED` after:

* Carrier reports permanent closure
* Path validation fails
* No authenticated response arrives within local failure policy
* Route or relay layer reports permanent failure

Path failure does not close the session while another usable path exists or recovery remains within session timeout.

When no live path exists, the session enters an implementation-defined suspended condition inside `ACTIVE`. Streams remain open, writes apply backpressure, datagrams may be dropped, and the idle timer continues unless a disruption-tolerant profile negotiated suspension behavior.

---

# 29. Multipath

Multipath requires negotiated capability and `maximum_paths` greater than one.

UMP/1 uses one Session data packet-number space across all paths. ACKs may travel on any validated path and acknowledge packets sent on any path.

Each path retains separate:

* RTT estimates
* Congestion state
* Validation state
* MTU
* Failure state

## 29.1 Scheduling

The sender may distribute packets across validated paths. It MUST obey each path's congestion and carrier limits.

The scheduler SHOULD avoid moving ordered stream data across paths when RTT differences would create excessive reordering.

## 29.2 Duplication

An endpoint MAY duplicate control or latency-sensitive data across paths.

Each duplicate packet MUST use a distinct packet number. Duplicate STREAM frames keep the same offsets.

The sender MUST count every duplicate packet against congestion and carrier budgets. Stream and session flow control count unique bytes once.

## 29.3 ACK routing

The receiver SHOULD send an ACK on the path where it received the ack-eliciting packet. It MAY use another validated path when the receive path cannot send.

## 29.4 Limits

The endpoint MUST NOT maintain more active path records than the negotiated `maximum_paths` plus a bounded validation allowance. Default allowance is two candidate paths.

---

# 30. Connection IDs

Connection IDs route packets to session state while allowing addresses and paths to change.

Each endpoint selects the connection IDs that its peer uses as destination IDs.

A connection ID:

* Is 1 to 20 bytes unless a carrier profile permits zero length
* MUST be unpredictable to off-path observers
* MUST NOT encode an endpoint ID, raw address, or stable device identifier
* MUST NOT be reused across unrelated live sessions

## 30.1 Issuance

`NEW_CONNECTION_ID` carries:

* Monotonic sequence number
* `Retire Prior To` value
* Connection ID
* 16-byte stateless-reset token

The sequence number starts at zero for the first post-handshake issued ID and increases by one.

The sender MUST NOT issue two different connection IDs or reset tokens with the same sequence.

The receiver MUST close with `CONNECTION_ID_ERROR` on conflict.

## 30.2 Active limit

An endpoint MUST NOT provide more active IDs than the peer's `active_connection_id_limit`.

The negotiated limit MUST be at least two when migration is enabled. An endpoint that cannot support two IDs MUST disable active migration.

## 30.3 Retirement

`RETIRE_CONNECTION_ID` names a sequence the sender no longer uses.

An endpoint MUST NOT retire the destination connection ID of the packet carrying the retirement frame unless another active ID is available and the peer can switch safely.

After retirement, the issuer SHOULD retain reset-token handling for at least three PTO durations.

`Retire Prior To` asks the peer to retire all lower sequence numbers. It MUST NOT exceed the issuing frame's Sequence value.

## 30.4 Rotation

An endpoint SHOULD rotate connection IDs during migration and may rotate them to reduce linkability.

It MUST avoid rotation rates that exhaust peer state or create a stable timing fingerprint.

## 30.5 Zero-length IDs

Zero-length connection IDs prohibit connection-ID based migration and multiplexing on the affected carrier context. Both the carrier profile and handshake parameters must permit them.

---

# 31. Stateless reset

An endpoint may send a stateless reset for a short-header packet whose connection ID maps to retired or lost state.

The reset follows `wire-format.md` and MUST:

* Carry the 16-byte token assigned to that connection ID in the canonical
  fixed slot (see `wire-format.md` §76)
* Be shorter than or equal to the triggering packet
* Be indistinguishable in length and leading bytes from protected traffic
* Be rate-limited

An endpoint accepts a reset only when the packet cannot be authenticated and
the token slot matches an active peer-provided token in constant time.

A valid reset closes the session without sending a response.

---

# 32. Carrier behavior

The session layer treats carrier delivery properties as hints, not correctness guarantees.

## 32.1 Unreliable carriers

The session layer performs ACK generation, loss detection, retransmission, pacing, and congestion control.

## 32.2 Reliable ordered carriers

The session layer still uses packet numbers, ACKs, replay protection, flow control, and key updates.

It MAY suppress rapid packet-threshold retransmission when the carrier guarantees ordered delivery. It MUST retain an end-to-end probe timeout so a stalled carrier cannot block recovery forever.

The sender SHOULD keep carrier write queues short so path migration and transport backpressure remain effective.

## 32.3 Carrier replacement

A carrier failure invalidates its link, not the session. The endpoint attempts another permitted carrier or path until idle timeout or local policy ends the session.

---

# 33. Scheduling priorities

The sender SHOULD schedule these classes from highest to lowest urgency:

```text
Close and handshake confirmation
ACK and path validation
Flow control and connection-ID management
Interactive stream data
Normal stream data and datagrams
Bulk stream data
Background traffic
```

Priority does not permit starvation. The scheduler MUST provide bounded progress to active streams when congestion and flow-control credit allow it.

Applications MAY provide stream priority hints. Peers do not trust remote priority as authorization for resource use.

---

# 34. Error handling

Transport errors close the session unless a frame defines stream- or path-scoped recovery.

| Condition | Error |
| --- | --- |
| Malformed frame | `FRAME_ENCODING_ERROR` |
| Invalid frame context or state transition | `PROTOCOL_VIOLATION` |
| Data above advertised credit | `FLOW_CONTROL_ERROR` |
| Stream above advertised count | `STREAM_LIMIT_ERROR` |
| Conflicting connection ID state | `CONNECTION_ID_ERROR` |
| Path validation policy failure | `PATH_VALIDATION_FAILED` |
| Invalid key-update transition | `KEY_UPDATE_ERROR` |
| Authentication or packet protection failure | Silent discard, then local abuse policy |
| Resource quota exhausted | `RESOURCE_LIMIT` or local backpressure |

An endpoint SHOULD omit detailed reason text when it could reveal policy, identity, or parser distinctions to an unauthenticated peer.

Repeated malformed authenticated packets SHOULD close the session even when one occurrence permits frame-scoped recovery.

---

# 35. Resource limits

Every implementation MUST enforce bounded limits for:

* Sent-packet metadata
* ACK ranges
* Replay windows
* Open streams
* Stream reassembly bytes
* Pending application writes
* Queued datagrams
* Candidate paths
* Active paths
* Connection IDs
* Retained old keys
* Close and draining state

Recommended defaults:

| Resource | Default |
| --- | ---: |
| ACK ranges per frame | 64 |
| Replay window per packet space | 4,096 packets |
| Initial peer streams per direction and type | 16 |
| Candidate paths beyond negotiated active paths | 2 |
| Outstanding path challenges per path | 3 |
| Queued datagrams per session | 256 |
| Retained key phases | 2 |

`resource-limits.md` may set deployment profiles and tighter global budgets. It MUST preserve the protocol invariants in this document.

---

# 36. Application-visible behavior

The session API MUST expose enough state for applications to distinguish:

* Clean peer closure
* Transport error
* Stream reset
* Local cancellation
* Flow-control backpressure
* Carrier or path suspension
* Deadline expiry
* Datagram rejection due to size or queue limits

Path migration MUST NOT create a new application session handle.

An application write accepted for a reliable stream means the core owns the bytes until acknowledgement, reset, cancellation, or session failure. It does not mean the peer application consumed them.

A successful datagram send means the core accepted the datagram for transmission. It does not prove network or application delivery.

---

# 37. Concurrency invariants

Implementations may process carriers, timers, and applications concurrently. They MUST serialize state transitions that affect one session.

The implementation MUST ensure:

* One packet number allocation per space at a time
* One final size per stream direction
* Monotonic flow-control limits
* Monotonic stream limits
* Monotonic migration sequences
* Monotonic connection-ID sequences
* At most one unconfirmed locally initiated key update

Cancellation races must produce one stable externally visible result. An implementation MUST NOT acknowledge application ownership of bytes after reporting that it rejected those bytes.

---

# 38. Crash and restart behavior

Live session state is ephemeral in UMP/1.

After process restart, an endpoint MUST NOT reconstruct a live session from persisted packet numbers and traffic keys unless a future extension defines crash-safe session continuity.

The endpoint may use a resumption ticket to create a new session. The new session uses:

* New connection IDs
* New packet-number spaces
* Fresh ephemeral contributions required by the resumption profile

Persisted application state decides whether to reopen application operations.

---

# 39. Security considerations

## 39.1 Memory exhaustion

An attacker may create sparse stream offsets, ACK ranges, candidate paths, or connection IDs. Implementations MUST validate limits before allocation and charge retained state to peer and session quotas.

## 39.2 ACK attacks

Forged ACKs can corrupt congestion and loss state. Endpoints process ACKs only inside authenticated packets and reject acknowledgements for unsent packets.

## 39.3 Path hijacking

An address change does not authorize migration. The peer must authenticate packets and complete path validation.

## 39.4 Linkability

Long-lived connection IDs link paths. Endpoints should rotate IDs during migration, subject to state limits. Packet timing and endpoint addresses may still permit correlation.

## 39.5 Reliable-carrier deadlock

Nested buffering over TCP can delay ACKs and control frames. Implementations should bound carrier queues and give control traffic scheduling priority.

## 39.6 Key-phase attacks

Attackers may flip protected key-phase bits or inject undecryptable packets. Receivers install new keys only after authenticated decryption and bound candidate derivation work.

---

# 40. Required tests

A compliant implementation MUST test:

1. Session state transitions.
2. Packet-number reconstruction at window boundaries.
3. Duplicate and stale packet rejection.
4. ACK range encoding and malformed range rejection.
5. Packet- and time-threshold loss detection.
6. PTO backoff.
7. Stream open, half-close, reset, and final-size conflicts.
8. Overlapping stream data with matching and conflicting bytes.
9. Stream- and session-level flow-control violations.
10. Datagram loss, reordering, size rejection, and expiry.
11. Idle-timeout behavior.
12. Close and draining behavior.
13. Key update with reordering and loss.
14. Path validation, failure, and migration.
15. Multipath ACKs and duplicate stream frames.
16. Connection-ID issue, retire, conflict, and rotation.
17. Reliable-carrier stalls and replacement.
18. Memory bounds under sparse offsets and ACK ranges.
19. Concurrency races between close, reset, migration, and key update.
20. Restart creating new session state.

Property tests SHOULD verify:

```text
Packet numbers never repeat under one key and space.
Flow-control and stream limits never decrease.
Applications receive each reliable stream byte at most once.
One stream direction has one final size.
Unvalidated paths never exceed amplification limits.
Migration never changes endpoint identity or stream state.
```

---

# 41. Minimal UMP/1 compliance

A compliant UMP/1 implementation MUST support:

* One active path
* Independent packet-number spaces
* ACK generation and parsing
* Packet- and time-threshold loss detection
* Probe timeout
* Reliable bidirectional streams
* Stream reset and stop-sending
* Stream and session flow control
* Unreliable datagrams
* Idle timeout
* Session closure and draining
* One key update at a time
* Path challenge and response
* Migration to one replacement path
* Connection-ID issuance and retirement
* Bounded replay and transport state

An implementation MAY defer:

* Concurrent multipath transmission
* Unidirectional application streams, if it does not advertise them
* Active connection-ID rotation beyond migration needs
* Datagram duplicate-suppression extensions
* Suspended sessions with paused idle timeout

An implementation MUST NOT advertise a deferred capability.

---

# 42. Open design decisions

The project must resolve these items before freezing UMP/1 interoperability:

1. Whether to assign dedicated `ACK_ERROR` and `FINAL_SIZE_ERROR` codes.
2. Exact ACK delay exponent default.
3. Carrier-specific initial PTO values.
4. Maximum permitted negotiated idle timeout.
5. Whether UMP/1 requires unidirectional streams.
6. Whether STREAM `OFF_PRESENT = 0` remains legal after the opening frame.
7. Whether DATAGRAM gains a transport sequence number.
8. Exact semantics of datagram duplicate suppression.
9. Whether reliable carriers use packet-threshold loss detection.
10. Whether Path ID remains public in the short header.
11. Whether path IDs use one shared or two directional namespaces.
12. Exact migration behavior after `disable_active_migration`.
13. Whether multipath remains optional for the frozen profile.
14. Whether each path receives an independent Session data packet-number space.
15. Default active connection-ID limit.
16. Connection-ID rotation guidance for privacy profiles.
17. Exact old-key retention cap.
18. Whether a disruption-tolerant profile may pause idle timeout.

---

# 43. Core rule

A UMP session preserves authenticated endpoint and application transport state across packet loss, carrier failure, and path migration.

Endpoints apply packet numbering, acknowledgement, loss recovery, flow control, and key updates above every carrier. Streams provide ordered reliable bytes. Datagrams preserve message boundaries without delivery guarantees. No address, link, path, relay, or connection ID becomes the session identity.
