# Universal Mesh Protocol Wire Format

**Status:** Draft
**Version:** 0.1
**Document:** Wire Format Specification
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines the binary wire format used by UMP nodes after a carrier link has been established.

It specifies:

* Primitive integer encodings
* Packet boundaries
* Public packet headers
* Encrypted packet payloads
* Frame encoding
* Packet-number handling
* Stream frames
* Datagram frames
* Acknowledgements
* Routing frames
* Relay frames
* Path-management frames
* Bundle frames
* Error handling
* Extension rules
* Parser requirements

This document does not define:

* Cryptographic algorithms
* Handshake message contents
* Routing algorithms
* Carrier-specific encapsulation
* Application payload formats

Those are defined in separate specifications.

---

# 2. Design requirements

The wire format MUST be:

* Compact
* Versioned
* Deterministically parseable
* Safe to process under hostile input
* Independent of the underlying carrier
* Suitable for reliable and unreliable links
* Suitable for streams and datagrams
* Extensible without ambiguous parsing
* Compatible with encrypted payloads
* Resistant to downgrade and confusion attacks
* Easy to fuzz
* Implementable without recursive parsers

The wire format MUST NOT require:

* Fixed-width network addresses
* IP addresses
* Human-readable identifiers
* Null-terminated strings
* Unbounded field lengths
* Carrier-specific semantics

---

# 3. Terminology

## 3.1 Packet

A complete UMP protocol unit transferred over a carrier.

A packet contains:

```text
Public Header
Encrypted Payload
Authentication Tag
```

## 3.2 Frame

A typed structure contained inside an encrypted packet payload.

One packet may contain multiple frames.

## 3.3 Public header

The portion of a packet visible before decryption.

The public header contains only fields required to:

* Identify the protocol version
* Select cryptographic state
* Reconstruct packet numbers
* Validate packet size
* Perform limited routing or demultiplexing

## 3.4 Connection ID

A short temporary identifier used to route a packet to local cryptographic state.

A connection ID is not an endpoint identity.

## 3.5 Packet number

A monotonically increasing unsigned integer within a packet-number space.

## 3.6 Varint

A variable-length unsigned integer encoding defined in this document.

---

# 4. Byte order

All fixed-width integers MUST use network byte order:

```text
big-endian
```

Varints use the encoding defined in Section 5.

Bit numbering in diagrams proceeds from most significant bit to least significant bit.

---

# 5. Variable-length integers

UMP uses a QUIC-style prefix varint with four supported widths.

The two most significant bits of the first byte indicate the total encoded width.

| Prefix |   Width | Usable bits |             Maximum value |
| ------ | ------: | ----------: | ------------------------: |
| `00`   |  1 byte |           6 |                        63 |
| `01`   | 2 bytes |          14 |                    16,383 |
| `10`   | 4 bytes |          30 |             1,073,741,823 |
| `11`   | 8 bytes |          62 | 4,611,686,018,427,387,903 |

Examples:

```text
0       → 00 000000
63      → 00 111111
64      → 01 000000 01000000
16383   → 01 111111 11111111
```

A decoder MUST reject:

* Values encoded with an invalid width
* Truncated encodings
* Values larger than the supported field limit
* Non-canonical encodings where a smaller width was required

A sender MUST encode every value using the shortest valid representation.

---

# 6. Length-prefixed byte strings

A byte string is encoded as:

```text
Length: Varint
Value:  Length bytes
```

A decoder MUST validate the length before allocation.

Implementations MUST define maximum lengths for each field type.

A generic byte string MUST NOT exceed:

```text
16 MiB
```

unless a narrower limit is defined for that field.

---

# 7. Protocol constants

## 7.1 Protocol version

UMP v0.1 uses:

```text
Version = 0x00000001
```

The version field is 32 bits.

## 7.2 Magic value

Native UMP carriers MAY use the following magic value:

```text
0x554D5031
```

ASCII representation:

```text
UMP1
```

Censorship-resistant or mimicry carriers MUST NOT be required to expose this magic value.

The magic value belongs to the native carrier profile, not to every possible carrier.

## 7.3 Maximum packet size

The default maximum UMP packet size is:

```text
65,535 bytes
```

Individual carriers MAY impose smaller limits.

UDP-based carriers SHOULD default to a path-safe initial maximum of:

```text
1,200 bytes
```

until path MTU discovery succeeds.

---

# 8. Packet classes

UMP defines four packet classes:

| Class     | Purpose                                  |
| --------- | ---------------------------------------- |
| Initial   | Begin a new handshake                    |
| Retry     | Stateless handshake retry                |
| Handshake | Continue authenticated key establishment |
| Protected | Carry established-session frames         |

The packet class is encoded in the public header.

---

# 9. Common packet structure

Every packet uses the following conceptual structure:

```text
+----------------------------+
| Public Header              |
+----------------------------+
| Encrypted Payload          |
+----------------------------+
| Authentication Tag         |
+----------------------------+
```

The authentication tag size depends on the negotiated AEAD suite.

UMP v0.1 SHOULD use a 16-byte authentication tag.

---

# 10. Header-form byte

The first byte of every native UMP packet is the header-form byte.

```text
  0 1 2 3 4 5 6 7
 +-+-+-+-+-+-+-+-+
 |F| T |K|P| R |
 +-+-+-+-+-+-+-+-+
```

Fields:

```text
F: Header form
T: Packet type
K: Key phase
P: Packet-number length
R: Reserved bits
```

Detailed meaning:

| Bits | Field | Meaning                           |
| ---- | ----- | --------------------------------- |
| 7    | F     | `1` long header, `0` short header |
| 6–5  | T     | Packet type                       |
| 4    | K     | Key phase                         |
| 3–2  | P     | Packet-number encoded length      |
| 1–0  | R     | Reserved                          |

Packet-number length mapping:

| P value |  Length |
| ------- | ------: |
| `00`    |  1 byte |
| `01`    | 2 bytes |
| `10`    | 4 bytes |
| `11`    | 8 bytes |

Reserved bits MUST be set to zero before header protection.

After header protection is removed, a receiver MUST reject non-zero reserved bits unless an extension explicitly defines them.

---

# 11. Long header

Long headers are used for:

* Initial packets
* Retry packets
* Handshake packets
* Version negotiation

Long-header format:

```text
+-------------------------------+
| Header Form Byte              | 1 byte
+-------------------------------+
| Version                       | 4 bytes
+-------------------------------+
| Destination Connection ID Len | 1 byte
+-------------------------------+
| Destination Connection ID     | variable
+-------------------------------+
| Source Connection ID Len      | 1 byte
+-------------------------------+
| Source Connection ID          | variable
+-------------------------------+
| Token Length                  | Varint
+-------------------------------+
| Token                         | variable
+-------------------------------+
| Payload Length                | Varint
+-------------------------------+
| Packet Number                 | 1/2/4/8 bytes
+-------------------------------+
| Encrypted Payload             | variable
+-------------------------------+
| Authentication Tag            | variable
+-------------------------------+
```

## 11.1 Connection ID limits

Connection IDs MUST be between:

```text
0 and 20 bytes
```

A zero-length connection ID is permitted only where explicitly allowed by the carrier or handshake profile.

## 11.2 Token field

The token field is used for:

* Stateless retry cookies
* Invitation authenticators
* Bridge authenticators
* Address-validation tokens
* Future anti-probing extensions

The token MUST be treated as opaque by the generic packet parser.

The token length MUST NOT exceed:

```text
1,024 bytes
```

## 11.3 Payload length

Payload Length includes:

```text
Packet Number
Encrypted Payload
Authentication Tag
```

It excludes the bytes preceding the Payload Length field.

---

# 12. Long-header packet types

When `F = 1`, the two-bit `T` field is interpreted as:

| T    | Type                |
| ---- | ------------------- |
| `00` | Initial             |
| `01` | Retry               |
| `10` | Handshake           |
| `11` | Version Negotiation |

---

# 13. Initial packet

Initial packets begin a new session handshake.

Initial packet requirements:

* MUST use a long header.
* MUST include a source connection ID.
* MAY include a destination connection ID.
* MAY contain a token.
* MUST be encrypted or integrity-protected using initial-key derivation rules from the handshake specification.
* MUST be padded to the carrier-specific minimum Initial size.

For UDP carriers, an Initial packet SHOULD be at least:

```text
1,200 bytes
```

This reduces amplification risk and supports path validation.

---

# 14. Retry packet

Retry packets allow a responder to validate return reachability without allocating significant state.

Retry packet format differs from ordinary encrypted packets:

```text
+-------------------------------+
| Long Header Fields            |
+-------------------------------+
| Retry Token Length            | Varint
+-------------------------------+
| Retry Token                   | variable
+-------------------------------+
| Integrity Tag                 | fixed
+-------------------------------+
```

A Retry packet:

* MUST NOT contain ordinary encrypted frames.
* MUST contain a cryptographically protected retry token.
* MUST bind the token to relevant connection context.
* SHOULD bind the token to observed network information where appropriate.
* MUST expire.
* MUST NOT reveal endpoint identity.

---

# 15. Handshake packet

Handshake packets carry encrypted handshake frames after Initial processing.

Handshake packets:

* MUST use the long header.
* MUST use handshake traffic keys.
* MAY contain multiple handshake-related frames.
* MUST NOT contain application stream data before handshake authorization permits it.

---

# 16. Version negotiation packet

A version-negotiation packet is sent when the received version is unsupported.

Format:

```text
+-------------------------------+
| Long Header                   |
+-------------------------------+
| Supported Version Count       | Varint
+-------------------------------+
| Supported Versions            | 4 bytes each
+-------------------------------+
| Integrity Data                | variable
+-------------------------------+
```

A version-negotiation packet MUST be authenticated when possible.

Implementations MUST protect against downgrade attacks by authenticating the final negotiated version in the handshake transcript.

---

# 17. Short header

Short headers are used after session establishment.

Format:

```text
+-------------------------------+
| Header Form Byte              | 1 byte
+-------------------------------+
| Destination Connection ID     | negotiated length
+-------------------------------+
| Path ID                       | Varint
+-------------------------------+
| Packet Number                 | 1/2/4/8 bytes
+-------------------------------+
| Encrypted Payload             | variable
+-------------------------------+
| Authentication Tag            | variable
+-------------------------------+
```

For short headers:

```text
F = 0
```

The `T` bits are interpreted as packet-space selectors:

| T    | Packet space |
| ---- | ------------ |
| `00` | Session data |
| `01` | Path control |
| `10` | Relay data   |
| `11` | Reserved     |

The destination connection-ID length is negotiated during the handshake.

---

# 18. Header protection

UMP SHOULD apply header protection to:

* Packet-number bytes
* Key-phase bit
* Reserved bits
* Packet-type bits where permitted

Header protection MUST use a negotiated, standardized construction.

Header protection MUST NOT replace authenticated encryption.

Receivers MUST remove header protection before interpreting protected header bits.

---

# 19. Packet numbers

Packet numbers are unsigned 62-bit integers.

Packet numbers:

* Start at zero or another implementation-selected initial value.
* MUST increase monotonically within each packet-number space.
* MUST NOT be reused with the same encryption key.
* MAY be truncated on the wire.
* MUST be reconstructed using the largest successfully processed packet number.

Independent packet-number spaces SHOULD exist for:

* Initial
* Handshake
* Session data
* Path control
* Relay data

A receiver MUST reject packet-number reuse when detected.

---

# 20. Packet payload

The decrypted packet payload contains zero or more frames.

Frames are encoded sequentially:

```text
Frame
Frame
Frame
...
```

There is no global frame-count field.

The packet ends when the decrypted payload length is exhausted.

A receiver MUST reject a packet if any frame:

* Extends beyond the packet boundary
* Uses a malformed length
* Violates packet-context rules
* Uses an invalid frame type
* Uses invalid reserved values

---

# 21. Generic frame encoding

Every frame begins with:

```text
Frame Type: Varint
```

Frame types fall into two categories.

## 21.1 Self-delimiting frames

The frame type defines the exact field layout.

Example:

```text
PING
ACK
MAX_DATA
```

## 21.2 Length-delimited frames

Format:

```text
Frame Type: Varint
Frame Length: Varint
Frame Body: Frame Length bytes
```

Unknown length-delimited frames MAY be skipped if marked optional.

Unknown critical frames MUST cause a protocol error.

---

# 22. Frame-type namespace

Frame types use a 62-bit integer.

The lowest two bits define extension behavior:

| Low bits | Meaning                    |
| -------- | -------------------------- |
| `00`     | Critical, fixed-layout     |
| `01`     | Optional, fixed-layout     |
| `10`     | Critical, length-delimited |
| `11`     | Optional, length-delimited |

A receiver that does not recognize:

* A critical frame MUST close the relevant protocol context.
* An optional length-delimited frame MUST skip it.
* An unknown optional fixed-layout frame MUST reject it because its length is unknown.

Therefore new optional extensions SHOULD use length-delimited frame types.

---

# 23. Core frame registry

UMP v0.1 reserves the following frame types:

|   Type | Name                 |
| -----: | -------------------- |
| `0x00` | PADDING              |
| `0x04` | PING                 |
| `0x08` | ACK                  |
| `0x0C` | CONNECTION_CLOSE     |
| `0x10` | STREAM               |
| `0x14` | RESET_STREAM         |
| `0x18` | STOP_SENDING         |
| `0x1C` | MAX_DATA             |
| `0x20` | MAX_STREAM_DATA      |
| `0x24` | MAX_STREAMS          |
| `0x28` | DATAGRAM             |
| `0x2C` | NEW_CONNECTION_ID    |
| `0x30` | RETIRE_CONNECTION_ID |
| `0x34` | PATH_CHALLENGE       |
| `0x38` | PATH_RESPONSE        |
| `0x3C` | PATH_STATUS          |
| `0x40` | MIGRATE              |
| `0x44` | KEY_UPDATE           |
| `0x48` | ROUTE_REQUEST        |
| `0x4C` | ROUTE_RESPONSE       |
| `0x50` | ROUTE_ERROR          |
| `0x54` | RELAY_OPEN           |
| `0x58` | RELAY_DATA           |
| `0x5C` | RELAY_CLOSE          |
| `0x60` | BUNDLE               |
| `0x64` | BUNDLE_ACK           |
| `0x68` | PEER_HINT            |
| `0x6C` | CAPABILITIES         |
| `0x70` | AUTH                 |
| `0x74` | HANDSHAKE_DATA       |
| `0x78` | SESSION_TICKET       |
| `0x7C` | SERVICE_HINT         |

Frame values may be revised before protocol finalization.

---

# 24. PADDING frame

Type:

```text
0x00
```

Format:

```text
Type: 0x00
```

Each `0x00` byte represents one byte of padding.

Multiple consecutive zero bytes are multiple PADDING frames.

PADDING frames:

* MAY appear in any encrypted packet.
* MUST be ignored by the receiver.
* MAY be used to reach a desired packet size.
* MUST NOT be used outside authenticated protection unless the carrier profile defines it.

---

# 25. PING frame

Type:

```text
0x04
```

Format:

```text
Type: Varint
```

PING is ack-eliciting.

It carries no additional data.

PING may be used for:

* Reachability checks
* Path validation support
* Keeping NAT state alive
* Triggering acknowledgement generation

Applications MUST NOT directly depend on PING semantics.

---

# 26. ACK frame

Type:

```text
0x08
```

Format:

```text
Type
Largest Acknowledged
ACK Delay
ACK Range Count
First ACK Range
Additional ACK Ranges...
```

Each additional range contains:

```text
Gap
ACK Range Length
```

Fields are varints.

Interpretation:

```text
Largest Acknowledged
```

is the largest packet number being acknowledged.

```text
ACK Delay
```

is the delay between receiving that packet and generating the ACK.

ACK delay units are negotiated.

```text
First ACK Range
```

describes the number of contiguous acknowledged packets ending at Largest Acknowledged.

Each additional range describes a lower acknowledged range.

An implementation MUST limit:

* Maximum ACK range count
* Maximum memory retained for acknowledgement state
* ACK generation frequency

Recommended maximum ACK ranges:

```text
64
```

ACK frames are not themselves ack-eliciting.

---

# 27. CONNECTION_CLOSE frame

Type:

```text
0x0C
```

Format:

```text
Type
Error Code
Trigger Frame Type
Reason Length
Reason Bytes
```

Limits:

```text
Reason Length <= 1,024 bytes
```

Reason text SHOULD be UTF-8 but MUST be treated as untrusted display data.

Before full authentication, implementations SHOULD avoid detailed reason strings.

Error codes are defined in Section 52.

---

# 28. STREAM frame

Type:

```text
0x10
```

Format:

```text
Type
Stream ID
Flags
Offset
Data Length
Data
```

All integer fields except Flags use varints.

Flags is one byte:

```text
bit 0: FIN
bit 1: OFF_PRESENT
bit 2: LEN_PRESENT
bit 3: OPEN
bit 4: UNIDIRECTIONAL
bits 5–7: reserved
```

Rules:

* Reserved bits MUST be zero.
* If `OFF_PRESENT = 0`, Offset is omitted and assumed to be zero only for the first frame on that stream.
* If `LEN_PRESENT = 0`, Data extends to the end of the packet.
* `OPEN = 1` indicates the first frame opening the stream.
* `FIN = 1` indicates final stream offset.
* `UNIDIRECTIONAL = 1` applies only to stream creation.

When `OPEN = 1`, the frame additionally includes:

```text
Protocol ID Length
Protocol ID
Initial Stream Metadata Length
Initial Stream Metadata
```

Limits:

```text
Protocol ID Length <= 255 bytes
Initial Stream Metadata Length <= 4,096 bytes
```

Protocol IDs SHOULD use UTF-8 lowercase ASCII-compatible names.

Example:

```text
org.example.echo/1
```

Protocol IDs are application-level selectors and are visible only after session decryption.

---

# 29. Stream identifiers

Stream IDs are unsigned varints.

The low two bits encode:

| Bit | Meaning                                      |
| --- | -------------------------------------------- |
| 0   | Initiator: 0 originator, 1 responder         |
| 1   | Direction: 0 bidirectional, 1 unidirectional |

Remaining bits contain a stream sequence number.

Stream IDs MUST NOT be reused within a session.

---

# 30. RESET_STREAM frame

Type:

```text
0x14
```

Format:

```text
Type
Stream ID
Application Error Code
Final Size
```

RESET_STREAM terminates sending on a stream.

The final size MUST be consistent with previously transmitted data.

---

# 31. STOP_SENDING frame

Type:

```text
0x18
```

Format:

```text
Type
Stream ID
Application Error Code
```

STOP_SENDING requests that the peer stop transmitting on the given stream.

The peer SHOULD respond with RESET_STREAM if transmission is still active.

---

# 32. MAX_DATA frame

Type:

```text
0x1C
```

Format:

```text
Type
Maximum Data
```

Maximum Data is the absolute session-level byte limit permitted by the receiver.

Values MUST NOT decrease.

---

# 33. MAX_STREAM_DATA frame

Type:

```text
0x20
```

Format:

```text
Type
Stream ID
Maximum Stream Data
```

The limit is absolute.

Values MUST NOT decrease.

---

# 34. MAX_STREAMS frame

Type:

```text
0x24
```

Format:

```text
Type
Direction
Maximum Streams
```

Direction:

| Value | Meaning        |
| ----: | -------------- |
|     0 | Bidirectional  |
|     1 | Unidirectional |

Other values are invalid.

---

# 35. DATAGRAM frame

Type:

```text
0x28
```

Format:

```text
Type
Context ID
Flags
Expiration Delta
Data Length
Data
```

Flags:

```text
bit 0: ACK_REQUESTED
bit 1: DUPLICATE_SUPPRESSION
bit 2: EXPIRATION_PRESENT
bits 3–7: reserved
```

If `EXPIRATION_PRESENT = 0`, Expiration Delta is omitted.

Expiration Delta is measured relative to packet send time using negotiated units.

Datagrams:

* Are not retransmitted by default.
* May be dropped.
* May be reordered.
* May be duplicated unless duplicate suppression is requested.
* MUST obey negotiated maximum datagram size.

---

# 36. NEW_CONNECTION_ID frame

Type:

```text
0x2C
```

Format:

```text
Type
Sequence
Retire Prior To
Connection ID Length
Connection ID
Reset Token
```

Reset Token SHOULD be 16 bytes.

Connection ID Length MUST be between 1 and 20 bytes.

This frame allows migration and connection-ID rotation.

---

# 37. RETIRE_CONNECTION_ID frame

Type:

```text
0x30
```

Format:

```text
Type
Sequence
```

A peer MUST stop using the retired connection ID after processing the frame.

---

# 38. PATH_CHALLENGE frame

Type:

```text
0x34
```

Format:

```text
Type
Challenge Data
```

Challenge Data is exactly:

```text
8 bytes
```

The value MUST be unpredictable.

PATH_CHALLENGE is ack-eliciting.

---

# 39. PATH_RESPONSE frame

Type:

```text
0x38
```

Format:

```text
Type
Response Data
```

Response Data is exactly the 8-byte value from the received PATH_CHALLENGE.

A valid response confirms bidirectional reachability on the tested path.

---

# 40. PATH_STATUS frame

Type:

```text
0x3C
```

Format:

```text
Type
Path ID
Status Flags
Estimated RTT
Estimated Bandwidth
Estimated Loss
Cost Class
```

Status Flags:

```text
bit 0: VALIDATED
bit 1: ACTIVE
bit 2: DEGRADED
bit 3: LOCAL
bit 4: METERED
bit 5: CENSORED_OR_FILTERED
bits 6–7: reserved
```

Path metrics are advisory and MUST NOT be trusted as authoritative claims from untrusted peers.

---

# 41. MIGRATE frame

Type:

```text
0x40
```

Format:

```text
Type
Old Path ID
New Path ID
Migration Sequence
Flags
```

Flags:

```text
bit 0: MAKE_PRIMARY
bit 1: KEEP_OLD_PATH
bit 2: DUPLICATE_CRITICAL_FRAMES
bits 3–7: reserved
```

A MIGRATE frame requests session traffic movement to another validated path.

Migration MUST NOT reset:

* Stream state
* Packet-number state
* Flow-control state
* Cryptographic endpoint identity

---

# 42. KEY_UPDATE frame

Type:

```text
0x44
```

Format:

```text
Type
Update Sequence
Flags
```

Flags:

```text
bit 0: REQUEST_PEER_UPDATE
bits 1–7: reserved
```

The exact key-update procedure is defined in the cryptographic specification.

Packet numbers MUST NOT be reset during a key update.

---

# 43. ROUTE_REQUEST frame

Type:

```text
0x48
```

This frame MUST be length-delimited in the finalized registry even if the provisional numeric registry is revised.

Body:

```text
Request ID
Flags
Hop Limit
Expiration Delta
Destination Hint Length
Destination Hint
Path Exclusion Count
Path Exclusions
Requester Auth Length
Requester Auth
```

Flags:

```text
bit 0: ALLOW_RELAY
bit 1: ALLOW_STORE_FORWARD
bit 2: REQUIRE_PRIVATE_RESPONSE
bit 3: LOCAL_SCOPE_ONLY
bit 4: GATEWAY_QUERY
bits 5–7: reserved
```

Limits:

```text
Hop Limit <= 32
Destination Hint Length <= 512 bytes
Path Exclusion Count <= 32
Requester Auth Length <= 1,024 bytes
```

Destination Hint is opaque to the generic frame parser.

It may represent:

* Endpoint lookup token
* Routing hash
* Service hint
* Gateway capability query

---

# 44. ROUTE_RESPONSE frame

Type:

```text
0x4C
```

Body:

```text
Request ID
Response Sequence
Flags
Route Lifetime
Next-Hop Hint Length
Next-Hop Hint
Route Metadata Length
Route Metadata
Authentication Length
Authentication
```

Flags:

```text
bit 0: DIRECT
bit 1: RELAY_REQUIRED
bit 2: STORE_FORWARD_AVAILABLE
bit 3: LOCAL_PATH
bit 4: GATEWAY_PATH
bits 5–7: reserved
```

Route responses MUST expire.

A route response MUST NOT be treated as proof that the advertised route is trustworthy.

---

# 45. ROUTE_ERROR frame

Type:

```text
0x50
```

Body:

```text
Request ID
Error Code
Failed-Hop Index
Diagnostic Length
Diagnostic
```

Diagnostics SHOULD be omitted or minimized across untrusted paths.

---

# 46. RELAY_OPEN frame

Type:

```text
0x54
```

Body:

```text
Relay Circuit ID
Flags
Requested Lifetime
Requested Byte Quota
Next-Hop Hint Length
Next-Hop Hint
Authorization Length
Authorization
```

Flags:

```text
bit 0: BIDIRECTIONAL
bit 1: STORE_FORWARD_ALLOWED
bit 2: PRIVATE_CIRCUIT
bit 3: MULTIPATH_ALLOWED
bits 4–7: reserved
```

A relay MAY reject the request based on local policy.

Relay Circuit IDs are local to the adjacent relay relationship.

---

# 47. RELAY_DATA frame

Type:

```text
0x58
```

Format:

```text
Type
Relay Circuit ID
Relay Sequence
Flags
Data Length
Data
```

Flags:

```text
bit 0: FIN
bit 1: ACK_REQUESTED
bit 2: HIGH_PRIORITY
bits 3–7: reserved
```

Data is opaque to the relay.

A relay MUST NOT parse inner session frames unless it is also an endpoint of that inner session.

---

# 48. RELAY_CLOSE frame

Type:

```text
0x5C
```

Format:

```text
Type
Relay Circuit ID
Reason Code
Final Relay Sequence
```

---

# 49. BUNDLE frame

Type:

```text
0x60
```

This frame carries a disruption-tolerant encrypted bundle.

Format:

```text
Type
Bundle ID Length
Bundle ID
Flags
Priority
Creation Time
Expiration Time
Replication Limit
Destination Hint Length
Destination Hint
Payload Length
Encrypted Bundle Payload
Bundle Auth Length
Bundle Auth
```

Flags:

```text
bit 0: CUSTODY_REQUESTED
bit 1: DELIVERY_ACK_REQUESTED
bit 2: DO_NOT_REPLICATE
bit 3: LOCAL_SCOPE_ONLY
bit 4: HIGH_SENSITIVITY
bits 5–7: reserved
```

Limits:

```text
Bundle ID Length <= 64 bytes
Destination Hint Length <= 512 bytes
Bundle Auth Length <= 1,024 bytes
Payload Length <= local configured maximum
```

A node MUST apply storage policy before accepting a bundle.

A BUNDLE frame MUST NOT force immediate allocation of the declared payload size without validating configured limits.

---

# 50. BUNDLE_ACK frame

Type:

```text
0x64
```

Format:

```text
Type
Bundle ID Length
Bundle ID
Status
Stored Until
Authentication Length
Authentication
```

Status values:

| Value | Meaning          |
| ----: | ---------------- |
|     0 | Received         |
|     1 | Custody accepted |
|     2 | Forwarded        |
|     3 | Delivered        |
|     4 | Rejected         |
|     5 | Expired          |
|     6 | Evicted          |

A BUNDLE_ACK does not necessarily prove final delivery unless authenticated by the destination endpoint.

---

# 51. PEER_HINT frame

Type:

```text
0x68
```

Body:

```text
Hint Count
Repeated Peer Hint Entries
```

Each entry:

```text
Temporary Peer ID Length
Temporary Peer ID
Carrier Type Length
Carrier Type
Connection Hint Length
Connection Hint
Expiration Time
Flags
Authenticator Length
Authenticator
```

Flags:

```text
bit 0: PUBLIC
bit 1: INTRODUCED
bit 2: LOCAL
bit 3: EPHEMERAL
bit 4: DO_NOT_RESHARE
bits 5–7: reserved
```

Limits:

```text
Hint Count <= 32
Temporary Peer ID Length <= 64 bytes
Carrier Type Length <= 64 bytes
Connection Hint Length <= 1,024 bytes
Authenticator Length <= 1,024 bytes
```

A node MUST NOT automatically reshare hints marked `DO_NOT_RESHARE`.

---

# 52. CAPABILITIES frame

Type:

```text
0x6C
```

Body:

```text
Capability Count
Repeated Capability Entries
```

Each entry:

```text
Capability ID
Capability Length
Capability Value
```

Capability ID is a varint.

Capability Value is opaque.

Limits:

```text
Capability Count <= 128
Capability Length <= 4,096 bytes
```

Capabilities MUST be authenticated by the enclosing packet or handshake transcript.

---

# 53. AUTH frame

Type:

```text
0x70
```

Used only in Initial or Handshake packet spaces.

Body:

```text
Auth Method
Auth Data Length
Auth Data
```

Auth methods may include:

* Retry token validation
* Invitation proof
* Bridge proof
* Endpoint authentication
* Delegation proof

The exact methods are defined in the handshake specification.

---

# 54. HANDSHAKE_DATA frame

Type:

```text
0x74
```

Body:

```text
Handshake Offset
Handshake Data Length
Handshake Data
```

Handshake data uses an independent ordered byte stream.

Implementations MUST limit total handshake transcript size.

Recommended maximum:

```text
64 KiB
```

---

# 55. SESSION_TICKET frame

Type:

```text
0x78
```

Body:

```text
Ticket Lifetime
Ticket Age Add
Ticket Nonce Length
Ticket Nonce
Ticket Length
Ticket
```

The ticket is opaque to the receiver.

Session tickets MUST:

* Expire
* Be cryptographically protected
* Be bound to negotiated protocol parameters
* Avoid exposing long-term endpoint identity

---

# 56. SERVICE_HINT frame

Type:

```text
0x7C
```

Body:

```text
Protocol ID Length
Protocol ID
Endpoint Hint Length
Endpoint Hint
Metadata Length
Metadata
Expiration Time
Signature Length
Signature
```

This frame permits lightweight service advertisement.

The core MUST treat Metadata as opaque.

Limits:

```text
Protocol ID Length <= 255 bytes
Endpoint Hint Length <= 512 bytes
Metadata Length <= 4,096 bytes
Signature Length <= 1,024 bytes
```

---

# 57. Packet-context restrictions

Certain frames are permitted only in specific packet classes.

| Frame          | Initial | Handshake   | Protected |
| -------------- | ------- | ----------- | --------- |
| PADDING        | Yes     | Yes         | Yes       |
| PING           | Yes     | Yes         | Yes       |
| ACK            | Yes     | Yes         | Yes       |
| AUTH           | Yes     | Yes         | No        |
| HANDSHAKE_DATA | Yes     | Yes         | No        |
| CAPABILITIES   | Yes     | Yes         | Yes       |
| STREAM         | No      | Conditional | Yes       |
| DATAGRAM       | No      | Conditional | Yes       |
| ROUTE_*        | No      | No          | Yes       |
| RELAY_*        | No      | No          | Yes       |
| BUNDLE         | No      | No          | Yes       |
| PATH_*         | No      | Conditional | Yes       |
| KEY_UPDATE     | No      | No          | Yes       |

Conditional use requires explicit handshake negotiation.

A receiver MUST reject frames appearing in invalid packet contexts.

---

# 58. Frame ordering

Unless otherwise stated, frame order within a packet is not semantically significant.

Exceptions:

* HANDSHAKE_DATA offsets determine logical order.
* STREAM offsets determine stream order.
* Frames affecting packet interpretation MUST NOT depend on earlier frames in the same packet.
* A CONNECTION_CLOSE frame SHOULD be the final non-padding frame.
* KEY_UPDATE applies only according to cryptographic state rules, not immediate frame order.

---

# 59. Retransmission rules

Frames are classified as:

## Retransmittable

* STREAM
* RESET_STREAM
* STOP_SENDING
* MAX_DATA
* MAX_STREAM_DATA
* MAX_STREAMS
* NEW_CONNECTION_ID
* RETIRE_CONNECTION_ID
* PATH_CHALLENGE
* MIGRATE
* KEY_UPDATE
* ROUTE_REQUEST
* ROUTE_RESPONSE
* RELAY_OPEN
* RELAY_CLOSE
* BUNDLE when policy requires reliability

## Not retransmittable

* ACK
* PADDING
* PATH_RESPONSE, unless a new challenge is received
* PATH_STATUS
* DATAGRAM by default
* RELAY_DATA when the inner protocol handles reliability
* BUNDLE_ACK unless application policy requires retry

Retransmission MUST generate a new packet number.

---

# 60. Duplicate handling

Receivers MUST detect duplicate protected packets within an implementation-defined replay window.

Duplicate STREAM data MUST be discarded after consistency validation.

Duplicate frames with state-changing semantics MUST be idempotent or rejected safely.

Examples:

* Repeated MAX_DATA with the same value is harmless.
* Repeated NEW_CONNECTION_ID with conflicting values is an error.
* Repeated BUNDLE with the same Bundle ID SHOULD be deduplicated.
* Repeated ROUTE_REQUEST with the same Request ID SHOULD be suppressed.

---

# 61. Fragmentation

UMP packet fragmentation at the core packet layer is NOT supported.

If a packet exceeds the carrier MTU, the sender MUST:

* Use smaller packets
* Split STREAM data
* Split DATAGRAM data at the application layer
* Use bundle segmentation
* Select a carrier supporting larger frames

Carriers MAY perform their own fragmentation, but UMP correctness MUST NOT depend on successful transparent fragmentation.

---

# 62. Bundle segmentation

Large bundles MAY be segmented using a future optional frame extension.

Version 0.1 implementations SHOULD initially enforce a conservative maximum bundle-frame size.

Recommended default:

```text
256 KiB
```

for stream carriers, subject to local policy.

For datagram carriers, bundle transfer SHOULD occur through reliable streams or segmented extensions.

---

# 63. Time fields

Absolute times are unsigned 64-bit integers representing:

```text
milliseconds since Unix epoch
```

Relative times are varints in negotiated units.

Nodes with unreliable clocks MUST avoid rejecting otherwise valid traffic solely because of small clock differences.

Implementations SHOULD support configurable clock-skew tolerance.

Default tolerance:

```text
5 minutes
```

Security-sensitive expiration checks SHOULD use monotonic clocks where possible after receipt.

---

# 64. Error-code registry

Core transport error codes:

|   Code | Name                   |
| -----: | ---------------------- |
| `0x00` | NO_ERROR               |
| `0x01` | INTERNAL_ERROR         |
| `0x02` | PROTOCOL_VIOLATION     |
| `0x03` | FRAME_ENCODING_ERROR   |
| `0x04` | UNSUPPORTED_VERSION    |
| `0x05` | UNSUPPORTED_FRAME      |
| `0x06` | CRYPTO_ERROR           |
| `0x07` | AUTHENTICATION_FAILED  |
| `0x08` | REPLAY_DETECTED        |
| `0x09` | FLOW_CONTROL_ERROR     |
| `0x0A` | STREAM_LIMIT_ERROR     |
| `0x0B` | CONNECTION_ID_ERROR    |
| `0x0C` | PATH_VALIDATION_FAILED |
| `0x0D` | ROUTE_NOT_FOUND        |
| `0x0E` | ROUTE_LOOP             |
| `0x0F` | RELAY_REFUSED          |
| `0x10` | RESOURCE_LIMIT         |
| `0x11` | STORAGE_LIMIT          |
| `0x12` | EXPIRED                |
| `0x13` | POLICY_REJECTED        |
| `0x14` | CARRIER_FAILURE        |
| `0x15` | HANDSHAKE_TIMEOUT      |
| `0x16` | IDLE_TIMEOUT           |
| `0x17` | KEY_UPDATE_ERROR       |

Application error codes occupy a separate namespace.

---

# 65. Parser safety requirements

Every implementation MUST:

1. Validate packet length before parsing nested fields.
2. Validate every varint before use.
3. Enforce canonical varint encoding.
4. Enforce field-specific maximum lengths.
5. Avoid integer overflow.
6. Avoid signed/unsigned conversion errors.
7. Avoid allocating directly from untrusted lengths.
8. Avoid recursion.
9. Bound loop iteration counts.
10. Bound ACK range counts.
11. Bound capability counts.
12. Bound peer-hint counts.
13. Reject truncated packets.
14. Reject trailing bytes where the structure forbids them.
15. Treat all text as untrusted.
16. Fuzz every frame parser.
17. Test malformed and adversarial combinations.

A parser MUST NOT partially apply state changes before the full relevant frame has been validated.

---

# 66. Memory-allocation rules

Implementations SHOULD parse using slices into the receive buffer where possible.

Before authentication:

```text
Maximum single packet allocation: carrier packet limit
Maximum stored handshake state: implementation-defined and bounded
Maximum pending Initial states: strictly limited
```

After authentication:

* Session memory MUST remain quota-controlled.
* Stream reassembly buffers MUST be bounded.
* Out-of-order data MUST be bounded.
* Bundle allocation MUST obey storage policy.
* Peer-hint data MUST be bounded.

---

# 67. Unknown versions

When receiving an unsupported version:

* A node MAY send a version-negotiation packet.
* A node MUST NOT attempt to interpret frames under an unknown version.
* A node MUST rate-limit version-negotiation responses.
* A node MUST avoid amplification.

Carrier profiles designed for censorship resistance MAY silently ignore unsupported versions.

---

# 68. Unknown frame types

Unknown frame behavior follows the low-bit extension rules from Section 22.

A receiver MUST NOT guess the length of an unknown fixed-layout frame.

Unknown critical frames terminate the relevant session or handshake context.

Unknown optional length-delimited frames are skipped.

---

# 69. Extension fields

Future extensions SHOULD use one of:

* New optional length-delimited frame types
* New capability IDs
* New carrier profiles
* New handshake capabilities
* New route metadata fields

Extensions MUST define:

* Parsing rules
* Maximum size
* Packet contexts
* Authentication requirements
* Retransmission behavior
* Error behavior
* Downgrade behavior
* Privacy implications

---

# 70. Carrier framing

UMP itself defines packets, but carriers differ in how packet boundaries are transferred.

## 70.1 Datagram carriers

For UDP-like carriers:

```text
One carrier datagram = one UMP packet
```

Multiple UMP packets MUST NOT be concatenated into one datagram in v0.1.

A truncated datagram MUST be discarded.

## 70.2 Stream carriers

For TCP-like carriers:

```text
Packet Length: Varint
Packet Bytes: Packet Length bytes
```

The packet length excludes the length prefix itself.

A stream carrier parser MUST enforce a maximum packet length before allocation.

## 70.3 Message carriers

For WebSocket-like or Bluetooth-message carriers:

```text
One carrier message SHOULD contain one UMP packet
```

A carrier MAY split or aggregate internally, but MUST restore UMP packet boundaries.

## 70.4 Raw byte carriers

Raw serial or radio carriers MUST define:

* Packet delimiting
* Escaping
* Integrity checking
* Resynchronization after corruption

These mechanisms belong to the carrier profile.

---

# 71. Native UDP carrier profile

The native UDP profile SHOULD use:

```text
UDP destination port: configurable
One UDP datagram: one UMP packet
Minimum Initial size: 1,200 bytes
Maximum initial datagram size: 1,200 bytes
```

Port numbers MUST NOT be fixed by the protocol.

Nodes SHOULD support random or configured ports.

The native UDP profile is intended for interoperability and testing, not guaranteed censorship resistance.

---

# 72. Native TCP carrier profile

The native TCP profile uses:

```text
Varint packet length
UMP packet bytes
```

The connection MAY carry packets for one or more sessions depending on negotiated multiplexing.

TCP connection closure MUST NOT automatically destroy a UMP session if another validated path exists.

---

# 73. Local-carrier profile requirements

Bluetooth, local Wi-Fi, serial, or radio carrier profiles MUST expose:

* Peer discovery behavior
* Maximum packet size
* Reliability properties
* Ordering properties
* Connection setup
* Link identity hints
* Power-cost information
* Broadcast support
* Resynchronization behavior

Local carrier identifiers MUST NOT be treated as cryptographic endpoint identities.

---

# 74. Privacy considerations

The public header may expose:

* Packet size
* Packet timing
* Temporary connection identifiers
* Version
* Packet class
* Path identifier
* Carrier metadata

The encrypted payload protects:

* Endpoint protocol identifiers
* Application payload
* Stream identifiers
* Route frame contents
* Relay frame contents
* Bundle contents
* Capability details

Where feasible, implementations SHOULD:

* Rotate connection IDs
* Avoid long-lived stable identifiers
* Pad sensitive packets
* Randomize non-semantic timing
* Avoid unique reason strings
* Avoid exposing endpoint identity before encryption
* Avoid unnecessary path metadata

---

# 75. Traffic-analysis considerations

Wire-format encryption does not hide:

* Packet lengths
* Packet timing
* Traffic direction
* Connection duration
* Carrier choice
* Peer IP addresses on IP carriers

Carrier-specific anti-analysis mechanisms MAY add:

* Padding
* Packet coalescing
* Packet splitting
* Timing shaping
* Cover traffic
* Observable-format transformation

These mechanisms are outside the stable core wire format.

---

# 76. Stateless reset

A node that receives a short-header packet for an unknown connection ID MAY send a stateless reset.

A stateless reset:

* MUST be indistinguishable from an ordinary protected packet to an observer lacking the reset token.
* MUST contain an unpredictable body.
* MUST end with the reset token associated with the connection ID.
* MUST be no larger than the triggering packet.
* MUST be rate-limited.

Small triggering packets SHOULD be silently discarded to avoid amplification and fingerprinting.

---

# 77. Idle timeout

Peers negotiate an idle timeout during the handshake.

A session MAY be considered idle when no ack-eliciting packet has been successfully received within the timeout.

Idle timeout MUST NOT be shorter than:

```text
3 seconds
```

unless explicitly configured for a constrained local carrier.

Disconnected store-and-forward state is not necessarily destroyed when a live session times out.

---

# 78. Test vectors

The finalized specification MUST include test vectors for:

* Varint encoding
* Long-header parsing
* Short-header parsing
* Header protection
* Packet-number reconstruction
* AEAD associated-data construction
* STREAM frames
* ACK frames
* ROUTE_REQUEST
* RELAY_DATA
* BUNDLE
* Unknown optional frames
* Malformed length handling

Every official implementation MUST pass the same interoperability vectors.

---

# 79. Fuzzing corpus

The project SHOULD maintain a public fuzzing corpus containing:

* Empty packets
* Truncated headers
* Oversized connection IDs
* Malformed varints
* Non-canonical varints
* Maximum legal values
* Duplicate frames
* Invalid frame contexts
* Nested length inconsistencies
* Huge ACK range counts
* Conflicting stream final sizes
* Invalid route hop limits
* Oversized bundle declarations
* Unknown critical frames
* Unknown optional frames
* Corrupted authentication tags

---

# 80. Reference packet example

The following is a conceptual example, not a finalized byte-level test vector.

```text
Short Header:
    F = 0
    T = session data
    K = 0
    P = 2-byte packet number
    Destination Connection ID = 8 bytes
    Path ID = 1
    Packet Number = 4021

Encrypted Payload:
    STREAM
        Stream ID = 0
        Flags = OPEN | LEN_PRESENT
        Protocol ID = "org.example.echo/1"
        Offset = 0
        Data = "hello"

    PING

Authentication Tag:
    16 bytes
```

The public observer sees only:

```text
temporary connection ID
path identifier
protected header fields
ciphertext length
packet timing
```

The observer does not see the application protocol identifier or payload.

---

# 81. Minimal v0.1 implementation set

A minimal interoperable v0.1 implementation MUST support:

* Canonical varints
* Long and short headers
* Initial packets
* Handshake packets
* Protected packets
* Header protection
* Packet numbers
* PADDING
* PING
* ACK
* CONNECTION_CLOSE
* STREAM
* RESET_STREAM
* STOP_SENDING
* MAX_DATA
* MAX_STREAM_DATA
* MAX_STREAMS
* DATAGRAM
* PATH_CHALLENGE
* PATH_RESPONSE
* MIGRATE
* ROUTE_REQUEST
* ROUTE_RESPONSE
* RELAY_OPEN
* RELAY_DATA
* RELAY_CLOSE
* CAPABILITIES
* AUTH
* HANDSHAKE_DATA
* TCP carrier framing
* UDP carrier framing

BUNDLE and peer-hint support MAY be optional for the first implementation milestone but remain part of the v0.1 protocol family.

---

# 82. Open design decisions

The following decisions remain unresolved and MUST be finalized before implementation interoperability is frozen:

1. Exact AEAD suite.
2. Exact header-protection construction.
3. Exact handshake framework and pattern.
4. Whether packet classes use independent packet-number spaces.
5. Exact packet-number reconstruction algorithm.
6. Exact ACK delay units.
7. Whether Path ID remains public or becomes protected.
8. Whether routing frames use nested end-to-end encryption.
9. Whether relay frames expose per-circuit sequence numbers.
10. Exact Bundle ID derivation.
11. Exact capability registry.
12. Whether native packets expose a magic value.
13. Whether frame-type values should reserve larger extension ranges.
14. Exact maximum handshake transcript size.
15. Whether route requests contain destination hashes or privacy-preserving lookup tokens.
16. Whether connection IDs are selected by receiver or jointly negotiated.
17. Whether 0-RTT application data is permitted.
18. Whether the first release supports multipath packet-number spaces.

---

# 83. Recommended implementation order

The wire-format parser SHOULD be implemented in this order:

1. Varints
2. Length-prefixed byte strings
3. Long header
4. Short header
5. Packet-number parsing
6. Generic frame dispatch
7. PADDING
8. PING
9. ACK
10. CONNECTION_CLOSE
11. STREAM
12. Flow-control frames
13. DATAGRAM
14. Path frames
15. Handshake frames
16. Routing frames
17. Relay frames
18. Bundle frames
19. Extension skipping
20. Fuzzing and differential parser tests

Cryptographic processing SHOULD be added only after the parser can safely reject malformed unauthenticated structures.

---

# 84. Core rule

A UMP packet is a versioned, authenticated container with a minimal public header and one or more encrypted typed frames.

The public header exists only to support packet delivery and cryptographic state selection.

All application, routing, relay, service, and bundle semantics SHOULD remain inside authenticated encryption whenever operationally possible.
