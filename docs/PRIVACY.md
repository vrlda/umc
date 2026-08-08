# Privacy implementation status

The normative requirements are in [`spec/privacy.md`](../spec/privacy.md).
The implementation follows the opt-in ladder: secure encrypted direct
communication is the default, while anonymity and traffic-analysis defenses
must never be silently enabled or claimed.

| Profile | Current status |
| --- | --- |
| P0 Secure | Implemented and the default: end-to-end authenticated encryption, encrypted identity binding, redacted peer logging, bounded discovery hints, and no TLS-to-endpoint identity conflation. |
| P1 Identity/topology minimization | Partial: the profile and local policy floor are exposed, the handshake binds a requested minimum and fails closed above the daemon’s p1 maximum, control candidate enumeration is budgeted, and the daemon rotates advertised connection IDs periodically; bounded hints and redacted logs exist, while session-level reporting and mesh-secret hint authentication remain pending. |
| P2 Private routing | Primitives implemented: authenticated onion layers expose only one opaque transition at a time, and sessions can reject direct paths; daemon route integration, rendezvous/introduction points, and replica privacy remain future work. |
| P3 Traffic analysis resistance | Partial: an explicit daemon/session opt-in pads small application payloads to a fixed 1,024-byte target; cover traffic, timing hygiene, and profile-level reporting remain future work. |

Metadata classification used during review:

| Data | Classification |
| --- | --- |
| UMP version, carrier type, packet length | PUBLIC / observer-visible |
| Endpoint IDs in authenticated control state | PEER; not sent in the clear during the handshake |
| Route and relay circuit identifiers | ROUTE / session-local; endpoint topology is not exposed through the application API |
| Traffic keys and identity private material | SECRET; never part of carrier or application payloads |
| Addresses, timing, sizes, connection duration | PUBLIC to the carrier observer; encryption does not hide them |

The project does not claim global-passive anonymity. Anonymous credentials,
private information retrieval, private set intersection, rendezvous/replica
privacy, mix modes, and P3 cover traffic are explicitly out of scope for the
current release and must be documented again before any profile is promoted.
