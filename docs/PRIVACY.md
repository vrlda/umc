# Privacy implementation status

The normative requirements are in [`spec/privacy.md`](../spec/privacy.md).
The implementation follows the opt-in ladder: secure encrypted direct
communication is the default, while anonymity and traffic-analysis defenses
must never be silently enabled or claimed.

| Profile | Current status |
| --- | --- |
| P0 Secure | Implemented and the default: end-to-end authenticated encryption, encrypted identity binding, redacted peer logging, bounded discovery hints, and no TLS-to-endpoint identity conflation. |
| P1 Identity/topology minimization | Partial: the profile and local policy floor are exposed, and the handshake binds a requested minimum and fails closed above the daemon’s p1 maximum; per-session identifiers, bounded hints, and redacted logs exist, while session-level reporting and periodic DCID rotation remain pending. |
| P2 Private routing | Not yet implemented: onion layers, direct-path prohibition, rendezvous/introduction points, and replica privacy remain future work. |
| P3 Traffic analysis resistance | Not yet implemented: opt-in fixed-size padding, cover traffic, and timing hygiene remain future work. |

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
