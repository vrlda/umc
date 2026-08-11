# Privacy implementation status

The normative requirements are in [`spec/privacy.md`](../spec/privacy.md).
The implementation follows the opt-in ladder: secure encrypted direct
communication is the default, while anonymity and traffic-analysis defenses
must never be silently enabled or claimed.

| Profile | Current status |
| --- | --- |
| P0 Secure | Implemented and the default: end-to-end authenticated encryption, encrypted identity binding, redacted peer logging, bounded discovery hints, and no TLS-to-endpoint identity conflation. |
| P1 Identity/topology minimization | Partial: the profile and local policy floor are exposed, the handshake binds a requested minimum through the capabilities hash, registered sessions report their negotiated profile/direct-path/padding state, candidate enumeration is budgeted, advertised connection IDs rotate on a bounded policy schedule, and optional local-mesh hints use membership authentication. Full discovery minimization remains outside this release. |
| P2 Private routing | Bounded daemon path implemented: direct paths are forbidden for negotiated P2+, originators send a non-reversible route token, each relay resolves only its authenticated adjacent leg, private route metadata is reduced to the local adjacent leg, fresh relay circuit IDs scope downstream legs, and data waits for downstream acceptance. The terminal relay alone resolves the destination endpoint. Rendezvous/replica privacy and global-passive anonymity are outside UMP/1. |
| P3 Traffic analysis resistance | Negotiated and policy-enforced: P3 forces 1,024-byte application padding, applies bounded configurable send jitter, rotates privacy identifiers on a session-preserving cadence, supports optional authenticated cover packets with per-session bandwidth ceilings, and selects bounded diverse relay alternatives with failover on route failure. Anonymous authorization and global-passive anonymity remain outside UMP/1. |

The current live route probe path binds learned candidates to the originating
destination and scope. The daemon's relay-chain path is bounded and
admission-gated; intermediate relays retain only their adjacent route leg,
while the originator may retain the path it selected. This is not a claim of
rendezvous privacy or global-passive anonymity.

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
privacy, and mix modes are outside the current UMP/1 profile. Cover traffic is
implemented only as an optional, locally budgeted defense; it is never
peer-triggered or mandatory.
