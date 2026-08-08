# Universal Mesh Protocol — Privacy Architecture

**Document:** `privacy.md`
**Protocol:** Universal Mesh Protocol (UMP)
**Project:** Universal Mesh Core (UMC)
**Status:** Draft
**Intended scope:** Normative privacy architecture

---

# 1. Purpose

This document defines the privacy architecture of the Universal Mesh Protocol.

UMP MUST protect more than application payloads.

A secure encrypted connection may still reveal:

* who is communicating,
* where participants are located,
* which service is being accessed,
* where that service is hosted,
* how traffic traverses the network,
* which nodes participate in a service,
* communication timing,
* communication volume,
* relationships between endpoints.

UMP therefore treats metadata protection as a protocol-level concern.

The privacy architecture is designed around one principle:

> A participant MUST learn no more information than is reasonably necessary to perform its immediate protocol role.

Privacy mechanisms MUST NOT depend on project-controlled infrastructure.

---

# 2. Scope

This specification defines requirements for:

* content confidentiality,
* endpoint identity privacy,
* sender and receiver unlinkability,
* topology privacy,
* service-location privacy,
* private service discovery,
* private rendezvous,
* private relaying,
* replica privacy,
* anonymous authorization,
* privacy-preserving credentials,
* traffic-analysis resistance,
* metadata minimization,
* privacy-aware routing,
* privacy-aware logging,
* privacy profiles.

This specification does not attempt to guarantee anonymity against every possible adversary.

In particular, no protocol can guarantee anonymity against an adversary capable of continuously observing every relevant network link and correlating all traffic with sufficient precision.

Implementations MUST document their protection assumptions.

---

# 3. Terminology

## 3.1 Endpoint

A cryptographic UMP participant identified by protocol identity rather than by a network address.

## 3.2 Physical address

A carrier-specific locator such as:

* IP address,
* IP/port tuple,
* Bluetooth address,
* local interface identifier,
* radio address.

Physical addresses MUST NOT be treated as persistent endpoint identities.

## 3.3 Service identity

A cryptographic identifier representing an application or service.

A service identity MUST NOT inherently reveal:

* its physical host,
* its IP address,
* its geographic location,
* its replicas,
* its ingress nodes.

## 3.4 Relay

A node forwarding encrypted UMP traffic between other nodes.

## 3.5 Introduction point

A node or protocol endpoint through which communication with a hidden service can begin without exposing the physical service host.

## 3.6 Rendezvous

A protocol operation allowing two parties to establish communication without requiring either party to publish its physical location directly to the other.

## 3.7 Replica

One of multiple nodes capable of serving the same authenticated service or content.

## 3.8 Observer

An entity capable of observing one or more carriers without necessarily participating in UMP.

## 3.9 Active adversary

An entity capable of:

* connecting to nodes,
* injecting traffic,
* dropping traffic,
* replaying traffic,
* delaying traffic,
* modifying unauthenticated traffic,
* operating malicious nodes.

## 3.10 Global passive adversary

An adversary capable of observing a sufficiently large fraction of network traffic to correlate traffic entering and leaving privacy paths.

UMP does not claim perfect anonymity against a global passive adversary.

---

# 4. Privacy properties

UMP separates privacy into five primary properties.

```text
P-CONTENT     Content privacy
P-IDENTITY    Identity privacy
P-TOPOLOGY    Topology privacy
P-LOCATION    Location privacy
P-TRAFFIC     Traffic-analysis resistance
```

These properties MUST be considered independently.

An implementation MUST NOT claim that encrypted payloads imply anonymous communication.

---

# 5. Content privacy

Application payloads MUST be end-to-end encrypted between authenticated endpoints unless an application explicitly requests otherwise.

Intermediate nodes MUST NOT require access to application plaintext.

Relays MUST NOT receive session traffic keys that permit them to decrypt application payloads.

Carrier plugins MUST NOT receive application plaintext unless explicitly required by an application-level protocol.

Routing metadata SHOULD be encrypted wherever forwarding does not require plaintext access.

Sensitive control messages MUST use authenticated encryption.

Cryptographic integrity MUST prevent intermediate nodes from modifying protected messages without detection.

---

# 6. Identity privacy

UMP MUST minimize disclosure of persistent endpoint identities.

Long-term identities SHOULD NOT be transmitted in plaintext before authenticated encryption is established.

Where possible, handshake messages visible to unauthenticated observers SHOULD use:

* ephemeral identifiers,
* temporary connection identifiers,
* encrypted identity payloads,
* proof-of-possession mechanisms.

A node MUST NOT disclose another endpoint's persistent identity merely because a third party requests discovery information.

Applications SHOULD be able to establish sessions without revealing a globally reusable identity when persistent identity is unnecessary.

---

# 7. Ephemeral identifiers

UMP SHOULD support temporary identifiers scoped to:

* a session,
* a route,
* a rendezvous,
* an application,
* a peer relationship.

Ephemeral identifiers SHOULD NOT be trivially derivable from permanent identities.

Where practical:

```text
Endpoint A <-> Endpoint B
```

SHOULD use identifiers different from:

```text
Endpoint A <-> Endpoint C
```

This reduces cross-context correlation.

Ephemeral identifiers MUST have bounded lifetimes.

Implementations SHOULD rotate them periodically and after meaningful topology changes.

---

# 8. Physical addresses are path metadata

An IP address or other physical address MUST be treated as temporary path information.

It MUST NOT define endpoint identity.

The following relationship MUST hold:

```text
Endpoint identity != IP address
Endpoint identity != socket
Endpoint identity != carrier
Endpoint identity != relay
Endpoint identity != physical interface
```

Changing:

* Wi-Fi networks,
* cellular providers,
* IP addresses,
* carriers,
* relays,

MUST NOT inherently change endpoint identity.

Physical addresses SHOULD be retained only for as long as operationally useful.

---

# 9. Topology privacy

UMP privacy paths SHOULD prevent any single relay from learning the complete communication route.

For a privacy path:

```text
A -> R1 -> R2 -> R3 -> B
```

the intended knowledge distribution is:

```text
R1:
    previous = A or previous transport hop
    next = R2

R2:
    previous = R1
    next = R3

R3:
    previous = R2
    next = B or an introduction point
```

A relay SHOULD NOT learn:

* the complete route,
* all participating relays,
* unnecessary endpoint identities,
* application payloads.

Higher privacy profiles MUST use layered forwarding information such that each relay can recover only the forwarding information required for its hop.

---

# 10. Layered private routing

UMP MUST define a private routing mode based on layered authenticated encryption.

Conceptually:

```text
Layer R1 {
    next = R2

    Layer R2 {
        next = R3

        Layer R3 {
            destination_context
        }
    }
}
```

Each relay removes exactly one forwarding layer.

A forwarding layer SHOULD contain only:

* next-hop information,
* route-local identifier,
* expiration,
* integrity data,
* necessary forwarding flags.

It MUST NOT unnecessarily contain:

* source identity,
* final service identity,
* complete route,
* application metadata.

Layered routing keys MUST be independent between hops.

Compromise of one relay MUST NOT reveal forwarding layers belonging to unrelated hops.

---

# 11. Route identifiers

Privacy routes MUST use route-local identifiers.

A route identifier MUST NOT be a permanent endpoint identifier.

Different routes between the same endpoints SHOULD use unrelated identifiers.

Route identifiers MUST expire.

Relays SHOULD discard expired route state promptly.

---

# 12. Sender/receiver unlinkability

Higher privacy profiles SHOULD make it difficult for an individual intermediate node to determine both communication endpoints.

Where possible:

* the first relay SHOULD NOT know the final destination,
* the final relay SHOULD NOT know the original source,
* middle relays SHOULD know neither.

Direct communication inherently reveals physical network information between direct peers.

Applications requiring stronger privacy MUST be able to prohibit direct-path optimization.

---

# 13. Direct-path privacy tradeoff

Direct paths provide:

* lower latency,
* lower bandwidth overhead,
* fewer dependencies.

They also reveal physical addressing information between peers.

Therefore an application MUST be able to request:

```text
allow_direct = false
```

for privacy-sensitive sessions.

Routing MUST NOT automatically migrate such a session to a direct path.

A privacy policy MUST override performance optimization.

---

# 14. Private service identity

A mesh-hosted service MUST be identifiable independently from its physical hosts.

Conceptually:

```text
ServiceIdentity
    |
    v
private discovery
    |
    v
introduction / rendezvous
    |
    v
one reachable service instance
```

A service identity MUST NOT encode:

* IP address,
* DNS name,
* geographic location,
* host endpoint identity.

Service identity SHOULD derive from cryptographic key material or another cryptographically authenticated namespace.

---

# 15. Private service discovery

UMP MUST NOT require clients to broadcast plaintext queries such as:

```text
WHO HOSTS SERVICE X?
```

Privacy-capable discovery MUST minimize disclosure of:

* requested service identity,
* querying endpoint identity,
* physical location of service hosts.

Discovery systems MAY use:

* opaque lookup identifiers,
* keyed derivations,
* encrypted descriptors,
* distributed lookup,
* rendezvous records,
* private information retrieval mechanisms,
* future privacy-preserving extensions.

No discovery mechanism SHOULD expose an enumerable global mapping:

```text
ServiceIdentity -> [physical host addresses]
```

---

# 16. Service descriptors

Private services MAY publish encrypted or opaque service descriptors.

A descriptor MAY contain:

* introduction points,
* supported protocol versions,
* ephemeral routing information,
* replica-selection hints,
* expiration,
* service capabilities,
* authentication requirements.

Sensitive descriptor contents SHOULD be accessible only to intended clients.

Descriptors MUST be authenticated by the service identity or an authorized delegated key.

Descriptors MUST expire.

Long-lived descriptors SHOULD rotate introduction information.

---

# 17. Introduction points

A service MAY maintain one or more introduction points.

Introduction points provide reachability without requiring the service host to expose its physical location publicly.

An introduction point SHOULD know only the information necessary to forward introduction traffic.

It SHOULD NOT be required to know:

* application plaintext,
* public client identity,
* complete route to the client,
* complete service topology,
* all service replicas.

Services SHOULD use multiple introduction points where practical.

Introduction points SHOULD be replaceable without changing service identity.

---

# 18. Private rendezvous

High-privacy service communication SHOULD use rendezvous rather than direct client-to-host connections.

Conceptually:

```text
Client
   |
   +-- private path --> Rendezvous <-- private path --+
                                                       |
                                                    Service
```

The client constructs a privacy path toward a rendezvous context.

The service constructs an independent privacy path toward the same context.

The rendezvous mechanism joins the paths without requiring either side to reveal its physical address directly to the other.

The rendezvous node MUST NOT receive application session keys.

The rendezvous node SHOULD NOT learn persistent identities unless required by policy.

Rendezvous identifiers MUST be:

* unguessable,
* temporary,
* scoped,
* replay-resistant.

---

# 19. Replica privacy

A replicated service SHOULD NOT publish the physical identities or addresses of all replicas.

Clients SHOULD discover only enough information to reach one or more suitable instances.

Replica selection MAY consider:

* reachability,
* latency,
* load,
* jurisdiction diversity,
* carrier diversity,
* trust policy,
* privacy policy.

These inputs SHOULD be revealed only where required.

A client MUST NOT need a complete replica list merely to access a service.

---

# 20. Replica unlinkability

Where practical, service replicas SHOULD use service-scoped credentials rather than exposing their unrelated node identities.

A replica SHOULD be able to prove:

> I am authorized to serve Service S.

without necessarily revealing:

> I am permanent Node N.

The exact mechanism MAY use:

* delegated signing keys,
* short-lived certificates,
* anonymous credentials,
* zero-knowledge proofs.

---

# 21. Anonymous authorization

UMP SHOULD support authorization without requiring disclosure of permanent identity.

An application MAY require proof of a statement such as:

```text
The requester possesses a valid membership credential.
```

without requiring the requester to reveal which credential it possesses.

Potential statements include:

* membership,
* invitation possession,
* subscription status,
* role membership,
* publication authority,
* quota possession,
* age or jurisdiction predicates where legally appropriate,
* possession of an unrevoked credential.

The base protocol MUST NOT mandate one zero-knowledge proof system.

---

# 22. Privacy credential interface

UMP SHOULD define an extensible credential-proof interface.

Conceptually:

```text
prove(
    statement,
    credential,
    context
) -> proof
```

and:

```text
verify(
    statement,
    proof,
    context
) -> valid | invalid
```

Proof mechanisms MUST be negotiated explicitly.

Unsupported proof systems MUST fail safely.

Credential proofs MUST be bound to appropriate context to prevent replay across:

* services,
* sessions,
* applications,
* time periods.

---

# 23. Zero-knowledge proof extensions

Zero-knowledge systems MUST be optional extensions.

The minimal UMP core MUST NOT depend on a particular ZK implementation.

A ZK extension specification MUST define:

* proof system,
* security assumptions,
* statement format,
* credential format,
* proof encoding,
* verification procedure,
* replay protection,
* revocation handling,
* domain separation,
* resource limits,
* maximum proof size,
* verification cost limits.

New proof systems MUST undergo independent cryptographic review before becoming stable.

---

# 24. Trust without identity disclosure

Trust and identity MUST remain separate concepts.

A node MAY know that another participant:

```text
is authorized
```

without knowing:

```text
who the participant is globally.
```

Similarly, a service MAY trust a credential issuer without learning the credential holder's permanent UMP identity.

Policy engines SHOULD support both:

```text
identity-based authorization
```

and:

```text
credential-based anonymous authorization
```

---

# 25. Traffic-analysis resistance

Encryption alone does not conceal:

* packet sizes,
* timing,
* connection duration,
* direction,
* burst patterns,
* volume.

Higher privacy profiles SHOULD support traffic-analysis countermeasures.

Possible mechanisms include:

* packet padding,
* size-class normalization,
* randomized padding,
* timing jitter,
* batching,
* delayed transmission,
* cover traffic,
* route rotation,
* multiplexing unrelated sessions.

These mechanisms impose real resource costs.

They MUST therefore be policy-controlled.

---

# 26. Packet-size privacy

Privacy modes SHOULD avoid exposing application-specific packet sizes directly.

Implementations MAY define padded size classes such as:

```text
256
512
1024
1280
4096
...
```

The exact classes MUST account for carrier MTU.

Padding bytes MUST be cryptographically indistinguishable from protected payload data to observers lacking session keys.

Receivers MUST validate padding framing strictly.

---

# 27. Timing privacy

Applications MAY request timing obfuscation.

Implementations MAY introduce:

* randomized delay,
* batching windows,
* constant-rate transmission,
* cover packets.

Timing defenses MUST expose explicit resource policies because they may increase:

* latency,
* bandwidth,
* power consumption.

Mobile and embedded nodes MUST be able to disable expensive traffic defenses.

---

# 28. Cover traffic

Cover traffic MUST be optional.

Cover packets MUST be cryptographically authenticated.

Unauthenticated peers MUST NOT be able to force a node to generate substantial cover traffic.

Cover-traffic policies MUST have:

* bandwidth ceilings,
* power ceilings where applicable,
* time limits,
* peer limits.

The protocol MUST NOT assume cover traffic is universally available.

---

# 29. Route rotation

Privacy routes SHOULD have bounded lifetimes.

Long-lived sessions MAY periodically construct replacement privacy routes.

Route rotation SHOULD consider:

* correlation risk,
* latency,
* network stability,
* resource cost.

Route rotation MUST NOT unnecessarily terminate the logical application session.

A UMP session MAY survive replacement of its underlying privacy path.

---

# 30. Multipath privacy

Using multiple independent paths MAY improve both availability and privacy.

Applications MAY request route diversity.

Possible diversity constraints include:

```text
different first hops
different relay sets
different carriers
different administrative domains
different geographic regions
```

Where geography or administrative ownership cannot be verified reliably, the implementation MUST treat such information as advisory.

Multipath MUST NOT duplicate sensitive plaintext outside end-to-end encryption.

---

# 31. Discovery privacy

Peer discovery MUST follow data minimization.

A node SHOULD NOT reveal its complete peer table.

A discovery response SHOULD contain only bounded information relevant to the requester.

Peer hints SHOULD:

* expire,
* be rate-limited,
* have bounded fan-out,
* respect privacy labels,
* avoid exposing private peers.

A node MUST be able to mark a peer:

```text
do_not_advertise
```

or equivalent.

---

# 32. Enumeration resistance

UMP MUST resist attempts to enumerate:

* nodes,
* services,
* replicas,
* private peers,
* introduction points.

Mechanisms SHOULD include:

* unpredictable identifiers,
* rate limiting,
* authenticated discovery,
* scoped peer exchange,
* private descriptors,
* bounded negative responses.

An unauthenticated actor MUST NOT be able to request a complete network directory.

---

# 33. Active probing resistance

Private nodes MAY operate in modes where unauthenticated probes receive no recognizable UMP response.

Such modes MAY require:

* PSK-gated handshakes,
* invitation tokens,
* authenticated first packets,
* carrier-specific access secrets.

A private node SHOULD be able to appear indistinguishable from:

```text
no compatible service
```

to unauthorized active probes, subject to carrier limitations.

---

# 34. Carrier privacy

Carriers expose different metadata.

UMP MUST NOT assume all carriers provide equivalent privacy.

A carrier profile SHOULD document:

* observable protocol fingerprint,
* exposed addresses,
* packet-size behavior,
* timing behavior,
* active-probing behavior,
* middlebox visibility,
* censorship characteristics.

Applications MAY impose carrier privacy requirements.

Example:

```text
require:
    active_probe_resistance = true
    direct_ip_disclosure = false
```

---

# 35. Carrier independence

Changing carriers MUST NOT inherently require changing:

* endpoint identity,
* service identity,
* application session,
* authorization state.

A privacy-sensitive session SHOULD be able to migrate between carriers while preserving logical session continuity.

---

# 36. Local-network privacy

Local discovery mechanisms MUST NOT automatically broadcast permanent global endpoint identities.

LAN advertisements SHOULD use:

* ephemeral discovery identifiers,
* scoped service identifiers,
* authenticated advertisements where appropriate.

A node SHOULD be configurable as:

```text
undiscoverable
```

while still allowing explicitly authorized inbound sessions.

---

# 37. Logging

Privacy-sensitive information MUST NOT be logged by default.

Default logs MUST NOT contain:

* session keys,
* private keys,
* credential secrets,
* plaintext application payloads,
* complete private routes,
* private service descriptors.

Implementations SHOULD avoid logging:

* persistent peer identifiers,
* IP addresses,
* service identities,
* detailed traffic timing,

unless required for explicitly enabled diagnostics.

Debug logging MUST display a privacy warning when enabling sensitive metadata.

---

# 38. Metrics

Metrics SHOULD be aggregated.

Preferred:

```text
active_sessions = 14
relay_bytes = 4.2GB
route_failures = 3
```

Avoid by default:

```text
endpoint ABC sent 472MB to endpoint XYZ through IP A.B.C.D
```

Telemetry MUST be opt-in.

UMC MUST NOT require project-controlled telemetry infrastructure.

---

# 39. Crash reports

Automatic crash reports MUST NOT include:

* secrets,
* peer databases,
* service descriptors,
* route tables,
* application payloads.

Remote crash reporting MUST be opt-in.

Implementations SHOULD provide local crash artifacts suitable for manual inspection before submission.

---

# 40. Persistent state minimization

Nodes SHOULD persist only information necessary for:

* identity continuity,
* trust policy,
* application requirements,
* operational recovery.

Temporary route state SHOULD normally remain ephemeral.

Expired:

* routes,
* descriptors,
* introduction records,
* rendezvous records,
* ephemeral identifiers,

SHOULD be deleted promptly.

---

# 41. Privacy profiles

UMP defines privacy profiles representing minimum requested behavior.

Profiles are cumulative.

---

## 41.1 P0 — Secure

P0 requires:

* authenticated encryption,
* forward secrecy,
* endpoint authentication,
* replay protection,
* protected application payloads.

P0 does not guarantee:

* topology hiding,
* identity anonymity,
* service-location hiding,
* traffic-analysis resistance.

P0 is appropriate for trusted local networks and constrained environments.

---

## 41.2 P1 — Private

P1 includes P0 and additionally requires:

* identity protection during handshake where possible,
* ephemeral route/session identifiers,
* minimized discovery disclosure,
* no unnecessary permanent identity advertisements,
* bounded peer exchange,
* privacy-aware logging.

P1 remains compatible with direct peer connections.

---

## 41.3 P2 — Anonymous

P2 includes P1 and additionally requires:

* multi-hop privacy routing,
* layered forwarding information,
* sender/receiver unlinkability against individual relays,
* private service discovery where applicable,
* private rendezvous for hidden services,
* no direct physical-address disclosure between endpoints unless explicitly permitted.

Direct-path optimization MUST be disabled by default for P2 sessions.

---

## 41.4 P3 — Hardened

P3 includes P2 and SHOULD additionally use:

* route rotation,
* route diversity,
* packet padding,
* timing defenses,
* optional cover traffic,
* stronger discovery privacy,
* anonymous credentials where authorization is required,
* multiple introduction points,
* replica-location hiding.

P3 is intended for high-risk environments.

P3 consumes substantially more:

* bandwidth,
* CPU,
* memory,
* battery,
* latency.

---

# 42. Privacy negotiation

An application MAY request:

```text
minimum_privacy = P2
```

The core MUST either:

1. establish a route satisfying P2 or higher, or
2. return an explicit failure.

It MUST NOT silently downgrade to P1 or P0.

A peer MAY advertise supported privacy capabilities.

Negotiation MUST be cryptographically bound to the authenticated session to prevent downgrade attacks.

---

# 43. Privacy policy overrides

Local policy MAY require privacy stronger than requested by the application.

For example:

```text
application requests P0
local policy requires P1
effective privacy = P1
```

Local policy MUST NOT silently weaken an application's requested minimum.

---

# 44. Resource-constrained nodes

UMP privacy MUST remain usable on constrained devices.

Therefore:

* P0 MUST remain lightweight.
* P1 SHOULD remain practical on embedded systems.
* P2 and P3 MAY require additional resources.
* ZK proof generation MUST NOT be mandatory for basic node operation.
* cover traffic MUST NOT be mandatory.
* multi-hop anonymity MUST NOT be mandatory for local authenticated communication.

A constrained node MAY rely on more capable peers for routing while retaining end-to-end cryptographic protection.

---

# 45. Relay privacy

Relays MUST be considered untrusted.

A relay MUST NOT require access to:

* application plaintext,
* end-to-end session keys,
* permanent endpoint identities where avoidable.

Relay state MUST be bounded and temporary.

A relay SHOULD identify circuits using opaque local identifiers.

Different hops SHOULD use different circuit identifiers.

---

# 46. Colluding relays

UMP MUST assume that some relays may collude.

A privacy route SHOULD therefore prefer diversity where information is available.

No fixed number of relays can guarantee anonymity against arbitrary collusion.

Applications SHOULD be able to specify minimum hop counts.

Implementations MUST document the privacy implications of hop count.

---

# 47. Malicious introduction points

Introduction points are untrusted.

A malicious introduction point may:

* refuse service,
* delay traffic,
* attempt correlation,
* provide stale information.

It MUST NOT be able to:

* impersonate the service,
* decrypt application traffic,
* forge authenticated service descriptors.

Services SHOULD rotate compromised or unavailable introduction points.

---

# 48. Malicious rendezvous nodes

Rendezvous nodes are untrusted.

A rendezvous node MAY:

* observe traffic timing,
* drop traffic,
* delay traffic,
* attempt correlation.

It MUST NOT possess sufficient cryptographic material to impersonate either endpoint or decrypt application traffic.

---

# 49. Malicious replicas

A malicious replica MUST NOT be able to impersonate a service unless it possesses currently valid service authorization.

Clients MUST authenticate the service cryptographically.

Physical reachability MUST NOT imply authenticity.

For replicated content, clients MUST verify:

* publisher signatures,
* manifests,
* content hashes,
* revocation state where applicable.

---

# 50. Sybil resistance and privacy

Privacy mechanisms MUST NOT assume every network identity corresponds to an independent human or machine.

An adversary may create many nodes.

Route selection SHOULD avoid relying solely on:

```text
number of distinct node IDs
```

as evidence of diversity.

Future mechanisms MAY incorporate:

* historical reliability,
* independent introductions,
* administrative diversity,
* path observations,
* resource proofs,

but MUST avoid turning privacy into mandatory real-world identity disclosure.

---

# 51. Eclipse resistance

A node SHOULD maintain diverse discovery sources.

It SHOULD avoid learning the entire network exclusively from one peer.

Where possible, bootstrap information SHOULD come from independent sources.

Previously known valid peers MAY be retained to assist recovery from attempted eclipse attacks.

Privacy restrictions MUST still apply to retained peer information.

---

# 52. Correlation attacks

UMP recognizes that an observer may correlate:

```text
traffic entering route
```

with:

```text
traffic leaving route
```

using:

* timing,
* volume,
* packet sizes,
* burst structure.

P2 reduces topology exposure but does not claim strong resistance to a global traffic-correlation adversary.

P3 SHOULD deploy additional traffic-analysis countermeasures.

Applications operating under extreme threat models SHOULD assume that sufficiently broad observation can defeat low-latency anonymity.

---

# 53. Latency versus anonymity

Low latency and strong traffic-analysis resistance are partially conflicting goals.

UMP MUST expose this tradeoff rather than conceal it.

Applications MAY prioritize:

```text
latency
bandwidth
battery
anonymity
availability
```

Privacy requirements remain hard minimums.

Performance preferences are optimization objectives.

---

# 54. Denial of service

Privacy mechanisms MUST NOT create unbounded anonymous resource consumption.

Before allocating expensive resources, nodes SHOULD require progressively stronger evidence such as:

* valid cryptographic framing,
* handshake progress,
* authorization,
* bounded proof-of-work where explicitly enabled,
* rate-limit compliance.

Expensive ZK verification MUST be protected by admission control.

Unauthenticated requests MUST have strict CPU, memory, and bandwidth ceilings.

---

# 55. Privacy failure behavior

Privacy failures MUST fail closed where an application requested a minimum privacy level.

Examples:

If P2 routing becomes unavailable:

```text
CORRECT:
session cannot currently satisfy P2

INCORRECT:
silently connect directly
```

If anonymous authorization fails:

```text
CORRECT:
authorization failed

INCORRECT:
request permanent identity instead
```

unless the application explicitly permits identity fallback.

---

# 56. Privacy state changes

If an established route stops satisfying its privacy requirements, the core MUST:

1. attempt migration to a compliant route,
2. suspend sensitive transmission while appropriate,
3. terminate the session if compliance cannot be restored.

It MUST NOT silently continue over a weaker route.

---

# 57. Application visibility

Applications SHOULD receive privacy information such as:

```text
requested_profile
effective_profile
hop_count_range
direct_path
traffic_padding_active
anonymous_authorization_active
```

Applications MUST NOT receive sensitive route topology merely for diagnostics.

The core SHOULD expose properties rather than complete internal routes.

---

# 58. Diagnostics

Privacy diagnostics SHOULD answer:

```text
Why can this session not satisfy P2?
```

without exposing unnecessary network information.

For example:

```text
insufficient privacy-capable relays
private rendezvous unavailable
selected carrier violates policy
```

rather than dumping the complete peer graph.

---

# 59. Private mesh mode

UMC SHOULD support private meshes where membership itself is confidential.

A private mesh MAY require possession of a secret or credential before revealing recognizable protocol behavior.

Unauthorized parties SHOULD learn as little as practical about:

* mesh existence,
* members,
* services,
* topology.

Private-mesh credentials SHOULD be rotatable.

Compromise of one member SHOULD NOT require permanent replacement of all endpoint identities.

---

# 60. Public/private coexistence

A node MAY simultaneously participate in:

```text
public UMP
private mesh A
private mesh B
local mesh C
```

Identity and discovery information SHOULD remain isolated between these contexts unless policy explicitly permits bridging.

A peer learned through a private mesh MUST NOT automatically be advertised publicly.

---

# 61. Gateway privacy

Applications may bridge UMP services to external networks such as:

* HTTP,
* HTTPS,
* messaging platforms,
* traditional Internet services.

A gateway MUST be treated as an application-layer boundary.

The UMP core MUST NOT require a gateway to reveal the physical location of the service it exposes.

A gateway SHOULD connect to hidden services using privacy-preserving UMP routes when requested.

---

# 62. Stateless ingress

Publicly reachable services SHOULD be capable of using multiple replaceable ingress nodes.

An ingress node SHOULD NOT be the canonical identity of the service.

Conceptually:

```text
Internet
   |
   +--> Ingress A --+
   +--> Ingress B --+--> private UMP paths --> Service
   +--> Ingress C --+
```

Loss or compromise of one ingress SHOULD NOT require changing service identity.

Ingress nodes SHOULD contain minimal persistent application state.

---

# 63. Metadata classification

UMP implementations SHOULD classify metadata.

Suggested classes:

```text
PUBLIC
    safe for intentional publication

PEER
    visible to immediate authenticated peer

ROUTE
    visible only to necessary routing participants

SESSION
    visible only to session endpoints

SECRET
    never transmitted except under intended cryptographic protection
```

Protocol structures SHOULD explicitly document the classification of sensitive fields.

---

# 64. Data minimization rule

For every protocol field, designers MUST ask:

1. Which participant requires this field?
2. Why is it required?
3. How long must it exist?
4. Can it use an ephemeral value?
5. Can it be encrypted?
6. Can it be derived locally?
7. Can disclosure be delayed?
8. Can the same function be achieved with less identifying information?

Fields without a clear operational requirement SHOULD NOT be added.

---

# 65. Extension privacy review

Every UMEP affecting protocol behavior MUST include a privacy analysis.

The analysis MUST consider:

* new observable metadata,
* new identifiers,
* correlation risks,
* enumeration risks,
* topology disclosure,
* service-location disclosure,
* logging implications,
* downgrade behavior.

A protocol extension MUST NOT become stable without addressing material privacy regressions.

---

# 66. Cryptographic agility

Privacy mechanisms MUST use versioned cryptographic profiles.

Algorithms MUST be replaceable without changing permanent endpoint identity where possible.

Deprecated algorithms MUST be removable through protocol negotiation and policy.

Downgrade to deprecated privacy mechanisms MUST NOT occur silently.

---

# 67. Implementation fingerprinting

Implementations SHOULD minimize unnecessary differences that allow observers to distinguish:

* UMC versions,
* operating systems,
* device classes,
* applications.

Privacy-sensitive wire behavior SHOULD avoid exposing:

* exact software versions,
* platform names,
* hardware information,

unless operationally necessary.

---

# 68. Error privacy

Protocol errors MUST avoid leaking sensitive state.

An unauthenticated requester SHOULD NOT be able to distinguish unnecessarily between:

```text
unknown service
private service
blocked requester
invalid credential
hidden node
```

where doing so would enable enumeration.

Generic failure responses or silent failure MAY be appropriate before authentication.

---

# 69. Clock privacy

Exact device timestamps MAY aid fingerprinting and correlation.

Protocol messages SHOULD avoid transmitting precise wall-clock values where monotonic counters, relative lifetimes, or coarse timestamps suffice.

Where timestamps are required, specifications SHOULD define the minimum necessary precision.

---

# 70. Privacy-preserving defaults

Default UMC behavior SHOULD prefer:

* encrypted communication,
* ephemeral identifiers,
* minimal logging,
* bounded discovery,
* non-public peer tables,
* no telemetry,
* no unnecessary identity disclosure.

Expensive anonymity mechanisms MAY remain opt-in or application-requested because of their resource cost.

Security MUST be default.

Strong anonymity MUST be available by policy.

---

# 71. Non-goals and impossible guarantees

UMP does not claim to prevent:

* physical device seizure,
* endpoint compromise,
* malware reading application plaintext,
* users voluntarily revealing their identities,
* global traffic correlation under all conditions,
* denial of all communication by complete physical disconnection,
* an authorized service from learning information intentionally supplied by its application.

UMP also cannot force independent nodes to:

* delete previously received data,
* obey routing policy,
* remain online,
* provide truthful self-reported metadata.

Cryptographic verification and protocol design MUST therefore minimize reliance on node honesty.

---

# 72. Required security principle

Privacy MUST NOT depend on trusting intermediate infrastructure.

The intended hierarchy is:

```text
endpoint cryptography
        >
route privacy
        >
relay behavior
        >
carrier behavior
```

A malicious relay may deny service.

It SHOULD NOT be able to silently defeat end-to-end confidentiality or authentication.

---

# 73. Required architecture principle

UMP separates:

```text
WHO
endpoint/service identity

WHERE
temporary physical location

HOW
current route

OVER WHAT
carrier

WHAT
application protocol
```

These concepts MUST remain independently changeable.

In particular:

```text
WHO != WHERE
WHERE != HOW
HOW != CARRIER
```

This separation is fundamental to UMP privacy.

---

# 74. Privacy invariants

A conforming implementation MUST preserve the following invariants:

1. Physical network addresses are not permanent UMP identities.
2. Relays never require application plaintext.
3. Long-term secret keys never leave their owning security boundary.
4. Requested privacy levels are never silently downgraded.
5. Discovery does not provide an unrestricted global node directory.
6. Private peers are not advertised outside their permitted scope.
7. Service identity does not require revealing service location.
8. Private routing does not intentionally reveal the complete route to individual relays.
9. Persistent sensitive metadata is minimized.
10. Privacy-sensitive logs and telemetry are disabled by default.
11. Applications can prohibit direct paths.
12. Cryptographic authentication remains end-to-end across relays.
13. Intermediate infrastructure is assumed untrusted.
14. Unsupported privacy mechanisms fail safely.
15. Privacy extensions undergo explicit privacy and security review.

---

# 75. Reference privacy architecture

A high-privacy public-to-hidden-service connection SHOULD conceptually resemble:

```text
External Client
      |
      v
Replaceable Ingress
      |
      v
Privacy Relay A
      |
      v
Privacy Relay B
      |
      v
Rendezvous
      ^
      |
Privacy Relay C
      ^
      |
Privacy Relay D
      ^
      |
Service Replica
```

The desired knowledge distribution is:

```text
External client:
    knows ingress
    knows service identity

Ingress:
    knows external client
    knows first UMP hop
    does not know physical service host

Relay A/B:
    know adjacent route hops only

Rendezvous:
    joins opaque route contexts
    does not possess application keys

Relay C/D:
    know adjacent route hops only

Service replica:
    knows final route hop
    proves service authorization
    need not expose permanent physical identity

Service:
    authenticates end-to-end
```

No single intermediate component SHOULD possess enough information to trivially reconstruct:

```text
external client
    <->
physical service replica
```

---

# 76. Minimal implementation requirements

A minimal P0 implementation MUST support:

* authenticated encryption,
* forward secrecy,
* replay protection,
* endpoint authentication,
* secure key erasure where practical.

A P1 implementation MUST additionally support:

* identity-hiding handshake behavior,
* ephemeral identifiers,
* privacy-aware discovery,
* safe logging defaults.

A P2 implementation MUST additionally support:

* layered multi-hop privacy routes,
* private service rendezvous,
* direct-path prohibition,
* topology-minimized relay state.

A P3 implementation SHOULD additionally support:

* traffic padding,
* route rotation,
* path diversity,
* timing defenses,
* anonymous authorization extensions,
* stronger discovery privacy.

---

# 77. Future work

Potential future privacy extensions include:

* standardized anonymous credential systems,
* zero-knowledge membership proofs,
* private set intersection for discovery,
* private information retrieval,
* oblivious service lookup,
* mix-network routing modes,
* delay-tolerant anonymous messaging,
* post-quantum anonymous credentials,
* verifiable relay diversity,
* privacy-preserving reputation,
* unlinkable payment authorization,
* stronger global-correlation defenses.

Such mechanisms MUST remain modular unless required by a future major UMP version.

---

# 78. Summary

UMP privacy is based on minimizing what every participant must know.

The protocol aims to make the following independently controllable:

```text
identity
location
route
carrier
application
```

The strongest privacy architecture combines:

```text
end-to-end encryption
        +
identity hiding
        +
ephemeral identifiers
        +
layered multi-hop routing
        +
private discovery
        +
private rendezvous
        +
hidden service replicas
        +
anonymous authorization
        +
traffic-analysis defenses
```

No individual mechanism provides complete privacy.

Together, they allow UMP applications to choose privacy appropriate to their threat model while preserving the ability of the core to operate on constrained hardware.

The fundamental rule is:

> Reveal only what is required to the party that requires it, only for as long as it is required.
