# Universal Mesh Protocol Handshake Specification

**Status:** Draft
**Version:** 0.1
**Document:** Handshake and Key Schedule
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines how two UMP endpoints establish an authenticated, encrypted session.

It specifies:

* Cryptographic algorithm requirements
* Endpoint authentication
* Handshake modes
* Initial key derivation
* Handshake message flow
* Transcript construction
* Identity protection
* Stateless retry
* Invitation and private-bridge authentication
* Active-probing resistance
* Session key derivation
* Key confirmation
* Capability negotiation
* Session resumption
* Optional early data
* Key updates
* Error behavior
* Resource-exhaustion protections

This document does not define:

* Application authentication
* Human-readable identities
* Routing algorithms
* Carrier-specific traffic obfuscation
* Public-key recovery systems
* User-facing trust models

---

# 2. Design objectives

The UMP handshake MUST provide:

1. Mutual endpoint authentication.
2. Forward secrecy.
3. Transcript integrity.
4. Replay resistance.
5. Downgrade resistance.
6. Key confirmation.
7. Session-key separation.
8. Identity hiding from passive observers where possible.
9. Minimal responder work before address or invitation validation.
10. Optional resistance to active protocol probing.
11. Carrier independence.
12. Negotiation of protocol versions and capabilities.
13. Support for known and previously unknown peers.
14. Support for session resumption.
15. Safe rejection of unsupported or malicious inputs.

The handshake SHOULD provide:

1. Responder identity protection from unauthenticated probes.
2. Initiator identity protection until responder authentication.
3. Stateless retry.
4. Private bridge authentication.
5. Session resumption without exposing permanent identity.
6. Resistance to cross-protocol attacks.
7. Resistance to handshake fingerprinting at the core layer.

The handshake does not guarantee:

* Anonymity against a global observer
* Protection after endpoint compromise
* Availability under complete network shutdown
* Indistinguishability from every permitted protocol
* Protection from traffic correlation
* Trustworthiness of authenticated endpoints

Authentication proves possession of an endpoint key. It does not prove that the endpoint is honest.

---

# 3. Cryptographic profile

UMP v0.1 defines one mandatory cryptographic profile.

```text
Profile ID: UMP-CRYPTO-1
```

The mandatory profile uses:

```text
Identity signatures: Ed25519
Ephemeral key agreement: X25519
Static handshake key agreement: X25519
Hash: BLAKE2s-256
HKDF: HKDF-BLAKE2s
AEAD: ChaCha20-Poly1305
Header protection: ChaCha20
Random nonce material: 256-bit cryptographically secure random values
Authentication tag: 16 bytes
```

An implementation MUST NOT silently substitute algorithms.

Future algorithm profiles MUST use distinct profile identifiers.

---

# 4. Endpoint cryptographic material

Each persistent endpoint has two cryptographic key pairs.

## 4.1 Identity signing key

```text
IdentityPrivateKey: Ed25519 private key
IdentityPublicKey:  Ed25519 public key
```

The endpoint identifier is:

```text
EndpointID = BLAKE2s-256(
    "UMP-ENDPOINT-ID-v1" ||
    IdentityPublicKey
)
```

The domain-separation string MUST be encoded exactly as UTF-8 bytes without a terminating null byte.

## 4.2 Static handshake key

```text
HandshakeStaticPrivateKey: X25519 private key
HandshakeStaticPublicKey:  X25519 public key
```

The static handshake key is bound to the identity key using an identity binding.

## 4.3 Identity binding

An identity binding is:

```text
BindingVersion
EndpointID
IdentityPublicKey
HandshakeStaticPublicKey
NotBefore
NotAfter
Sequence
CapabilitiesHash
Signature
```

The signature is:

```text
Ed25519.Sign(
    IdentityPrivateKey,
    BLAKE2s-256(
        "UMP-IDENTITY-BINDING-v1" ||
        canonical_binding_without_signature
    )
)
```

The receiver MUST verify that:

* `EndpointID` matches `IdentityPublicKey`.
* The signature is valid.
* The binding is currently valid, subject to clock-skew policy.
* The sequence is not older than a previously accepted binding.
* The handshake static key is the key used in the handshake.
* The binding is permitted by local trust policy.

## 4.4 Key separation

The identity signing key MUST NOT be used for:

* Diffie–Hellman
* Payload encryption
* Packet encryption
* Header protection
* Session-ticket encryption

The static handshake key MUST NOT be used for:

* Application signatures
* Persistent content signatures
* Human-readable identity claims

---

# 5. Handshake modes

UMP v0.1 defines three handshake modes.

| Mode     | Purpose                                                    |
| -------- | ---------------------------------------------------------- |
| `XX`     | First contact between endpoints                            |
| `IK`     | Initiator already knows responder static handshake key     |
| `PSK-XX` | First contact gated by invitation or private bridge secret |

## 5.1 XX mode

XX mode is mandatory.

It is used when:

* The peers have not communicated previously.
* The initiator does not know the responder’s current static handshake key.
* Public or local peer discovery was used.
* An introduced peer did not provide an authenticated static key.

XX provides mutual authentication while withholding the initiator’s permanent identity until the responder has demonstrated possession of its static handshake key.

## 5.2 IK mode

IK mode is optional in v0.1 but recommended.

It is used when:

* The initiator already knows and trusts the responder’s current identity binding.
* The initiator possesses the responder’s static handshake public key.
* A previous authenticated session or signed invitation supplied the key.

IK reduces round trips.

## 5.3 PSK-XX mode

PSK-XX is mandatory for implementations claiming private-bridge or active-probing resistance.

It is used when access requires prior secret knowledge.

The pre-shared key may come from:

* An invitation
* A QR code
* A trusted peer introduction
* A private bridge secret
* A removable bootstrap file
* An out-of-band exchange

The pre-shared key is an admission secret, not a permanent endpoint identity.

---

# 6. Handshake state machine

A handshake has the following states:

```text
IDLE
INITIAL_SENT
INITIAL_RECEIVED
RETRY_SENT
RETRY_RECEIVED
HANDSHAKE_KEYS
PEER_AUTHENTICATED
SESSION_KEYS
CONFIRMED
CLOSED
```

A node MUST reject messages that are invalid for its current state.

A node MUST NOT install application traffic keys until:

* The required Diffie–Hellman operations have completed.
* The handshake transcript is authenticated.
* The peer identity binding is verified.
* Negotiated parameters are validated.

A node MUST NOT consider a session confirmed until key confirmation has succeeded.

---

# 7. Handshake packet mapping

Handshake messages are transferred inside:

* Initial packets
* Handshake packets
* `AUTH` frames
* `HANDSHAKE_DATA` frames
* `CAPABILITIES` frames

The logical handshake byte stream is carried using `HANDSHAKE_DATA`.

Each handshake message is encoded as:

```text
MessageType:       Varint
MessageLength:     Varint
MessageBody:       MessageLength bytes
```

Handshake messages MUST be processed in ascending handshake-stream offset order.

A receiver MAY buffer out-of-order handshake fragments, subject to strict limits.

The default maximum total handshake transcript is:

```text
65,536 bytes
```

The default maximum individual handshake message is:

```text
16,384 bytes
```

---

# 8. Handshake message registry

UMP v0.1 defines:

|   Type | Name                |
| -----: | ------------------- |
| `0x00` | CLIENT_HELLO        |
| `0x01` | SERVER_HELLO        |
| `0x02` | CLIENT_AUTH         |
| `0x03` | SERVER_FINISHED     |
| `0x04` | CLIENT_FINISHED     |
| `0x05` | RETRY_INFO          |
| `0x06` | NEW_SESSION_TICKET  |
| `0x07` | EARLY_DATA_REJECTED |
| `0x08` | HANDSHAKE_CLOSE     |

Unknown critical handshake messages MUST terminate the handshake.

Future optional messages MUST be length-delimited and explicitly marked optional by the extension registry.

---

# 9. Canonical encoding

All handshake structures MUST use one deterministic canonical binary encoding.

The encoding MUST provide:

* Fixed field order
* Canonical varints
* Length-prefixed byte strings
* No duplicate map keys
* No implicit default values in signed structures
* No indefinite-length values
* No recursive structures

The same semantic handshake structure MUST produce exactly one byte representation.

Signatures and transcript hashes MUST operate on canonical bytes.

---

# 10. Transcript hash

The handshake transcript begins with:

```text
TranscriptHash_0 = BLAKE2s-256(
    "UMP-HANDSHAKE-v1" ||
    selected_handshake_mode ||
    selected_crypto_profile ||
    carrier_binding
)
```

Each logical handshake message updates the transcript:

```text
TranscriptHash_n = BLAKE2s-256(
    TranscriptHash_(n-1) ||
    canonical_message_type ||
    canonical_message_length ||
    canonical_message_body
)
```

Retry packets are incorporated as defined in Section 21.

The final transcript MUST bind:

* UMP protocol version
* Handshake mode
* Cryptographic profile
* Client and server random values
* Ephemeral public keys
* Static handshake keys
* Identity bindings
* Connection IDs
* Selected capabilities
* Carrier binding
* Retry state
* Resumption state
* Early-data acceptance or rejection
* Negotiated application limits

---

# 11. Carrier binding

The handshake MUST be cryptographically bound to the carrier context.

The carrier binding is:

```text
CarrierBinding = BLAKE2s-256(
    "UMP-CARRIER-BINDING-v1" ||
    CarrierType ||
    CarrierInstanceData
)
```

`CarrierInstanceData` MAY include:

* Native carrier profile identifier
* TLS exporter value
* WebSocket connection binding
* Bluetooth link identifier
* Local radio channel context
* A zero-length value where no secure carrier binding exists

The carrier binding MUST NOT contain unstable values that prevent legitimate path migration.

It binds the initial handshake, not the lifetime of the session.

New paths are separately validated.

---

# 12. Initial secrets

Initial packet protection is not endpoint authentication.

Initial keys exist to:

* Prevent trivial plaintext parsing
* Protect handshake framing
* Reduce accidental cross-protocol interpretation
* Provide integrity before authenticated handshake keys exist

For native UMP carriers:

```text
InitialSalt = fixed 32-byte version-specific value
InitialSecret = HKDF-Extract(
    InitialSalt,
    DestinationConnectionID
)
```

Then:

```text
ClientInitialSecret = HKDF-Expand-Label(
    InitialSecret,
    "client initial",
    "",
    32
)

ServerInitialSecret = HKDF-Expand-Label(
    InitialSecret,
    "server initial",
    "",
    32
)
```

Each directional initial secret derives:

```text
packet_key
packet_iv
header_protection_key
```

Initial secrets MUST be discarded after Handshake keys are installed.

Initial packet protection MUST NOT be presented as confidential against an observer who knows the public derivation.

Private carrier profiles MAY define a secret Initial derivation.

---

# 13. HKDF label construction

UMP uses:

```text
HKDF-Expand-Label(
    Secret,
    Label,
    Context,
    Length
)
```

with an encoded label:

```text
Length
"ump v1 " || Label
ContextLength
Context
```

All protocol labels MUST include the `ump v1 ` prefix.

Labels are case-sensitive ASCII.

---

# 14. XX handshake overview

The XX flow is:

```text
Initiator                                Responder

CLIENT_HELLO
  client ephemeral key
  supported parameters
  optional retry token
  optional invitation hint
                         ---------------->

                                      SERVER_HELLO
                                        server ephemeral key
                                        encrypted server static key
                                        encrypted server identity binding
                                        selected parameters
                         <----------------

CLIENT_AUTH
  encrypted client static key
  encrypted client identity binding
  client authentication signature
  client finished data
                         ---------------->

                                      SERVER_FINISHED
                                        server authentication signature
                                        server finished data
                         <----------------

CLIENT_FINISHED
  final key confirmation
                         ---------------->
```

A session is fully confirmed after both sides have validated the required Finished messages.

---

# 15. CLIENT_HELLO

The `CLIENT_HELLO` body contains:

```text
HandshakeVersion
ClientRandom
ClientEphemeralPublicKey
SupportedCryptoProfiles
SupportedHandshakeModes
SupportedProtocolVersions
SupportedCapabilitiesHash
DestinationHint
RetryToken
InvitationAuthenticator
ResumptionTicket
EarlyDataIndication
ClientConnectionParameters
Padding
```

## 15.1 Client random

`ClientRandom` is 32 random bytes.

It MUST be generated independently for every new handshake attempt.

It MUST NOT be reused after a process restart.

## 15.2 Client ephemeral key

The initiator generates a fresh X25519 ephemeral key pair.

The ephemeral private key MUST be erased when:

* The handshake completes
* The handshake fails
* The handshake times out

## 15.3 Destination hint

The destination hint is optional and carrier-dependent.

It MAY identify:

* A temporary connection identifier
* A rendezvous token
* A bridge selector
* A local service token

It MUST NOT contain a plaintext permanent endpoint identifier unless the user’s policy explicitly permits it.

## 15.4 Invitation authenticator

In PSK-XX mode, the initiator includes:

```text
InvitationAuthenticator = HMAC-BLAKE2s(
    InvitationKey,
    "UMP-INVITE-AUTH-v1" ||
    ClientRandom ||
    ClientEphemeralPublicKey ||
    DestinationConnectionID ||
    CarrierBinding
)
```

The authenticator is truncated to 16 bytes.

The invitation key itself MUST NOT be transmitted.

## 15.5 Padding

`CLIENT_HELLO` SHOULD support configurable padding.

Native profiles SHOULD pad Initial packets to at least the carrier minimum.

Anti-censorship carriers MAY define independent outer padding behavior.

---

# 16. SERVER_HELLO

The responder generates a fresh X25519 ephemeral key pair.

Before sending `SERVER_HELLO`, the responder MUST validate any required:

* Retry token
* Invitation authenticator
* Bridge authenticator
* Rate limit
* Admission policy

The message contains:

```text
ServerRandom
ServerEphemeralPublicKey
SelectedProtocolVersion
SelectedCryptoProfile
SelectedHandshakeMode
SelectedCapabilities
ServerConnectionParameters
EncryptedServerAuthentication
ServerHelloAuthenticator
Padding
```

`ServerRandom` is 32 fresh random bytes.

## 16.1 Encrypted server authentication

The encrypted server-authentication block contains:

```text
ServerHandshakeStaticPublicKey
ServerIdentityBinding
ServerDelegationChain
ServerPolicyHints
```

It is encrypted under a key derived from the first ephemeral Diffie–Hellman result:

```text
DH_ee = X25519(
    ServerEphemeralPrivateKey,
    ClientEphemeralPublicKey
)
```

Then:

```text
HandshakeExtract1 = HKDF-Extract(
    zero_salt,
    DH_ee
)

ServerHelloKey = HKDF-Expand-Label(
    HandshakeExtract1,
    "server hello key",
    TranscriptHash_before_server_auth,
    32
)
```

The encrypted block uses ChaCha20-Poly1305.

Its associated data is the current transcript hash and all preceding unencrypted `SERVER_HELLO` fields.

## 16.2 Server identity protection

The server identity key and static handshake key MUST appear only inside the encrypted authentication block in XX mode.

A passive observer MUST NOT be able to derive the responder endpoint identity from `SERVER_HELLO`.

---

# 17. Server authentication proof

After decrypting the server authentication block, the initiator verifies the identity binding.

The server proves possession of both:

* The X25519 static handshake private key
* The Ed25519 identity private key

Possession of the static handshake key is proven through:

```text
DH_es = X25519(
    ClientEphemeralPrivateKey,
    ServerHandshakeStaticPublicKey
)
```

Possession of the identity signing key is proven using a signature in `SERVER_FINISHED`.

The intermediate secret becomes:

```text
HandshakeSecret2 = HKDF-Extract(
    HandshakeExtract1,
    DH_es
)
```

---

# 18. CLIENT_AUTH

After authenticating the responder’s static key binding, the initiator sends `CLIENT_AUTH`.

The message body contains an encrypted authentication block:

```text
ClientHandshakeStaticPublicKey
ClientIdentityBinding
ClientDelegationChain
ClientAuthorizationData
ClientSignature
ClientFinishedMAC
```

The initiator computes:

```text
DH_se = X25519(
    ClientHandshakeStaticPrivateKey,
    ServerEphemeralPublicKey
)
```

Then:

```text
HandshakeSecret3 = HKDF-Extract(
    HandshakeSecret2,
    DH_se
)
```

The client authentication encryption key is:

```text
ClientAuthKey = HKDF-Expand-Label(
    HandshakeSecret3,
    "client auth key",
    TranscriptHash_before_client_auth_ciphertext,
    32
)
```

## 18.1 Client signature

The client signs:

```text
ClientSignatureInput = BLAKE2s-256(
    "UMP-CLIENT-AUTH-v1" ||
    TranscriptHash_before_client_signature ||
    ClientEndpointID ||
    ServerEndpointID ||
    ClientHandshakeStaticPublicKey ||
    ServerHandshakeStaticPublicKey
)
```

The signature is Ed25519.

## 18.2 Static-static contribution

After receiving the client static handshake key, both peers compute:

```text
DH_ss = X25519(
    local_static_handshake_private_key,
    remote_static_handshake_public_key
)
```

The complete handshake secret is:

```text
HandshakeSecret4 = HKDF-Extract(
    HandshakeSecret3,
    DH_ss
)
```

This contribution MUST NOT replace ephemeral Diffie–Hellman.

Forward secrecy depends on the ephemeral contributions.

---

# 19. SERVER_FINISHED

The responder verifies:

* Client identity binding
* Client delegation chain
* Client signature
* Client Finished MAC
* Authorization policy
* Negotiated parameters

The responder then sends:

```text
ServerSignature
ServerFinishedMAC
SessionParametersHash
OptionalSessionTicketPolicy
```

## 19.1 Server signature

```text
ServerSignatureInput = BLAKE2s-256(
    "UMP-SERVER-AUTH-v1" ||
    TranscriptHash_before_server_signature ||
    ServerEndpointID ||
    ClientEndpointID ||
    ServerHandshakeStaticPublicKey ||
    ClientHandshakeStaticPublicKey
)
```

## 19.2 Finished key

```text
ClientFinishedKey = HKDF-Expand-Label(
    HandshakeSecret4,
    "client finished",
    TranscriptHash,
    32
)

ServerFinishedKey = HKDF-Expand-Label(
    HandshakeSecret4,
    "server finished",
    TranscriptHash,
    32
)
```

The Finished MAC is:

```text
HMAC-BLAKE2s(
    FinishedKey,
    TranscriptHash
)
```

The full 32-byte MAC is transmitted.

---

# 20. CLIENT_FINISHED

After validating `SERVER_FINISHED`, the initiator sends `CLIENT_FINISHED`.

It contains:

```text
ClientConfirmationMAC
AcknowledgedSessionParametersHash
```

The confirmation MAC is:

```text
HMAC-BLAKE2s(
    ClientFinishedKey,
    TranscriptHash_after_server_finished
)
```

The responder considers the handshake confirmed after validating `CLIENT_FINISHED`.

The initiator MAY begin sending protected application data after validating `SERVER_FINISHED`, but it MUST retain retransmittable confirmation state until `CLIENT_FINISHED` is acknowledged.

---

# 21. Stateless retry

A responder MAY issue a Retry before performing expensive cryptographic work.

A Retry token SHOULD bind:

```text
TokenVersion
ObservedSourceContext
OriginalDestinationConnectionID
ClientRandom
ClientEphemeralPublicKeyHash
CarrierBindingHash
IssuedAt
ExpiresAt
RetryPolicy
RandomNonce
```

The token is encrypted and authenticated using a responder-local rotating Retry key.

The Retry token MUST:

* Be opaque to the initiator
* Expire quickly
* Be integrity-protected
* Prevent modification
* Prevent use with a different Client ephemeral key
* Prevent use with a different carrier binding where appropriate
* Avoid storing responder-side handshake state

Recommended validity:

```text
30 seconds to 5 minutes
```

## 21.1 Retry transcript binding

After Retry, the transcript begins with a synthetic message:

```text
RETRY_CONTEXT = BLAKE2s-256(
    "UMP-RETRY-CONTEXT-v1" ||
    original_client_hello_hash ||
    retry_packet_hash
)
```

The subsequent handshake transcript MUST include this value.

This prevents removal or substitution of the Retry exchange.

## 21.2 Amplification limit

Before validating return reachability, a responder MUST NOT transmit more than three times the number of bytes received from the apparent source on datagram carriers.

---

# 22. PSK-XX admission secret

PSK-XX adds an admission secret before the responder reveals UMP-specific behavior.

The invitation key is mixed into the first handshake extract:

```text
PSKExtract = HKDF-Extract(
    InvitationKey,
    ClientRandom ||
    ClientEphemeralPublicKey ||
    CarrierBinding
)

HandshakeExtract1 = HKDF-Extract(
    PSKExtract,
    DH_ee
)
```

An invalid invitation authenticator MUST cause one of:

* Silent discard
* Carrier-consistent generic failure
* Normal-looking non-UMP behavior defined by the carrier profile

It MUST NOT produce a distinctive UMP authentication error.

## 22.1 Invitation key scope

Invitation keys SHOULD be:

* Random
* Expiring
* Scope-limited
* Single-use or use-limited
* Bound to a responder or bridge group
* Revocable where practical

Invitation keys MUST NOT be derived from low-entropy passwords without a memory-hard password derivation function.

---

# 23. Active-probing resistance

A node operating in private or anti-probing mode MUST NOT reveal recognizable UMP behavior to an unauthenticated initiator.

Before validating an admission authenticator, the node SHOULD avoid:

* Sending UMP version negotiation
* Sending UMP-specific errors
* Revealing connection IDs
* Revealing identity bindings
* Performing expensive public-key operations
* Maintaining substantial state

The node MAY:

* Silently discard the input
* Close the carrier normally
* Return carrier-compatible cover behavior
* Delay the response within configured limits

The generic UMP specification does not require protocol impersonation.

Carrier plugins MAY implement additional cover behavior.

---

# 24. IK handshake

IK is used when the initiator already knows the responder’s authenticated static handshake key.

The flow is:

```text
Initiator                                Responder

CLIENT_HELLO_IK
  client ephemeral key
  encrypted client static key
  encrypted client identity binding
  client authentication
                         ---------------->

                                      SERVER_HELLO_IK
                                        server ephemeral key
                                        server authentication
                                        finished data
                         <----------------

CLIENT_FINISHED
                         ---------------->
```

The initiator MUST identify the expected responder binding through a local trust record or signed invitation.

If the responder presents a different binding, the handshake MUST fail unless an authenticated key-rotation proof is supplied.

IK MUST still use fresh ephemeral keys.

IK MUST NOT sacrifice forward secrecy merely because static keys are known.

---

# 25. Handshake traffic secrets

After sufficient Diffie–Hellman contributions have been mixed, each side derives directional Handshake traffic secrets:

```text
ClientHandshakeTrafficSecret =
    HKDF-Expand-Label(
        HandshakeSecret3,
        "client handshake traffic",
        TranscriptHash,
        32
    )

ServerHandshakeTrafficSecret =
    HKDF-Expand-Label(
        HandshakeSecret3,
        "server handshake traffic",
        TranscriptHash,
        32
    )
```

Each traffic secret derives:

```text
packet_key
packet_iv
header_protection_key
```

Handshake packet keys MUST be distinct from:

* Initial packet keys
* Session packet keys
* Finished keys
* Resumption secrets
* Exporter secrets

---

# 26. Session master secret

After all required Diffie–Hellman contributions are mixed:

```text
DerivedHandshakeSecret = HKDF-Expand-Label(
    HandshakeSecret4,
    "derived",
    TranscriptHash,
    32
)

SessionMasterSecret = HKDF-Extract(
    DerivedHandshakeSecret,
    zero_input
)
```

Directional session traffic secrets are:

```text
ClientSessionTrafficSecret_0 =
    HKDF-Expand-Label(
        SessionMasterSecret,
        "client session traffic",
        FinalHandshakeTranscriptHash,
        32
    )

ServerSessionTrafficSecret_0 =
    HKDF-Expand-Label(
        SessionMasterSecret,
        "server session traffic",
        FinalHandshakeTranscriptHash,
        32
    )
```

Additional secrets:

```text
ExporterMasterSecret
ResumptionMasterSecret
PathValidationSecret
ConnectionIDSecret
StatelessResetSecret
```

These MUST be independently derived using distinct labels.

---

# 27. Packet key derivation

For any traffic secret:

```text
PacketKey = HKDF-Expand-Label(
    TrafficSecret,
    "packet key",
    "",
    32
)

PacketIV = HKDF-Expand-Label(
    TrafficSecret,
    "packet iv",
    "",
    12
)

HeaderProtectionKey = HKDF-Expand-Label(
    TrafficSecret,
    "header protection",
    "",
    32
)
```

The packet nonce is:

```text
Nonce = PacketIV XOR Encode96(PacketNumber)
```

Packet numbers MUST never repeat under the same PacketKey and PacketIV.

---

# 28. Associated data

The AEAD associated data is the complete unencrypted packet header after header protection has been removed.

It includes:

* Header-form byte
* Version where present
* Connection IDs
* Token-related public fields where present
* Payload length
* Path ID where public
* Encoded packet number

Modification of any associated-data field MUST cause authentication failure.

---

# 29. Capability negotiation

Capabilities are exchanged through:

* `CLIENT_HELLO`
* `SERVER_HELLO`
* Authenticated `CAPABILITIES` frames

The client advertises supported capabilities.

The server selects a subset.

The client confirms the selection.

Negotiated capabilities MUST be included in the transcript.

Security-sensitive capabilities MUST NOT be enabled unless explicitly negotiated.

Capabilities include:

```text
maximum packet size
maximum streams
maximum connection data
maximum stream data
datagram support
multipath support
store-and-forward support
relay support
supported path types
session resumption
early data
padding profiles
key-update limits
idle timeout
ACK delay parameters
```

A server MUST NOT select capabilities the client did not offer.

---

# 30. Connection parameters

Each side advertises connection parameters.

Recommended parameters include:

```text
initial_max_data
initial_max_stream_data
initial_max_bidirectional_streams
initial_max_unidirectional_streams
maximum_datagram_size
idle_timeout
maximum_ack_delay
ack_delay_exponent
active_connection_id_limit
maximum_paths
maximum_bundle_size
maximum_relay_circuits
```

All limits MUST be bounded by local policy.

A received value MUST NOT force the receiver to allocate the advertised amount.

---

# 31. Identity authorization

Cryptographic authentication and authorization are separate.

After validating the peer identity, a node applies local policy.

Possible outcomes:

* Accept unrestricted session
* Accept limited session
* Accept only selected application protocols
* Accept only local communication
* Accept but deny relaying
* Require additional application authentication
* Reject

Authorization decisions SHOULD be included in encrypted session parameters where they affect protocol behavior.

A rejected endpoint SHOULD receive minimal information.

---

# 32. Trust-on-first-use

UMP MAY support trust-on-first-use as a local policy.

When enabled:

1. The first valid identity binding is stored.
2. Future changes require:

   * A valid signed rotation proof
   * Explicit user approval
   * A configured expiry policy
3. Unexpected key changes produce a security warning or rejection.

TOFU is not mandatory.

The protocol itself does not define the user interface for trust decisions.

---

# 33. Key rotation

An endpoint may rotate its static handshake key by issuing a new identity binding with a higher sequence number.

The identity signing key signs the new binding.

A peer that has stored an older binding MUST verify:

* Same identity signing key
* Higher sequence number
* Valid time range
* Valid signature

Identity signing-key rotation requires a separate signed rotation proof.

A rotation proof SHOULD be signed by:

* The old identity key
* The new identity key

If the old key is unavailable, recovery becomes a higher-level trust-policy issue.

---

# 34. Delegation chains

A device or service endpoint MAY authenticate using a delegated identity.

A delegation chain MUST be:

* Canonically encoded
* Signed at every link
* Bounded in length
* Bounded in total size
* Capability-restricted
* Time-limited where possible

Recommended maximum chain length:

```text
4 certificates
```

Recommended maximum encoded chain size:

```text
8 KiB
```

A receiver MUST reject cycles and repeated keys.

---

# 35. Session resumption

A server MAY issue a session ticket after handshake completion.

The ticket is opaque to the client.

A ticket SHOULD contain:

```text
TicketVersion
TicketID
ClientEndpointIDHash
ServerEndpointIDHash
ResumptionSecret
IssuedAt
ExpiresAt
NegotiatedVersion
CryptoProfile
CapabilitySnapshot
AuthorizationSnapshot
AntiReplayPolicy
RandomNonce
```

The ticket is encrypted and authenticated using a server-local rotating ticket key.

## 35.1 Resumption PSK

The client derives:

```text
ResumptionPSK = HKDF-Expand-Label(
    ResumptionMasterSecret,
    "resumption",
    TicketNonce,
    32
)
```

The resumed handshake mixes this PSK into the key schedule.

## 35.2 Ticket lifetime

Recommended maximum ticket lifetime:

```text
24 hours
```

Longer lifetimes require explicit policy.

Tickets MUST be rejected after:

* Expiration
* Identity-key revocation
* Incompatible capability change
* Crypto-profile removal
* Authorization-policy invalidation

---

# 36. Early data

Zero-round-trip early data is OPTIONAL and disabled by default.

Early data is replayable unless the deployment provides strong anti-replay state.

Therefore early data MUST NOT be used for:

* Payments
* State-changing administrative operations
* Account recovery
* Key changes
* Irreversible actions
* Relay quota purchases
* Bundle deletion
* Authorization changes

Early data MAY be used for idempotent operations such as:

* Cacheable requests
* Read-only status queries
* Idempotent service discovery
* Repeated safe requests

Applications MUST explicitly mark protocols as early-data-safe.

The responder MAY reject early data while continuing the handshake.

---

# 37. Replay protection

Each handshake includes fresh:

* Client random
* Server random
* Client ephemeral key
* Server ephemeral key

A responder SHOULD maintain bounded replay detection for:

* Valid invitation authenticators
* Resumption tickets
* Early-data attempts
* Recently completed ClientHello hashes

Replay caches MUST have bounded memory and expiry.

Normal full handshakes remain protected by fresh ephemeral keys and transcript validation.

---

# 38. Handshake timeouts

Recommended defaults:

```text
Initial response timeout:       3 seconds
Handshake total timeout:       15 seconds
Private bridge probe timeout:  carrier-defined
Maximum retransmission count:  5
```

Timeouts SHOULD adapt to carrier properties.

Bluetooth, radio and disruption-tolerant carriers MAY require longer limits.

A timed-out handshake MUST erase ephemeral secrets.

---

# 39. Retransmission

Handshake messages transmitted over unreliable carriers MUST be retransmittable.

Retransmitted logical handshake data:

* Uses new packet numbers
* Retains the same handshake-stream offsets
* Retains the same canonical message bytes
* MUST NOT generate a new ephemeral key unless restarting the entire handshake

A peer MUST handle duplicate handshake fragments idempotently.

Conflicting bytes at the same handshake-stream offset are a protocol violation.

---

# 40. Key discard schedule

Implementations MUST discard secrets promptly.

## 40.1 Initial secrets

Discard after:

* Handshake packet keys are installed
* No outstanding Initial retransmissions remain

## 40.2 Ephemeral private keys

Discard after:

* All required Diffie–Hellman calculations complete
* The handshake is confirmed
* Or the handshake fails

## 40.3 Handshake traffic secrets

Discard after:

* Session traffic keys are installed
* The handshake is confirmed
* No outstanding Handshake retransmissions remain

## 40.4 Old session keys

Retain only for the bounded reordering window required during key update.

---

# 41. Key update

Either endpoint may initiate a key update after handshake confirmation.

The next traffic secret is:

```text
TrafficSecret_(n+1) = HKDF-Expand-Label(
    TrafficSecret_n,
    "traffic update",
    "",
    32
)
```

A key update:

* Does not reset packet numbers
* Does not change endpoint identity
* Does not reset streams
* Does not reset flow control
* Must be acknowledged through successful decryption in the new key phase

Implementations SHOULD update keys after either:

```text
2^24 protected packets
```

or:

```text
one hour of active traffic
```

whichever occurs first.

These values are provisional.

A key update MUST occur before packet-number or AEAD safety limits are approached.

---

# 42. Path migration after handshake

New carriers and paths do not repeat the identity handshake.

They are attached to an existing session using:

* Session-derived path validation tokens
* `PATH_CHALLENGE`
* `PATH_RESPONSE`
* Connection ID validation
* Optional carrier binding

A new path MUST NOT become primary until it is validated.

Path validation MUST prove:

* Bidirectional reachability
* Possession of current session keys
* Association with the intended session

A relay path may require additional relay authorization.

---

# 43. Cross-protocol protection

Every signature, MAC and KDF operation MUST include a unique UMP domain-separation label.

Handshake parsers MUST reject:

* Unexpected message types
* Unexpected field order
* Duplicate mandatory fields
* Unknown critical parameters
* Invalid mode transitions

UMP cryptographic messages MUST NOT be accepted by another protocol context.

Carrier data MUST NOT be interpreted as UMP solely because it decrypts under an unrelated key.

---

# 44. Downgrade protection

The transcript MUST include:

* Client-supported protocol versions
* Server-selected protocol version
* Client-supported cryptographic profiles
* Server-selected cryptographic profile
* Client-supported handshake modes
* Server-selected handshake mode
* Offered and selected security capabilities

If a negotiation value is modified, Finished verification MUST fail.

A peer MUST NOT silently fall back after an authenticated negotiation failure.

Fallback requires a new handshake attempt under explicit local policy.

---

# 45. Unknown algorithm profiles

A node receiving no mutually supported crypto profile MUST:

* Reject the handshake
* Avoid disclosing unnecessary local capabilities
* Rate-limit repeated failures

Private bridge mode SHOULD silently discard incompatible unauthenticated probes.

Algorithm agility MUST NOT permit unauthenticated downgrade.

---

# 46. Handshake errors

Before peer authentication, detailed errors SHOULD NOT be sent.

Permitted unauthenticated behavior includes:

* Silent discard
* Retry
* Generic close
* Carrier-defined failure

After authentication, `HANDSHAKE_CLOSE` may include:

```text
ErrorCode
TriggerMessageType
DiagnosticLength
Diagnostic
```

Diagnostics MUST be bounded and treated as untrusted text.

Recommended handshake errors:

|   Code | Name                       |
| -----: | -------------------------- |
| `0x00` | HANDSHAKE_NO_ERROR         |
| `0x01` | UNSUPPORTED_VERSION        |
| `0x02` | UNSUPPORTED_CRYPTO_PROFILE |
| `0x03` | UNSUPPORTED_HANDSHAKE_MODE |
| `0x04` | INVALID_MESSAGE            |
| `0x05` | INVALID_BINDING            |
| `0x06` | INVALID_SIGNATURE          |
| `0x07` | INVALID_FINISHED           |
| `0x08` | RETRY_REQUIRED             |
| `0x09` | INVALID_RETRY_TOKEN        |
| `0x0A` | INVITATION_REQUIRED        |
| `0x0B` | INVALID_INVITATION         |
| `0x0C` | AUTHORIZATION_REJECTED     |
| `0x0D` | REPLAY_DETECTED            |
| `0x0E` | RESOURCE_LIMIT             |
| `0x0F` | HANDSHAKE_TIMEOUT          |
| `0x10` | IDENTITY_REVOKED           |
| `0x11` | BINDING_EXPIRED            |
| `0x12` | DOWNGRADE_DETECTED         |
| `0x13` | INTERNAL_ERROR             |

---

# 47. Resource-exhaustion protection

Before validating a Retry token or invitation authenticator, a responder SHOULD perform only:

* Packet-length validation
* Minimal header parsing
* Cheap token lookup or MAC verification
* Rate-limit checks
* Stateless response construction

Before authentication, a responder MUST bound:

```text
Concurrent handshake states
Handshake bytes buffered
Out-of-order fragments
Signature verifications
Diffie–Hellman operations
Retry responses
Version responses
Memory per source context
CPU time per source context
```

A responder SHOULD use:

* Stateless retries
* Per-source token buckets
* Global handshake limits
* Admission queues
* Short expiration
* Delayed allocation
* Rotating token keys

Source addresses alone MUST NOT be treated as reliable identities.

---

# 48. Random-number requirements

All cryptographic random values MUST come from an operating-system CSPRNG or equivalent secure source.

The implementation MUST fail closed if secure randomness is unavailable.

Random values include:

* Identity keys
* Static handshake keys
* Ephemeral keys
* Client and server randoms
* Connection IDs
* Retry nonces
* Ticket nonces
* Path challenges
* Invitation keys
* Reset tokens

Testing builds MAY use deterministic randomness only when clearly separated from production builds.

---

# 49. Clock handling

Identity bindings, delegation certificates, Retry tokens and tickets may contain timestamps.

The default allowed clock skew is:

```text
5 minutes
```

Nodes with unreliable clocks MAY use:

* Previously authenticated peer time
* Relative validity windows
* Monotonic time after receipt
* Explicit local trust overrides

A clock anomaly MUST NOT cause acceptance of an invalid signature.

---

# 50. Logging requirements

Implementations MUST NOT log:

* Identity private keys
* Static handshake private keys
* Ephemeral private keys
* Handshake traffic secrets
* Session traffic secrets
* Invitation keys
* Ticket encryption keys
* Full resumption tickets
* Finished keys

Default logs SHOULD avoid:

* Permanent endpoint identifiers
* Full identity public keys
* Full network addresses
* Invitation authenticators
* Detailed authorization reasons

Debug logging that exposes sensitive metadata MUST require explicit opt-in.

---

# 51. Side-channel considerations

Implementations SHOULD:

* Use constant-time cryptographic libraries
* Avoid secret-dependent branching in cryptographic operations
* Avoid detailed timing differences for invalid invitation authenticators
* Avoid distinguishable error timing before authentication
* Clear secret buffers where supported
* Prevent secrets from appearing in crash reports

Perfect timing indistinguishability is not guaranteed.

Carrier plugins may require additional defenses.

---

# 52. Formal verification and testing

The handshake implementation SHOULD be tested using:

* Protocol state-machine tests
* Transcript test vectors
* Differential implementation tests
* Mutation fuzzing
* Packet reordering
* Packet duplication
* Message truncation
* Replay simulation
* Retry substitution
* Downgrade attempts
* Invalid identity bindings
* Invalid signatures
* Malformed delegation chains
* Key-update races
* Path-migration races

The final handshake design SHOULD be modeled using a formal protocol-analysis tool before v1.0.

Suitable categories include:

* Symbolic protocol verification
* State-machine model checking
* Transcript consistency testing
* Cryptographic composition review

---

# 53. Required test vectors

The finalized specification MUST publish vectors for:

1. Endpoint ID derivation.
2. Identity binding signing.
3. Initial secret derivation.
4. Initial packet keys.
5. XX ClientHello.
6. XX ServerHello encryption.
7. Client authentication encryption.
8. All Diffie–Hellman intermediate secrets.
9. Handshake traffic secrets.
10. Client signature input.
11. Server signature input.
12. Finished MACs.
13. Session traffic secrets.
14. Packet-key derivation.
15. Retry-token validation.
16. PSK-XX admission authentication.
17. Session-ticket derivation.
18. Key update.
19. Invalid transcript rejection.
20. Downgrade rejection.

Private keys used in test vectors MUST be clearly marked as test-only.

---

# 54. Minimal v0.1 compliance

A compliant v0.1 implementation MUST support:

* UMP-CRYPTO-1
* Ed25519 endpoint identities
* X25519 static handshake keys
* Identity bindings
* XX handshake mode
* Mutual authentication
* Fresh ephemeral keys
* Transcript hashing
* Initial packet protection
* Handshake packet protection
* Session traffic-key derivation
* Finished key confirmation
* Capability negotiation
* Stateless Retry on datagram carriers
* Handshake timeout
* Replay-resistant packet numbers
* Secret erasure where supported
* Strict message and buffer limits

An implementation MAY defer:

* IK mode
* PSK-XX
* Private bridges
* Session resumption
* Early data
* Delegation chains
* Identity-signing-key rotation
* Advanced cover behavior

An implementation MUST NOT claim active-probing resistance unless it supports PSK-gated or equivalent private admission behavior.

---

# 55. Recommended implementation order

Implement the handshake in this order:

1. Canonical handshake encoding.
2. Endpoint ID derivation.
3. Identity bindings.
4. Transcript hashing.
5. Initial key derivation.
6. Initial packet encryption.
7. XX ClientHello and ServerHello.
8. Ephemeral Diffie–Hellman.
9. Encrypted server authentication.
10. Client identity authentication.
11. Finished MACs.
12. Session traffic-key derivation.
13. Capability negotiation.
14. Stateless Retry.
15. Failure cleanup.
16. Fuzzing.
17. Test vectors.
18. PSK-XX.
19. IK.
20. Session resumption.
21. Key rotation.
22. Formal protocol review.

---

# 56. Open design decisions

The following items remain provisional:

1. Whether BLAKE2s or BLAKE3 should be the mandatory hash.
2. Whether the handshake should directly adopt a named Noise pattern encoding.
3. Whether Ed25519 and X25519 keys should remain separate.
4. Exact identity-binding lifetime defaults.
5. Exact Retry token lifetime.
6. Whether responder authentication should finish in `SERVER_HELLO` or `SERVER_FINISHED`.
7. Whether `CLIENT_FINISHED` is always required.
8. Whether IK belongs in v0.1 interoperability requirements.
9. Whether PSK-XX uses one or multiple PSK mixing points.
10. Whether privacy-sensitive deployments should encrypt capability lists earlier.
11. Whether connection parameters belong inside or outside encrypted authentication blocks.
12. Exact early-data anti-replay requirements.
13. Exact key-update packet limits.
14. Exact delegation certificate format.
15. Exact identity-key rotation mechanism.
16. Whether session tickets may migrate across responder nodes.
17. Whether a cluster of nodes may share private-bridge admission keys.
18. Whether private bridge failures should be silent or carrier-simulated.
19. Exact carrier-binding rules for each carrier.
20. Whether post-quantum hybrid key agreement should be added before v1.0.

---

# 57. Security warning

This specification combines established cryptographic primitives into a new protocol.

Before production deployment, the handshake MUST receive:

* Independent cryptographic review
* State-machine review
* Implementation audit
* Interoperability testing
* Active attack testing
* Formal or semi-formal protocol analysis

The use of standard primitives does not automatically make a new handshake secure.

No production implementation should claim strong censorship resistance or high-assurance security solely from compliance with this draft.

---

# 58. Core handshake rule

A UMP session becomes trusted only after both endpoints have:

1. Contributed fresh ephemeral key material.
2. Authenticated their static handshake keys.
3. Verified identity bindings.
4. Bound all negotiated parameters into one transcript.
5. Derived independent directional traffic keys.
6. Confirmed possession of the resulting handshake secrets.

Permanent endpoint identity, logical session state, carrier selection and network location remain separate concepts.
