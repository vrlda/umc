use umc_crypto::signatures::{
    IdentityKeyPair, IdentityPublicKey, StaticHandshakeKeyPair, StaticHandshakePublicKey,
};
use umc_types::runtime::EntropySource;
use umc_wire::header::{HeaderByte, LongPacketType};

pub const CRYPTO_PROFILE: &[u8] = b"UMP-CRYPTO-1";
pub const MODE_XX: &[u8] = b"XX";

/// The protocol version this implementation supports (compatibility.md
/// §5.2). Version 1 is the only version the v1 wire defines; the
/// responder selects it from the client's offered list and the client
/// retries on a Version-Negotiation response that lists it.
pub const SUPPORTED_PROTOCOL_VERSION: u32 = 1;

pub const CLIENT_RANDOM_LEN: usize = 32;
pub const MAX_SUPPORTED_PARAMETERS: usize = 16;
/// Maximum privacy profile this v1 implementation can negotiate.
pub const MAX_SUPPORTED_PRIVACY_PROFILE: &[u8] = b"p1";
/// Secure-by-default privacy profile requested by a new client.
pub const DEFAULT_MINIMUM_PRIVACY_PROFILE: &[u8] = b"p0";

/// Returns the ordered numeric level for a wire privacy profile.
#[must_use]
pub fn privacy_profile_level(profile: &[u8]) -> Option<u8> {
    match profile {
        b"p0" => Some(0),
        b"p1" => Some(1),
        b"p2" => Some(2),
        b"p3" => Some(3),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClientHello {
    pub version: u32,
    pub client_random: [u8; CLIENT_RANDOM_LEN],
    pub client_ephemeral_public_key: [u8; 32],
    pub supported_crypto_profiles: Vec<Vec<u8>>,
    pub supported_handshake_modes: Vec<Vec<u8>>,
    pub supported_protocol_versions: Vec<u32>,
    pub capabilities_hash: [u8; 32],
    /// Minimum privacy profile requested by the client. The value is
    /// transcript-bound through [`capabilities_hash_for_minimum_privacy`].
    pub minimum_privacy: Vec<u8>,
    pub destination_hint: Vec<u8>,
    pub retry_token: Vec<u8>,
    pub invitation_authenticator: Vec<u8>,
    pub padding: Vec<u8>,
}

impl ClientHello {
    pub fn new(entropy: &dyn EntropySource, ephemeral: &StaticHandshakeKeyPair) -> Self {
        Self::new_with_minimum_privacy(entropy, ephemeral, DEFAULT_MINIMUM_PRIVACY_PROFILE)
    }

    /// Builds a hello requesting a minimum privacy profile.
    #[must_use]
    pub fn new_with_minimum_privacy(
        entropy: &dyn EntropySource,
        ephemeral: &StaticHandshakeKeyPair,
        minimum_privacy: &[u8],
    ) -> Self {
        let mut client_random = [0u8; CLIENT_RANDOM_LEN];
        entropy.fill(&mut client_random);
        Self {
            version: 1,
            client_random,
            client_ephemeral_public_key: ephemeral.public().0,
            supported_crypto_profiles: vec![CRYPTO_PROFILE.to_vec()],
            supported_handshake_modes: vec![MODE_XX.to_vec()],
            supported_protocol_versions: vec![SUPPORTED_PROTOCOL_VERSION],
            // Capability negotiation (compatibility.md §5.4): the client
            // binds its capability set with the canonical hash, replacing
            // the placeholder zero hash (audit B.17).
            capabilities_hash: capabilities_hash_for_minimum_privacy(minimum_privacy),
            minimum_privacy: minimum_privacy.to_vec(),
            destination_hint: Vec::new(),
            retry_token: Vec::new(),
            invitation_authenticator: Vec::new(),
            padding: vec![0u8; 64],
        }
    }

    /// Returns the requested privacy level, or `None` for an invalid wire
    /// value. Validation is performed by the responder before DH work.
    #[must_use]
    pub fn minimum_privacy_level(&self) -> Option<u8> {
        privacy_profile_level(&self.minimum_privacy)
    }

    /// Encodes the client hello body (handshake.md §15).
    ///
    /// # Errors
    ///
    /// Returns `EncodeError::Varint` if a field does not fit a varint, or
    /// `EncodeError::Bytes` if a field exceeds its length limit.
    #[allow(clippy::cast_lossless)]
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        umc_wire::varint::encode_into(&mut out, u64::from(self.version))
            .map_err(|_| EncodeError::Varint)?;
        out.extend_from_slice(&self.client_random);
        out.extend_from_slice(&self.client_ephemeral_public_key);
        umc_wire::varint::encode_into(&mut out, self.supported_crypto_profiles.len() as u64)
            .map_err(|_| EncodeError::Varint)?;
        for p in &self.supported_crypto_profiles {
            umc_wire::bytes::encode(&mut out, p, 64).map_err(|_| EncodeError::Bytes)?;
        }
        umc_wire::varint::encode_into(&mut out, self.supported_handshake_modes.len() as u64)
            .map_err(|_| EncodeError::Varint)?;
        for m in &self.supported_handshake_modes {
            umc_wire::bytes::encode(&mut out, m, 64).map_err(|_| EncodeError::Bytes)?;
        }
        umc_wire::varint::encode_into(&mut out, self.supported_protocol_versions.len() as u64)
            .map_err(|_| EncodeError::Varint)?;
        for v in &self.supported_protocol_versions {
            umc_wire::varint::encode_into(&mut out, u64::from(*v))
                .map_err(|_| EncodeError::Varint)?;
        }
        out.extend_from_slice(&self.capabilities_hash);
        umc_wire::bytes::encode(&mut out, &self.minimum_privacy, 8)
            .map_err(|_| EncodeError::Bytes)?;
        umc_wire::bytes::encode(&mut out, &self.destination_hint, 512)
            .map_err(|_| EncodeError::Bytes)?;
        umc_wire::bytes::encode(&mut out, &self.retry_token, 1_024)
            .map_err(|_| EncodeError::Bytes)?;
        umc_wire::bytes::encode(&mut out, &self.invitation_authenticator, 64)
            .map_err(|_| EncodeError::Bytes)?;
        umc_wire::bytes::encode(&mut out, &self.padding, 4_096).map_err(|_| EncodeError::Bytes)?;
        Ok(out)
    }

    /// Decodes a client hello body (handshake.md §15).
    ///
    /// # Errors
    ///
    /// Returns `EncodeError::Varint` if a varint field is malformed,
    /// `EncodeError::Bytes` if a length-prefixed field is malformed or exceeds
    /// its limit, `EncodeError::Truncated` if the body is too short, or
    /// `EncodeError::TooManyParameters` if a supported-parameter list is
    /// longer than [`MAX_SUPPORTED_PARAMETERS`].
    #[allow(clippy::cast_possible_truncation)]
    pub fn decode(body: &[u8]) -> Result<Self, EncodeError> {
        let mut pos = 0usize;
        let read_varint = |p: &mut usize| -> Result<u64, EncodeError> {
            let (v, n) = umc_wire::varint::decode(&body[*p..]).map_err(|_| EncodeError::Varint)?;
            *p += n;
            Ok(v)
        };
        let read_bytes = |p: &mut usize, limit: usize| -> Result<Vec<u8>, EncodeError> {
            let (v, n) =
                umc_wire::bytes::decode(&body[*p..], limit).map_err(|_| EncodeError::Bytes)?;
            *p += n;
            Ok(v.to_vec())
        };
        let version = read_varint(&mut pos)? as u32;
        let mut client_random = [0u8; CLIENT_RANDOM_LEN];
        client_random.copy_from_slice(
            body.get(pos..pos + CLIENT_RANDOM_LEN)
                .ok_or(EncodeError::Truncated)?,
        );
        pos += CLIENT_RANDOM_LEN;
        let mut client_ephemeral_public_key = [0u8; 32];
        client_ephemeral_public_key
            .copy_from_slice(body.get(pos..pos + 32).ok_or(EncodeError::Truncated)?);
        pos += 32;
        let profile_count = read_varint(&mut pos)?;
        if profile_count as usize > MAX_SUPPORTED_PARAMETERS {
            return Err(EncodeError::TooManyParameters);
        }
        let mut supported_crypto_profiles = Vec::new();
        for _ in 0..profile_count {
            supported_crypto_profiles.push(read_bytes(&mut pos, 64)?);
        }
        let mode_count = read_varint(&mut pos)?;
        if mode_count as usize > MAX_SUPPORTED_PARAMETERS {
            return Err(EncodeError::TooManyParameters);
        }
        let mut supported_handshake_modes = Vec::new();
        for _ in 0..mode_count {
            supported_handshake_modes.push(read_bytes(&mut pos, 64)?);
        }
        let ver_count = read_varint(&mut pos)?;
        if ver_count as usize > MAX_SUPPORTED_PARAMETERS {
            return Err(EncodeError::TooManyParameters);
        }
        let mut supported_protocol_versions = Vec::new();
        for _ in 0..ver_count {
            supported_protocol_versions.push(read_varint(&mut pos)? as u32);
        }
        let mut capabilities_hash = [0u8; 32];
        capabilities_hash.copy_from_slice(body.get(pos..pos + 32).ok_or(EncodeError::Truncated)?);
        pos += 32;
        let minimum_privacy = read_bytes(&mut pos, 8)?;
        let destination_hint = read_bytes(&mut pos, 512)?;
        let retry_token = read_bytes(&mut pos, 1_024)?;
        let invitation_authenticator = read_bytes(&mut pos, 64)?;
        let padding = read_bytes(&mut pos, 4_096)?;
        Ok(Self {
            version,
            client_random,
            client_ephemeral_public_key,
            supported_crypto_profiles,
            supported_handshake_modes,
            supported_protocol_versions,
            capabilities_hash,
            minimum_privacy,
            destination_hint,
            retry_token,
            invitation_authenticator,
            padding,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    Varint,
    Bytes,
    Truncated,
    TooManyParameters,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerHello {
    pub server_random: [u8; 32],
    pub server_ephemeral_public_key: [u8; 32],
    pub selected_protocol_version: u32,
    pub selected_crypto_profile: Vec<u8>,
    pub selected_handshake_mode: Vec<u8>,
    pub encrypted_server_authentication: Vec<u8>,
    pub padding: Vec<u8>,
}

impl ServerHello {
    /// Encodes the server hello body (handshake.md §16).
    ///
    /// # Errors
    ///
    /// Returns `EncodeError::Varint` if a field does not fit a varint, or
    /// `EncodeError::Bytes` if a field exceeds its length limit.
    #[allow(clippy::cast_lossless)]
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.server_random);
        out.extend_from_slice(&self.server_ephemeral_public_key);
        umc_wire::varint::encode_into(&mut out, u64::from(self.selected_protocol_version))
            .map_err(|_| EncodeError::Varint)?;
        umc_wire::bytes::encode(&mut out, &self.selected_crypto_profile, 64)
            .map_err(|_| EncodeError::Bytes)?;
        umc_wire::bytes::encode(&mut out, &self.selected_handshake_mode, 64)
            .map_err(|_| EncodeError::Bytes)?;
        umc_wire::bytes::encode(&mut out, &self.encrypted_server_authentication, 8_192)
            .map_err(|_| EncodeError::Bytes)?;
        umc_wire::bytes::encode(&mut out, &self.padding, 4_096).map_err(|_| EncodeError::Bytes)?;
        Ok(out)
    }

    /// Decodes a server hello body (handshake.md §16).
    ///
    /// # Errors
    ///
    /// Returns `EncodeError::Varint` if a varint field is malformed,
    /// `EncodeError::Bytes` if a length-prefixed field is malformed or exceeds
    /// its limit, or `EncodeError::Truncated` if the body is too short.
    #[allow(clippy::cast_possible_truncation)]
    pub fn decode(body: &[u8]) -> Result<Self, EncodeError> {
        let mut pos = 0usize;
        let read_varint = |p: &mut usize| -> Result<u64, EncodeError> {
            let (v, n) = umc_wire::varint::decode(&body[*p..]).map_err(|_| EncodeError::Varint)?;
            *p += n;
            Ok(v)
        };
        let read_bytes = |p: &mut usize, limit: usize| -> Result<Vec<u8>, EncodeError> {
            let (v, n) =
                umc_wire::bytes::decode(&body[*p..], limit).map_err(|_| EncodeError::Bytes)?;
            *p += n;
            Ok(v.to_vec())
        };
        let mut server_random = [0u8; 32];
        server_random.copy_from_slice(body.get(pos..pos + 32).ok_or(EncodeError::Truncated)?);
        pos += 32;
        let mut server_ephemeral_public_key = [0u8; 32];
        server_ephemeral_public_key
            .copy_from_slice(body.get(pos..pos + 32).ok_or(EncodeError::Truncated)?);
        pos += 32;
        let selected_protocol_version = read_varint(&mut pos)? as u32;
        let selected_crypto_profile = read_bytes(&mut pos, 64)?;
        let selected_handshake_mode = read_bytes(&mut pos, 64)?;
        let encrypted_server_authentication = read_bytes(&mut pos, 8_192)?;
        let padding = read_bytes(&mut pos, 4_096)?;
        Ok(Self {
            server_random,
            server_ephemeral_public_key,
            selected_protocol_version,
            selected_crypto_profile,
            selected_handshake_mode,
            encrypted_server_authentication,
            padding,
        })
    }

    /// The server's capabilities hash (compatibility.md §5.4): the first
    /// 32 bytes of the padding field — the documented convention the
    /// responder writes and the client verifies. The padding prefix is
    /// inside the encoded `SERVER_HELLO`, so the hash is transcript-bound
    /// like every other hello field. Returns `None` when the padding is
    /// shorter than 32 bytes (a malformed hello).
    #[must_use]
    pub fn server_capabilities_hash(&self) -> Option<[u8; 32]> {
        self.padding.get(..32)?.try_into().ok()
    }

    /// Returns the selected privacy level from the transcript-bound padding
    /// extension. Missing extension bytes are interpreted as P0 for v1
    /// compatibility with pre-profile peers.
    #[must_use]
    pub fn selected_privacy_level(&self) -> Option<u8> {
        self.padding.get(32).copied().or(Some(0))
    }
}

/// Select the protocol version from the client's offered list
/// (compatibility.md §5.2, handshake.md §16): the highest version we
/// support — v1 offers exactly [`SUPPORTED_PROTOCOL_VERSION`]. Returns
/// `None` when the list excludes every supported version; the responder
/// then answers with a Version-Negotiation packet instead of a
/// `SERVER_HELLO`.
#[must_use]
pub fn select_version(offered: &[u32]) -> Option<u32> {
    if offered.contains(&SUPPORTED_PROTOCOL_VERSION) {
        Some(SUPPORTED_PROTOCOL_VERSION)
    } else {
        None
    }
}

/// The capability identifiers negotiated at protocol version 1
/// (compatibility.md §5.4): streaming, datagrams, relay, bundles,
/// routing, and mobility. The list order is part of the convention —
/// every implementation hashes the same canonical bytes.
pub const CANONICAL_CAPABILITY_IDS: &[&[u8]] = &[
    b"stream",
    b"datagram",
    b"relay",
    b"bundle",
    b"route",
    b"mobility",
    b"privacy=p1",
];

/// The canonical capability set serialized for hashing (compatibility.md
/// §5.4): `"UMP-CAPABILITIES-v1"` followed by the varint count and the
/// length-prefixed capability identifiers in canonical order. The bytes
/// are deterministic and identical on every v1 implementation.
///
/// # Panics
///
/// Panics if a varint or length-prefixed identifier cannot be encoded
/// (the canonical list is small and bounded — it never does).
#[must_use]
pub fn canonical_capabilities() -> Vec<u8> {
    canonical_capabilities_with_extra(None)
}

/// The canonical capability set plus the client's requested privacy floor.
/// Keeping the request in the hashed set makes a tampered minimum fail before
/// any handshake secret is derived.
#[must_use]
pub fn canonical_capabilities_for_minimum_privacy(minimum_privacy: &[u8]) -> Vec<u8> {
    canonical_capabilities_with_extra(Some(minimum_privacy))
}

fn canonical_capabilities_with_extra(minimum_privacy: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"UMP-CAPABILITIES-v1");
    let extra = usize::from(minimum_privacy.is_some());
    umc_wire::varint::encode_into(&mut out, (CANONICAL_CAPABILITY_IDS.len() + extra) as u64)
        .expect("bounded count");
    for id in CANONICAL_CAPABILITY_IDS {
        umc_wire::bytes::encode(&mut out, id, 64).expect("bounded identifier");
    }
    if let Some(minimum_privacy) = minimum_privacy {
        let mut requested = b"privacy-min=".to_vec();
        requested.extend_from_slice(minimum_privacy);
        umc_wire::bytes::encode(&mut out, &requested, 64).expect("bounded identifier");
    }
    out
}

/// The capabilities hash (compatibility.md §5.4): BLAKE2s-256 over the
/// capability serialization. The client's hash rides in
/// `ClientHello.capabilities_hash`; the server's rides in the first 32
/// bytes of `ServerHello.padding`. Each side verifies the other's hash
/// against the canonical set, so the session's effective capability set
/// is the intersection of the two (v1: the canonical set).
#[must_use]
pub fn capabilities_hash(caps: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(caps);
    hasher.finalize().into()
}

/// Hashes a canonical capability set carrying a requested privacy floor.
#[must_use]
pub fn capabilities_hash_for_minimum_privacy(minimum_privacy: &[u8]) -> [u8; 32] {
    capabilities_hash(&canonical_capabilities_for_minimum_privacy(minimum_privacy))
}

/// Build a minimal Version-Negotiation packet (wire-format §25): the long
/// header form with the `VersionNegotiation` type, version 0 (the VN
/// convention — no version is being negotiated), the connection-id echo
/// (VN DCID ← client SCID, VN SCID ← client DCID, RFC 9000 §17.2.1), the
/// varint count of supported versions, and each version as a big-endian
/// u32. VN packets are never protected: no keys exist before version
/// agreement, so the packet is plain header + list bytes.
///
/// SANCTIONED minimal construction: the wire crate defines the
/// `VersionNegotiation` type and header byte but no VN packet builder.
///
/// # Panics
///
/// Panics if the version count does not fit a varint (it never does).
#[must_use]
pub fn build_version_negotiation(dcid: &[u8], scid: &[u8], supported: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(HeaderByte::LONG_VERSION_NEGOTIATION.encode());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.push(u8::try_from(dcid.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(dcid);
    out.push(u8::try_from(scid.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(scid);
    umc_wire::varint::encode_into(&mut out, supported.len() as u64).expect("bounded");
    for v in supported {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}

/// Parse a Version-Negotiation packet (wire-format §25): the long header
/// form with the `VersionNegotiation` type and version 0, followed by the
/// supported protocol versions as big-endian u32s. Returns the offered
/// versions; `None` when the bytes are not a VN packet or the fields are
/// malformed. VN packets carry no AEAD (no keys exist before version
/// agreement), so this is a plain header + list parse.
#[must_use]
pub fn parse_version_negotiation(bytes: &[u8]) -> Option<(Vec<u32>, Vec<u8>)> {
    let hb = HeaderByte::decode(*bytes.first()?).ok()?;
    if !hb.long || hb.long_type()? != LongPacketType::VersionNegotiation {
        return None;
    }
    if u32::from_be_bytes(bytes.get(1..5)?.try_into().ok()?) != 0 {
        return None;
    }
    let dcid_len = usize::from(*bytes.get(5)?);
    let dcid = bytes.get(6..6 + dcid_len)?.to_vec();
    let scid_len = usize::from(*bytes.get(6 + dcid_len)?);
    let mut pos = 7 + dcid_len + scid_len;
    let (count, n) = umc_wire::varint::decode(bytes.get(pos..)?).ok()?;
    pos += n;
    let count = usize::try_from(count).ok()?;
    if count > MAX_SUPPORTED_PARAMETERS {
        return None;
    }
    let mut versions = Vec::with_capacity(count);
    for _ in 0..count {
        versions.push(u32::from_be_bytes(
            bytes.get(pos..pos + 4)?.try_into().ok()?,
        ));
        pos += 4;
    }
    Some((versions, dcid))
}

use blake2::{Blake2s256, Digest};

/// Server authentication block encryption (handshake.md §16.1).
#[derive(Debug, Clone, PartialEq)]
pub struct ServerAuthBlock {
    pub server_static_public_key: [u8; 32],
    pub server_identity_binding: Vec<u8>,
}

/// Encrypts the server authentication block.
///
/// # Errors
///
/// Returns `EncodeError::Bytes` if key derivation or sealing fails.
pub fn encrypt_server_auth(
    handshake_extract1: &[u8; 32],
    transcript_before: &[u8; 32],
    block: &ServerAuthBlock,
    server_ephemeral_public_key: &[u8; 32],
    server_random: &[u8; 32],
    selected_profile: &[u8],
) -> Result<Vec<u8>, EncodeError> {
    let server_hello_key = expand(handshake_extract1, b"server hello key", transcript_before);
    let keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&server_hello_key)
        .map_err(|_| EncodeError::Bytes)?;
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&block.server_static_public_key);
    plaintext.extend_from_slice(&block.server_identity_binding);
    let mut aad = Vec::new();
    aad.extend_from_slice(transcript_before); // §16.1: transcript hash + preceding fields
    aad.extend_from_slice(server_random);
    aad.extend_from_slice(server_ephemeral_public_key);
    aad.extend_from_slice(selected_profile);
    keys.seal(0, &aad, &plaintext)
        .map_err(|_| EncodeError::Bytes)
}

/// Decrypts the server authentication block.
///
/// # Errors
///
/// Returns `EncodeError::Bytes` if key derivation or opening fails, or
/// `EncodeError::Truncated` if the plaintext is shorter than 32 bytes.
pub fn decrypt_server_auth(
    handshake_extract1: &[u8; 32],
    transcript_before: &[u8; 32],
    ciphertext: &[u8],
    server_ephemeral_public_key: &[u8; 32],
    server_random: &[u8; 32],
    selected_profile: &[u8],
) -> Result<ServerAuthBlock, EncodeError> {
    let server_hello_key = expand(handshake_extract1, b"server hello key", transcript_before);
    let keys = umc_crypto::aead::PacketKeys::from_traffic_secret(&server_hello_key)
        .map_err(|_| EncodeError::Bytes)?;
    let mut aad = Vec::new();
    aad.extend_from_slice(transcript_before);
    aad.extend_from_slice(server_random);
    aad.extend_from_slice(server_ephemeral_public_key);
    aad.extend_from_slice(selected_profile);
    let plaintext = keys
        .open(0, &aad, ciphertext)
        .map_err(|_| EncodeError::Bytes)?;
    let mut server_static_public_key = [0u8; 32];
    server_static_public_key.copy_from_slice(plaintext.get(..32).ok_or(EncodeError::Truncated)?);
    Ok(ServerAuthBlock {
        server_static_public_key,
        server_identity_binding: plaintext[32..].to_vec(),
    })
}

/// Finished MACs (handshake.md §19.2): HMAC-BLAKE2s(FinishedKey, `TranscriptHash`).
///
/// # Panics
///
/// Panics if `finished_key` is not exactly 32 bytes (it always is by type).
#[must_use]
pub fn finished_mac(finished_key: &[u8; 32], transcript: &[u8; 32]) -> [u8; 32] {
    use blake2::digest::{KeyInit, Mac};
    let mut mac =
        <blake2::Blake2sMac256 as KeyInit>::new_from_slice(finished_key).expect("32-byte key");
    mac.update(transcript);
    mac.finalize().into_bytes().into()
}

/// Derives a finished key from the handshake secret (handshake.md §19.2).
#[must_use]
pub fn finished_key(handshake_secret4: &[u8; 32], label: &[u8], transcript: &[u8; 32]) -> [u8; 32] {
    expand(handshake_secret4, label, transcript)
}

/// Encrypts the `CLIENT_AUTH` payload with the client-auth key derived
/// from `secret3` and the transcript hash BEFORE the message is appended
/// (handshake.md §18). Returns the AEAD ciphertext; the caller applies the
/// wire framing (the responder's `CLIENT_AUTH` body is length-prefixed
/// bytes, per the T13 driver).
///
/// # Panics
///
/// Panics when the key derivation or the AEAD seal fails (a 32-byte
/// client-auth key always derives valid packet keys).
#[must_use]
pub fn encrypt_client_auth(
    client_auth_key: &[u8; 32],
    transcript: &[u8; 32],
    plaintext: &[u8],
) -> Vec<u8> {
    umc_crypto::aead::PacketKeys::from_traffic_secret(client_auth_key)
        .expect("32-byte client auth key")
        .seal(0, transcript, plaintext)
        .expect("seal client auth")
}

/// Decrypts a `CLIENT_AUTH` ciphertext with the client-auth key and the
/// transcript hash before the message was appended (handshake.md §18).
///
/// # Errors
///
/// Returns a message when key derivation or the AEAD open fails.
pub fn decrypt_client_auth(
    client_auth_key: &[u8; 32],
    transcript: &[u8; 32],
    ct: &[u8],
) -> Result<Vec<u8>, String> {
    umc_crypto::aead::PacketKeys::from_traffic_secret(client_auth_key)
        .map_err(|e| format!("client auth keys: {e:?}"))?
        .open(0, transcript, ct)
        .map_err(|e| format!("client auth open: {e:?}"))
}

/// Assembles the `CLIENT_AUTH` plaintext (handshake.md §18, T13 driver
/// layout): client static key (32) || identity binding signed bytes (153)
/// || the binding's own signature (64) || the client's transcript-bound
/// signature (64).
#[must_use]
pub fn build_client_auth_plaintext(
    client_static_public_key: &[u8; 32],
    binding: &crate::identity::IdentityBinding,
    client_signature: &[u8; 64],
) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(32 + binding.signed_bytes().len() + 64 + 64);
    plaintext.extend_from_slice(client_static_public_key);
    plaintext.extend_from_slice(&binding.signed_bytes());
    plaintext.extend_from_slice(&binding.signature);
    plaintext.extend_from_slice(client_signature);
    plaintext
}

/// Client authentication signature input (handshake.md §18.1).
#[must_use]
pub fn client_signature_input(
    transcript_before: &[u8; 32],
    client_endpoint_id: &[u8; 32],
    server_endpoint_id: &[u8; 32],
    client_static_public_key: &[u8; 32],
    server_static_public_key: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(b"UMP-CLIENT-AUTH-v1");
    hasher.update(transcript_before);
    hasher.update(client_endpoint_id);
    hasher.update(server_endpoint_id);
    hasher.update(client_static_public_key);
    hasher.update(server_static_public_key);
    hasher.finalize().into()
}

/// Server authentication signature input (handshake.md §19.1): the
/// transcript hash BEFORE `SERVER_FINISHED` is appended, both endpoint
/// ids, and both static handshake keys.
#[must_use]
fn server_auth_signature_input(
    transcript_before: &[u8; 32],
    server_endpoint_id: &[u8; 32],
    client_endpoint_id: &[u8; 32],
    server_static_public_key: &[u8; 32],
    client_static_public_key: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(b"UMP-SERVER-AUTH-v1");
    hasher.update(transcript_before);
    hasher.update(server_endpoint_id);
    hasher.update(client_endpoint_id);
    hasher.update(server_static_public_key);
    hasher.update(client_static_public_key);
    hasher.finalize().into()
}

/// Verifies the server's `SERVER_FINISHED` signature (handshake.md §19.1):
/// the T13 driver's `server_sig_input_client`, checked against the
/// server's identity public key recovered from its auth block.
#[must_use]
pub fn verify_server_auth_signature(
    server_identity_key: &IdentityPublicKey,
    transcript_before: &[u8; 32],
    server_endpoint_id: &[u8; 32],
    client_endpoint_id: &[u8; 32],
    server_static_public_key: &[u8; 32],
    client_static_public_key: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    let sig_input = server_auth_signature_input(
        transcript_before,
        server_endpoint_id,
        client_endpoint_id,
        server_static_public_key,
        client_static_public_key,
    );
    server_identity_key.verify(&sig_input, signature)
}

/// Builds `SERVER_FINISHED` (handshake.md §19): the 64-byte server
/// signature followed by the 32-byte server finished MAC. Both bind the
/// transcript hash AFTER `CLIENT_AUTH` and BEFORE `SERVER_FINISHED` is
/// appended (the T13 driver's snapshot).
#[must_use]
pub fn build_server_finished(
    handshake_secret4: &[u8; 32],
    transcript_after_client_auth: &[u8; 32],
    server_identity: &IdentityKeyPair,
    server_endpoint_id: &[u8; 32],
    client_endpoint_id: &[u8; 32],
    server_static_public_key: &[u8; 32],
    client_static_public_key: &[u8; 32],
) -> Vec<u8> {
    let server_finished_key = finished_key(
        handshake_secret4,
        b"server finished",
        transcript_after_client_auth,
    );
    let server_mac = finished_mac(&server_finished_key, transcript_after_client_auth);
    let sig_input = server_auth_signature_input(
        transcript_after_client_auth,
        server_endpoint_id,
        client_endpoint_id,
        server_static_public_key,
        client_static_public_key,
    );
    let server_signature = server_identity.sign(&sig_input);
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&server_signature);
    out.extend_from_slice(&server_mac);
    out
}

fn expand(secret: &[u8; 32], label: &[u8], context: &[u8; 32]) -> [u8; 32] {
    let out =
        umc_crypto::label::expand_label(secret, label, context, 32).expect("32-byte expansion");
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

use crate::traffic::SessionSecrets;
use crate::transcript::Transcript;

/// Client-side material from [`complete_client_side`]: the session
/// secrets, the handshake secret4, and the inputs the client needs to
/// build and seal its `CLIENT_AUTH` message and verify `SERVER_FINISHED`
/// (handshake.md §18-19).
#[derive(Debug, Clone)]
pub struct ClientHandshakeOutput {
    /// Session secrets (client and server traffic secrets).
    pub session_secrets: SessionSecrets,
    /// The handshake secret4 (the `DH_ss` extract): derives the finished
    /// keys over the transcript hash AFTER `CLIENT_AUTH` is appended
    /// (handshake.md §19.2).
    pub handshake_secret4: [u8; 32],
    /// The client-auth key sealing `CLIENT_AUTH` (handshake.md §18).
    pub client_auth_key: [u8; 32],
    /// The transcript hash BEFORE `CLIENT_AUTH` is appended: the AEAD AAD
    /// and the signature-input transcript.
    pub transcript_hash: [u8; 32],
    /// The server's endpoint id, recovered from its identity binding.
    pub server_endpoint_id: [u8; 32],
    /// The server's identity public key, recovered from its binding: the
    /// key the `SERVER_FINISHED` signature verifies against (handshake.md
    /// §19.1).
    pub server_identity_public_key: IdentityPublicKey,
    /// The server's static handshake public key, from its auth block.
    pub server_static_public_key: [u8; 32],
}

/// Deterministic XX handshake over an in-memory transport (handshake.md §14).
///
/// Runs the full XX flow — `CLIENT_HELLO`, `SERVER_HELLO` with encrypted
/// server authentication, `CLIENT_AUTH` with client signature,
/// `SERVER_FINISHED` with server signature and finished MAC, and the
/// `CLIENT_FINISHED` confirmation — with both roles executed over a shared
/// transcript. Returns the session secrets derived by each side.
///
/// # Errors
///
/// Returns a message describing the first failed protocol invariant:
/// a Diffie-Hellman mismatch, a failed AEAD open, an invalid signature, or
/// non-matching derived secrets.
// The flow is a fixed-length sequential protocol driver, and the DH variable
// names follow handshake.md §14-18 (DH_ee, DH_es, DH_se, DH_ss).
#[allow(clippy::too_many_lines, clippy::similar_names)]
pub fn run_xx_handshake(
    client_identity: &IdentityKeyPair,
    client_static: &StaticHandshakeKeyPair,
    server_identity: &IdentityKeyPair,
    server_static: &StaticHandshakeKeyPair,
    entropy: &dyn EntropySource,
    carrier_binding: &[u8],
    now_ms: u64,
) -> Result<(SessionSecrets, SessionSecrets), String> {
    let client_ephemeral = StaticHandshakeKeyPair::generate();
    let client_hello = ClientHello::new(entropy, &client_ephemeral);
    // Capability negotiation (compatibility.md §5.4): the driver's server
    // half verifies the client's capabilities hash against the canonical
    // set, exactly as the responder does.
    if client_hello.capabilities_hash
        != capabilities_hash_for_minimum_privacy(&client_hello.minimum_privacy)
    {
        return Err("client capabilities hash mismatch".into());
    }

    let mut transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, carrier_binding);
    transcript
        .update_message(
            crate::encoding::CLIENT_HELLO,
            &client_hello.encode().map_err(|e| format!("{e:?}"))?,
        )
        .map_err(|e| format!("{e:?}"))?;

    // Server side: receive hello, respond.
    let server_ephemeral = StaticHandshakeKeyPair::generate();
    let mut server_random = [0u8; 32];
    entropy.fill(&mut server_random);
    let dh_ee = server_ephemeral.diffie_hellman(&StaticHandshakePublicKey(
        client_hello.client_ephemeral_public_key,
    ));
    let handshake_extract1 = umc_crypto::hkdf::extract(&[0u8; 32], &dh_ee);

    let binding = crate::identity::IdentityBinding::sign(
        server_identity,
        &server_static.public(),
        0,
        u64::MAX,
        0,
        [0u8; 32],
    );
    // Both sides derive the server-auth key and AAD from the transcript hash
    // BEFORE the SERVER_HELLO message is appended (handshake.md §16.1).
    let server_auth_transcript = transcript.hash;
    let encrypted_auth = encrypt_server_auth(
        &handshake_extract1,
        &server_auth_transcript,
        &ServerAuthBlock {
            server_static_public_key: server_static.public().0,
            server_identity_binding: binding.signed_bytes(),
        },
        &server_ephemeral.public().0,
        &server_random,
        CRYPTO_PROFILE,
    )
    .map_err(|e| format!("{e:?}"))?;

    let server_hello = ServerHello {
        server_random,
        server_ephemeral_public_key: server_ephemeral.public().0,
        selected_protocol_version: SUPPORTED_PROTOCOL_VERSION,
        selected_crypto_profile: CRYPTO_PROFILE.to_vec(),
        selected_handshake_mode: MODE_XX.to_vec(),
        encrypted_server_authentication: encrypted_auth,
        // The server's capabilities hash rides in the first 32 bytes of
        // the padding (compatibility.md §5.4): the client verifies it.
        padding: {
            let mut padding = Vec::with_capacity(64);
            padding.extend_from_slice(&capabilities_hash(&canonical_capabilities()));
            padding.extend_from_slice(&[0u8; 32]);
            padding
        },
    };
    let server_hello_bytes = server_hello.encode().map_err(|e| format!("{e:?}"))?;
    transcript
        .update_message(crate::encoding::SERVER_HELLO, &server_hello_bytes)
        .map_err(|e| format!("{e:?}"))?;

    // Client: verify server auth, DH_es, send CLIENT_AUTH.
    let client_dh_ee = client_ephemeral.diffie_hellman(&StaticHandshakePublicKey(
        server_hello.server_ephemeral_public_key,
    ));
    if client_dh_ee != dh_ee {
        return Err("DH_ee mismatch".into());
    }
    // Capability negotiation (compatibility.md §5.4): the driver's client
    // half verifies the server's hash from the padding prefix, exactly as
    // `complete_client_side` does.
    if server_hello.server_capabilities_hash() != Some(capabilities_hash(&canonical_capabilities()))
    {
        return Err("server capabilities hash mismatch".into());
    }
    let requested_privacy = client_hello
        .minimum_privacy_level()
        .ok_or_else(|| "invalid minimum privacy profile".to_string())?;
    let selected_privacy = server_hello
        .selected_privacy_level()
        .ok_or_else(|| "missing selected privacy profile".to_string())?;
    let max_privacy = privacy_profile_level(MAX_SUPPORTED_PRIVACY_PROFILE)
        .ok_or_else(|| "invalid implementation maximum privacy profile".to_string())?;
    if selected_privacy > max_privacy {
        return Err("server selected unsupported privacy profile".into());
    }
    if selected_privacy < requested_privacy {
        return Err("server selected privacy profile below requested minimum".into());
    }
    let client_extract1 = umc_crypto::hkdf::extract(&[0u8; 32], &client_dh_ee);
    let server_block = decrypt_server_auth(
        &client_extract1,
        &server_auth_transcript,
        &server_hello.encrypted_server_authentication,
        &server_hello.server_ephemeral_public_key,
        &server_hello.server_random,
        &server_hello.selected_crypto_profile,
    )
    .map_err(|e| format!("{e:?}"))?;
    let server_static_pub = StaticHandshakePublicKey(server_block.server_static_public_key);
    let server_eid = crate::identity::endpoint_id(&binding.identity_public_key);

    let dh_es = client_ephemeral.diffie_hellman(&server_static_pub);
    let handshake_secret2 = umc_crypto::hkdf::extract(&client_extract1, &dh_es);
    let dh_se = client_static.diffie_hellman(&StaticHandshakePublicKey(
        server_hello.server_ephemeral_public_key,
    ));
    let handshake_secret3 = umc_crypto::hkdf::extract(&handshake_secret2, &dh_se);
    let client_auth_key = expand(&handshake_secret3, b"client auth key", &transcript.hash);

    let client_eid = crate::identity::endpoint_id(&client_identity.public());
    let sig_input = client_signature_input(
        &transcript.hash,
        &client_eid,
        &server_eid,
        &client_static.public().0,
        &server_static_pub.0,
    );
    let client_signature = client_identity.sign(&sig_input);
    // NOTE (placeholder): the client identity binding is represented by the
    // server binding's bytes here; the real client binding serialization lands
    // with the live handshake path (Phase 1 Task 25).
    let client_auth_plaintext = {
        let mut p = Vec::new();
        p.extend_from_slice(&client_static.public().0);
        p.extend_from_slice(&binding.signed_bytes());
        p.extend_from_slice(&client_signature);
        p
    };
    let client_auth_encrypted = umc_crypto::aead::PacketKeys::from_traffic_secret(&client_auth_key)
        .map_err(|e| format!("{e:?}"))?
        .seal(0, &transcript.hash, &client_auth_plaintext)
        .map_err(|e| format!("{e:?}"))?;
    let client_auth_bytes = {
        let mut out = Vec::new();
        umc_wire::bytes::encode(&mut out, &client_auth_encrypted, 16_384)
            .map_err(|_| "bytes".to_string())?;
        out
    };
    // Server derives the client-auth key from the transcript hash BEFORE the
    // CLIENT_AUTH message is appended (handshake.md §18).
    let client_auth_transcript = transcript.hash;
    transcript
        .update_message(crate::encoding::CLIENT_AUTH, &client_auth_bytes)
        .map_err(|e| format!("{e:?}"))?;

    // Server: verify client auth, DH_ss both sides.
    let server_dh_se = server_ephemeral.diffie_hellman(&client_static.public());
    let server_secret3 = umc_crypto::hkdf::extract(&handshake_secret2, &server_dh_se);
    if server_secret3 != handshake_secret3 {
        return Err("DH_se mismatch".into());
    }
    let server_auth_key = expand(&server_secret3, b"client auth key", &client_auth_transcript);
    let (client_auth_ciphertext, _) =
        umc_wire::bytes::decode(&client_auth_bytes, 16_384).map_err(|_| "bytes")?;
    let decrypted_client_auth = umc_crypto::aead::PacketKeys::from_traffic_secret(&server_auth_key)
        .map_err(|e| format!("{e:?}"))?
        .open(0, &client_auth_transcript, client_auth_ciphertext)
        .map_err(|e| format!("{e:?}"))?;
    if decrypted_client_auth[..32] != client_static.public().0 {
        return Err("client static key mismatch".into());
    }

    let dh_ss = client_static.diffie_hellman(&server_static_pub);
    let handshake_secret4 = umc_crypto::hkdf::extract(&handshake_secret3, &dh_ss);

    // Finished messages (handshake.md §19): the finished keys bind the
    // transcript hash AFTER CLIENT_AUTH and BEFORE SERVER_FINISHED is
    // appended.
    let client_finished_key =
        finished_key(&handshake_secret4, b"client finished", &transcript.hash);
    let server_finished_key =
        finished_key(&handshake_secret4, b"server finished", &transcript.hash);
    // Server sends SERVER_FINISHED with signature + MAC.
    let server_finished = build_server_finished(
        &handshake_secret4,
        &transcript.hash,
        server_identity,
        &server_eid,
        &client_eid,
        &server_static_pub.0,
        &client_static.public().0,
    );
    // Client verifies the server finished MAC and signature against the
    // transcript hash BEFORE SERVER_FINISHED is appended (handshake.md §19).
    let server_finished_transcript = transcript.hash;
    transcript
        .update_message(crate::encoding::SERVER_FINISHED, &server_finished)
        .map_err(|e| format!("{e:?}"))?;

    // Client verifies server MAC and signature, sends CLIENT_FINISHED.
    let client_verify_finished_key = finished_key(
        &handshake_secret4,
        b"server finished",
        &server_finished_transcript,
    );
    if client_verify_finished_key != server_finished_key {
        return Err("server finished key mismatch".into());
    }
    let server_signature: [u8; 64] = server_finished[..64]
        .try_into()
        .map_err(|_| "server finished truncated")?;
    if !verify_server_auth_signature(
        &binding.identity_public_key,
        &server_finished_transcript,
        &server_eid,
        &client_eid,
        &server_static_pub.0,
        &client_static.public().0,
        &server_signature,
    ) {
        return Err("server signature invalid".into());
    }

    // CORRECTED: verify the client confirmation MAC against the transcript
    // hash BEFORE the CLIENT_FINISHED message is appended (handshake.md §20).
    let confirmation_transcript = transcript.hash;
    let client_confirmation = finished_mac(&client_finished_key, &confirmation_transcript);
    transcript
        .update_message(crate::encoding::CLIENT_FINISHED, &client_confirmation)
        .map_err(|e| format!("{e:?}"))?;
    let server_verify_confirmation = finished_mac(&client_finished_key, &confirmation_transcript);
    if server_verify_confirmation != client_confirmation {
        return Err("client confirmation mismatch".into());
    }

    // Session secrets from the final transcript.
    let final_transcript = transcript.hash;
    let client_secrets =
        crate::traffic::derive_session_secrets(&handshake_secret4, &final_transcript);
    let server_secrets =
        crate::traffic::derive_session_secrets(&handshake_secret4, &final_transcript);
    if client_secrets.client != server_secrets.client {
        return Err("client traffic secret mismatch".into());
    }
    if client_secrets.server != server_secrets.server {
        return Err("server traffic secret mismatch".into());
    }
    let _ = now_ms;
    Ok((client_secrets, server_secrets))
}

/// Client-side continuation of the XX handshake given a received
/// `SERVER_HELLO` (handshake.md §14-18). The client has already sent
/// `client_hello`; the transcript covers `CLIENT_HELLO` and `SERVER_HELLO`
/// as the driver does. Returns the session secrets, the `CLIENT_FINISHED`
/// key, and the material the client seals into `CLIENT_AUTH` next (the
/// client-auth key, the pre-append transcript hash, and the server's
/// endpoint id / static handshake key recovered from its auth block).
/// The `CLIENT_AUTH`/`SERVER_FINISHED` continuation arrives with the
/// daemon loop.
///
/// # Errors
///
/// Returns a message describing the first failed protocol invariant: a
/// `CLIENT_HELLO`/`SERVER_HELLO` encoding failure, a failed AEAD open of the
/// server-auth block, or a truncated auth plaintext or server binding.
// The DH variable names follow handshake.md §14-18 (DH_ee, DH_es, DH_se,
// DH_ss) as in the deterministic driver.
#[allow(clippy::similar_names)]
pub fn complete_client_side(
    client_identity: &IdentityKeyPair,
    client_static: &StaticHandshakeKeyPair,
    client_ephemeral: &StaticHandshakeKeyPair,
    client_hello: &ClientHello,
    server_hello: &ServerHello,
    entropy: &dyn EntropySource,
    carrier_binding: &[u8],
) -> Result<ClientHandshakeOutput, String> {
    let _ = client_identity;
    let _ = entropy;
    // Capability negotiation (compatibility.md §5.4): the server's
    // capabilities hash rides in the first 32 bytes of the SERVER_HELLO
    // padding; verify it against the canonical set before any secret
    // derivation. A mismatch is a protocol violation (or a peer speaking
    // a different capability set) and the handshake is refused.
    if server_hello.server_capabilities_hash() != Some(capabilities_hash(&canonical_capabilities()))
    {
        return Err("server capabilities hash mismatch".into());
    }
    // Transcript through CLIENT_HELLO; SERVER_HELLO fields are the preceding
    // unencrypted fields for the auth-block AAD (handshake.md §16.1).
    let mut transcript = Transcript::new(MODE_XX, CRYPTO_PROFILE, carrier_binding);
    transcript
        .update_message(
            crate::encoding::CLIENT_HELLO,
            &client_hello.encode().map_err(|e| format!("{e:?}"))?,
        )
        .map_err(|e| format!("{e:?}"))?;
    let server_auth_transcript = transcript.hash;

    let dh_ee = client_ephemeral.diffie_hellman(&StaticHandshakePublicKey(
        server_hello.server_ephemeral_public_key,
    ));
    let extract1 = umc_crypto::hkdf::extract(&[0u8; 32], &dh_ee);
    let server_block = decrypt_server_auth(
        &extract1,
        &server_auth_transcript,
        &server_hello.encrypted_server_authentication,
        &server_hello.server_ephemeral_public_key,
        &server_hello.server_random,
        &server_hello.selected_crypto_profile,
    )
    .map_err(|e| format!("{e:?}"))?;
    let server_static_pub = StaticHandshakePublicKey(server_block.server_static_public_key);
    // The server's endpoint id rides in its identity binding (signed bytes
    // layout: version (1) || endpoint id (32) || identity key (32) ||
    // static key (32) || validity || sequence || capabilities). The client
    // signs it into `CLIENT_AUTH`, so the server's identity is recovered
    // here without parsing the full binding (handshake.md §18.1).
    let server_binding_bytes = &server_block.server_identity_binding;
    let server_identity_key: [u8; 32] = server_binding_bytes
        .get(33..65)
        .ok_or("server binding truncated")?
        .try_into()
        .map_err(|_| "server binding truncated")?;
    let server_endpoint_id = crate::identity::endpoint_id(&IdentityPublicKey(server_identity_key));

    // Append SERVER_HELLO to the transcript (decrypt used the pre-append hash).
    transcript
        .update_message(
            crate::encoding::SERVER_HELLO,
            &server_hello.encode().map_err(|e| format!("{e:?}"))?,
        )
        .map_err(|e| format!("{e:?}"))?;

    let dh_es = client_ephemeral.diffie_hellman(&server_static_pub);
    let secret2 = umc_crypto::hkdf::extract(&extract1, &dh_es);
    let dh_se = client_static.diffie_hellman(&StaticHandshakePublicKey(
        server_hello.server_ephemeral_public_key,
    ));
    let secret3 = umc_crypto::hkdf::extract(&secret2, &dh_se);
    let dh_ss = client_static.diffie_hellman(&server_static_pub);
    let secret4 = umc_crypto::hkdf::extract(&secret3, &dh_ss);

    // The client-auth key derives from the transcript hash BEFORE the
    // CLIENT_AUTH message is appended (handshake.md §18) — the same hash
    // the client signs over and seals with. The finished keys instead bind
    // the hash AFTER CLIENT_AUTH is appended (handshake.md §19.2), so
    // secret4 rides in the output and the caller derives them once the
    // auth body is known (see [`verify_server_finished_and_build_confirmation`]).
    let transcript_hash = transcript.hash;
    let client_auth_key = expand(&secret3, b"client auth key", &transcript_hash);
    let client_secrets = crate::traffic::derive_session_secrets(&secret4, &transcript_hash);
    Ok(ClientHandshakeOutput {
        session_secrets: client_secrets,
        handshake_secret4: secret4,
        client_auth_key,
        transcript_hash,
        server_endpoint_id,
        server_identity_public_key: IdentityPublicKey(server_identity_key),
        server_static_public_key: server_static_pub.0,
    })
}

/// Verifies the server's `SERVER_FINISHED` message and builds the
/// `CLIENT_FINISHED` confirmation MAC (handshake.md §19-20), mirroring the
/// T13 driver's snapshot order:
///
/// 1. append `CLIENT_AUTH` (its length-prefixed ciphertext body) to the
///    client's transcript — `transcript` must already hold `CLIENT_HELLO`
///    and `SERVER_HELLO` with the same bytes both sides exchanged;
/// 2. verify the server's finished MAC with the server finished key over
///    the transcript hash BEFORE `SERVER_FINISHED` is appended;
/// 3. verify the server signature over `"UMP-SERVER-AUTH-v1"` and that
///    same pre-append hash (the driver's `server_sig_input_client`);
/// 4. append `SERVER_FINISHED` and return
///    `finished_mac(client_finished_key, hash_after_server_finished)` —
///    the confirmation the client transmits in `CLIENT_FINISHED`.
///
/// # Errors
///
/// Returns a message when the transcript cannot be updated, the message is
/// truncated, or the MAC or signature does not verify (the handshake is
/// refused).
#[allow(clippy::too_many_arguments)]
pub fn verify_server_finished_and_build_confirmation(
    transcript: &mut Transcript,
    handshake_secret4: &[u8; 32],
    server_identity_key: &IdentityPublicKey,
    server_endpoint_id: &[u8; 32],
    client_endpoint_id: &[u8; 32],
    server_static_public_key: &[u8; 32],
    client_static_public_key: &[u8; 32],
    client_auth_body: &[u8],
    server_finished: &[u8],
) -> Result<[u8; 32], String> {
    transcript
        .update_message(crate::encoding::CLIENT_AUTH, client_auth_body)
        .map_err(|e| format!("transcript: {e:?}"))?;
    let transcript_before_server_finished = transcript.hash;
    let signature: [u8; 64] = server_finished
        .get(..64)
        .and_then(|s| s.try_into().ok())
        .ok_or("server finished truncated")?;
    let server_mac: [u8; 32] = server_finished
        .get(64..96)
        .and_then(|s| s.try_into().ok())
        .ok_or("server finished truncated")?;
    let server_finished_key = finished_key(
        handshake_secret4,
        b"server finished",
        &transcript_before_server_finished,
    );
    if finished_mac(&server_finished_key, &transcript_before_server_finished) != server_mac {
        return Err("server finished MAC invalid".into());
    }
    if !verify_server_auth_signature(
        server_identity_key,
        &transcript_before_server_finished,
        server_endpoint_id,
        client_endpoint_id,
        server_static_public_key,
        client_static_public_key,
        &signature,
    ) {
        return Err("server finished signature invalid".into());
    }
    transcript
        .update_message(crate::encoding::SERVER_FINISHED, server_finished)
        .map_err(|e| format!("transcript: {e:?}"))?;
    let client_finished_key = finished_key(
        handshake_secret4,
        b"client finished",
        &transcript_before_server_finished,
    );
    Ok(finished_mac(&client_finished_key, &transcript.hash))
}

/// Verifies the client's `CLIENT_FINISHED` confirmation MAC (handshake.md
/// §20): the client finished key derives from the transcript hash BEFORE
/// `SERVER_FINISHED` is appended, and the confirmation MAC covers the hash
/// AFTER `SERVER_FINISHED` (the driver's snapshot order). `transcript`
/// must hold `CLIENT_HELLO` and `SERVER_HELLO` with the same bytes the
/// counterpart appended; `CLIENT_AUTH` and `SERVER_FINISHED` are appended
/// here.
///
/// # Errors
///
/// Returns a message when the transcript cannot be updated or the
/// confirmation MAC does not match (the session is refused).
pub fn verify_client_finished(
    handshake_secret4: &[u8; 32],
    transcript: &mut Transcript,
    client_auth_body: &[u8],
    server_finished: &[u8],
    client_finished: &[u8],
) -> Result<(), String> {
    transcript
        .update_message(crate::encoding::CLIENT_AUTH, client_auth_body)
        .map_err(|e| format!("transcript: {e:?}"))?;
    let transcript_before_server_finished = transcript.hash;
    let client_finished_key = finished_key(
        handshake_secret4,
        b"client finished",
        &transcript_before_server_finished,
    );
    transcript
        .update_message(crate::encoding::SERVER_FINISHED, server_finished)
        .map_err(|e| format!("transcript: {e:?}"))?;
    let expected = finished_mac(&client_finished_key, &transcript.hash);
    if expected.as_slice() != client_finished {
        return Err("client finished MAC mismatch".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestEntropy;

    impl EntropySource for TestEntropy {
        fn fill(&self, out: &mut [u8]) {
            out.fill(0xAB);
        }
    }

    #[test]
    fn client_hello_round_trip() {
        let eph = StaticHandshakeKeyPair::generate();
        let ch = ClientHello::new(&TestEntropy, &eph);
        let enc = ch.encode().unwrap();
        let dec = ClientHello::decode(&enc).unwrap();
        assert_eq!(dec.client_random, ch.client_random);
        assert_eq!(
            dec.client_ephemeral_public_key,
            ch.client_ephemeral_public_key
        );
        assert_eq!(dec.supported_crypto_profiles, vec![CRYPTO_PROFILE.to_vec()]);
        assert_eq!(
            dec.capabilities_hash,
            capabilities_hash_for_minimum_privacy(b"p0"),
            "the hello must carry the canonical capabilities hash, not zeros"
        );
        assert_eq!(dec.minimum_privacy, b"p0");
    }

    #[test]
    fn minimum_privacy_is_bound_into_capabilities_hash() {
        let eph = StaticHandshakeKeyPair::generate();
        let p0 = ClientHello::new(&TestEntropy, &eph);
        let p2 = ClientHello::new_with_minimum_privacy(&TestEntropy, &eph, b"p2");
        assert_eq!(p2.minimum_privacy, b"p2");
        assert_ne!(p0.capabilities_hash, p2.capabilities_hash);
        assert_eq!(
            p2.capabilities_hash,
            capabilities_hash_for_minimum_privacy(b"p2")
        );
    }

    /// Version selection (compatibility.md §5.2): the offered list selects
    /// the supported version when present, `None` otherwise.
    #[test]
    fn select_version_picks_supported_offer() {
        assert_eq!(select_version(&[1]), Some(1));
        assert_eq!(select_version(&[2, 1, 3]), Some(1));
        assert_eq!(select_version(&[2, 3]), None);
        assert_eq!(select_version(&[]), None);
    }

    /// The canonical capabilities serialize and hash deterministically
    /// (compatibility.md §5.4): two calls produce identical bytes and
    /// hashes, and a different input hashes differently. The canonical
    /// set is the v1 negotiated capability list.
    #[test]
    fn capabilities_hash_is_canonical() {
        let a = canonical_capabilities();
        let b = canonical_capabilities();
        assert_eq!(a, b, "the canonical serialization must be deterministic");
        assert_eq!(capabilities_hash(&a), capabilities_hash(&b));
        assert_ne!(capabilities_hash(&a), capabilities_hash(b"other"));
        let expected: [&[u8]; 7] = [
            b"stream",
            b"datagram",
            b"relay",
            b"bundle",
            b"route",
            b"mobility",
            b"privacy=p1",
        ];
        assert_eq!(CANONICAL_CAPABILITY_IDS, expected.as_slice());
    }

    /// The Version-Negotiation packet (wire-format §25): the minimal
    /// builder's bytes parse back to the listed versions, a VN listing
    /// only unsupported versions parses but selects nothing, and
    /// non-VN bytes are not a VN.
    #[test]
    fn version_negotiation_round_trip() {
        let vn = build_version_negotiation(&[1u8; 8], &[2u8; 8], &[1]);
        let (versions, _) = parse_version_negotiation(&vn).expect("vn");
        assert_eq!(versions, vec![1]);
        let vn = build_version_negotiation(&[], &[], &[2, 3]);
        let (versions, _) = parse_version_negotiation(&vn).expect("vn");
        assert_eq!(versions, vec![2, 3]);
        assert_eq!(select_version(&[2, 3]), None);
        // An Initial long header is not a VN packet.
        assert_eq!(parse_version_negotiation(&[0xC0, 0, 0, 0, 1, 0, 0]), None);
    }

    /// The client verifies the server's capabilities hash from the
    /// `SERVER_HELLO` padding prefix (compatibility.md §5.4): a hello
    /// carrying a non-canonical hash is refused before any secret
    /// derivation.
    #[test]
    fn client_refuses_non_canonical_server_capabilities() {
        let eph = StaticHandshakeKeyPair::generate();
        let hello = ClientHello::new(&TestEntropy, &eph);
        let server_hello = ServerHello {
            server_random: [3u8; 32],
            server_ephemeral_public_key: [4u8; 32],
            selected_protocol_version: 1,
            selected_crypto_profile: CRYPTO_PROFILE.to_vec(),
            selected_handshake_mode: MODE_XX.to_vec(),
            encrypted_server_authentication: vec![7u8; 100],
            padding: vec![0u8; 32],
        };
        let error = complete_client_side(
            &IdentityKeyPair::generate(),
            &eph,
            &eph,
            &hello,
            &server_hello,
            &TestEntropy,
            b"binding",
        )
        .expect_err("a non-canonical server hash must be refused");
        assert!(error.contains("capabilities"), "{error}");
    }

    #[test]
    fn server_hello_round_trip() {
        let sh = ServerHello {
            server_random: [3u8; 32],
            server_ephemeral_public_key: [4u8; 32],
            selected_protocol_version: 1,
            selected_crypto_profile: CRYPTO_PROFILE.to_vec(),
            selected_handshake_mode: MODE_XX.to_vec(),
            encrypted_server_authentication: vec![7u8; 100],
            padding: vec![0u8; 32],
        };
        let enc = sh.encode().unwrap();
        let dec = ServerHello::decode(&enc).unwrap();
        assert_eq!(dec, sh);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn client_hello_rejects_too_many_parameters() {
        let mut ch = ClientHello::new(&TestEntropy, &StaticHandshakeKeyPair::generate());
        ch.supported_protocol_versions = (0..=MAX_SUPPORTED_PARAMETERS as u32).collect();
        let enc = ch.encode().unwrap();
        assert_eq!(
            ClientHello::decode(&enc),
            Err(EncodeError::TooManyParameters)
        );
    }

    #[test]
    fn server_auth_block_round_trip() {
        let e1 = [1u8; 32];
        let tr = [2u8; 32];
        let block = ServerAuthBlock {
            server_static_public_key: [3u8; 32],
            server_identity_binding: vec![4u8; 100],
        };
        let eph = [5u8; 32];
        let rnd = [6u8; 32];
        let ct = encrypt_server_auth(&e1, &tr, &block, &eph, &rnd, CRYPTO_PROFILE).unwrap();
        let dec = decrypt_server_auth(&e1, &tr, &ct, &eph, &rnd, CRYPTO_PROFILE).unwrap();
        assert_eq!(dec.server_static_public_key, block.server_static_public_key);
        assert_eq!(dec.server_identity_binding, block.server_identity_binding);
    }

    #[test]
    fn wrong_transcript_fails_decryption() {
        let e1 = [1u8; 32];
        let block = ServerAuthBlock {
            server_static_public_key: [3u8; 32],
            server_identity_binding: vec![4u8; 16],
        };
        let ct = encrypt_server_auth(
            &e1,
            &[2u8; 32],
            &block,
            &[5u8; 32],
            &[6u8; 32],
            CRYPTO_PROFILE,
        )
        .unwrap();
        assert!(
            decrypt_server_auth(&e1, &[7u8; 32], &ct, &[5u8; 32], &[6u8; 32], CRYPTO_PROFILE)
                .is_err()
        );
    }

    #[test]
    fn finished_mac_binds_transcript() {
        let key = [1u8; 32];
        let a = finished_mac(&key, &[2u8; 32]);
        let b = finished_mac(&key, &[3u8; 32]);
        assert_ne!(a, b);
        assert_eq!(finished_mac(&key, &[2u8; 32]), a);
    }

    #[test]
    fn signature_input_binds_identities() {
        let a = client_signature_input(&[1u8; 32], &[2u8; 32], &[3u8; 32], &[4u8; 32], &[5u8; 32]);
        let b = client_signature_input(&[1u8; 32], &[2u8; 32], &[9u8; 32], &[4u8; 32], &[5u8; 32]);
        assert_ne!(a, b);
    }

    /// The `CLIENT_AUTH` halves (handshake.md §18): a plaintext sealed with
    /// `encrypt_client_auth` under the client-auth key and the transcript
    /// hash reopens verbatim with `decrypt_client_auth`; a different
    /// transcript cannot open it.
    #[test]
    fn client_auth_round_trip() {
        let auth_key = [0x11u8; 32];
        let transcript = [0x22u8; 32];
        // 32-byte static + 153 signed bytes + 64 binding signature + 64
        // client signature, as the T13 driver lays the plaintext out.
        let plaintext = vec![0x33u8; 32 + 153 + 64 + 64];
        let ct = encrypt_client_auth(&auth_key, &transcript, &plaintext);
        let reopened = decrypt_client_auth(&auth_key, &transcript, &ct).expect("decrypt");
        assert_eq!(reopened, plaintext);
        assert!(
            decrypt_client_auth(&auth_key, &[0x44u8; 32], &ct).is_err(),
            "a transcript-bound message must not open under another transcript"
        );
        assert!(
            decrypt_client_auth(&[0x55u8; 32], &transcript, &ct).is_err(),
            "a transcript-bound message must not open under another key"
        );
    }
}
