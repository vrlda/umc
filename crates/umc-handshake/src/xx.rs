use umc_crypto::signatures::StaticHandshakeKeyPair;
use umc_types::runtime::EntropySource;

pub const CRYPTO_PROFILE: &[u8] = b"UMP-CRYPTO-1";
pub const MODE_XX: &[u8] = b"XX";

pub const CLIENT_RANDOM_LEN: usize = 32;
pub const MAX_SUPPORTED_PARAMETERS: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub struct ClientHello {
    pub version: u32,
    pub client_random: [u8; CLIENT_RANDOM_LEN],
    pub client_ephemeral_public_key: [u8; 32],
    pub supported_crypto_profiles: Vec<Vec<u8>>,
    pub supported_handshake_modes: Vec<Vec<u8>>,
    pub supported_protocol_versions: Vec<u32>,
    pub capabilities_hash: [u8; 32],
    pub destination_hint: Vec<u8>,
    pub retry_token: Vec<u8>,
    pub invitation_authenticator: Vec<u8>,
    pub padding: Vec<u8>,
}

impl ClientHello {
    pub fn new(entropy: &dyn EntropySource, ephemeral: &StaticHandshakeKeyPair) -> Self {
        let mut client_random = [0u8; CLIENT_RANDOM_LEN];
        entropy.fill(&mut client_random);
        Self {
            version: 1,
            client_random,
            client_ephemeral_public_key: ephemeral.public().0,
            supported_crypto_profiles: vec![CRYPTO_PROFILE.to_vec()],
            supported_handshake_modes: vec![MODE_XX.to_vec()],
            supported_protocol_versions: vec![1],
            capabilities_hash: [0u8; 32],
            destination_hint: Vec::new(),
            retry_token: Vec::new(),
            invitation_authenticator: Vec::new(),
            padding: vec![0u8; 64],
        }
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
    fn client_hello_rejects_too_many_parameters() {
        let mut ch = ClientHello::new(&TestEntropy, &StaticHandshakeKeyPair::generate());
        ch.supported_protocol_versions = (0..=MAX_SUPPORTED_PARAMETERS as u32).collect();
        let enc = ch.encode().unwrap();
        assert_eq!(
            ClientHello::decode(&enc),
            Err(EncodeError::TooManyParameters)
        );
    }
}
