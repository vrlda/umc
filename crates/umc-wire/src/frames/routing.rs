use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const MAX_HOP_LIMIT: u64 = 32;
pub const MAX_DESTINATION_HINT: usize = 512;
pub const MAX_PATH_EXCLUSIONS: usize = 32;
pub const MAX_ROUTE_AUTH: usize = 1_024;
pub const MAX_EXCLUSION_ENTRY: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct RouteRequestFrame {
    pub request_id: u64,
    pub allow_relay: bool,
    pub allow_store_forward: bool,
    pub require_private_response: bool,
    pub local_scope_only: bool,
    pub gateway_query: bool,
    pub hop_limit: u64,
    pub expiration_delta: u64,
    pub destination_hint: Vec<u8>,
    pub path_exclusions: Vec<Vec<u8>>,
    pub requester_auth: Vec<u8>,
}

impl RouteRequestFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPadding` if the hop limit is zero or exceeds
    /// [`MAX_HOP_LIMIT`], `LengthExceedsLimit` if the path exclusion count or
    /// a field exceeds its limit, and `VarintEncode` if a field cannot be
    /// encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.hop_limit == 0 || self.hop_limit > MAX_HOP_LIMIT {
            return Err(FrameError::InvalidPadding);
        }
        if self.path_exclusions.len() > MAX_PATH_EXCLUSIONS {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::ROUTE_REQUEST.0)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.request_id).map_err(FrameError::VarintEncode)?;
        let mut flags = 0u8;
        if self.allow_relay {
            flags |= 0x01;
        }
        if self.allow_store_forward {
            flags |= 0x02;
        }
        if self.require_private_response {
            flags |= 0x04;
        }
        if self.local_scope_only {
            flags |= 0x08;
        }
        if self.gateway_query {
            flags |= 0x10;
        }
        out.push(flags);
        crate::varint::encode_into(&mut out, self.hop_limit).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.expiration_delta)
            .map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(&mut out, &self.destination_hint, MAX_DESTINATION_HINT)
            .map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::varint::encode_into(&mut out, self.path_exclusions.len() as u64)
            .map_err(FrameError::VarintEncode)?;
        for e in &self.path_exclusions {
            crate::bytes::encode(&mut out, e, MAX_EXCLUSION_ENTRY)
                .map_err(|_| FrameError::LengthExceedsLimit)?;
        }
        crate::bytes::encode(&mut out, &self.requester_auth, MAX_ROUTE_AUTH)
            .map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    /// Decodes a `ROUTE_REQUEST` body (bytes after the type varint), returning
    /// the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPadding` if reserved flag bits are set or the hop limit
    /// is out of range, `LengthExceedsLimit` if the path exclusion count
    /// exceeds [`MAX_PATH_EXCLUSIONS`], and `Truncated` or `Varint` if the
    /// body is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let request_id = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xE0 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let hop_limit = read_varint(&mut pos)?;
        if hop_limit == 0 || hop_limit > MAX_HOP_LIMIT {
            return Err(FrameError::InvalidPadding);
        }
        let expiration = read_varint(&mut pos)?;
        let (hint, n) = crate::bytes::decode(&body[pos..], MAX_DESTINATION_HINT)
            .map_err(|_| FrameError::Truncated)?;
        pos += n;
        let ex_count = read_varint(&mut pos)?;
        #[allow(clippy::cast_possible_truncation)]
        if ex_count as usize > MAX_PATH_EXCLUSIONS {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut exclusions = Vec::new();
        for _ in 0..ex_count {
            let (e, n) = crate::bytes::decode(&body[pos..], MAX_EXCLUSION_ENTRY)
                .map_err(|_| FrameError::Truncated)?;
            pos += n;
            exclusions.push(e.to_vec());
        }
        let (auth, n) = crate::bytes::decode(&body[pos..], MAX_ROUTE_AUTH)
            .map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((
            Self {
                request_id,
                allow_relay: flags & 0x01 != 0,
                allow_store_forward: flags & 0x02 != 0,
                require_private_response: flags & 0x04 != 0,
                local_scope_only: flags & 0x08 != 0,
                gateway_query: flags & 0x10 != 0,
                hop_limit,
                expiration_delta: expiration,
                destination_hint: hint.to_vec(),
                path_exclusions: exclusions,
                requester_auth: auth.to_vec(),
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct RouteResponseFrame {
    pub request_id: u64,
    pub response_sequence: u64,
    pub direct: bool,
    pub relay_required: bool,
    pub store_forward_available: bool,
    pub local_path: bool,
    pub gateway_path: bool,
    pub route_lifetime: u64,
    pub next_hop_hint: Vec<u8>,
    pub route_metadata: Vec<u8>,
    pub authentication: Vec<u8>,
}

impl RouteResponseFrame {
    pub const MAX_NEXT_HOP_HINT: usize = 1_024;
    pub const MAX_ROUTE_METADATA: usize = 4_096;

    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPadding` if both `direct` and `relay_required` are set,
    /// `LengthExceedsLimit` if a field exceeds its limit, and `VarintEncode`
    /// if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.direct && self.relay_required {
            return Err(FrameError::InvalidPadding);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::ROUTE_RESPONSE.0)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.request_id).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.response_sequence)
            .map_err(FrameError::VarintEncode)?;
        let mut flags = 0u8;
        if self.direct {
            flags |= 0x01;
        }
        if self.relay_required {
            flags |= 0x02;
        }
        if self.store_forward_available {
            flags |= 0x04;
        }
        if self.local_path {
            flags |= 0x08;
        }
        if self.gateway_path {
            flags |= 0x10;
        }
        out.push(flags);
        crate::varint::encode_into(&mut out, self.route_lifetime)
            .map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(&mut out, &self.next_hop_hint, Self::MAX_NEXT_HOP_HINT)
            .map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.route_metadata, Self::MAX_ROUTE_METADATA)
            .map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.authentication, MAX_ROUTE_AUTH)
            .map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    /// Decodes a `ROUTE_RESPONSE` body (bytes after the type varint),
    /// returning the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPadding` if reserved flag bits are set, and `Truncated`
    /// or `Varint` if the body is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let request_id = read_varint(&mut pos)?;
        let sequence = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xE0 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let lifetime = read_varint(&mut pos)?;
        let (nh, n) = crate::bytes::decode(&body[pos..], Self::MAX_NEXT_HOP_HINT)
            .map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (meta, n) = crate::bytes::decode(&body[pos..], Self::MAX_ROUTE_METADATA)
            .map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (auth, n) = crate::bytes::decode(&body[pos..], MAX_ROUTE_AUTH)
            .map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((
            Self {
                request_id,
                response_sequence: sequence,
                direct: flags & 0x01 != 0,
                relay_required: flags & 0x02 != 0,
                store_forward_available: flags & 0x04 != 0,
                local_path: flags & 0x08 != 0,
                gateway_path: flags & 0x10 != 0,
                route_lifetime: lifetime,
                next_hop_hint: nh.to_vec(),
                route_metadata: meta.to_vec(),
                authentication: auth.to_vec(),
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteErrorFrame {
    pub request_id: u64,
    pub error_code: u64,
    pub failed_hop_index: u64,
    pub diagnostic: Vec<u8>,
}

impl RouteErrorFrame {
    /// Sentinel for an undisclosed or undeterminable failed hop; the maximum
    /// representable varint value (routing.md "Failed-Hop Index").
    pub const UNKNOWN_HOP: u64 = crate::varint::MAX_VARINT;
    pub const MAX_DIAGNOSTIC: usize = 256;

    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if the diagnostic is longer than
    /// [`Self::MAX_DIAGNOSTIC`], and `VarintEncode` if a field cannot be
    /// encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::ROUTE_ERROR.0)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.request_id).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.error_code).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.failed_hop_index)
            .map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(&mut out, &self.diagnostic, Self::MAX_DIAGNOSTIC)
            .map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    /// Decodes a `ROUTE_ERROR` body (bytes after the type varint), returning
    /// the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the diagnostic length exceeds the remaining
    /// buffer, and `Varint` if a field is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let request_id = read_varint(&mut pos)?;
        let code = read_varint(&mut pos)?;
        let hop = read_varint(&mut pos)?;
        let (diag, n) = crate::bytes::decode(&body[pos..], Self::MAX_DIAGNOSTIC)
            .map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((
            Self {
                request_id,
                error_code: code,
                failed_hop_index: hop,
                diagnostic: diag.to_vec(),
            },
            pos,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_len(ty: u64) -> usize {
        crate::varint::encode(ty).unwrap().len()
    }

    #[test]
    fn route_request_round_trip() {
        let f = RouteRequestFrame {
            request_id: 99,
            allow_relay: true,
            allow_store_forward: false,
            require_private_response: true,
            local_scope_only: false,
            gateway_query: false,
            hop_limit: 8,
            expiration_delta: 30_000,
            destination_hint: b"token".to_vec(),
            path_exclusions: vec![b"relay-a".to_vec()],
            requester_auth: b"proof".to_vec(),
        };
        let enc = f.encode().unwrap();
        let (dec, used) =
            RouteRequestFrame::decode(&enc[type_len(FrameType::ROUTE_REQUEST.0)..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - type_len(FrameType::ROUTE_REQUEST.0));
    }

    #[test]
    fn route_request_rejects_bad_hop_limit() {
        let mut f = RouteRequestFrame {
            request_id: 1,
            allow_relay: false,
            allow_store_forward: false,
            require_private_response: false,
            local_scope_only: false,
            gateway_query: false,
            hop_limit: 33,
            expiration_delta: 100,
            destination_hint: vec![],
            path_exclusions: vec![],
            requester_auth: vec![],
        };
        assert_eq!(f.encode(), Err(FrameError::InvalidPadding));
        f.hop_limit = 0;
        assert_eq!(f.encode(), Err(FrameError::InvalidPadding));
    }

    #[test]
    fn route_response_rejects_direct_and_relay() {
        let f = RouteResponseFrame {
            request_id: 1,
            response_sequence: 0,
            direct: true,
            relay_required: true,
            store_forward_available: false,
            local_path: false,
            gateway_path: false,
            route_lifetime: 600,
            next_hop_hint: vec![],
            route_metadata: vec![],
            authentication: vec![],
        };
        assert_eq!(f.encode(), Err(FrameError::InvalidPadding));
    }

    #[test]
    fn route_error_round_trip() {
        let f = RouteErrorFrame {
            request_id: 2,
            error_code: 0x0D,
            failed_hop_index: RouteErrorFrame::UNKNOWN_HOP,
            diagnostic: vec![],
        };
        let enc = f.encode().unwrap();
        let (dec, _) = RouteErrorFrame::decode(&enc[type_len(FrameType::ROUTE_ERROR.0)..]).unwrap();
        assert_eq!(dec, f);
    }
}
