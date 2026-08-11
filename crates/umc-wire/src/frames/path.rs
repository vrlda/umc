use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const CHALLENGE_LEN: usize = 8;
pub const RESET_TOKEN_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathChallengeFrame {
    pub data: [u8; CHALLENGE_LEN],
}

impl PathChallengeFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `VarintEncode` if the type byte cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::PATH_CHALLENGE.0)
            .map_err(FrameError::VarintEncode)?;
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    /// Decodes a `PATH_CHALLENGE` body (bytes after the type byte), returning
    /// the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if fewer than [`CHALLENGE_LEN`] bytes remain.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut data = [0u8; CHALLENGE_LEN];
        data.copy_from_slice(body.get(..CHALLENGE_LEN).ok_or(FrameError::Truncated)?);
        Ok((Self { data }, CHALLENGE_LEN))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathResponseFrame {
    pub data: [u8; CHALLENGE_LEN],
}

impl PathResponseFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `VarintEncode` if the type byte cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::PATH_RESPONSE.0)
            .map_err(FrameError::VarintEncode)?;
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    /// Decodes a `PATH_RESPONSE` body (bytes after the type byte), returning
    /// the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if fewer than [`CHALLENGE_LEN`] bytes remain.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut data = [0u8; CHALLENGE_LEN];
        data.copy_from_slice(body.get(..CHALLENGE_LEN).ok_or(FrameError::Truncated)?);
        Ok((Self { data }, CHALLENGE_LEN))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct PathStatusFrame {
    pub path_id: u64,
    pub validated: bool,
    pub active: bool,
    pub degraded: bool,
    pub local: bool,
    pub metered: bool,
    pub censored_or_filtered: bool,
    pub estimated_rtt: u64,
    pub estimated_bandwidth: u64,
    pub estimated_loss: u64,
    pub cost_class: u64,
}

impl PathStatusFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::PATH_STATUS.0)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.path_id).map_err(FrameError::VarintEncode)?;
        let mut flags = 0u8;
        if self.validated {
            flags |= 0x01;
        }
        if self.active {
            flags |= 0x02;
        }
        if self.degraded {
            flags |= 0x04;
        }
        if self.local {
            flags |= 0x08;
        }
        if self.metered {
            flags |= 0x10;
        }
        if self.censored_or_filtered {
            flags |= 0x20;
        }
        out.push(flags);
        crate::varint::encode_into(&mut out, self.estimated_rtt)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.estimated_bandwidth)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.estimated_loss)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.cost_class).map_err(FrameError::VarintEncode)?;
        Ok(out)
    }

    /// Decodes a `PATH_STATUS` body (bytes after the type byte), returning the
    /// frame and the number of body bytes consumed.
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
        let path_id = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xC0 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let rtt = read_varint(&mut pos)?;
        let bw = read_varint(&mut pos)?;
        let loss = read_varint(&mut pos)?;
        let cost = read_varint(&mut pos)?;
        Ok((
            Self {
                path_id,
                validated: flags & 0x01 != 0,
                active: flags & 0x02 != 0,
                degraded: flags & 0x04 != 0,
                local: flags & 0x08 != 0,
                metered: flags & 0x10 != 0,
                censored_or_filtered: flags & 0x20 != 0,
                estimated_rtt: rtt,
                estimated_bandwidth: bw,
                estimated_loss: loss,
                cost_class: cost,
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrateFrame {
    pub old_path_id: u64,
    pub new_path_id: u64,
    pub migration_sequence: u64,
    pub make_primary: bool,
    pub keep_old_path: bool,
    pub duplicate_critical_frames: bool,
}

impl MigrateFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::MIGRATE.0)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.old_path_id).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.new_path_id).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.migration_sequence)
            .map_err(FrameError::VarintEncode)?;
        let mut flags = 0u8;
        if self.make_primary {
            flags |= 0x01;
        }
        if self.keep_old_path {
            flags |= 0x02;
        }
        if self.duplicate_critical_frames {
            flags |= 0x04;
        }
        out.push(flags);
        Ok(out)
    }

    /// Decodes a `MIGRATE` body (bytes after the type byte), returning the
    /// frame and the number of body bytes consumed.
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
        let old = read_varint(&mut pos)?;
        let new = read_varint(&mut pos)?;
        let seq = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xF8 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        Ok((
            Self {
                old_path_id: old,
                new_path_id: new,
                migration_sequence: seq,
                make_primary: flags & 0x01 != 0,
                keep_old_path: flags & 0x02 != 0,
                duplicate_critical_frames: flags & 0x04 != 0,
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUpdateFrame {
    pub update_sequence: u64,
    pub request_peer_update: bool,
}

impl KeyUpdateFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `VarintEncode` if the sequence cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::KEY_UPDATE.0)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.update_sequence)
            .map_err(FrameError::VarintEncode)?;
        out.push(u8::from(self.request_peer_update));
        Ok(out)
    }

    /// Decodes a `KEY_UPDATE` body (bytes after the type byte), returning the
    /// frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPadding` if reserved flag bits are set, and `Truncated`
    /// or `Varint` if the body is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (seq, n) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        let flags = *body.get(n).ok_or(FrameError::Truncated)?;
        if flags & 0xFE != 0 {
            return Err(FrameError::InvalidPadding);
        }
        Ok((
            Self {
                update_sequence: seq,
                request_peer_update: flags & 0x01 != 0,
            },
            n + 1,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewConnectionIdFrame {
    pub sequence: u64,
    pub retire_prior_to: u64,
    pub connection_id: Vec<u8>,
    pub reset_token: [u8; RESET_TOKEN_LEN],
}

impl NewConnectionIdFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if the connection id is not between 1 and
    /// 20 bytes, `InvalidPadding` if `retire_prior_to` exceeds `sequence`, and
    /// `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if !(1..=20).contains(&self.connection_id.len()) {
            return Err(FrameError::LengthExceedsLimit);
        }
        if self.retire_prior_to > self.sequence {
            return Err(FrameError::InvalidPadding);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::NEW_CONNECTION_ID.0)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.sequence).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.retire_prior_to)
            .map_err(FrameError::VarintEncode)?;
        #[allow(clippy::cast_possible_truncation)]
        out.push(self.connection_id.len() as u8);
        out.extend_from_slice(&self.connection_id);
        out.extend_from_slice(&self.reset_token);
        Ok(out)
    }

    /// Decodes a `NEW_CONNECTION_ID` body (bytes after the type byte),
    /// returning the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if the connection id length is not between
    /// 1 and 20, `InvalidPadding` if `retire_prior_to` exceeds `sequence`, and
    /// `Truncated` or `Varint` if the body is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (seq, n1) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        let (retire, n2) = crate::varint::decode(&body[n1..]).map_err(FrameError::Varint)?;
        let len_pos = n1 + n2;
        let cid_len = *body.get(len_pos).ok_or(FrameError::Truncated)? as usize;
        if !(1..=20).contains(&cid_len) {
            return Err(FrameError::LengthExceedsLimit);
        }
        let cid_start = len_pos + 1;
        let cid_end = cid_start
            .checked_add(cid_len)
            .ok_or(FrameError::Truncated)?;
        let cid = body
            .get(cid_start..cid_end)
            .ok_or(FrameError::Truncated)?
            .to_vec();
        let token_start = cid_end;
        let token_end = token_start
            .checked_add(RESET_TOKEN_LEN)
            .ok_or(FrameError::Truncated)?;
        let mut reset_token = [0u8; RESET_TOKEN_LEN];
        reset_token.copy_from_slice(
            body.get(token_start..token_end)
                .ok_or(FrameError::Truncated)?,
        );
        if retire > seq {
            return Err(FrameError::InvalidPadding);
        }
        Ok((
            Self {
                sequence: seq,
                retire_prior_to: retire,
                connection_id: cid,
                reset_token,
            },
            token_end,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireConnectionIdFrame {
    pub sequence: u64,
}

impl RetireConnectionIdFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `VarintEncode` if the sequence cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::RETIRE_CONNECTION_ID.0)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.sequence).map_err(FrameError::VarintEncode)?;
        Ok(out)
    }

    /// Decodes a `RETIRE_CONNECTION_ID` body (bytes after the type byte),
    /// returning the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `Varint` if the sequence is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (seq, n) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        Ok((Self { sequence: seq }, n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_challenge_round_trip() {
        let f = PathChallengeFrame {
            data: [7u8; CHALLENGE_LEN],
        };
        let enc = f.encode().unwrap();
        let (dec, used) = PathChallengeFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, CHALLENGE_LEN);
    }

    #[test]
    fn path_status_round_trip() {
        let f = PathStatusFrame {
            path_id: 1,
            validated: true,
            active: true,
            degraded: false,
            local: true,
            metered: false,
            censored_or_filtered: false,
            estimated_rtt: 25,
            estimated_bandwidth: 10_000,
            estimated_loss: 1,
            cost_class: 0,
        };
        let enc = f.encode().unwrap();
        let (dec, _) = PathStatusFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn migrate_round_trip() {
        let f = MigrateFrame {
            old_path_id: 0,
            new_path_id: 1,
            migration_sequence: 3,
            make_primary: true,
            keep_old_path: true,
            duplicate_critical_frames: false,
        };
        let enc = f.encode().unwrap();
        let ty_len = crate::varint::encode(FrameType::MIGRATE.0).unwrap().len();
        let (dec, _) = MigrateFrame::decode(&enc[ty_len..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn key_update_round_trip() {
        let f = KeyUpdateFrame {
            update_sequence: 1,
            request_peer_update: true,
        };
        let enc = f.encode().unwrap();
        let ty_len = crate::varint::encode(FrameType::KEY_UPDATE.0)
            .unwrap()
            .len();
        let (dec, _) = KeyUpdateFrame::decode(&enc[ty_len..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn new_connection_id_round_trip_and_validation() {
        let f = NewConnectionIdFrame {
            sequence: 0,
            retire_prior_to: 0,
            connection_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
            reset_token: [9u8; RESET_TOKEN_LEN],
        };
        let enc = f.encode().unwrap();
        let (dec, used) = NewConnectionIdFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - 1);
        let bad = NewConnectionIdFrame {
            sequence: 1,
            retire_prior_to: 2,
            connection_id: vec![1],
            reset_token: [0u8; 16],
        };
        assert_eq!(bad.encode(), Err(FrameError::InvalidPadding));
    }

    #[test]
    fn retire_connection_id_round_trip() {
        let f = RetireConnectionIdFrame { sequence: 2 };
        let enc = f.encode().unwrap();
        let (dec, _) = RetireConnectionIdFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }
}
