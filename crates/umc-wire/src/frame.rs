use umc_types::frame::{ExtensionBehavior, FrameType};

pub const MAX_ACK_RANGES: usize = 64;
pub const MAX_REASON_LEN: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    UnknownCriticalFrame(FrameType),
    UnknownOptionalFixedFrame(FrameType),
    InvalidPadding,
    AckRangeUnderflow,
    TooManyAckRanges,
    AckDelayTooLarge,
    Varint(crate::varint::DecodeError),
    VarintEncode(crate::varint::EncodeError),
    Truncated,
    LengthExceedsLimit,
    UnsupportedLengthDelimited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRange {
    pub gap: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Padding,
    Ping,
    Ack(AckFrame),
    ConnectionClose(ConnectionCloseFrame),
    Stream(crate::frames::stream::StreamFrame),
    ResetStream(crate::frames::stream::ResetStreamFrame),
    StopSending(crate::frames::stream::StopSendingFrame),
    MaxData(crate::frames::flow::MaxDataFrame),
    MaxStreamData(crate::frames::flow::MaxStreamDataFrame),
    MaxStreams(crate::frames::flow::MaxStreamsFrame),
    Datagram(crate::frames::datagram::DatagramFrame),
    NewConnectionId(crate::frames::path::NewConnectionIdFrame),
    RetireConnectionId(crate::frames::path::RetireConnectionIdFrame),
    PathChallenge(crate::frames::path::PathChallengeFrame),
    PathResponse(crate::frames::path::PathResponseFrame),
    PathStatus(crate::frames::path::PathStatusFrame),
    Migrate(crate::frames::path::MigrateFrame),
    KeyUpdate(crate::frames::path::KeyUpdateFrame),
    Auth(crate::frames::handshake::AuthFrame),
    HandshakeData(crate::frames::handshake::HandshakeDataFrame),
    Capabilities(crate::frames::handshake::CapabilitiesFrame),
    SessionTicket(crate::frames::handshake::SessionTicketFrame),
    RouteRequest(crate::frames::routing::RouteRequestFrame),
    RouteResponse(crate::frames::routing::RouteResponseFrame),
    RouteError(crate::frames::routing::RouteErrorFrame),
    RelayOpen(crate::frames::relay::RelayOpenFrame),
    RelayStatus(crate::frames::relay::RelayStatusFrame),
    RelayData(crate::frames::relay::RelayDataFrame),
    RelayClose(crate::frames::relay::RelayCloseFrame),
    Bundle(crate::frames::bundle::BundleFrame),
    BundleAck(crate::frames::bundle::BundleAckFrame),
    PeerHint(crate::frames::misc::PeerHintFrame),
    ServiceHint(crate::frames::misc::ServiceHintFrame),
    DhtLookup(crate::frames::misc::DhtLookupFrame),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckFrame {
    pub largest_acknowledged: u64,
    pub ack_delay: u64,
    pub first_ack_range: u64,
    pub additional_ranges: Vec<AckRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCloseFrame {
    pub error_code: u64,
    pub trigger_frame_type: u64,
    pub reason: Vec<u8>,
}

impl AckFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `TooManyAckRanges` if more than [`MAX_ACK_RANGES`] additional
    /// ranges are present, and `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.additional_ranges.len() > MAX_ACK_RANGES {
            return Err(FrameError::TooManyAckRanges);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::ACK.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.largest_acknowledged)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.ack_delay).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, (self.additional_ranges.len() + 1) as u64)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.first_ack_range)
            .map_err(FrameError::VarintEncode)?;
        for r in &self.additional_ranges {
            crate::varint::encode_into(&mut out, r.gap).map_err(FrameError::VarintEncode)?;
            crate::varint::encode_into(&mut out, r.length).map_err(FrameError::VarintEncode)?;
        }
        Ok(out)
    }

    /// Decodes an `ACK` body (bytes after the type byte), returning the frame
    /// and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `TooManyAckRanges` if the range count is zero or exceeds
    /// [`MAX_ACK_RANGES`] + 1, `AckRangeUnderflow` if a range length is zero,
    /// and `Varint` if a field is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let largest = read_varint(&mut pos)?;
        let delay = read_varint(&mut pos)?;
        let range_count = read_varint(&mut pos)?;
        if range_count == 0 || range_count > MAX_ACK_RANGES as u64 + 1 {
            return Err(FrameError::TooManyAckRanges);
        }
        let first = read_varint(&mut pos)?;
        if first == 0 {
            return Err(FrameError::AckRangeUnderflow);
        }
        let mut ranges = Vec::new();
        for _ in 1..range_count {
            let gap = read_varint(&mut pos)?;
            let length = read_varint(&mut pos)?;
            if length == 0 {
                return Err(FrameError::AckRangeUnderflow);
            }
            ranges.push(AckRange { gap, length });
        }
        Ok((
            Self {
                largest_acknowledged: largest,
                ack_delay: delay,
                first_ack_range: first,
                additional_ranges: ranges,
            },
            pos,
        ))
    }
}

impl ConnectionCloseFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if the reason is longer than
    /// [`MAX_REASON_LEN`], and `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.reason.len() > MAX_REASON_LEN {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::CONNECTION_CLOSE.0)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.error_code).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.trigger_frame_type)
            .map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(&mut out, &self.reason, MAX_REASON_LEN)
            .map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    /// Decodes a `CONNECTION_CLOSE` body (bytes after the type byte), returning
    /// the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the reason length exceeds the remaining buffer,
    /// and `Varint` if a field is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let code = read_varint(&mut pos)?;
        let trigger = read_varint(&mut pos)?;
        let (reason, n) = crate::bytes::decode(&body[pos..], MAX_REASON_LEN)
            .map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((
            Self {
                error_code: code,
                trigger_frame_type: trigger,
                reason: reason.to_vec(),
            },
            pos,
        ))
    }
}

/// Parse frames from a decrypted payload (wire-format §20-22).
///
/// Unknown length-delimited frame types are skipped: they carry their body
/// length and are self-delimiting, so an unrecognized extension never aborts
/// the packet (wire-format §21).
///
/// # Errors
///
/// Returns `UnknownCriticalFrame` for unrecognized critical fixed frames,
/// `UnknownOptionalFixedFrame` for unrecognized optional fixed frames,
/// and the frame body's decode error for malformed or truncated frames.
#[allow(clippy::too_many_lines)]
pub fn decode_frames(payload: &[u8]) -> Result<Vec<Frame>, FrameError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < payload.len() {
        let (raw_ty, n) = crate::varint::decode(&payload[pos..]).map_err(FrameError::Varint)?;
        pos += n;
        let ty = FrameType(raw_ty);
        match ty.behavior() {
            ExtensionBehavior::CriticalFixed | ExtensionBehavior::OptionalFixed => {
                let rest = &payload[pos..];
                match ty {
                    // FIX-E2: the type byte consumed IS the padding byte;
                    // each 0x00 type is one PADDING frame with no body.
                    FrameType::PADDING => {
                        out.push(Frame::Padding);
                    }
                    FrameType::PING => {
                        out.push(Frame::Ping);
                    }
                    FrameType::ACK => {
                        let (f, used) = AckFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::Ack(f));
                    }
                    FrameType::CONNECTION_CLOSE => {
                        let (f, used) = ConnectionCloseFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::ConnectionClose(f));
                    }
                    FrameType::STREAM => {
                        let (f, used) = crate::frames::stream::StreamFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::Stream(f));
                    }
                    FrameType::RESET_STREAM => {
                        let (f, used) = crate::frames::stream::ResetStreamFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::ResetStream(f));
                    }
                    FrameType::STOP_SENDING => {
                        let (f, used) = crate::frames::stream::StopSendingFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::StopSending(f));
                    }
                    FrameType::MAX_DATA => {
                        let (f, used) = crate::frames::flow::MaxDataFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::MaxData(f));
                    }
                    FrameType::MAX_STREAM_DATA => {
                        let (f, used) = crate::frames::flow::MaxStreamDataFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::MaxStreamData(f));
                    }
                    FrameType::MAX_STREAMS => {
                        let (f, used) = crate::frames::flow::MaxStreamsFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::MaxStreams(f));
                    }
                    FrameType::DATAGRAM => {
                        let (f, used) = crate::frames::datagram::DatagramFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::Datagram(f));
                    }
                    FrameType::NEW_CONNECTION_ID => {
                        let (f, used) = crate::frames::path::NewConnectionIdFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::NewConnectionId(f));
                    }
                    FrameType::RETIRE_CONNECTION_ID => {
                        let (f, used) = crate::frames::path::RetireConnectionIdFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::RetireConnectionId(f));
                    }
                    FrameType::PATH_CHALLENGE => {
                        let (f, used) = crate::frames::path::PathChallengeFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::PathChallenge(f));
                    }
                    FrameType::PATH_RESPONSE => {
                        let (f, used) = crate::frames::path::PathResponseFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::PathResponse(f));
                    }
                    FrameType::PATH_STATUS => {
                        let (f, used) = crate::frames::path::PathStatusFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::PathStatus(f));
                    }
                    FrameType::MIGRATE => {
                        let (f, used) = crate::frames::path::MigrateFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::Migrate(f));
                    }
                    FrameType::KEY_UPDATE => {
                        let (f, used) = crate::frames::path::KeyUpdateFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::KeyUpdate(f));
                    }
                    FrameType::AUTH => {
                        let (f, used) = crate::frames::handshake::AuthFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::Auth(f));
                    }
                    FrameType::HANDSHAKE_DATA => {
                        let (f, used) = crate::frames::handshake::HandshakeDataFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::HandshakeData(f));
                    }
                    FrameType::CAPABILITIES => {
                        let (f, used) = crate::frames::handshake::CapabilitiesFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::Capabilities(f));
                    }
                    FrameType::SESSION_TICKET => {
                        let (f, used) = crate::frames::handshake::SessionTicketFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::SessionTicket(f));
                    }
                    FrameType::ROUTE_REQUEST => {
                        let (f, used) = crate::frames::routing::RouteRequestFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::RouteRequest(f));
                    }
                    FrameType::ROUTE_RESPONSE => {
                        let (f, used) = crate::frames::routing::RouteResponseFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::RouteResponse(f));
                    }
                    FrameType::ROUTE_ERROR => {
                        let (f, used) = crate::frames::routing::RouteErrorFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::RouteError(f));
                    }
                    FrameType::RELAY_OPEN => {
                        let (f, used) = crate::frames::relay::RelayOpenFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::RelayOpen(f));
                    }
                    FrameType::RELAY_STATUS => {
                        let (f, used) = crate::frames::relay::RelayStatusFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::RelayStatus(f));
                    }
                    FrameType::RELAY_DATA => {
                        let (f, used) = crate::frames::relay::RelayDataFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::RelayData(f));
                    }
                    FrameType::RELAY_CLOSE => {
                        let (f, used) = crate::frames::relay::RelayCloseFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::RelayClose(f));
                    }
                    FrameType::BUNDLE => {
                        let (f, used) = crate::frames::bundle::BundleFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::Bundle(f));
                    }
                    FrameType::BUNDLE_ACK => {
                        let (f, used) = crate::frames::bundle::BundleAckFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::BundleAck(f));
                    }
                    FrameType::PEER_HINT => {
                        let (f, used) = crate::frames::misc::PeerHintFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::PeerHint(f));
                    }
                    FrameType::SERVICE_HINT => {
                        let (f, used) = crate::frames::misc::ServiceHintFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::ServiceHint(f));
                    }
                    _ if ty.behavior() == ExtensionBehavior::OptionalFixed => {
                        return Err(FrameError::UnknownOptionalFixedFrame(ty));
                    }
                    _ => return Err(FrameError::UnknownCriticalFrame(ty)),
                }
            }
            ExtensionBehavior::CriticalLengthDelimited => {
                // Known critical length-delimited frames decode with their
                // declared length. An unknown critical extension must abort
                // the packet rather than being silently ignored.
                if ty == FrameType::RELAY_STATUS {
                    let (f, used) =
                        crate::frames::relay::RelayStatusFrame::decode_length_delimited(
                            &payload[pos..],
                        )?;
                    pos += used;
                    out.push(Frame::RelayStatus(f));
                } else {
                    return Err(FrameError::UnknownCriticalFrame(ty));
                }
            }
            ExtensionBehavior::OptionalLengthDelimited => {
                // Unknown optional length-delimited frames are self-delimiting
                // and can be skipped without changing the rest of the packet.
                let (len, used) =
                    crate::varint::decode(&payload[pos..]).map_err(FrameError::Varint)?;
                pos += used;
                let len = usize::try_from(len).map_err(|_| FrameError::LengthExceedsLimit)?;
                pos = pos.checked_add(len).ok_or(FrameError::LengthExceedsLimit)?;
                if pos > payload.len() {
                    return Err(FrameError::Truncated);
                }
                if ty == FrameType::DHT_LOOKUP {
                    let start = pos - len;
                    let (frame, used) =
                        crate::frames::misc::DhtLookupFrame::decode(&payload[start..pos])?;
                    if used != len {
                        return Err(FrameError::Truncated);
                    }
                    out.push(Frame::DhtLookup(frame));
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_round_trip() {
        assert_eq!(decode_frames(&[0x04]).unwrap(), vec![Frame::Ping]);
    }

    #[test]
    fn padding_is_one_byte_per_frame() {
        assert_eq!(
            decode_frames(&[0x00, 0x00, 0x00]).unwrap(),
            vec![Frame::Padding, Frame::Padding, Frame::Padding]
        );
    }

    #[test]
    fn non_zero_padding_byte_is_an_error() {
        assert_eq!(
            decode_frames(&[0x00, 0x01]),
            Err(FrameError::UnknownOptionalFixedFrame(FrameType(0x01)))
        );
    }

    #[test]
    fn ack_round_trip_with_ranges() {
        let f = AckFrame {
            largest_acknowledged: 100,
            ack_delay: 5,
            first_ack_range: 3,
            additional_ranges: vec![AckRange { gap: 2, length: 4 }],
        };
        let enc = f.encode().unwrap();
        let (dec, used) = AckFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - 1);
    }

    #[test]
    fn ack_rejects_zero_length_range() {
        let enc = [0x08, 0x40, 0x64, 0x05, 0x02, 0x03, 0x02, 0x00];
        assert_eq!(decode_frames(&enc), Err(FrameError::AckRangeUnderflow));
    }

    #[test]
    fn ack_rejects_zero_first_range() {
        // ACK(0x08): largest=5, delay=0, range_count=1, first_ack_range=0.
        let enc = [0x08, 0x05, 0x00, 0x01, 0x00];
        assert_eq!(decode_frames(&enc), Err(FrameError::AckRangeUnderflow));
    }

    #[test]
    fn connection_close_round_trip() {
        let f = ConnectionCloseFrame {
            error_code: 0x02,
            trigger_frame_type: 0x10,
            reason: b"bad stream".to_vec(),
        };
        let enc = f.encode().unwrap();
        let (dec, used) = ConnectionCloseFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - 1);
    }

    #[test]
    fn unknown_optional_fixed_is_rejected() {
        assert_eq!(
            decode_frames(&[0x01]),
            Err(FrameError::UnknownOptionalFixedFrame(FrameType(0x01)))
        );
    }

    #[test]
    fn unknown_critical_length_delimited_is_rejected() {
        // Type 0x02 is an unknown critical length-delimited extension.
        assert_eq!(
            decode_frames(&[0x02, 0x01, 0xAA]),
            Err(FrameError::UnknownCriticalFrame(FrameType(0x02)))
        );
    }

    #[test]
    fn unknown_optional_length_delimited_is_skipped() {
        // Type 0x0F is optional length-delimited; its two-byte body is
        // skipped and the following PING remains visible.
        let payload = [0x0F, 0x02, 0xAA, 0xBB, 0x04];
        assert_eq!(decode_frames(&payload).unwrap(), vec![Frame::Ping]);
    }

    #[test]
    fn truncated_optional_length_delimited_is_rejected() {
        assert_eq!(
            decode_frames(&[0x0F, 0x05, 0xAA]),
            Err(FrameError::Truncated)
        );
    }
}
