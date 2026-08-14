use crate::frame::{decode_frames, Frame, FrameError};
use crate::header::ShortPacketSpace;
use umc_types::version::MAX_PACKET_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketContext {
    Initial,
    Handshake,
    Protected(ShortPacketSpace),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    TooLarge,
    Frame(FrameError),
    ContextViolation(umc_types::frame::FrameType),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPacket {
    pub context: PacketContext,
    pub frames: Vec<Frame>,
}

/// Parse a decrypted, header-validated payload into frames,
/// enforcing the packet-context rules from wire-format §57.
///
/// # Errors
///
/// Returns `TooLarge` if the payload exceeds [`MAX_PACKET_SIZE`], `Frame` if
/// the payload contains malformed or unrecognized frames, and
/// `ContextViolation` if a frame is not allowed in this packet context.
pub fn parse_payload(context: &PacketContext, payload: &[u8]) -> Result<ParsedPacket, PacketError> {
    if payload.len() > MAX_PACKET_SIZE {
        return Err(PacketError::TooLarge);
    }
    let frames = decode_frames(payload).map_err(PacketError::Frame)?;
    for f in &frames {
        check_context(context, f)?;
    }
    Ok(ParsedPacket {
        context: context.clone(),
        frames,
    })
}

#[must_use]
#[allow(clippy::match_like_matches_macro)]
pub fn context_allows(context: &PacketContext, ty: umc_types::frame::FrameType) -> bool {
    use umc_types::frame::FrameType as T;
    use ShortPacketSpace::{PathControl, RelayData, SessionData};
    match (context, ty) {
        (_, T::PADDING | T::PING | T::ACK | T::CAPABILITIES) => true,
        (PacketContext::Initial | PacketContext::Handshake, T::AUTH | T::HANDSHAKE_DATA) => true,
        (PacketContext::Protected(_), T::STREAM | T::DATAGRAM) => true,
        (PacketContext::Protected(_), T::ROUTE_REQUEST | T::ROUTE_RESPONSE | T::ROUTE_ERROR) => {
            true
        }
        (
            PacketContext::Protected(_),
            T::RELAY_OPEN | T::RELAY_STATUS | T::RELAY_DATA | T::RELAY_CLOSE,
        ) => true,
        (PacketContext::Protected(_), T::BUNDLE | T::BUNDLE_ACK) => true,
        (
            PacketContext::Protected(_),
            T::PATH_CHALLENGE | T::PATH_RESPONSE | T::PATH_STATUS | T::MIGRATE,
        ) => true,
        (PacketContext::Protected(_), T::KEY_UPDATE) => true,
        (PacketContext::Protected(_), T::NEW_CONNECTION_ID | T::RETIRE_CONNECTION_ID) => true,
        (
            PacketContext::Protected(_),
            T::PEER_HINT | T::SERVICE_HINT | T::DHT_LOOKUP | T::REVOCATION_BATCH,
        ) => true,
        (PacketContext::Protected(_), T::MAX_DATA | T::MAX_STREAM_DATA | T::MAX_STREAMS) => true,
        (PacketContext::Protected(_), T::RESET_STREAM | T::STOP_SENDING) => true,
        (PacketContext::Protected(_), T::CONNECTION_CLOSE) => true,
        (PacketContext::Protected(SessionData | PathControl | RelayData), T::SESSION_TICKET) => {
            true
        }
        _ => false,
    }
}

fn check_context(context: &PacketContext, frame: &Frame) -> Result<(), PacketError> {
    let ty = frame_type_of(frame);
    if context_allows(context, ty) {
        Ok(())
    } else {
        Err(PacketError::ContextViolation(ty))
    }
}

#[must_use]
pub fn frame_type_of(frame: &Frame) -> umc_types::frame::FrameType {
    use umc_types::frame::FrameType as T;
    match frame {
        Frame::Padding => T::PADDING,
        Frame::Ping => T::PING,
        Frame::Ack(_) => T::ACK,
        Frame::ConnectionClose(_) => T::CONNECTION_CLOSE,
        Frame::Stream(_) => T::STREAM,
        Frame::ResetStream(_) => T::RESET_STREAM,
        Frame::StopSending(_) => T::STOP_SENDING,
        Frame::MaxData(_) => T::MAX_DATA,
        Frame::MaxStreamData(_) => T::MAX_STREAM_DATA,
        Frame::MaxStreams(_) => T::MAX_STREAMS,
        Frame::Datagram(_) => T::DATAGRAM,
        Frame::NewConnectionId(_) => T::NEW_CONNECTION_ID,
        Frame::RetireConnectionId(_) => T::RETIRE_CONNECTION_ID,
        Frame::PathChallenge(_) => T::PATH_CHALLENGE,
        Frame::PathResponse(_) => T::PATH_RESPONSE,
        Frame::PathStatus(_) => T::PATH_STATUS,
        Frame::Migrate(_) => T::MIGRATE,
        Frame::KeyUpdate(_) => T::KEY_UPDATE,
        Frame::RouteRequest(_) => T::ROUTE_REQUEST,
        Frame::RouteResponse(_) => T::ROUTE_RESPONSE,
        Frame::RouteError(_) => T::ROUTE_ERROR,
        Frame::RelayOpen(_) => T::RELAY_OPEN,
        Frame::RelayStatus(_) => T::RELAY_STATUS,
        Frame::RelayData(_) => T::RELAY_DATA,
        Frame::RelayClose(_) => T::RELAY_CLOSE,
        Frame::Bundle(_) => T::BUNDLE,
        Frame::BundleAck(_) => T::BUNDLE_ACK,
        Frame::PeerHint(_) => T::PEER_HINT,
        Frame::Capabilities(_) => T::CAPABILITIES,
        Frame::Auth(_) => T::AUTH,
        Frame::HandshakeData(_) => T::HANDSHAKE_DATA,
        Frame::SessionTicket(_) => T::SESSION_TICKET,
        Frame::ServiceHint(_) => T::SERVICE_HINT,
        Frame::DhtLookup(_) => T::DHT_LOOKUP,
        Frame::RevocationBatch(_) => T::REVOCATION_BATCH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::frame::FrameType as T;

    #[test]
    fn stream_allowed_in_protected_not_initial() {
        let payload = [0x10, 0x00, 0x00, 0x61];
        assert!(parse_payload(
            &PacketContext::Protected(ShortPacketSpace::SessionData),
            &payload
        )
        .is_ok());
        assert_eq!(
            parse_payload(&PacketContext::Initial, &payload).unwrap_err(),
            PacketError::ContextViolation(T::STREAM)
        );
    }

    #[test]
    fn handshake_data_allowed_only_in_handshake_contexts() {
        // 0x74 is a 2-byte varint: [0x40, 0x74] = HANDSHAKE_DATA, then
        // offset 0, then empty data.
        let payload = [0x40, 0x74, 0x00, 0x00];
        assert!(parse_payload(&PacketContext::Initial, &payload).is_ok());
        assert_eq!(
            parse_payload(
                &PacketContext::Protected(ShortPacketSpace::SessionData),
                &payload
            )
            .unwrap_err(),
            PacketError::ContextViolation(T::HANDSHAKE_DATA)
        );
    }

    #[test]
    fn route_request_only_in_protected() {
        // NOTE: ROUTE_REQUEST is dispatched fixed-layout (no length prefix) in
        // this implementation; the payload is: type (2-byte varint 0x48) then
        // request_id 99, flags 0x00, hop_limit 8, expiration 30s, empty hint,
        // 0 exclusions, empty auth.
        let mut payload = Vec::new();
        crate::varint::encode_into(&mut payload, T::ROUTE_REQUEST.0).unwrap();
        let frame = crate::frames::routing::RouteRequestFrame {
            request_id: 99,
            allow_relay: false,
            allow_store_forward: false,
            require_private_response: false,
            local_scope_only: false,
            gateway_query: false,
            hop_limit: 8,
            expiration_delta: 30_000,
            destination_hint: vec![],
            path_exclusions: vec![],
            requester_auth: vec![],
        };
        let enc = frame.encode().unwrap();
        let type_len = crate::varint::encode(T::ROUTE_REQUEST.0).unwrap().len();
        payload.extend_from_slice(&enc[type_len..]);
        assert!(parse_payload(
            &PacketContext::Protected(ShortPacketSpace::SessionData),
            &payload
        )
        .is_ok());
        assert_eq!(
            parse_payload(&PacketContext::Handshake, &payload).unwrap_err(),
            PacketError::ContextViolation(T::ROUTE_REQUEST)
        );
    }

    #[test]
    fn revocation_batch_only_in_protected() {
        let encoded = crate::frames::misc::RevocationBatchFrame {
            payload: b"RS\x01\x00\x00".to_vec(),
        }
        .encode()
        .unwrap();
        assert!(parse_payload(
            &PacketContext::Protected(ShortPacketSpace::SessionData),
            &encoded
        )
        .is_ok());
        assert_eq!(
            parse_payload(&PacketContext::Initial, &encoded).unwrap_err(),
            PacketError::ContextViolation(T::REVOCATION_BATCH)
        );
    }

    #[test]
    fn oversize_payload_rejected() {
        let big = vec![0x04; MAX_PACKET_SIZE + 1];
        assert_eq!(
            parse_payload(
                &PacketContext::Protected(ShortPacketSpace::SessionData),
                &big
            ),
            Err(PacketError::TooLarge)
        );
    }
}
