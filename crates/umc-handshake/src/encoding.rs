// Handshake message registry (handshake.md §8).
pub const CLIENT_HELLO: u64 = 0x00;
pub const SERVER_HELLO: u64 = 0x01;
pub const CLIENT_AUTH: u64 = 0x02;
pub const SERVER_FINISHED: u64 = 0x03;
pub const CLIENT_FINISHED: u64 = 0x04;
pub const RETRY_INFO: u64 = 0x05;
pub const NEW_SESSION_TICKET: u64 = 0x06;
pub const EARLY_DATA_REJECTED: u64 = 0x07;
pub const HANDSHAKE_CLOSE: u64 = 0x08;

pub const MAX_HANDSHAKE_TRANSCRIPT: usize = 65_536;
pub const MAX_HANDSHAKE_MESSAGE: usize = 16_384;

/// Handshake stream encoding (handshake.md §7):
/// `MessageType`: Varint, `MessageLength`: Varint, `MessageBody`.
///
/// # Errors
///
/// Returns `EncodeError::MessageTooLarge` if the body exceeds
/// [`MAX_HANDSHAKE_MESSAGE`], or `EncodeError::Varint` if the message type
/// does not fit a varint.
pub fn encode_message(
    out: &mut Vec<u8>,
    message_type: u64,
    body: &[u8],
) -> Result<(), EncodeError> {
    if body.len() > MAX_HANDSHAKE_MESSAGE {
        return Err(EncodeError::MessageTooLarge);
    }
    umc_wire::varint::encode_into(out, message_type).map_err(|_| EncodeError::Varint)?;
    umc_wire::varint::encode_into(out, body.len() as u64).map_err(|_| EncodeError::Varint)?;
    out.extend_from_slice(body);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    MessageTooLarge,
    Varint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    MessageTooLarge,
    Varint,
}

#[derive(Debug, PartialEq)]
pub struct DecodedMessage {
    pub message_type: u64,
    pub body: Vec<u8>,
}

/// Decode one message; returns `(message, bytes_consumed)`.
///
/// # Errors
///
/// Returns `DecodeError::Varint` if a varint fails to decode,
/// `DecodeError::MessageTooLarge` if the declared length exceeds
/// [`MAX_HANDSHAKE_MESSAGE`], or `DecodeError::Truncated` if the body is
/// missing from the buffer.
pub fn decode_message(buf: &[u8]) -> Result<(DecodedMessage, usize), DecodeError> {
    let (message_type, n1) = umc_wire::varint::decode(buf).map_err(|_| DecodeError::Varint)?;
    let (len, n2) = umc_wire::varint::decode(&buf[n1..]).map_err(|_| DecodeError::Varint)?;
    if len > MAX_HANDSHAKE_MESSAGE as u64 {
        return Err(DecodeError::MessageTooLarge);
    }
    let start = n1 + n2;
    let len = usize::try_from(len).map_err(|_| DecodeError::Truncated)?;
    let end = start.checked_add(len).ok_or(DecodeError::Truncated)?;
    let body = buf.get(start..end).ok_or(DecodeError::Truncated)?.to_vec();
    Ok((DecodedMessage { message_type, body }, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut out = Vec::new();
        encode_message(&mut out, CLIENT_HELLO, b"hello").unwrap();
        let (msg, used) = decode_message(&out).unwrap();
        assert_eq!(msg.message_type, CLIENT_HELLO);
        assert_eq!(msg.body, b"hello");
        assert_eq!(used, out.len());
    }

    #[test]
    fn rejects_oversize() {
        let mut out = Vec::new();
        assert_eq!(
            encode_message(&mut out, CLIENT_HELLO, &[0u8; MAX_HANDSHAKE_MESSAGE + 1]),
            Err(EncodeError::MessageTooLarge)
        );
        // Declared length 16385 (4-byte varint 0x80 0x00 0x40 0x01) exceeds
        // the 16384 limit.
        assert_eq!(
            decode_message(&[0x00, 0x80, 0x00, 0x40, 0x01]),
            Err(DecodeError::MessageTooLarge)
        );
    }

    #[test]
    fn multiple_messages_decode_sequentially() {
        let mut out = Vec::new();
        encode_message(&mut out, 0x00, b"a").unwrap();
        encode_message(&mut out, 0x01, b"bb").unwrap();
        let (m1, used1) = decode_message(&out).unwrap();
        let (m2, used2) = decode_message(&out[used1..]).unwrap();
        assert_eq!((m1.message_type, m2.message_type), (0x00, 0x01));
        assert_eq!(used1 + used2, out.len());
    }

    #[test]
    fn unknown_message_types_are_preserved() {
        let mut out = Vec::new();
        encode_message(&mut out, 0xFF, b"x").unwrap();
        let (msg, _) = decode_message(&out).unwrap();
        assert_eq!(msg.message_type, 0xFF);
    }
}
