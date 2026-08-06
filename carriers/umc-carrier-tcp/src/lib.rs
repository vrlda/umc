//! TCP carrier profile (carriers/tcp.md): varint-length-framed UMP packets.
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use umc_carrier::error::{CarrierError, CarrierErrorKind};
use umc_carrier::types::{
    CarrierCapabilities, CarrierTypeId, ConnectionModel, InboundPacket, LinkEvent, LinkProperties,
    Ordering, OutboundPacket, PacketMode, QueueState, Reliability, SendResult,
};
use umc_carrier::{BoxLink, Carrier, Link, Listener};
use umc_types::runtime::Instant;

pub const CARRIER_TYPE: &str = "ump.tcp/1";
pub const MAX_PACKET_LEN: usize = 65_535;
pub const SEND_QUEUE_CAPACITY: usize = 256;
pub const SEND_QUEUE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug)]
pub struct TcpCarrier;

impl Carrier for TcpCarrier {
    fn type_id(&self) -> CarrierTypeId {
        CarrierTypeId(CARRIER_TYPE.to_string())
    }

    fn capabilities(&self) -> CarrierCapabilities {
        CarrierCapabilities {
            api_version: 1,
            carrier_type: self.type_id(),
            packet_mode: PacketMode::StreamFramed,
            reliability: Reliability::ReliableUntilLinkFailure,
            ordering: Ordering::Ordered,
            connection_model: ConnectionModel::Connected,
            supports_listen: true,
            supports_dial: true,
            supports_discovery: false,
            minimum_packet_size: 1,
            maximum_packet_size: MAX_PACKET_LEN,
            scope_classes: vec!["general_network".into()],
        }
    }

    fn listen(&self, bind: String) -> Result<Box<dyn Listener + Send + Sync>, CarrierError> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "listen"))?;
        let listener = rt
            .block_on(TokioListener::bind(&bind))
            .map_err(|e| CarrierError {
                kind: CarrierErrorKind::AddressInUse,
                operation: "listen",
                retryable: false,
                message: e.to_string(),
            })?;
        Ok(Box::new(TcpListenerAdapter {
            inner: Arc::new(listener),
        }))
    }

    fn dial(&self, remote: String) -> Result<BoxLink, CarrierError> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "dial"))?;
        let stream = rt
            .block_on(TcpStream::connect(&remote))
            .map_err(|e| CarrierError {
                kind: CarrierErrorKind::Unreachable,
                operation: "dial",
                retryable: true,
                message: e.to_string(),
            })?;
        Ok(Box::new(TcpLink::new(stream)))
    }
}

#[derive(Debug)]
pub struct TcpListenerAdapter {
    inner: Arc<TokioListener>,
}

impl Listener for TcpListenerAdapter {
    fn accept(&self) -> Result<BoxLink, CarrierError> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "accept"))?;
        let (stream, _addr) = rt.block_on(self.inner.accept()).map_err(|e| CarrierError {
            kind: CarrierErrorKind::Internal,
            operation: "accept",
            retryable: true,
            message: e.to_string(),
        })?;
        Ok(Box::new(TcpLink::new(stream)))
    }

    fn close(&self) -> Result<(), CarrierError> {
        Ok(())
    }
}

/// How long `recv` holds the stream lock waiting for one byte before
/// releasing it (returning `WouldBlock`) so the writer task can flush.
/// A blocking read that holds the shared mutex indefinitely would starve
/// the writer once a session reads ahead of its replies.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(20);

#[derive(Debug)]
pub struct TcpLink {
    stream: Arc<Mutex<(TcpStream, Vec<u8>)>>, // stream + partial-frame bytes
    outbound: mpsc::Sender<OutboundPacket>,
}

impl TcpLink {
    pub fn new(stream: TcpStream) -> Self {
        let stream = Arc::new(Mutex::new((stream, Vec::new())));
        let (tx, mut rx) = mpsc::channel::<OutboundPacket>(SEND_QUEUE_CAPACITY);
        let writer_stream = stream.clone();
        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                let mut framed = Vec::with_capacity(packet.bytes.len() + 4);
                if umc_wire_framing::push_length(&mut framed, packet.bytes.len()).is_err() {
                    break;
                }
                framed.extend_from_slice(&packet.bytes);
                let mut guard = writer_stream.lock().await;
                if guard.0.write_all(&framed).await.is_err() {
                    break;
                }
                let _ = guard.0.flush().await;
            }
        });
        Self {
            stream,
            outbound: tx,
        }
    }
}

/// Internal framing helper (no crate dependency on umc-wire for the carrier).
// Lengths are range-checked before each cast; the `Result` wrapper matches the
// umc-wire call shape.
#[allow(clippy::cast_possible_truncation, clippy::unnecessary_wraps)]
mod umc_wire_framing {
    pub fn push_length(out: &mut Vec<u8>, len: usize) -> Result<(), ()> {
        let len = len as u64;
        if len <= 63 {
            out.push(len as u8);
        } else if len <= 16_383 {
            out.push(0b0100_0000 | ((len >> 8) as u8));
            out.push(len as u8);
        } else if len <= 1_073_741_823 {
            out.push(0b1000_0000 | ((len >> 24) as u8));
            out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
        } else {
            out.push(0b1100_0000 | ((len >> 56) as u8));
            out.extend_from_slice(&len.to_be_bytes()[1..]);
        }
        Ok(())
    }

    pub fn read_length(buf: &[u8]) -> Result<Option<(usize, usize)>, ()> {
        let first = *buf.first().ok_or(())?;
        let width = match first >> 6 {
            0 => 1usize,
            1 => 2usize,
            2 => 4usize,
            _ => 8usize,
        };
        if buf.len() < width {
            return Ok(None);
        }
        let mut raw = [0u8; 8];
        raw[..width].copy_from_slice(&buf[..width]);
        raw[0] &= 0x3F;
        // CORRECTED: shift the masked prefix bits into the right position.
        let v = u64::from_be_bytes(raw) >> ((8 - width) * 8);
        if v > 65_535 {
            return Err(());
        }
        Ok(Some((v as usize, width)))
    }
}

impl Link for TcpLink {
    fn properties(&self) -> LinkProperties {
        LinkProperties {
            reliability: Reliability::ReliableUntilLinkFailure,
            ordering: Ordering::Ordered,
            current_mtu: MAX_PACKET_LEN,
            queue_bytes: 0,
            queue_capacity: SEND_QUEUE_BYTES,
            estimated_rtt_ms: None,
            estimated_loss: None,
            metered: false,
        }
    }

    fn send(&self, packet: OutboundPacket) -> Result<SendResult, CarrierError> {
        self.outbound
            .try_send(packet)
            .map_err(|_| CarrierError::new(CarrierErrorKind::QueueFull, "send"))?;
        Ok(SendResult::Accepted {
            queue_state: QueueState::QueuedBounded,
        })
    }

    fn recv(&self) -> Result<InboundPacket, CarrierError> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "recv"))?;
        let stream = self.stream.clone();
        let packet = rt.block_on(async move {
            let mut guard = stream.lock().await;
            let mut buf = std::mem::take(&mut guard.1);
            loop {
                let mut b = [0u8; 1];
                match tokio::time::timeout(READ_TIMEOUT, guard.0.read_exact(&mut b)).await {
                    Err(_) => {
                        // Timed out waiting for a byte: park the partial
                        // frame and release the lock so the writer flushes.
                        guard.1 = buf;
                        return Err(CarrierError::new(CarrierErrorKind::WouldBlock, "recv"));
                    }
                    Ok(Err(_)) => {
                        return Err(CarrierError::new(CarrierErrorKind::LinkFailed, "recv"))
                    }
                    Ok(Ok(_)) => buf.push(b[0]),
                }
                match umc_wire_framing::read_length(&buf) {
                    Ok(Some((len, used))) => {
                        let mut payload = vec![0u8; len];
                        match tokio::time::timeout(READ_TIMEOUT, guard.0.read_exact(&mut payload))
                            .await
                        {
                            Err(_) => {
                                guard.1 = buf;
                                return Err(CarrierError::new(
                                    CarrierErrorKind::WouldBlock,
                                    "recv",
                                ));
                            }
                            Ok(Err(_)) => {
                                return Err(CarrierError::new(CarrierErrorKind::LinkFailed, "recv"))
                            }
                            Ok(Ok(_)) => {
                                let _ = used;
                                return Ok(payload);
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(()) => {
                        return Err(CarrierError::new(CarrierErrorKind::ProtocolError, "recv"))
                    }
                }
            }
        })?;
        Ok(InboundPacket {
            bytes: packet,
            received_at: Instant(0),
        })
    }

    fn events(&self) -> Result<LinkEvent, CarrierError> {
        Err(CarrierError::new(CarrierErrorKind::WouldBlock, "events"))
    }

    fn close(&self, _reason: &str) -> Result<(), CarrierError> {
        let stream = self.stream.clone();
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "close"))?;
        rt.block_on(async move {
            let mut guard = stream.lock().await;
            let _ = guard.0.shutdown().await;
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_length_round_trip() {
        let mut buf = Vec::new();
        umc_wire_framing::push_length(&mut buf, 64).unwrap();
        assert_eq!(umc_wire_framing::read_length(&buf).unwrap(), Some((64, 2)));
        let mut buf = Vec::new();
        umc_wire_framing::push_length(&mut buf, 65_535).unwrap();
        assert_eq!(
            umc_wire_framing::read_length(&buf).unwrap(),
            Some((65_535, 4))
        );
    }

    #[test]
    fn framing_rejects_oversize() {
        let buf = vec![0b1000_0000, 0xFF, 0xFF, 0xFF];
        assert!(umc_wire_framing::read_length(&buf).is_err());
    }

    #[test]
    fn capabilities_match_profile() {
        let c = TcpCarrier;
        assert_eq!(c.type_id().0, "ump.tcp/1");
        assert_eq!(c.capabilities().packet_mode, PacketMode::StreamFramed);
        assert_eq!(
            c.capabilities().reliability,
            Reliability::ReliableUntilLinkFailure
        );
    }
}
