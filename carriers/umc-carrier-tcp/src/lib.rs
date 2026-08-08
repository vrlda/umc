//! TCP carrier profile (carriers/tcp.md): varint-length-framed UMP packets.
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
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
    /// Bytes sitting in the outbound queue (congestion.md §16): incremented
    /// on each accepted `try_send`, decremented by the writer task once the
    /// bytes reach the stream. `properties().queue_bytes` reports the gauge
    /// so the daemon can gate data sends on the real queue depth.
    pending_bytes: Arc<AtomicUsize>,
}

impl TcpLink {
    pub fn new(stream: TcpStream) -> Self {
        let stream = Arc::new(Mutex::new((stream, Vec::new())));
        let pending_bytes = Arc::new(AtomicUsize::new(0));
        let (tx, mut rx) = mpsc::channel::<OutboundPacket>(SEND_QUEUE_CAPACITY);
        let writer_stream = stream.clone();
        let writer_pending = pending_bytes.clone();
        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                let mut framed = Vec::with_capacity(packet.bytes.len() + 4);
                if umc_wire_framing::push_length(&mut framed, packet.bytes.len()).is_err() {
                    writer_pending.fetch_sub(packet.bytes.len(), AtomicOrdering::Relaxed);
                    break;
                }
                framed.extend_from_slice(&packet.bytes);
                let mut guard = writer_stream.lock().await;
                if guard.0.write_all(&framed).await.is_err() {
                    writer_pending.fetch_sub(packet.bytes.len(), AtomicOrdering::Relaxed);
                    break;
                }
                let _ = guard.0.flush().await;
                // The queued bytes leave the gauge once they are on the
                // stream (congestion.md §16).
                writer_pending.fetch_sub(packet.bytes.len(), AtomicOrdering::Relaxed);
            }
        });
        Self {
            stream,
            outbound: tx,
            pending_bytes,
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
            queue_bytes: self.pending_bytes.load(AtomicOrdering::Relaxed),
            queue_capacity: SEND_QUEUE_BYTES,
            estimated_rtt_ms: None,
            estimated_loss: None,
            metered: false,
        }
    }

    fn send(&self, packet: OutboundPacket) -> Result<SendResult, CarrierError> {
        let bytes = packet.bytes.len();
        // Count BEFORE the enqueue so a writer that drains concurrently can
        // never decrement past the increment (atomic wrap would trip the
        // backpressure gate permanently); on rejection the count is
        // compensated.
        self.pending_bytes.fetch_add(bytes, AtomicOrdering::Relaxed);
        self.outbound
            .try_send(packet)
            .map_err(|_| {
                self.pending_bytes.fetch_sub(bytes, AtomicOrdering::Relaxed);
                CarrierError::new(CarrierErrorKind::QueueFull, "send")
            })?;
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

    #[test]
    fn pending_bytes_tracks_queue() {
        // A single-threaded runtime drives the spawned writer only while
        // the test future yields, so the gauge is exact between sends and
        // the drain is observable in the poll loop.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = TokioListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let accept = tokio::spawn(async move {
                let (stream, _addr) = listener.accept().await.unwrap();
                stream
            });
            let client = TcpStream::connect(addr).await.unwrap();
            let server = accept.await.unwrap();
            let link = TcpLink::new(server);
            // Queue accounting (congestion.md §16): every accepted send
            // counts its bytes into `queue_bytes`; the writer drains them
            // asynchronously.
            let sizes = [32usize, 48, 64];
            for size in sizes {
                link.send(OutboundPacket {
                    bytes: vec![0xAB; size],
                    control: false,
                    deadline_ms: None,
                })
                .unwrap();
            }
            assert_eq!(
                link.properties().queue_bytes,
                sizes.iter().sum::<usize>(),
                "queued bytes reported before the writer drains"
            );
            // Poll until the writer puts the packets on the stream and the
            // gauge returns to zero.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            while link.properties().queue_bytes > 0 {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "writer did not drain the queue"
                );
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            assert_eq!(link.properties().queue_bytes, 0);
            assert_eq!(
                link.properties().queue_capacity,
                SEND_QUEUE_BYTES,
                "capacity reported from the send-queue budget"
            );
            // The peer received exactly the three frames.
            let mut reader = client;
            for size in sizes {
                let mut len_buf = Vec::new();
                loop {
                    let mut b = [0u8; 1];
                    reader.read_exact(&mut b).await.unwrap();
                    len_buf.push(b[0]);
                    if let Some((len, _used)) =
                        umc_wire_framing::read_length(&len_buf).expect("valid length prefix")
                    {
                        assert_eq!(len, size, "frame length prefix");
                        break;
                    }
                }
                let mut payload = vec![0u8; size];
                reader.read_exact(&mut payload).await.unwrap();
                assert_eq!(payload, vec![0xAB; size]);
            }
        });
    }
}
