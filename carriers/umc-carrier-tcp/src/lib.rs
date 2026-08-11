//! TCP carrier profile (carriers/tcp.md): varint-length-framed UMP packets.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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
        let _runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "listen"))?;
        let std_listener = std::net::TcpListener::bind(&bind).map_err(|e| CarrierError {
            kind: CarrierErrorKind::AddressInUse,
            operation: "listen",
            retryable: false,
            message: e.to_string(),
        })?;
        std_listener
            .set_nonblocking(true)
            .map_err(|e| CarrierError {
                kind: CarrierErrorKind::Internal,
                operation: "listen",
                retryable: false,
                message: e.to_string(),
            })?;
        Ok(Box::new(TcpListenerAdapter {
            std_inner: Arc::new(std_listener),
            closed: Arc::new(AtomicBool::new(false)),
        }))
    }

    fn dial(&self, remote: String) -> Result<BoxLink, CarrierError> {
        // The carrier trait is synchronous, while Node::connect is async.
        // Use a blocking socket connect here so dialing from an async runtime
        // never nests `Handle::block_on` (which panics); the caller owns the
        // blocking boundary for the short dial operation.
        let stream = std::net::TcpStream::connect(&remote).map_err(|e| CarrierError {
            kind: CarrierErrorKind::Unreachable,
            operation: "dial",
            retryable: true,
            message: e.to_string(),
        })?;
        stream.set_nonblocking(true).map_err(|e| CarrierError {
            kind: CarrierErrorKind::Internal,
            operation: "dial",
            retryable: false,
            message: e.to_string(),
        })?;
        let stream = TcpStream::from_std(stream).map_err(|e| CarrierError {
            kind: CarrierErrorKind::Internal,
            operation: "dial",
            retryable: false,
            message: e.to_string(),
        })?;
        Ok(Box::new(TcpLink::new(stream)))
    }
}

#[derive(Debug)]
pub struct TcpListenerAdapter {
    std_inner: Arc<std::net::TcpListener>,
    closed: Arc<AtomicBool>,
}

impl Listener for TcpListenerAdapter {
    fn accept(&self) -> Result<BoxLink, CarrierError> {
        if self.closed.load(AtomicOrdering::Acquire) {
            return Err(CarrierError::new(CarrierErrorKind::NotRunning, "accept"));
        }
        let (stream, _addr) = self.std_inner.accept().map_err(|error| {
            let kind = if error.kind() == std::io::ErrorKind::WouldBlock {
                CarrierErrorKind::WouldBlock
            } else {
                CarrierErrorKind::Internal
            };
            CarrierError {
                kind,
                operation: "accept",
                retryable: true,
                message: error.to_string(),
            }
        })?;
        // Accepted sockets do not consistently inherit the listener's
        // nonblocking flag across platforms (Linux returns a blocking
        // socket). Tokio rejects blocking descriptors in `from_std`, so
        // normalize the accepted stream before handing it to Tokio.
        stream.set_nonblocking(true).map_err(|error| CarrierError {
            kind: CarrierErrorKind::Internal,
            operation: "accept",
            retryable: false,
            message: error.to_string(),
        })?;
        let stream = TcpStream::from_std(stream).map_err(|error| CarrierError {
            kind: CarrierErrorKind::Internal,
            operation: "accept",
            retryable: false,
            message: error.to_string(),
        })?;
        Ok(Box::new(TcpLink::new(stream)))
    }

    fn close(&self) -> Result<(), CarrierError> {
        self.closed.store(true, AtomicOrdering::Release);
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
                if umc_carrier::framing::push_length(
                    &mut framed,
                    packet.bytes.len(),
                    MAX_PACKET_LEN,
                )
                .is_err()
                {
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
        self.outbound.try_send(packet).map_err(|_| {
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
                match umc_carrier::framing::read_length(&buf, MAX_PACKET_LEN) {
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
                    Err(_) => {
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
        let close = async move {
            let mut guard = stream.lock().await;
            let _ = guard.0.shutdown().await;
        };
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(close);
        } else {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "close"))?;
            runtime.block_on(close);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener as TokioListener;

    #[test]
    fn framing_length_round_trip() {
        let mut buf = Vec::new();
        umc_carrier::framing::push_length(&mut buf, 64, MAX_PACKET_LEN).unwrap();
        assert_eq!(
            umc_carrier::framing::read_length(&buf, MAX_PACKET_LEN).unwrap(),
            Some((64, 2))
        );
        let mut buf = Vec::new();
        umc_carrier::framing::push_length(&mut buf, 65_535, MAX_PACKET_LEN).unwrap();
        assert_eq!(
            umc_carrier::framing::read_length(&buf, MAX_PACKET_LEN).unwrap(),
            Some((65_535, 4))
        );
    }

    #[test]
    fn framing_rejects_oversize() {
        let buf = vec![0b1000_0000, 0xFF, 0xFF, 0xFF];
        assert!(umc_carrier::framing::read_length(&buf, MAX_PACKET_LEN).is_err());
    }

    #[test]
    fn listener_close_stops_accepting() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let listener = TcpCarrier
                .listen("127.0.0.1:0".to_string())
                .expect("listener");
            listener.close().expect("close");
            let Err(error) = listener.accept() else {
                panic!("closed listener accepted a link")
            };
            assert_eq!(error.kind, CarrierErrorKind::NotRunning);
        });
    }

    #[test]
    fn accepted_stream_is_registered_as_nonblocking() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
            std_listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            let address = std_listener.local_addr().expect("listener address");
            let adapter = TcpListenerAdapter {
                std_inner: Arc::new(std_listener),
                closed: Arc::new(AtomicBool::new(false)),
            };
            let _client = std::net::TcpStream::connect(address).expect("client connect");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            loop {
                match adapter.accept() {
                    Ok(_link) => break,
                    Err(error) if error.kind == CarrierErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline, "accept timed out");
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept failed: {error:?}"),
                }
            }
        });
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
                        umc_carrier::framing::read_length(&len_buf, MAX_PACKET_LEN)
                            .expect("valid length prefix")
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

    #[test]
    fn dial_is_safe_from_an_async_runtime_context() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = TokioListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
            let link = TcpCarrier.dial(address.to_string()).expect("dial");
            let _ = accept.await.expect("accept");
            link.close("test").expect("close");
        });
    }
}
