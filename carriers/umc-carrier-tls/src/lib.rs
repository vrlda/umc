//! Experimental TLS 1.3 stream carrier (carriers/tls-stream.md).
//!
//! The carrier uses the same bounded varint stream framing as the TCP
//! profile, but wraps the stream in TLS 1.3. UMP's own handshake remains the
//! authentication layer; the ephemeral self-signed certificate is a transport
//! binding and is intentionally marked experimental in the registry.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use umc_carrier::error::{CarrierError, CarrierErrorKind};
use umc_carrier::types::{
    CarrierCapabilities, CarrierTypeId, ConnectionModel, InboundPacket, LinkEvent, LinkProperties,
    Ordering, OutboundPacket, PacketMode, QueueState, Reliability, SendResult,
};
use umc_carrier::{BoxLink, Carrier, Link, Listener};
use umc_types::runtime::Instant;

pub const CARRIER_TYPE: &str = "ump.tls-stream/1";
pub const MAX_PACKET_LEN: usize = 65_535;
pub const SEND_QUEUE_CAPACITY: usize = 256;
pub const SEND_QUEUE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct TlsCarrier {
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
    server_name: String,
}

impl std::fmt::Debug for TlsCarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsCarrier").finish_non_exhaustive()
    }
}

impl Default for TlsCarrier {
    fn default() -> Self {
        Self::new().expect("TLS carrier configuration")
    }
}

impl TlsCarrier {
    /// Generates an ephemeral self-signed transport certificate. UMP's
    /// endpoint handshake authenticates the peer above this experimental
    /// transport layer.
    ///
    /// # Errors
    ///
    /// Returns a carrier error when certificate generation or TLS config
    /// construction fails.
    pub fn new() -> Result<Self, CarrierError> {
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(|e| {
                CarrierError {
                    kind: CarrierErrorKind::Internal,
                    operation: "tls-config",
                    retryable: false,
                    message: e.to_string(),
                }
            })?;
        let cert = certified.cert.der().to_vec();
        let key = certified.signing_key.serialize_der();
        Self::from_der(cert.clone(), key, vec![cert], "localhost")
    }

    /// Builds a carrier from operator-provisioned DER material.
    ///
    /// The server certificate and private key are expected to be a DER
    /// certificate and PKCS#8 private key. `trusted_roots` supplies the CA or
    /// pinned certificate set used by outbound dials; it is intentionally
    /// explicit so independently configured daemons do not accidentally
    /// trust each other's ephemeral development certificates.
    ///
    /// # Errors
    ///
    /// Returns a carrier error when the key/certificate cannot be installed or
    /// no trust roots are supplied.
    pub fn from_der(
        server_certificate_der: Vec<u8>,
        private_key_der: Vec<u8>,
        trusted_roots: Vec<Vec<u8>>,
        server_name: impl Into<String>,
    ) -> Result<Self, CarrierError> {
        if trusted_roots.is_empty() {
            return Err(CarrierError {
                kind: CarrierErrorKind::AuthenticationFailed,
                operation: "tls-config",
                retryable: false,
                message: "at least one TLS trust root is required".into(),
            });
        }
        let cert = CertificateDer::from(server_certificate_der);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der));
        let mut roots = RootCertStore::empty();
        for root in trusted_roots {
            roots
                .add(CertificateDer::from(root))
                .map_err(|e| CarrierError {
                    kind: CarrierErrorKind::AuthenticationFailed,
                    operation: "tls-config",
                    retryable: false,
                    message: e.to_string(),
                })?;
        }
        let server_name = server_name.into();
        ServerName::try_from(server_name.clone()).map_err(|e| CarrierError {
            kind: CarrierErrorKind::AddressInvalid,
            operation: "tls-config",
            retryable: false,
            message: e.to_string(),
        })?;
        let client =
            ClientConfig::builder_with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
        let server =
            ServerConfig::builder_with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .map_err(|e| CarrierError {
                    kind: CarrierErrorKind::Internal,
                    operation: "tls-config",
                    retryable: false,
                    message: e.to_string(),
                })?;
        Ok(Self {
            client: Arc::new(client),
            server: Arc::new(server),
            server_name,
        })
    }

    /// Returns TLS exporter bytes for binding carrier instances into a
    /// higher-level handshake.
    ///
    /// # Errors
    ///
    /// Returns an error when the TLS connection has no exporter material or
    /// the requested label/context cannot be derived.
    pub fn exporter(
        stream: &TlsStream<TcpStream>,
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, String> {
        let mut out = vec![0u8; len];
        let result = match stream {
            TlsStream::Client(stream) => {
                stream
                    .get_ref()
                    .1
                    .export_keying_material(&mut out, label, Some(context))
            }
            TlsStream::Server(stream) => {
                stream
                    .get_ref()
                    .1
                    .export_keying_material(&mut out, label, Some(context))
            }
        };
        result
            .map(|output| output.clone())
            .map_err(|e| e.to_string())
    }

    /// Binds a concrete listener and retains its ephemeral address for
    /// embedding applications and conformance tests.
    ///
    /// # Errors
    ///
    /// Returns a carrier error when the address cannot be bound or no Tokio
    /// runtime is active.
    pub fn bind(&self, bind: &str) -> Result<TlsListener, CarrierError> {
        let _runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "listen"))?;
        let listener = std::net::TcpListener::bind(bind).map_err(|e| CarrierError {
            kind: CarrierErrorKind::AddressInUse,
            operation: "listen",
            retryable: false,
            message: e.to_string(),
        })?;
        listener.set_nonblocking(true).map_err(|e| CarrierError {
            kind: CarrierErrorKind::Internal,
            operation: "listen",
            retryable: false,
            message: e.to_string(),
        })?;
        Ok(TlsListener {
            inner: Arc::new(listener),
            acceptor: TlsAcceptor::from(self.server.clone()),
            closed: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl Carrier for TlsCarrier {
    fn type_id(&self) -> CarrierTypeId {
        CarrierTypeId(CARRIER_TYPE.into())
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
        Ok(Box::new(self.bind(&bind)?))
    }

    fn dial(&self, remote: String) -> Result<BoxLink, CarrierError> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "dial"))?;
        let connector = TlsConnector::from(self.client.clone());
        let stream = rt.block_on(async move {
            let tcp = TcpStream::connect(&remote)
                .await
                .map_err(|e| CarrierError {
                    kind: CarrierErrorKind::Unreachable,
                    operation: "dial",
                    retryable: true,
                    message: e.to_string(),
                })?;
            let server_name =
                ServerName::try_from(self.server_name.clone()).map_err(|e| CarrierError {
                    kind: CarrierErrorKind::AddressInvalid,
                    operation: "dial",
                    retryable: false,
                    message: e.to_string(),
                })?;
            connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| CarrierError {
                    kind: CarrierErrorKind::AuthenticationFailed,
                    operation: "tls-handshake",
                    retryable: false,
                    message: e.to_string(),
                })
        })?;
        Ok(Box::new(TlsLink::new(TlsStream::Client(stream))))
    }
}

pub struct TlsListener {
    inner: Arc<std::net::TcpListener>,
    acceptor: TlsAcceptor,
    closed: Arc<AtomicBool>,
}

impl std::fmt::Debug for TlsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsListener").finish_non_exhaustive()
    }
}

impl TlsListener {
    /// Returns the bound socket address.
    ///
    /// # Errors
    ///
    /// Returns the operating-system address query error.
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
}

impl Listener for TlsListener {
    fn accept(&self) -> Result<BoxLink, CarrierError> {
        if self.closed.load(AtomicOrdering::Acquire) {
            return Err(CarrierError::new(CarrierErrorKind::NotRunning, "accept"));
        }
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "accept"))?;
        let (stream, _) = loop {
            if self.closed.load(AtomicOrdering::Acquire) {
                return Err(CarrierError::new(CarrierErrorKind::NotRunning, "accept"));
            }
            match self.inner.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => {
                    return Err(CarrierError {
                        kind: CarrierErrorKind::Internal,
                        operation: "accept",
                        retryable: true,
                        message: error.to_string(),
                    });
                }
            }
        };
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
        let stream = rt
            .block_on(self.acceptor.accept(stream))
            .map_err(|e| CarrierError {
                kind: CarrierErrorKind::AuthenticationFailed,
                operation: "tls-accept",
                retryable: true,
                message: e.to_string(),
            })?;
        Ok(Box::new(TlsLink::new(TlsStream::Server(stream))))
    }

    fn close(&self) -> Result<(), CarrierError> {
        self.closed.store(true, AtomicOrdering::Release);
        Ok(())
    }
}

enum TlsTransport {
    Client(tokio_rustls::client::TlsStream<TcpStream>),
    Server(tokio_rustls::server::TlsStream<TcpStream>),
}

impl std::fmt::Debug for TlsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TlsTransport").finish()
    }
}

impl TlsTransport {
    async fn read_exact(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.read_exact(bytes).await.map(|_| ()),
            Self::Server(stream) => stream.read_exact(bytes).await.map(|_| ()),
        }
    }

    async fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Client(stream) => stream.read(bytes).await,
            Self::Server(stream) => stream.read(bytes).await,
        }
    }

    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.write_all(bytes).await,
            Self::Server(stream) => stream.write_all(bytes).await,
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.flush().await,
            Self::Server(stream) => stream.flush().await,
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            Self::Client(stream) => stream.shutdown().await,
            Self::Server(stream) => stream.shutdown().await,
        }
    }
}

#[derive(Debug)]
pub struct TlsLink {
    stream: Arc<Mutex<(TlsTransport, Vec<u8>)>>,
    outbound: mpsc::Sender<OutboundPacket>,
    pending_bytes: Arc<AtomicUsize>,
}

impl TlsLink {
    fn new(stream: TlsStream<TcpStream>) -> Self {
        let transport = match stream {
            TlsStream::Client(stream) => TlsTransport::Client(stream),
            TlsStream::Server(stream) => TlsTransport::Server(stream),
        };
        let stream = Arc::new(Mutex::new((transport, Vec::new())));
        let pending_bytes = Arc::new(AtomicUsize::new(0));
        let (tx, mut rx) = mpsc::channel::<OutboundPacket>(SEND_QUEUE_CAPACITY);
        let writer_stream = stream.clone();
        let writer_pending = pending_bytes.clone();
        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                let Ok(mut framed) =
                    umc_carrier::framing::frame_packet(&packet.bytes, MAX_PACKET_LEN)
                else {
                    writer_pending.fetch_sub(packet.bytes.len(), AtomicOrdering::Relaxed);
                    break;
                };
                let mut guard = writer_stream.lock().await;
                if guard.0.write_all(&framed).await.is_err() || guard.0.flush().await.is_err() {
                    writer_pending.fetch_sub(packet.bytes.len(), AtomicOrdering::Relaxed);
                    break;
                }
                framed.clear();
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

impl Link for TlsLink {
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
        if bytes > MAX_PACKET_LEN {
            return Err(CarrierError::new(CarrierErrorKind::PacketTooLarge, "send"));
        }
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
        let packet =
            rt.block_on(async move {
                let mut guard = stream.lock().await;
                let mut prefix = std::mem::take(&mut guard.1);
                loop {
                    match umc_carrier::framing::read_length(&prefix, MAX_PACKET_LEN) {
                        Ok(Some((length, used))) => {
                            let mut payload = vec![0u8; length];
                            guard.0.read_exact(&mut payload).await.map_err(|_| {
                                CarrierError::new(CarrierErrorKind::LinkFailed, "recv")
                            })?;
                            prefix.drain(..used);
                            return Ok(payload);
                        }
                        Ok(None) => {}
                        Err(_) => {
                            return Err(CarrierError::new(CarrierErrorKind::ProtocolError, "recv"));
                        }
                    }
                    let mut byte = [0u8; 1];
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(20),
                        guard.0.read(&mut byte),
                    )
                    .await
                    {
                        Err(_) => {
                            guard.1 = prefix;
                            return Err(CarrierError::new(CarrierErrorKind::WouldBlock, "recv"));
                        }
                        Ok(Ok(0)) => {
                            return Err(CarrierError::new(CarrierErrorKind::LinkClosed, "recv"))
                        }
                        Ok(Ok(_)) => prefix.push(byte[0]),
                        Ok(Err(_)) => {
                            return Err(CarrierError::new(CarrierErrorKind::LinkFailed, "recv"))
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
        // `Link::close` is called from the daemon's Tokio runtime thread.
        // Enter a blocking section before synchronously waiting on the async
        // shutdown; calling `Handle::block_on` directly from a runtime thread
        // panics and tears down the whole daemon (which made a TLS peer's
        // normal version-refusal path look like a carrier failure).
        tokio::task::block_in_place(|| {
            rt.block_on(async move {
                let mut guard = stream.lock().await;
                let _ = guard.0.shutdown().await;
            });
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_tls_stream_experimental_shape() {
        let carrier = TlsCarrier::new().unwrap();
        assert_eq!(carrier.type_id().0, CARRIER_TYPE);
        assert_eq!(carrier.capabilities().packet_mode, PacketMode::StreamFramed);
        assert_eq!(carrier.capabilities().maximum_packet_size, MAX_PACKET_LEN);
    }

    #[test]
    fn framing_rejects_oversize() {
        assert!(
            umc_carrier::framing::frame_packet(&vec![0u8; MAX_PACKET_LEN + 1], MAX_PACKET_LEN)
                .is_err()
        );
        assert_eq!(
            umc_carrier::framing::read_length(&[0], MAX_PACKET_LEN),
            Ok(Some((0, 1)))
        );
        assert!(umc_carrier::framing::read_length(&[0xff; 8], MAX_PACKET_LEN).is_err());
    }

    #[test]
    fn framing_uses_varint_boundaries() {
        for length in [0usize, 63, 64, 16_383, 16_384, MAX_PACKET_LEN] {
            let framed =
                umc_carrier::framing::frame_packet(&vec![0u8; length], MAX_PACKET_LEN).unwrap();
            let (decoded, used) = umc_carrier::framing::read_length(&framed, MAX_PACKET_LEN)
                .unwrap()
                .unwrap();
            assert_eq!(decoded, length);
            assert_eq!(&framed[used..], vec![0u8; length].as_slice());
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn listener_close_stops_accepting() {
        let carrier = TlsCarrier::new().unwrap();
        let listener = carrier.bind("127.0.0.1:0").unwrap();
        listener.close().expect("close");
        let Err(error) = listener.accept() else {
            panic!("closed listener accepted a link")
        };
        assert_eq!(error.kind, CarrierErrorKind::NotRunning);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tls_echo_round_trip() {
        let carrier = TlsCarrier::new().unwrap();
        let listener = tokio::task::block_in_place(|| carrier.bind("127.0.0.1:0")).unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::task::spawn_blocking(move || listener.accept());
        let client = tokio::task::spawn_blocking({
            let carrier = carrier.clone();
            move || carrier.dial(address.to_string())
        })
        .await
        .unwrap()
        .unwrap();
        let server = server.await.unwrap().unwrap();
        client
            .send(OutboundPacket {
                bytes: b"tls-payload".to_vec(),
                control: false,
                deadline_ms: None,
            })
            .unwrap();
        let received = tokio::task::spawn_blocking(move || server.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.bytes, b"tls-payload");
        // Closing from a Tokio task must not synchronously nest `block_on`
        // into the runtime (the daemon uses this path on handshake refusal).
        client.close("test close").expect("close link");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn provisioned_certificate_and_root_are_used_for_dial() {
        let certified = rcgen::generate_simple_self_signed(vec!["mesh.example".into()]).unwrap();
        let certificate = certified.cert.der().to_vec();
        let key = certified.signing_key.serialize_der();
        let server = TlsCarrier::from_der(
            certificate.clone(),
            key.clone(),
            vec![certificate.clone()],
            "mesh.example",
        )
        .unwrap();
        let client =
            TlsCarrier::from_der(certificate.clone(), key, vec![certificate], "mesh.example")
                .unwrap();
        let listener = tokio::task::block_in_place(|| server.bind("127.0.0.1:0")).unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::task::spawn_blocking(move || listener.accept());
        let client_link = tokio::task::spawn_blocking(move || client.dial(address.to_string()))
            .await
            .unwrap()
            .unwrap();
        let server_link = server_task.await.unwrap().unwrap();
        client_link
            .send(OutboundPacket {
                bytes: b"provisioned".to_vec(),
                control: false,
                deadline_ms: None,
            })
            .unwrap();
        let received = tokio::task::spawn_blocking(move || server_link.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.bytes, b"provisioned");
    }
}
