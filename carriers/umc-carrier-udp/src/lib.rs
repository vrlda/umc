//! UDP carrier profile (carriers/udp.md): one datagram = one UMP packet.
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use umc_carrier::error::{CarrierError, CarrierErrorKind};
use umc_carrier::types::{
    CarrierCapabilities, CarrierTypeId, ConnectionModel, InboundPacket, LinkEvent, LinkProperties,
    Ordering, OutboundPacket, PacketMode, QueueState, Reliability, SendResult,
};
use umc_carrier::{BoxLink, Carrier, Link, Listener};
use umc_types::runtime::Instant;

pub const CARRIER_TYPE: &str = "ump.udp/1";
pub const INITIAL_MTU: usize = 1_200;
pub const MAX_QUEUED_DATAGRAMS: usize = 256;
pub const MAX_QUEUED_BYTES: usize = 2 * 1024 * 1024;
const RECV_WAIT: std::time::Duration = std::time::Duration::from_millis(100);

#[derive(Debug)]
pub struct UdpCarrier;

impl Carrier for UdpCarrier {
    fn type_id(&self) -> CarrierTypeId {
        CarrierTypeId(CARRIER_TYPE.to_string())
    }

    fn capabilities(&self) -> CarrierCapabilities {
        CarrierCapabilities {
            api_version: 1,
            carrier_type: self.type_id(),
            packet_mode: PacketMode::Datagram,
            reliability: Reliability::Unreliable,
            ordering: Ordering::Unordered,
            connection_model: ConnectionModel::ConnectionlessAssociation,
            supports_listen: true,
            supports_dial: true,
            supports_discovery: false,
            minimum_packet_size: 1,
            maximum_packet_size: INITIAL_MTU,
            scope_classes: vec!["general_network".into()],
        }
    }

    fn listen(&self, bind: String) -> Result<Box<dyn Listener + Send + Sync>, CarrierError> {
        let _runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "listen"))?;
        // The carrier trait is synchronous. Bind with the standard library
        // so callers can invoke this from an async context without nesting
        // `Handle::block_on`; the Tokio view is only used for address queries
        // and compatibility with the Link trait's test constructors.
        let std_socket = std::net::UdpSocket::bind(&bind).map_err(|e| CarrierError {
            kind: CarrierErrorKind::AddressInUse,
            operation: "listen",
            retryable: false,
            message: e.to_string(),
        })?;
        std_socket.set_nonblocking(true).map_err(|e| CarrierError {
            kind: CarrierErrorKind::Internal,
            operation: "listen",
            retryable: false,
            message: e.to_string(),
        })?;
        let std_socket = Arc::new(std_socket);
        let socket = UdpSocket::from_std(std_socket.try_clone().map_err(|e| CarrierError {
            kind: CarrierErrorKind::Internal,
            operation: "listen",
            retryable: false,
            message: e.to_string(),
        })?)
        .map_err(|e| CarrierError {
            kind: CarrierErrorKind::Internal,
            operation: "listen",
            retryable: false,
            message: e.to_string(),
        })?;
        Ok(Box::new(UdpListenerAdapter {
            socket: Arc::new(socket),
            std_socket,
            closed: Arc::new(AtomicBool::new(false)),
        }))
    }

    fn dial(&self, remote: String) -> Result<BoxLink, CarrierError> {
        let _runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "dial"))?;
        // `Carrier::dial` is synchronous; use a nonblocking std socket so it
        // can be called by async node/control paths without nested
        // `Handle::block_on` panics.
        let _remote_addr: std::net::SocketAddr = remote
            .parse()
            .map_err(|_| CarrierError::new(CarrierErrorKind::AddressInvalid, "dial"))?;
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| CarrierError {
            kind: CarrierErrorKind::Internal,
            operation: "dial",
            retryable: true,
            message: e.to_string(),
        })?;
        socket.set_nonblocking(true).map_err(|e| CarrierError {
            kind: CarrierErrorKind::Internal,
            operation: "dial",
            retryable: false,
            message: e.to_string(),
        })?;
        let std_socket = Arc::new(socket);
        let socket = UdpSocket::from_std(std_socket.try_clone().map_err(|e| CarrierError {
            kind: CarrierErrorKind::Internal,
            operation: "dial",
            retryable: false,
            message: e.to_string(),
        })?)
        .map_err(|e| CarrierError {
            kind: CarrierErrorKind::Internal,
            operation: "dial",
            retryable: false,
            message: e.to_string(),
        })?;
        Ok(Box::new(UdpLink {
            socket: Arc::new(socket),
            std_socket: Some(std_socket),
            remote: remote.clone(),
        }))
    }
}

#[derive(Debug)]
pub struct UdpListenerAdapter {
    socket: Arc<UdpSocket>,
    std_socket: Arc<std::net::UdpSocket>,
    closed: Arc<AtomicBool>,
}

impl Listener for UdpListenerAdapter {
    fn accept(&self) -> Result<BoxLink, CarrierError> {
        if self.closed.load(AtomicOrdering::Acquire) {
            return Err(CarrierError::new(CarrierErrorKind::NotRunning, "accept"));
        }
        // Connectionless: first datagram establishes the association.
        // Peek instead of receiving so the first handshake datagram remains
        // available to the session reader after the association is returned.
        let mut buf = [0u8; INITIAL_MTU];
        let (_n, addr) = self.std_socket.peek_from(&mut buf).map_err(|error| {
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
        let remote = addr.to_string();
        Ok(Box::new(UdpLink {
            socket: self.socket.clone(),
            std_socket: Some(self.std_socket.clone()),
            remote,
        }))
    }

    fn close(&self) -> Result<(), CarrierError> {
        self.closed.store(true, AtomicOrdering::Release);
        Ok(())
    }
}

#[derive(Debug)]
pub struct UdpLink {
    socket: Arc<UdpSocket>,
    std_socket: Option<Arc<std::net::UdpSocket>>,
    remote: String,
}

impl UdpLink {
    #[must_use]
    pub fn remote(&self) -> &str {
        &self.remote
    }

    #[must_use]
    pub fn socket_local_addr(&self) -> String {
        self.socket
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn from_parts(socket: Arc<UdpSocket>, remote: String) -> Self {
        Self {
            socket,
            std_socket: None,
            remote,
        }
    }
}

impl Link for UdpLink {
    fn properties(&self) -> LinkProperties {
        LinkProperties {
            reliability: Reliability::Unreliable,
            ordering: Ordering::Unordered,
            current_mtu: INITIAL_MTU,
            queue_bytes: 0,
            queue_capacity: MAX_QUEUED_BYTES,
            estimated_rtt_ms: None,
            estimated_loss: None,
            metered: false,
        }
    }

    fn send(&self, packet: OutboundPacket) -> Result<SendResult, CarrierError> {
        if packet.bytes.len() > INITIAL_MTU {
            return Err(CarrierError::new(CarrierErrorKind::PacketTooLarge, "send"));
        }
        let socket = self.socket.clone();
        let remote = self.remote.clone();
        let remote_addr = remote
            .parse()
            .map_err(|_| CarrierError::new(CarrierErrorKind::AddressInvalid, "send"))?;
        let packet_len = packet.bytes.len();
        let bytes = packet.bytes;
        let n = if let Some(std_socket) = &self.std_socket {
            std_socket.send_to(&bytes, remote_addr)
        } else if let Ok(handle) = tokio::runtime::Handle::try_current() {
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                tokio::task::block_in_place(|| handle.block_on(socket.send_to(&bytes, remote_addr)))
            } else {
                socket.try_send_to(&bytes, remote_addr)
            }
        } else {
            return Err(CarrierError::new(CarrierErrorKind::NotRunning, "send"));
        }
        .map_err(|e| CarrierError {
            kind: CarrierErrorKind::Internal,
            operation: "send",
            retryable: true,
            message: e.to_string(),
        })?;
        if n != packet_len {
            return Err(CarrierError::new(CarrierErrorKind::Internal, "send"));
        }
        Ok(SendResult::Accepted {
            queue_state: QueueState::SentToMedium,
        })
    }

    fn recv(&self) -> Result<InboundPacket, CarrierError> {
        let socket = self.socket.clone();
        let remote = self.remote.clone();
        let remote_addr = remote
            .parse()
            .map_err(|_| CarrierError::new(CarrierErrorKind::AddressInvalid, "recv"))?;
        let mut buf = [0u8; INITIAL_MTU];
        if self.std_socket.is_none() && tokio::runtime::Handle::try_current().is_err() {
            return Err(CarrierError::new(CarrierErrorKind::NotRunning, "recv"));
        }
        let deadline = std::time::Instant::now() + RECV_WAIT;
        loop {
            let result = if let Some(std_socket) = &self.std_socket {
                std_socket.recv_from(&mut buf)
            } else {
                socket.try_recv_from(&mut buf)
            };
            match result {
                Ok((n, addr)) if addr == remote_addr => {
                    return Ok(InboundPacket {
                        bytes: buf[..n].to_vec(),
                        received_at: Instant(0),
                    });
                }
                Ok(_) => return Err(CarrierError::new(CarrierErrorKind::WouldBlock, "recv")),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Err(CarrierError::new(CarrierErrorKind::WouldBlock, "recv"));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => {
                    return Err(CarrierError {
                        kind: CarrierErrorKind::Internal,
                        operation: "recv",
                        retryable: true,
                        message: error.to_string(),
                    });
                }
            }
        }
    }

    fn events(&self) -> Result<LinkEvent, CarrierError> {
        Err(CarrierError::new(CarrierErrorKind::WouldBlock, "events"))
    }

    fn close(&self, _reason: &str) -> Result<(), CarrierError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_match_profile() {
        let c = UdpCarrier;
        assert_eq!(c.type_id().0, "ump.udp/1");
        assert_eq!(c.capabilities().packet_mode, PacketMode::Datagram);
        assert_eq!(c.capabilities().maximum_packet_size, 1_200);
    }

    #[test]
    fn datagram_round_trip_between_two_links() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.handle().enter();
        let server_socket = Arc::new(rt.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap());
        let server_addr = server_socket.local_addr().unwrap().to_string();
        let client_socket = Arc::new(rt.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap());
        let client_addr = client_socket.local_addr().unwrap().to_string();
        let client = UdpLink {
            socket: client_socket,
            std_socket: None,
            remote: server_addr.clone(),
        };
        let server_link = UdpLink {
            socket: server_socket.clone(),
            std_socket: None,
            remote: client_addr,
        };

        client
            .send(OutboundPacket {
                bytes: b"ping".to_vec(),
                control: false,
                deadline_ms: None,
            })
            .unwrap();
        let pkt = server_link.recv().unwrap();
        assert_eq!(pkt.bytes, b"ping");

        server_link
            .send(OutboundPacket {
                bytes: b"pong".to_vec(),
                control: false,
                deadline_ms: None,
            })
            .unwrap();
        let reply = client.recv().unwrap();
        assert_eq!(reply.bytes, b"pong");
    }

    #[test]
    fn dial_is_safe_from_an_async_runtime_context() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = server.local_addr().unwrap();
            let link = UdpCarrier.dial(address.to_string()).expect("dial");
            link.send(OutboundPacket {
                bytes: b"ping".to_vec(),
                control: false,
                deadline_ms: None,
            })
            .expect("send");
            let mut buffer = [0u8; 16];
            let (size, _) = server.recv_from(&mut buffer).await.expect("receive");
            assert_eq!(&buffer[..size], b"ping");
        });
    }

    #[test]
    fn listener_peeks_without_consuming_first_datagram() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.handle().enter();
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let listener = UdpCarrier.listen(address.to_string()).unwrap();
        rt.block_on(async {
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            client.send_to(b"first", address).await.unwrap();
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let link = loop {
            match listener.accept() {
                Ok(link) => break link,
                Err(error)
                    if error.kind == CarrierErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => panic!("accept: {error:?}"),
            }
        };
        let packet = link.recv().expect("first datagram");
        assert_eq!(packet.bytes, b"first");
        listener.close().expect("close");
        let Err(error) = listener.accept() else {
            panic!("closed listener accepted a link")
        };
        assert_eq!(error.kind, CarrierErrorKind::NotRunning);
    }
}
