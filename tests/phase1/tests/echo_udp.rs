//! Phase 1 success criterion: a datagram round-trips over the UDP carrier.
use std::sync::Arc;
use umc_carrier::types::OutboundPacket;
use umc_carrier::Link;
use umc_carrier_udp::UdpLink;

#[test]
fn datagram_echo_over_udp_carrier() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = rt.handle().enter();
    let server_socket = Arc::new(
        rt.block_on(tokio::net::UdpSocket::bind("127.0.0.1:0"))
            .unwrap(),
    );
    let server_addr = server_socket.local_addr().unwrap().to_string();
    let client_socket = Arc::new(
        rt.block_on(tokio::net::UdpSocket::bind("127.0.0.1:0"))
            .unwrap(),
    );
    let client = UdpLink::from_parts(client_socket, server_addr.clone());
    let server_link = UdpLink::from_parts(server_socket, client.socket_local_addr());

    client
        .send(OutboundPacket {
            bytes: b"ping".to_vec(),
            control: false,
            deadline_ms: None,
        })
        .unwrap();
    let inbound = server_link.recv().unwrap();
    assert_eq!(inbound.bytes, b"ping");
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
