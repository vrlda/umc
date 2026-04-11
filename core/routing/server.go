package routing

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/openmesh/core/handshake"
	"github.com/openmesh/core/transport"
)

// StreamDialContext connects the exit hop to a destination stream.
type StreamDialContext func(context.Context, string, int) (net.Conn, error)
type PacketDialContext func(context.Context, string, int) (*packetSession, error)

// HopServer terminates a single hop in a circuit and can relay to the next hop or act as the exit.
type HopServer struct {
	Listener          transport.Listener
	Transport         transport.Transport
	Handshaker        *handshake.Handshaker
	PrivateKey        []byte
	StreamDialContext StreamDialContext
	PacketDialContext PacketDialContext
	ProbeTimeout      time.Duration
}

// Serve accepts circuits until the context is canceled.
func (s *HopServer) Serve(ctx context.Context) error {
	if s.Listener == nil {
		return errNoTransport
	}
	if len(s.PrivateKey) == 0 {
		return errNoPrivateKey
	}

	for {
		conn, err := s.Listener.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		go s.handleConn(conn)
	}
}

func (s *HopServer) handleConn(conn transport.Conn) {
	defer conn.Close()

	handshaker := s.serverHandshaker()
	session, err := handshaker.Accept(conn, s.PrivateKey)
	if err != nil {
		return
	}

	serverConn := &serverCircuit{
		server:   s,
		conn:     conn,
		session:  session,
		streams:  make(map[uint32]net.Conn),
		packets:  make(map[uint32]*packetSession),
		closedCh: make(chan struct{}),
	}
	serverConn.serve()
}

func (s *HopServer) serverHandshaker() *handshake.Handshaker {
	if s.Handshaker == nil {
		return &handshake.Handshaker{}
	}
	clone := *s.Handshaker
	return &clone
}

type serverCircuit struct {
	server  *HopServer
	conn    transport.Conn
	session handshake.Session

	sendMu sync.Mutex

	mu        sync.Mutex
	circuitID [circuitIDSize]byte
	haveID    bool
	childConn transport.Conn
	streams   map[uint32]net.Conn
	packets   map[uint32]*packetSession
	closed    bool
	closedCh  chan struct{}
}

func (c *serverCircuit) serve() {
	defer c.close()

	for {
		payload, err := c.conn.Recv()
		if err != nil {
			return
		}

		packet, ok := decodeOnionPacket(payload)
		if !ok {
			return
		}

		c.mu.Lock()
		if !c.haveID {
			c.circuitID = packet.CircuitID
			c.haveID = true
		} else if c.circuitID != packet.CircuitID {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		plain, err := c.session.Decrypt(packet.Payload)
		if err != nil {
			return
		}

		message, err := decodeProtocolMessage(plain)
		if err != nil {
			return
		}

		switch message.Type {
		case msgTypeExtend:
			c.handleExtend(message)
		case msgTypeTunnelData:
			c.handleTunnelData(message)
		case msgTypeTunnelClose:
			c.handleTunnelClose()
		case msgTypeConnect:
			c.handleConnect(message)
		case msgTypeStreamData:
			c.handleStreamData(message)
		case msgTypeStreamClose:
			c.handleStreamClose(message)
		case msgTypeUDPAssociate:
			c.handleUDPAssociate(message)
		case msgTypeUDPData:
			c.handleUDPData(message)
		case msgTypeUDPClose:
			c.handleUDPClose(message)
		case msgTypeKeepalivePing:
			_ = c.send(protocolMessage{Type: msgTypeKeepalivePong, RequestID: message.RequestID})
		}
	}
}

func (c *serverCircuit) handleExtend(message protocolMessage) {
	if c.server.Transport == nil {
		_ = c.send(protocolMessage{Type: msgTypeExtended, RequestID: message.RequestID, Error: errNoTransport.Error()})
		return
	}

	nextPubKey, err := base64.StdEncoding.DecodeString(message.NextPubKey)
	if err != nil || len(nextPubKey) == 0 {
		_ = c.send(protocolMessage{Type: msgTypeExtended, RequestID: message.RequestID, Error: errInvalidPeerPubKey.Error()})
		return
	}

	probeCtx, cancel := context.WithTimeout(context.Background(), c.server.probeTimeout())
	_, err = probePeerAddr(probeCtx, c.server.Transport, c.server.Handshaker, c.server.PrivateKey, message.NextID, message.NextAddr, nextPubKey)
	cancel()
	if err != nil {
		_ = c.send(errorResponse(msgTypeExtended, message.RequestID, err))
		return
	}

	childConn, err := c.server.Transport.Dial(message.NextAddr)
	if err != nil {
		_ = c.send(errorResponse(msgTypeExtended, message.RequestID, &PeerUnreachableError{
			PeerID: message.NextID,
			Addr:   message.NextAddr,
			Stage:  "connect",
			Cause:  err,
		}))
		return
	}

	c.mu.Lock()
	oldChild := c.childConn
	c.childConn = childConn
	c.mu.Unlock()
	if oldChild != nil {
		_ = oldChild.Close()
	}

	go c.forwardChild(childConn)
	_ = c.send(protocolMessage{Type: msgTypeExtended, RequestID: message.RequestID})
}

func (c *serverCircuit) handleTunnelData(message protocolMessage) {
	c.mu.Lock()
	childConn := c.childConn
	c.mu.Unlock()
	if childConn == nil {
		_ = c.send(protocolMessage{Type: msgTypeTunnelClose})
		return
	}
	_ = childConn.Send(message.Payload)
}

func (c *serverCircuit) handleTunnelClose() {
	c.mu.Lock()
	childConn := c.childConn
	c.childConn = nil
	c.mu.Unlock()
	if childConn != nil {
		_ = childConn.Close()
	}
}

func (c *serverCircuit) forwardChild(childConn transport.Conn) {
	for {
		payload, err := childConn.Recv()
		if err != nil {
			_ = c.send(protocolMessage{Type: msgTypeTunnelClose})
			return
		}
		if err := c.send(protocolMessage{Type: msgTypeTunnelData, Payload: payload}); err != nil {
			return
		}
	}
}

func (c *serverCircuit) handleConnect(message protocolMessage) {
	streamConn, err := c.streamDialContext()(context.Background(), message.Dst, message.Port)
	if err != nil {
		_ = c.send(protocolMessage{Type: msgTypeConnected, RequestID: message.RequestID, StreamID: message.StreamID, Error: err.Error()})
		return
	}

	c.mu.Lock()
	c.streams[message.StreamID] = streamConn
	c.mu.Unlock()

	go c.forwardStream(message.StreamID, streamConn)
	_ = c.send(protocolMessage{Type: msgTypeConnected, RequestID: message.RequestID, StreamID: message.StreamID})
}

func (c *serverCircuit) handleStreamData(message protocolMessage) {
	c.mu.Lock()
	streamConn := c.streams[message.StreamID]
	c.mu.Unlock()
	if streamConn == nil {
		return
	}
	_, _ = streamConn.Write(message.Payload)
}

func (c *serverCircuit) handleStreamClose(message protocolMessage) {
	c.mu.Lock()
	streamConn := c.streams[message.StreamID]
	delete(c.streams, message.StreamID)
	c.mu.Unlock()
	if streamConn != nil {
		_ = streamConn.Close()
	}
}

func (c *serverCircuit) handleUDPAssociate(message protocolMessage) {
	packetConn, err := c.packetDialContext()(context.Background(), message.Dst, message.Port)
	if err != nil {
		_ = c.send(protocolMessage{Type: msgTypeUDPAssociated, RequestID: message.RequestID, StreamID: message.StreamID, Error: err.Error()})
		return
	}

	c.mu.Lock()
	c.packets[message.StreamID] = packetConn
	c.mu.Unlock()

	go c.forwardPacket(message.StreamID, packetConn)
	_ = c.send(protocolMessage{Type: msgTypeUDPAssociated, RequestID: message.RequestID, StreamID: message.StreamID})
}

func (c *serverCircuit) handleUDPData(message protocolMessage) {
	c.mu.Lock()
	packetConn := c.packets[message.StreamID]
	c.mu.Unlock()
	if packetConn == nil {
		return
	}
	_ = packetConn.write(message.Payload)
}

func (c *serverCircuit) handleUDPClose(message protocolMessage) {
	c.mu.Lock()
	packetConn := c.packets[message.StreamID]
	delete(c.packets, message.StreamID)
	c.mu.Unlock()
	if packetConn != nil {
		_ = packetConn.close()
	}
}

func (c *serverCircuit) forwardStream(streamID uint32, streamConn net.Conn) {
	defer func() {
		c.mu.Lock()
		delete(c.streams, streamID)
		c.mu.Unlock()
		_ = streamConn.Close()
		_ = c.send(protocolMessage{Type: msgTypeStreamClose, StreamID: streamID})
	}()

	buffer := make([]byte, 32<<10)
	for {
		n, err := streamConn.Read(buffer)
		if n > 0 {
			if sendErr := c.send(protocolMessage{
				Type:     msgTypeStreamData,
				StreamID: streamID,
				Payload:  append([]byte(nil), buffer[:n]...),
			}); sendErr != nil {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			return
		}
	}
}

func (c *serverCircuit) forwardPacket(streamID uint32, packetConn *packetSession) {
	defer func() {
		c.mu.Lock()
		delete(c.packets, streamID)
		c.mu.Unlock()
		_ = packetConn.close()
		_ = c.send(protocolMessage{Type: msgTypeUDPClose, StreamID: streamID})
	}()

	buffer := make([]byte, 64<<10)
	for {
		n, _, err := packetConn.conn.ReadFrom(buffer)
		if n > 0 {
			if sendErr := c.send(protocolMessage{
				Type:     msgTypeUDPData,
				StreamID: streamID,
				Payload:  append([]byte(nil), buffer[:n]...),
			}); sendErr != nil {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			return
		}
	}
}

func (c *serverCircuit) send(message protocolMessage) error {
	plain, err := encodeProtocolMessage(message)
	if err != nil {
		return err
	}

	ciphertext := c.session.Encrypt(plain)
	if ciphertext == nil {
		return errors.New("routing: failed to encrypt server message")
	}

	c.mu.Lock()
	packet := onionPacket{
		HopCount:  1,
		CircuitID: c.circuitID,
		Payload:   ciphertext,
	}
	c.mu.Unlock()

	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	return c.conn.Send(encodeOnionPacket(packet))
}

func (c *serverCircuit) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	childConn := c.childConn
	c.childConn = nil
	streams := make([]net.Conn, 0, len(c.streams))
	for streamID, streamConn := range c.streams {
		delete(c.streams, streamID)
		streams = append(streams, streamConn)
	}
	packets := make([]*packetSession, 0, len(c.packets))
	for streamID, packetConn := range c.packets {
		delete(c.packets, streamID)
		packets = append(packets, packetConn)
	}
	c.mu.Unlock()

	if childConn != nil {
		_ = childConn.Close()
	}
	for _, streamConn := range streams {
		_ = streamConn.Close()
	}
	for _, packetConn := range packets {
		_ = packetConn.close()
	}
	close(c.closedCh)
}

func (c *serverCircuit) streamDialContext() StreamDialContext {
	if c.server.StreamDialContext != nil {
		return c.server.StreamDialContext
	}

	dialer := net.Dialer{}
	return func(ctx context.Context, dst string, port int) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(dst, strconv.Itoa(port)))
	}
}

func (c *serverCircuit) packetDialContext() PacketDialContext {
	if c.server.PacketDialContext != nil {
		return c.server.PacketDialContext
	}
	return func(context.Context, string, int) (*packetSession, error) {
		return nil, errRelayCannotExit
	}
}

func (s *HopServer) probeTimeout() time.Duration {
	if s.ProbeTimeout > 0 {
		return s.ProbeTimeout
	}
	return defaultProbeTimeout
}

func errorResponse(messageType, requestID string, err error) protocolMessage {
	response := protocolMessage{
		Type:      messageType,
		RequestID: requestID,
		Error:     err.Error(),
	}

	var peerErr *PeerUnreachableError
	if errors.As(err, &peerErr) {
		response.FailedPeerID = peerErr.PeerID
		response.FailedAddr = peerErr.Addr
		response.FailedStage = peerErr.Stage
	}
	return response
}
