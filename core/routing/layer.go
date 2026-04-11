package routing

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"

	"github.com/openmesh/core/dht"
	"github.com/openmesh/core/handshake"
	"github.com/openmesh/core/transport"
)

type clientLayer struct {
	conn          transport.Conn
	session       handshake.Session
	hopCount      uint8
	circuitID     [circuitIDSize]byte
	unsolicitedCh chan protocolMessage

	sendMu    sync.Mutex
	pendingMu sync.Mutex
	pending   map[string]chan protocolMessage

	tunnelMu  sync.Mutex
	tunnelCh  chan []byte
	closedCh  chan struct{}
	closeOnce sync.Once

	errMu sync.Mutex
	err   error
}

func newClientLayer(conn transport.Conn, session handshake.Session, hopCount uint8, circuitID [circuitIDSize]byte) *clientLayer {
	layer := &clientLayer{
		conn:          conn,
		session:       session,
		hopCount:      hopCount,
		circuitID:     circuitID,
		unsolicitedCh: make(chan protocolMessage, 64),
		pending:       make(map[string]chan protocolMessage),
		closedCh:      make(chan struct{}),
	}
	go layer.readLoop()
	return layer
}

func (l *clientLayer) readLoop() {
	for {
		payload, err := l.conn.Recv()
		if err != nil {
			l.fail(err)
			return
		}

		packet, ok := decodeOnionPacket(payload)
		if !ok || packet.CircuitID != l.circuitID {
			l.fail(errUnexpectedPacket)
			return
		}

		plain, err := l.session.Decrypt(packet.Payload)
		if err != nil {
			l.fail(err)
			return
		}

		message, err := decodeProtocolMessage(plain)
		if err != nil {
			l.fail(err)
			return
		}

		switch message.Type {
		case msgTypeTunnelData:
			if !l.deliverTunnel(message.Payload) {
				l.fail(errNoTunnel)
				return
			}
		case msgTypeTunnelClose:
			l.closeTunnel()
		default:
			if l.deliverPending(message) {
				continue
			}
			select {
			case l.unsolicitedCh <- message:
			case <-l.closedCh:
				return
			}
		}
	}
}

func (l *clientLayer) sendMessage(message protocolMessage) error {
	select {
	case <-l.closedCh:
		return l.layerErr()
	default:
	}

	plain, err := encodeProtocolMessage(message)
	if err != nil {
		return err
	}

	ciphertext := l.session.Encrypt(plain)
	if ciphertext == nil {
		return errors.New("routing: failed to encrypt layer message")
	}

	packet := encodeOnionPacket(onionPacket{
		HopCount:  l.hopCount,
		CircuitID: l.circuitID,
		Payload:   ciphertext,
	})

	l.sendMu.Lock()
	defer l.sendMu.Unlock()
	return l.conn.Send(packet)
}

func (l *clientLayer) request(ctx context.Context, message protocolMessage, wantType string) (protocolMessage, error) {
	if message.RequestID == "" {
		requestID, err := newRequestID()
		if err != nil {
			return protocolMessage{}, err
		}
		message.RequestID = requestID
	}

	responseCh := make(chan protocolMessage, 1)
	l.pendingMu.Lock()
	l.pending[message.RequestID] = responseCh
	l.pendingMu.Unlock()

	if err := l.sendMessage(message); err != nil {
		l.pendingMu.Lock()
		delete(l.pending, message.RequestID)
		l.pendingMu.Unlock()
		return protocolMessage{}, err
	}

	select {
	case response, ok := <-responseCh:
		if !ok {
			return protocolMessage{}, l.layerErr()
		}
		if response.Type != wantType {
			return protocolMessage{}, errUnexpectedMessage
		}
		if response.Error != "" {
			return protocolMessage{}, routingErrorFromResponse(response)
		}
		return response, nil
	case <-ctx.Done():
		l.pendingMu.Lock()
		delete(l.pending, message.RequestID)
		l.pendingMu.Unlock()
		return protocolMessage{}, ctx.Err()
	case <-l.closedCh:
		return protocolMessage{}, l.layerErr()
	}
}

func (l *clientLayer) openTunnel(ctx context.Context, peer dht.PeerRecord) (transport.Conn, error) {
	nextAddr, err := peerAddress(peer)
	if err != nil {
		return nil, err
	}

	l.tunnelMu.Lock()
	if l.tunnelCh != nil {
		l.tunnelMu.Unlock()
		return nil, errTunnelActive
	}
	tunnelCh := make(chan []byte, 64)
	l.tunnelCh = tunnelCh
	l.tunnelMu.Unlock()

	if _, err := l.request(ctx, protocolMessage{
		Type:       msgTypeExtend,
		NextID:     peer.ID,
		NextAddr:   nextAddr,
		NextPubKey: peer.PubKey,
	}, msgTypeExtended); err != nil {
		l.tunnelMu.Lock()
		if l.tunnelCh == tunnelCh {
			close(tunnelCh)
			l.tunnelCh = nil
		}
		l.tunnelMu.Unlock()
		return nil, err
	}

	return &tunneledConn{parent: l, recvCh: tunnelCh}, nil
}

func (l *clientLayer) deliverPending(message protocolMessage) bool {
	if message.RequestID == "" {
		return false
	}

	l.pendingMu.Lock()
	responseCh, ok := l.pending[message.RequestID]
	if ok {
		delete(l.pending, message.RequestID)
	}
	l.pendingMu.Unlock()
	if !ok {
		return false
	}

	select {
	case responseCh <- message:
	default:
	}
	close(responseCh)
	return true
}

func (l *clientLayer) deliverTunnel(payload []byte) bool {
	l.tunnelMu.Lock()
	tunnelCh := l.tunnelCh
	l.tunnelMu.Unlock()
	if tunnelCh == nil {
		return false
	}

	select {
	case tunnelCh <- append([]byte(nil), payload...):
		return true
	case <-l.closedCh:
		return false
	}
}

func (l *clientLayer) closeTunnel() {
	l.tunnelMu.Lock()
	defer l.tunnelMu.Unlock()
	if l.tunnelCh == nil {
		return
	}
	close(l.tunnelCh)
	l.tunnelCh = nil
}

func (l *clientLayer) Close() error {
	l.fail(io.EOF)
	return nil
}

func (l *clientLayer) fail(err error) {
	l.closeOnce.Do(func() {
		if err == nil {
			err = io.EOF
		}

		l.errMu.Lock()
		l.err = err
		l.errMu.Unlock()

		_ = l.conn.Close()

		l.pendingMu.Lock()
		for requestID, responseCh := range l.pending {
			delete(l.pending, requestID)
			close(responseCh)
		}
		l.pendingMu.Unlock()

		l.closeTunnel()
		close(l.unsolicitedCh)
		close(l.closedCh)
	})
}

func (l *clientLayer) layerErr() error {
	l.errMu.Lock()
	defer l.errMu.Unlock()
	if l.err != nil {
		return l.err
	}
	return errCircuitClosed
}

type tunneledConn struct {
	parent    *clientLayer
	recvCh    <-chan []byte
	closeOnce sync.Once
}

func (c *tunneledConn) Send(payload []byte) error {
	return c.parent.sendMessage(protocolMessage{
		Type:    msgTypeTunnelData,
		Payload: append([]byte(nil), payload...),
	})
}

func (c *tunneledConn) Recv() ([]byte, error) {
	payload, ok := <-c.recvCh
	if !ok {
		return nil, io.EOF
	}
	return append([]byte(nil), payload...), nil
}

func (c *tunneledConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.parent.sendMessage(protocolMessage{Type: msgTypeTunnelClose})
		c.parent.closeTunnel()
	})
	return nil
}

func newRequestID() (string, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
