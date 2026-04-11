package routing

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/openmesh/core/dht"
	"github.com/openmesh/core/handshake"
	"github.com/openmesh/core/transport"
)

const defaultProbeTimeout = 5 * time.Second

var errPeerUnreachable = errors.New("routing: peer is unreachable")

// PeerUnreachableError reports that a specific peer did not answer a reachability probe.
type PeerUnreachableError struct {
	PeerID string
	Addr   string
	Stage  string
	RTT    time.Duration
	Cause  error
}

func (e *PeerUnreachableError) Error() string {
	if e == nil {
		return errPeerUnreachable.Error()
	}

	location := e.PeerID
	if location == "" {
		location = e.Addr
	}
	if location == "" {
		location = "unknown peer"
	}
	if e.Stage != "" && e.Cause != nil {
		return fmt.Sprintf("routing: peer %s is unreachable during %s: %v", location, e.Stage, e.Cause)
	}
	if e.Cause != nil {
		return fmt.Sprintf("routing: peer %s is unreachable: %v", location, e.Cause)
	}
	return fmt.Sprintf("routing: peer %s is unreachable", location)
}

func (e *PeerUnreachableError) Unwrap() error {
	if e == nil {
		return nil
	}
	if e.Cause != nil {
		return e.Cause
	}
	return errPeerUnreachable
}

func (e *PeerUnreachableError) Is(target error) bool {
	return target == errPeerUnreachable
}

func probePeer(ctx context.Context, tr transport.Transport, handshaker *handshake.Handshaker, localPrivateKey []byte, peer dht.PeerRecord) (time.Duration, error) {
	addr, err := peerAddress(peer)
	if err != nil {
		return 0, err
	}
	pubKey, err := peerPublicKey(peer)
	if err != nil {
		return 0, err
	}
	return probePeerAddr(ctx, tr, handshaker, localPrivateKey, peer.ID, addr, pubKey)
}

func probePeerAddr(ctx context.Context, tr transport.Transport, handshaker *handshake.Handshaker, localPrivateKey []byte, peerID, addr string, peerPubKey []byte) (time.Duration, error) {
	if tr == nil {
		return 0, errNoTransport
	}
	if len(localPrivateKey) == 0 {
		return 0, errNoPrivateKey
	}

	startedAt := time.Now()
	conn, err := tr.Dial(addr)
	if err != nil {
		return 0, &PeerUnreachableError{PeerID: peerID, Addr: addr, Stage: "dial", Cause: err}
	}
	defer conn.Close()

	session, err := runConnFunc(ctx, conn, func() (handshake.Session, error) {
		return initiatorHandshaker(handshaker, localPrivateKey).Initiate(conn, peerPubKey)
	})
	if err != nil {
		return 0, &PeerUnreachableError{PeerID: peerID, Addr: addr, Stage: "handshake", Cause: err}
	}

	circuitID, err := newProbeCircuitID()
	if err != nil {
		return 0, err
	}
	requestID, err := newRequestID()
	if err != nil {
		return 0, err
	}

	if err := sendProbeMessage(conn, session, circuitID, protocolMessage{
		Type:      msgTypeKeepalivePing,
		RequestID: requestID,
	}); err != nil {
		return 0, &PeerUnreachableError{PeerID: peerID, Addr: addr, Stage: "ping", Cause: err}
	}

	response, err := runConnFunc(ctx, conn, func() (protocolMessage, error) {
		return recvProbeMessage(conn, session, circuitID)
	})
	if err != nil {
		return 0, &PeerUnreachableError{PeerID: peerID, Addr: addr, Stage: "pong", Cause: err}
	}
	if response.Type != msgTypeKeepalivePong || response.RequestID != requestID {
		return 0, &PeerUnreachableError{PeerID: peerID, Addr: addr, Stage: "pong", Cause: errUnexpectedMessage}
	}
	if response.Error != "" {
		return 0, &PeerUnreachableError{PeerID: peerID, Addr: addr, Stage: "pong", Cause: errors.New(response.Error)}
	}

	return time.Since(startedAt), nil
}

func initiatorHandshaker(base *handshake.Handshaker, localPrivateKey []byte) *handshake.Handshaker {
	if base == nil {
		return &handshake.Handshaker{StaticPrivateKey: append([]byte(nil), localPrivateKey...)}
	}
	clone := *base
	clone.StaticPrivateKey = append([]byte(nil), localPrivateKey...)
	return &clone
}

func sendProbeMessage(conn transport.Conn, session handshake.Session, circuitID [circuitIDSize]byte, message protocolMessage) error {
	plain, err := encodeProtocolMessage(message)
	if err != nil {
		return err
	}

	ciphertext := session.Encrypt(plain)
	if ciphertext == nil {
		return errors.New("routing: failed to encrypt probe message")
	}

	return conn.Send(encodeOnionPacket(onionPacket{
		HopCount:  1,
		CircuitID: circuitID,
		Payload:   ciphertext,
	}))
}

func recvProbeMessage(conn transport.Conn, session handshake.Session, circuitID [circuitIDSize]byte) (protocolMessage, error) {
	payload, err := conn.Recv()
	if err != nil {
		return protocolMessage{}, err
	}

	packet, ok := decodeOnionPacket(payload)
	if !ok || packet.CircuitID != circuitID {
		return protocolMessage{}, errUnexpectedPacket
	}

	plain, err := session.Decrypt(packet.Payload)
	if err != nil {
		return protocolMessage{}, err
	}

	return decodeProtocolMessage(plain)
}

func newProbeCircuitID() ([circuitIDSize]byte, error) {
	var circuitID [circuitIDSize]byte
	if _, err := io.ReadFull(rand.Reader, circuitID[:]); err != nil {
		return [circuitIDSize]byte{}, err
	}
	return circuitID, nil
}

type connResult[T any] struct {
	value T
	err   error
}

func runConnFunc[T any](ctx context.Context, conn transport.Conn, fn func() (T, error)) (T, error) {
	resultCh := make(chan connResult[T], 1)
	go func() {
		value, err := fn()
		resultCh <- connResult[T]{value: value, err: err}
	}()

	select {
	case result := <-resultCh:
		return result.value, result.err
	case <-ctx.Done():
		_ = conn.Close()
		result := <-resultCh
		var zero T
		if ctxErr := ctx.Err(); ctxErr != nil {
			return zero, ctxErr
		}
		return result.value, result.err
	}
}
