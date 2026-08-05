package secure

import (
	"context"
	"errors"
	"sync"

	"github.com/flynn/noise"
	"github.com/openmesh/core/identity"
	"github.com/openmesh/core/link"
)

var ErrPeerIdentityMismatch = errors.New("secure: peer identity mismatch")

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// Session encrypts application-independent payloads after a Noise XX handshake.
// Rekey coordination belongs to the future control plane; this type does not
// perform unsafe clock-based unilateral rekeying.
type Session struct {
	peer identity.ID
	send *noise.CipherState
	recv *noise.CipherState

	sendMu sync.Mutex
	recvMu sync.Mutex
}

func (s *Session) Peer() identity.ID { return s.peer }

func (s *Session) Encrypt(payload []byte) ([]byte, error) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.send.Encrypt(nil, nil, payload)
}

func (s *Session) Decrypt(payload []byte) ([]byte, error) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	return s.recv.Decrypt(nil, nil, payload)
}

func Initiate(ctx context.Context, conn link.Conn, local *identity.Identity, expected identity.ID) (*Session, error) {
	handshake, err := newHandshake(local, true)
	if err != nil {
		return nil, err
	}

	message1, _, _, err := handshake.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := conn.Send(ctx, message1); err != nil {
		return nil, err
	}
	message2, err := conn.Receive(ctx)
	if err != nil {
		return nil, err
	}
	if _, _, _, err := handshake.ReadMessage(nil, message2); err != nil {
		return nil, err
	}

	peer, err := identity.IDFromPublicKey(handshake.PeerStatic())
	if err != nil {
		return nil, err
	}
	if expected != (identity.ID{}) && peer != expected {
		return nil, ErrPeerIdentityMismatch
	}

	message3, send, recv, err := handshake.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := conn.Send(ctx, message3); err != nil {
		return nil, err
	}
	return &Session{peer: peer, send: send, recv: recv}, nil
}

func Accept(ctx context.Context, conn link.Conn, local *identity.Identity) (*Session, error) {
	handshake, err := newHandshake(local, false)
	if err != nil {
		return nil, err
	}

	message1, err := conn.Receive(ctx)
	if err != nil {
		return nil, err
	}
	if _, _, _, err := handshake.ReadMessage(nil, message1); err != nil {
		return nil, err
	}
	message2, _, _, err := handshake.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := conn.Send(ctx, message2); err != nil {
		return nil, err
	}
	message3, err := conn.Receive(ctx)
	if err != nil {
		return nil, err
	}
	if _, first, second, err := handshake.ReadMessage(nil, message3); err != nil {
		return nil, err
	} else {
		peer, err := identity.IDFromPublicKey(handshake.PeerStatic())
		if err != nil {
			return nil, err
		}
		return &Session{peer: peer, send: second, recv: first}, nil
	}
}

func newHandshake(local *identity.Identity, initiator bool) (*noise.HandshakeState, error) {
	if local == nil {
		return nil, errors.New("secure: local identity is required")
	}
	return noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite,
		Pattern:     noise.HandshakeXX,
		Initiator:   initiator,
		Prologue:    []byte("openmesh/core/0.1"),
		StaticKeypair: noise.DHKey{
			Private: local.PrivateKey(),
			Public:  local.PublicKey(),
		},
	})
}
