package handshake

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/openmesh/core/transport"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

const (
	randomPaddingLength  = 32
	probeTokenLength     = 32
	defaultPrologue      = "openmesh-noise-xx"
	defaultRekeyInterval = 10 * time.Minute
)

var (
	errMissingStaticKey      = errors.New("handshake: local static private key is required")
	errInvalidPrivateKey     = errors.New("handshake: private key must be 32 bytes")
	errInvalidPeerPublicKey  = errors.New("handshake: remote static key mismatch")
	errInvalidProbeToken     = errors.New("handshake: probe token must be exactly 32 bytes")
	errInitialPacketTooShort = errors.New("handshake: initial packet too short")
	errInvalidPrologue       = errors.New("handshake: invalid obfuscated prologue")
	errEncryptFailed         = errors.New("handshake: encrypt failed")
)

// Session encrypts and decrypts transport payloads after a successful handshake.
type Session struct {
	send *noise.CipherState
	recv *noise.CipherState

	peerStatic     []byte
	channelBinding []byte
	rekeyInterval  time.Duration
	now            func() time.Time

	mu        sync.Mutex
	lastRekey time.Time
}

// Encrypt encrypts payload for the remote peer.
func (s *Session) Encrypt(payload []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.maybeRekeyLocked()
	out, err := s.send.Encrypt(nil, nil, payload)
	if err != nil {
		return nil
	}
	return out
}

// Decrypt authenticates and decrypts payload from the remote peer.
func (s *Session) Decrypt(payload []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.maybeRekeyLocked()
	return s.recv.Decrypt(nil, nil, payload)
}

// Rekey rotates both directional cipher states.
func (s *Session) Rekey() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rekeyLocked()
}

// PeerStatic returns the remote node's static public key.
func (s *Session) PeerStatic() []byte {
	return append([]byte(nil), s.peerStatic...)
}

// ChannelBinding returns the final handshake hash for binding higher-level channels.
func (s *Session) ChannelBinding() []byte {
	return append([]byte(nil), s.channelBinding...)
}

func (s *Session) maybeRekeyLocked() {
	if s.rekeyInterval <= 0 {
		return
	}
	if s.now().Sub(s.lastRekey) < s.rekeyInterval {
		return
	}
	s.rekeyLocked()
}

func (s *Session) rekeyLocked() {
	s.send.Rekey()
	s.recv.Rekey()
	s.lastRekey = s.now()
}

// Handshaker performs the OpenMesh Noise_XX handshake with the spec's obfuscation layer.
type Handshaker struct {
	StaticPrivateKey []byte
	Prologue         []byte
	ProbeToken       []byte
	ProbeValidator   func([]byte) bool
	CipherSuite      noise.CipherSuite
	Random           io.Reader
	RekeyInterval    time.Duration
	Now              func() time.Time
}

// Initiate performs the initiator side of the obfuscated Noise_XX handshake.
func (h *Handshaker) Initiate(conn transport.Conn, serverPubkey []byte) (Session, error) {
	staticKey, err := dhKeyFromPrivate(h.StaticPrivateKey)
	if err != nil {
		return Session{}, err
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   h.cipherSuite(),
		Random:        h.randomSource(),
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		Prologue:      h.prologue(),
		StaticKeypair: staticKey,
	})
	if err != nil {
		return Session{}, err
	}

	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return Session{}, err
	}

	packet1, err := h.wrapInitialMessage(msg1)
	if err != nil {
		return Session{}, err
	}
	if err := conn.Send(packet1); err != nil {
		return Session{}, err
	}

	msg2, err := conn.Recv()
	if err != nil {
		return Session{}, err
	}

	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		return Session{}, err
	}
	if len(serverPubkey) > 0 && !bytes.Equal(hs.PeerStatic(), serverPubkey) {
		return Session{}, errInvalidPeerPublicKey
	}

	msg3, send, recv, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return Session{}, err
	}
	if err := conn.Send(msg3); err != nil {
		return Session{}, err
	}

	return h.newSession(true, send, recv, hs.PeerStatic(), hs.ChannelBinding()), nil
}

// Accept performs the responder side of the obfuscated Noise_XX handshake.
func (h *Handshaker) Accept(conn transport.Conn, privkey []byte) (Session, error) {
	staticKey, err := dhKeyFromPrivate(privkey)
	if err != nil {
		return Session{}, err
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   h.cipherSuite(),
		Random:        h.randomSource(),
		Pattern:       noise.HandshakeXX,
		Initiator:     false,
		Prologue:      h.prologue(),
		StaticKeypair: staticKey,
	})
	if err != nil {
		return Session{}, err
	}

	packet1, err := conn.Recv()
	if err != nil {
		return Session{}, err
	}

	msg1, token, err := h.unwrapInitialMessage(packet1)
	if err != nil {
		return Session{}, err
	}
	if h.ProbeValidator != nil && !h.ProbeValidator(token) {
		return Session{}, errInvalidProbeToken
	}

	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		return Session{}, err
	}

	msg2, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return Session{}, err
	}
	if err := conn.Send(msg2); err != nil {
		return Session{}, err
	}

	msg3, err := conn.Recv()
	if err != nil {
		return Session{}, err
	}

	if _, cs0, cs1, err := hs.ReadMessage(nil, msg3); err != nil {
		return Session{}, err
	} else {
		return h.newSession(false, cs0, cs1, hs.PeerStatic(), hs.ChannelBinding()), nil
	}
}

func (h *Handshaker) newSession(initiator bool, cs0, cs1 *noise.CipherState, peerStatic, channelBinding []byte) Session {
	now := h.timeNow()
	send, recv := cs0, cs1
	if !initiator {
		send, recv = cs1, cs0
	}
	return Session{
		send:           send,
		recv:           recv,
		peerStatic:     append([]byte(nil), peerStatic...),
		channelBinding: append([]byte(nil), channelBinding...),
		rekeyInterval:  h.rekeyInterval(),
		now:            now,
		lastRekey:      now(),
	}
}

func (h *Handshaker) wrapInitialMessage(msg []byte) ([]byte, error) {
	randomPadding := make([]byte, randomPaddingLength)
	if _, err := io.ReadFull(h.randomSource(), randomPadding); err != nil {
		return nil, err
	}

	token, err := h.probeToken()
	if err != nil {
		return nil, err
	}

	plain := append(append([]byte(nil), h.prologue()...), msg...)
	masked := xorWithBLAKE2sMask(plain, randomPadding)

	packet := make([]byte, randomPaddingLength+probeTokenLength+len(masked))
	copy(packet[:randomPaddingLength], randomPadding)
	copy(packet[randomPaddingLength:randomPaddingLength+probeTokenLength], token)
	copy(packet[randomPaddingLength+probeTokenLength:], masked)
	return packet, nil
}

func (h *Handshaker) unwrapInitialMessage(packet []byte) ([]byte, []byte, error) {
	prologue := h.prologue()
	if len(packet) < randomPaddingLength+probeTokenLength+len(prologue) {
		return nil, nil, errInitialPacketTooShort
	}

	randomPadding := append([]byte(nil), packet[:randomPaddingLength]...)
	token := append([]byte(nil), packet[randomPaddingLength:randomPaddingLength+probeTokenLength]...)
	masked := packet[randomPaddingLength+probeTokenLength:]

	plain := xorWithBLAKE2sMask(masked, randomPadding)
	if !bytes.HasPrefix(plain, prologue) {
		return nil, nil, errInvalidPrologue
	}
	return plain[len(prologue):], token, nil
}

func (h *Handshaker) cipherSuite() noise.CipherSuite {
	if h.CipherSuite != nil {
		return h.CipherSuite
	}
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
}

func (h *Handshaker) prologue() []byte {
	if len(h.Prologue) > 0 {
		return append([]byte(nil), h.Prologue...)
	}
	return []byte(defaultPrologue)
}

func (h *Handshaker) randomSource() io.Reader {
	if h.Random != nil {
		return h.Random
	}
	return rand.Reader
}

func (h *Handshaker) rekeyInterval() time.Duration {
	if h.RekeyInterval > 0 {
		return h.RekeyInterval
	}
	return defaultRekeyInterval
}

func (h *Handshaker) timeNow() func() time.Time {
	if h.Now != nil {
		return h.Now
	}
	return time.Now
}

func (h *Handshaker) probeToken() ([]byte, error) {
	if len(h.ProbeToken) == 0 {
		return make([]byte, probeTokenLength), nil
	}
	if len(h.ProbeToken) != probeTokenLength {
		return nil, errInvalidProbeToken
	}
	return append([]byte(nil), h.ProbeToken...), nil
}

func dhKeyFromPrivate(privateKey []byte) (noise.DHKey, error) {
	if len(privateKey) == 0 {
		return noise.DHKey{}, errMissingStaticKey
	}
	if len(privateKey) != 32 {
		return noise.DHKey{}, errInvalidPrivateKey
	}

	pubkey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return noise.DHKey{}, err
	}
	return noise.DHKey{
		Private: append([]byte(nil), privateKey...),
		Public:  pubkey,
	}, nil
}

func xorWithBLAKE2sMask(payload, randomPadding []byte) []byte {
	mask := blake2s.Sum256(randomPadding)
	out := make([]byte, len(payload))
	for i := range payload {
		out[i] = payload[i] ^ mask[i%len(mask)]
	}
	return out
}
