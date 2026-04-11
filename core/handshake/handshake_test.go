package handshake

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
)

func TestHandshakerRoundTrip(t *testing.T) {
	t.Parallel()

	clientStatic, err := noise.DH25519.GenerateKeypair(bytes.NewReader(bytes.Repeat([]byte{0x11}, 64)))
	if err != nil {
		t.Fatalf("generate client keypair: %v", err)
	}
	serverStatic, err := noise.DH25519.GenerateKeypair(bytes.NewReader(bytes.Repeat([]byte{0x22}, 64)))
	if err != nil {
		t.Fatalf("generate server keypair: %v", err)
	}

	var nowMu sync.Mutex
	nowValue := time.Unix(1_710_000_000, 0)
	now := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return nowValue
	}

	clientHandshaker := &Handshaker{
		StaticPrivateKey: clientStatic.Private,
		ProbeToken:       bytes.Repeat([]byte{0xAB}, probeTokenLength),
		Random:           bytes.NewReader(bytes.Repeat([]byte{0x33}, 512)),
		Now:              now,
		RekeyInterval:    time.Minute,
	}
	serverHandshaker := &Handshaker{
		ProbeValidator: func(token []byte) bool {
			return bytes.Equal(token, bytes.Repeat([]byte{0xAB}, probeTokenLength))
		},
		Random:        bytes.NewReader(bytes.Repeat([]byte{0x44}, 512)),
		Now:           now,
		RekeyInterval: time.Minute,
	}

	clientConn, serverConn := newMemoryConnPair()

	serverResult := make(chan struct {
		session Session
		err     error
	}, 1)
	go func() {
		session, err := serverHandshaker.Accept(serverConn, serverStatic.Private)
		serverResult <- struct {
			session Session
			err     error
		}{session: session, err: err}
	}()

	clientSession, err := clientHandshaker.Initiate(clientConn, serverStatic.Public)
	if err != nil {
		t.Fatalf("client initiate: %v", err)
	}

	serverHandshake := <-serverResult
	if serverHandshake.err != nil {
		t.Fatalf("server accept: %v", serverHandshake.err)
	}
	serverSession := serverHandshake.session

	if !bytes.Equal(clientSession.PeerStatic(), serverStatic.Public) {
		t.Fatalf("client peer static mismatch")
	}
	if !bytes.Equal(serverSession.PeerStatic(), clientStatic.Public) {
		t.Fatalf("server peer static mismatch")
	}

	clientCiphertext := clientSession.Encrypt([]byte("hello from client"))
	if clientCiphertext == nil {
		t.Fatalf("client encrypt returned nil")
	}
	serverPlaintext, err := serverSession.Decrypt(clientCiphertext)
	if err != nil {
		t.Fatalf("server decrypt: %v", err)
	}
	if string(serverPlaintext) != "hello from client" {
		t.Fatalf("unexpected server plaintext: got %q", serverPlaintext)
	}

	serverCiphertext := serverSession.Encrypt([]byte("hello from server"))
	if serverCiphertext == nil {
		t.Fatalf("server encrypt returned nil")
	}
	clientPlaintext, err := clientSession.Decrypt(serverCiphertext)
	if err != nil {
		t.Fatalf("client decrypt: %v", err)
	}
	if string(clientPlaintext) != "hello from server" {
		t.Fatalf("unexpected client plaintext: got %q", clientPlaintext)
	}

	nowMu.Lock()
	nowValue = nowValue.Add(2 * time.Minute)
	nowMu.Unlock()

	rekeyedClientCiphertext := clientSession.Encrypt([]byte("after rekey"))
	if rekeyedClientCiphertext == nil {
		t.Fatalf("rekeyed client encrypt returned nil")
	}
	rekeyedServerPlaintext, err := serverSession.Decrypt(rekeyedClientCiphertext)
	if err != nil {
		t.Fatalf("server decrypt after rekey: %v", err)
	}
	if string(rekeyedServerPlaintext) != "after rekey" {
		t.Fatalf("unexpected post-rekey plaintext: got %q", rekeyedServerPlaintext)
	}
}

func TestWrapInitialMessageObfuscatesStaticBytes(t *testing.T) {
	t.Parallel()

	h := &Handshaker{
		ProbeToken: bytes.Repeat([]byte{0xBC}, probeTokenLength),
		Prologue:   []byte("custom-prologue"),
		Random:     bytes.NewReader(bytes.Repeat([]byte{0x55}, 128)),
	}

	noiseMessage := []byte("noise-handshake-message")
	packet, err := h.wrapInitialMessage(noiseMessage)
	if err != nil {
		t.Fatalf("wrapInitialMessage: %v", err)
	}
	if len(packet) <= randomPaddingLength+probeTokenLength {
		t.Fatalf("packet too short")
	}
	if bytes.Contains(packet, h.Prologue) {
		t.Fatalf("packet leaked prologue bytes")
	}
	if bytes.Contains(packet, noiseMessage) {
		t.Fatalf("packet leaked raw handshake bytes")
	}

	unwrapped, token, err := h.unwrapInitialMessage(packet)
	if err != nil {
		t.Fatalf("unwrapInitialMessage: %v", err)
	}
	if !bytes.Equal(token, h.ProbeToken) {
		t.Fatalf("unexpected token")
	}
	if !bytes.Equal(unwrapped, noiseMessage) {
		t.Fatalf("unexpected unwrapped payload: got %q want %q", unwrapped, noiseMessage)
	}
}

type memoryConn struct {
	send chan []byte
	recv chan []byte
}

func newMemoryConnPair() (*memoryConn, *memoryConn) {
	leftToRight := make(chan []byte, 8)
	rightToLeft := make(chan []byte, 8)
	return &memoryConn{
			send: leftToRight,
			recv: rightToLeft,
		}, &memoryConn{
			send: rightToLeft,
			recv: leftToRight,
		}
}

func (c *memoryConn) Send(payload []byte) error {
	c.send <- append([]byte(nil), payload...)
	return nil
}

func (c *memoryConn) Recv() ([]byte, error) {
	payload := <-c.recv
	return append([]byte(nil), payload...), nil
}

func (c *memoryConn) Close() error {
	return nil
}
