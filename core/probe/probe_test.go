package probe

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTokenValidatorAcceptsCurrentWindow(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_712_000_000, 0).UTC()
	validator := TokenValidator{
		Now: func() time.Time { return now },
	}
	secret := []byte("0123456789abcdef0123456789abcdef")

	current := validator.GenerateToken(secret)
	if !validator.ValidateToken(current, secret) {
		t.Fatalf("expected current token to validate")
	}

	previous := validator.generateForBucket(secret, now.Unix()/3600-1)
	if !validator.ValidateToken(previous, secret) {
		t.Fatalf("expected previous-hour token to validate")
	}

	old := validator.generateForBucket(secret, now.Unix()/3600-2)
	if validator.ValidateToken(old, secret) {
		t.Fatalf("did not expect expired token to validate")
	}
}

func TestProbeGuardRoutesValidToken(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	validator := TokenValidator{
		Now: func() time.Time { return time.Unix(1_712_000_000, 0).UTC() },
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	guard, err := NewProbeGuard(listener, &DecoyServer{DataDir: t.TempDir()}, validator, secret)
	if err != nil {
		t.Fatalf("new guard: %v", err)
	}
	defer guard.Close()

	packet := make([]byte, 96)
	copy(packet[tokenOffset:tokenEnd], validator.GenerateToken(secret))
	copy(packet[tokenEnd:], []byte("noise-handshake"))

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if _, err := client.Write(packet); err != nil {
		t.Fatalf("client write: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	serverConn, err := AcceptContext(ctx, guard)
	if err != nil {
		t.Fatalf("guard accept: %v", err)
	}
	defer serverConn.Close()

	got := make([]byte, len(packet))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(got, packet) {
		t.Fatalf("accepted payload mismatch")
	}
}

func TestProbeGuardRoutesInvalidTokenToDecoy(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	validator := TokenValidator{
		Now: func() time.Time { return time.Unix(1_712_000_000, 0).UTC() },
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	guard, err := NewProbeGuard(listener, &DecoyServer{DataDir: t.TempDir()}, validator, secret)
	if err != nil {
		t.Fatalf("new guard: %v", err)
	}
	defer guard.Close()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	request := "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(client, request); err != nil {
		t.Fatalf("client write: %v", err)
	}

	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}

	if !strings.Contains(string(response), "200 OK") {
		t.Fatalf("expected 200 OK response, got %q", response)
	}
	if !strings.Contains(string(response), "This site is under construction.") {
		t.Fatalf("expected decoy body, got %q", response)
	}
}
