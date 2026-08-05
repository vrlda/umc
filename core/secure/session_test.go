package secure

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/openmesh/core/identity"
	"github.com/openmesh/core/link"
)

func TestMutuallyAuthenticatedSession(t *testing.T) {
	clientIdentity, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	serverIdentity, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}

	clientNet, serverNet := net.Pipe()
	clientConn := framedPipe{Conn: clientNet}
	serverConn := framedPipe{Conn: serverNet}

	serverResult := make(chan *Session, 1)
	serverError := make(chan error, 1)
	go func() {
		session, err := Accept(context.Background(), serverConn, serverIdentity)
		serverResult <- session
		serverError <- err
	}()

	clientSession, err := Initiate(context.Background(), clientConn, clientIdentity, serverIdentity.ID())
	if err != nil {
		t.Fatal(err)
	}
	serverSession := <-serverResult
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
	if clientSession.Peer() != serverIdentity.ID() || serverSession.Peer() != clientIdentity.ID() {
		t.Fatal("peer identities were not authenticated")
	}

	ciphertext, err := clientSession.Encrypt([]byte("opaque payload"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := serverSession.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "opaque payload" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

// framedPipe adapts net.Pipe to link.Conn for a package-level handshake test.
type framedPipe struct{ net.Conn }

func (c framedPipe) Send(ctx context.Context, payload []byte) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetWriteDeadline(deadline)
	}
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(payload)))
	if err := writePipe(c.Conn, header); err != nil {
		return err
	}
	return writePipe(c.Conn, payload)
}

func (c framedPipe) Receive(ctx context.Context) ([]byte, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetReadDeadline(deadline)
	} else {
		_ = c.SetReadDeadline(time.Time{})
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header))
	payload := make([]byte, length)
	_, err := io.ReadFull(c.Conn, payload)
	return payload, err
}

func writePipe(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[written:]
	}
	return nil
}

var _ link.Conn = framedPipe{}
