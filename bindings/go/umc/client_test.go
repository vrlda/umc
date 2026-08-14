package umc

import (
	"context"
	"io"
	"net"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	server, clientConn := net.Pipe()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		defer close(done)
		readFrame := func() ([]byte, error) {
			var prefix [4]byte
			if _, err := io.ReadFull(server, prefix[:]); err != nil {
				return nil, err
			}
			payload := make([]byte, uint32(prefix[3])|uint32(prefix[2])<<8|uint32(prefix[1])<<16|uint32(prefix[0])<<24)
			_, err := io.ReadFull(server, payload)
			return payload, err
		}
		if _, err := readFrame(); err != nil {
			done <- err
			return
		}
		version := appendVarint(nil, 1, 1)
		version = appendVarint(version, 2, 0)
		serverHello := appendMessage(nil, 1, version)
		serverHello = appendVarint(serverHello, 7, maxEnvelope)
		if err := writeTestFrame(server, encodeEnvelope(11, serverHello)); err != nil {
			done <- err
			return
		}
		request, err := readFrame()
		if err != nil {
			done <- err
			return
		}
		body, ok := fieldBytes(request, 12)
		if !ok {
			done <- io.ErrUnexpectedEOF
			return
		}
		id, _, ok := readVarintField(body, 1)
		if !ok {
			done <- io.ErrUnexpectedEOF
			return
		}
		status := appendVarint(nil, 1, 0)
		response := appendVarint(nil, 1, id)
		response = appendMessage(response, 2, status)
		response = appendBytes(response, 3, []byte("ok"))
		done <- writeTestFrame(server, encodeEnvelope(13, response))
	}()

	client, err := New(clientConn, "go-test")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.Request(context.Background(), "NodeAdmin", "GetStatus", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Payload) != "ok" {
		t.Fatalf("payload = %q", response.Payload)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func writeTestFrame(w io.Writer, payload []byte) error {
	prefix := []byte{byte(len(payload) >> 24), byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload))}
	if _, err := w.Write(prefix); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
