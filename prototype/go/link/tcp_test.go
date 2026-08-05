package link

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestTCPFrameRoundTrip(t *testing.T) {
	adapter := &TCP{}
	listener, err := adapter.Listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.(*tcpListener).Addr().String()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		message, err := conn.Receive(context.Background())
		if err == nil {
			err = conn.Send(context.Background(), message)
		}
		serverDone <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := adapter.Dial(ctx, PeerHint{Address: address})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Send(ctx, []byte("openmesh")); err != nil {
		t.Fatal(err)
	}
	reply, err := client.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(reply) != "openmesh" {
		t.Fatalf("reply = %q", reply)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestTCPReceiveHonorsCancellationWithoutDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := (&tcpConn{Conn: client}).Receive(ctx)
		done <- err
	}()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Receive error = %v, want context.Canceled", err)
	}
}
