package routing

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/openmesh/core/dht"
	"github.com/openmesh/core/handshake"
	"github.com/openmesh/core/transport"
)

func TestRelayNodeForwardsToExitNode(t *testing.T) {
	echoAddr, shutdownEcho := startEchoServer(t)
	defer shutdownEcho()

	routingTransport := &transport.TCPTransport{
		MinJitter: time.Nanosecond,
		MaxJitter: time.Nanosecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exitPeer, shutdownExit := startExitNode(t, ctx, routingTransport, dht.ExitPolicy{Ports: []int{mustPort(t, echoAddr)}}, nil, func(ctx context.Context, dst string, port int) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", echoAddr)
	})
	defer shutdownExit()

	relayPeer, shutdownRelay := startRelayNode(t, ctx, routingTransport)
	defer shutdownRelay()

	builder := newTestCircuitBuilder(t, routingTransport)
	circuit, err := builder.Build([]dht.PeerRecord{relayPeer, exitPeer}, 2)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer circuit.Close()

	stream, err := circuit.OpenStream("allowed.example", mustPort(t, echoAddr))
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stream.Close()

	payload := []byte("relay-path")
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, reply); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(reply) != string(payload) {
		t.Fatalf("unexpected reply: got %q want %q", reply, payload)
	}
}

func TestExitNodeConnectsAndEnforcesPolicy(t *testing.T) {
	echoAddr, shutdownEcho := startEchoServer(t)
	defer shutdownEcho()

	blocklistServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "0.0.0.0 blocked.example\n")
	}))
	defer blocklistServer.Close()

	routingTransport := &transport.TCPTransport{
		MinJitter: time.Nanosecond,
		MaxJitter: time.Nanosecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exitPeer, shutdownExit := startExitNode(t, ctx, routingTransport, dht.ExitPolicy{Ports: []int{mustPort(t, echoAddr)}}, &DomainBlocklist{
		SourceURL: blocklistServer.URL,
		Client:    blocklistServer.Client(),
	}, func(ctx context.Context, dst string, port int) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", echoAddr)
	})
	defer shutdownExit()

	builder := newTestCircuitBuilder(t, routingTransport)
	circuit, err := builder.Build([]dht.PeerRecord{exitPeer}, 1)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer circuit.Close()

	stream, err := circuit.OpenStream("allowed.example", mustPort(t, echoAddr))
	if err != nil {
		t.Fatalf("OpenStream allowed: %v", err)
	}

	payload := []byte("exit-only")
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, reply); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(reply) != string(payload) {
		t.Fatalf("unexpected reply: got %q want %q", reply, payload)
	}
	_ = stream.Close()

	if _, err := circuit.OpenStream("blocked.example", mustPort(t, echoAddr)); !errors.Is(err, errBlockedDestination) {
		t.Fatalf("expected blocked destination error, got %v", err)
	}

	if _, err := circuit.OpenStream("allowed.example", mustPort(t, echoAddr)+1); !errors.Is(err, errPortNotAllowed) {
		t.Fatalf("expected port not allowed error, got %v", err)
	}
}

func TestRelayAndExitForwardUDPPackets(t *testing.T) {
	echoAddr, shutdownEcho := startUDPEchoServer(t)
	defer shutdownEcho()

	routingTransport := &transport.TCPTransport{
		MinJitter: time.Nanosecond,
		MaxJitter: time.Nanosecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	exitPeer, shutdownExit := startExitNode(t, ctx, routingTransport, dht.ExitPolicy{Ports: []int{mustPort(t, echoAddr)}}, nil, nil)
	defer shutdownExit()

	relayPeer, shutdownRelay := startRelayNode(t, ctx, routingTransport)
	defer shutdownRelay()

	builder := newTestCircuitBuilder(t, routingTransport)
	circuit, err := builder.Build([]dht.PeerRecord{relayPeer, exitPeer}, 2)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer circuit.Close()

	host, port := mustSplitHostPort(t, echoAddr)
	packetConn, err := circuit.OpenPacketConn(host, port)
	if err != nil {
		t.Fatalf("OpenPacketConn: %v", err)
	}
	defer packetConn.Close()

	payload := []byte("udp-through-openmesh")
	if _, err := packetConn.WriteTo(payload, &net.UDPAddr{IP: net.ParseIP(host), Port: port}); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	reply := make([]byte, len(payload))
	if err := packetConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, _, err := packetConn.ReadFrom(reply)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(reply[:n]) != string(payload) {
		t.Fatalf("unexpected udp reply: got %q want %q", reply[:n], payload)
	}
}

func startRelayNode(t *testing.T, ctx context.Context, routingTransport transport.Transport) (dht.PeerRecord, func()) {
	t.Helper()

	keypair, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair(relay): %v", err)
	}

	listener, err := routingTransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(relay): %v", err)
	}

	node := &RelayNode{
		Listener:   listener,
		Transport:  routingTransport,
		Handshaker: &handshake.Handshaker{},
		PrivateKey: keypair.Private,
	}

	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := node.Serve(ctx); err != nil {
			errCh <- err
		}
	}()

	record := dht.PeerRecord{
		ID:      dht.NodeIDFromPublicKey(keypair.Public),
		PubKey:  base64.StdEncoding.EncodeToString(keypair.Public),
		Addrs:   []string{listener.Addr().String()},
		Relay:   true,
		Exit:    false,
		Country: "US",
	}

	return record, func() {
		_ = listener.Close()
		wg.Wait()
		close(errCh)
		for err := range errCh {
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("RelayNode.Serve: %v", err)
			}
		}
	}
}

func startExitNode(t *testing.T, ctx context.Context, routingTransport transport.Transport, policy dht.ExitPolicy, blocklist *DomainBlocklist, dialer StreamDialContext) (dht.PeerRecord, func()) {
	t.Helper()

	keypair, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair(exit): %v", err)
	}

	listener, err := routingTransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(exit): %v", err)
	}

	node := &ExitNode{
		Listener:    listener,
		Handshaker:  &handshake.Handshaker{},
		PrivateKey:  keypair.Private,
		Policy:      policy,
		Blocklist:   blocklist,
		DialContext: dialer,
	}

	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := node.Serve(ctx); err != nil {
			errCh <- err
		}
	}()

	record := dht.PeerRecord{
		ID:      dht.NodeIDFromPublicKey(keypair.Public),
		PubKey:  base64.StdEncoding.EncodeToString(keypair.Public),
		Addrs:   []string{listener.Addr().String()},
		Relay:   true,
		Exit:    true,
		Country: "US",
	}

	return record, func() {
		_ = listener.Close()
		wg.Wait()
		close(errCh)
		for err := range errCh {
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("ExitNode.Serve: %v", err)
			}
		}
	}
}

func mustPort(t *testing.T, addr string) int {
	t.Helper()

	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portText, err)
	}
	return port
}

func startUDPEchoServer(t *testing.T) (string, func()) {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 64<<10)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, addr, err := conn.ReadFrom(buffer)
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				return
			}
			_, _ = conn.WriteTo(buffer[:n], addr)
		}
	}()

	return conn.LocalAddr().String(), func() {
		cancel()
		_ = conn.Close()
		<-done
	}
}
