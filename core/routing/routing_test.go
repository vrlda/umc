package routing

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/openmesh/core/dht"
	"github.com/openmesh/core/handshake"
	"github.com/openmesh/core/transport"
)

func TestCircuitBuilderBuildsLoopbackCircuits(t *testing.T) {
	for _, hops := range []int{1, 2, 3} {
		t.Run(strconv.Itoa(hops)+"-hop", func(t *testing.T) {
			echoAddr, shutdownEcho := startEchoServer(t)
			defer shutdownEcho()

			routingTransport := &transport.TCPTransport{
				MinJitter: time.Nanosecond,
				MaxJitter: time.Nanosecond,
			}

			hopPeers, shutdownHops := startHopPath(t, routingTransport, 3)
			defer shutdownHops()

			builder := newTestCircuitBuilder(t, routingTransport)
			circuit, err := builder.Build(hopPeers[:hops], hops)
			if err != nil {
				t.Fatalf("Build(%d): %v", hops, err)
			}
			defer circuit.Close()

			host, port := mustSplitHostPort(t, echoAddr)
			stream, err := circuit.OpenStream(host, port)
			if err != nil {
				t.Fatalf("OpenStream(%d): %v", hops, err)
			}
			defer stream.Close()

			payload := []byte("hello over " + strconv.Itoa(hops) + " hops")
			if _, err := stream.Write(payload); err != nil {
				t.Fatalf("Write(%d): %v", hops, err)
			}

			reply := make([]byte, len(payload))
			if _, err := io.ReadFull(stream, reply); err != nil {
				t.Fatalf("ReadFull(%d): %v", hops, err)
			}
			if string(reply) != string(payload) {
				t.Fatalf("unexpected reply: got %q want %q", reply, payload)
			}
		})
	}
}

func TestCircuitMultiplexesStreams(t *testing.T) {
	echoAddr, shutdownEcho := startEchoServer(t)
	defer shutdownEcho()

	routingTransport := &transport.TCPTransport{
		MinJitter: time.Nanosecond,
		MaxJitter: time.Nanosecond,
	}

	hopPeers, shutdownHops := startHopPath(t, routingTransport, 2)
	defer shutdownHops()

	builder := newTestCircuitBuilder(t, routingTransport)
	circuit, err := builder.Build(hopPeers[:2], 2)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer circuit.Close()

	host, port := mustSplitHostPort(t, echoAddr)
	streamA, err := circuit.OpenStream(host, port)
	if err != nil {
		t.Fatalf("OpenStream A: %v", err)
	}
	defer streamA.Close()

	streamB, err := circuit.OpenStream(host, port)
	if err != nil {
		t.Fatalf("OpenStream B: %v", err)
	}
	defer streamB.Close()

	payloadA := []byte("stream-a")
	payloadB := []byte("stream-b")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := streamA.Write(payloadA); err != nil {
			t.Errorf("streamA Write: %v", err)
			return
		}

		reply := make([]byte, len(payloadA))
		if _, err := io.ReadFull(streamA, reply); err != nil {
			t.Errorf("streamA ReadFull: %v", err)
			return
		}
		if string(reply) != string(payloadA) {
			t.Errorf("streamA reply mismatch: got %q want %q", reply, payloadA)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := streamB.Write(payloadB); err != nil {
			t.Errorf("streamB Write: %v", err)
			return
		}

		reply := make([]byte, len(payloadB))
		if _, err := io.ReadFull(streamB, reply); err != nil {
			t.Errorf("streamB ReadFull: %v", err)
			return
		}
		if string(reply) != string(payloadB) {
			t.Errorf("streamB reply mismatch: got %q want %q", reply, payloadB)
		}
	}()

	wg.Wait()
}

func TestCircuitBuilderReturnsPeerUnreachableForOfflinePeer(t *testing.T) {
	routingTransport := &transport.TCPTransport{
		MinJitter: time.Nanosecond,
		MaxJitter: time.Nanosecond,
	}

	keypair, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair(dead): %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	deadAddr := listener.Addr().String()
	_ = listener.Close()

	builder := newTestCircuitBuilder(t, routingTransport)
	_, err = builder.Build([]dht.PeerRecord{{
		ID:      dht.NodeIDFromPublicKey(keypair.Public),
		PubKey:  base64.StdEncoding.EncodeToString(keypair.Public),
		Addrs:   []string{deadAddr},
		Relay:   true,
		Exit:    true,
		Country: "US",
	}}, 1)
	if err == nil {
		t.Fatalf("expected build to fail for offline peer")
	}

	var unreachable *PeerUnreachableError
	if !errors.As(err, &unreachable) {
		t.Fatalf("expected PeerUnreachableError, got %T: %v", err, err)
	}
	if unreachable.PeerID == "" {
		t.Fatalf("expected unreachable error to include peer id")
	}
}

func TestRoutingErrorFromResponsePreservesPeerDetails(t *testing.T) {
	err := routingErrorFromResponse(protocolMessage{
		Error:        "probe timeout",
		FailedPeerID: "peer-1",
		FailedAddr:   "127.0.0.1:443",
		FailedStage:  "ping",
	})

	var unreachable *PeerUnreachableError
	if !errors.As(err, &unreachable) {
		t.Fatalf("expected PeerUnreachableError, got %T", err)
	}
	if unreachable.PeerID != "peer-1" || unreachable.Addr != "127.0.0.1:443" || unreachable.Stage != "ping" {
		t.Fatalf("unexpected unreachable error details: %+v", unreachable)
	}
}

func newTestCircuitBuilder(t *testing.T, routingTransport transport.Transport) *CircuitBuilder {
	t.Helper()

	clientKey, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair(client): %v", err)
	}

	return &CircuitBuilder{
		Transport:            routingTransport,
		LocalPrivateKey:      clientKey.Private,
		Handshaker:           &handshake.Handshaker{},
		ControlTimeout:       3 * time.Second,
		KeepaliveInterval:    time.Hour,
		RotateAfter:          time.Hour,
		MaxBytesBeforeRotate: 1 << 30,
	}
}

func startHopPath(t *testing.T, routingTransport transport.Transport, count int) ([]dht.PeerRecord, func()) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, count)
	var wg sync.WaitGroup
	listeners := make([]transport.Listener, 0, count)
	peers := make([]dht.PeerRecord, 0, count)

	for i := 0; i < count; i++ {
		keypair, err := noise.DH25519.GenerateKeypair(nil)
		if err != nil {
			t.Fatalf("GenerateKeypair(hop %d): %v", i, err)
		}

		listener, err := routingTransport.Listen("127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen(hop %d): %v", i, err)
		}
		listeners = append(listeners, listener)

		server := &HopServer{
			Listener:   listener,
			Transport:  routingTransport,
			Handshaker: &handshake.Handshaker{},
			PrivateKey: keypair.Private,
		}

		wg.Add(1)
		go func(server *HopServer) {
			defer wg.Done()
			if err := server.Serve(ctx); err != nil {
				errCh <- err
			}
		}(server)

		peers = append(peers, dht.PeerRecord{
			ID:      dht.NodeIDFromPublicKey(keypair.Public),
			PubKey:  base64.StdEncoding.EncodeToString(keypair.Public),
			Addrs:   []string{listener.Addr().String()},
			Relay:   true,
			Exit:    true,
			Country: "US",
		})
	}

	return peers, func() {
		cancel()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("HopServer.Serve: %v", err)
			}
		}
	}
}

func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					return
				}
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()

	return listener.Addr().String(), func() {
		cancel()
		_ = listener.Close()
		<-done
	}
}

func mustSplitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()

	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portText, err)
	}
	return host, port
}
