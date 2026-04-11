package integration_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/openmesh/core/dht"
	"github.com/openmesh/core/handshake"
	"github.com/openmesh/core/probe"
	"github.com/openmesh/core/routing"
	transportpkg "github.com/openmesh/core/transport"
)

func TestFiveNodeCircuitEstablishment(t *testing.T) {
	mesh := newFiveNodeMesh(t, 0)
	defer mesh.Close()

	testCases := []struct {
		name string
		path []dht.PeerRecord
	}{
		{
			name: "1-hop",
			path: []dht.PeerRecord{mesh.exit.record()},
		},
		{
			name: "2-hop",
			path: []dht.PeerRecord{mesh.relays[0].record(), mesh.exit.record()},
		},
		{
			name: "3-hop",
			path: []dht.PeerRecord{mesh.relays[0].record(), mesh.relays[1].record(), mesh.exit.record()},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			builder := newTestCircuitBuilder(t, mesh.transport, circuitBuilderOptions{})
			circuit, err := builder.Build(tc.path, len(tc.path))
			if err != nil {
				t.Fatalf("Build(%s): %v", tc.name, err)
			}
			defer circuit.Close()

			payload := []byte("integration-" + tc.name)
			reply := mesh.roundTrip(t, circuit, payload)
			if string(reply) != string(payload) {
				t.Fatalf("unexpected reply: got %q want %q", reply, payload)
			}
		})
	}
}

func TestProbeResistanceInvalidTokenGetsDecoy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer listener.Close()

	guard, err := probe.NewProbeGuard(
		listener,
		&probe.DecoyServer{DataDir: t.TempDir()},
		probe.TokenValidator{Now: func() time.Time { return time.Unix(1_712_000_000, 0).UTC() }},
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	if err != nil {
		t.Fatalf("NewProbeGuard: %v", err)
	}
	defer guard.Close()

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer client.Close()

	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("client.Write: %v", err)
	}

	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}

	body := string(response)
	if !containsAll(body, "200 OK", "This site is under construction.") {
		t.Fatalf("expected decoy HTTP response, got %q", body)
	}
}

func TestCircuitRotation(t *testing.T) {
	mesh := newFiveNodeMesh(t, 0)
	defer mesh.Close()

	builder := newTestCircuitBuilder(t, mesh.transport, circuitBuilderOptions{
		RotateAfter:          50 * time.Millisecond,
		KeepaliveInterval:    time.Hour,
		MaxBytesBeforeRotate: 1 << 30,
	})

	circuit, err := builder.Build([]dht.PeerRecord{mesh.relays[0].record(), mesh.exit.record()}, 2)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer circuit.Close()

	initial := circuit.Snapshot()
	time.Sleep(125 * time.Millisecond)

	reply := mesh.roundTrip(t, circuit, []byte("rotate-me"))
	if string(reply) != "rotate-me" {
		t.Fatalf("unexpected reply after rotation: got %q", reply)
	}

	rotated := circuit.Snapshot()
	if !rotated.CreatedAt.After(initial.CreatedAt) {
		t.Fatalf("expected rotated circuit to have newer creation time: initial=%s rotated=%s", initial.CreatedAt, rotated.CreatedAt)
	}
}

func TestNodeFailureMidCircuitRebuilds(t *testing.T) {
	mesh := newFiveNodeMesh(t, 0)
	defer mesh.Close()

	path := []dht.PeerRecord{mesh.relays[0].record(), mesh.relays[1].record(), mesh.exit.record()}
	builder := newTestCircuitBuilder(t, mesh.transport, circuitBuilderOptions{
		RotateAfter:          time.Hour,
		KeepaliveInterval:    time.Hour,
		MaxBytesBeforeRotate: 1 << 30,
	})

	circuit, err := builder.Build(path, len(path))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer circuit.Close()

	stream, err := circuit.OpenStream("allowed.example", mesh.echoPort())
	if err != nil {
		t.Fatalf("OpenStream(before failure): %v", err)
	}

	if _, err := stream.Write([]byte("before-failure")); err != nil {
		t.Fatalf("stream.Write(before failure): %v", err)
	}
	reply := make([]byte, len("before-failure"))
	if _, err := io.ReadFull(stream, reply); err != nil {
		t.Fatalf("io.ReadFull(before failure): %v", err)
	}
	if string(reply) != "before-failure" {
		t.Fatalf("unexpected reply before failure: got %q", reply)
	}

	mesh.relays[0].stop(t)
	if err := waitForStreamFailure(stream, 2*time.Second); err != nil {
		t.Fatalf("expected stream failure after relay shutdown: %v", err)
	}

	mesh.relays[0].start(t)
	replacement, err := circuit.OpenStream("allowed.example", mesh.echoPort())
	if err != nil {
		t.Fatalf("OpenStream(after rebuild): %v", err)
	}
	defer replacement.Close()

	if _, err := replacement.Write([]byte("after-rebuild")); err != nil {
		t.Fatalf("replacement.Write: %v", err)
	}
	reply = make([]byte, len("after-rebuild"))
	if _, err := io.ReadFull(replacement, reply); err != nil {
		t.Fatalf("replacement.ReadFull: %v", err)
	}
	if string(reply) != "after-rebuild" {
		t.Fatalf("unexpected reply after rebuild: got %q", reply)
	}
}

func TestBandwidthThrottlingRespected(t *testing.T) {
	mesh := newFiveNodeMesh(t, 1)
	defer mesh.Close()

	builder := newTestCircuitBuilder(t, mesh.transport, circuitBuilderOptions{
		RotateAfter:          time.Hour,
		KeepaliveInterval:    time.Hour,
		MaxBytesBeforeRotate: 1 << 30,
	})

	circuit, err := builder.Build([]dht.PeerRecord{mesh.exit.record()}, 1)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer circuit.Close()

	stream, err := circuit.OpenStream("allowed.example", mesh.echoPort())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stream.Close()

	started := time.Now()
	totalBytes := 0
	for chunkIndex := 0; chunkIndex < 6; chunkIndex++ {
		payload := make([]byte, 32<<10)
		for i := range payload {
			payload[i] = byte((chunkIndex + i) % 251)
		}

		if _, err := stream.Write(payload); err != nil {
			t.Fatalf("stream.Write(chunk %d): %v", chunkIndex, err)
		}

		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(stream, reply); err != nil {
			t.Fatalf("io.ReadFull(chunk %d): %v", chunkIndex, err)
		}
		totalBytes += len(reply)
	}
	elapsed := time.Since(started)

	if elapsed < 1500*time.Millisecond {
		t.Fatalf("expected throttled transfer to take at least 1.5s, got %s", elapsed)
	}
	if totalBytes != 192<<10 {
		t.Fatalf("unexpected echoed byte count: got %d want %d", totalBytes, 192<<10)
	}
}

type circuitBuilderOptions struct {
	RotateAfter          time.Duration
	KeepaliveInterval    time.Duration
	MaxBytesBeforeRotate int64
}

func newTestCircuitBuilder(t *testing.T, tr transportpkg.Transport, opts circuitBuilderOptions) *routing.CircuitBuilder {
	t.Helper()

	keypair, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair(client): %v", err)
	}

	rotateAfter := opts.RotateAfter
	if rotateAfter == 0 {
		rotateAfter = time.Hour
	}
	keepalive := opts.KeepaliveInterval
	if keepalive == 0 {
		keepalive = time.Hour
	}
	maxBytes := opts.MaxBytesBeforeRotate
	if maxBytes == 0 {
		maxBytes = 1 << 30
	}

	return &routing.CircuitBuilder{
		Transport:            tr,
		Handshaker:           &handshake.Handshaker{},
		LocalPrivateKey:      keypair.Private,
		ControlTimeout:       2 * time.Second,
		KeepaliveInterval:    keepalive,
		RotateAfter:          rotateAfter,
		MaxBytesBeforeRotate: maxBytes,
	}
}

type fiveNodeMesh struct {
	t         *testing.T
	transport transportpkg.Transport
	echoAddr  string
	echoStop  func()
	relays    []*meshNode
	exit      *meshNode
	extras    []*meshNode
}

func newFiveNodeMesh(t *testing.T, exitBandwidthMbps int) *fiveNodeMesh {
	t.Helper()

	echoAddr, echoStop := startEchoServer(t)
	echoPort := mustPort(t, echoAddr)
	tr := &transportpkg.TCPTransport{
		MinJitter: time.Nanosecond,
		MaxJitter: time.Nanosecond,
	}

	mesh := &fiveNodeMesh{
		t:         t,
		transport: tr,
		echoAddr:  echoAddr,
		echoStop:  echoStop,
	}

	mesh.relays = []*meshNode{
		newMeshRelayNode(t, tr, "127.0.0.1:0", "relay-a", 64501, "CA"),
		newMeshRelayNode(t, tr, "127.0.0.1:0", "relay-b", 64502, "FR"),
		newMeshRelayNode(t, tr, "127.0.0.1:0", "relay-c", 64503, "NL"),
	}
	mesh.exit = newMeshExitNode(t, tr, "127.0.0.1:0", "exit-a", 64510, "DE", echoAddr, echoPort, exitBandwidthMbps)
	mesh.extras = []*meshNode{
		newMeshRelayNode(t, tr, "127.0.0.1:0", "relay-d", 64504, "JP"),
	}

	for _, node := range mesh.allNodes() {
		node.start(t)
	}

	return mesh
}

func (m *fiveNodeMesh) Close() {
	for _, node := range m.allNodes() {
		node.stop(m.t)
	}
	if m.echoStop != nil {
		m.echoStop()
		m.echoStop = nil
	}
}

func (m *fiveNodeMesh) allNodes() []*meshNode {
	nodes := make([]*meshNode, 0, len(m.relays)+1+len(m.extras))
	nodes = append(nodes, m.relays...)
	nodes = append(nodes, m.exit)
	nodes = append(nodes, m.extras...)
	return nodes
}

func (m *fiveNodeMesh) echoPort() int {
	return mustPort(m.t, m.echoAddr)
}

func (m *fiveNodeMesh) roundTrip(t *testing.T, circuit *routing.Circuit, payload []byte) []byte {
	t.Helper()

	stream, err := circuit.OpenStream("allowed.example", m.echoPort())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("stream.Write: %v", err)
	}

	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, reply); err != nil {
		t.Fatalf("io.ReadFull: %v", err)
	}
	return reply
}

type meshNode struct {
	transport transportpkg.Transport
	addr      string
	name      string
	asn       int
	country   string
	bandwidth int

	keypair  noise.DHKey
	relay    bool
	exit     bool
	echoAddr string
	echoPort int

	mu       sync.Mutex
	listener *trackedListener
	cancel   context.CancelFunc
	doneCh   chan error
}

func newMeshRelayNode(t *testing.T, tr transportpkg.Transport, addr, name string, asn int, country string) *meshNode {
	t.Helper()

	keypair, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair(%s): %v", name, err)
	}

	return &meshNode{
		transport: tr,
		addr:      addr,
		name:      name,
		asn:       asn,
		country:   country,
		keypair:   keypair,
		relay:     true,
	}
}

func newMeshExitNode(t *testing.T, tr transportpkg.Transport, addr, name string, asn int, country, echoAddr string, echoPort, bandwidth int) *meshNode {
	t.Helper()

	keypair, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		t.Fatalf("GenerateKeypair(%s): %v", name, err)
	}

	return &meshNode{
		transport: tr,
		addr:      addr,
		name:      name,
		asn:       asn,
		country:   country,
		bandwidth: bandwidth,
		keypair:   keypair,
		relay:     true,
		exit:      true,
		echoAddr:  echoAddr,
		echoPort:  echoPort,
	}
}

func (n *meshNode) start(t *testing.T) {
	t.Helper()

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.listener != nil {
		return
	}

	listener, err := n.transport.Listen(n.addr)
	if err != nil {
		t.Fatalf("Listen(%s): %v", n.name, err)
	}

	tracked := newTrackedListener(listener)
	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan error, 1)

	if n.exit {
		server := &routing.ExitNode{
			Transport:          n.transport,
			Listener:           tracked,
			Handshaker:         &handshake.Handshaker{},
			PrivateKey:         n.keypair.Private,
			BandwidthLimitMbps: n.bandwidth,
			Policy:             dht.ExitPolicy{Ports: []int{n.echoPort}},
			DialContext: func(ctx context.Context, _ string, _ int) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", n.echoAddr)
			},
		}
		go func() {
			doneCh <- server.Serve(ctx)
		}()
	} else {
		server := &routing.RelayNode{
			Listener:           tracked,
			Transport:          n.transport,
			Handshaker:         &handshake.Handshaker{},
			PrivateKey:         n.keypair.Private,
			BandwidthLimitMbps: n.bandwidth,
		}
		go func() {
			doneCh <- server.Serve(ctx)
		}()
	}

	n.addr = tracked.Addr().String()
	n.listener = tracked
	n.cancel = cancel
	n.doneCh = doneCh
}

func (n *meshNode) stop(t *testing.T) {
	t.Helper()

	n.mu.Lock()
	listener := n.listener
	cancel := n.cancel
	doneCh := n.doneCh
	n.listener = nil
	n.cancel = nil
	n.doneCh = nil
	n.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if listener != nil {
		listener.CloseActive()
		_ = listener.Close()
	}
	if doneCh != nil {
		err := <-doneCh
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve(%s): %v", n.name, err)
		}
	}
}

func (n *meshNode) record() dht.PeerRecord {
	n.mu.Lock()
	addr := n.addr
	n.mu.Unlock()

	return dht.PeerRecord{
		ID:            dht.NodeIDFromPublicKey(n.keypair.Public),
		PubKey:        base64.StdEncoding.EncodeToString(n.keypair.Public),
		Addrs:         []string{addr},
		Relay:         n.relay,
		Exit:          n.exit,
		ExitPolicy:    dht.ExitPolicy{Ports: []int{n.echoPort}, Blocklist: "default"},
		Country:       n.country,
		ASN:           n.asn,
		BandwidthMbps: max(10, n.bandwidth),
		UptimeScore:   0.99,
		LastSeen:      time.Now().Unix(),
	}
}

type trackedListener struct {
	base transportpkg.Listener

	mu    sync.Mutex
	conns map[*trackedConn]struct{}
}

func newTrackedListener(base transportpkg.Listener) *trackedListener {
	return &trackedListener{
		base:  base,
		conns: make(map[*trackedConn]struct{}),
	}
}

func (l *trackedListener) Accept(ctx context.Context) (transportpkg.Conn, error) {
	conn, err := l.base.Accept(ctx)
	if err != nil {
		return nil, err
	}

	tracked := &trackedConn{base: conn, owner: l}
	l.mu.Lock()
	l.conns[tracked] = struct{}{}
	l.mu.Unlock()
	return tracked, nil
}

func (l *trackedListener) Close() error {
	return l.base.Close()
}

func (l *trackedListener) Addr() net.Addr {
	return l.base.Addr()
}

func (l *trackedListener) CloseActive() {
	l.mu.Lock()
	conns := make([]*trackedConn, 0, len(l.conns))
	for conn := range l.conns {
		conns = append(conns, conn)
	}
	l.mu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (l *trackedListener) remove(conn *trackedConn) {
	l.mu.Lock()
	delete(l.conns, conn)
	l.mu.Unlock()
}

type trackedConn struct {
	base  transportpkg.Conn
	owner *trackedListener

	closeOnce sync.Once
}

func (c *trackedConn) Send(payload []byte) error {
	return c.base.Send(payload)
}

func (c *trackedConn) Recv() ([]byte, error) {
	return c.base.Recv()
}

func (c *trackedConn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		closeErr = c.base.Close()
		c.owner.remove(c)
	})
	return closeErr
}

func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()
				buffer := make([]byte, 32<<10)
				for {
					n, err := conn.Read(buffer)
					if n > 0 {
						if _, writeErr := conn.Write(buffer[:n]); writeErr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func waitForStreamFailure(stream io.Writer, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := stream.Write([]byte("probe")); err != nil {
			return nil
		}
		time.Sleep(40 * time.Millisecond)
	}
	return errors.New("timed out waiting for stream failure")
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

func containsAll(value string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(value, needle) {
			return false
		}
	}
	return true
}
