package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestQUICTransportDialListenLoopback(t *testing.T) {
	t.Parallel()

	serverTransport := &QUICTransport{
		MinJitter: 0,
		MaxJitter: 0,
	}
	listener, err := serverTransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := listener.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		message, err := conn.Recv()
		if err != nil {
			serverErr <- err
			return
		}
		if string(message) != "ping" {
			serverErr <- errInvalidFrame
			return
		}

		serverErr <- conn.Send([]byte("pong"))
	}()

	clientTransport := &QUICTransport{
		MinJitter: 0,
		MaxJitter: 0,
	}
	conn, err := clientTransport.Dial(listener.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if err := conn.Send([]byte("ping")); err != nil {
		t.Fatalf("client send failed: %v", err)
	}

	reply, err := conn.Recv()
	if err != nil {
		t.Fatalf("client recv failed: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected reply: got %q want %q", reply, "pong")
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server flow failed: %v", err)
	}
}

func TestQUICConnEncodeFrameAppliesNormalizedPadding(t *testing.T) {
	t.Parallel()

	conn := &quicConn{
		paddingSizes: []int{256, 512, 1024, 1400},
		randomSource: bytes.NewReader(make([]byte, 8)),
	}

	frame, err := conn.encodeFrame([]byte("hello"))
	if err != nil {
		t.Fatalf("encodeFrame failed: %v", err)
	}
	if len(frame) != 256 {
		t.Fatalf("unexpected frame length: got %d want %d", len(frame), 256)
	}

	payload, err := decodeFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("decodeFrame failed: %v", err)
	}
	if string(payload) != "hello" {
		t.Fatalf("unexpected payload: got %q want %q", payload, "hello")
	}
}

func TestWebSocketTransportDialListenLoopback(t *testing.T) {
	t.Parallel()

	serverTransport := &WebSocketTransport{
		MinJitter:        0,
		MaxJitter:        0,
		HandshakeTimeout: time.Second,
	}
	listener, err := serverTransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := listener.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		message, err := conn.Recv()
		if err != nil {
			serverErr <- err
			return
		}
		if string(message) != "ping" {
			serverErr <- errInvalidFrame
			return
		}

		serverErr <- conn.Send([]byte("pong"))
	}()

	clientTransport := &WebSocketTransport{
		MinJitter:        0,
		MaxJitter:        0,
		HandshakeTimeout: time.Second,
	}
	conn, err := clientTransport.Dial(listener.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	if err := conn.Send([]byte("ping")); err != nil {
		t.Fatalf("client send failed: %v", err)
	}

	reply, err := conn.Recv()
	if err != nil {
		t.Fatalf("client recv failed: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected reply: got %q want %q", reply, "pong")
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server flow failed: %v", err)
	}
}

func TestAutoTransportFallsBackToWebSocket(t *testing.T) {
	t.Parallel()

	serverTransport := &WebSocketTransport{
		MinJitter:        0,
		MaxJitter:        0,
		HandshakeTimeout: time.Second,
	}
	listener, err := serverTransport.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := listener.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		payload, err := conn.Recv()
		if err != nil {
			serverErr <- err
			return
		}
		if string(payload) != "hello-ws" {
			serverErr <- errInvalidFrame
			return
		}

		serverErr <- conn.Send([]byte("hello-client"))
	}()

	auto := &AutoTransport{
		QUIC: &QUICTransport{
			DialTimeout: 100 * time.Millisecond,
			MinJitter:   0,
			MaxJitter:   0,
		},
		WebSocket: &WebSocketTransport{
			MinJitter:        0,
			MaxJitter:        0,
			HandshakeTimeout: time.Second,
		},
		TCP: &TCPTransport{
			DialTimeout: 200 * time.Millisecond,
			MinJitter:   0,
			MaxJitter:   0,
		},
	}

	conn, err := auto.Dial(listener.Addr().String())
	if err != nil {
		t.Fatalf("auto dial failed: %v", err)
	}
	defer conn.Close()

	if err := conn.Send([]byte("hello-ws")); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	reply, err := conn.Recv()
	if err != nil {
		t.Fatalf("recv failed: %v", err)
	}
	if string(reply) != "hello-client" {
		t.Fatalf("unexpected reply: got %q want %q", reply, "hello-client")
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server flow failed: %v", err)
	}

	protocol, ok := auto.cachedProtocol(listener.Addr().String())
	if !ok {
		t.Fatalf("expected cached protocol")
	}
	if protocol != ProtocolWebSocket {
		t.Fatalf("unexpected cached protocol: got %q want %q", protocol, ProtocolWebSocket)
	}
}

func TestAutoTransportFallsBackToTCPAndCachesSelection(t *testing.T) {
	t.Parallel()

	tcpTransport := &countingTransport{
		conn: &stubConn{},
	}
	auto := &AutoTransport{
		QUIC: &countingTransport{
			err: errors.New("quic unavailable"),
		},
		WebSocket: &countingTransport{
			err: errors.New("websocket unavailable"),
		},
		TCP: tcpTransport,
	}

	addr := "peer.example:443"

	conn, err := auto.Dial(addr)
	if err != nil {
		t.Fatalf("auto dial failed: %v", err)
	}
	if conn == nil {
		t.Fatalf("expected connection")
	}

	protocol, ok := auto.cachedProtocol(addr)
	if !ok {
		t.Fatalf("expected cached protocol")
	}
	if protocol != ProtocolTCP {
		t.Fatalf("unexpected cached protocol: got %q want %q", protocol, ProtocolTCP)
	}

	if tcpTransport.dials != 1 {
		t.Fatalf("unexpected tcp dial count: got %d want %d", tcpTransport.dials, 1)
	}

	_, err = auto.Dial(addr)
	if err != nil {
		t.Fatalf("cached auto dial failed: %v", err)
	}

	quicTransport := auto.QUIC.(*countingTransport)
	wsTransport := auto.WebSocket.(*countingTransport)
	if quicTransport.dials != 1 {
		t.Fatalf("unexpected quic dial count: got %d want %d", quicTransport.dials, 1)
	}
	if wsTransport.dials != 1 {
		t.Fatalf("unexpected websocket dial count: got %d want %d", wsTransport.dials, 1)
	}
	if tcpTransport.dials != 2 {
		t.Fatalf("unexpected tcp dial count after cache: got %d want %d", tcpTransport.dials, 2)
	}
}

type countingTransport struct {
	dials int
	conn  Conn
	err   error
}

func (t *countingTransport) Dial(string) (Conn, error) {
	t.dials++
	if t.err != nil {
		return nil, t.err
	}
	return t.conn, nil
}

func (t *countingTransport) Listen(string) (Listener, error) {
	return nil, errors.New("not implemented")
}

type stubConn struct{}

func (c *stubConn) Send([]byte) error     { return nil }
func (c *stubConn) Recv() ([]byte, error) { return nil, io.EOF }
func (c *stubConn) Close() error          { return nil }
