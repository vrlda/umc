package transport

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"time"
)

// TCPTransport implements the raw TCP fallback transport.
type TCPTransport struct {
	PaddingSizes       []int
	MinJitter          time.Duration
	MaxJitter          time.Duration
	DialTimeout        time.Duration
	BindInterfaceName  string
	BindInterfaceIndex int

	randomSource io.Reader
	sleep        func(time.Duration)
}

var _ Transport = (*TCPTransport)(nil)

// NewTCPTransport builds a TCP transport with spec-aligned defaults.
func NewTCPTransport() *TCPTransport {
	return &TCPTransport{}
}

func (t *TCPTransport) Dial(addr string) (Conn, error) {
	timeout := t.DialTimeout
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}

	conn, err := newBoundDialer(timeout, t.BindInterfaceName, t.BindInterfaceIndex).Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return t.wrapConn(conn), nil
}

func (t *TCPTransport) Listen(addr string) (Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		_ = listener.Close()
		return nil, net.InvalidAddrError("transport: expected TCP listener")
	}

	return &tcpListenerWrapper{
		listener:  tcpListener,
		transport: t,
	}, nil
}

func (t *TCPTransport) wrapConn(conn net.Conn) *tcpConn {
	paddingSizes := cloneIntSlice(t.PaddingSizes)
	if len(paddingSizes) == 0 {
		paddingSizes = cloneIntSlice(defaultPaddingSizes)
	}

	minJitter := t.MinJitter
	maxJitter := t.MaxJitter
	if minJitter == 0 && maxJitter == 0 {
		minJitter = defaultMinJitter
		maxJitter = defaultMaxJitter
	}
	if maxJitter < minJitter {
		maxJitter = minJitter
	}

	randomSource := t.randomSource
	if randomSource == nil {
		randomSource = rand.Reader
	}

	sleep := t.sleep
	if sleep == nil {
		sleep = time.Sleep
	}

	return &tcpConn{
		conn:         conn,
		paddingSizes: paddingSizes,
		minJitter:    minJitter,
		maxJitter:    maxJitter,
		randomSource: randomSource,
		sleep:        sleep,
	}
}

type tcpListenerWrapper struct {
	listener  *net.TCPListener
	transport *TCPTransport
}

func (l *tcpListenerWrapper) Accept(ctx context.Context) (Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	for {
		if err := l.listener.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			return nil, err
		}

		conn, err := l.listener.Accept()
		if err == nil {
			return l.transport.wrapConn(conn), nil
		}

		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		return nil, err
	}
}

func (l *tcpListenerWrapper) Close() error {
	return l.listener.Close()
}

func (l *tcpListenerWrapper) Addr() net.Addr {
	return l.listener.Addr()
}

type tcpConn struct {
	conn net.Conn

	paddingSizes []int
	minJitter    time.Duration
	maxJitter    time.Duration
	randomSource io.Reader
	sleep        func(time.Duration)

	readMu   sync.Mutex
	writeMu  sync.Mutex
	closeMu  sync.Once
	closeErr error
}

var _ Conn = (*tcpConn)(nil)

func (c *tcpConn) Send(payload []byte) error {
	frame, err := encodePaddedFrame(payload, c.paddingSizes, c.randomSource)
	if err != nil {
		return err
	}

	jitter, err := randomJitter(c.minJitter, c.maxJitter, c.randomSource)
	if err != nil {
		return err
	}
	if jitter > 0 {
		c.sleep(jitter)
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	return writeAll(c.conn, frame)
}

func (c *tcpConn) Recv() ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	return decodeFrame(c.conn)
}

func (c *tcpConn) Close() error {
	c.closeMu.Do(func() {
		c.closeErr = c.conn.Close()
	})
	return c.closeErr
}
