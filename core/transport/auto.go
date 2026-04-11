package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

const (
	ProtocolQUIC      = "quic"
	ProtocolWebSocket = "websocket"
	ProtocolTCP       = "tcp"
)

// AutoTransport tries QUIC first, then WebSocket, then raw TCP, caching the winning choice per peer.
type AutoTransport struct {
	QUIC      Transport
	WebSocket Transport
	TCP       Transport

	cache sync.Map
}

var _ Transport = (*AutoTransport)(nil)

// NewAutoTransport builds an auto-selecting transport with the default fallback chain.
func NewAutoTransport() *AutoTransport {
	return &AutoTransport{
		QUIC:      NewQUICTransport(),
		WebSocket: NewWebSocketTransport(),
		TCP:       NewTCPTransport(),
	}
}

// SetBindInterface pins outbound dials to a specific interface.
func (t *AutoTransport) SetBindInterface(name string, index int) {
	if quicTransport, ok := t.QUIC.(*QUICTransport); ok {
		quicTransport.BindInterfaceName = name
		quicTransport.BindInterfaceIndex = index
	}
	if wsTransport, ok := t.WebSocket.(*WebSocketTransport); ok {
		wsTransport.BindInterfaceName = name
		wsTransport.BindInterfaceIndex = index
	}
	if tcpTransport, ok := t.TCP.(*TCPTransport); ok {
		tcpTransport.BindInterfaceName = name
		tcpTransport.BindInterfaceIndex = index
	}
}

func (t *AutoTransport) Dial(addr string) (Conn, error) {
	attempts := t.orderedTransports(addr)
	var errs []error

	for _, attempt := range attempts {
		if attempt.transport == nil {
			continue
		}

		conn, err := attempt.transport.Dial(addr)
		if err == nil {
			t.cache.Store(addr, attempt.protocol)
			return conn, nil
		}

		errs = append(errs, errors.New(attempt.protocol+": "+err.Error()))
		if cached, ok := t.cache.Load(addr); ok && cached == attempt.protocol {
			t.cache.Delete(addr)
		}
	}

	if len(errs) == 0 {
		return nil, errors.New("transport: no transports configured")
	}
	return nil, errors.Join(errs...)
}

func (t *AutoTransport) Listen(addr string) (Listener, error) {
	wsTransport, _ := t.WebSocket.(*WebSocketTransport)
	tcpTransport, _ := t.TCP.(*TCPTransport)

	if wsTransport == nil && tcpTransport == nil && t.QUIC == nil {
		return nil, errors.New("transport: no listener transports configured")
	}
	if wsTransport == nil && tcpTransport == nil {
		return t.QUIC.Listen(addr)
	}

	tcpMux, err := newAutoTCPMux(addr, wsTransport, tcpTransport)
	if err != nil {
		return nil, err
	}

	var quicListener Listener
	if t.QUIC != nil {
		quicListener, err = t.QUIC.Listen(tcpMux.Addr().String())
		if err != nil {
			_ = tcpMux.Close()
			return nil, err
		}
	}

	listener := &autoListener{
		addr:     tcpMux.Addr(),
		tcpMux:   tcpMux,
		quic:     quicListener,
		acceptCh: make(chan Conn, 32),
		errCh:    make(chan error, 4),
		closed:   make(chan struct{}),
	}
	listener.ctx, listener.cancel = context.WithCancel(context.Background())

	go listener.forwardTCP()
	if quicListener != nil {
		go listener.forwardQUIC()
	}

	return listener, nil
}

func (t *AutoTransport) cachedProtocol(addr string) (string, bool) {
	value, ok := t.cache.Load(addr)
	if !ok {
		return "", false
	}
	protocol, _ := value.(string)
	return protocol, protocol != ""
}

func (t *AutoTransport) orderedTransports(addr string) []namedTransport {
	base := []namedTransport{
		{protocol: ProtocolQUIC, transport: t.QUIC},
		{protocol: ProtocolWebSocket, transport: t.WebSocket},
		{protocol: ProtocolTCP, transport: t.TCP},
	}

	cached, ok := t.cachedProtocol(addr)
	if !ok {
		return base
	}

	ordered := make([]namedTransport, 0, len(base))
	for _, candidate := range base {
		if candidate.protocol == cached {
			ordered = append(ordered, candidate)
		}
	}
	for _, candidate := range base {
		if candidate.protocol != cached {
			ordered = append(ordered, candidate)
		}
	}
	return ordered
}

type namedTransport struct {
	protocol  string
	transport Transport
}

type autoListener struct {
	addr   net.Addr
	tcpMux *autoTCPMux
	quic   Listener

	ctx    context.Context
	cancel context.CancelFunc

	acceptCh chan Conn
	errCh    chan error
	closed   chan struct{}

	closeOnce sync.Once
}

func (l *autoListener) Accept(ctx context.Context) (Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case err := <-l.errCh:
		return nil, err
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *autoListener) Close() error {
	var closeErr error
	l.closeOnce.Do(func() {
		close(l.closed)
		l.cancel()

		if l.quic != nil {
			closeErr = l.quic.Close()
		}
		if err := l.tcpMux.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	})
	return closeErr
}

func (l *autoListener) Addr() net.Addr {
	return l.addr
}

func (l *autoListener) forwardTCP() {
	for {
		conn, err := l.tcpMux.Accept(l.ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case l.errCh <- err:
			default:
			}
			return
		}

		select {
		case l.acceptCh <- conn:
		case <-l.ctx.Done():
			_ = conn.Close()
			return
		}
	}
}

func (l *autoListener) forwardQUIC() {
	for {
		conn, err := l.quic.Accept(l.ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case l.errCh <- err:
			default:
			}
			return
		}

		select {
		case l.acceptCh <- conn:
		case <-l.ctx.Done():
			_ = conn.Close()
			return
		}
	}
}

type autoTCPMux struct {
	listener     *net.TCPListener
	wsTransport  *WebSocketTransport
	tcpTransport *TCPTransport

	acceptCh chan Conn
	errCh    chan error
	closed   chan struct{}

	wsServer     *http.Server
	wsConnSource *connChannelListener

	closeOnce sync.Once
}

func newAutoTCPMux(addr string, wsTransport *WebSocketTransport, tcpTransport *TCPTransport) (*autoTCPMux, error) {
	if wsTransport == nil && tcpTransport == nil {
		return nil, errors.New("transport: no TCP-based transports configured")
	}
	if tcpTransport == nil {
		tcpTransport = NewTCPTransport()
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		_ = listener.Close()
		return nil, net.InvalidAddrError("transport: expected TCP listener")
	}

	mux := &autoTCPMux{
		listener:     tcpListener,
		wsTransport:  wsTransport,
		tcpTransport: tcpTransport,
		acceptCh:     make(chan Conn, 32),
		errCh:        make(chan error, 2),
		closed:       make(chan struct{}),
	}

	if wsTransport != nil {
		if err := mux.startWebSocketServer(); err != nil {
			_ = tcpListener.Close()
			return nil, err
		}
	}

	go mux.run()
	return mux, nil
}

func (m *autoTCPMux) Accept(ctx context.Context) (Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case conn := <-m.acceptCh:
		return conn, nil
	case err := <-m.errCh:
		return nil, err
	case <-m.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *autoTCPMux) Close() error {
	var closeErr error
	m.closeOnce.Do(func() {
		close(m.closed)
		if m.wsConnSource != nil {
			_ = m.wsConnSource.Close()
		}
		if m.wsServer != nil {
			_ = m.wsServer.Close()
		}
		closeErr = m.listener.Close()
	})
	return closeErr
}

func (m *autoTCPMux) Addr() net.Addr {
	return m.listener.Addr()
}

func (m *autoTCPMux) run() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case m.errCh <- err:
			default:
			}
			return
		}

		buffered := newBufferedNetConn(conn)
		if m.wsTransport != nil && looksLikeTLSHandshake(buffered) {
			if err := m.wsConnSource.Push(buffered); err != nil {
				_ = buffered.Close()
			}
			continue
		}

		select {
		case m.acceptCh <- m.tcpTransport.wrapConn(buffered):
		case <-m.closed:
			_ = buffered.Close()
			return
		}
	}
}

func (m *autoTCPMux) startWebSocketServer() error {
	serverTLSConfig, err := m.wsTransport.serverTLSConfig()
	if err != nil {
		return err
	}

	m.wsConnSource = newConnChannelListener(m.listener.Addr())

	upgrader := websocketUpgrader()
	mux := http.NewServeMux()
	mux.HandleFunc(m.wsTransport.path(), func(w http.ResponseWriter, r *http.Request) {
		conn, upgradeErr := upgrader.Upgrade(w, r, nil)
		if upgradeErr != nil {
			return
		}

		select {
		case m.acceptCh <- m.wsTransport.wrapConn(conn):
		case <-m.closed:
			_ = conn.Close()
		}
	})

	server := &http.Server{Handler: mux}
	m.wsServer = server

	go func() {
		tlsListener := tls.NewListener(m.wsConnSource, serverTLSConfig)
		if serveErr := server.Serve(tlsListener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
			select {
			case m.errCh <- serveErr:
			default:
			}
		}
	}()

	return nil
}

func looksLikeTLSHandshake(conn *bufferedNetConn) bool {
	header, err := conn.Peek(3)
	if err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	return len(header) >= 3 && header[0] == 0x16 && header[1] == 0x03
}

type bufferedNetConn struct {
	net.Conn
	reader *bufio.Reader
}

func newBufferedNetConn(conn net.Conn) *bufferedNetConn {
	return &bufferedNetConn{
		Conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

func (c *bufferedNetConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *bufferedNetConn) Peek(n int) ([]byte, error) {
	return c.reader.Peek(n)
}

type connChannelListener struct {
	addr   net.Addr
	conns  chan net.Conn
	closed chan struct{}

	closeOnce sync.Once
}

func newConnChannelListener(addr net.Addr) *connChannelListener {
	return &connChannelListener{
		addr:   addr,
		conns:  make(chan net.Conn, 32),
		closed: make(chan struct{}),
	}
}

func (l *connChannelListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *connChannelListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
	})
	return nil
}

func (l *connChannelListener) Addr() net.Addr {
	return l.addr
}

func (l *connChannelListener) Push(conn net.Conn) error {
	select {
	case l.conns <- conn:
		return nil
	case <-l.closed:
		return net.ErrClosed
	}
}

func websocketUpgrader() websocket.Upgrader {
	return websocket.Upgrader{
		CheckOrigin: func(_ *http.Request) bool { return true },
	}
}
