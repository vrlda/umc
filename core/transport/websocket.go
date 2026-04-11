package transport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const defaultWebSocketPath = "/ws"

var browserUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
}

// WebSocketTransport implements the TCP fallback transport using browser-like WebSocket upgrades.
type WebSocketTransport struct {
	ClientTLSConfig    *tls.Config
	ServerTLSConfig    *tls.Config
	DialTimeout        time.Duration
	HandshakeTimeout   time.Duration
	MinJitter          time.Duration
	MaxJitter          time.Duration
	Path               string
	BindInterfaceName  string
	BindInterfaceIndex int

	randomSource io.Reader
	sleep        func(time.Duration)

	serverTLSOnce sync.Once
	serverTLS     *tls.Config
	serverTLSErr  error
}

var _ Transport = (*WebSocketTransport)(nil)

// NewWebSocketTransport builds a WebSocket transport with spec-aligned defaults.
func NewWebSocketTransport() *WebSocketTransport {
	return &WebSocketTransport{}
}

func (t *WebSocketTransport) Dial(addr string) (Conn, error) {
	dialTimeout := t.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}

	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: t.handshakeTimeout(),
		TLSClientConfig:  t.clientTLSConfig(addr),
		NetDialContext:   newBoundDialer(dialTimeout, t.BindInterfaceName, t.BindInterfaceIndex).DialContext,
	}

	wsURL := url.URL{
		Scheme: "wss",
		Host:   addr,
		Path:   t.path(),
	}

	header := http.Header{}
	header.Set("User-Agent", t.randomUserAgent())
	header.Set("Accept-Language", "en-US,en;q=0.9")
	header.Set("Cache-Control", "no-cache")
	header.Set("Pragma", "no-cache")
	header.Set("Origin", websocketOrigin(addr))

	conn, response, err := dialer.Dial(wsURL.String(), header)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return nil, err
	}

	return t.wrapConn(conn), nil
}

func (t *WebSocketTransport) Listen(addr string) (Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		_ = listener.Close()
		return nil, net.InvalidAddrError("transport: expected TCP listener")
	}

	serverTLSConfig, err := t.serverTLSConfig()
	if err != nil {
		_ = tcpListener.Close()
		return nil, err
	}

	acceptCh := make(chan Conn, 32)
	errCh := make(chan error, 1)

	upgrader := websocket.Upgrader{
		CheckOrigin: func(_ *http.Request) bool { return true },
	}

	mux := http.NewServeMux()
	mux.HandleFunc(t.path(), func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}

		select {
		case acceptCh <- t.wrapConn(conn):
		default:
			_ = conn.Close()
		}
	})

	server := &http.Server{
		Handler:  mux,
		ErrorLog: log.New(io.Discard, "", 0),
	}

	go func() {
		tlsListener := tls.NewListener(tcpListener, serverTLSConfig)
		if serveErr := server.Serve(tlsListener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
			select {
			case errCh <- serveErr:
			default:
			}
		}
	}()

	return &webSocketListener{
		listener: listener,
		server:   server,
		acceptCh: acceptCh,
		errCh:    errCh,
	}, nil
}

func (t *WebSocketTransport) wrapConn(conn *websocket.Conn) *webSocketConn {
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

	conn.SetReadLimit(maxFrameSize)

	return &webSocketConn{
		conn:         conn,
		minJitter:    minJitter,
		maxJitter:    maxJitter,
		randomSource: randomSource,
		sleep:        sleep,
	}
}

func (t *WebSocketTransport) clientTLSConfig(addr string) *tls.Config {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	if t.ClientTLSConfig == nil {
		return &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			NextProtos:         []string{"http/1.1"},
			CurvePreferences:   chromeLikeCurves(),
			ClientSessionCache: tls.NewLRUClientSessionCache(32),
		}
	}

	cfg := t.ClientTLSConfig.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	if len(cfg.NextProtos) == 0 {
		cfg.NextProtos = []string{"http/1.1"}
	}
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS13
	}
	if cfg.MaxVersion == 0 {
		cfg.MaxVersion = tls.VersionTLS13
	}
	if len(cfg.CurvePreferences) == 0 {
		cfg.CurvePreferences = chromeLikeCurves()
	}
	if cfg.ClientSessionCache == nil {
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(32)
	}
	return cfg
}

func (t *WebSocketTransport) serverTLSConfig() (*tls.Config, error) {
	if t.ServerTLSConfig != nil {
		cfg := t.ServerTLSConfig.Clone()
		if len(cfg.NextProtos) == 0 {
			cfg.NextProtos = []string{"http/1.1"}
		}
		if cfg.MinVersion == 0 {
			cfg.MinVersion = tls.VersionTLS13
		}
		if cfg.MaxVersion == 0 {
			cfg.MaxVersion = tls.VersionTLS13
		}
		if len(cfg.CurvePreferences) == 0 {
			cfg.CurvePreferences = chromeLikeCurves()
		}
		return cfg, nil
	}

	t.serverTLSOnce.Do(func() {
		cert, err := generateSelfSignedCertificate()
		if err != nil {
			t.serverTLSErr = err
			return
		}
		t.serverTLS = &tls.Config{
			Certificates:     []tls.Certificate{cert},
			MinVersion:       tls.VersionTLS13,
			MaxVersion:       tls.VersionTLS13,
			NextProtos:       []string{"http/1.1"},
			CurvePreferences: chromeLikeCurves(),
		}
	})
	if t.serverTLSErr != nil {
		return nil, t.serverTLSErr
	}
	return t.serverTLS.Clone(), nil
}

func (t *WebSocketTransport) path() string {
	if t.Path == "" {
		return defaultWebSocketPath
	}
	if strings.HasPrefix(t.Path, "/") {
		return t.Path
	}
	return "/" + t.Path
}

func (t *WebSocketTransport) handshakeTimeout() time.Duration {
	if t.HandshakeTimeout > 0 {
		return t.HandshakeTimeout
	}
	return 3 * time.Second
}

func (t *WebSocketTransport) randomUserAgent() string {
	if len(browserUserAgents) == 0 {
		return ""
	}

	index, err := randomInt(t.randomReader(), len(browserUserAgents))
	if err != nil {
		return browserUserAgents[0]
	}
	return browserUserAgents[index]
}

func (t *WebSocketTransport) randomReader() io.Reader {
	if t.randomSource != nil {
		return t.randomSource
	}
	return rand.Reader
}

type webSocketListener struct {
	listener net.Listener
	server   *http.Server
	acceptCh chan Conn
	errCh    chan error
}

func (l *webSocketListener) Accept(ctx context.Context) (Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case conn := <-l.acceptCh:
		return conn, nil
	case err := <-l.errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *webSocketListener) Close() error {
	closeErr := l.listener.Close()
	_ = l.server.Close()
	return closeErr
}

func (l *webSocketListener) Addr() net.Addr {
	return l.listener.Addr()
}

type webSocketConn struct {
	conn *websocket.Conn

	minJitter    time.Duration
	maxJitter    time.Duration
	randomSource io.Reader
	sleep        func(time.Duration)

	writeMu  sync.Mutex
	closeMu  sync.Once
	closeErr error
}

var _ Conn = (*webSocketConn)(nil)

func (c *webSocketConn) Send(payload []byte) error {
	jitter, err := randomJitter(c.minJitter, c.maxJitter, c.randomSource)
	if err != nil {
		return err
	}
	if jitter > 0 {
		c.sleep(jitter)
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	return c.conn.WriteMessage(websocket.BinaryMessage, payload)
}

func (c *webSocketConn) Recv() ([]byte, error) {
	for {
		messageType, payload, err := c.conn.ReadMessage()
		if err != nil {
			return nil, err
		}
		if messageType == websocket.BinaryMessage {
			return payload, nil
		}
	}
}

func (c *webSocketConn) Close() error {
	c.closeMu.Do(func() {
		c.closeErr = c.conn.Close()
	})
	return c.closeErr
}

func websocketOrigin(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		host = "localhost"
	}
	return "https://" + host + "/"
}
