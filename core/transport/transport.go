package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	alpnH3               = "h3"
	frameHeaderSize      = 8
	defaultDialTimeout   = 5 * time.Second
	defaultMinJitter     = 1 * time.Millisecond
	defaultMaxJitter     = 30 * time.Millisecond
	defaultHandshakeIdle = 5 * time.Second
	defaultMaxIdle       = 30 * time.Second
	maxFrameSize         = 16 << 20
)

var (
	defaultPaddingSizes = []int{256, 512, 1024, 1400}

	errInvalidFrame  = errors.New("transport: invalid framed payload")
	errFrameTooLarge = errors.New("transport: framed payload exceeds maximum size")
)

// Transport establishes outbound connections and listeners for a specific wire protocol.
type Transport interface {
	Dial(addr string) (Conn, error)
	Listen(addr string) (Listener, error)
}

// Conn is a message-oriented transport connection.
type Conn interface {
	Send([]byte) error
	Recv() ([]byte, error)
	Close() error
}

// Listener accepts inbound transport connections.
type Listener interface {
	Accept(ctx context.Context) (Conn, error)
	Close() error
	Addr() net.Addr
}

// QUICTransport implements the transport contract over QUIC with HTTP/3-style TLS settings.
type QUICTransport struct {
	ClientTLSConfig    *tls.Config
	ServerTLSConfig    *tls.Config
	QUICConfig         *quic.Config
	BindInterfaceName  string
	BindInterfaceIndex int

	PaddingSizes []int
	MinJitter    time.Duration
	MaxJitter    time.Duration
	DialTimeout  time.Duration

	randomSource io.Reader
	sleep        func(time.Duration)

	serverTLSOnce sync.Once
	serverTLS     *tls.Config
	serverTLSErr  error
}

var _ Transport = (*QUICTransport)(nil)

// NewQUICTransport builds a QUIC transport with spec-aligned defaults.
func NewQUICTransport() *QUICTransport {
	return &QUICTransport{}
}

// Dial connects to a remote QUIC listener and opens the first bidirectional stream.
func (t *QUICTransport) Dial(addr string) (Conn, error) {
	ctx := context.Background()
	timeout := t.DialTimeout
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	listenConfig := newBoundListenConfig(t.BindInterfaceName, t.BindInterfaceIndex)
	packetConn, err := listenConfig.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return nil, err
	}

	qconn, err := quic.Dial(ctx, packetConn, udpAddr, t.clientTLSConfig(addr), t.quicConfig())
	if err != nil {
		_ = packetConn.Close()
		return nil, err
	}

	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		_ = packetConn.Close()
		_ = qconn.CloseWithError(0, "stream open failed")
		return nil, err
	}

	return t.wrapConn(qconn, stream, packetConn), nil
}

// Listen starts a QUIC listener on the provided address.
func (t *QUICTransport) Listen(addr string) (Listener, error) {
	serverTLSConfig, err := t.serverTLSConfig()
	if err != nil {
		return nil, err
	}

	listener, err := quic.ListenAddr(addr, serverTLSConfig, t.quicConfig())
	if err != nil {
		return nil, err
	}

	return &quicListener{listener: listener, transport: t}, nil
}

func (t *QUICTransport) wrapConn(qconn *quic.Conn, stream *quic.Stream, packetConn net.PacketConn) *quicConn {
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
		randomSource = cryptorand.Reader
	}

	sleep := t.sleep
	if sleep == nil {
		sleep = time.Sleep
	}

	return &quicConn{
		conn:         qconn,
		stream:       stream,
		packetConn:   packetConn,
		paddingSizes: paddingSizes,
		minJitter:    minJitter,
		maxJitter:    maxJitter,
		randomSource: randomSource,
		sleep:        sleep,
	}
}

func (t *QUICTransport) clientTLSConfig(addr string) *tls.Config {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	if t.ClientTLSConfig == nil {
		return defaultQUICClientTLSConfig(host)
	}

	cfg := t.ClientTLSConfig.Clone()
	if len(cfg.NextProtos) == 0 {
		cfg.NextProtos = []string{alpnH3}
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
	if cfg.ServerName == "" && host != "" {
		cfg.ServerName = host
	}
	return cfg
}

func (t *QUICTransport) serverTLSConfig() (*tls.Config, error) {
	if t.ServerTLSConfig != nil {
		cfg := t.ServerTLSConfig.Clone()
		if len(cfg.NextProtos) == 0 {
			cfg.NextProtos = []string{alpnH3}
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
		t.serverTLS, t.serverTLSErr = defaultQUICServerTLSConfig()
	})
	if t.serverTLSErr != nil {
		return nil, t.serverTLSErr
	}
	return t.serverTLS.Clone(), nil
}

func (t *QUICTransport) quicConfig() *quic.Config {
	if t.QUICConfig == nil {
		return defaultQUICConfig()
	}
	cfg := *t.QUICConfig
	if cfg.HandshakeIdleTimeout == 0 {
		cfg.HandshakeIdleTimeout = defaultHandshakeIdle
	}
	if cfg.MaxIdleTimeout == 0 {
		cfg.MaxIdleTimeout = defaultMaxIdle
	}
	return &cfg
}

type quicListener struct {
	listener  *quic.Listener
	transport *QUICTransport
}

func (l *quicListener) Accept(ctx context.Context) (Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	qconn, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := qconn.AcceptStream(ctx)
	if err != nil {
		_ = qconn.CloseWithError(0, "stream accept failed")
		return nil, err
	}

	return l.transport.wrapConn(qconn, stream, nil), nil
}

func (l *quicListener) Close() error {
	return l.listener.Close()
}

func (l *quicListener) Addr() net.Addr {
	return l.listener.Addr()
}

type quicConn struct {
	conn       *quic.Conn
	stream     *quic.Stream
	packetConn net.PacketConn

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

var _ Conn = (*quicConn)(nil)

func (c *quicConn) Send(payload []byte) error {
	frame, err := c.encodeFrame(payload)
	if err != nil {
		return err
	}

	if jitter, err := c.nextJitter(); err != nil {
		return err
	} else if jitter > 0 {
		c.sleep(jitter)
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	return writeAll(c.stream, frame)
}

func (c *quicConn) Recv() ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	return decodeFrame(c.stream)
}

func (c *quicConn) Close() error {
	c.closeMu.Do(func() {
		if err := c.stream.Close(); err != nil {
			c.closeErr = err
		}
		c.stream.CancelRead(0)
		if c.packetConn != nil {
			if err := c.packetConn.Close(); err != nil && c.closeErr == nil {
				c.closeErr = err
			}
		}
	})
	return c.closeErr
}

func (c *quicConn) encodeFrame(payload []byte) ([]byte, error) {
	return encodePaddedFrame(payload, c.paddingSizes, c.randomSource)
}

func (c *quicConn) normalizedFrameSize(payloadLen int) (int, error) {
	return normalizedFrameSize(payloadLen, c.paddingSizes, c.randomSource)
}

func (c *quicConn) nextJitter() (time.Duration, error) {
	return randomJitter(c.minJitter, c.maxJitter, c.randomSource)
}

func decodeFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, frameHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	frameLen := int(binary.BigEndian.Uint32(header[:4]))
	payloadLen := int(binary.BigEndian.Uint32(header[4:8]))
	if frameLen < frameHeaderSize || payloadLen < 0 || payloadLen > frameLen-frameHeaderSize {
		return nil, errInvalidFrame
	}
	if frameLen > maxFrameSize {
		return nil, errFrameTooLarge
	}

	body := make([]byte, frameLen-frameHeaderSize)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append([]byte(nil), body[:payloadLen]...), nil
}

func writeAll(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := w.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[written:]
	}
	return nil
}

func defaultQUICClientTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // Authentication is layered on top in the Noise handshake.
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{alpnH3},
		CurvePreferences:   chromeLikeCurves(),
		ClientSessionCache: tls.NewLRUClientSessionCache(32),
	}
}

func defaultQUICServerTLSConfig() (*tls.Config, error) {
	cert, err := generateSelfSignedCertificate()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		NextProtos:       []string{alpnH3},
		CurvePreferences: chromeLikeCurves(),
	}, nil
}

func chromeLikeCurves() []tls.CurveID {
	// Go doesn't let us fully clone Chrome's ClientHello, but TLS 1.3 + h3 + common curve ordering
	// gets us close using the stock library.
	return []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
}

func defaultQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: defaultHandshakeIdle,
		MaxIdleTimeout:       defaultMaxIdle,
		KeepAlivePeriod:      15 * time.Second,
	}
}

func generateSelfSignedCertificate() (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "openmesh.local",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "openmesh.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func cloneIntSlice(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]int, len(values))
	copy(cloned, values)
	return cloned
}
