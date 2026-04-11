package probe

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

const (
	tokenOffset        = 32
	tokenEnd           = 64
	probeTokenLength   = 32
	defaultPeekTimeout = 250 * time.Millisecond
	certFileName       = "decoy-cert.pem"
	keyFileName        = "decoy-key.pem"
	openmeshNoticePath = "/.well-known/openmesh"
)

var (
	errSecretRequired     = errors.New("probe: network secret is required")
	errTokenLength        = errors.New("probe: token must be 32 bytes")
	errNoWrappedListener  = errors.New("probe: wrapped listener is required")
	errNoDecoyServer      = errors.New("probe: decoy server is required")
	errClosedListener     = errors.New("probe: listener closed")
	errInvalidCertificate = errors.New("probe: invalid stored certificate")

	//go:embed decoy/index.html
	decoyFS embed.FS
)

const operatorNotice = `This server is a node in the OpenMesh network, a volunteer-operated
censorship circumvention network. This server forwards encrypted traffic
on behalf of users seeking access to the open internet. The operator of
this server does not select, initiate, or store any of the content or
connections passing through it. For more information: openmesh.net
`

// TokenValidator generates and validates rotating probe tokens.
type TokenValidator struct {
	Now func() time.Time
}

// GenerateToken returns the current hour-bucket HMAC token for the shared secret.
func (v TokenValidator) GenerateToken(networkSecret []byte) []byte {
	now := v.timeNow()
	return v.generateForBucket(networkSecret, now.Unix()/3600)
}

// ValidateToken accepts tokens from the current hour bucket and the adjacent hours.
func (v TokenValidator) ValidateToken(token []byte, networkSecret []byte) bool {
	if len(token) != probeTokenLength || len(networkSecret) == 0 {
		return false
	}

	currentBucket := v.timeNow().Unix() / 3600
	for offset := int64(-1); offset <= 1; offset++ {
		expected := v.generateForBucket(networkSecret, currentBucket+offset)
		if hmac.Equal(token, expected) {
			return true
		}
	}
	return false
}

func (v TokenValidator) generateForBucket(networkSecret []byte, bucket int64) []byte {
	mac := hmac.New(sha256.New, networkSecret)
	var hourBytes [8]byte
	binary.BigEndian.PutUint64(hourBytes[:], uint64(bucket))
	_, _ = mac.Write(hourBytes[:])
	return mac.Sum(nil)
}

func (v TokenValidator) timeNow() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now().UTC()
}

// DecoyServer serves a minimal HTTP/HTTPS decoy page.
type DecoyServer struct {
	DataDir string
	Domain  string

	once      sync.Once
	tlsConfig *tls.Config
	tlsErr    error
}

// Handler returns the decoy HTTP handler.
func (s *DecoyServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(openmeshNoticePath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, operatorNotice)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(s.decoyHTML())
	})
	return mux
}

// TLSConfig returns the configured TLS settings for decoy HTTPS service.
func (s *DecoyServer) TLSConfig() (*tls.Config, error) {
	s.once.Do(func() {
		s.tlsConfig, s.tlsErr = s.buildTLSConfig()
	})
	if s.tlsErr != nil {
		return nil, s.tlsErr
	}
	return s.tlsConfig.Clone(), nil
}

// ServeConn serves a single plain HTTP or HTTPS decoy connection.
func (s *DecoyServer) ServeConn(conn net.Conn) error {
	buffered := newBufferedConn(conn)
	server := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}

	listener := newSingleConnListener(buffered)
	var servingListener net.Listener = listener
	if looksLikeTLSHandshake(buffered) {
		tlsConfig, err := s.TLSConfig()
		if err != nil {
			return err
		}
		servingListener = tls.NewListener(listener, tlsConfig)
	}

	err := server.Serve(servingListener)
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) || isClosedNetworkErr(err) {
		return nil
	}
	return err
}

func (s *DecoyServer) buildTLSConfig() (*tls.Config, error) {
	if s.Domain != "" {
		cacheDir, err := s.ensureDir(filepath.Join(s.resolveDataDir(), "autocert"))
		if err != nil {
			return nil, err
		}
		manager := &autocert.Manager{
			Cache:      autocert.DirCache(cacheDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.Domain),
		}
		return manager.TLSConfig(), nil
	}

	cert, err := s.loadOrCreateSelfSignedCert()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1", "h2"},
	}, nil
}

func (s *DecoyServer) loadOrCreateSelfSignedCert() (tls.Certificate, error) {
	dataDir, err := s.ensureDir(s.resolveDataDir())
	if err != nil {
		return tls.Certificate{}, err
	}

	certPath := filepath.Join(dataDir, certFileName)
	keyPath := filepath.Join(dataDir, keyFileName)

	if fileExists(certPath) && fileExists(keyPath) {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err == nil {
			return cert, nil
		}
		return tls.Certificate{}, errInvalidCertificate
	}

	certPEM, keyPEM, err := generateSelfSignedPEM()
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func (s *DecoyServer) resolveDataDir() string {
	if s.DataDir != "" {
		return s.DataDir
	}
	return filepath.Join(os.TempDir(), "openmesh-decoy")
}

func (s *DecoyServer) ensureDir(path string) (string, error) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return "", err
	}
	return path, nil
}

func (s *DecoyServer) decoyHTML() []byte {
	html, err := decoyFS.ReadFile("decoy/index.html")
	if err != nil {
		return []byte("<!DOCTYPE html><html><head><title>Welcome</title></head><body><p>This site is under construction.</p></body></html>")
	}
	return html
}

// ProbeGuard wraps a raw listener and exposes only connections with valid probe tokens.
type ProbeGuard struct {
	listener       net.Listener
	decoyServer    *DecoyServer
	tokenValidator TokenValidator
	networkSecret  []byte
	peekTimeout    time.Duration

	acceptCh chan net.Conn
	errCh    chan error
	closed   chan struct{}

	closeOnce sync.Once
}

// NewProbeGuard wraps a listener and begins dispatching inbound connections.
func NewProbeGuard(listener net.Listener, decoyServer *DecoyServer, validator TokenValidator, networkSecret []byte) (*ProbeGuard, error) {
	if listener == nil {
		return nil, errNoWrappedListener
	}
	if decoyServer == nil {
		return nil, errNoDecoyServer
	}
	if len(networkSecret) == 0 {
		return nil, errSecretRequired
	}

	guard := &ProbeGuard{
		listener:       listener,
		decoyServer:    decoyServer,
		tokenValidator: validator,
		networkSecret:  append([]byte(nil), networkSecret...),
		peekTimeout:    defaultPeekTimeout,
		acceptCh:       make(chan net.Conn, 32),
		errCh:          make(chan error, 1),
		closed:         make(chan struct{}),
	}
	go guard.run()
	return guard, nil
}

// Accept returns the next connection with a valid probe token.
func (g *ProbeGuard) Accept() (net.Conn, error) {
	select {
	case conn := <-g.acceptCh:
		return conn, nil
	case err := <-g.errCh:
		return nil, err
	case <-g.closed:
		return nil, net.ErrClosed
	}
}

// Close shuts down the guard and the wrapped listener.
func (g *ProbeGuard) Close() error {
	var closeErr error
	g.closeOnce.Do(func() {
		close(g.closed)
		closeErr = g.listener.Close()
	})
	return closeErr
}

// Addr returns the address of the wrapped listener.
func (g *ProbeGuard) Addr() net.Addr {
	return g.listener.Addr()
}

func (g *ProbeGuard) run() {
	for {
		conn, err := g.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case g.errCh <- err:
			default:
			}
			return
		}
		go g.dispatch(conn)
	}
}

func (g *ProbeGuard) dispatch(conn net.Conn) {
	buffered := newBufferedConn(conn)
	_ = buffered.SetReadDeadline(time.Now().Add(g.peekTimeout))
	peeked, err := buffered.Peek(tokenEnd)
	_ = buffered.SetReadDeadline(time.Time{})

	if err == nil && len(peeked) >= tokenEnd && g.tokenValidator.ValidateToken(peeked[tokenOffset:tokenEnd], g.networkSecret) {
		select {
		case g.acceptCh <- buffered:
		case <-g.closed:
			_ = buffered.Close()
		}
		return
	}

	if err != nil && !errors.Is(err, io.EOF) && !isTimeoutErr(err) {
		select {
		case g.errCh <- err:
		default:
		}
		_ = buffered.Close()
		return
	}

	_ = g.decoyServer.ServeConn(buffered)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func newBufferedConn(conn net.Conn) *bufferedConn {
	return &bufferedConn{
		Conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *bufferedConn) Peek(n int) ([]byte, error) {
	return c.reader.Peek(n)
}

type singleConnListener struct {
	conn net.Conn
	once sync.Once
	addr net.Addr
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{
		conn: conn,
		addr: conn.LocalAddr(),
	}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var accepted net.Conn
	l.once.Do(func() {
		accepted = l.conn
	})
	if accepted != nil {
		return accepted, nil
	}
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.addr
}

func looksLikeTLSHandshake(conn *bufferedConn) bool {
	header, err := conn.Peek(3)
	if err != nil && !errors.Is(err, io.EOF) && !isTimeoutErr(err) {
		return false
	}
	return len(header) >= 3 && header[0] == 0x16 && header[1] == 0x03
}

func generateSelfSignedPEM() ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "openmesh.local",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "openmesh.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return certPEM, keyPEM, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func isTimeoutErr(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isClosedNetworkErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "use of closed network connection")
}

// AcceptContext bridges the net.Listener-style guard with context-aware waits when needed.
func AcceptContext(ctx context.Context, guard *ProbeGuard) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}

	resultCh := make(chan result, 1)
	go func() {
		conn, err := guard.Accept()
		resultCh <- result{conn: conn, err: err}
	}()

	select {
	case out := <-resultCh:
		return out.conn, out.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
