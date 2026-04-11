package routing

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"time"

	"github.com/openmesh/core/dht"
	"github.com/openmesh/core/handshake"
	"github.com/openmesh/core/transport"
)

type builtPath struct {
	circuitID [circuitIDSize]byte
	layers    []*clientLayer
}

// CircuitBuilder establishes telescoping multi-hop circuits over the transport and Noise layers.
type CircuitBuilder struct {
	Transport            transport.Transport
	Handshaker           *handshake.Handshaker
	LocalPrivateKey      []byte
	ControlTimeout       time.Duration
	KeepaliveInterval    time.Duration
	RotateAfter          time.Duration
	MaxBytesBeforeRotate int64
	Now                  func() time.Time
	Random               io.Reader
}

// Build creates a 1-, 2-, or 3-hop circuit using the provided peer path.
func (b *CircuitBuilder) Build(peers []dht.PeerRecord, hops int) (*Circuit, error) {
	if hops < 1 || hops > 3 {
		return nil, errInvalidHopCount
	}
	if len(peers) < hops {
		return nil, errInsufficientPeers
	}
	if err := b.preflightPeers(peers[:hops]); err != nil {
		return nil, err
	}

	path, err := b.buildPath(peers[:hops], hops)
	if err != nil {
		return nil, err
	}

	circuit := &Circuit{
		builder:              b,
		peers:                clonePeerRecords(peers[:hops]),
		hops:                 hops,
		circuitID:            path.circuitID,
		layers:               path.layers,
		final:                path.layers[len(path.layers)-1],
		createdAt:            b.now(),
		lastActivity:         b.now(),
		keepaliveInterval:    b.keepaliveInterval(),
		rotateAfter:          b.rotateAfter(),
		maxBytesBeforeRotate: b.rotateBytes(),
		streams:              make(map[uint32]*Stream),
		packets:              make(map[uint32]*DatagramConn),
		done:                 make(chan struct{}),
	}

	circuit.startFinalDispatch(circuit.final)
	go circuit.keepaliveLoop()
	return circuit, nil
}

func (b *CircuitBuilder) preflightPeers(peers []dht.PeerRecord) error {
	timeout := b.probeTimeout()
	for _, peer := range peers {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		_, err := probePeer(ctx, b.Transport, b.Handshaker, b.LocalPrivateKey, peer)
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *CircuitBuilder) buildPath(peers []dht.PeerRecord, hops int) (builtPath, error) {
	if b.Transport == nil {
		return builtPath{}, errNoTransport
	}
	if len(b.LocalPrivateKey) == 0 {
		return builtPath{}, errNoPrivateKey
	}

	circuitID, err := b.newCircuitID()
	if err != nil {
		return builtPath{}, err
	}

	path := builtPath{
		circuitID: circuitID,
		layers:    make([]*clientLayer, 0, hops),
	}

	peerAddr, err := peerAddress(peers[0])
	if err != nil {
		return builtPath{}, err
	}

	conn, err := b.Transport.Dial(peerAddr)
	if err != nil {
		return builtPath{}, err
	}

	serverPubKey, err := peerPublicKey(peers[0])
	if err != nil {
		_ = conn.Close()
		return builtPath{}, err
	}

	session, err := b.clientHandshaker().Initiate(conn, serverPubKey)
	if err != nil {
		_ = conn.Close()
		return builtPath{}, err
	}

	path.layers = append(path.layers, newClientLayer(conn, session, uint8(hops), circuitID))

	for i := 1; i < hops; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), b.controlTimeout())
		tunnel, err := path.layers[i-1].openTunnel(ctx, peers[i])
		cancel()
		if err != nil {
			closeLayers(path.layers)
			return builtPath{}, err
		}

		serverPubKey, err := peerPublicKey(peers[i])
		if err != nil {
			_ = tunnel.Close()
			closeLayers(path.layers)
			return builtPath{}, err
		}

		session, err := b.clientHandshaker().Initiate(tunnel, serverPubKey)
		if err != nil {
			_ = tunnel.Close()
			closeLayers(path.layers)
			return builtPath{}, err
		}
		path.layers = append(path.layers, newClientLayer(tunnel, session, uint8(hops-i), circuitID))
	}

	return path, nil
}

func (b *CircuitBuilder) clientHandshaker() *handshake.Handshaker {
	if b.Handshaker == nil {
		return &handshake.Handshaker{StaticPrivateKey: append([]byte(nil), b.LocalPrivateKey...)}
	}
	clone := *b.Handshaker
	clone.StaticPrivateKey = append([]byte(nil), b.LocalPrivateKey...)
	return &clone
}

func (b *CircuitBuilder) controlTimeout() time.Duration {
	if b.ControlTimeout > 0 {
		return b.ControlTimeout
	}
	return defaultControlTimeout
}

func (b *CircuitBuilder) keepaliveInterval() time.Duration {
	if b.KeepaliveInterval > 0 {
		return b.KeepaliveInterval
	}
	return defaultKeepaliveInterval
}

func (b *CircuitBuilder) rotateAfter() time.Duration {
	if b.RotateAfter > 0 {
		return b.RotateAfter
	}
	return defaultRotateAfter
}

func (b *CircuitBuilder) rotateBytes() int64 {
	if b.MaxBytesBeforeRotate > 0 {
		return b.MaxBytesBeforeRotate
	}
	return defaultRotateBytes
}

func (b *CircuitBuilder) probeTimeout() time.Duration {
	if b.ControlTimeout > 0 {
		return b.ControlTimeout
	}
	return defaultProbeTimeout
}

func (b *CircuitBuilder) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func (b *CircuitBuilder) randomReader() io.Reader {
	if b.Random != nil {
		return b.Random
	}
	return rand.Reader
}

func (b *CircuitBuilder) newCircuitID() ([circuitIDSize]byte, error) {
	var circuitID [circuitIDSize]byte
	if _, err := io.ReadFull(b.randomReader(), circuitID[:]); err != nil {
		return [circuitIDSize]byte{}, err
	}
	return circuitID, nil
}

func peerAddress(peer dht.PeerRecord) (string, error) {
	for _, addr := range peer.Addrs {
		if addr != "" {
			return addr, nil
		}
	}
	return "", errMissingPeerAddress
}

func peerPublicKey(peer dht.PeerRecord) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(peer.PubKey)
	if err != nil || len(decoded) == 0 {
		return nil, errInvalidPeerPubKey
	}
	return decoded, nil
}

func closeLayers(layers []*clientLayer) {
	for i := len(layers) - 1; i >= 0; i-- {
		_ = layers[i].Close()
	}
}

func clonePeerRecords(records []dht.PeerRecord) []dht.PeerRecord {
	cloned := make([]dht.PeerRecord, 0, len(records))
	for _, record := range records {
		record.Addrs = append([]string(nil), record.Addrs...)
		record.ExitPolicy.Ports = append([]int(nil), record.ExitPolicy.Ports...)
		cloned = append(cloned, record)
	}
	return cloned
}
