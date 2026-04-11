package routing

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openmesh/core/dht"
)

// Circuit is a live multi-hop path that can open multiplexed TCP streams through the final hop.
type Circuit struct {
	builder *CircuitBuilder
	peers   []dht.PeerRecord
	hops    int

	circuitID [circuitIDSize]byte
	layers    []*clientLayer
	final     *clientLayer

	createdAt            time.Time
	lastActivity         time.Time
	keepaliveInterval    time.Duration
	rotateAfter          time.Duration
	maxBytesBeforeRotate int64

	mu      sync.RWMutex
	streams map[uint32]*Stream
	packets map[uint32]*DatagramConn
	closed  bool

	dispatchWG sync.WaitGroup
	closeOnce  sync.Once
	done       chan struct{}
	bytesUsed  int64
	rebuildMu  sync.Mutex
}

// CircuitSnapshot is a read-only view of circuit state for status reporting.
type CircuitSnapshot struct {
	Hops      int
	CreatedAt time.Time
	BytesUsed int64
	Streams   int
	Path      []dht.PeerRecord
}

// OpenStream opens a new multiplexed stream through the exit hop.
func (c *Circuit) OpenStream(dst string, port int) (*Stream, error) {
	if err := c.rotateIfNeeded(); err != nil {
		return nil, err
	}

	var lastErr error
	for attempt := 0; attempt < maxCircuitRecoveryAttempts; attempt++ {
		if c.needsRebuild() {
			if err := c.rebuildPath(true); err != nil {
				lastErr = err
				if attempt == maxCircuitRecoveryAttempts-1 || !isRecoverableCircuitErr(err) {
					return nil, err
				}
				continue
			}
		}

		stream, err := c.openStreamOnce(dst, port)
		if err == nil {
			return stream, nil
		}

		lastErr = err
		if attempt == maxCircuitRecoveryAttempts-1 || !isRecoverableCircuitErr(err) {
			return nil, err
		}

		if rebuildErr := c.rebuildPath(true); rebuildErr != nil {
			lastErr = rebuildErr
			if attempt == maxCircuitRecoveryAttempts-1 || !isRecoverableCircuitErr(rebuildErr) {
				return nil, rebuildErr
			}
		}
	}

	return nil, lastErr
}

func (c *Circuit) openStreamOnce(dst string, port int) (*Stream, error) {
	streamID, err := newStreamID()
	if err != nil {
		return nil, err
	}

	stream := newStream(streamID, c)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errCircuitClosed
	}
	c.streams[streamID] = stream
	final := c.final
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), c.builder.controlTimeout())
	defer cancel()

	_, err = final.request(ctx, protocolMessage{
		Type:     msgTypeConnect,
		StreamID: streamID,
		Dst:      dst,
		Port:     port,
	}, msgTypeConnected)
	if err != nil {
		c.removeStream(streamID)
		stream.signalClosed()
		return nil, err
	}

	c.markActivity()
	return stream, nil
}

// OpenPacketConn opens a UDP-style packet connection through the exit hop.
func (c *Circuit) OpenPacketConn(dst string, port int) (*DatagramConn, error) {
	if err := c.rotateIfNeeded(); err != nil {
		return nil, err
	}

	packetID, err := newStreamID()
	if err != nil {
		return nil, err
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(dst, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}

	packetConn := newDatagramConn(packetID, c, remoteAddr)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errCircuitClosed
	}
	c.packets[packetID] = packetConn
	final := c.final
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), c.builder.controlTimeout())
	defer cancel()

	_, err = final.request(ctx, protocolMessage{
		Type:     msgTypeUDPAssociate,
		StreamID: packetID,
		Dst:      dst,
		Port:     port,
	}, msgTypeUDPAssociated)
	if err != nil {
		c.removePacket(packetID)
		packetConn.signalClosed()
		return nil, err
	}

	c.markActivity()
	return packetConn, nil
}

// Close tears down the circuit and all active streams.
func (c *Circuit) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)

		c.mu.Lock()
		c.closed = true
		streams := make([]*Stream, 0, len(c.streams))
		for _, stream := range c.streams {
			streams = append(streams, stream)
		}
		packets := make([]*DatagramConn, 0, len(c.packets))
		for _, packetConn := range c.packets {
			packets = append(packets, packetConn)
		}
		layers := append([]*clientLayer(nil), c.layers...)
		c.mu.Unlock()

		for _, stream := range streams {
			stream.signalClosed()
		}
		for _, packetConn := range packets {
			packetConn.signalClosed()
		}
		closeLayers(layers)
		c.dispatchWG.Wait()
	})
	return nil
}

// Snapshot returns a consistent read-only summary of the current circuit state.
func (c *Circuit) Snapshot() CircuitSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := clonePeerRecords(c.peers)
	return CircuitSnapshot{
		Hops:      c.hops,
		CreatedAt: c.createdAt,
		BytesUsed: atomic.LoadInt64(&c.bytesUsed),
		Streams:   len(c.streams) + len(c.packets),
		Path:      path,
	}
}

func (c *Circuit) startFinalDispatch(layer *clientLayer) {
	c.dispatchWG.Add(1)
	go func(layer *clientLayer) {
		defer c.dispatchWG.Done()
		for {
			select {
			case <-c.done:
				return
			case message, ok := <-layer.unsolicitedCh:
				if !ok {
					return
				}
				c.handleFinalMessage(message)
			}
		}
	}(layer)
}

func (c *Circuit) handleFinalMessage(message protocolMessage) {
	c.markActivity()

	switch message.Type {
	case msgTypeStreamData:
		c.mu.RLock()
		stream := c.streams[message.StreamID]
		c.mu.RUnlock()
		if stream != nil {
			stream.deliver(message.Payload)
			atomic.AddInt64(&c.bytesUsed, int64(len(message.Payload)))
		}
	case msgTypeStreamClose:
		if stream := c.removeStream(message.StreamID); stream != nil {
			stream.signalClosed()
		}
	case msgTypeUDPData:
		c.mu.RLock()
		packetConn := c.packets[message.StreamID]
		c.mu.RUnlock()
		if packetConn != nil {
			packetConn.deliver(message.Payload)
			atomic.AddInt64(&c.bytesUsed, int64(len(message.Payload)))
		}
	case msgTypeUDPClose:
		if packetConn := c.removePacket(message.StreamID); packetConn != nil {
			packetConn.signalClosed()
		}
	}
}

func (c *Circuit) keepaliveLoop() {
	ticker := time.NewTicker(c.keepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if !c.idleFor(c.keepaliveInterval) {
				continue
			}
			_ = c.sendKeepalive()
		}
	}
}

func (c *Circuit) sendKeepalive() error {
	c.mu.RLock()
	if c.closed || c.final == nil {
		c.mu.RUnlock()
		return errCircuitClosed
	}
	final := c.final
	c.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), c.builder.controlTimeout())
	defer cancel()

	_, err := final.request(ctx, protocolMessage{Type: msgTypeKeepalivePing}, msgTypeKeepalivePong)
	if err == nil {
		c.markActivity()
	}
	return err
}

func (c *Circuit) writeStreamData(streamID uint32, payload []byte) error {
	c.mu.RLock()
	if c.closed || c.final == nil {
		c.mu.RUnlock()
		return errCircuitClosed
	}
	final := c.final
	c.mu.RUnlock()

	if err := final.sendMessage(protocolMessage{
		Type:     msgTypeStreamData,
		StreamID: streamID,
		Payload:  append([]byte(nil), payload...),
	}); err != nil {
		return err
	}

	atomic.AddInt64(&c.bytesUsed, int64(len(payload)))
	c.markActivity()
	return nil
}

func (c *Circuit) closeStream(streamID uint32) error {
	c.removeStream(streamID)

	c.mu.RLock()
	if c.closed || c.final == nil {
		c.mu.RUnlock()
		return errCircuitClosed
	}
	final := c.final
	c.mu.RUnlock()

	if err := final.sendMessage(protocolMessage{
		Type:     msgTypeStreamClose,
		StreamID: streamID,
	}); err != nil {
		return err
	}

	c.markActivity()
	return nil
}

func (c *Circuit) writePacketData(streamID uint32, payload []byte) error {
	c.mu.RLock()
	if c.closed || c.final == nil {
		c.mu.RUnlock()
		return errCircuitClosed
	}
	final := c.final
	c.mu.RUnlock()

	if err := final.sendMessage(protocolMessage{
		Type:     msgTypeUDPData,
		StreamID: streamID,
		Payload:  append([]byte(nil), payload...),
	}); err != nil {
		return err
	}

	atomic.AddInt64(&c.bytesUsed, int64(len(payload)))
	c.markActivity()
	return nil
}

func (c *Circuit) closePacket(streamID uint32) error {
	c.removePacket(streamID)

	c.mu.RLock()
	if c.closed || c.final == nil {
		c.mu.RUnlock()
		return errCircuitClosed
	}
	final := c.final
	c.mu.RUnlock()

	if err := final.sendMessage(protocolMessage{
		Type:     msgTypeUDPClose,
		StreamID: streamID,
	}); err != nil {
		return err
	}

	c.markActivity()
	return nil
}

func (c *Circuit) removeStream(streamID uint32) *Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	stream := c.streams[streamID]
	delete(c.streams, streamID)
	return stream
}

func (c *Circuit) removePacket(streamID uint32) *DatagramConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	packetConn := c.packets[streamID]
	delete(c.packets, streamID)
	return packetConn
}

func (c *Circuit) rotateIfNeeded() error {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return errCircuitClosed
	}
	needsRotate := c.builder.now().Sub(c.createdAt) >= c.rotateAfter ||
		atomic.LoadInt64(&c.bytesUsed) >= c.maxBytesBeforeRotate
	if !needsRotate || len(c.streams) > 0 || len(c.packets) > 0 {
		c.mu.RUnlock()
		return nil
	}
	c.mu.RUnlock()

	return c.rebuildPath(false)
}

func (c *Circuit) idleFor(duration time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.builder.now().Sub(c.lastActivity) >= duration
}

func (c *Circuit) markActivity() {
	c.mu.Lock()
	c.lastActivity = c.builder.now()
	c.mu.Unlock()
}

func (c *Circuit) needsRebuild() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed || c.final == nil {
		return false
	}

	select {
	case <-c.final.closedCh:
		return true
	default:
		return false
	}
}

func (c *Circuit) rebuildPath(closeStreams bool) error {
	c.rebuildMu.Lock()
	defer c.rebuildMu.Unlock()

	path, err := c.builder.buildPath(c.peers, c.hops)
	if err != nil {
		return err
	}

	var oldLayers []*clientLayer
	var streams []*Stream
	var packets []*DatagramConn

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		closeLayers(path.layers)
		return errCircuitClosed
	}

	oldLayers = c.layers
	c.circuitID = path.circuitID
	c.layers = path.layers
	c.final = path.layers[len(path.layers)-1]
	c.createdAt = c.builder.now()
	c.lastActivity = c.createdAt
	atomic.StoreInt64(&c.bytesUsed, 0)

	if closeStreams {
		streams = make([]*Stream, 0, len(c.streams))
		for streamID, stream := range c.streams {
			delete(c.streams, streamID)
			streams = append(streams, stream)
		}
		packets = make([]*DatagramConn, 0, len(c.packets))
		for streamID, packetConn := range c.packets {
			delete(c.packets, streamID)
			packets = append(packets, packetConn)
		}
	}
	c.mu.Unlock()

	c.startFinalDispatch(c.final)
	for _, stream := range streams {
		stream.signalClosed()
	}
	for _, packetConn := range packets {
		packetConn.signalClosed()
	}
	closeLayers(oldLayers)
	return nil
}

func isRecoverableCircuitErr(err error) bool {
	if err == nil {
		return false
	}

	switch {
	case errors.Is(err, io.EOF),
		errors.Is(err, net.ErrClosed),
		errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return true
	}

	switch err {
	case errCircuitClosed,
		errNoTunnel,
		errUnexpectedPacket,
		errUnexpectedMessage:
		return true
	case errPortNotAllowed,
		errBlockedDestination,
		errRelayCannotExit,
		errInvalidHopCount,
		errInsufficientPeers,
		errMissingPeerAddress,
		errInvalidPeerPubKey:
		return false
	default:
		return true
	}
}

// Stream is a multiplexed byte stream carried over a circuit.
type Stream struct {
	id      uint32
	circuit *Circuit

	readCh  chan []byte
	closeCh chan struct{}

	readMu  sync.Mutex
	readBuf []byte

	closeOnce sync.Once
}

func newStream(id uint32, circuit *Circuit) *Stream {
	return &Stream{
		id:      id,
		circuit: circuit,
		readCh:  make(chan []byte, 32),
		closeCh: make(chan struct{}),
	}
}

// Read reads data delivered from the exit hop.
func (s *Stream) Read(p []byte) (int, error) {
	for {
		s.readMu.Lock()
		if len(s.readBuf) > 0 {
			n := copy(p, s.readBuf)
			s.readBuf = s.readBuf[n:]
			s.readMu.Unlock()
			return n, nil
		}
		s.readMu.Unlock()

		select {
		case payload := <-s.readCh:
			if len(payload) == 0 {
				continue
			}
			s.readMu.Lock()
			s.readBuf = append(s.readBuf, payload...)
			s.readMu.Unlock()
		case <-s.closeCh:
			select {
			case payload := <-s.readCh:
				if len(payload) == 0 {
					return 0, io.EOF
				}
				s.readMu.Lock()
				s.readBuf = append(s.readBuf, payload...)
				s.readMu.Unlock()
			default:
				return 0, io.EOF
			}
		}
	}
}

// Write sends data through the circuit to the exit hop.
func (s *Stream) Write(p []byte) (int, error) {
	select {
	case <-s.closeCh:
		return 0, errStreamClosed
	default:
	}

	if err := s.circuit.writeStreamData(s.id, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the multiplexed stream.
func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		_ = s.circuit.closeStream(s.id)
		close(s.closeCh)
	})
	return nil
}

func (s *Stream) deliver(payload []byte) {
	data := append([]byte(nil), payload...)
	select {
	case <-s.closeCh:
		return
	case s.readCh <- data:
	}
}

func (s *Stream) signalClosed() {
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
}

func newStreamID() (uint32, error) {
	var payload [4]byte
	if _, err := io.ReadFull(rand.Reader, payload[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(payload[:]), nil
}
