package routing

import (
	"context"
	"math"
	"net"
	"sync"
	"time"

	"github.com/openmesh/core/transport"
)

type tokenBucket struct {
	rateBytesPerSecond float64
	capacity           float64
	tokens             float64
	lastRefill         time.Time
	now                func() time.Time
	sleep              func(time.Duration)
	mu                 sync.Mutex
}

func newTokenBucket(limitMbps int) *tokenBucket {
	if limitMbps <= 0 {
		return nil
	}

	rate := float64(limitMbps) * 125000
	capacity := math.Max(rate, 64*1024)
	now := time.Now
	return &tokenBucket{
		rateBytesPerSecond: rate,
		capacity:           capacity,
		tokens:             capacity,
		lastRefill:         now(),
		now:                now,
		sleep:              time.Sleep,
	}
}

func (b *tokenBucket) wait(size int) {
	if b == nil || size <= 0 {
		return
	}

	required := float64(size)
	for {
		b.mu.Lock()
		now := b.now()
		elapsed := now.Sub(b.lastRefill).Seconds()
		if elapsed > 0 {
			b.tokens = math.Min(b.capacity, b.tokens+(elapsed*b.rateBytesPerSecond))
			b.lastRefill = now
		}

		if b.tokens >= required {
			b.tokens -= required
			b.mu.Unlock()
			return
		}

		deficit := required - b.tokens
		wait := time.Duration(deficit / b.rateBytesPerSecond * float64(time.Second))
		if wait <= 0 {
			wait = time.Millisecond
		}
		b.mu.Unlock()
		b.sleep(wait)
	}
}

func wrapTransport(limitMbps int, base transport.Transport) transport.Transport {
	if base == nil || limitMbps <= 0 {
		return base
	}
	return &throttledTransport{
		base:      base,
		limitMbps: limitMbps,
	}
}

func wrapListener(limitMbps int, base transport.Listener) transport.Listener {
	if base == nil || limitMbps <= 0 {
		return base
	}
	return &throttledListener{
		base:      base,
		limitMbps: limitMbps,
	}
}

func wrapTransportConn(limitMbps int, base transport.Conn) transport.Conn {
	if base == nil || limitMbps <= 0 {
		return base
	}
	return &throttledTransportConn{
		base:    base,
		limiter: newTokenBucket(limitMbps),
	}
}

func wrapNetConn(limitMbps int, base net.Conn) net.Conn {
	if base == nil || limitMbps <= 0 {
		return base
	}
	return &throttledNetConn{
		Conn:    base,
		limiter: newTokenBucket(limitMbps),
	}
}

type throttledTransport struct {
	base      transport.Transport
	limitMbps int
}

func (t *throttledTransport) Dial(addr string) (transport.Conn, error) {
	conn, err := t.base.Dial(addr)
	if err != nil {
		return nil, err
	}
	return wrapTransportConn(t.limitMbps, conn), nil
}

func (t *throttledTransport) Listen(addr string) (transport.Listener, error) {
	listener, err := t.base.Listen(addr)
	if err != nil {
		return nil, err
	}
	return wrapListener(t.limitMbps, listener), nil
}

type throttledListener struct {
	base      transport.Listener
	limitMbps int
}

func (l *throttledListener) Accept(ctx context.Context) (transport.Conn, error) {
	conn, err := l.base.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return wrapTransportConn(l.limitMbps, conn), nil
}

func (l *throttledListener) Close() error {
	return l.base.Close()
}

func (l *throttledListener) Addr() net.Addr {
	return l.base.Addr()
}

type throttledTransportConn struct {
	base    transport.Conn
	limiter *tokenBucket
}

func (c *throttledTransportConn) Send(payload []byte) error {
	c.limiter.wait(len(payload))
	return c.base.Send(payload)
}

func (c *throttledTransportConn) Recv() ([]byte, error) {
	payload, err := c.base.Recv()
	if err != nil {
		return nil, err
	}
	c.limiter.wait(len(payload))
	return payload, nil
}

func (c *throttledTransportConn) Close() error {
	return c.base.Close()
}

type throttledNetConn struct {
	net.Conn
	limiter *tokenBucket
}

func (c *throttledNetConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.limiter.wait(n)
	}
	return n, err
}

func (c *throttledNetConn) Write(p []byte) (int, error) {
	c.limiter.wait(len(p))
	return c.Conn.Write(p)
}
