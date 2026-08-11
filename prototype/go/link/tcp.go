package link

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const maxTCPFrameSize = 16 << 20

type TCP struct {
	Dialer net.Dialer
	MTU    int
}

func (t *TCP) Name() string                                  { return "tcp" }
func (t *TCP) Open(context.Context) error                    { return nil }
func (t *TCP) Close() error                                  { return nil }
func (t *TCP) Discover(context.Context) ([]Candidate, error) { return nil, ErrUnsupported }
func (t *TCP) Capabilities() Capabilities {
	mtu := t.MTU
	if mtu == 0 {
		mtu = 1500
	}
	return Capabilities{MTU: mtu, FullDuplex: true, Reliable: true}
}

func (t *TCP) Dial(ctx context.Context, peer PeerHint) (Conn, error) {
	conn, err := t.Dialer.DialContext(ctx, "tcp", peer.Address)
	if err != nil {
		return nil, err
	}
	return &tcpConn{Conn: conn}, nil
}

func (t *TCP) Listen(_ context.Context, address string) (Listener, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return &tcpListener{Listener: listener}, nil
}

type tcpListener struct{ net.Listener }

func (l *tcpListener) Accept(ctx context.Context) (Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tcp, ok := l.Listener.(*net.TCPListener); ok {
		restore := deadlineFromContext(ctx, tcp.SetDeadline)
		defer restore()
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return &tcpConn{Conn: conn}, nil
}

type tcpConn struct{ net.Conn }

func (c *tcpConn) Send(ctx context.Context, payload []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(payload) > maxTCPFrameSize {
		return fmt.Errorf("link: frame exceeds %d bytes", maxTCPFrameSize)
	}
	restore := deadlineFromContext(ctx, c.SetWriteDeadline)
	defer restore()
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if err := writeAll(c.Conn, header); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	err := writeAll(c.Conn, payload)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (c *tcpConn) Receive(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	restore := deadlineFromContext(ctx, c.SetReadDeadline)
	defer restore()
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	size := binary.BigEndian.Uint32(header)
	if size > maxTCPFrameSize {
		return nil, errors.New("link: incoming frame too large")
	}
	payload := make([]byte, size)
	_, err := io.ReadFull(c.Conn, payload)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return payload, err
}

func deadlineFromContext(ctx context.Context, set func(time.Time) error) func() {
	if deadline, ok := ctx.Deadline(); ok {
		_ = set(deadline)
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		_ = set(time.Now())
	})
	return func() {
		if !stop() {
			<-done
		}
		_ = set(time.Time{})
	}
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[written:]
	}
	return nil
}
