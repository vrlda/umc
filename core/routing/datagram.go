package routing

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

type packetMessage struct {
	payload []byte
	addr    net.Addr
}

// DatagramConn is a multiplexed UDP-style packet connection carried over a circuit.
type DatagramConn struct {
	id      uint32
	circuit *Circuit
	remote  net.Addr
	local   net.Addr

	readCh  chan packetMessage
	closeCh chan struct{}

	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time

	closeOnce sync.Once
}

func newDatagramConn(id uint32, circuit *Circuit, remote net.Addr) *DatagramConn {
	return &DatagramConn{
		id:      id,
		circuit: circuit,
		remote:  remote,
		local:   &net.UDPAddr{IP: net.IPv4zero, Port: 0},
		readCh:  make(chan packetMessage, 64),
		closeCh: make(chan struct{}),
	}
}

func (c *DatagramConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		message, ok, err := c.waitReadMessage()
		if err != nil {
			return 0, nil, err
		}
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, message.payload)
		return n, message.addr, nil
	}
}

func (c *DatagramConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closeCh:
		return 0, net.ErrClosed
	default:
	}

	if addr == nil {
		addr = c.remote
	}
	if c.remote != nil && addr != nil && addr.String() != c.remote.String() {
		return 0, errors.New("routing: datagram connection is bound to a different remote address")
	}

	if err := c.circuit.writePacketData(c.id, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *DatagramConn) Close() error {
	c.closeOnce.Do(func() {
		_ = c.circuit.closePacket(c.id)
		close(c.closeCh)
	})
	return nil
}

func (c *DatagramConn) LocalAddr() net.Addr {
	return c.local
}

func (c *DatagramConn) SetDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	return nil
}

func (c *DatagramConn) SetReadDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = deadline
	return nil
}

func (c *DatagramConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.writeDeadline = deadline
	return nil
}

func (c *DatagramConn) deliver(payload []byte) {
	message := packetMessage{
		payload: append([]byte(nil), payload...),
		addr:    c.remote,
	}
	select {
	case <-c.closeCh:
		return
	case c.readCh <- message:
	}
}

func (c *DatagramConn) signalClosed() {
	c.closeOnce.Do(func() {
		close(c.closeCh)
	})
}

func (c *DatagramConn) waitReadMessage() (packetMessage, bool, error) {
	c.deadlineMu.RLock()
	deadline := c.readDeadline
	c.deadlineMu.RUnlock()

	if deadline.IsZero() {
		select {
		case message := <-c.readCh:
			return message, true, nil
		case <-c.closeCh:
			select {
			case message := <-c.readCh:
				return message, true, nil
			default:
				return packetMessage{}, false, nil
			}
		}
	}

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	select {
	case message := <-c.readCh:
		return message, true, nil
	case <-c.closeCh:
		select {
		case message := <-c.readCh:
			return message, true, nil
		default:
			return packetMessage{}, false, nil
		}
	case <-timer.C:
		return packetMessage{}, false, context.DeadlineExceeded
	}
}
