package routing

import (
	"net"
	"sync"
)

type packetSession struct {
	conn    net.PacketConn
	remote  net.Addr
	writeMu sync.Mutex
}

func (s *packetSession) write(payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if writer, ok := s.conn.(interface{ Write([]byte) (int, error) }); ok {
		_, err := writer.Write(payload)
		return err
	}
	_, err := s.conn.WriteTo(payload, s.remote)
	return err
}

func (s *packetSession) close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}
