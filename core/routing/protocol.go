package routing

import (
	"encoding/binary"
	"encoding/json"
	"time"
)

const (
	circuitIDSize              = 16
	defaultControlTimeout      = 5 * time.Second
	defaultKeepaliveInterval   = 30 * time.Second
	defaultRotateAfter         = 10 * time.Minute
	defaultRotateBytes         = 50 << 20
	maxCircuitRecoveryAttempts = 3

	msgTypeExtend        = "extend"
	msgTypeExtended      = "extended"
	msgTypeTunnelData    = "tunnel_data"
	msgTypeTunnelClose   = "tunnel_close"
	msgTypeConnect       = "connect"
	msgTypeConnected     = "connected"
	msgTypeStreamData    = "stream_data"
	msgTypeStreamClose   = "stream_close"
	msgTypeUDPAssociate  = "udp_associate"
	msgTypeUDPAssociated = "udp_associated"
	msgTypeUDPData       = "udp_data"
	msgTypeUDPClose      = "udp_close"
	msgTypeKeepalivePing = "keepalive_ping"
	msgTypeKeepalivePong = "keepalive_pong"
)

const onionHeaderSize = 1 + circuitIDSize + 4

type onionPacket struct {
	HopCount  uint8
	CircuitID [circuitIDSize]byte
	Payload   []byte
}

type protocolMessage struct {
	Type         string `json:"type"`
	RequestID    string `json:"request_id,omitempty"`
	StreamID     uint32 `json:"stream_id,omitempty"`
	NextID       string `json:"next_id,omitempty"`
	NextAddr     string `json:"next_addr,omitempty"`
	NextPubKey   string `json:"next_pubkey,omitempty"`
	Dst          string `json:"dst,omitempty"`
	Port         int    `json:"port,omitempty"`
	Payload      []byte `json:"payload,omitempty"`
	Error        string `json:"error,omitempty"`
	FailedPeerID string `json:"failed_peer_id,omitempty"`
	FailedAddr   string `json:"failed_addr,omitempty"`
	FailedStage  string `json:"failed_stage,omitempty"`
}

func encodeOnionPacket(packet onionPacket) []byte {
	encoded := make([]byte, onionHeaderSize+len(packet.Payload))
	encoded[0] = packet.HopCount
	copy(encoded[1:1+circuitIDSize], packet.CircuitID[:])
	binary.BigEndian.PutUint32(encoded[1+circuitIDSize:1+circuitIDSize+4], uint32(len(packet.Payload)))
	copy(encoded[onionHeaderSize:], packet.Payload)
	return encoded
}

func decodeOnionPacket(payload []byte) (onionPacket, bool) {
	if len(payload) < onionHeaderSize {
		return onionPacket{}, false
	}

	var packet onionPacket
	packet.HopCount = payload[0]
	copy(packet.CircuitID[:], payload[1:1+circuitIDSize])

	payloadLength := binary.BigEndian.Uint32(payload[1+circuitIDSize : onionHeaderSize])
	if int(payloadLength) != len(payload)-onionHeaderSize {
		return onionPacket{}, false
	}
	packet.Payload = append([]byte(nil), payload[onionHeaderSize:]...)
	return packet, true
}

func encodeProtocolMessage(message protocolMessage) ([]byte, error) {
	return json.Marshal(message)
}

func decodeProtocolMessage(payload []byte) (protocolMessage, error) {
	var message protocolMessage
	if err := json.Unmarshal(payload, &message); err != nil {
		return protocolMessage{}, err
	}
	return message, nil
}
