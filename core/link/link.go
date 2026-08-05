package link

import (
	"context"
	"errors"
	"time"

	"github.com/openmesh/core/identity"
)

type Capabilities struct {
	MTU                    int
	BandwidthBitsPerSecond int64
	EstimatedLatency       time.Duration
	ConnectionCost         uint32
	EnergyCost             uint32
	Broadcast              bool
	FullDuplex             bool
	Reliable               bool
}

type PeerHint struct {
	Identity identity.ID
	Address  string
	Metadata map[string]string
}

type Candidate struct {
	Adapter string
	Peer    PeerHint
}

// Conn carries opaque frames over one transport link.
type Conn interface {
	Send(context.Context, []byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
}

type Listener interface {
	Accept(context.Context) (Conn, error)
	Close() error
}

// Adapter is the extension point for TCP, QUIC, LAN, Bluetooth, radio, and
// application-provided links.
type Adapter interface {
	Name() string
	Open(context.Context) error
	Close() error
	Discover(context.Context) ([]Candidate, error)
	Dial(context.Context, PeerHint) (Conn, error)
	Listen(context.Context, string) (Listener, error)
	Capabilities() Capabilities
}

var ErrUnsupported = errors.New("link: operation unsupported by adapter")
