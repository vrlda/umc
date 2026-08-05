// Package openmesh exposes the application-facing networking boundary.
// Routing, discovery, links, and storage remain replaceable behind Network.
package openmesh

import (
	"context"
	"errors"
	"time"

	"github.com/openmesh/core/identity"
	"github.com/openmesh/core/protocol"
)

type Trust uint8

const (
	TrustAnyAuthenticated Trust = iota
	TrustIntroduced
	TrustKnownPeer
)

type Policy struct {
	AllowStoreAndForward bool
	AllowInternetRelays  bool
	AllowLocalLinks      bool
	MaximumLatency       time.Duration
	MaximumHops          uint8
	MaximumCost          uint32
	MinimumTrust         Trust
	PreferLowEnergy      bool
}

type Connection interface {
	Send(context.Context, []byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
}

type Listener interface {
	Accept(context.Context) (Connection, error)
	Close() error
}

// Network is intentionally small. Current repository provides primitives for
// implementations; a complete adaptive router is version 0.1 work.
type Network interface {
	Listen(context.Context, *identity.Identity, protocol.ID) (Listener, error)
	Connect(context.Context, identity.ID, protocol.ID, Policy) (Connection, error)
	PublishService(context.Context, identity.ID, protocol.ID, map[string]string) error
	DiscoverServices(context.Context, protocol.ID) ([]identity.ID, error)
}

var ErrNotImplemented = errors.New("openmesh: operation not implemented")
