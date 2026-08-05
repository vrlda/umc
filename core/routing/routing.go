// Package routing defines path selection without imposing a global topology.
package routing

import (
	"context"
	"time"

	"github.com/openmesh/core/identity"
	"github.com/openmesh/core/link"
)

type Path struct {
	ID        string
	Hops      []identity.ID
	Links     []string
	ExpiresAt time.Time
	Latency   time.Duration
	Cost      uint32
	Energy    uint32
}

type Constraints struct {
	MaximumLatency  time.Duration
	MaximumHops     uint8
	MaximumCost     uint32
	AllowStored     bool
	AllowRelays     bool
	AllowLocal      bool
	PreferLowEnergy bool
}

type Resolver interface {
	Paths(context.Context, identity.ID, Constraints) ([]Path, error)
	Observe(context.Context, identity.ID, link.PeerHint) error
	Invalidate(context.Context, string) error
}
