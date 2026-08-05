// Package store defines bounded custody for encrypted packets while no live
// route exists. Stores must enforce quotas, expiry, deduplication, and pressure.
package store

import (
	"context"
	"time"

	"github.com/openmesh/core/identity"
	"github.com/openmesh/core/protocol"
)

type Limits struct {
	MaximumBytes      int64
	MaximumPackets    int
	MaximumPacketSize int
	MaximumLifetime   time.Duration
}

type Queue interface {
	Put(context.Context, protocol.Envelope) error
	Take(context.Context, identity.ID, int) ([]protocol.Envelope, error)
	Delete(context.Context, protocol.PacketID) error
	Sweep(context.Context, time.Time) error
	Limits() Limits
}
