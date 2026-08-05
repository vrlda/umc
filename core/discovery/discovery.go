// Package discovery defines replaceable sources of untrusted peer candidates.
package discovery

import (
	"context"
	"time"

	"github.com/openmesh/core/identity"
	"github.com/openmesh/core/link"
	"github.com/openmesh/core/protocol"
)

type Candidate struct {
	Identity  identity.ID
	Hints     []link.PeerHint
	Protocols []protocol.ID
	ExpiresAt time.Time
}

// Provider returns contact candidates, never trust decisions.
type Provider interface {
	Name() string
	FindPeer(context.Context, identity.ID) ([]Candidate, error)
	FindServices(context.Context, protocol.ID) ([]Candidate, error)
	Advertise(context.Context, Candidate) error
}
