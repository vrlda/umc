package node

import (
	"context"
	"sync"
	"time"

	"github.com/openmesh/core/dht"
)

// AnnounceStore is the DHT write path used by the peer announcer.
type AnnounceStore interface {
	Put(id string, record dht.PeerRecord) error
}

// PeerAnnouncer publishes the local node record on startup and refresh intervals.
type PeerAnnouncer struct {
	Store    AnnounceStore
	Record   dht.PeerRecord
	Interval time.Duration
	Now      func() time.Time

	mu sync.Mutex
}

// Announce publishes the current peer record and refreshes its last-seen timestamp.
func (a *PeerAnnouncer) Announce() error {
	if a == nil || a.Store == nil {
		return errNoAnnounceStore
	}

	record := clonePeerRecord(a.currentRecord())
	record.LastSeen = a.now().Unix()
	if err := a.Store.Put(record.ID, record); err != nil {
		return err
	}

	a.mu.Lock()
	a.Record.LastSeen = record.LastSeen
	a.mu.Unlock()
	return nil
}

// Run announces immediately, then refreshes the peer record on the configured interval.
func (a *PeerAnnouncer) Run(ctx context.Context) error {
	if err := a.Announce(); err != nil {
		return err
	}

	ticker := time.NewTicker(a.interval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := a.Announce(); err != nil {
				return err
			}
		}
	}
}

func (a *PeerAnnouncer) interval() time.Duration {
	if a != nil && a.Interval > 0 {
		return a.Interval
	}
	return defaultAnnounceInterval
}

func (a *PeerAnnouncer) now() time.Time {
	if a != nil && a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *PeerAnnouncer) currentRecord() dht.PeerRecord {
	if a == nil {
		return dht.PeerRecord{}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	return clonePeerRecord(a.Record)
}
