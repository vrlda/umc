package node

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openmesh/core/dht"
)

func TestPeerSelectorSelectCircuitRespectsConstraints(t *testing.T) {
	t.Parallel()

	source := staticPeerSource{
		peerRecord("exit-same-country", peerOptions{exit: true, relay: true, country: "DE", asn: 64501, addr: "10.0.0.1:443", uptime: 0.99, bandwidth: 100}),
		peerRecord("exit-good", peerOptions{exit: true, relay: true, country: "US", asn: 64502, addr: "20.0.0.1:443", uptime: 0.96, bandwidth: 90}),
		peerRecord("relay-same-asn", peerOptions{relay: true, country: "FR", asn: 64502, addr: "30.0.0.1:443", uptime: 0.98, bandwidth: 80}),
		peerRecord("relay-same-subnet", peerOptions{relay: true, country: "NL", asn: 64503, addr: "20.0.0.9:443", uptime: 0.97, bandwidth: 70}),
		peerRecord("relay-low-uptime", peerOptions{relay: true, country: "SE", asn: 64504, addr: "40.0.0.1:443", uptime: 0.50, bandwidth: 120}),
		peerRecord("relay-good-one", peerOptions{relay: true, country: "PL", asn: 64505, addr: "50.0.0.1:443", uptime: 0.95, bandwidth: 60}),
		peerRecord("relay-good-two", peerOptions{relay: true, country: "GB", asn: 64506, addr: "60.0.0.1:443", uptime: 0.91, bandwidth: 50}),
	}

	selector := NewPeerSelector(source)
	path, err := selector.SelectCircuit(3, "DE")
	if err != nil {
		t.Fatalf("SelectCircuit: %v", err)
	}
	if len(path) != 3 {
		t.Fatalf("unexpected path length: got %d want 3", len(path))
	}

	exitPeer := path[len(path)-1]
	if !exitPeer.Exit {
		t.Fatalf("expected last hop to be exit, got %+v", exitPeer)
	}
	if exitPeer.Country == "DE" {
		t.Fatalf("expected exit in different country, got %+v", exitPeer)
	}

	seenASN := make(map[int]struct{})
	seenSubnets := make(map[string]struct{})
	for _, peer := range path {
		if peer.ASN != 0 {
			if _, exists := seenASN[peer.ASN]; exists {
				t.Fatalf("duplicate ASN selected: %d", peer.ASN)
			}
			seenASN[peer.ASN] = struct{}{}
		}
		for subnet := range peerSubnetSet(peer) {
			if _, exists := seenSubnets[subnet]; exists {
				t.Fatalf("duplicate subnet selected: %s", subnet)
			}
			seenSubnets[subnet] = struct{}{}
		}
	}

	for _, peer := range path {
		if peer.ID == testNodeID("relay-low-uptime") {
			t.Fatalf("selected low-uptime peer despite preferred peers being available")
		}
		if peer.ID == testNodeID("relay-same-asn") || peer.ID == testNodeID("relay-same-subnet") {
			t.Fatalf("selected peer that violates circuit constraints: %+v", peer)
		}
	}
}

func TestPeerSelectorBlacklistAfterThreeFailures(t *testing.T) {
	t.Parallel()

	relayPreferred := peerRecord("relay-preferred", peerOptions{relay: true, country: "FR", asn: 64510, addr: "70.0.0.1:443", uptime: 0.94, bandwidth: 70})
	relayFallback := peerRecord("relay-fallback", peerOptions{relay: true, country: "PL", asn: 64511, addr: "80.0.0.1:443", uptime: 0.83, bandwidth: 60})
	exitPeer := peerRecord("exit", peerOptions{exit: true, relay: true, country: "US", asn: 64512, addr: "90.0.0.1:443", uptime: 0.99, bandwidth: 100})

	selector := NewPeerSelector(staticPeerSource{relayPreferred, relayFallback, exitPeer})

	initial, err := selector.SelectCircuit(2, "DE")
	if err != nil {
		t.Fatalf("SelectCircuit: %v", err)
	}
	if initial[0].ID != relayPreferred.ID {
		t.Fatalf("expected preferred relay before blacklist, got %+v", initial)
	}

	selector.ReportFailure(relayPreferred.ID)
	selector.ReportFailure(relayPreferred.ID)
	if selector.IsBlacklisted(relayPreferred.ID) {
		t.Fatalf("peer blacklisted too early")
	}

	stillSelected, err := selector.SelectCircuit(2, "DE")
	if err != nil {
		t.Fatalf("SelectCircuit after two failures: %v", err)
	}
	if stillSelected[0].ID != relayPreferred.ID {
		t.Fatalf("expected relay to remain eligible before threshold, got %+v", stillSelected)
	}

	selector.ReportFailure(relayPreferred.ID)
	if !selector.IsBlacklisted(relayPreferred.ID) {
		t.Fatalf("expected peer to be blacklisted after three failures")
	}

	blacklisted, err := selector.SelectCircuit(2, "DE")
	if err != nil {
		t.Fatalf("SelectCircuit after blacklist: %v", err)
	}
	if blacklisted[0].ID != relayFallback.ID {
		t.Fatalf("expected fallback relay after blacklist, got %+v", blacklisted)
	}

	selector.ReportSuccess(relayPreferred.ID)
	if selector.IsBlacklisted(relayPreferred.ID) {
		t.Fatalf("expected success to clear blacklist")
	}
}

func TestPeerSelectorSelectCircuitExcludingSkipsRejectedPeers(t *testing.T) {
	t.Parallel()

	relayPreferred := peerRecord("relay-preferred", peerOptions{relay: true, country: "FR", asn: 64510, addr: "70.0.0.1:443", uptime: 0.94, bandwidth: 70})
	relayFallback := peerRecord("relay-fallback", peerOptions{relay: true, country: "PL", asn: 64511, addr: "80.0.0.1:443", uptime: 0.83, bandwidth: 60})
	exitPeer := peerRecord("exit", peerOptions{exit: true, relay: true, country: "US", asn: 64512, addr: "90.0.0.1:443", uptime: 0.99, bandwidth: 100})

	selector := NewPeerSelector(staticPeerSource{relayPreferred, relayFallback, exitPeer})
	path, err := selector.SelectCircuitExcluding(2, "DE", map[string]struct{}{
		normalizePeerID(relayPreferred.ID): {},
	})
	if err != nil {
		t.Fatalf("SelectCircuitExcluding: %v", err)
	}
	if path[0].ID != relayFallback.ID {
		t.Fatalf("expected fallback relay after exclusion, got %+v", path)
	}
}

func TestPeerAnnouncerRunAnnouncesImmediatelyAndRefreshes(t *testing.T) {
	t.Parallel()

	record := peerRecord("self", peerOptions{relay: true, country: "DE", asn: 64520, addr: "100.0.0.1:443", uptime: 0.9, bandwidth: 40})
	store := &announceStore{
		calls: make(chan dht.PeerRecord, 4),
	}

	start := time.Unix(1712000000, 0)
	nowValues := []time.Time{
		start,
		start.Add(30 * time.Minute),
	}

	var nowMu sync.Mutex
	announcer := &PeerAnnouncer{
		Store:    store,
		Record:   record,
		Interval: 10 * time.Millisecond,
		Now: func() time.Time {
			nowMu.Lock()
			defer nowMu.Unlock()
			if len(nowValues) == 0 {
				return start.Add(time.Hour)
			}
			next := nowValues[0]
			nowValues = nowValues[1:]
			return next
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- announcer.Run(ctx)
	}()

	first := waitForAnnouncement(t, store.calls)
	second := waitForAnnouncement(t, store.calls)
	cancel()

	if err := <-errCh; err != nil {
		t.Fatalf("Run: %v", err)
	}

	if first.LastSeen != start.Unix() {
		t.Fatalf("unexpected first last_seen: got %d want %d", first.LastSeen, start.Unix())
	}
	if second.LastSeen != start.Add(30*time.Minute).Unix() {
		t.Fatalf("unexpected refreshed last_seen: got %d want %d", second.LastSeen, start.Add(30*time.Minute).Unix())
	}
}

type staticPeerSource []dht.PeerRecord

func (s staticPeerSource) Peers() []dht.PeerRecord {
	return clonePeerRecords(s)
}

type announceStore struct {
	mu    sync.Mutex
	calls chan dht.PeerRecord
}

func (s *announceStore) Put(_ string, record dht.PeerRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls <- clonePeerRecord(record)
	return nil
}

type peerOptions struct {
	relay     bool
	exit      bool
	country   string
	asn       int
	addr      string
	uptime    float64
	bandwidth int
}

func peerRecord(name string, opts peerOptions) dht.PeerRecord {
	return dht.PeerRecord{
		ID:            testNodeID(name),
		PubKey:        name + "-pub",
		Addrs:         []string{opts.addr},
		Relay:         opts.relay,
		Exit:          opts.exit,
		ExitPolicy:    dht.ExitPolicy{Ports: []int{443}, Blocklist: "default"},
		Country:       opts.country,
		ASN:           opts.asn,
		BandwidthMbps: opts.bandwidth,
		UptimeScore:   opts.uptime,
		LastSeen:      1712000000,
	}
}

func testNodeID(name string) string {
	return dht.NodeIDFromPublicKey([]byte(name))
}

func waitForAnnouncement(t *testing.T, calls <-chan dht.PeerRecord) dht.PeerRecord {
	t.Helper()

	select {
	case record := <-calls:
		return record
	case <-time.After(250 * time.Millisecond):
		t.Fatal("timed out waiting for announcement")
		return dht.PeerRecord{}
	}
}
