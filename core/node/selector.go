package node

import (
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openmesh/core/dht"
)

const (
	blacklistThreshold      = 3
	defaultAnnounceInterval = 30 * time.Minute
)

var (
	errInvalidHopCount   = errors.New("node: hops must be between 1 and 3")
	errNoPeerSource      = errors.New("node: peer source is not configured")
	errInsufficientPeers = errors.New("node: not enough eligible peers to build circuit")
	errNoAnnounceStore   = errors.New("node: announce store is not configured")
)

// PeerSource exposes the current peer table to the selector.
type PeerSource interface {
	Peers() []dht.PeerRecord
}

// PeerSelector chooses relay and exit peers while enforcing circuit diversity rules.
type PeerSelector struct {
	Source PeerSource

	mu       sync.RWMutex
	failures map[string]int
}

// NewPeerSelector constructs a selector for the given peer source.
func NewPeerSelector(source PeerSource) *PeerSelector {
	return &PeerSelector{
		Source:   source,
		failures: make(map[string]int),
	}
}

// SelectCircuit picks relay hops followed by an exit node.
func (s *PeerSelector) SelectCircuit(hops int, clientCountry string) ([]dht.PeerRecord, error) {
	return s.SelectCircuitExcluding(hops, clientCountry, nil)
}

// SelectCircuitExcluding picks relay hops followed by an exit node while skipping excluded peer IDs.
func (s *PeerSelector) SelectCircuitExcluding(hops int, clientCountry string, excludedIDs map[string]struct{}) ([]dht.PeerRecord, error) {
	if hops < 1 || hops > 3 {
		return nil, errInvalidHopCount
	}
	if s == nil || s.Source == nil {
		return nil, errNoPeerSource
	}

	peers := clonePeerRecords(s.Source.Peers())
	if len(peers) == 0 {
		return nil, errInsufficientPeers
	}

	clientCountry = normalizeCountry(clientCountry)

	var exits []dht.PeerRecord
	var relays []dht.PeerRecord
	for _, peer := range peers {
		if peer.ID == "" || s.IsBlacklisted(peer.ID) || isExcludedPeer(peer.ID, excludedIDs) {
			continue
		}
		if peer.Relay {
			relays = append(relays, peer)
		}
		if peer.Exit && (clientCountry == "" || normalizeCountry(peer.Country) != clientCountry) {
			exits = append(exits, peer)
		}
	}

	sortPeers(exits)
	sortPeers(relays)

	for _, exitPeer := range exits {
		selected := make([]dht.PeerRecord, 0, hops)
		selected = append(selected, clonePeerRecord(exitPeer))

		usedIDs := map[string]struct{}{
			strings.ToLower(exitPeer.ID): {},
		}
		usedASNs := make(map[int]struct{})
		if exitPeer.ASN != 0 {
			usedASNs[exitPeer.ASN] = struct{}{}
		}
		usedSubnets := peerSubnetSet(exitPeer)

		relayPath := make([]dht.PeerRecord, 0, hops-1)
		for _, relayPeer := range relays {
			if len(relayPath) == hops-1 {
				break
			}
			if !isEligibleRelay(relayPeer, usedIDs, usedASNs, usedSubnets) {
				continue
			}

			relayPath = append(relayPath, clonePeerRecord(relayPeer))
			usedIDs[strings.ToLower(relayPeer.ID)] = struct{}{}
			if relayPeer.ASN != 0 {
				usedASNs[relayPeer.ASN] = struct{}{}
			}
			mergeSubnetSet(usedSubnets, relayPeer)
		}

		if len(relayPath) != hops-1 {
			continue
		}

		return append(relayPath, selected...), nil
	}

	return nil, errInsufficientPeers
}

// ReportFailure increments the consecutive failure count for a peer.
func (s *PeerSelector) ReportFailure(peerID string) {
	if s == nil {
		return
	}

	peerID = normalizePeerID(peerID)
	if peerID == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.failures == nil {
		s.failures = make(map[string]int)
	}
	s.failures[peerID]++
}

// ReportSuccess clears the consecutive failure count for a peer.
func (s *PeerSelector) ReportSuccess(peerID string) {
	if s == nil {
		return
	}

	peerID = normalizePeerID(peerID)
	if peerID == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, peerID)
}

// IsBlacklisted reports whether a peer has failed three consecutive times.
func (s *PeerSelector) IsBlacklisted(peerID string) bool {
	if s == nil {
		return false
	}

	peerID = normalizePeerID(peerID)
	if peerID == "" {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.failures[peerID] >= blacklistThreshold
}

func isEligibleRelay(peer dht.PeerRecord, usedIDs map[string]struct{}, usedASNs map[int]struct{}, usedSubnets map[string]struct{}) bool {
	if !peer.Relay {
		return false
	}
	if _, exists := usedIDs[normalizePeerID(peer.ID)]; exists {
		return false
	}
	if peer.ASN != 0 {
		if _, exists := usedASNs[peer.ASN]; exists {
			return false
		}
	}
	for subnet := range peerSubnetSet(peer) {
		if _, exists := usedSubnets[subnet]; exists {
			return false
		}
	}
	return true
}

func sortPeers(peers []dht.PeerRecord) {
	sort.Slice(peers, func(i, j int) bool {
		leftPreferred := peers[i].UptimeScore > 0.8
		rightPreferred := peers[j].UptimeScore > 0.8
		if leftPreferred != rightPreferred {
			return leftPreferred
		}
		if peers[i].UptimeScore != peers[j].UptimeScore {
			return peers[i].UptimeScore > peers[j].UptimeScore
		}
		if peers[i].BandwidthMbps != peers[j].BandwidthMbps {
			return peers[i].BandwidthMbps > peers[j].BandwidthMbps
		}
		if peers[i].LastSeen != peers[j].LastSeen {
			return peers[i].LastSeen > peers[j].LastSeen
		}
		return normalizePeerID(peers[i].ID) < normalizePeerID(peers[j].ID)
	})
}

func normalizeCountry(country string) string {
	return strings.ToUpper(strings.TrimSpace(country))
}

func normalizePeerID(peerID string) string {
	return strings.ToLower(strings.TrimSpace(peerID))
}

func isExcludedPeer(peerID string, excludedIDs map[string]struct{}) bool {
	if len(excludedIDs) == 0 {
		return false
	}
	_, exists := excludedIDs[normalizePeerID(peerID)]
	return exists
}

func peerSubnetSet(peer dht.PeerRecord) map[string]struct{} {
	subnets := make(map[string]struct{})
	for _, addr := range peer.Addrs {
		subnet := subnetForAddress(addr)
		if subnet == "" {
			continue
		}
		subnets[subnet] = struct{}{}
	}
	return subnets
}

func mergeSubnetSet(dst map[string]struct{}, peer dht.PeerRecord) {
	for subnet := range peerSubnetSet(peer) {
		dst[subnet] = struct{}{}
	}
}

func subnetForAddress(addr string) string {
	host := strings.TrimSpace(addr)
	if host == "" {
		return ""
	}

	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")

	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return net.IPv4(ipv4[0], ipv4[1], ipv4[2], 0).String() + "/24"
	}
	return ip.String()
}

func clonePeerRecord(record dht.PeerRecord) dht.PeerRecord {
	record.Addrs = append([]string(nil), record.Addrs...)
	record.ExitPolicy.Ports = append([]int(nil), record.ExitPolicy.Ports...)
	return record
}

func clonePeerRecords(records []dht.PeerRecord) []dht.PeerRecord {
	cloned := make([]dht.PeerRecord, 0, len(records))
	for _, record := range records {
		cloned = append(cloned, clonePeerRecord(record))
	}
	return cloned
}
