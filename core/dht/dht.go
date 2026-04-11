package dht

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/bits"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultBucketSize = 20
	defaultAlpha      = 3
)

var (
	errInvalidNodeID      = errors.New("dht: node id must be a 64-character hex string")
	errBootstrapResolver  = errors.New("dht: bootstrap resolver is not configured")
	errQueryPeerResolver  = errors.New("dht: query peer resolver is not configured")
	defaultBootstrapNodes = []string{
		"bootstrap1.openmesh.net:443",
		"bootstrap2.openmesh.net:443",
		"bootstrap3.openmesh.net:443",
		"bootstrap4.openmesh.net:443",
		"bootstrap5.openmesh.net:443",
	}
)

// BootstrapNodes is the baked-in seed set used for initial peer discovery.
var BootstrapNodes = append([]string(nil), defaultBootstrapNodes...)

type ExitPolicy struct {
	Ports     []int  `json:"ports"`
	Blocklist string `json:"blocklist"`
}

// PeerRecord matches the peer table schema from the specification.
type PeerRecord struct {
	ID            string     `json:"id"`
	PubKey        string     `json:"pubkey"`
	Addrs         []string   `json:"addrs"`
	Relay         bool       `json:"relay"`
	Exit          bool       `json:"exit"`
	ExitPolicy    ExitPolicy `json:"exit_policy"`
	Country       string     `json:"country"`
	ASN           int        `json:"asn"`
	BandwidthMbps int        `json:"bandwidth_mbps"`
	UptimeScore   float64    `json:"uptime_score"`
	LastSeen      int64      `json:"last_seen"`
}

// Score computes the spec's peer score from uptime, normalized bandwidth, and latency.
func (p PeerRecord) Score(bandwidthScore, latencyScore float64) float64 {
	return (clampScore(p.UptimeScore) * 0.4) +
		(clampScore(bandwidthScore) * 0.3) +
		(clampScore(latencyScore) * 0.3)
}

type QueryFunc func(context.Context, PeerRecord, string) ([]PeerRecord, error)
type BootstrapResolver func(context.Context, string) (PeerRecord, error)

// Node is a minimal Kademlia routing table and lookup engine for 256-bit node IDs.
type Node struct {
	ID    string
	K     int
	Alpha int

	BootstrapNodes   []string
	QueryPeer        QueryFunc
	ResolveBootstrap BootstrapResolver

	mu      sync.RWMutex
	localID nodeID
	buckets [256][]PeerRecord
	peers   map[string]PeerRecord
}

// NewNode creates a DHT node with default Kademlia parameters.
func NewNode(id string) (*Node, error) {
	parsed, err := parseNodeID(id)
	if err != nil {
		return nil, err
	}

	return &Node{
		ID:             strings.ToLower(id),
		K:              defaultBucketSize,
		Alpha:          defaultAlpha,
		BootstrapNodes: append([]string(nil), BootstrapNodes...),
		localID:        parsed,
		peers:          make(map[string]PeerRecord),
	}, nil
}

// Put inserts or updates a peer record and maintains the appropriate k-bucket.
func (n *Node) Put(id string, record PeerRecord) error {
	targetID, err := parseNodeID(id)
	if err != nil {
		return err
	}
	if n.localID == targetID {
		return nil
	}

	record.ID = strings.ToLower(id)
	if record.LastSeen == 0 {
		record.LastSeen = time.Now().Unix()
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	bucketIndex := bucketIndexFor(n.localID, targetID)
	if bucketIndex < 0 {
		return nil
	}

	record = clonePeerRecord(record)
	bucket := n.buckets[bucketIndex]
	for i, existing := range bucket {
		if existing.ID == record.ID {
			bucket = append(bucket[:i], bucket[i+1:]...)
			bucket = append(bucket, record)
			n.buckets[bucketIndex] = bucket
			n.peers[record.ID] = record
			return nil
		}
	}

	if len(bucket) >= n.bucketSize() {
		evicted := bucket[0]
		delete(n.peers, evicted.ID)
		bucket = bucket[1:]
	}
	bucket = append(bucket, record)
	n.buckets[bucketIndex] = bucket
	n.peers[record.ID] = record
	return nil
}

// Get returns a peer record by ID, or the zero value if no record is known.
func (n *Node) Get(id string) PeerRecord {
	n.mu.RLock()
	defer n.mu.RUnlock()

	record, ok := n.peers[strings.ToLower(id)]
	if !ok {
		return PeerRecord{}
	}
	return clonePeerRecord(record)
}

// Peers returns a snapshot of the current peer table.
func (n *Node) Peers() []PeerRecord {
	return n.allPeers()
}

// FindNode performs an iterative Kademlia node lookup and returns the closest known peers.
func (n *Node) FindNode(id string) []PeerRecord {
	targetID, err := parseNodeID(id)
	if err != nil {
		return nil
	}
	return n.findNode(context.Background(), strings.ToLower(id), targetID)
}

// Bootstrap resolves the baked-in bootstrap nodes and adds them to the routing table.
func (n *Node) Bootstrap(ctx context.Context) error {
	if n.ResolveBootstrap == nil {
		return errBootstrapResolver
	}

	nodes := n.BootstrapNodes
	if len(nodes) == 0 {
		nodes = BootstrapNodes
	}

	var errs []error
	successes := 0
	for _, addr := range nodes {
		record, err := n.ResolveBootstrap(ctx, addr)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := n.Put(record.ID, record); err != nil {
			errs = append(errs, err)
			continue
		}
		successes++
	}

	if successes > 0 {
		return nil
	}
	if len(errs) == 0 {
		return errBootstrapResolver
	}
	return errors.Join(errs...)
}

// SavePeerTable persists the peer table as JSON.
func (n *Node) SavePeerTable(path string) error {
	if path == "" {
		return errors.New("dht: persistence path is required")
	}

	records := n.allPeers()
	sort.Slice(records, func(i, j int) bool {
		return records[i].ID < records[j].ID
	})

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	bytes, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	bytes = append(bytes, '\n')

	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, bytes, 0o600); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

// LoadPeerTable restores peer records from a persisted JSON peer table.
func (n *Node) LoadPeerTable(path string) error {
	if path == "" {
		return errors.New("dht: persistence path is required")
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	if len(strings.TrimSpace(string(bytes))) == 0 {
		return nil
	}

	var records []PeerRecord
	if err := json.Unmarshal(bytes, &records); err != nil {
		return err
	}

	for _, record := range records {
		if err := n.Put(record.ID, record); err != nil {
			return err
		}
	}
	return nil
}

// ScorePeer computes the peer score using normalized bandwidth relative to the table's best peer.
func (n *Node) ScorePeer(record PeerRecord, latencyScore float64) float64 {
	maxBandwidth := n.maxBandwidthMbps()
	bandwidthScore := 0.0
	if maxBandwidth > 0 {
		bandwidthScore = float64(record.BandwidthMbps) / float64(maxBandwidth)
	}
	return record.Score(bandwidthScore, latencyScore)
}

func (n *Node) findNode(ctx context.Context, targetHex string, target nodeID) []PeerRecord {
	shortlist := make(map[string]PeerRecord)
	for _, peer := range n.closestPeers(target, n.bucketSize()) {
		shortlist[peer.ID] = peer
	}
	queried := make(map[string]bool)

	for {
		batch := nextUnqueried(shortlistToSortedSlice(shortlist, target), queried, n.lookupAlpha())
		if len(batch) == 0 {
			break
		}

		for _, peer := range batch {
			queried[peer.ID] = true
			results, err := n.queryPeer(ctx, peer, targetHex)
			if err != nil {
				continue
			}
			for _, candidate := range results {
				if err := n.Put(candidate.ID, candidate); err != nil {
					continue
				}
				shortlist[candidate.ID] = clonePeerRecord(candidate)
			}
		}

		pruned := shortlistToSortedSlice(shortlist, target)
		if len(pruned) > n.bucketSize() {
			pruned = pruned[:n.bucketSize()]
		}
		shortlist = make(map[string]PeerRecord, len(pruned))
		for _, peer := range pruned {
			shortlist[peer.ID] = peer
		}
	}

	return shortlistToSortedSlice(shortlist, target)
}

func (n *Node) queryPeer(ctx context.Context, peer PeerRecord, targetID string) ([]PeerRecord, error) {
	if n.QueryPeer == nil {
		return nil, errQueryPeerResolver
	}
	return n.QueryPeer(ctx, peer, targetID)
}

func (n *Node) closestPeers(target nodeID, limit int) []PeerRecord {
	records := n.allPeers()
	sort.Slice(records, func(i, j int) bool {
		leftID, leftErr := parseNodeID(records[i].ID)
		rightID, rightErr := parseNodeID(records[j].ID)
		if leftErr != nil && rightErr != nil {
			return records[i].ID < records[j].ID
		}
		if leftErr != nil {
			return false
		}
		if rightErr != nil {
			return true
		}
		return lessDistance(leftID, rightID, target)
	})
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	return records
}

func (n *Node) allPeers() []PeerRecord {
	n.mu.RLock()
	defer n.mu.RUnlock()

	records := make([]PeerRecord, 0, len(n.peers))
	for _, record := range n.peers {
		records = append(records, clonePeerRecord(record))
	}
	return records
}

func (n *Node) maxBandwidthMbps() int {
	n.mu.RLock()
	defer n.mu.RUnlock()

	maxBandwidth := 0
	for _, record := range n.peers {
		if record.BandwidthMbps > maxBandwidth {
			maxBandwidth = record.BandwidthMbps
		}
	}
	return maxBandwidth
}

func (n *Node) bucketSize() int {
	if n.K > 0 {
		return n.K
	}
	return defaultBucketSize
}

func (n *Node) lookupAlpha() int {
	if n.Alpha > 0 {
		return n.Alpha
	}
	return defaultAlpha
}

type nodeID [32]byte

func parseNodeID(id string) (nodeID, error) {
	var parsed nodeID
	id = strings.TrimSpace(strings.ToLower(id))
	if len(id) != hex.EncodedLen(len(parsed)) {
		return nodeID{}, errInvalidNodeID
	}

	bytes, err := hex.DecodeString(id)
	if err != nil {
		return nodeID{}, errInvalidNodeID
	}
	copy(parsed[:], bytes)
	return parsed, nil
}

func NodeIDFromPublicKey(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

func bucketIndexFor(local, target nodeID) int {
	for i := 0; i < len(local); i++ {
		xor := local[i] ^ target[i]
		if xor != 0 {
			return i*8 + bits.LeadingZeros8(uint8(xor))
		}
	}
	return -1
}

func lessDistance(left, right, target nodeID) bool {
	for i := 0; i < len(target); i++ {
		leftDistance := left[i] ^ target[i]
		rightDistance := right[i] ^ target[i]
		if leftDistance == rightDistance {
			continue
		}
		return leftDistance < rightDistance
	}
	return false
}

func nextUnqueried(sorted []PeerRecord, queried map[string]bool, limit int) []PeerRecord {
	if limit <= 0 {
		limit = defaultAlpha
	}

	batch := make([]PeerRecord, 0, limit)
	for _, peer := range sorted {
		if queried[peer.ID] {
			continue
		}
		batch = append(batch, peer)
		if len(batch) == limit {
			break
		}
	}
	return batch
}

func shortlistToSortedSlice(shortlist map[string]PeerRecord, target nodeID) []PeerRecord {
	records := make([]PeerRecord, 0, len(shortlist))
	for _, record := range shortlist {
		records = append(records, clonePeerRecord(record))
	}
	sort.Slice(records, func(i, j int) bool {
		leftID, leftErr := parseNodeID(records[i].ID)
		rightID, rightErr := parseNodeID(records[j].ID)
		if leftErr != nil && rightErr != nil {
			return records[i].ID < records[j].ID
		}
		if leftErr != nil {
			return false
		}
		if rightErr != nil {
			return true
		}
		return lessDistance(leftID, rightID, target)
	})
	return records
}

func clonePeerRecord(record PeerRecord) PeerRecord {
	record.Addrs = append([]string(nil), record.Addrs...)
	record.ExitPolicy.Ports = append([]int(nil), record.ExitPolicy.Ports...)
	return record
}

func clampScore(value float64) float64 {
	switch {
	case value < 0:
		return 0
	case value > 1:
		return 1
	default:
		return value
	}
}
