package dht

import (
	"context"
	"path/filepath"
	"testing"
)

func TestNodePutGetRoundTrip(t *testing.T) {
	t.Parallel()

	node := newTestNode(t, "self")
	record := PeerRecord{
		ID:            testNodeID("peer-1"),
		PubKey:        "cHVia2V5",
		Addrs:         []string{"1.2.3.4:443"},
		Relay:         true,
		Exit:          false,
		ExitPolicy:    ExitPolicy{Ports: []int{443, 80}, Blocklist: "default"},
		Country:       "DE",
		ASN:           64512,
		BandwidthMbps: 10,
		UptimeScore:   0.95,
		LastSeen:      1712000000,
	}

	if err := node.Put(record.ID, record); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got := node.Get(record.ID)
	if got.ID != record.ID {
		t.Fatalf("unexpected id: got %q want %q", got.ID, record.ID)
	}
	if len(got.Addrs) != 1 || got.Addrs[0] != record.Addrs[0] {
		t.Fatalf("unexpected addrs: %#v", got.Addrs)
	}
	if got.UptimeScore != record.UptimeScore || got.BandwidthMbps != record.BandwidthMbps {
		t.Fatalf("unexpected record values: %+v", got)
	}

	score := node.ScorePeer(got, 0.8)
	if score <= 0 {
		t.Fatalf("expected positive score, got %f", score)
	}
}

func TestFindNodeConvergesViaIterativeLookup(t *testing.T) {
	t.Parallel()

	nodes := map[string]*Node{
		"a": newTestNode(t, "a"),
		"b": newTestNode(t, "b"),
		"c": newTestNode(t, "c"),
		"d": newTestNode(t, "d"),
		"e": newTestNode(t, "e"),
	}

	records := map[string]PeerRecord{
		"a": newPeerRecord("a"),
		"b": newPeerRecord("b"),
		"c": newPeerRecord("c"),
		"d": newPeerRecord("d"),
		"e": newPeerRecord("e"),
	}

	mustPut(t, nodes["a"], records["b"], records["c"])
	mustPut(t, nodes["b"], records["c"], records["d"])
	mustPut(t, nodes["c"], records["d"])
	mustPut(t, nodes["d"], records["e"])
	mustPut(t, nodes["e"], records["d"])

	for _, node := range nodes {
		node.QueryPeer = func(_ context.Context, peer PeerRecord, targetID string) ([]PeerRecord, error) {
			for name, record := range records {
				if record.ID == peer.ID {
					return nodes[name].closestPeers(mustParseID(t, targetID), node.bucketSize()), nil
				}
			}
			return nil, nil
		}
	}

	found := nodes["a"].FindNode(records["e"].ID)
	if len(found) == 0 {
		t.Fatalf("expected lookup results")
	}
	if found[0].ID != records["e"].ID {
		t.Fatalf("expected closest result to be target, got %q want %q", found[0].ID, records["e"].ID)
	}
}

func TestPeerTablePersistence(t *testing.T) {
	t.Parallel()

	node := newTestNode(t, "self")
	recordOne := newPeerRecord("peer-one")
	recordTwo := newPeerRecord("peer-two")
	mustPut(t, node, recordOne, recordTwo)

	path := filepath.Join(t.TempDir(), "peers.json")
	if err := node.SavePeerTable(path); err != nil {
		t.Fatalf("SavePeerTable: %v", err)
	}

	reloaded := newTestNode(t, "self-reloaded")
	if err := reloaded.LoadPeerTable(path); err != nil {
		t.Fatalf("LoadPeerTable: %v", err)
	}

	if got := reloaded.Get(recordOne.ID); got.ID != recordOne.ID {
		t.Fatalf("expected persisted peer %q, got %+v", recordOne.ID, got)
	}
	if got := reloaded.Get(recordTwo.ID); got.ID != recordTwo.ID {
		t.Fatalf("expected persisted peer %q, got %+v", recordTwo.ID, got)
	}
}

func TestBootstrapResolvesSeedPeers(t *testing.T) {
	t.Parallel()

	node := newTestNode(t, "self")
	seed := newPeerRecord("bootstrap-peer")
	node.BootstrapNodes = []string{"bootstrap1.openmesh.net:443"}
	node.ResolveBootstrap = func(_ context.Context, addr string) (PeerRecord, error) {
		if addr != "bootstrap1.openmesh.net:443" {
			t.Fatalf("unexpected bootstrap address: %q", addr)
		}
		return seed, nil
	}

	if err := node.Bootstrap(context.Background()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if got := node.Get(seed.ID); got.ID != seed.ID {
		t.Fatalf("expected bootstrap peer to be added, got %+v", got)
	}
}

func newTestNode(t *testing.T, name string) *Node {
	t.Helper()

	node, err := NewNode(testNodeID(name))
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	return node
}

func newPeerRecord(name string) PeerRecord {
	return PeerRecord{
		ID:            testNodeID(name),
		PubKey:        name + "-pub",
		Addrs:         []string{name + ".example:443"},
		Relay:         true,
		Exit:          false,
		ExitPolicy:    ExitPolicy{Ports: []int{443}, Blocklist: "default"},
		Country:       "DE",
		ASN:           len(name) + 64500,
		BandwidthMbps: 10 + len(name),
		UptimeScore:   0.9,
		LastSeen:      1712000000,
	}
}

func testNodeID(name string) string {
	return NodeIDFromPublicKey([]byte(name))
}

func mustPut(t *testing.T, node *Node, records ...PeerRecord) {
	t.Helper()

	for _, record := range records {
		if err := node.Put(record.ID, record); err != nil {
			t.Fatalf("Put(%s): %v", record.ID, err)
		}
	}
}

func mustParseID(t *testing.T, id string) nodeID {
	t.Helper()

	parsed, err := parseNodeID(id)
	if err != nil {
		t.Fatalf("parseNodeID(%q): %v", id, err)
	}
	return parsed
}
