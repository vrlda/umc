package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	cfgpkg "github.com/openmesh/core/config"
	"github.com/openmesh/core/dht"
)

func TestDaemonBootstrapIfNeededLoadsManifestPeers(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]dht.PeerRecord{
			{
				ID:     "1111111111111111111111111111111111111111111111111111111111111111",
				PubKey: "cHVia2V5",
				Addrs:  []string{"198.51.100.10:443"},
				Relay:  true,
			},
		})
	}))
	defer server.Close()

	dhtNode, err := dht.NewNode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}

	daemon := &daemon{
		cfg: &cfgpkg.Config{
			BootstrapManifestURLs: []string{server.URL},
		},
		dhtNode: dhtNode,
	}

	if !daemon.bootstrapIfNeeded(context.Background()) {
		t.Fatalf("expected bootstrapIfNeeded to add peers")
	}
	if len(daemon.dhtNode.Peers()) != 1 {
		t.Fatalf("expected one bootstrapped peer, got %#v", daemon.dhtNode.Peers())
	}
}
