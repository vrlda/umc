package dht

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBootstrapRecordURL(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"bootstrap1.example:443":     "https://bootstrap1.example:443/.well-known/openmesh/peer-record.json",
		"https://bootstrap1.example": "https://bootstrap1.example/.well-known/openmesh/peer-record.json",
		"https://bootstrap1.example/.well-known/openmesh/peer-record.json": "https://bootstrap1.example/.well-known/openmesh/peer-record.json",
	}

	for input, want := range tests {
		if got := BootstrapRecordURL(input); got != want {
			t.Fatalf("BootstrapRecordURL(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestFetchPeerManifest(t *testing.T) {
	t.Parallel()

	records := []PeerRecord{{ID: "peer-1", Addrs: []string{"127.0.0.1:443"}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(records)
	}))
	defer server.Close()

	got, err := FetchPeerManifest(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("FetchPeerManifest: %v", err)
	}
	if len(got) != 1 || got[0].ID != "peer-1" {
		t.Fatalf("unexpected manifest records: %#v", got)
	}
}
