package openmeshmobile

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestEngineConfigureAndStatusJSON(t *testing.T) {
	t.Parallel()

	engine, err := NewEngine(filepath.Join(t.TempDir(), "mobile-engine"))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	if err := engine.Configure("relay", 3, 25); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if err := engine.AttachTun(42); err != nil {
		t.Fatalf("AttachTun: %v", err)
	}
	if err := engine.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer engine.Stop()

	var status map[string]any
	if err := json.Unmarshal([]byte(engine.StatusJSON()), &status); err != nil {
		t.Fatalf("StatusJSON: %v", err)
	}
	if got := status["mode"]; got != "relay" {
		t.Fatalf("unexpected mode: got %v want relay", got)
	}
	if got := int(status["hops"].(float64)); got != 3 {
		t.Fatalf("unexpected hops: got %d want 3", got)
	}
	if got := int(status["tun_fd"].(float64)); got != 42 {
		t.Fatalf("unexpected tun fd: got %d want 42", got)
	}
	if got := status["running"].(bool); !got {
		t.Fatalf("expected running=true")
	}
}

func TestSetRelaySuspended(t *testing.T) {
	t.Parallel()

	engine, err := NewEngine(filepath.Join(t.TempDir(), "mobile-engine"))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	if err := engine.Configure("relay", 2, 10); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if err := engine.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer engine.Stop()

	if err := engine.SetRelaySuspended(true); err != nil {
		t.Fatalf("SetRelaySuspended(true): %v", err)
	}
	if !contains(engine.StatusJSON(), `"relay_suspended":true`) {
		t.Fatalf("expected relay_suspended=true")
	}

	if err := engine.SetRelaySuspended(false); err != nil {
		t.Fatalf("SetRelaySuspended(false): %v", err)
	}
	if !contains(engine.StatusJSON(), `"relay_suspended":false`) {
		t.Fatalf("expected relay_suspended=false")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && func() bool {
		return stringIndex(haystack, needle) >= 0
	}()
}

func stringIndex(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
