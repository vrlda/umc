package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/99designs/keyring"
)

func TestLoadConfigRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	cfg := &Config{
		Mode:               "exit",
		Hops:               3,
		BandwidthLimitMbps: 25,
		ExitPolicy: ExitPolicy{
			Ports:     []int{80, 443},
			Blocklist: "custom",
		},
		DataDir:               "~/custom-openmesh",
		LogLevel:              "info",
		BootstrapManifestURLs: []string{"https://github.com/example/openmesh/releases/latest/download/bootstrap-peers.json"},
	}

	if err := SaveConfig(cfg, path); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if loaded.Mode != cfg.Mode {
		t.Fatalf("unexpected mode: got %q want %q", loaded.Mode, cfg.Mode)
	}
	if loaded.Hops != cfg.Hops {
		t.Fatalf("unexpected hops: got %d want %d", loaded.Hops, cfg.Hops)
	}
	if loaded.BandwidthLimitMbps != cfg.BandwidthLimitMbps {
		t.Fatalf("unexpected bandwidth: got %d want %d", loaded.BandwidthLimitMbps, cfg.BandwidthLimitMbps)
	}
	if len(loaded.ExitPolicy.Ports) != 2 || loaded.ExitPolicy.Ports[0] != 80 || loaded.ExitPolicy.Ports[1] != 443 {
		t.Fatalf("unexpected exit policy ports: %#v", loaded.ExitPolicy.Ports)
	}
	if loaded.ExitPolicy.Blocklist != cfg.ExitPolicy.Blocklist {
		t.Fatalf("unexpected blocklist: got %q want %q", loaded.ExitPolicy.Blocklist, cfg.ExitPolicy.Blocklist)
	}
	if loaded.DataDir != cfg.DataDir {
		t.Fatalf("unexpected data dir: got %q want %q", loaded.DataDir, cfg.DataDir)
	}
	if loaded.LogLevel != cfg.LogLevel {
		t.Fatalf("unexpected log level: got %q want %q", loaded.LogLevel, cfg.LogLevel)
	}
	if len(loaded.BootstrapManifestURLs) != 1 || loaded.BootstrapManifestURLs[0] != cfg.BootstrapManifestURLs[0] {
		t.Fatalf("unexpected bootstrap urls: %#v", loaded.BootstrapManifestURLs)
	}
}

func TestLoadConfigTreatsEmptyFileAsValid(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("write empty config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Mode != defaultMode || cfg.Hops != defaultHops || cfg.BandwidthLimitMbps != defaultBandwidthMbps {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.ExitPolicy.Blocklist != defaultBlocklist || len(cfg.ExitPolicy.Ports) != 1 || cfg.ExitPolicy.Ports[0] != 443 {
		t.Fatalf("unexpected exit policy defaults: %+v", cfg.ExitPolicy)
	}
	if len(cfg.BootstrapManifestURLs) != 0 {
		t.Fatalf("expected no default bootstrap urls in test env, got %#v", cfg.BootstrapManifestURLs)
	}
}

func TestNormalizeStringList(t *testing.T) {
	t.Parallel()

	values := NormalizeStringList([]string{
		" https://example.com/a.json ",
		"",
		"https://example.com/b.json",
		"https://example.com/a.json",
	})

	if len(values) != 2 {
		t.Fatalf("expected 2 values, got %#v", values)
	}
	if values[0] != "https://example.com/a.json" || values[1] != "https://example.com/b.json" {
		t.Fatalf("unexpected normalized values: %#v", values)
	}
}

func TestKeyStoreGeneratesIdempotentFallbackKey(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	machineID := func() (string, error) { return "test-machine-id", nil }

	store1 := &KeyStore{
		DataDir:         dataDir,
		ServiceName:     "openmesh-test",
		openKeyring:     func(keyring.Config) (keyring.Keyring, error) { return nil, keyring.ErrNoAvailImpl },
		machineIDSource: machineID,
		allowedBackends: append([]keyring.BackendType(nil), systemBackends...),
		itemKey:         privateKeyItemKey,
	}
	if err := store1.ensureLoaded(); err != nil {
		t.Fatalf("ensureLoaded store1: %v", err)
	}

	store2 := &KeyStore{
		DataDir:         dataDir,
		ServiceName:     "openmesh-test",
		openKeyring:     func(keyring.Config) (keyring.Keyring, error) { return nil, keyring.ErrNoAvailImpl },
		machineIDSource: machineID,
		allowedBackends: append([]keyring.BackendType(nil), systemBackends...),
		itemKey:         privateKeyItemKey,
	}
	if err := store2.ensureLoaded(); err != nil {
		t.Fatalf("ensureLoaded store2: %v", err)
	}

	if string(store1.GetPrivateKey()) != string(store2.GetPrivateKey()) {
		t.Fatalf("private keys do not match across loads")
	}
	if string(store1.GetPublicKey()) != string(store2.GetPublicKey()) {
		t.Fatalf("public keys do not match across loads")
	}
	if store1.GetNodeID() != store2.GetNodeID() {
		t.Fatalf("node ids do not match: %q != %q", store1.GetNodeID(), store2.GetNodeID())
	}
}

func TestKeyStoreUsesKeyringWhenAvailable(t *testing.T) {
	t.Parallel()

	arrayRing := keyring.NewArrayKeyring(nil)
	store := &KeyStore{
		DataDir:         t.TempDir(),
		ServiceName:     "openmesh-test",
		openKeyring:     func(keyring.Config) (keyring.Keyring, error) { return arrayRing, nil },
		machineIDSource: func() (string, error) { return "", errors.New("unused") },
		allowedBackends: append([]keyring.BackendType(nil), systemBackends...),
		itemKey:         privateKeyItemKey,
	}
	if err := store.ensureLoaded(); err != nil {
		t.Fatalf("ensureLoaded store: %v", err)
	}

	storeReloaded := &KeyStore{
		DataDir:         t.TempDir(),
		ServiceName:     "openmesh-test",
		openKeyring:     func(keyring.Config) (keyring.Keyring, error) { return arrayRing, nil },
		machineIDSource: func() (string, error) { return "", errors.New("unused") },
		allowedBackends: append([]keyring.BackendType(nil), systemBackends...),
		itemKey:         privateKeyItemKey,
	}
	if err := storeReloaded.ensureLoaded(); err != nil {
		t.Fatalf("ensureLoaded reloaded: %v", err)
	}

	if string(store.GetPrivateKey()) != string(storeReloaded.GetPrivateKey()) {
		t.Fatalf("expected keyring-backed private key to persist")
	}
}
