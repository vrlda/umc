//go:build !windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"time"
)

func ipcEndpoint(dataDir string) string {
	if override := os.Getenv(envIPCPath); override != "" {
		return override
	}

	base := filepath.Join(dataDir, "openmeshd.sock")
	if len(base) <= 100 {
		return base
	}
	sum := sha256.Sum256([]byte(base))
	return filepath.Join(os.TempDir(), "openmeshd-"+hex.EncodeToString(sum[:8])+".sock")
}

func listenIPC(endpoint string) (net.Listener, error) {
	_ = cleanupIPCEndpoint(endpoint)
	return net.Listen("unix", endpoint)
}

func dialIPC(endpoint string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", endpoint, timeout)
}

func cleanupIPCEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	if err := os.Remove(endpoint); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
