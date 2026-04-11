//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"time"

	"github.com/natefinch/npipe"
)

func ipcEndpoint(dataDir string) string {
	if override := os.Getenv(envIPCPath); override != "" {
		return override
	}

	sanitized := strings.NewReplacer(":", "", "\\", "", "/", "", ".", "").Replace(dataDir)
	if sanitized == "" {
		sanitized = "default"
	}
	if len(sanitized) > 24 {
		sum := sha256.Sum256([]byte(sanitized))
		sanitized = hex.EncodeToString(sum[:8])
	}
	return `\\.\pipe\openmeshd-` + sanitized
}

func listenIPC(endpoint string) (net.Listener, error) {
	return npipe.Listen(endpoint)
}

func dialIPC(endpoint string, timeout time.Duration) (net.Conn, error) {
	return npipe.DialTimeout(endpoint, timeout)
}

func cleanupIPCEndpoint(string) error {
	return nil
}
