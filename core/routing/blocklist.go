package routing

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const DefaultMalwareBlocklistURL = "https://urlhaus.abuse.ch/downloads/hostfile/"

// DomainBlocklist stores blocked domains fetched from a remote threat-intel source.
type DomainBlocklist struct {
	SourceURL string
	Client    *http.Client

	mu      sync.RWMutex
	domains map[string]struct{}
}

// Refresh downloads and replaces the current blocklist contents.
func (b *DomainBlocklist) Refresh(ctx context.Context) error {
	if b == nil || strings.TrimSpace(b.SourceURL) == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.SourceURL, nil)
	if err != nil {
		return err
	}

	resp, err := b.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	next := make(map[string]struct{})
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		domain := parseBlocklistLine(scanner.Text())
		if domain == "" {
			continue
		}
		next[domain] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	b.domains = next
	b.mu.Unlock()
	return nil
}

// Blocks reports whether the host or one of its parent domains is present in the blocklist.
func (b *DomainBlocklist) Blocks(host string) bool {
	if b == nil {
		return false
	}

	host = normalizeBlockHost(host)
	if host == "" {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	for {
		if _, blocked := b.domains[host]; blocked {
			return true
		}
		index := strings.IndexByte(host, '.')
		if index < 0 {
			return false
		}
		host = host[index+1:]
	}
}

func (b *DomainBlocklist) httpClient() *http.Client {
	if b != nil && b.Client != nil {
		return b.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func parseBlocklistLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}

	candidate := fields[0]
	if len(fields) > 1 {
		candidate = fields[len(fields)-1]
	}
	return normalizeBlockHost(candidate)
}

func normalizeBlockHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || host == "localhost" {
		return ""
	}
	return host
}
