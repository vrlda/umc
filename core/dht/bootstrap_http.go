package dht

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const WellKnownPeerRecordPath = "/.well-known/openmesh/peer-record.json"

func BootstrapRecordURL(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}

	if strings.Contains(addr, "://") {
		if strings.Contains(addr, WellKnownPeerRecordPath) {
			return addr
		}
		return strings.TrimRight(addr, "/") + WellKnownPeerRecordPath
	}
	return "https://" + strings.TrimRight(addr, "/") + WellKnownPeerRecordPath
}

func FetchPeerRecord(ctx context.Context, addr string) (PeerRecord, error) {
	url := BootstrapRecordURL(addr)
	if url == "" {
		return PeerRecord{}, fmt.Errorf("dht: bootstrap address is required")
	}

	var record PeerRecord
	if err := fetchJSON(ctx, url, &record); err != nil {
		return PeerRecord{}, err
	}
	return record, nil
}

func FetchPeerManifest(ctx context.Context, url string) ([]PeerRecord, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return nil, fmt.Errorf("dht: bootstrap manifest url is required")
	}

	var records []PeerRecord
	if err := fetchJSON(ctx, url, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func fetchJSON(ctx context.Context, url string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "openmesh-bootstrap/1.0")

	response, err := insecureBootstrapHTTPClient().Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("dht: bootstrap fetch %s returned %s", url, response.Status)
	}
	return json.NewDecoder(response.Body).Decode(target)
}

func insecureBootstrapHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
}
