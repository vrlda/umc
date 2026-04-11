package openmeshmobile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cfgpkg "github.com/openmesh/core/config"
	"github.com/openmesh/core/dht"
	nodemgr "github.com/openmesh/core/node"
)

const (
	peerTableFileName = "mobile-peers.json"

	modeOff    = "off"
	modeRelay  = "relay"
	modeExit   = "exit"
	modeClient = "client"
	modeFull   = "full"
)

var (
	errInvalidMode = errors.New("openmeshmobile: invalid mode")
	errInvalidHops = errors.New("openmeshmobile: hops must be 1, 2, or 3")
	errInvalidTun  = errors.New("openmeshmobile: tun file descriptor must be non-negative")
)

type Engine struct {
	dataDir string

	mu      sync.RWMutex
	saveMu  sync.Mutex
	mode    string
	hops    int
	bandwid int
	tunFD   int

	keyStore  *cfgpkg.KeyStore
	dhtNode   *dht.Node
	announcer *nodemgr.PeerAnnouncer

	announceCancel        context.CancelFunc
	running               bool
	relayPaused           bool
	bytesIn               int64
	bytesOut              int64
	startedAt             time.Time
	peerTablePath         string
	bootstrapManifestURLs []string
}

type status struct {
	NodeID          string `json:"node_id"`
	Running         bool   `json:"running"`
	Mode            string `json:"mode"`
	Hops            int    `json:"hops"`
	BandwidthMbps   int    `json:"bandwidth_mbps"`
	TunFD           int    `json:"tun_fd"`
	RelaySuspended  bool   `json:"relay_suspended"`
	BytesIn         int64  `json:"bytes_in"`
	BytesOut        int64  `json:"bytes_out"`
	KnownPeers      int    `json:"known_peers"`
	StartedAtUnix   int64  `json:"started_at_unix"`
	LastUpdatedUnix int64  `json:"last_updated_unix"`
}

func NewEngine(dataDir string) (*Engine, error) {
	resolvedDataDir, err := resolveDataDir(dataDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(resolvedDataDir, 0o700); err != nil {
		return nil, err
	}

	keyStore, err := cfgpkg.NewFallbackKeyStore(resolvedDataDir)
	if err != nil {
		return nil, err
	}

	dhtNode, err := dht.NewNode(keyStore.GetNodeID())
	if err != nil {
		return nil, err
	}

	peerTablePath := filepath.Join(resolvedDataDir, peerTableFileName)
	if err := dhtNode.LoadPeerTable(peerTablePath); err != nil {
		return nil, err
	}

	return &Engine{
		dataDir:               resolvedDataDir,
		mode:                  modeOff,
		hops:                  2,
		bandwid:               10,
		tunFD:                 -1,
		keyStore:              keyStore,
		dhtNode:               dhtNode,
		peerTablePath:         peerTablePath,
		bootstrapManifestURLs: cfgpkg.DefaultBootstrapManifestURLs(),
	}, nil
}

func (e *Engine) Configure(mode string, hops int, bandwidthMbps int) error {
	mode = normalizeMode(mode)
	if !isAllowedMode(mode) {
		return errInvalidMode
	}
	if hops < 1 || hops > 3 {
		return errInvalidHops
	}
	if bandwidthMbps < 0 {
		bandwidthMbps = 0
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.mode = mode
	e.hops = hops
	e.bandwid = bandwidthMbps
	return nil
}

func (e *Engine) AttachTun(fd int) error {
	if fd < 0 {
		return errInvalidTun
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.tunFD = fd
	return nil
}

func (e *Engine) Start() error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil
	}
	e.running = true
	e.startedAt = time.Now()
	paused := e.relayPaused
	e.mu.Unlock()

	if len(e.dhtNode.Peers()) == 0 {
		e.bootstrapPeerTable()
	}

	if shouldAnnounce(e.Mode()) && !paused {
		if err := e.startAnnouncer(); err != nil {
			return err
		}
	}

	return e.savePeerTable()
}

func (e *Engine) SetBootstrapManifestURLs(raw string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bootstrapManifestURLs = cfgpkg.ParseStringList(raw)
}

func (e *Engine) Stop() error {
	e.stopAnnouncer()

	e.mu.Lock()
	e.running = false
	e.mu.Unlock()

	return e.savePeerTable()
}

func (e *Engine) SetRelaySuspended(suspended bool) error {
	e.mu.Lock()
	wasRunning := e.running
	mode := e.mode
	e.relayPaused = suspended
	e.mu.Unlock()

	if !wasRunning || !shouldAnnounce(mode) {
		return nil
	}

	if suspended {
		e.stopAnnouncer()
		return nil
	}
	return e.startAnnouncer()
}

func (e *Engine) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

func (e *Engine) BytesIn() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.bytesIn
}

func (e *Engine) BytesOut() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.bytesOut
}

func (e *Engine) Mode() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mode
}

func (e *Engine) NodeID() string {
	return e.keyStore.GetNodeID()
}

func (e *Engine) StatusJSON() string {
	e.mu.RLock()
	currentStatus := status{
		NodeID:          e.keyStore.GetNodeID(),
		Running:         e.running,
		Mode:            e.mode,
		Hops:            e.hops,
		BandwidthMbps:   e.bandwid,
		TunFD:           e.tunFD,
		RelaySuspended:  e.relayPaused,
		BytesIn:         e.bytesIn,
		BytesOut:        e.bytesOut,
		KnownPeers:      len(e.dhtNode.Peers()),
		StartedAtUnix:   e.startedAt.Unix(),
		LastUpdatedUnix: time.Now().Unix(),
	}
	e.mu.RUnlock()

	bytes, err := json.Marshal(currentStatus)
	if err != nil {
		return `{}`
	}
	return string(bytes)
}

func (e *Engine) startAnnouncer() error {
	e.stopAnnouncer()

	record := e.selfRecord()
	store := &mobileStore{engine: e}
	announcer := &nodemgr.PeerAnnouncer{
		Store:  store,
		Record: record,
	}

	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.announcer = announcer
	e.announceCancel = cancel
	e.mu.Unlock()

	go func() {
		_ = announcer.Run(ctx)
	}()
	return nil
}

func (e *Engine) stopAnnouncer() {
	e.mu.Lock()
	cancel := e.announceCancel
	e.announceCancel = nil
	e.announcer = nil
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
}

func (e *Engine) selfRecord() dht.PeerRecord {
	e.mu.RLock()
	mode := e.mode
	bandwidth := e.bandwid
	e.mu.RUnlock()

	return dht.PeerRecord{
		ID:            e.keyStore.GetNodeID(),
		PubKey:        base64.StdEncoding.EncodeToString(e.keyStore.GetPublicKey()),
		Relay:         mode == modeRelay || mode == modeExit || mode == modeFull,
		Exit:          mode == modeExit || mode == modeFull,
		BandwidthMbps: bandwidth,
		UptimeScore:   1,
		LastSeen:      time.Now().Unix(),
	}
}

func (e *Engine) bootstrapPeerTable() {
	e.mu.RLock()
	urls := append([]string(nil), e.bootstrapManifestURLs...)
	e.mu.RUnlock()

	for _, url := range cfgpkg.NormalizeStringList(urls) {
		records, err := dht.FetchPeerManifest(context.Background(), url)
		if err != nil {
			continue
		}
		for _, record := range records {
			if strings.TrimSpace(record.ID) == "" {
				continue
			}
			_ = e.dhtNode.Put(record.ID, record)
		}
	}
}

func shouldAnnounce(mode string) bool {
	mode = normalizeMode(mode)
	return mode == modeRelay || mode == modeExit || mode == modeFull
}

func isAllowedMode(mode string) bool {
	switch mode {
	case modeOff, modeRelay, modeExit, modeClient, modeFull:
		return true
	default:
		return false
	}
}

func normalizeMode(mode string) string {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		return modeOff
	}
	return mode
}

func resolveDataDir(dataDir string) (string, error) {
	if dataDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(homeDir, ".openmesh-mobile"), nil
	}
	if dataDir == "~" || strings.HasPrefix(dataDir, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if dataDir == "~" {
			return homeDir, nil
		}
		return filepath.Join(homeDir, dataDir[2:]), nil
	}
	return dataDir, nil
}

type mobileStore struct {
	engine *Engine
}

func (s *mobileStore) Put(id string, record dht.PeerRecord) error {
	if err := s.engine.dhtNode.Put(id, record); err != nil {
		return err
	}
	return s.engine.savePeerTable()
}

func (e *Engine) savePeerTable() error {
	e.saveMu.Lock()
	defer e.saveMu.Unlock()
	return e.dhtNode.SavePeerTable(e.peerTablePath)
}
