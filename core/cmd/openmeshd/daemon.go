package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	clientpkg "github.com/openmesh/core/client"
	cfgpkg "github.com/openmesh/core/config"
	"github.com/openmesh/core/dht"
	"github.com/openmesh/core/handshake"
	nodemgr "github.com/openmesh/core/node"
	"github.com/openmesh/core/routing"
	transportpkg "github.com/openmesh/core/transport"
	"github.com/rs/zerolog"
)

const (
	modeClient = "client"
	modeRelay  = "relay"
	modeExit   = "exit"
	modeFull   = "full"

	peerTableFileName  = "peers.json"
	selfRecordFileName = "self-record.json"
)

type daemon struct {
	configPath  string
	dataDir     string
	ipcEndpoint string

	cfg       *cfgpkg.Config
	logger    zerolog.Logger
	logCloser io.Closer

	keyStore       *cfgpkg.KeyStore
	dhtNode        *dht.Node
	peerSelector   *nodemgr.PeerSelector
	transport      transportpkg.Transport
	circuitBuilder *routing.CircuitBuilder

	peerTablePath  string
	selfRecordPath string

	mode       string
	listenAddr string
	startedAt  time.Time

	mu         sync.RWMutex
	selfRecord dht.PeerRecord
	circuit    *routing.Circuit
	listener   transportpkg.Listener
	tunnel     clientpkg.Tunnel
	tunnelOn   bool

	runCancel     context.CancelFunc
	announcer     *nodemgr.PeerAnnouncer
	announcerStop context.CancelFunc

	asyncErrCh   chan error
	backgroundWG sync.WaitGroup
	closeOnce    sync.Once
}

type daemonOptions struct {
	enableSystemTunnel bool
}

type daemonStatus struct {
	NodeID             string             `json:"node_id"`
	Mode               string             `json:"mode"`
	ListenAddr         string             `json:"listen_addr,omitempty"`
	StartedAt          time.Time          `json:"started_at"`
	KnownPeers         int                `json:"known_peers"`
	BandwidthUsedBytes int64              `json:"bandwidth_used_bytes"`
	Circuit            *daemonCircuitInfo `json:"circuit,omitempty"`
	Tunnel             *daemonTunnelInfo  `json:"tunnel,omitempty"`
}

type daemonCircuitInfo struct {
	Hops      int       `json:"hops"`
	Streams   int       `json:"streams"`
	CreatedAt time.Time `json:"created_at"`
	Path      []string  `json:"path"`
}

type daemonTunnelInfo struct {
	InterfaceName     string   `json:"interface_name"`
	PhysicalInterface string   `json:"physical_interface"`
	DNSServers        []string `json:"dns_servers,omitempty"`
	MTU               int      `json:"mtu"`
}

type daemonPeer struct {
	ID            string   `json:"id"`
	Score         float64  `json:"score"`
	Relay         bool     `json:"relay"`
	Exit          bool     `json:"exit"`
	Country       string   `json:"country"`
	ASN           int      `json:"asn"`
	BandwidthMbps int      `json:"bandwidth_mbps"`
	LastSeen      int64    `json:"last_seen"`
	Addrs         []string `json:"addrs"`
}

func newDaemon(configPath, dataDir string, cfg *cfgpkg.Config, opts daemonOptions) (*daemon, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}

	logger, logCloser, err := newDaemonLogger(dataDir, cfg.LogLevel)
	if err != nil {
		return nil, err
	}

	keyStore, err := cfgpkg.NewKeyStore(dataDir)
	if err != nil {
		_ = logCloser.Close()
		return nil, err
	}

	dhtNode, err := dht.NewNode(keyStore.GetNodeID())
	if err != nil {
		_ = logCloser.Close()
		return nil, err
	}

	peerTablePath := filepath.Join(dataDir, peerTableFileName)
	if err := dhtNode.LoadPeerTable(peerTablePath); err != nil {
		_ = logCloser.Close()
		return nil, err
	}

	transport := transportpkg.NewAutoTransport()
	if opts.enableSystemTunnel {
		if routeInfo, err := detectTunnelBypassInterface(); err == nil {
			transport.SetBindInterface(routeInfo.Name, routeInfo.Index)
		}
	}
	builder := &routing.CircuitBuilder{
		Transport:            transport,
		Handshaker:           &handshake.Handshaker{},
		LocalPrivateKey:      keyStore.GetPrivateKey(),
		KeepaliveInterval:    30 * time.Second,
		RotateAfter:          10 * time.Minute,
		MaxBytesBeforeRotate: 50 << 20,
	}

	return &daemon{
		configPath:     configPath,
		dataDir:        dataDir,
		ipcEndpoint:    ipcEndpoint(dataDir),
		cfg:            cfg,
		logger:         logger,
		logCloser:      logCloser,
		keyStore:       keyStore,
		dhtNode:        dhtNode,
		peerSelector:   nodemgr.NewPeerSelector(dhtNode),
		transport:      transport,
		circuitBuilder: builder,
		peerTablePath:  peerTablePath,
		selfRecordPath: filepath.Join(dataDir, selfRecordFileName),
		mode:           normalizeMode(cfg.Mode),
		tunnelOn:       opts.enableSystemTunnel,
		startedAt:      time.Now(),
		asyncErrCh:     make(chan error, 4),
	}, nil
}

func (d *daemon) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	d.runCancel = cancel
	defer d.Close()

	ipcServer, err := newIPCServer(d.ipcEndpoint, d.handleIPC)
	if err != nil {
		return err
	}
	defer ipcServer.Close()

	d.backgroundWG.Add(1)
	go func() {
		defer d.backgroundWG.Done()
		if err := ipcServer.Serve(runCtx); err != nil {
			d.reportAsyncErr(err)
		}
	}()

	if err := d.startServices(runCtx); err != nil {
		return err
	}

	d.logger.Info().
		Str("mode", d.mode).
		Str("node_id", d.keyStore.GetNodeID()).
		Str("ipc_endpoint", d.ipcEndpoint).
		Msg("daemon started")

	select {
	case <-runCtx.Done():
		return nil
	case err := <-d.asyncErrCh:
		return err
	}
}

func (d *daemon) Close() error {
	var closeErr error
	d.closeOnce.Do(func() {
		if d.runCancel != nil {
			d.runCancel()
		}
		if d.announcerStop != nil {
			d.announcerStop()
		}

		d.announceDeparture()

		d.mu.Lock()
		circuit := d.circuit
		d.circuit = nil
		listener := d.listener
		d.listener = nil
		tunnel := d.tunnel
		d.tunnel = nil
		d.mu.Unlock()

		if circuit != nil {
			_ = circuit.Close()
		}
		if tunnel != nil {
			_ = tunnel.Close()
		}
		if listener != nil {
			_ = listener.Close()
		}

		d.backgroundWG.Wait()

		if err := d.dhtNode.SavePeerTable(d.peerTablePath); err != nil && closeErr == nil {
			closeErr = err
		}
		if err := d.logCloser.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	})
	return closeErr
}

func (d *daemon) startServices(ctx context.Context) error {
	if d.shouldServe() {
		listenAddr := os.Getenv(envListenAddr)
		if strings.TrimSpace(listenAddr) == "" {
			listenAddr = defaultListenAddr
		}

		listener, err := d.transport.Listen(listenAddr)
		if err != nil {
			return err
		}

		d.mu.Lock()
		d.listener = listener
		d.listenAddr = listener.Addr().String()
		d.mu.Unlock()
		d.logger.Info().Str("listen_addr", d.listenAddr).Msg("listener started")
	}

	d.setSelfRecord(d.buildSelfRecord())

	if d.shouldAnnounce() {
		store := &selfRecordStore{daemon: d}
		announcer := &nodemgr.PeerAnnouncer{
			Store:  store,
			Record: d.currentSelfRecord(),
		}

		d.announcer = announcer
		announceCtx, cancel := context.WithCancel(ctx)
		d.announcerStop = cancel

		d.backgroundWG.Add(1)
		go func() {
			defer d.backgroundWG.Done()
			if err := announcer.Run(announceCtx); err != nil {
				d.reportAsyncErr(err)
			}
		}()
	}

	if d.shouldServe() {
		server, err := d.buildServer()
		if err != nil {
			return err
		}

		d.backgroundWG.Add(1)
		go func() {
			defer d.backgroundWG.Done()
			if err := server(ctx); err != nil {
				d.reportAsyncErr(err)
			}
		}()
	}

	if d.shouldBuildCircuit() {
		bootstrapCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		d.bootstrapIfNeeded(bootstrapCtx)
		cancel()

		d.tryBuildCircuit()
		if d.tunnelOn && d.currentCircuit() != nil {
			if err := d.tryStartTunnel(); err != nil {
				return err
			}
		}

		d.backgroundWG.Add(1)
		go func() {
			defer d.backgroundWG.Done()
			d.clientLoop(ctx)
		}()
	}

	return nil
}

func (d *daemon) buildServer() (func(context.Context) error, error) {
	d.mu.RLock()
	listener := d.listener
	d.mu.RUnlock()
	if listener == nil {
		return nil, fmt.Errorf("listener is not configured")
	}

	switch d.mode {
	case modeRelay:
		node := &routing.RelayNode{
			Listener:           listener,
			Transport:          d.transport,
			Handshaker:         &handshake.Handshaker{},
			PrivateKey:         d.keyStore.GetPrivateKey(),
			BandwidthLimitMbps: d.cfg.BandwidthLimitMbps,
		}
		return node.Serve, nil
	case modeExit:
		node := &routing.ExitNode{
			Listener:           listener,
			Handshaker:         &handshake.Handshaker{},
			PrivateKey:         d.keyStore.GetPrivateKey(),
			BandwidthLimitMbps: d.cfg.BandwidthLimitMbps,
			Policy:             toRoutingExitPolicy(d.cfg.ExitPolicy),
			BlocklistURL:       d.exitBlocklistURL(),
		}
		return node.Serve, nil
	case modeFull:
		node := &routing.ExitNode{
			Transport:          d.transport,
			Listener:           listener,
			Handshaker:         &handshake.Handshaker{},
			PrivateKey:         d.keyStore.GetPrivateKey(),
			BandwidthLimitMbps: d.cfg.BandwidthLimitMbps,
			Policy:             toRoutingExitPolicy(d.cfg.ExitPolicy),
			BlocklistURL:       d.exitBlocklistURL(),
		}
		return node.Serve, nil
	default:
		return nil, nil
	}
}

func (d *daemon) tryBuildCircuit() {
	excluded := make(map[string]struct{})
	maxAttempts := len(d.dhtNode.Peers())
	if maxAttempts == 0 {
		d.logger.Warn().Msg("no circuit available yet")
		return
	}

	var (
		peers   []dht.PeerRecord
		circuit *routing.Circuit
		err     error
	)

	for attempts := 0; attempts < maxAttempts; attempts++ {
		peers, err = d.peerSelector.SelectCircuitExcluding(d.cfg.Hops, "", excluded)
		if err != nil {
			break
		}

		circuit, err = d.circuitBuilder.Build(peers, d.cfg.Hops)
		if err == nil {
			for _, peer := range peers {
				d.peerSelector.ReportSuccess(peer.ID)
			}
			break
		}

		for _, peerID := range candidateFailurePeers(err, peers) {
			normalized := strings.ToLower(strings.TrimSpace(peerID))
			if normalized == "" {
				continue
			}
			excluded[normalized] = struct{}{}
			d.peerSelector.ReportFailure(peerID)
		}
	}
	if err != nil {
		d.logger.Warn().Err(err).Msg("failed to build circuit")
		return
	}

	d.mu.Lock()
	oldCircuit := d.circuit
	d.circuit = circuit
	d.mu.Unlock()
	if oldCircuit != nil {
		_ = oldCircuit.Close()
	}

	d.logger.Info().Int("hops", d.cfg.Hops).Msg("circuit established")
}

func candidateFailurePeers(err error, peers []dht.PeerRecord) []string {
	var unreachable *routing.PeerUnreachableError
	if errors.As(err, &unreachable) && strings.TrimSpace(unreachable.PeerID) != "" {
		return []string{unreachable.PeerID}
	}

	peerIDs := make([]string, 0, len(peers))
	for _, peer := range peers {
		if strings.TrimSpace(peer.ID) != "" {
			peerIDs = append(peerIDs, peer.ID)
		}
	}
	return peerIDs
}

func (d *daemon) shouldServe() bool {
	return d.mode == modeRelay || d.mode == modeExit || d.mode == modeFull
}

func (d *daemon) shouldAnnounce() bool {
	return d.shouldServe()
}

func (d *daemon) shouldBuildCircuit() bool {
	return d.mode == modeClient || d.mode == modeFull || d.tunnelOn
}

func (d *daemon) exitBlocklistURL() string {
	blocklist := strings.TrimSpace(d.cfg.ExitPolicy.Blocklist)
	switch strings.ToLower(blocklist) {
	case "", "default":
		return ""
	case "off", "none", "disabled":
		return ""
	default:
		return blocklist
	}
}

func (d *daemon) handleIPC(request ipcRequest) ipcResponse {
	switch request.Command {
	case ipcCommandStatus:
		status := d.status()
		return ipcResponse{Status: &status}
	case ipcCommandPeers:
		return ipcResponse{Peers: d.peerList()}
	case ipcCommandStop:
		go d.Stop()
		return ipcResponse{Message: "stop signal sent"}
	default:
		return ipcResponse{Error: fmt.Sprintf("unknown command %q", request.Command)}
	}
}

func (d *daemon) Stop() {
	if d.runCancel != nil {
		d.runCancel()
	}
}

func (d *daemon) status() daemonStatus {
	status := daemonStatus{
		NodeID:     d.keyStore.GetNodeID(),
		Mode:       d.mode,
		ListenAddr: d.listenAddr,
		StartedAt:  d.startedAt,
		KnownPeers: len(d.dhtNode.Peers()),
	}

	d.mu.RLock()
	circuit := d.circuit
	d.mu.RUnlock()

	if circuit != nil {
		snapshot := circuit.Snapshot()
		status.BandwidthUsedBytes = snapshot.BytesUsed

		path := make([]string, 0, len(snapshot.Path))
		for _, peer := range snapshot.Path {
			path = append(path, peer.ID)
		}
		status.Circuit = &daemonCircuitInfo{
			Hops:      snapshot.Hops,
			Streams:   snapshot.Streams,
			CreatedAt: snapshot.CreatedAt,
			Path:      path,
		}
	}

	if tunnel := d.currentTunnel(); tunnel != nil {
		tunnelStatus := tunnel.Status()
		status.Tunnel = &daemonTunnelInfo{
			InterfaceName:     tunnelStatus.InterfaceName,
			PhysicalInterface: tunnelStatus.PhysicalInterface,
			DNSServers:        append([]string(nil), tunnelStatus.DNSServers...),
			MTU:               tunnelStatus.MTU,
		}
	}

	return status
}

func (d *daemon) peerList() []daemonPeer {
	records := d.dhtNode.Peers()
	peers := make([]daemonPeer, 0, len(records))
	for _, record := range records {
		peers = append(peers, daemonPeer{
			ID:            record.ID,
			Score:         d.dhtNode.ScorePeer(record, 0.5),
			Relay:         record.Relay,
			Exit:          record.Exit,
			Country:       record.Country,
			ASN:           record.ASN,
			BandwidthMbps: record.BandwidthMbps,
			LastSeen:      record.LastSeen,
			Addrs:         append([]string(nil), record.Addrs...),
		})
	}
	return peers
}

func (d *daemon) buildSelfRecord() dht.PeerRecord {
	d.mu.RLock()
	listenAddr := d.listenAddr
	d.mu.RUnlock()

	relay := d.mode == modeRelay || d.mode == modeExit || d.mode == modeFull
	exit := d.mode == modeExit || d.mode == modeFull

	record := dht.PeerRecord{
		ID:            d.keyStore.GetNodeID(),
		PubKey:        base64.StdEncoding.EncodeToString(d.keyStore.GetPublicKey()),
		Relay:         relay,
		Exit:          exit,
		ExitPolicy:    toRoutingExitPolicy(d.cfg.ExitPolicy),
		BandwidthMbps: d.cfg.BandwidthLimitMbps,
		UptimeScore:   1,
		LastSeen:      time.Now().Unix(),
	}
	if listenAddr != "" {
		record.Addrs = []string{listenAddr}
	}
	return record
}

func (d *daemon) announceDeparture() {
	if !d.shouldAnnounce() || d.announcer == nil || d.announcer.Store == nil {
		return
	}

	record := d.currentSelfRecord()
	record.Addrs = nil
	record.Relay = false
	record.Exit = false
	record.UptimeScore = 0
	record.LastSeen = time.Now().Unix()
	_ = d.announcer.Store.Put(record.ID, record)
}

func (d *daemon) setSelfRecord(record dht.PeerRecord) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.selfRecord = clonePeerRecord(record)
}

func (d *daemon) currentSelfRecord() dht.PeerRecord {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return clonePeerRecord(d.selfRecord)
}

func (d *daemon) reportAsyncErr(err error) {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, os.ErrClosed) {
		return
	}
	d.logger.Error().Err(err).Msg("background task failed")
	select {
	case d.asyncErrCh <- err:
	default:
	}
	if d.runCancel != nil {
		d.runCancel()
	}
}

func (d *daemon) clientLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		d.mu.RLock()
		hasCircuit := d.circuit != nil
		hasTunnel := d.tunnel != nil
		d.mu.RUnlock()

		if !hasCircuit {
			if len(d.dhtNode.Peers()) == 0 {
				bootstrapCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				d.bootstrapIfNeeded(bootstrapCtx)
				cancel()
			}
			d.tryBuildCircuit()
		}
		if d.tunnelOn && !hasTunnel {
			if err := d.tryStartTunnel(); err != nil {
				d.reportAsyncErr(err)
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *daemon) tryStartTunnel() error {
	d.mu.RLock()
	if d.tunnel != nil {
		d.mu.RUnlock()
		return nil
	}
	d.mu.RUnlock()

	tunnel, err := clientpkg.StartSystemTunnel(d.currentCircuit, clientpkg.Options{})
	if err != nil {
		return err
	}

	d.mu.Lock()
	if d.tunnel != nil {
		d.mu.Unlock()
		_ = tunnel.Close()
		return nil
	}
	d.tunnel = tunnel
	d.mu.Unlock()

	d.logger.Info().
		Str("interface", tunnel.Status().InterfaceName).
		Msg("system tunnel enabled")
	return nil
}

func (d *daemon) currentCircuit() *routing.Circuit {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.circuit
}

func (d *daemon) currentTunnel() clientpkg.Tunnel {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.tunnel
}

func toRoutingExitPolicy(policy cfgpkg.ExitPolicy) dht.ExitPolicy {
	return dht.ExitPolicy{
		Ports:     append([]int(nil), policy.Ports...),
		Blocklist: policy.Blocklist,
	}
}

func clonePeerRecord(record dht.PeerRecord) dht.PeerRecord {
	record.Addrs = append([]string(nil), record.Addrs...)
	record.ExitPolicy.Ports = append([]int(nil), record.ExitPolicy.Ports...)
	return record
}

type selfRecordStore struct {
	daemon *daemon
}

func (s *selfRecordStore) Put(_ string, record dht.PeerRecord) error {
	record = clonePeerRecord(record)
	s.daemon.setSelfRecord(record)
	return writeJSONFile(s.daemon.selfRecordPath, record)
}

func writeJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	bytes, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	bytes = append(bytes, '\n')

	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, bytes, 0o600); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
