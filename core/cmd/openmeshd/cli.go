package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	cfgpkg "github.com/openmesh/core/config"
	"github.com/spf13/cobra"
)

const (
	defaultConfigFileName = "config.json"
	defaultListenAddr     = ":443"

	envListenAddr = "OPENMESH_LISTEN_ADDR"
	envIPCPath    = "OPENMESH_IPC_PATH"
)

type rootOptions struct {
	configPath string
}

type startOptions struct {
	mode      string
	hops      int
	bandwidth int
	utun      bool
}

func newRootCommand() *cobra.Command {
	rootOpts := &rootOptions{}
	startOpts := &startOptions{}

	cmd := &cobra.Command{
		Use:           "openmeshd",
		Short:         "OpenMesh node daemon",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.PersistentFlags().StringVar(&rootOpts.configPath, "config", defaultConfigPath(), "Path to config.json")

	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the OpenMesh daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStart(cmd.Context(), cmd.OutOrStdout(), rootOpts, startOpts, cmd)
		},
	}
	startCmd.Flags().StringVar(&startOpts.mode, "mode", "", "Run mode: client, relay, exit, or full")
	startCmd.Flags().IntVar(&startOpts.hops, "hops", 0, "Circuit hop count: 1, 2, or 3")
	startCmd.Flags().IntVar(&startOpts.bandwidth, "bandwidth", 0, "Bandwidth limit in Mbps")
	startCmd.Flags().BoolVar(&startOpts.utun, "utun", false, "Enable the macOS utun system tunnel")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Print daemon status",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStatus(cmd.OutOrStdout(), rootOpts)
		},
	}

	peersCmd := &cobra.Command{
		Use:   "peers",
		Short: "List known peers with scores",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPeers(cmd.OutOrStdout(), rootOpts)
		},
	}

	selfRecordCmd := &cobra.Command{
		Use:   "self-record",
		Short: "Print the persisted self peer record as JSON",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSelfRecord(cmd.OutOrStdout(), rootOpts)
		},
	}

	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the running daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStop(cmd.OutOrStdout(), rootOpts)
		},
	}

	cmd.AddCommand(startCmd, statusCmd, peersCmd, selfRecordCmd, stopCmd)
	return cmd
}

func runStart(ctx context.Context, out io.Writer, rootOpts *rootOptions, startOpts *startOptions, cmd *cobra.Command) error {
	configPath, cfg, dataDir, err := loadRuntimeConfig(rootOpts.configPath)
	if err != nil {
		return err
	}

	if cmd.Flags().Changed("mode") {
		cfg.Mode = startOpts.mode
	}
	if cmd.Flags().Changed("hops") {
		cfg.Hops = startOpts.hops
	}
	if cmd.Flags().Changed("bandwidth") {
		cfg.BandwidthLimitMbps = startOpts.bandwidth
	}

	if err := validateRuntimeConfig(cfg); err != nil {
		return err
	}
	if err := cfgpkg.SaveConfig(cfg, configPath); err != nil {
		return err
	}

	daemon, err := newDaemon(configPath, dataDir, cfg, daemonOptions{
		enableSystemTunnel: startOpts.utun,
	})
	if err != nil {
		return err
	}
	defer daemon.Close()

	if err := ensureNoRunningDaemon(daemon.ipcEndpoint); err != nil {
		return err
	}

	runCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	_, _ = fmt.Fprintf(out, "openmeshd running in %s mode\n", daemon.mode)
	return daemon.Run(runCtx)
}

func runStatus(out io.Writer, rootOpts *rootOptions) error {
	_, _, dataDir, err := loadRuntimeConfig(rootOpts.configPath)
	if err != nil {
		return err
	}

	response, err := sendIPCRequest(ipcEndpoint(dataDir), ipcRequest{Command: ipcCommandStatus}, 3*time.Second)
	if err != nil {
		return fmt.Errorf("daemon is not running: %w", err)
	}
	if response.Error != "" {
		return fmt.Errorf("%s", response.Error)
	}
	if response.Status == nil {
		return fmt.Errorf("daemon returned no status")
	}

	printStatus(out, *response.Status)
	return nil
}

func runPeers(out io.Writer, rootOpts *rootOptions) error {
	_, _, dataDir, err := loadRuntimeConfig(rootOpts.configPath)
	if err != nil {
		return err
	}

	response, err := sendIPCRequest(ipcEndpoint(dataDir), ipcRequest{Command: ipcCommandPeers}, 3*time.Second)
	if err != nil {
		return fmt.Errorf("daemon is not running: %w", err)
	}
	if response.Error != "" {
		return fmt.Errorf("%s", response.Error)
	}

	printPeers(out, response.Peers)
	return nil
}

func runStop(out io.Writer, rootOpts *rootOptions) error {
	_, _, dataDir, err := loadRuntimeConfig(rootOpts.configPath)
	if err != nil {
		return err
	}

	response, err := sendIPCRequest(ipcEndpoint(dataDir), ipcRequest{Command: ipcCommandStop}, 3*time.Second)
	if err != nil {
		return fmt.Errorf("daemon is not running: %w", err)
	}
	if response.Error != "" {
		return fmt.Errorf("%s", response.Error)
	}

	message := response.Message
	if strings.TrimSpace(message) == "" {
		message = "stop signal sent"
	}
	_, _ = fmt.Fprintln(out, message)
	return nil
}

func runSelfRecord(out io.Writer, rootOpts *rootOptions) error {
	_, _, dataDir, err := loadRuntimeConfig(rootOpts.configPath)
	if err != nil {
		return err
	}

	path := filepath.Join(dataDir, selfRecordFileName)
	bytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("self record is not available yet: start the node once, then retry")
		}
		return err
	}

	var payload any
	if err := json.Unmarshal(bytes, &payload); err != nil {
		return fmt.Errorf("invalid self record at %s: %w", path, err)
	}

	pretty, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	pretty = append(pretty, '\n')
	_, _ = out.Write(pretty)
	return nil
}

func printStatus(out io.Writer, status daemonStatus) {
	_, _ = fmt.Fprintf(out, "Node ID: %s\n", status.NodeID)
	_, _ = fmt.Fprintf(out, "Mode: %s\n", status.Mode)
	_, _ = fmt.Fprintf(out, "Started: %s\n", status.StartedAt.Format(time.RFC3339))
	if status.ListenAddr != "" {
		_, _ = fmt.Fprintf(out, "Listen: %s\n", status.ListenAddr)
	}
	_, _ = fmt.Fprintf(out, "Known peers: %d\n", status.KnownPeers)
	_, _ = fmt.Fprintf(out, "Bandwidth used: %d bytes\n", status.BandwidthUsedBytes)
	if status.Tunnel != nil {
		_, _ = fmt.Fprintf(out, "Tunnel: %s via %s\n", status.Tunnel.InterfaceName, status.Tunnel.PhysicalInterface)
	}

	if status.Circuit == nil {
		_, _ = fmt.Fprintln(out, "Circuit: inactive")
		return
	}

	_, _ = fmt.Fprintf(out, "Circuit: %d hops, %d streams, created %s\n", status.Circuit.Hops, status.Circuit.Streams, status.Circuit.CreatedAt.Format(time.RFC3339))
	if len(status.Circuit.Path) > 0 {
		_, _ = fmt.Fprintf(out, "Path: %s\n", strings.Join(status.Circuit.Path, " -> "))
	}
}

func printPeers(out io.Writer, peers []daemonPeer) {
	if len(peers) == 0 {
		_, _ = fmt.Fprintln(out, "No peers known.")
		return
	}

	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Score != peers[j].Score {
			return peers[i].Score > peers[j].Score
		}
		return peers[i].ID < peers[j].ID
	})

	writer := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(writer, "ID\tSCORE\tRELAY\tEXIT\tCOUNTRY\tASN\tBANDWIDTH\tLAST_SEEN\tADDRS")
	for _, peer := range peers {
		lastSeen := ""
		if peer.LastSeen != 0 {
			lastSeen = time.Unix(peer.LastSeen, 0).UTC().Format(time.RFC3339)
		}
		_, _ = fmt.Fprintf(
			writer,
			"%s\t%.2f\t%t\t%t\t%s\t%d\t%d\t%s\t%s\n",
			peer.ID,
			peer.Score,
			peer.Relay,
			peer.Exit,
			peer.Country,
			peer.ASN,
			peer.BandwidthMbps,
			lastSeen,
			strings.Join(peer.Addrs, ","),
		)
	}
	_ = writer.Flush()
}

func ensureNoRunningDaemon(endpoint string) error {
	response, err := sendIPCRequest(endpoint, ipcRequest{Command: ipcCommandStatus}, 750*time.Millisecond)
	if err != nil {
		return nil
	}
	if response.Error == "" {
		return fmt.Errorf("daemon is already running")
	}
	return nil
}

func loadRuntimeConfig(path string) (string, *cfgpkg.Config, string, error) {
	configPath, err := expandUserPath(path)
	if err != nil {
		return "", nil, "", err
	}

	cfg, err := cfgpkg.LoadConfig(configPath)
	if err != nil {
		return "", nil, "", err
	}

	dataDir, err := expandUserPath(cfg.DataDir)
	if err != nil {
		return "", nil, "", err
	}
	return configPath, cfg, dataDir, nil
}

func validateRuntimeConfig(cfg *cfgpkg.Config) error {
	switch normalizeMode(cfg.Mode) {
	case modeClient, modeRelay, modeExit, modeFull:
	default:
		return fmt.Errorf("invalid mode %q", cfg.Mode)
	}

	if cfg.Hops < 1 || cfg.Hops > 3 {
		return fmt.Errorf("invalid hops %d: must be 1, 2, or 3", cfg.Hops)
	}
	if cfg.BandwidthLimitMbps < 0 {
		return fmt.Errorf("invalid bandwidth %d: must be non-negative", cfg.BandwidthLimitMbps)
	}
	return nil
}

func defaultConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", defaultConfigFileName)
	}
	return filepath.Join(homeDir, ".openmesh", defaultConfigFileName)
}

func expandUserPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			return homeDir, nil
		}
		return filepath.Join(homeDir, path[2:]), nil
	}
	return path, nil
}

func normalizeMode(mode string) string {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		return modeRelay
	}
	return mode
}

func printJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
