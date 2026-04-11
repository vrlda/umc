//go:build darwin

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/openmesh/core/routing"
	tunstack "github.com/xjasonlyu/tun2socks/v2/core"
	tunDevice "github.com/xjasonlyu/tun2socks/v2/core/device"
	tunNative "github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"github.com/xjasonlyu/tun2socks/v2/tunnel/statistic"
	gvstack "gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	defaultMTU             = 1500
	defaultInterfaceName   = "utun"
	tunnelIPv4Address      = "198.51.100.1"
	tunnelIPv6Address      = "fd42:4f50:4d45:5348::1"
	defaultScopedProbeHost = "1.1.1.1"
)

type systemTunnel struct {
	device tunDevice.Device
	stack  *gvstack.Stack
	tunnel *tunnel.Tunnel

	status      TunnelStatus
	cleanupPlan routePlan
	closeOnce   sync.Once
	closeErr    error
}

type physicalRoute struct {
	Interface string
	Gateway   netip.Addr
	DNS       []netip.Addr
}

type routePlan struct {
	TunnelInterface   string
	PhysicalInterface string
	PhysicalGateway   netip.Addr
	DNSServers        []netip.Addr
}

type routeLookup struct {
	Interface string
	Gateway   netip.Addr
}

func StartSystemTunnel(circuitFn func() *routing.Circuit, opts Options) (Tunnel, error) {
	if circuitFn == nil {
		return nil, ErrNoCircuit
	}

	mtu := opts.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}
	interfaceName := strings.TrimSpace(opts.InterfaceName)
	if interfaceName == "" {
		interfaceName = defaultInterfaceName
	}

	physical, err := discoverPhysicalRoute()
	if err != nil {
		return nil, err
	}

	device, err := tunNative.Open(interfaceName, uint32(mtu))
	if err != nil {
		return nil, err
	}

	tunnelName := device.Name()
	tcpTunnel := tunnel.New(&circuitDialer{circuitFn: circuitFn}, statistic.DefaultManager)
	tcpTunnel.ProcessAsync()

	stack, err := tunstack.CreateStack(&tunstack.Config{
		LinkEndpoint:     device,
		TransportHandler: tcpTunnel,
	})
	if err != nil {
		tcpTunnel.Close()
		device.Close()
		return nil, err
	}

	plan := routePlan{
		TunnelInterface:   tunnelName,
		PhysicalInterface: physical.Interface,
		PhysicalGateway:   physical.Gateway,
		DNSServers:        append([]netip.Addr(nil), physical.DNS...),
	}
	if err := runPrivilegedCommands(plan.startCommands()); err != nil {
		stack.Close()
		stack.Wait()
		tcpTunnel.Close()
		device.Close()
		return nil, err
	}

	return &systemTunnel{
		device: device,
		stack:  stack,
		tunnel: tcpTunnel,
		status: TunnelStatus{
			Active:            true,
			InterfaceName:     tunnelName,
			PhysicalInterface: physical.Interface,
			DNSServers:        netipStrings(physical.DNS),
			MTU:               mtu,
		},
		cleanupPlan: plan,
	}, nil
}

func (t *systemTunnel) Close() error {
	t.closeOnce.Do(func() {
		var errs []error
		if err := runPrivilegedCommands(t.cleanupPlan.stopCommands()); err != nil {
			errs = append(errs, err)
		}
		if t.tunnel != nil {
			t.tunnel.Close()
		}
		if t.stack != nil {
			t.stack.Close()
			t.stack.Wait()
		}
		if t.device != nil {
			t.device.Close()
		}
		t.status.Active = false
		t.closeErr = errors.Join(errs...)
	})
	return t.closeErr
}

func (t *systemTunnel) Status() TunnelStatus {
	status := t.status
	status.DNSServers = append([]string(nil), status.DNSServers...)
	return status
}

type circuitDialer struct {
	circuitFn func() *routing.Circuit
}

func (d *circuitDialer) DialContext(_ context.Context, metadata *metadata.Metadata) (net.Conn, error) {
	circuit := d.circuitFn()
	if circuit == nil {
		return nil, ErrNoCircuit
	}
	if metadata == nil {
		return nil, fmt.Errorf("client: missing metadata")
	}

	stream, err := circuit.OpenStream(metadata.DstIP.String(), int(metadata.DstPort))
	if err != nil {
		return nil, err
	}
	return newStreamConn(stream, metadata), nil
}

func (d *circuitDialer) DialUDP(metadata *metadata.Metadata) (net.PacketConn, error) {
	circuit := d.circuitFn()
	if circuit == nil {
		return nil, ErrNoCircuit
	}
	if metadata == nil {
		return nil, fmt.Errorf("client: missing metadata")
	}

	return circuit.OpenPacketConn(metadata.DstIP.String(), int(metadata.DstPort))
}

type streamConn struct {
	stream *routing.Stream
	local  net.Addr
	remote net.Addr
}

func newStreamConn(stream *routing.Stream, metadata *metadata.Metadata) net.Conn {
	return &streamConn{
		stream: stream,
		local:  &net.TCPAddr{IP: net.IPv4zero, Port: 0},
		remote: &net.TCPAddr{IP: metadata.DstIP.AsSlice(), Port: int(metadata.DstPort)},
	}
}

func (c *streamConn) Read(p []byte) (int, error)       { return c.stream.Read(p) }
func (c *streamConn) Write(p []byte) (int, error)      { return c.stream.Write(p) }
func (c *streamConn) Close() error                     { return c.stream.Close() }
func (c *streamConn) LocalAddr() net.Addr              { return c.local }
func (c *streamConn) RemoteAddr() net.Addr             { return c.remote }
func (c *streamConn) SetDeadline(time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

func discoverPhysicalRoute() (physicalRoute, error) {
	lookup, err := routeGet("", "default")
	if err == nil && lookup.Interface != "" && !isTunnelInterface(lookup.Interface) && lookup.Gateway.IsValid() {
		return physicalRoute{
			Interface: lookup.Interface,
			Gateway:   lookup.Gateway,
			DNS:       dnsServersForInterface(lookup.Interface),
		}, nil
	}

	candidates := dnsResolverInterfaces()
	for _, candidate := range candidates {
		lookup, candidateErr := routeGet(candidate, defaultScopedProbeHost)
		if candidateErr != nil || lookup.Interface == "" || isTunnelInterface(lookup.Interface) || !lookup.Gateway.IsValid() {
			continue
		}
		return physicalRoute{
			Interface: lookup.Interface,
			Gateway:   lookup.Gateway,
			DNS:       dnsServersForInterface(lookup.Interface),
		}, nil
	}

	return physicalRoute{}, fmt.Errorf("client: unable to determine a physical default route")
}

func routeGet(interfaceName, destination string) (routeLookup, error) {
	args := []string{"-n", "get"}
	if interfaceName != "" {
		args = append(args, "-ifscope", interfaceName)
	}
	args = append(args, destination)

	output, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		return routeLookup{}, fmt.Errorf("client: route lookup failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return parseRouteGetOutput(string(output))
}

func parseRouteGetOutput(output string) (routeLookup, error) {
	var lookup routeLookup
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		switch {
		case strings.HasPrefix(line, "interface:"):
			lookup.Interface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		case strings.HasPrefix(line, "gateway:"):
			addr := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
			if parsed, err := netip.ParseAddr(addr); err == nil {
				lookup.Gateway = parsed
			}
		}
	}

	if lookup.Interface == "" {
		return routeLookup{}, fmt.Errorf("client: route output did not include an interface")
	}
	return lookup, nil
}

func dnsResolverInterfaces() []string {
	output, err := exec.Command("scutil", "--dns").CombinedOutput()
	if err != nil {
		return nil
	}
	interfaces := parseDNSInterfaces(string(output))
	return uniqStrings(interfaces)
}

func dnsServersForInterface(interfaceName string) []netip.Addr {
	output, err := exec.Command("scutil", "--dns").CombinedOutput()
	if err != nil {
		return nil
	}
	return parseDNSServers(string(output), interfaceName)
}

func parseDNSInterfaces(output string) []string {
	var interfaces []string
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(line, "if_index :") {
			continue
		}
		start := strings.Index(line, "(")
		end := strings.Index(line, ")")
		if start == -1 || end == -1 || end <= start+1 {
			continue
		}
		iface := strings.TrimSpace(line[start+1 : end])
		if iface != "" && !isTunnelInterface(iface) {
			interfaces = append(interfaces, iface)
		}
	}
	return interfaces
}

func parseDNSServers(output, interfaceName string) []netip.Addr {
	type resolver struct {
		iface       string
		nameservers []netip.Addr
	}

	var (
		current resolver
		all     []resolver
	)

	flush := func() {
		if current.iface != "" || len(current.nameservers) > 0 {
			current.nameservers = uniqAddrs(current.nameservers)
			all = append(all, current)
		}
		current = resolver{}
	}

	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, "resolver #"):
			flush()
		case strings.HasPrefix(line, "if_index :"):
			start := strings.Index(line, "(")
			end := strings.Index(line, ")")
			if start != -1 && end != -1 && end > start+1 {
				current.iface = strings.TrimSpace(line[start+1 : end])
			}
		case strings.HasPrefix(line, "nameserver["):
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			addr, err := netip.ParseAddr(strings.TrimSpace(parts[1]))
			if err == nil {
				current.nameservers = append(current.nameservers, addr)
			}
		}
	}
	flush()

	for _, resolver := range all {
		if resolver.iface == interfaceName {
			return append([]netip.Addr(nil), resolver.nameservers...)
		}
	}
	return nil
}

func (p routePlan) startCommands() []string {
	commands := []string{
		fmt.Sprintf("ifconfig %s inet %s %s up", shellQuote(p.TunnelInterface), shellQuote(tunnelIPv4Address), shellQuote(tunnelIPv4Address)),
		fmt.Sprintf("ifconfig %s inet6 %s/64 up", shellQuote(p.TunnelInterface), shellQuote(tunnelIPv6Address)),
		fmt.Sprintf("route -n delete -net 0.0.0.0/1 -interface %s >/dev/null 2>&1 || true", shellQuote(p.TunnelInterface)),
		fmt.Sprintf("route -n add -net 0.0.0.0/1 -interface %s", shellQuote(p.TunnelInterface)),
		fmt.Sprintf("route -n delete -net 128.0.0.0/1 -interface %s >/dev/null 2>&1 || true", shellQuote(p.TunnelInterface)),
		fmt.Sprintf("route -n add -net 128.0.0.0/1 -interface %s", shellQuote(p.TunnelInterface)),
		fmt.Sprintf("route -n delete -inet6 -net ::/1 -interface %s >/dev/null 2>&1 || true", shellQuote(p.TunnelInterface)),
		fmt.Sprintf("route -n add -inet6 -net ::/1 -interface %s", shellQuote(p.TunnelInterface)),
		fmt.Sprintf("route -n delete -inet6 -net 8000::/1 -interface %s >/dev/null 2>&1 || true", shellQuote(p.TunnelInterface)),
		fmt.Sprintf("route -n add -inet6 -net 8000::/1 -interface %s", shellQuote(p.TunnelInterface)),
	}

	if p.PhysicalGateway.IsValid() {
		for _, server := range p.DNSServers {
			if server.Is4() && p.PhysicalGateway.Is4() {
				commands = append(commands,
					fmt.Sprintf("route -n delete -host -ifscope %s %s %s >/dev/null 2>&1 || true", shellQuote(p.PhysicalInterface), shellQuote(server.String()), shellQuote(p.PhysicalGateway.String())),
					fmt.Sprintf("route -n add -host -ifscope %s %s %s", shellQuote(p.PhysicalInterface), shellQuote(server.String()), shellQuote(p.PhysicalGateway.String())),
				)
			}
		}
	}

	return commands
}

func (p routePlan) stopCommands() []string {
	commands := []string{
		fmt.Sprintf("route -n delete -net 0.0.0.0/1 -interface %s >/dev/null 2>&1 || true", shellQuote(p.TunnelInterface)),
		fmt.Sprintf("route -n delete -net 128.0.0.0/1 -interface %s >/dev/null 2>&1 || true", shellQuote(p.TunnelInterface)),
		fmt.Sprintf("route -n delete -inet6 -net ::/1 -interface %s >/dev/null 2>&1 || true", shellQuote(p.TunnelInterface)),
		fmt.Sprintf("route -n delete -inet6 -net 8000::/1 -interface %s >/dev/null 2>&1 || true", shellQuote(p.TunnelInterface)),
	}
	if p.PhysicalGateway.IsValid() {
		for _, server := range p.DNSServers {
			if server.Is4() && p.PhysicalGateway.Is4() {
				commands = append(commands,
					fmt.Sprintf("route -n delete -host -ifscope %s %s %s >/dev/null 2>&1 || true", shellQuote(p.PhysicalInterface), shellQuote(server.String()), shellQuote(p.PhysicalGateway.String())),
				)
			}
		}
	}
	return commands
}

func runPrivilegedCommands(commands []string) error {
	if len(commands) == 0 {
		return nil
	}

	script := "PATH=/usr/sbin:/sbin:/usr/bin:/bin; set -e; " + strings.Join(commands, "; ")
	if os.Geteuid() == 0 {
		output, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
		if err != nil {
			return fmt.Errorf("client: privileged shell failed: %w: %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	}

	output, err := exec.Command("osascript", "-e", "do shell script "+appleScriptQuote(script)+" with administrator privileges").CombinedOutput()
	if err != nil {
		return fmt.Errorf("client: administrator privileges were required: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func appleScriptQuote(value string) string {
	escaped := strings.ReplaceAll(value, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
	return "\"" + escaped + "\""
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func isTunnelInterface(name string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(name)), "utun")
}

func uniqStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func uniqAddrs(values []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(values))
	result := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func netipStrings(values []netip.Addr) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.String())
	}
	return result
}
