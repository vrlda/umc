package client

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParseRouteGetOutput(t *testing.T) {
	lookup, err := parseRouteGetOutput(`
   route to: default
destination: default
    gateway: 192.168.5.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,IFSCOPE,GLOBAL>
`)
	if err != nil {
		t.Fatalf("parseRouteGetOutput returned error: %v", err)
	}
	if lookup.Interface != "en0" {
		t.Fatalf("unexpected interface: got %q want %q", lookup.Interface, "en0")
	}
	if got := lookup.Gateway.String(); got != "192.168.5.1" {
		t.Fatalf("unexpected gateway: got %q want %q", got, "192.168.5.1")
	}
}

func TestParseDNSServers(t *testing.T) {
	output := `
resolver #1
  search domain[0] : tail.ts.net
  nameserver[0] : 100.100.100.100
  if_index : 29 (utun7)

resolver #2
  search domain[0] : example.local
  nameserver[0] : 192.168.5.1
  nameserver[1] : 1.1.1.1
  if_index : 14 (en0)
`
	got := parseDNSServers(output, "en0")
	want := []netip.Addr{
		netip.MustParseAddr("192.168.5.1"),
		netip.MustParseAddr("1.1.1.1"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected dns servers: got %v want %v", got, want)
	}
}

func TestRoutePlanIncludesSplitRoutesAndDNSBypass(t *testing.T) {
	plan := routePlan{
		TunnelInterface:   "utun42",
		PhysicalInterface: "en0",
		PhysicalGateway:   netip.MustParseAddr("192.168.5.1"),
		DNSServers: []netip.Addr{
			netip.MustParseAddr("192.168.5.1"),
		},
	}

	commands := strings.Join(plan.startCommands(), "\n")
	for _, fragment := range []string{
		"ifconfig 'utun42' inet '198.51.100.1' '198.51.100.1' up",
		"route -n add -net 0.0.0.0/1 -interface 'utun42'",
		"route -n add -inet6 -net ::/1 -interface 'utun42'",
		"route -n add -host -ifscope 'en0' '192.168.5.1' '192.168.5.1'",
	} {
		if !strings.Contains(commands, fragment) {
			t.Fatalf("expected command fragment %q in %s", fragment, commands)
		}
	}
}
