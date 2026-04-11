//go:build darwin

package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

type outboundInterface struct {
	Name  string
	Index int
}

func detectTunnelBypassInterface() (outboundInterface, error) {
	ifaceName := parseRouteInterface(runCommand("route", "-n", "get", "default"))
	if ifaceName != "" && !strings.HasPrefix(strings.ToLower(ifaceName), "utun") {
		return interfaceByName(ifaceName)
	}

	output := runCommand("scutil", "--dns")
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
		ifaceName = strings.TrimSpace(line[start+1 : end])
		if ifaceName == "" || strings.HasPrefix(strings.ToLower(ifaceName), "utun") {
			continue
		}
		return interfaceByName(ifaceName)
	}

	return outboundInterface{}, fmt.Errorf("unable to determine a physical interface for system tunnel bypass")
}

func interfaceByName(name string) (outboundInterface, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return outboundInterface{}, err
	}
	return outboundInterface{Name: iface.Name, Index: iface.Index}, nil
}

func parseRouteInterface(output string) string {
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "interface:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	return ""
}

func runCommand(name string, args ...string) string {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return ""
	}
	return string(output)
}
