//go:build !darwin

package main

import "fmt"

type outboundInterface struct {
	Name  string
	Index int
}

func detectTunnelBypassInterface() (outboundInterface, error) {
	return outboundInterface{}, fmt.Errorf("system tunnel interface binding is only available on macOS")
}
