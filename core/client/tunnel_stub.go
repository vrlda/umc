//go:build !darwin

package client

import "github.com/openmesh/core/routing"

func StartSystemTunnel(_ func() *routing.Circuit, _ Options) (Tunnel, error) {
	return nil, ErrTunnelUnsupported
}
