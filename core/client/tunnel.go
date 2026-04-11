package client

import "errors"

var (
	ErrTunnelUnsupported = errors.New("client: system tunnel is not supported on this platform")
	ErrNoCircuit         = errors.New("client: no circuit is available for tunneled traffic")
)

type TunnelStatus struct {
	Active            bool
	InterfaceName     string
	PhysicalInterface string
	DNSServers        []string
	MTU               int
}

type Tunnel interface {
	Close() error
	Status() TunnelStatus
}

type Options struct {
	InterfaceName string
	MTU           int
}
