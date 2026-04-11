package transport

import (
	"net"
	"syscall"
	"time"
)

func newBoundDialer(timeout time.Duration, interfaceName string, interfaceIndex int) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: socketControlFunc(interfaceName, interfaceIndex),
	}
}

func newBoundListenConfig(interfaceName string, interfaceIndex int) net.ListenConfig {
	return net.ListenConfig{
		Control: socketControlFunc(interfaceName, interfaceIndex),
	}
}

func socketControlFunc(interfaceName string, interfaceIndex int) func(string, string, syscall.RawConn) error {
	if interfaceName == "" && interfaceIndex == 0 {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		return applySocketBinding(network, address, c, interfaceName, interfaceIndex)
	}
}
