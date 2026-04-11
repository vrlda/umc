//go:build darwin

package transport

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func applySocketBinding(network, address string, c syscall.RawConn, interfaceName string, interfaceIndex int) (err error) {
	host, _, splitErr := net.SplitHostPort(address)
	if splitErr == nil {
		if ip := net.ParseIP(host); ip != nil && !ip.IsGlobalUnicast() {
			return nil
		}
	}

	if interfaceIndex == 0 && interfaceName != "" {
		iface, lookupErr := net.InterfaceByName(interfaceName)
		if lookupErr != nil {
			return lookupErr
		}
		interfaceIndex = iface.Index
	}
	if interfaceIndex == 0 {
		return nil
	}

	var innerErr error
	if err := c.Control(func(fd uintptr) {
		switch network {
		case "tcp4", "udp4":
			innerErr = unix.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_BOUND_IF, interfaceIndex)
		case "tcp6", "udp6":
			innerErr = unix.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, interfaceIndex)
		}
	}); err != nil {
		return err
	}

	return innerErr
}
