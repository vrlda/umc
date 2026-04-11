package routing

import (
	"context"
	"net"
	"net/http"
	"strconv"

	"github.com/openmesh/core/dht"
	"github.com/openmesh/core/handshake"
	"github.com/openmesh/core/transport"
)

// RelayNode accepts client circuits, decrypts one layer, and forwards traffic to the next hop.
type RelayNode struct {
	Listener           transport.Listener
	Transport          transport.Transport
	Handshaker         *handshake.Handshaker
	PrivateKey         []byte
	BandwidthLimitMbps int
}

// Serve accepts relay traffic until the context is canceled.
func (n *RelayNode) Serve(ctx context.Context) error {
	server := &HopServer{
		Listener:   wrapListener(n.BandwidthLimitMbps, n.Listener),
		Transport:  wrapTransport(n.BandwidthLimitMbps, n.Transport),
		Handshaker: n.Handshaker,
		PrivateKey: n.PrivateKey,
		StreamDialContext: func(context.Context, string, int) (net.Conn, error) {
			return nil, errRelayCannotExit
		},
		PacketDialContext: func(context.Context, string, int) (*packetSession, error) {
			return nil, errRelayCannotExit
		},
	}
	return server.Serve(ctx)
}

// ExitNode accepts final-hop circuits, enforces exit policy, and connects to destinations.
type ExitNode struct {
	Transport          transport.Transport
	Listener           transport.Listener
	Handshaker         *handshake.Handshaker
	PrivateKey         []byte
	BandwidthLimitMbps int
	Policy             dht.ExitPolicy
	Blocklist          *DomainBlocklist
	BlocklistURL       string
	BlocklistClient    *http.Client
	DialContext        StreamDialContext
	PacketDialContext  PacketDialContext
}

// RefreshBlocklist fetches the configured malware-domain blocklist.
func (n *ExitNode) RefreshBlocklist(ctx context.Context) error {
	if n.Blocklist == nil {
		n.Blocklist = &DomainBlocklist{
			SourceURL: n.blocklistURL(),
			Client:    n.BlocklistClient,
		}
	} else {
		if n.Blocklist.SourceURL == "" {
			n.Blocklist.SourceURL = n.blocklistURL()
		}
		if n.Blocklist.Client == nil {
			n.Blocklist.Client = n.BlocklistClient
		}
	}
	return n.Blocklist.Refresh(ctx)
}

// Serve accepts exit traffic until the context is canceled.
func (n *ExitNode) Serve(ctx context.Context) error {
	_ = n.RefreshBlocklist(ctx)

	server := &HopServer{
		Listener:   wrapListener(n.BandwidthLimitMbps, n.Listener),
		Transport:  wrapTransport(n.BandwidthLimitMbps, n.Transport),
		Handshaker: n.Handshaker,
		PrivateKey: n.PrivateKey,
		StreamDialContext: func(ctx context.Context, dst string, port int) (net.Conn, error) {
			if port <= 0 {
				port = 443
			}
			if err := n.enforceExitPolicy(dst, port); err != nil {
				return nil, err
			}
			conn, err := n.streamDialer()(ctx, dst, port)
			if err != nil {
				return nil, err
			}
			return wrapNetConn(n.BandwidthLimitMbps, conn), nil
		},
		PacketDialContext: func(ctx context.Context, dst string, port int) (*packetSession, error) {
			if port <= 0 {
				port = 443
			}
			if err := n.enforceExitPolicy(dst, port); err != nil {
				return nil, err
			}
			return n.packetDialer()(ctx, dst, port)
		},
	}
	return server.Serve(ctx)
}

func (n *ExitNode) enforceExitPolicy(dst string, port int) error {
	if len(n.Policy.Ports) > 0 {
		allowed := false
		for _, allowedPort := range n.Policy.Ports {
			if port == allowedPort {
				allowed = true
				break
			}
		}
		if !allowed {
			return errPortNotAllowed
		}
	}

	if n.Blocklist != nil && n.Blocklist.Blocks(dst) {
		return errBlockedDestination
	}
	return nil
}

func (n *ExitNode) streamDialer() StreamDialContext {
	if n.DialContext != nil {
		return n.DialContext
	}

	dialer := net.Dialer{}
	return func(ctx context.Context, dst string, port int) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(dst, strconv.Itoa(port)))
	}
}

func (n *ExitNode) blocklistURL() string {
	if n.BlocklistURL != "" {
		return n.BlocklistURL
	}
	return DefaultMalwareBlocklistURL
}

func (n *ExitNode) packetDialer() PacketDialContext {
	if n.PacketDialContext != nil {
		return n.PacketDialContext
	}

	return func(ctx context.Context, dst string, port int) (*packetSession, error) {
		remoteAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(dst, strconv.Itoa(port)))
		if err != nil {
			return nil, err
		}

		dialer := net.Dialer{}
		conn, err := dialer.DialContext(ctx, "udp", remoteAddr.String())
		if err != nil {
			return nil, err
		}

		packetConn, ok := conn.(net.PacketConn)
		if !ok {
			_ = conn.Close()
			return nil, errRelayCannotExit
		}

		return &packetSession{
			conn:   packetConn,
			remote: remoteAddr,
		}, nil
	}
}
