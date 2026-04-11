package routing

import "errors"

var (
	errNoTransport        = errors.New("routing: transport is not configured")
	errNoPrivateKey       = errors.New("routing: client private key is required")
	errInvalidHopCount    = errors.New("routing: hops must be between 1 and 3")
	errInsufficientPeers  = errors.New("routing: not enough peers to build circuit")
	errMissingPeerAddress = errors.New("routing: peer is missing an address")
	errInvalidPeerPubKey  = errors.New("routing: peer public key is invalid")
	errCircuitClosed      = errors.New("routing: circuit is closed")
	errNoTunnel           = errors.New("routing: tunnel is not established")
	errTunnelActive       = errors.New("routing: tunnel is already active")
	errUnexpectedPacket   = errors.New("routing: unexpected onion packet")
	errUnexpectedMessage  = errors.New("routing: unexpected routing message")
	errNoStreamDialer     = errors.New("routing: stream dialer is not configured")
	errStreamClosed       = errors.New("routing: stream is closed")
	errRelayCannotExit    = errors.New("routing: relay node cannot connect to destinations")
	errPortNotAllowed     = errors.New("routing: exit policy does not allow the requested port")
	errBlockedDestination = errors.New("routing: destination is blocked by exit policy")
)

func routingErrorFromResponse(message protocolMessage) error {
	if message.FailedPeerID != "" || message.FailedAddr != "" {
		return &PeerUnreachableError{
			PeerID: message.FailedPeerID,
			Addr:   message.FailedAddr,
			Stage:  message.FailedStage,
			Cause:  routingErrorFromString(message.Error),
		}
	}
	return routingErrorFromString(message.Error)
}

func routingErrorFromString(message string) error {
	switch message {
	case "":
		return nil
	case errNoTransport.Error():
		return errNoTransport
	case errNoPrivateKey.Error():
		return errNoPrivateKey
	case errInvalidHopCount.Error():
		return errInvalidHopCount
	case errInsufficientPeers.Error():
		return errInsufficientPeers
	case errMissingPeerAddress.Error():
		return errMissingPeerAddress
	case errInvalidPeerPubKey.Error():
		return errInvalidPeerPubKey
	case errCircuitClosed.Error():
		return errCircuitClosed
	case errNoTunnel.Error():
		return errNoTunnel
	case errTunnelActive.Error():
		return errTunnelActive
	case errUnexpectedPacket.Error():
		return errUnexpectedPacket
	case errUnexpectedMessage.Error():
		return errUnexpectedMessage
	case errNoStreamDialer.Error():
		return errNoStreamDialer
	case errStreamClosed.Error():
		return errStreamClosed
	case errRelayCannotExit.Error():
		return errRelayCannotExit
	case errPortNotAllowed.Error():
		return errPortNotAllowed
	case errBlockedDestination.Error():
		return errBlockedDestination
	case errPeerUnreachable.Error():
		return errPeerUnreachable
	default:
		return errors.New(message)
	}
}
