package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

const KeySize = 32

var ErrInvalidPrivateKey = errors.New("identity: private key must be 32 bytes")

// ID is the stable address of a cryptographic endpoint.
type ID [32]byte

func (id ID) String() string { return hex.EncodeToString(id[:]) }

func ParseID(value string) (ID, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(ID{}) {
		return ID{}, errors.New("identity: invalid endpoint id")
	}
	var id ID
	copy(id[:], decoded)
	return id, nil
}

func IDFromPublicKey(public []byte) (ID, error) {
	if len(public) != KeySize {
		return ID{}, errors.New("identity: public key must be 32 bytes")
	}
	return sha256.Sum256(public), nil
}

// Identity holds the long-term X25519 key material for one generic endpoint.
// Ownership, delegation, recovery, and human naming belong in signed
// certificates layered above this routing identity.
type Identity struct {
	private [KeySize]byte
	public  [KeySize]byte
	id      ID
}

func New() (*Identity, error) { return Generate(rand.Reader) }

func Generate(random io.Reader) (*Identity, error) {
	private := make([]byte, KeySize)
	if _, err := io.ReadFull(random, private); err != nil {
		return nil, err
	}
	return FromPrivateKey(private)
}

func FromPrivateKey(private []byte) (*Identity, error) {
	if len(private) != KeySize {
		return nil, ErrInvalidPrivateKey
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	identity := &Identity{}
	copy(identity.private[:], private)
	copy(identity.public[:], public)
	identity.id = sha256.Sum256(public)
	return identity, nil
}

func (i *Identity) ID() ID { return i.id }

func (i *Identity) PublicKey() []byte {
	return append([]byte(nil), i.public[:]...)
}

// PrivateKey returns a defensive copy for cryptographic adapters and stores.
func (i *Identity) PrivateKey() []byte {
	return append([]byte(nil), i.private[:]...)
}
