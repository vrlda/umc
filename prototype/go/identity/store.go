package identity

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Store allows platforms to provide keychain, hardware-backed, or custom
// persistence without coupling identity to an application.
type Store interface {
	Load(name string) (*Identity, error)
	Save(name string, identity *Identity) error
}

// FileStore is the minimal portable store. It relies on filesystem permissions;
// production applications should prefer a platform keychain implementation.
type FileStore struct{ Directory string }

type storedIdentity struct {
	PrivateKey string `json:"private_key"`
}

func (s FileStore) Load(name string) (*Identity, error) {
	path, err := s.path(name)
	if err != nil {
		return nil, err
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var stored storedIdentity
	if err := json.Unmarshal(bytes, &stored); err != nil {
		return nil, err
	}
	private, err := base64.StdEncoding.DecodeString(stored.PrivateKey)
	if err != nil {
		return nil, err
	}
	return FromPrivateKey(private)
}

func (s FileStore) Save(name string, identity *Identity) error {
	if identity == nil {
		return errors.New("identity: cannot save nil identity")
	}
	if err := os.MkdirAll(s.Directory, 0o700); err != nil {
		return err
	}
	payload, err := json.Marshal(storedIdentity{
		PrivateKey: base64.StdEncoding.EncodeToString(identity.PrivateKey()),
	})
	if err != nil {
		return err
	}
	path, err := s.path(name)
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(payload, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func (s FileStore) LoadOrCreate(name string) (*Identity, error) {
	identity, err := s.Load(name)
	if err == nil {
		return identity, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	identity, err = New()
	if err != nil {
		return nil, err
	}
	if err := s.Save(name, identity); err != nil {
		return nil, err
	}
	return identity, nil
}

func (s FileStore) path(name string) (string, error) {
	if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
		return "", errors.New("identity: invalid store name")
	}
	return filepath.Join(s.Directory, name+".json"), nil
}
