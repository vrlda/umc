package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/99designs/keyring"
	"golang.org/x/crypto/curve25519"
)

const (
	defaultMode          = "relay"
	defaultHops          = 2
	defaultBandwidthMbps = 10
	defaultLogLevel      = "warn"
	defaultDataDir       = "~/.openmesh"
	defaultBlocklist     = "default"
	defaultServiceName   = "openmesh"
	privateKeyItemKey    = "node-private-x25519"
	fallbackKeyFileName  = "identity.enc"
	envBootstrapURLs     = "OPENMESH_BOOTSTRAP_MANIFEST_URLS"
)

var (
	errInvalidPrivateKey    = errors.New("config: private key must be 32 bytes")
	errMachineIDUnavailable = errors.New("config: unable to derive machine identifier")
	systemBackends          = []keyring.BackendType{
		keyring.WinCredBackend,
		keyring.KeychainBackend,
		keyring.SecretServiceBackend,
		keyring.KWalletBackend,
		keyring.KeyCtlBackend,
	}
)

type ExitPolicy struct {
	Ports     []int  `json:"ports"`
	Blocklist string `json:"blocklist"`
}

type Config struct {
	Mode                  string     `json:"mode"`
	Hops                  int        `json:"hops"`
	BandwidthLimitMbps    int        `json:"bandwidth_limit_mbps"`
	ExitPolicy            ExitPolicy `json:"exit_policy"`
	DataDir               string     `json:"data_dir"`
	LogLevel              string     `json:"log_level"`
	BootstrapManifestURLs []string   `json:"bootstrap_manifest_urls,omitempty"`
}

func DefaultConfig() *Config {
	return &Config{
		Mode:               defaultMode,
		Hops:               defaultHops,
		BandwidthLimitMbps: defaultBandwidthMbps,
		ExitPolicy: ExitPolicy{
			Ports:     []int{443},
			Blocklist: defaultBlocklist,
		},
		DataDir:               defaultDataDir,
		LogLevel:              defaultLogLevel,
		BootstrapManifestURLs: DefaultBootstrapManifestURLs(),
	}
}

func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("config: path is required")
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}

		cfg := DefaultConfig()
		if err := SaveConfig(cfg, path); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	cfg := DefaultConfig()
	if len(strings.TrimSpace(string(bytes))) == 0 {
		return cfg, nil
	}

	if err := json.Unmarshal(bytes, cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	return cfg, nil
}

func SaveConfig(cfg *Config, path string) error {
	if path == "" {
		return errors.New("config: path is required")
	}

	normalized := DefaultConfig()
	if cfg != nil {
		*normalized = *cfg
		if cfg.ExitPolicy.Ports != nil {
			normalized.ExitPolicy.Ports = append([]int(nil), cfg.ExitPolicy.Ports...)
		}
		if cfg.BootstrapManifestURLs != nil {
			normalized.BootstrapManifestURLs = append([]string(nil), cfg.BootstrapManifestURLs...)
		}
	}
	normalized.applyDefaults()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	bytes, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return err
	}
	bytes = append(bytes, '\n')

	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, bytes, 0o600); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = defaultMode
	}
	if c.Hops == 0 {
		c.Hops = defaultHops
	}
	if c.BandwidthLimitMbps == 0 {
		c.BandwidthLimitMbps = defaultBandwidthMbps
	}
	if len(c.ExitPolicy.Ports) == 0 {
		c.ExitPolicy.Ports = []int{443}
	}
	if c.ExitPolicy.Blocklist == "" {
		c.ExitPolicy.Blocklist = defaultBlocklist
	}
	if c.DataDir == "" {
		c.DataDir = defaultDataDir
	}
	if c.LogLevel == "" {
		c.LogLevel = defaultLogLevel
	}
	if c.BootstrapManifestURLs == nil {
		c.BootstrapManifestURLs = DefaultBootstrapManifestURLs()
	}
	c.BootstrapManifestURLs = NormalizeStringList(c.BootstrapManifestURLs)
}

func DefaultBootstrapManifestURLs() []string {
	return ParseStringList(os.Getenv(envBootstrapURLs))
}

func ParseStringList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return NormalizeStringList(strings.Split(raw, ","))
}

func NormalizeStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

type encryptedKeyFile struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type keyringOpener func(keyring.Config) (keyring.Keyring, error)

type KeyStore struct {
	DataDir     string
	ServiceName string

	openKeyring     keyringOpener
	machineIDSource func() (string, error)
	allowedBackends []keyring.BackendType
	itemKey         string

	mu         sync.Mutex
	ring       keyring.Keyring
	privateKey []byte
	publicKey  []byte
	nodeID     string
}

func NewKeyStore(dataDir string) (*KeyStore, error) {
	ks := &KeyStore{
		DataDir:         dataDir,
		ServiceName:     defaultServiceName,
		openKeyring:     keyring.Open,
		machineIDSource: defaultMachineID,
		allowedBackends: append([]keyring.BackendType(nil), systemBackends...),
		itemKey:         privateKeyItemKey,
	}
	if err := ks.ensureLoaded(); err != nil {
		return nil, err
	}
	return ks, nil
}

// NewFallbackKeyStore creates a keystore that skips OS keyring backends and always uses the encrypted file fallback.
func NewFallbackKeyStore(dataDir string) (*KeyStore, error) {
	ks := &KeyStore{
		DataDir:         dataDir,
		ServiceName:     defaultServiceName,
		machineIDSource: defaultMachineID,
		itemKey:         privateKeyItemKey,
	}
	if err := ks.ensureLoaded(); err != nil {
		return nil, err
	}
	return ks, nil
}

func (k *KeyStore) GetPrivateKey() []byte {
	if err := k.ensureLoaded(); err != nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]byte(nil), k.privateKey...)
}

func (k *KeyStore) GetPublicKey() []byte {
	if err := k.ensureLoaded(); err != nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]byte(nil), k.publicKey...)
}

func (k *KeyStore) GetNodeID() string {
	if err := k.ensureLoaded(); err != nil {
		return ""
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.nodeID
}

func (k *KeyStore) ensureLoaded() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if len(k.privateKey) != 0 {
		return nil
	}

	privateKey, err := k.loadOrGeneratePrivateKey()
	if err != nil {
		return err
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return err
	}
	nodeID := sha256.Sum256(publicKey)

	k.privateKey = append([]byte(nil), privateKey...)
	k.publicKey = append([]byte(nil), publicKey...)
	k.nodeID = hex.EncodeToString(nodeID[:])
	return nil
}

func (k *KeyStore) loadOrGeneratePrivateKey() ([]byte, error) {
	var (
		ring    keyring.Keyring
		ringErr error
	)

	ring, ringErr = k.openConfiguredKeyring()
	if ring != nil {
		privateKey, err := k.loadFromKeyring(ring)
		if err == nil {
			return privateKey, nil
		}
		if !errors.Is(err, keyring.ErrKeyNotFound) {
			ringErr = err
			ring = nil
		}
	}

	privateKey, fallbackErr := k.loadFromFallback()
	if fallbackErr == nil {
		if ring != nil {
			_ = k.storeInKeyring(ring, privateKey)
		}
		return privateKey, nil
	}
	if !errors.Is(fallbackErr, os.ErrNotExist) {
		if ringErr != nil {
			return nil, errors.Join(ringErr, fallbackErr)
		}
		return nil, fallbackErr
	}

	privateKey, err := generatePrivateKey()
	if err != nil {
		return nil, err
	}

	if ring != nil {
		if err := k.storeInKeyring(ring, privateKey); err == nil {
			return privateKey, nil
		} else {
			ringErr = err
		}
	}

	if err := k.storeToFallback(privateKey); err != nil {
		if ringErr != nil {
			return nil, errors.Join(ringErr, err)
		}
		return nil, err
	}
	return privateKey, nil
}

func (k *KeyStore) openConfiguredKeyring() (keyring.Keyring, error) {
	if k.ring != nil {
		return k.ring, nil
	}
	if k.openKeyring == nil {
		return nil, keyring.ErrNoAvailImpl
	}

	serviceName := k.ServiceName
	if serviceName == "" {
		serviceName = defaultServiceName
	}

	ring, err := k.openKeyring(keyring.Config{
		ServiceName:     serviceName,
		AllowedBackends: append([]keyring.BackendType(nil), k.allowedBackends...),
	})
	if err != nil {
		return nil, err
	}
	k.ring = ring
	return ring, nil
}

func (k *KeyStore) loadFromKeyring(ring keyring.Keyring) ([]byte, error) {
	item, err := ring.Get(k.itemKeyName())
	if err != nil {
		return nil, err
	}
	return normalizePrivateKey(item.Data)
}

func (k *KeyStore) storeInKeyring(ring keyring.Keyring, privateKey []byte) error {
	normalized, err := normalizePrivateKey(privateKey)
	if err != nil {
		return err
	}
	return ring.Set(keyring.Item{
		Key:         k.itemKeyName(),
		Data:        normalized,
		Label:       "OpenMesh node identity",
		Description: "OpenMesh X25519 node private key",
	})
}

func (k *KeyStore) loadFromFallback() ([]byte, error) {
	bytes, err := os.ReadFile(k.fallbackFilePath())
	if err != nil {
		return nil, err
	}

	var payload encryptedKeyFile
	if err := json.Unmarshal(bytes, &payload); err != nil {
		return nil, err
	}

	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return nil, err
	}

	encryptionKey, err := k.encryptionKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(k.itemKeyName()))
	if err != nil {
		return nil, err
	}
	return normalizePrivateKey(plaintext)
}

func (k *KeyStore) storeToFallback(privateKey []byte) error {
	normalized, err := normalizePrivateKey(privateKey)
	if err != nil {
		return err
	}

	dataDir, err := expandPath(k.dataDir())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}

	encryptionKey, err := k.encryptionKey()
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, normalized, []byte(k.itemKeyName()))

	payload := encryptedKeyFile{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	bytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return os.WriteFile(k.fallbackFilePath(), bytes, 0o600)
}

func (k *KeyStore) encryptionKey() ([]byte, error) {
	machineID, err := k.machineID()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(k.serviceName() + ":" + machineID))
	return sum[:], nil
}

func (k *KeyStore) machineID() (string, error) {
	if k.machineIDSource != nil {
		id, err := k.machineIDSource()
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(id) != "" {
			return strings.TrimSpace(id), nil
		}
	}
	return "", errMachineIDUnavailable
}

func (k *KeyStore) dataDir() string {
	if k.DataDir != "" {
		return k.DataDir
	}
	return defaultDataDir
}

func (k *KeyStore) serviceName() string {
	if k.ServiceName != "" {
		return k.ServiceName
	}
	return defaultServiceName
}

func (k *KeyStore) itemKeyName() string {
	if k.itemKey != "" {
		return k.itemKey
	}
	return privateKeyItemKey
}

func (k *KeyStore) fallbackFilePath() string {
	dataDir, err := expandPath(k.dataDir())
	if err != nil {
		return filepath.Join(k.dataDir(), fallbackKeyFileName)
	}
	return filepath.Join(dataDir, fallbackKeyFileName)
}

func generatePrivateKey() ([]byte, error) {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func normalizePrivateKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) != 32 {
		return nil, errInvalidPrivateKey
	}
	return append([]byte(nil), privateKey...), nil
}

func expandPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			return homeDir, nil
		}
		return filepath.Join(homeDir, path[2:]), nil
	}
	return path, nil
}

func defaultMachineID() (string, error) {
	candidates := []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
		"/sys/class/dmi/id/product_uuid",
	}

	for _, candidate := range candidates {
		bytes, err := os.ReadFile(candidate)
		if err == nil {
			if id := strings.TrimSpace(string(bytes)); id != "" {
				return id, nil
			}
		}
	}

	hostname, err := os.Hostname()
	if err != nil {
		return "", errMachineIDUnavailable
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return "", errMachineIDUnavailable
	}
	return hostname, nil
}
