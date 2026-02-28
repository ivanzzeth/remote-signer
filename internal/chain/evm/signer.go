package evm

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/ethsig"
	"github.com/ivanzzeth/ethsig/keystore"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// SignerConfig defines configuration for EVM signers
type SignerConfig struct {
	PrivateKeys []PrivateKeyConfig `yaml:"private_keys"`
	Keystores   []KeystoreConfig   `yaml:"keystores"`
	HDWallets   []HDWalletConfig   `yaml:"hd_wallets"`
}

// HDWalletConfig defines an HD wallet signer configuration
type HDWalletConfig struct {
	Path          string   `yaml:"path"`           // Path to encrypted HD wallet file
	PasswordEnv   string   `yaml:"password_env"`   // Environment variable containing password
	PasswordStdin bool     `yaml:"password_stdin"` // If true, read password from stdin
	DeriveIndices []uint32 `yaml:"derive_indices"` // Indices to derive at startup
	Enabled       bool     `yaml:"enabled"`        // Whether this HD wallet is enabled
}

// PrivateKeyConfig defines a private key signer configuration
type PrivateKeyConfig struct {
	Address   string `yaml:"address"`    // Expected address (for verification)
	KeyEnvVar string `yaml:"key_env"`    // Environment variable containing hex private key
	Enabled   bool   `yaml:"enabled"`    // Whether this signer is enabled
}

// KeystoreConfig defines a keystore signer configuration
type KeystoreConfig struct {
	Address       string `yaml:"address"`        // Expected address (for verification)
	Path          string `yaml:"path"`           // Path to keystore file
	PasswordEnv   string `yaml:"password_env"`   // Environment variable containing password (used when password_stdin is false)
	PasswordStdin bool   `yaml:"password_stdin"` // If true, read password from stdin at startup (more secure)
	Enabled       bool   `yaml:"enabled"`        // Whether this signer is enabled
}

// SignerRegistry manages EVM signers
type SignerRegistry struct {
	mu        sync.RWMutex
	signers   map[string]*ethsig.Signer           // address -> signer (flat, O(1) lookup)
	info      map[string]types.SignerInfo           // address -> metadata
	providers map[types.SignerType]SignerProvider    // type -> provider
}

// NewEmptySignerRegistry creates an empty registry for provider-based initialization.
func NewEmptySignerRegistry() *SignerRegistry {
	return &SignerRegistry{
		signers:   make(map[string]*ethsig.Signer),
		info:      make(map[string]types.SignerInfo),
		providers: make(map[types.SignerType]SignerProvider),
	}
}

// RegisterSigner adds a signer to the registry. Called by providers during init/derive.
func (r *SignerRegistry) RegisterSigner(address string, signer *ethsig.Signer, info types.SignerInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	addrKey := normalizeAddress(address)
	if _, exists := r.signers[addrKey]; exists {
		return types.ErrAlreadyExists
	}

	r.signers[addrKey] = signer
	r.info[addrKey] = info
	return nil
}

// RegisterProvider registers a provider for a given signer type.
func (r *SignerRegistry) RegisterProvider(p SignerProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.providers[p.Type()] = p
}

// Provider returns the provider for a given signer type.
func (r *SignerRegistry) Provider(t types.SignerType) (SignerProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.providers[t]
	return p, ok
}

// SignerCount returns the number of registered signers.
func (r *SignerRegistry) SignerCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.signers)
}

// Close closes all registered providers (zeroize keys, cleanup).
func (r *SignerRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var firstErr error
	for _, p := range r.providers {
		if err := p.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// NewSignerRegistry creates a new signer registry from configuration
// For keystores with password_stdin=true, passwords will be read from stdin interactively
func NewSignerRegistry(cfg SignerConfig) (*SignerRegistry, error) {
	// Check if any keystore requires stdin password
	hasStdinKeystores := false
	for _, ks := range cfg.Keystores {
		if ks.Enabled && ks.PasswordStdin {
			hasStdinKeystores = true
			break
		}
	}

	// Create composite password provider
	provider, err := NewCompositePasswordProvider(hasStdinKeystores)
	if err != nil {
		return nil, fmt.Errorf("failed to create password provider: %w", err)
	}

	return NewSignerRegistryWithProvider(cfg, provider)
}

// NewSignerRegistryWithProvider creates a new signer registry with a custom password provider
func NewSignerRegistryWithProvider(cfg SignerConfig, provider PasswordProvider) (*SignerRegistry, error) {
	if provider == nil {
		return nil, fmt.Errorf("password provider is required")
	}

	registry := &SignerRegistry{
		signers:   make(map[string]*ethsig.Signer),
		info:      make(map[string]types.SignerInfo),
		providers: make(map[types.SignerType]SignerProvider),
	}

	// Load private key signers
	for _, pk := range cfg.PrivateKeys {
		if !pk.Enabled {
			continue
		}

		// Support both direct hex value and environment variable name
		keyHex := resolvePrivateKey(pk.KeyEnvVar)
		if keyHex == "" {
			return nil, fmt.Errorf("private key is empty for signer %s (check key_env value or environment variable)", pk.Address)
		}

		privKeySigner, err := ethsig.NewEthPrivateKeySignerFromPrivateKeyHex(keyHex)
		if err != nil {
			return nil, fmt.Errorf("failed to create private key signer for %s: %w", pk.Address, err)
		}

		// Verify address matches
		expectedAddr := common.HexToAddress(pk.Address)
		actualAddr := privKeySigner.GetAddress()
		if actualAddr != expectedAddr {
			return nil, fmt.Errorf("address mismatch for %s: expected %s, got %s", pk.Address, expectedAddr.Hex(), actualAddr.Hex())
		}

		signer := ethsig.NewSigner(privKeySigner)
		addrKey := normalizeAddress(actualAddr.Hex())
		registry.signers[addrKey] = signer
		registry.info[addrKey] = types.SignerInfo{
			Address: actualAddr.Hex(),
			Type:    "private_key",
			Enabled: true,
		}
	}

	// Load keystore signers
	for _, ks := range cfg.Keystores {
		if !ks.Enabled {
			continue
		}

		// Get password via provider
		password, err := provider.GetPassword(ks.Address, ks)
		if err != nil {
			return nil, fmt.Errorf("failed to get password for keystore %s: %w", ks.Address, err)
		}

		expectedAddr := common.HexToAddress(ks.Address)
		keystoreSigner, err := ethsig.NewKeystoreSignerFromPath(ks.Path, expectedAddr, string(password), nil)
		// Zeroize password immediately after use, not defer in loop
		keystore.SecureZeroize(password)
		if err != nil {
			return nil, fmt.Errorf("failed to load keystore for %s: %w", ks.Address, err)
		}

		signer := ethsig.NewSigner(keystoreSigner)
		addrKey := normalizeAddress(expectedAddr.Hex())
		registry.signers[addrKey] = signer
		registry.info[addrKey] = types.SignerInfo{
			Address: expectedAddr.Hex(),
			Type:    "keystore",
			Enabled: true,
		}
	}

	if len(registry.signers) == 0 {
		return nil, fmt.Errorf("no signers configured")
	}

	return registry, nil
}

// GetSigner returns the signer for the given address
func (r *SignerRegistry) GetSigner(address string) (*ethsig.Signer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	addrKey := normalizeAddress(address)
	signer, exists := r.signers[addrKey]
	if !exists {
		return nil, types.ErrSignerNotFound
	}
	return signer, nil
}

// HasSigner checks if a signer exists for the given address
func (r *SignerRegistry) HasSigner(address string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	addrKey := normalizeAddress(address)
	_, exists := r.signers[addrKey]
	return exists
}

// ListSigners returns information about all registered signers
func (r *SignerRegistry) ListSigners() []types.SignerInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	signers := make([]types.SignerInfo, 0, len(r.info))
	for _, info := range r.info {
		signers = append(signers, info)
	}
	return signers
}

// ListSignersWithFilter returns signers matching the filter with pagination
func (r *SignerRegistry) ListSignersWithFilter(filter types.SignerFilter) types.SignerListResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Collect all matching signers
	var allSigners []types.SignerInfo
	for _, info := range r.info {
		// Apply type filter
		if filter.Type != nil && types.SignerType(info.Type) != *filter.Type {
			continue
		}
		allSigners = append(allSigners, info)
	}

	// Stable order for pagination (map iteration is non-deterministic)
	sort.Slice(allSigners, func(i, j int) bool {
		return strings.ToLower(allSigners[i].Address) < strings.ToLower(allSigners[j].Address)
	})

	total := len(allSigners)

	// Apply pagination
	start := filter.Offset
	if start > total {
		start = total
	}

	end := start + filter.Limit
	if filter.Limit <= 0 {
		end = total // No limit means return all
	}
	if end > total {
		end = total
	}

	hasMore := end < total

	return types.SignerListResult{
		Signers: allSigners[start:end],
		Total:   total,
		HasMore: hasMore,
	}
}

// RegisterKeystore dynamically registers a keystore signer
func (r *SignerRegistry) RegisterKeystore(address string, keystorePath string, password []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	addrKey := normalizeAddress(address)

	// Check if signer already exists
	if _, exists := r.signers[addrKey]; exists {
		return types.ErrAlreadyExists
	}

	expectedAddr := common.HexToAddress(address)
	keystoreSigner, err := ethsig.NewKeystoreSignerFromPath(keystorePath, expectedAddr, string(password), nil)
	if err != nil {
		return fmt.Errorf("failed to load keystore: %w", err)
	}

	signer := ethsig.NewSigner(keystoreSigner)
	r.signers[addrKey] = signer
	r.info[addrKey] = types.SignerInfo{
		Address: expectedAddr.Hex(),
		Type:    string(types.SignerTypeKeystore),
		Enabled: true,
	}

	return nil
}

// normalizeAddress converts an address to lowercase for consistent map keys
func normalizeAddress(address string) string {
	return common.HexToAddress(address).Hex()
}

// resolvePrivateKey resolves a private key from either:
// 1. Direct hex value (64+ hex chars, with or without 0x prefix)
// 2. Environment variable name
func resolvePrivateKey(keyOrEnv string) string {
	// Check if it looks like a direct hex private key (64 or 128 hex chars)
	cleaned := keyOrEnv
	if len(cleaned) >= 2 && cleaned[:2] == "0x" {
		cleaned = cleaned[2:]
	}

	// If it's 64 hex chars (32 bytes seed) or 128 hex chars (64 bytes full key), treat as direct value
	if len(cleaned) == 64 || len(cleaned) == 128 {
		isHex := true
		for _, c := range cleaned {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				isHex = false
				break
			}
		}
		if isHex {
			return cleaned
		}
	}

	// Otherwise, treat as environment variable name
	return os.Getenv(keyOrEnv)
}
