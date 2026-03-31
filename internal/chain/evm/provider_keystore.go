package evm

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/ethsig"
	"github.com/ivanzzeth/ethsig/keystore"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/logger"
)

// KeystoreProvider loads signers from encrypted keystore files and supports dynamic creation.
type KeystoreProvider struct {
	registry    *SignerRegistry
	keystoreDir string
	pwProvider  PasswordProvider
	mu          sync.RWMutex
	lockedPaths map[string]string // address (checksummed) -> filePath
}

// NewKeystoreProvider creates a KeystoreProvider and loads all configured keystores into the registry.
func NewKeystoreProvider(
	registry *SignerRegistry,
	configs []KeystoreConfig,
	keystoreDir string,
	pwProvider PasswordProvider,
) (*KeystoreProvider, error) {
	if registry == nil {
		return nil, fmt.Errorf("registry is required")
	}
	if pwProvider == nil {
		return nil, fmt.Errorf("password provider is required")
	}

	p := &KeystoreProvider{
		registry:    registry,
		keystoreDir: keystoreDir,
		pwProvider:  pwProvider,
		lockedPaths: make(map[string]string),
	}

	for _, ks := range configs {
		if !ks.Enabled {
			continue
		}

		password, err := pwProvider.GetPassword(ks.Address, ks)
		if err != nil {
			return nil, fmt.Errorf("failed to get password for keystore %s: %w", ks.Address, err)
		}

		expectedAddr := common.HexToAddress(ks.Address)
		keystoreSigner, err := ethsig.NewKeystoreSignerFromPath(ks.Path, expectedAddr, string(password), nil)
		keystore.SecureZeroize(password)
		if err != nil {
			return nil, fmt.Errorf("failed to load keystore for %s: %w", ks.Address, err)
		}

		signer := ethsig.NewSigner(keystoreSigner)
		if err := registry.RegisterSigner(expectedAddr.Hex(), signer, types.SignerInfo{
			Address: expectedAddr.Hex(),
			Type:    string(types.SignerTypeKeystore),
			Enabled: true,
		}); err != nil {
			return nil, fmt.Errorf("failed to register keystore signer %s: %w", ks.Address, err)
		}
	}

	return p, nil
}

func (p *KeystoreProvider) Type() types.SignerType {
	return types.SignerTypeKeystore
}

func (p *KeystoreProvider) Close() error {
	return nil
}

// CreateSigner creates a new keystore signer dynamically via API.
func (p *KeystoreProvider) CreateSigner(ctx context.Context, params interface{}) (*types.SignerInfo, error) {
	ksParams, ok := params.(*types.CreateKeystoreParams)
	if !ok {
		return nil, fmt.Errorf("invalid params type for keystore provider: expected *CreateKeystoreParams")
	}
	if ksParams == nil {
		return nil, types.ErrMissingKeystoreParams
	}

	password := []byte(ksParams.Password)
	defer keystore.SecureZeroize(password)

	address, keystorePath, err := keystore.CreateKeystore(p.keystoreDir, password)
	if err != nil {
		return nil, fmt.Errorf("failed to create keystore: %w", err)
	}

	logger.EVM().Info().Str("address", address).Str("path", keystorePath).Msg("keystore created")

	// Register the new signer in the shared registry
	expectedAddr := common.HexToAddress(address)
	keystoreSigner, err := ethsig.NewKeystoreSignerFromPath(keystorePath, expectedAddr, string(password), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load newly created keystore: %w", err)
	}

	signer := ethsig.NewSigner(keystoreSigner)
	if err := p.registry.RegisterSigner(expectedAddr.Hex(), signer, types.SignerInfo{
		Address: expectedAddr.Hex(),
		Type:    string(types.SignerTypeKeystore),
		Enabled: true,
	}); err != nil {
		return nil, fmt.Errorf("failed to register keystore: %w", err)
	}

	logger.EVM().Info().Str("address", address).Str("type", string(types.SignerTypeKeystore)).Msg("signer registered")

	return &types.SignerInfo{
		Address: address,
		Type:    string(types.SignerTypeKeystore),
		Enabled: true,
	}, nil
}

// DiscoverLockedSigners scans keystoreDir for keystore files not already loaded.
func (p *KeystoreProvider) DiscoverLockedSigners() ([]types.SignerInfo, error) {
	if p.keystoreDir == "" {
		return nil, nil
	}

	keystores, err := keystore.ListKeystores(p.keystoreDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list keystores in %s: %w", p.keystoreDir, err)
	}

	var discovered []types.SignerInfo
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ks := range keystores {
		addrKey := normalizeAddress(ks.Address)
		if p.registry.HasSigner(addrKey) {
			continue
		}

		p.lockedPaths[addrKey] = ks.Path
		info := types.SignerInfo{
			Address: common.HexToAddress(ks.Address).Hex(),
			Type:    string(types.SignerTypeKeystore),
			Enabled: false,
			Locked:  true,
		}
		discovered = append(discovered, info)

		logger.EVM().Info().Str("address", info.Address).Str("path", ks.Path).Msg("discovered locked keystore")
	}

	return discovered, nil
}

// UnlockSigner unlocks a locked keystore signer with the given password.
func (p *KeystoreProvider) UnlockSigner(ctx context.Context, address string, password string) (*ethsig.Signer, error) {
	addrKey := normalizeAddress(address)

	p.mu.RLock()
	filePath, ok := p.lockedPaths[addrKey]
	p.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no locked keystore found for address %s", address)
	}

	expectedAddr := common.HexToAddress(address)
	passwordBytes := []byte(password)
	keystoreSigner, err := ethsig.NewKeystoreSignerFromPath(filePath, expectedAddr, string(passwordBytes), nil)
	keystore.SecureZeroize(passwordBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unlock keystore for %s: %w", address, err)
	}

	signer := ethsig.NewSigner(keystoreSigner)

	p.mu.Lock()
	delete(p.lockedPaths, addrKey)
	p.mu.Unlock()

	logger.EVM().Info().Str("address", address).Msg("keystore signer unlocked")

	return signer, nil
}

// LockSigner locks an unlocked keystore signer (stores path for later unlock).
func (p *KeystoreProvider) LockSigner(ctx context.Context, address string) error {
	addrKey := normalizeAddress(address)

	// Find the keystore file path by scanning the directory
	keystores, err := keystore.ListKeystores(p.keystoreDir)
	if err != nil {
		return fmt.Errorf("failed to list keystores: %w", err)
	}

	for _, ks := range keystores {
		if normalizeAddress(ks.Address) == addrKey {
			p.mu.Lock()
			p.lockedPaths[addrKey] = ks.Path
			p.mu.Unlock()
			logger.EVM().Info().Str("address", address).Msg("keystore signer locked")
			return nil
		}
	}

	return fmt.Errorf("keystore file not found for address %s", address)
}

// DeleteSigner permanently deletes a keystore signer (removes file and cleans in-memory state).
func (p *KeystoreProvider) DeleteSigner(ctx context.Context, address string) error {
	addrKey := normalizeAddress(address)

	// Find the keystore file path by scanning the directory
	keystores, err := keystore.ListKeystores(p.keystoreDir)
	if err != nil {
		return fmt.Errorf("failed to list keystores: %w", err)
	}

	var keystorePath string
	for _, ks := range keystores {
		if normalizeAddress(ks.Address) == addrKey {
			keystorePath = ks.Path
			break
		}
	}

	if keystorePath == "" {
		return fmt.Errorf("keystore file not found for address %s", address)
	}

	// Remove the keystore file
	if err := os.Remove(keystorePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete keystore file: %w", err)
	}

	// Clean in-memory state
	p.mu.Lock()
	delete(p.lockedPaths, addrKey)
	p.mu.Unlock()

	// Unregister from the shared registry
	p.registry.UnregisterSigner(addrKey)

	logger.EVM().Info().Str("address", address).Str("path", keystorePath).Msg("keystore signer deleted")
	return nil
}

// Compile-time interface checks.
var (
	_ SignerDiscoverer = (*KeystoreProvider)(nil)
	_ SignerUnlocker   = (*KeystoreProvider)(nil)
	_ SignerLocker     = (*KeystoreProvider)(nil)
	_ SignerDeleter    = (*KeystoreProvider)(nil)
)
