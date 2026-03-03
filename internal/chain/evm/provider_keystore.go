package evm

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ivanzzeth/ethsig"
	"github.com/ivanzzeth/ethsig/keystore"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// KeystoreProvider loads signers from encrypted keystore files and supports dynamic creation.
type KeystoreProvider struct {
	registry    *SignerRegistry
	keystoreDir string
	pwProvider  PasswordProvider
	logger      *slog.Logger
	lockedPaths map[string]string // address (checksummed) -> filePath
}

// NewKeystoreProvider creates a KeystoreProvider and loads all configured keystores into the registry.
func NewKeystoreProvider(
	registry *SignerRegistry,
	configs []KeystoreConfig,
	keystoreDir string,
	pwProvider PasswordProvider,
	logger *slog.Logger,
) (*KeystoreProvider, error) {
	if registry == nil {
		return nil, fmt.Errorf("registry is required")
	}
	if pwProvider == nil {
		return nil, fmt.Errorf("password provider is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	p := &KeystoreProvider{
		registry:    registry,
		keystoreDir: keystoreDir,
		pwProvider:  pwProvider,
		logger:      logger,
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

	p.logger.Info("keystore created",
		slog.String("address", address),
		slog.String("path", keystorePath),
	)

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

	p.logger.Info("signer registered",
		slog.String("address", address),
		slog.String("type", string(types.SignerTypeKeystore)),
	)

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

		p.logger.Info("discovered locked keystore",
			slog.String("address", info.Address),
			slog.String("path", ks.Path),
		)
	}

	return discovered, nil
}

// UnlockSigner unlocks a locked keystore signer with the given password.
func (p *KeystoreProvider) UnlockSigner(ctx context.Context, address string, password string) (*ethsig.Signer, error) {
	addrKey := normalizeAddress(address)
	filePath, ok := p.lockedPaths[addrKey]
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
	delete(p.lockedPaths, addrKey)

	p.logger.Info("keystore signer unlocked",
		slog.String("address", address),
	)

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
			p.lockedPaths[addrKey] = ks.Path
			p.logger.Info("keystore signer locked",
				slog.String("address", address),
			)
			return nil
		}
	}

	return fmt.Errorf("keystore file not found for address %s", address)
}

// Compile-time interface checks.
var (
	_ SignerDiscoverer = (*KeystoreProvider)(nil)
	_ SignerUnlocker   = (*KeystoreProvider)(nil)
	_ SignerLocker     = (*KeystoreProvider)(nil)
)
