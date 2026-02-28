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
