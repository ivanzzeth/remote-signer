package evm

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ivanzzeth/ethsig/keystore"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// SignerManager manages signer lifecycle operations
type SignerManager interface {
	// CreateSigner creates a new signer based on the request type
	CreateSigner(ctx context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error)

	// ListSigners returns signers matching the filter with pagination
	ListSigners(ctx context.Context, filter types.SignerFilter) (types.SignerListResult, error)
}

// SignerManagerImpl implements SignerManager
type SignerManagerImpl struct {
	registry    *SignerRegistry
	keystoreDir string
	logger      *slog.Logger
}

// NewSignerManager creates a new SignerManager
func NewSignerManager(registry *SignerRegistry, keystoreDir string, logger *slog.Logger) (*SignerManagerImpl, error) {
	if registry == nil {
		return nil, fmt.Errorf("registry is required")
	}
	if keystoreDir == "" {
		return nil, fmt.Errorf("keystore directory is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &SignerManagerImpl{
		registry:    registry,
		keystoreDir: keystoreDir,
		logger:      logger,
	}, nil
}

// CreateSigner creates a new signer based on the request type
func (m *SignerManagerImpl) CreateSigner(ctx context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error) {
	// Validate request
	if err := req.Validate(); err != nil {
		return nil, err
	}

	switch req.Type {
	case types.SignerTypeKeystore:
		return m.createKeystoreSigner(ctx, req.Keystore)
	default:
		return nil, types.ErrUnsupportedSignerType
	}
}

// createKeystoreSigner creates a new keystore signer
func (m *SignerManagerImpl) createKeystoreSigner(ctx context.Context, params *types.CreateKeystoreParams) (*types.SignerInfo, error) {
	if params == nil {
		return nil, types.ErrMissingKeystoreParams
	}

	password := []byte(params.Password)
	defer keystore.SecureZeroize(password)

	// Create keystore using ethsig
	address, keystorePath, err := keystore.CreateKeystore(m.keystoreDir, password)
	if err != nil {
		return nil, fmt.Errorf("failed to create keystore: %w", err)
	}

	m.logger.Info("keystore created",
		slog.String("address", address),
		slog.String("path", keystorePath),
	)

	// Register the new signer to make it immediately available
	if err := m.registry.RegisterKeystore(address, keystorePath, password); err != nil {
		return nil, fmt.Errorf("failed to register keystore: %w", err)
	}

	m.logger.Info("signer registered",
		slog.String("address", address),
		slog.String("type", string(types.SignerTypeKeystore)),
	)

	return &types.SignerInfo{
		Address: address,
		Type:    string(types.SignerTypeKeystore),
		Enabled: true,
	}, nil
}

// ListSigners returns signers matching the filter with pagination
func (m *SignerManagerImpl) ListSigners(ctx context.Context, filter types.SignerFilter) (types.SignerListResult, error) {
	return m.registry.ListSignersWithFilter(filter), nil
}
