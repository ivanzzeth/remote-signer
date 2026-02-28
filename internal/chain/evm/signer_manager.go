package evm

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// SignerManager manages signer lifecycle operations
type SignerManager interface {
	// CreateSigner creates a new signer based on the request type
	CreateSigner(ctx context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error)

	// ListSigners returns signers matching the filter with pagination
	ListSigners(ctx context.Context, filter types.SignerFilter) (types.SignerListResult, error)

	// HDWalletManager returns the HD wallet provider, or error if not configured.
	HDWalletManager() (HDWalletManager, error)
}

// SignerManagerImpl implements SignerManager
type SignerManagerImpl struct {
	registry *SignerRegistry
	logger   *slog.Logger
}

// NewSignerManager creates a new SignerManager
func NewSignerManager(registry *SignerRegistry, logger *slog.Logger) (*SignerManagerImpl, error) {
	if registry == nil {
		return nil, fmt.Errorf("registry is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &SignerManagerImpl{
		registry: registry,
		logger:   logger,
	}, nil
}

// CreateSigner dispatches to the appropriate provider via type assertion.
func (m *SignerManagerImpl) CreateSigner(ctx context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	p, ok := m.registry.Provider(req.Type)
	if !ok {
		return nil, types.ErrUnsupportedSignerType
	}

	creator, ok := p.(SignerCreator)
	if !ok {
		return nil, fmt.Errorf("signer type %q does not support dynamic creation", req.Type)
	}

	return creator.CreateSigner(ctx, req.TypedParams())
}

// ListSigners returns signers matching the filter with pagination
func (m *SignerManagerImpl) ListSigners(ctx context.Context, filter types.SignerFilter) (types.SignerListResult, error) {
	return m.registry.ListSignersWithFilter(filter), nil
}

// HDWalletManager returns the HD wallet provider if configured.
func (m *SignerManagerImpl) HDWalletManager() (HDWalletManager, error) {
	p, ok := m.registry.Provider(types.SignerTypeHDWallet)
	if !ok {
		return nil, types.ErrHDWalletNotConfigured
	}

	mgr, ok := p.(HDWalletManager)
	if !ok {
		return nil, fmt.Errorf("HD wallet provider does not implement HDWalletManager")
	}

	return mgr, nil
}
