package evm

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// Compile-time check that SignerManagerImpl implements SignerManager.
var _ SignerManager = (*SignerManagerImpl)(nil)

// SignerManager manages signer lifecycle operations
type SignerManager interface {
	// CreateSigner creates a new signer based on the request type
	CreateSigner(ctx context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error)

	// ListSigners returns signers matching the filter with pagination
	ListSigners(ctx context.Context, filter types.SignerFilter) (types.SignerListResult, error)

	// HDWalletManager returns the HD wallet provider, or error if not configured.
	HDWalletManager() (HDWalletManager, error)

	// DiscoverLockedSigners scans all providers for locked signers and registers them.
	DiscoverLockedSigners(ctx context.Context) error

	// UnlockSigner unlocks a locked signer with the given password.
	UnlockSigner(ctx context.Context, address string, password string) (*types.SignerInfo, error)

	// LockSigner locks an unlocked signer (remove key from memory).
	LockSigner(ctx context.Context, address string) (*types.SignerInfo, error)
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

// DiscoverLockedSigners scans all providers for locked signers and registers them.
func (m *SignerManagerImpl) DiscoverLockedSigners(ctx context.Context) error {
	m.registry.mu.RLock()
	providers := make([]SignerProvider, 0, len(m.registry.providers))
	for _, p := range m.registry.providers {
		providers = append(providers, p)
	}
	m.registry.mu.RUnlock()

	for _, p := range providers {
		discoverer, ok := p.(SignerDiscoverer)
		if !ok {
			continue
		}

		infos, err := discoverer.DiscoverLockedSigners()
		if err != nil {
			m.logger.Error("failed to discover locked signers",
				slog.String("provider", string(p.Type())),
				slog.String("error", err.Error()),
			)
			continue
		}

		for _, info := range infos {
			if err := m.registry.RegisterLockedSigner(info.Address, info); err != nil {
				m.logger.Warn("failed to register locked signer",
					slog.String("address", info.Address),
					slog.String("error", err.Error()),
				)
			}
		}
	}

	return nil
}

// UnlockSigner unlocks a locked signer with the given password.
func (m *SignerManagerImpl) UnlockSigner(ctx context.Context, address string, password string) (*types.SignerInfo, error) {
	if !m.registry.IsLocked(address) {
		return nil, types.ErrSignerNotLocked
	}

	info, ok := m.registry.GetSignerInfo(address)
	if !ok {
		return nil, types.ErrSignerNotFound
	}

	p, ok := m.registry.Provider(types.SignerType(info.Type))
	if !ok {
		return nil, fmt.Errorf("no provider for signer type %q", info.Type)
	}

	unlocker, ok := p.(SignerUnlocker)
	if !ok {
		return nil, fmt.Errorf("provider %q does not support unlock", info.Type)
	}

	signer, err := unlocker.UnlockSigner(ctx, address, password)
	if err != nil {
		return nil, err
	}

	if err := m.registry.UnlockSigner(address, signer); err != nil {
		return nil, fmt.Errorf("failed to register unlocked signer: %w", err)
	}

	updatedInfo, _ := m.registry.GetSignerInfo(address)

	m.logger.Info("signer unlocked",
		slog.String("address", address),
		slog.String("type", info.Type),
	)

	return &updatedInfo, nil
}

// LockSigner locks an unlocked signer (remove key from memory).
func (m *SignerManagerImpl) LockSigner(ctx context.Context, address string) (*types.SignerInfo, error) {
	info, ok := m.registry.GetSignerInfo(address)
	if !ok {
		return nil, types.ErrSignerNotFound
	}

	if info.Locked {
		return nil, types.ErrSignerLocked
	}

	p, ok := m.registry.Provider(types.SignerType(info.Type))
	if !ok {
		return nil, fmt.Errorf("no provider for signer type %q", info.Type)
	}

	locker, ok := p.(SignerLocker)
	if !ok {
		return nil, fmt.Errorf("provider %q does not support lock", info.Type)
	}

	if err := locker.LockSigner(ctx, address); err != nil {
		return nil, err
	}

	if err := m.registry.LockSigner(address); err != nil {
		return nil, fmt.Errorf("failed to lock signer in registry: %w", err)
	}

	updatedInfo, _ := m.registry.GetSignerInfo(address)

	m.logger.Info("signer locked",
		slog.String("address", address),
		slog.String("type", info.Type),
	)

	return &updatedInfo, nil
}
