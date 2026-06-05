package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
		"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// mockSignerManager implements evm.SignerManager for testing.
type mockSignerManager struct {
	mu      sync.Mutex
	signers []types.SignerInfo
}

func newMockSignerManager(signers ...types.SignerInfo) *mockSignerManager {
	return &mockSignerManager{signers: signers}
}

func (m *mockSignerManager) ListSigners(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return types.SignerListResult{Signers: m.signers, Total: len(m.signers)}, nil
}

func (m *mockSignerManager) CreateSigner(_ context.Context, _ types.CreateSignerRequest) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSignerManager) HDWalletManager() (evm.HDWalletManager, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSignerManager) DiscoverLockedSigners(_ context.Context) error {
	return nil
}

func (m *mockSignerManager) UnlockSigner(_ context.Context, _, _ string) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSignerManager) LockSigner(_ context.Context, _ string) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSignerManager) DeleteSigner(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockSignerManager) GetHDHierarchy() map[string]evm.HDHierarchyInfo {
	return nil
}

// mockSignerOwnershipRepository implements storage.SignerOwnershipRepository for testing.
type mockSignerOwnershipRepository struct {
	mu         sync.Mutex
	ownerships map[string]*types.SignerOwnership
}

func newMockSignerOwnershipRepo() *mockSignerOwnershipRepository {
	return &mockSignerOwnershipRepository{ownerships: make(map[string]*types.SignerOwnership)}
}

func (m *mockSignerOwnershipRepository) Get(_ context.Context, signerAddress string) (*types.SignerOwnership, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if o, ok := m.ownerships[signerAddress]; ok {
		clone := *o
		return &clone, nil
	}
	return nil, types.ErrNotFound
}

func (m *mockSignerOwnershipRepository) Upsert(_ context.Context, ownership *types.SignerOwnership) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clone := *ownership
	m.ownerships[ownership.SignerAddress] = &clone
	return nil
}

func (m *mockSignerOwnershipRepository) GetBoth(_ context.Context, senderAddress, recipientAddress string) (*types.SignerOwnership, *types.SignerOwnership, error) {
	return nil, nil, nil
}

func (m *mockSignerOwnershipRepository) GetByOwner(_ context.Context, ownerID string) ([]*types.SignerOwnership, error) {
	return nil, nil
}

func (m *mockSignerOwnershipRepository) GetByStatus(_ context.Context, status types.SignerOwnershipStatus) ([]*types.SignerOwnership, error) {
	var result []*types.SignerOwnership
	for _, o := range m.ownerships {
		if o.Status == status {
			result = append(result, o)
		}
	}
	return result, nil
}

func (m *mockSignerOwnershipRepository) Delete(_ context.Context, signerAddress string) error {
	return nil
}

func (m *mockSignerOwnershipRepository) UpdateOwner(_ context.Context, signerAddress, newOwnerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if o, ok := m.ownerships[signerAddress]; ok {
		o.OwnerID = newOwnerID
		return nil
	}
	return types.ErrNotFound
}

func (m *mockSignerOwnershipRepository) CountByOwner(_ context.Context, ownerID string) (int64, error) {
	return 0, nil
}

func (m *mockSignerOwnershipRepository) CountByOwnerAndType(_ context.Context, ownerID string, signerType types.SignerType) (int64, error) {
	return 0, nil
}

// newTestOwnershipLogger creates a logger for ownership tests.
func newTestOwnershipLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// ===========================================================================
// findFirstAdmin
// ===========================================================================

func TestFindFirstAdmin(t *testing.T) {
	ctx := context.Background()

	t.Run("no keys at all", func(t *testing.T) {
		repo := newMockAPIKeyRepo()
		first, err := findFirstAdmin(ctx, repo)
		require.NoError(t, err)
		assert.Equal(t, "", first)
	})

	t.Run("no admin keys", func(t *testing.T) {
		repo := newMockAPIKeyRepo()
		now := time.Now()
		_ = repo.Create(ctx, &types.APIKey{
			ID: "key-1", Name: "Agent", Role: types.RoleAgent, Enabled: true,
			CreatedAt: now, UpdatedAt: now,
		})
		first, err := findFirstAdmin(ctx, repo)
		require.NoError(t, err)
		assert.Equal(t, "", first)
	})

	t.Run("finds single admin key", func(t *testing.T) {
		repo := newMockAPIKeyRepo()
		now := time.Now()
		_ = repo.Create(ctx, &types.APIKey{
			ID: "admin-1", Name: "Admin", Role: types.RoleAdmin, Enabled: true,
			CreatedAt: now, UpdatedAt: now,
		})
		first, err := findFirstAdmin(ctx, repo)
		require.NoError(t, err)
		assert.Equal(t, "admin-1", first)
	})

	t.Run("picks earliest created admin", func(t *testing.T) {
		repo := newMockAPIKeyRepo()
		base := time.Now()
		_ = repo.Create(ctx, &types.APIKey{
			ID: "admin-later", Name: "Later", Role: types.RoleAdmin, Enabled: true,
			CreatedAt: base.Add(1 * time.Hour), UpdatedAt: base.Add(1 * time.Hour),
		})
		_ = repo.Create(ctx, &types.APIKey{
			ID: "admin-earliest", Name: "Earliest", Role: types.RoleAdmin, Enabled: true,
			CreatedAt: base, UpdatedAt: base,
		})
		first, err := findFirstAdmin(ctx, repo)
		require.NoError(t, err)
		assert.Equal(t, "admin-earliest", first)
	})

	t.Run("skips disabled admin keys", func(t *testing.T) {
		repo := newMockAPIKeyRepo()
		now := time.Now()
		_ = repo.Create(ctx, &types.APIKey{
			ID: "admin-disabled", Name: "Disabled Admin", Role: types.RoleAdmin, Enabled: false,
			CreatedAt: now, UpdatedAt: now,
		})
		first, err := findFirstAdmin(ctx, repo)
		require.NoError(t, err)
		assert.Equal(t, "", first)
	})

	t.Run("prefers enabled admin over disabled", func(t *testing.T) {
		repo := newMockAPIKeyRepo()
		base := time.Now()
		_ = repo.Create(ctx, &types.APIKey{
			ID: "admin-enabled", Name: "Enabled", Role: types.RoleAdmin, Enabled: true,
			CreatedAt: base.Add(1 * time.Hour), UpdatedAt: base.Add(1 * time.Hour),
		})
		_ = repo.Create(ctx, &types.APIKey{
			ID: "admin-disabled-earliest", Name: "Disabled Early", Role: types.RoleAdmin, Enabled: false,
			CreatedAt: base, UpdatedAt: base,
		})
		first, err := findFirstAdmin(ctx, repo)
		require.NoError(t, err)
		assert.Equal(t, "admin-enabled", first)
	})

	t.Run("list error propagates", func(t *testing.T) {
		repo := &errorListAPIKeyRepository{}
		_, err := findFirstAdmin(ctx, repo)
		require.Error(t, err)
	})
}

// ===========================================================================
// SyncSignerOwnership
// ===========================================================================

func TestSyncSignerOwnership(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	t.Run("no signers returns early", func(t *testing.T) {
		signerMgr := newMockSignerManager()
		ownershipRepo := newMockSignerOwnershipRepo()
		apiKeyRepo := newMockAPIKeyRepo()

		err := SyncSignerOwnership(ctx, signerMgr, ownershipRepo, apiKeyRepo, newTestOwnershipLogger())
		assert.NoError(t, err)
	})

	t.Run("no admin key returns early", func(t *testing.T) {
		signerMgr := newMockSignerManager(
			types.SignerInfo{Address: "0xaaa", Type: string(types.SignerTypeKeystore), Enabled: true},
		)
		ownershipRepo := newMockSignerOwnershipRepo()
		apiKeyRepo := newMockAPIKeyRepo()

		err := SyncSignerOwnership(ctx, signerMgr, ownershipRepo, apiKeyRepo, newTestOwnershipLogger())
		assert.NoError(t, err)
	})

	t.Run("creates ownership for new signer", func(t *testing.T) {
		signerMgr := newMockSignerManager(
			types.SignerInfo{Address: "0xaaa", Type: string(types.SignerTypeKeystore), Enabled: true},
		)
		ownershipRepo := newMockSignerOwnershipRepo()
		apiKeyRepo := newMockAPIKeyRepo()
		_ = apiKeyRepo.Create(ctx, &types.APIKey{
			ID: "admin-1", Name: "Admin", Role: types.RoleAdmin, Enabled: true,
			CreatedAt: now, UpdatedAt: now,
		})

		err := SyncSignerOwnership(ctx, signerMgr, ownershipRepo, apiKeyRepo, newTestOwnershipLogger())
		require.NoError(t, err)

		ownership, err := ownershipRepo.Get(ctx, "0xaaa")
		require.NoError(t, err)
		assert.Equal(t, "admin-1", ownership.OwnerID)
		assert.Equal(t, types.SignerOwnershipActive, ownership.Status)
	})

	t.Run("preserves existing ownership", func(t *testing.T) {
		signerMgr := newMockSignerManager(
			types.SignerInfo{Address: "0xaaa", Type: string(types.SignerTypeKeystore), Enabled: true},
		)
		ownershipRepo := newMockSignerOwnershipRepo()
		_ = ownershipRepo.Upsert(ctx, &types.SignerOwnership{
			SignerAddress: "0xaaa",
			OwnerID:       "existing-owner",
			Status:        types.SignerOwnershipActive,
		})
		apiKeyRepo := newMockAPIKeyRepo()
		_ = apiKeyRepo.Create(ctx, &types.APIKey{
			ID: "admin-1", Name: "Admin", Role: types.RoleAdmin, Enabled: true,
			CreatedAt: now, UpdatedAt: now,
		})
		_ = apiKeyRepo.Create(ctx, &types.APIKey{
			ID: "existing-owner", Name: "Existing", Role: types.RoleDev, Enabled: true,
			CreatedAt: now.Add(1 * time.Hour), UpdatedAt: now.Add(1 * time.Hour),
		})

		err := SyncSignerOwnership(ctx, signerMgr, ownershipRepo, apiKeyRepo, newTestOwnershipLogger())
		require.NoError(t, err)

		ownership, err := ownershipRepo.Get(ctx, "0xaaa")
		require.NoError(t, err)
		assert.Equal(t, "existing-owner", ownership.OwnerID) // unchanged
	})

	t.Run("reassigns ownership when owner key deleted", func(t *testing.T) {
		signerMgr := newMockSignerManager(
			types.SignerInfo{Address: "0xaaa", Type: string(types.SignerTypeKeystore), Enabled: true},
		)
		ownershipRepo := newMockSignerOwnershipRepo()
		_ = ownershipRepo.Upsert(ctx, &types.SignerOwnership{
			SignerAddress: "0xaaa",
			OwnerID:       "deleted-owner",
			Status:        types.SignerOwnershipActive,
		})
		apiKeyRepo := newMockAPIKeyRepo()
		_ = apiKeyRepo.Create(ctx, &types.APIKey{
			ID: "admin-1", Name: "Admin", Role: types.RoleAdmin, Enabled: true,
			CreatedAt: now, UpdatedAt: now,
		})

		err := SyncSignerOwnership(ctx, signerMgr, ownershipRepo, apiKeyRepo, newTestOwnershipLogger())
		require.NoError(t, err)

		ownership, err := ownershipRepo.Get(ctx, "0xaaa")
		require.NoError(t, err)
		assert.Equal(t, "admin-1", ownership.OwnerID)
	})

	t.Run("list signers error propagates", func(t *testing.T) {
		errMgr := &errorSignerManager{}
		err := SyncSignerOwnership(ctx, errMgr, newMockSignerOwnershipRepo(), newMockAPIKeyRepo(), newTestOwnershipLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to list signers")
	})

	t.Run("find admin error propagates", func(t *testing.T) {
		signerMgr := newMockSignerManager(
			types.SignerInfo{Address: "0xaaa", Type: string(types.SignerTypeKeystore), Enabled: true},
		)
		apiKeyRepo := &errorListAPIKeyRepository{}
		err := SyncSignerOwnership(ctx, signerMgr, newMockSignerOwnershipRepo(), apiKeyRepo, newTestOwnershipLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to find admin key")
	})
}

// errorListAPIKeyRepository returns an error from List for testing findFirstAdmin propagation.
type errorListAPIKeyRepository struct{}

func (e *errorListAPIKeyRepository) Create(_ context.Context, _ *types.APIKey) error { return nil }
func (e *errorListAPIKeyRepository) Get(_ context.Context, _ string) (*types.APIKey, error) {
	return nil, types.ErrNotFound
}
func (e *errorListAPIKeyRepository) Update(_ context.Context, _ *types.APIKey) error { return nil }
func (e *errorListAPIKeyRepository) Delete(_ context.Context, _ string) error        { return nil }
func (e *errorListAPIKeyRepository) List(_ context.Context, _ storage.APIKeyFilter) ([]*types.APIKey, error) {
	return nil, fmt.Errorf("list failed")
}
func (e *errorListAPIKeyRepository) UpdateLastUsed(_ context.Context, _ string) error { return nil }
func (e *errorListAPIKeyRepository) Count(_ context.Context, _ storage.APIKeyFilter) (int, error) {
	return 0, nil
}
func (e *errorListAPIKeyRepository) DeleteBySourceExcluding(_ context.Context, _ string, _ []string) (int64, error) {
	return 0, nil
}
func (e *errorListAPIKeyRepository) BackfillSource(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

// errorSignerManager returns an error for ListSigners to test error propagation.
type errorSignerManager struct{}

func (e *errorSignerManager) ListSigners(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
	return types.SignerListResult{}, fmt.Errorf("list signers failed")
}

func (e *errorSignerManager) CreateSigner(_ context.Context, _ types.CreateSignerRequest) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (e *errorSignerManager) HDWalletManager() (evm.HDWalletManager, error) {
	return nil, fmt.Errorf("not implemented")
}

func (e *errorSignerManager) DiscoverLockedSigners(_ context.Context) error {
	return nil
}

func (e *errorSignerManager) UnlockSigner(_ context.Context, _, _ string) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (e *errorSignerManager) LockSigner(_ context.Context, _ string) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (e *errorSignerManager) DeleteSigner(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (e *errorSignerManager) GetHDHierarchy() map[string]evm.HDHierarchyInfo {
	return nil
}
