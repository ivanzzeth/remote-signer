package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// mockSignerManagerForMaterial implements evmchain.SignerManager for material check tests.
// ---------------------------------------------------------------------------

type mockSignerManagerForMaterial struct {
	mu         sync.Mutex
	signers    []types.SignerInfo
	hierarchy  map[string]evmchain.HDHierarchyInfo
}

func newMockSignerManagerForMaterial(signers ...types.SignerInfo) *mockSignerManagerForMaterial {
	return &mockSignerManagerForMaterial{
		signers:   signers,
		hierarchy: make(map[string]evmchain.HDHierarchyInfo),
	}
}

func (m *mockSignerManagerForMaterial) ListSigners(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return types.SignerListResult{Signers: m.signers, Total: len(m.signers)}, nil
}

func (m *mockSignerManagerForMaterial) CreateSigner(_ context.Context, _ types.CreateSignerRequest) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSignerManagerForMaterial) HDWalletManager() (evmchain.HDWalletManager, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSignerManagerForMaterial) DiscoverLockedSigners(_ context.Context) error {
	return nil
}

func (m *mockSignerManagerForMaterial) UnlockSigner(_ context.Context, _, _ string) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSignerManagerForMaterial) LockSigner(_ context.Context, _ string) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSignerManagerForMaterial) DeleteSigner(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (m *mockSignerManagerForMaterial) GetHDHierarchy() map[string]evmchain.HDHierarchyInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hierarchy
}

// mockSignerRepo implements storage.SignerRepository for material check tests.
type mockSignerRepo struct {
	mu      sync.Mutex
	signers map[string]*types.Signer
}

func newMockSignerRepo() *mockSignerRepo {
	return &mockSignerRepo{signers: make(map[string]*types.Signer)}
}

func (m *mockSignerRepo) Upsert(_ context.Context, signer *types.Signer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clone := *signer
	m.signers[signer.Address] = &clone
	return nil
}

func (m *mockSignerRepo) Get(_ context.Context, address string) (*types.Signer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.signers[address]; ok {
		clone := *s
		return &clone, nil
	}
	return nil, types.ErrNotFound
}

func (m *mockSignerRepo) List(_ context.Context, _ storage.SignerListFilter) ([]types.Signer, int, error) {
	return nil, 0, nil
}

func (m *mockSignerRepo) Delete(_ context.Context, _ string) error {
	return nil
}

func (m *mockSignerRepo) UpdateMaterialStatus(_ context.Context, _ string, _ types.SignerMaterialStatus, _ time.Time, _ *time.Time, _ string) error {
	return nil
}

// errorSignerManagerForMaterial returns error from ListSigners.
type errorSignerManagerForMaterial struct{}

func (e *errorSignerManagerForMaterial) ListSigners(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
	return types.SignerListResult{}, fmt.Errorf("list signers failed")
}

func (e *errorSignerManagerForMaterial) CreateSigner(_ context.Context, _ types.CreateSignerRequest) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (e *errorSignerManagerForMaterial) HDWalletManager() (evmchain.HDWalletManager, error) {
	return nil, fmt.Errorf("not implemented")
}

func (e *errorSignerManagerForMaterial) DiscoverLockedSigners(_ context.Context) error {
	return nil
}

func (e *errorSignerManagerForMaterial) UnlockSigner(_ context.Context, _, _ string) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (e *errorSignerManagerForMaterial) LockSigner(_ context.Context, _ string) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (e *errorSignerManagerForMaterial) DeleteSigner(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}

func (e *errorSignerManagerForMaterial) GetHDHierarchy() map[string]evmchain.HDHierarchyInfo {
	return nil
}

func materialTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// shortAddr normalizes a short hex address to its EIP-55 checksummed form
// (HexToAddress pads to 20 bytes then returns the mixed-case checksum).
func shortAddr(addr string) string {
	return common.HexToAddress(addr).Hex()
}

// ---------------------------------------------------------------------------
// TestNewSignerMaterialChecker
// ---------------------------------------------------------------------------

func TestNewSignerMaterialChecker(t *testing.T) {
	logger := materialTestLogger()

	t.Run("valid_config", func(t *testing.T) {
		c, err := NewSignerMaterialChecker(
			newMockSignerManagerForMaterial(),
			newMockSignerRepo(),
			"", "", time.Minute, logger,
		)
		require.NoError(t, err)
		require.NotNil(t, c)
	})

	t.Run("nil_manager", func(t *testing.T) {
		_, err := NewSignerMaterialChecker(nil, newMockSignerRepo(), "", "", time.Minute, logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signer manager is required")
	})

	t.Run("nil_repo", func(t *testing.T) {
		_, err := NewSignerMaterialChecker(newMockSignerManagerForMaterial(), nil, "", "", time.Minute, logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signer repository is required")
	})

	t.Run("nil_logger", func(t *testing.T) {
		_, err := NewSignerMaterialChecker(newMockSignerManagerForMaterial(), newMockSignerRepo(), "", "", time.Minute, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("zero_interval", func(t *testing.T) {
		_, err := NewSignerMaterialChecker(newMockSignerManagerForMaterial(), newMockSignerRepo(), "", "", 0, logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "interval must be > 0")
	})

	t.Run("negative_interval", func(t *testing.T) {
		_, err := NewSignerMaterialChecker(newMockSignerManagerForMaterial(), newMockSignerRepo(), "", "", -1, logger)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "interval must be > 0")
	})
}

// ---------------------------------------------------------------------------
// TestRunOnce
// ---------------------------------------------------------------------------

func TestRunOnce(t *testing.T) {
	ctx := context.Background()

	t.Run("list_signers_error_propagates", func(t *testing.T) {
		mgr := &errorSignerManagerForMaterial{}
		checker, err := NewSignerMaterialChecker(mgr, newMockSignerRepo(), "", "", time.Minute, materialTestLogger())
		require.NoError(t, err)

		err = checker.RunOnce(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "list signers")
	})

	t.Run("no_signers_returns_early", func(t *testing.T) {
		mgr := newMockSignerManagerForMaterial()
		repo := newMockSignerRepo()
		checker, err := NewSignerMaterialChecker(mgr, repo, "", "", time.Minute, materialTestLogger())
		require.NoError(t, err)

		err = checker.RunOnce(ctx)
		require.NoError(t, err)
	})

	t.Run("keystore_signer_without_dir_is_missing", func(t *testing.T) {
		addr := shortAddr("0xaaaa")
		mgr := newMockSignerManagerForMaterial(
			types.SignerInfo{
				Address: addr,
				Type:    string(types.SignerTypeKeystore),
				Enabled: true,
			},
		)
		repo := newMockSignerRepo()
		checker, err := NewSignerMaterialChecker(mgr, repo, "", "", time.Minute, materialTestLogger())
		require.NoError(t, err)

		err = checker.RunOnce(ctx)
		require.NoError(t, err)

		s, err := repo.Get(ctx, addr)
		require.NoError(t, err)
		assert.Equal(t, types.SignerMaterialStatusMissing, s.MaterialStatus)
	})

	t.Run("keystore_signer_missing_when_file_not_found", func(t *testing.T) {
		dir := t.TempDir()
		addr := shortAddr("0xbbbb")
		mgr := newMockSignerManagerForMaterial(
			types.SignerInfo{
				Address: addr,
				Type:    string(types.SignerTypeKeystore),
				Enabled: true,
			},
		)
		repo := newMockSignerRepo()
		checker, err := NewSignerMaterialChecker(mgr, repo, dir, "", time.Minute, materialTestLogger())
		require.NoError(t, err)

		err = checker.RunOnce(ctx)
		require.NoError(t, err)

		s, err := repo.Get(ctx, addr)
		require.NoError(t, err)
		assert.Equal(t, types.SignerMaterialStatusMissing, s.MaterialStatus)
		assert.Contains(t, s.MaterialError, "keystore file not found")
	})

	t.Run("hdwallet_signer_missing_when_file_not_found", func(t *testing.T) {
		dir := t.TempDir()
		addr := shortAddr("0xcccc")
		mgr := newMockSignerManagerForMaterial(
			types.SignerInfo{
				Address: addr,
				Type:    string(types.SignerTypeHDWallet),
				Enabled: true,
			},
		)
		repo := newMockSignerRepo()
		checker, err := NewSignerMaterialChecker(mgr, repo, "", dir, time.Minute, materialTestLogger())
		require.NoError(t, err)

		err = checker.RunOnce(ctx)
		require.NoError(t, err)

		s, err := repo.Get(ctx, addr)
		require.NoError(t, err)
		assert.Equal(t, types.SignerMaterialStatusMissing, s.MaterialStatus)
		assert.Contains(t, s.MaterialError, "hd wallet file not found")
	})

	t.Run("unknown_signer_type_is_present", func(t *testing.T) {
		addr := shortAddr("0xdddd")
		mgr := newMockSignerManagerForMaterial(
			types.SignerInfo{
				Address: addr,
				Type:    "some_other_type",
				Enabled: true,
			},
		)
		repo := newMockSignerRepo()
		checker, err := NewSignerMaterialChecker(mgr, repo, "", "", time.Minute, materialTestLogger())
		require.NoError(t, err)

		err = checker.RunOnce(ctx)
		require.NoError(t, err)

		s, err := repo.Get(ctx, addr)
		require.NoError(t, err)
		assert.Equal(t, types.SignerMaterialStatusPresent, s.MaterialStatus)
	})

	t.Run("keystore_signer_present_when_file_exists", func(t *testing.T) {
		dir := t.TempDir()
		addr := shortAddr("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
		// Create a minimal keystore JSON with the matching address (no 0x prefix in file)
		ksContent := fmt.Sprintf(`{"address":"%s","crypto":{"ciphertext":"dead"},"version":3}`, addr[2:])
		require.NoError(t, os.WriteFile(filepath.Join(dir, "UTC--test-key"), []byte(ksContent), 0644))

		mgr := newMockSignerManagerForMaterial(
			types.SignerInfo{
				Address: addr,
				Type:    string(types.SignerTypeKeystore),
				Enabled: true,
			},
		)
		repo := newMockSignerRepo()
		checker, err := NewSignerMaterialChecker(mgr, repo, dir, "", time.Minute, materialTestLogger())
		require.NoError(t, err)

		err = checker.RunOnce(ctx)
		require.NoError(t, err)

		s, err := repo.Get(ctx, addr)
		require.NoError(t, err)
		assert.Equal(t, types.SignerMaterialStatusPresent, s.MaterialStatus)
	})

	t.Run("keystore_signer_preserves_existing_missing_at", func(t *testing.T) {
		dir := t.TempDir()
		addr := shortAddr("0xffffffffffffffffffffffffffffffffffffffff")
		repo := newMockSignerRepo()
		prevMissing := time.Now().Add(-1 * time.Hour).UTC()
		// Pre-seed an existing signer with MaterialMissingAt set
		require.NoError(t, repo.Upsert(ctx, &types.Signer{
			Address:           addr,
			Type:              types.SignerTypeKeystore,
			MaterialStatus:    types.SignerMaterialStatusMissing,
			MaterialMissingAt: &prevMissing,
			MaterialCheckedAt: &time.Time{},
		}))

		mgr := newMockSignerManagerForMaterial(
			types.SignerInfo{
				Address: addr,
				Type:    string(types.SignerTypeKeystore),
				Enabled: true,
			},
		)
		checker, err := NewSignerMaterialChecker(mgr, repo, dir, "", time.Minute, materialTestLogger())
		require.NoError(t, err)

		err = checker.RunOnce(ctx)
		require.NoError(t, err)

		s, err := repo.Get(ctx, addr)
		require.NoError(t, err)
		assert.Equal(t, types.SignerMaterialStatusMissing, s.MaterialStatus)
		// MaterialMissingAt should be preserved from the existing record
		require.NotNil(t, s.MaterialMissingAt)
		assert.Equal(t, prevMissing.Unix(), s.MaterialMissingAt.Unix())
	})

	t.Run("hsd_wallet_derived_signer_resolves_primary", func(t *testing.T) {
		dir := t.TempDir()
		primaryAddr := shortAddr("0x1111111111111111111111111111111111111111")
		derivedAddr := shortAddr("0x2222222222222222222222222222222222222222")

		// Create HD wallet file for primary
		hwContent := fmt.Sprintf(`{"primary_address":"%s","addresses":[],"crypto":{"ciphertext":"dead"},"version":1}`, primaryAddr[2:])
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("hdwallet--%s.json", strings.ToLower(primaryAddr[2:]))), []byte(hwContent), 0644))

		mgr := newMockSignerManagerForMaterial(
			types.SignerInfo{
				Address: derivedAddr,
				Type:    string(types.SignerTypeHDWallet),
				Enabled: true,
			},
		)
		// Wire hierarchy so derivedAddr maps to primaryAddr
		idx := uint32(0)
		mgr.hierarchy[derivedAddr] = evmchain.HDHierarchyInfo{
			ParentAddress:    primaryAddr,
			DerivationIndex:  idx,
		}

		repo := newMockSignerRepo()
		checker, err := NewSignerMaterialChecker(mgr, repo, "", dir, time.Minute, materialTestLogger())
		require.NoError(t, err)

		err = checker.RunOnce(ctx)
		require.NoError(t, err)

		s, err := repo.Get(ctx, derivedAddr)
		require.NoError(t, err)
		assert.Equal(t, types.SignerMaterialStatusPresent, s.MaterialStatus)
		assert.Equal(t, primaryAddr, s.PrimaryAddress)
		require.NotNil(t, s.HDDerivationIndex)
		assert.Equal(t, uint32(0), *s.HDDerivationIndex)
	})

	t.Run("hsd_wallet_derived_resolves_missing_parent", func(t *testing.T) {
		// Derived address with hierarchy info but no HD wallet file for its parent
		_ = t.TempDir()
		primaryAddr := shortAddr("0x3333333333333333333333333333333333333333")
		derivedAddr := shortAddr("0x4444444444444444444444444444444444444444")

		mgr := newMockSignerManagerForMaterial(
			types.SignerInfo{
				Address: derivedAddr,
				Type:    string(types.SignerTypeHDWallet),
				Enabled: true,
			},
		)
		idx := uint32(1)
		mgr.hierarchy[derivedAddr] = evmchain.HDHierarchyInfo{
			ParentAddress:    primaryAddr,
			DerivationIndex:  idx,
		}

		// Use a non-existent HD wallet dir
		repo := newMockSignerRepo()
		checker, err := NewSignerMaterialChecker(mgr, repo, "", "/nonexistent/hdwallet/dir", time.Minute, materialTestLogger())
		require.NoError(t, err)

		err = checker.RunOnce(ctx)
		require.NoError(t, err)

		s, err := repo.Get(ctx, derivedAddr)
		require.NoError(t, err)
		assert.Equal(t, types.SignerMaterialStatusMissing, s.MaterialStatus)
		assert.Equal(t, primaryAddr, s.PrimaryAddress)
		require.NotNil(t, s.HDDerivationIndex)
		assert.Equal(t, uint32(1), *s.HDDerivationIndex)
	})

	t.Run("set_missing_at_for_newly_missing_signer", func(t *testing.T) {
		dir := t.TempDir()
		addr := shortAddr("0x5555555555555555555555555555555555555555")
		mgr := newMockSignerManagerForMaterial(
			types.SignerInfo{
				Address: addr,
				Type:    string(types.SignerTypeKeystore),
				Enabled: true,
			},
		)
		repo := newMockSignerRepo()
		checker, err := NewSignerMaterialChecker(mgr, repo, dir, "", time.Minute, materialTestLogger())
		require.NoError(t, err)

		err = checker.RunOnce(ctx)
		require.NoError(t, err)

		s, err := repo.Get(ctx, addr)
		require.NoError(t, err)
		assert.Equal(t, types.SignerMaterialStatusMissing, s.MaterialStatus)
		require.NotNil(t, s.MaterialMissingAt)
	})

	t.Run("keystore_bad_directory_logs_warning", func(t *testing.T) {
		// A non-existent keystore dir logs a warning but doesn't fail
		addr := shortAddr("0x6666")
		mgr := newMockSignerManagerForMaterial(
			types.SignerInfo{
				Address: addr,
				Type:    string(types.SignerTypeKeystore),
				Enabled: true,
			},
		)
		repo := newMockSignerRepo()
		checker, err := NewSignerMaterialChecker(mgr, repo, "/nonexistent/keystore/dir", "", time.Minute, materialTestLogger())
		require.NoError(t, err)

		err = checker.RunOnce(ctx)
		require.NoError(t, err)
		// Warning logged but no error, signer still processed
		s, err := repo.Get(ctx, addr)
		require.NoError(t, err)
		assert.Equal(t, types.SignerMaterialStatusMissing, s.MaterialStatus)
	})
}

// ---------------------------------------------------------------------------
// TestStart - verify the periodic reconciliation loop
// ---------------------------------------------------------------------------

func TestStart(t *testing.T) {
	t.Run("runs_until_context_cancelled", func(t *testing.T) {
		addr := shortAddr("0xaaaa")
		mgr := newMockSignerManagerForMaterial(
			types.SignerInfo{
				Address: addr,
				Type:    string(types.SignerTypeKeystore),
				Enabled: true,
			},
		)
		repo := newMockSignerRepo()
		// Use a very short interval so the ticker fires quickly
		checker, err := NewSignerMaterialChecker(mgr, repo, "", "", 10*time.Millisecond, materialTestLogger())
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// Start runs the loop; ctx.Done() will cause it to return
		checker.Start(ctx)

		// After Start returns, the signer should have been processed
		s, err := repo.Get(context.Background(), addr)
		require.NoError(t, err)
		assert.Equal(t, types.SignerMaterialStatusMissing, s.MaterialStatus)
	})

	t.Run("logs_error_on_run_once_failure", func(t *testing.T) {
		mgr := &errorSignerManagerForMaterial{}
		repo := newMockSignerRepo()
		checker, err := NewSignerMaterialChecker(mgr, repo, "", "", 10*time.Millisecond, materialTestLogger())
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// Should not panic or deadlock despite RunOnce returning error
		checker.Start(ctx)
	})
}
