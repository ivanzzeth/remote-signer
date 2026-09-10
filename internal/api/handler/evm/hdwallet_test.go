package evm

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
	"github.com/stretchr/testify/require"
)

// This file holds the HD-wallet test fixtures and nothing else. The tests that
// used to live here moved to hdwallet_routes_test.go (proposal S4) — they drive
// the HD-wallet endpoints, and after decomposition an endpoint is reachable only
// through the route that names it, which means driving them requires
// internal/api's route registration. internal/api imports this package, so an
// in-package test cannot import it back; hdwallet_routes_test.go is therefore
// `package evm_test`, which can.
//
// ⚠️ Which is why the mocks below are exported despite living in a _test.go
// file: identifiers declared in package evm's test files are visible to package
// evm_test in the same directory (the standard export_test.go idiom), and
// exported is the only way that external package can set their fields.
// ⛔ They stay here rather than moving with the tests because they are not the
// HD-wallet tests' private property — MockSignerManager and MockHDWalletManager
// are what signer_response_test.go builds its fixtures from, and
// NewTestAccessService is what signer_readonly_test.go uses. A copy in the
// external package would be a second set of mocks drifting from this one.

// --- Mock HDWalletManager ---

type MockHDWalletManager struct {
	CreateWalletFn     func(ctx context.Context, params types.CreateHDWalletParams) (*evmchain.HDWalletInfo, error)
	ImportWalletFn     func(ctx context.Context, params types.ImportHDWalletParams) (*evmchain.HDWalletInfo, error)
	DeriveAddressFn    func(ctx context.Context, primaryAddr string, index uint32) (*types.SignerInfo, error)
	DeriveAddressesFn  func(ctx context.Context, primaryAddr string, start, count uint32) ([]types.SignerInfo, error)
	ListHDWalletsFn    func() []evmchain.HDWalletInfo
	ListDerivedAddrsFn func(primaryAddr string) ([]types.SignerInfo, error)
}

func (m *MockHDWalletManager) CreateHDWallet(ctx context.Context, params types.CreateHDWalletParams) (*evmchain.HDWalletInfo, error) {
	if m.CreateWalletFn != nil {
		return m.CreateWalletFn(ctx, params)
	}
	return &evmchain.HDWalletInfo{
		PrimaryAddress: "0x1234567890abcdef1234567890abcdef12345678",
		BasePath:       "m/44'/60'/0'/0",
		DerivedCount:   1,
		Derived: []types.SignerInfo{
			{Address: "0x1234567890abcdef1234567890abcdef12345678", Type: "hd_wallet", Enabled: true},
		},
	}, nil
}

func (m *MockHDWalletManager) ImportHDWallet(ctx context.Context, params types.ImportHDWalletParams) (*evmchain.HDWalletInfo, error) {
	if m.ImportWalletFn != nil {
		return m.ImportWalletFn(ctx, params)
	}
	return &evmchain.HDWalletInfo{
		PrimaryAddress: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
		BasePath:       "m/44'/60'/0'/0",
		DerivedCount:   1,
		Derived: []types.SignerInfo{
			{Address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd", Type: "hd_wallet", Enabled: true},
		},
	}, nil
}

func (m *MockHDWalletManager) DeriveAddress(ctx context.Context, primaryAddr string, index uint32) (*types.SignerInfo, error) {
	if m.DeriveAddressFn != nil {
		return m.DeriveAddressFn(ctx, primaryAddr, index)
	}
	return &types.SignerInfo{
		Address: fmt.Sprintf("0x%040x", index+1),
		Type:    "hd_wallet",
		Enabled: true,
	}, nil
}

func (m *MockHDWalletManager) DeriveAddresses(ctx context.Context, primaryAddr string, start, count uint32) ([]types.SignerInfo, error) {
	if m.DeriveAddressesFn != nil {
		return m.DeriveAddressesFn(ctx, primaryAddr, start, count)
	}
	result := make([]types.SignerInfo, count)
	for i := uint32(0); i < count; i++ {
		result[i] = types.SignerInfo{
			Address: fmt.Sprintf("0x%040x", start+i+1),
			Type:    "hd_wallet",
			Enabled: true,
		}
	}
	return result, nil
}

func (m *MockHDWalletManager) ListHDWallets() []evmchain.HDWalletInfo {
	if m.ListHDWalletsFn != nil {
		return m.ListHDWalletsFn()
	}
	return []evmchain.HDWalletInfo{
		{
			PrimaryAddress: "0x1111111111111111111111111111111111111111",
			BasePath:       "m/44'/60'/0'/0",
			DerivedCount:   2,
		},
	}
}

func (m *MockHDWalletManager) ListDerivedAddresses(primaryAddr string) ([]types.SignerInfo, error) {
	if m.ListDerivedAddrsFn != nil {
		return m.ListDerivedAddrsFn(primaryAddr)
	}
	return []types.SignerInfo{
		{Address: "0x2222222222222222222222222222222222222222", Type: "hd_wallet", Enabled: true},
		{Address: "0x3333333333333333333333333333333333333333", Type: "hd_wallet", Enabled: true},
	}, nil
}

func (m *MockHDWalletManager) ListPrimaryAddresses() []string {
	wallets := m.ListHDWallets()
	out := make([]string, 0, len(wallets))
	for _, w := range wallets {
		if w.PrimaryAddress != "" {
			out = append(out, w.PrimaryAddress)
		}
	}
	return out
}

// --- Mock SignerManager ---

type MockSignerManager struct {
	HDWalletMgr    *MockHDWalletManager
	HDWalletMgrErr error
	hdHierarchy    map[string]evmchain.HDHierarchyInfo // optional; GetHDHierarchy return value
}

func (m *MockSignerManager) CreateSigner(_ context.Context, _ types.CreateSignerRequest) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *MockSignerManager) ListSigners(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
	return types.SignerListResult{}, fmt.Errorf("not implemented in mock")
}

func (m *MockSignerManager) HDWalletManager() (evmchain.HDWalletManager, error) {
	if m.HDWalletMgrErr != nil {
		return nil, m.HDWalletMgrErr
	}
	return m.HDWalletMgr, nil
}

func (m *MockSignerManager) DiscoverLockedSigners(_ context.Context) error {
	return nil
}

func (m *MockSignerManager) UnlockSigner(_ context.Context, _ string, _ string) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *MockSignerManager) LockSigner(_ context.Context, _ string) (*types.SignerInfo, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *MockSignerManager) DeleteSigner(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented in mock")
}

func (m *MockSignerManager) GetHDHierarchy() map[string]evmchain.HDHierarchyInfo {
	if m.hdHierarchy == nil {
		return nil
	}
	out := make(map[string]evmchain.HDHierarchyInfo, len(m.hdHierarchy))
	for k, v := range m.hdHierarchy {
		out[k] = v
	}
	return out
}

// --- Mock repos for access service ---

type stubOwnershipRepo struct {
	ownerships map[string]*types.SignerOwnership // keyed by signer address
}

func (s *stubOwnershipRepo) Upsert(_ context.Context, _ *types.SignerOwnership) error { return nil }
func (s *stubOwnershipRepo) Get(_ context.Context, addr string) (*types.SignerOwnership, error) {
	if s.ownerships != nil {
		if o, ok := s.ownerships[addr]; ok {
			return o, nil
		}
	}
	// Default: return ownership for test-admin so access checks pass in tests
	return &types.SignerOwnership{
		SignerAddress: addr,
		OwnerID:       "test-admin",
		Status:        types.SignerOwnershipActive,
	}, nil
}
func (s *stubOwnershipRepo) GetByOwner(_ context.Context, _ string) ([]*types.SignerOwnership, error) {
	return nil, nil
}
func (s *stubOwnershipRepo) GetByStatus(_ context.Context, _ types.SignerOwnershipStatus) ([]*types.SignerOwnership, error) {
	return nil, nil
}
func (s *stubOwnershipRepo) Delete(_ context.Context, _ string) error                { return nil }
func (s *stubOwnershipRepo) UpdateOwner(_ context.Context, _, _ string) error        { return nil }
func (s *stubOwnershipRepo) CountByOwner(_ context.Context, _ string) (int64, error) { return 0, nil }
func (s *stubOwnershipRepo) CountByOwnerAndType(_ context.Context, _ string, _ types.SignerType) (int64, error) {
	return 0, nil
}
func (s *stubOwnershipRepo) GetBoth(_ context.Context, senderAddress, recipientAddress string) (*types.SignerOwnership, *types.SignerOwnership, error) {
	// Simple stub implementation for tests
	sender, _ := s.Get(context.TODO(), senderAddress)
	recipient, _ := s.Get(context.TODO(), recipientAddress)
	return sender, recipient, nil
}

type stubAccessRepo struct{}

func (s *stubAccessRepo) Grant(_ context.Context, _ *types.SignerAccess) error { return nil }
func (s *stubAccessRepo) Revoke(_ context.Context, _, _ string) error          { return nil }
func (s *stubAccessRepo) List(_ context.Context, _ string) ([]*types.SignerAccess, error) {
	return nil, nil
}
func (s *stubAccessRepo) HasAccess(_ context.Context, _, _ string) (bool, error) { return false, nil }
func (s *stubAccessRepo) HasAccessViaWallet(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
func (s *stubAccessRepo) DeleteBySigner(_ context.Context, _ string) error { return nil }
func (s *stubAccessRepo) DeleteByAPIKey(_ context.Context, _ string) error { return nil }
func (s *stubAccessRepo) ListAccessibleAddresses(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

type stubAPIKeyRepoForAccess struct{}

func (s *stubAPIKeyRepoForAccess) Create(_ context.Context, _ *types.APIKey) error { return nil }
func (s *stubAPIKeyRepoForAccess) Get(_ context.Context, _ string) (*types.APIKey, error) {
	return nil, types.ErrNotFound
}
func (s *stubAPIKeyRepoForAccess) Update(_ context.Context, _ *types.APIKey) error { return nil }
func (s *stubAPIKeyRepoForAccess) Delete(_ context.Context, _ string) error        { return nil }
func (s *stubAPIKeyRepoForAccess) List(_ context.Context, _ storage.APIKeyFilter) ([]*types.APIKey, error) {
	return nil, nil
}
func (s *stubAPIKeyRepoForAccess) UpdateLastUsed(_ context.Context, _ string) error { return nil }
func (s *stubAPIKeyRepoForAccess) Count(_ context.Context, _ storage.APIKeyFilter) (int, error) {
	return 0, nil
}
func (s *stubAPIKeyRepoForAccess) DeleteBySourceExcluding(_ context.Context, _ string, _ []string) (int64, error) {
	return 0, nil
}
func (s *stubAPIKeyRepoForAccess) BackfillSource(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

func NewTestAccessService(t *testing.T) *service.SignerAccessService {
	t.Helper()
	return NewTestAccessServiceWithOwnerships(t, nil)
}

func NewTestAccessServiceWithOwnerships(t *testing.T, ownerships map[string]*types.SignerOwnership) *service.SignerAccessService {
	t.Helper()
	svc, err := service.NewSignerAccessService(
		&stubOwnershipRepo{ownerships: ownerships},
		&stubAccessRepo{},
		&stubAPIKeyRepoForAccess{},
		nil,
		slog.Default(),
	)
	require.NoError(t, err)
	return svc
}
