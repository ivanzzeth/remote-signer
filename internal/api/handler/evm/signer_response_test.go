package evm

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// stubSignerRepo is a minimal SignerRepository for newSignerResponse enrichment tests.
// Only Get is exercised; other methods are no-ops.
type stubSignerRepo struct {
	records map[string]*types.Signer
}

func (r *stubSignerRepo) Upsert(_ context.Context, _ *types.Signer) error { return nil }
func (r *stubSignerRepo) Get(_ context.Context, address string) (*types.Signer, error) {
	for a, rec := range r.records {
		if strings.EqualFold(a, address) {
			return rec, nil
		}
	}
	return nil, types.ErrNotFound
}
func (r *stubSignerRepo) List(_ context.Context, _ storage.SignerListFilter) ([]types.Signer, int, error) {
	return nil, 0, nil
}
func (r *stubSignerRepo) Delete(_ context.Context, _ string) error { return nil }
func (r *stubSignerRepo) UpdateMaterialStatus(_ context.Context, _ string, _ types.SignerMaterialStatus, _ time.Time, _ *time.Time, _ string) error {
	return nil
}

// strictOwnershipRepo returns ErrNotFound for unmapped addresses (unlike stubOwnershipRepo which returns a default).
// This is needed to test ownership inheritance: derived addresses must fall through to primary.
type strictOwnershipRepo struct {
	stubOwnershipRepo
	strict map[string]*types.SignerOwnership
}

func (r *strictOwnershipRepo) Get(_ context.Context, addr string) (*types.SignerOwnership, error) {
	for a, o := range r.strict {
		if strings.EqualFold(a, addr) {
			return o, nil
		}
	}
	return nil, types.ErrNotFound
}

func newStrictAccessService(t *testing.T, ownerships map[string]*types.SignerOwnership) *service.SignerAccessService {
	t.Helper()
	svc, err := service.NewSignerAccessService(
		&strictOwnershipRepo{strict: ownerships},
		&stubAccessRepo{},
		&stubAPIKeyRepoForAccess{},
		nil,
		slog.Default(),
	)
	require.NoError(t, err)
	return svc
}

// --- Tests for newSignerResponse ---

func TestNewSignerResponse_NonHDWallet(t *testing.T) {
	mgr := &mockSignerManager{hdWalletMgrErr: types.ErrHDWalletNotConfigured}
	accessSvc := newStrictAccessService(t, nil)
	handler, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	resp := handler.newSignerResponse(context.Background(), types.SignerInfo{
		Address: "0x1111111111111111111111111111111111111111",
		Type:    "keystore",
		Enabled: true,
		Locked:  false,
	})
	assert.Equal(t, "0x1111111111111111111111111111111111111111", resp.Address)
	assert.Equal(t, "keystore", resp.Type)
	assert.True(t, resp.Enabled)
	assert.False(t, resp.Locked)
	assert.Empty(t, resp.OwnerID)
}

func TestNewSignerResponse_HDWallet_PrimaryUnlocked(t *testing.T) {
	primaryAddr := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	mgr := &mockSignerManager{
		hdWalletMgr: &mockHDWalletManager{
			listHDWalletsFn: func() []evmchain.HDWalletInfo {
				return []evmchain.HDWalletInfo{
					{PrimaryAddress: primaryAddr, Locked: false},
				}
			},
			listDerivedAddrsFn: func(_ string) ([]types.SignerInfo, error) {
				return nil, nil
			},
		},
	}

	accessSvc := newStrictAccessService(t, map[string]*types.SignerOwnership{
		primaryAddr: {
			SignerAddress: primaryAddr,
			OwnerID:       "user-1",
			Status:        types.SignerOwnershipActive,
			DisplayName:   "My HD Wallet",
			TagsJSON:      `["trading"]`,
		},
	})

	handler, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	resp := handler.newSignerResponse(context.Background(), types.SignerInfo{
		Address: primaryAddr,
		Type:    string(types.SignerTypeHDWallet),
		Enabled: true,
		Locked:  true, // DB says locked, runtime says unlocked
	})
	assert.False(t, resp.Locked, "primary address of unlocked wallet should be unlocked")
	assert.Equal(t, "user-1", resp.OwnerID)
	assert.Equal(t, "active", resp.Status)
	assert.Equal(t, "My HD Wallet", resp.DisplayName)
	assert.Equal(t, []string{"trading"}, resp.Tags)
}

func TestNewSignerResponse_HDWallet_PrimaryLocked(t *testing.T) {
	primaryAddr := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	mgr := &mockSignerManager{
		hdWalletMgr: &mockHDWalletManager{
			listHDWalletsFn: func() []evmchain.HDWalletInfo {
				return []evmchain.HDWalletInfo{
					{PrimaryAddress: primaryAddr, Locked: true},
				}
			},
		},
	}
	accessSvc := newStrictAccessService(t, nil)

	handler, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	resp := handler.newSignerResponse(context.Background(), types.SignerInfo{
		Address: primaryAddr,
		Type:    string(types.SignerTypeHDWallet),
		Enabled: true,
		Locked:  true,
	})
	assert.True(t, resp.Locked, "primary address of locked wallet should be locked")
}

func TestNewSignerResponse_HDWallet_DerivedInheritsOwnership(t *testing.T) {
	primaryAddr := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	derivedAddr := "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	mgr := &mockSignerManager{
		hdWalletMgr: &mockHDWalletManager{
			listHDWalletsFn: func() []evmchain.HDWalletInfo {
				return []evmchain.HDWalletInfo{
					{PrimaryAddress: primaryAddr, Locked: false},
				}
			},
			listDerivedAddrsFn: func(primary string) ([]types.SignerInfo, error) {
				if strings.EqualFold(primary, primaryAddr) {
					return []types.SignerInfo{
						{Address: derivedAddr, Type: string(types.SignerTypeHDWallet), Enabled: true},
					}, nil
				}
				return nil, nil
			},
		},
	}

	// Ownership only for primary, NOT for derived
	accessSvc := newStrictAccessService(t, map[string]*types.SignerOwnership{
		primaryAddr: {
			SignerAddress: primaryAddr,
			OwnerID:       "user-1",
			Status:        types.SignerOwnershipActive,
			DisplayName:   "My HD Wallet",
			TagsJSON:      `["trading","defi"]`,
		},
	})

	handler, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	resp := handler.newSignerResponse(context.Background(), types.SignerInfo{
		Address: derivedAddr,
		Type:    string(types.SignerTypeHDWallet),
		Enabled: true,
		Locked:  true,
	})
	assert.False(t, resp.Locked, "derived address of unlocked wallet should be unlocked")
	assert.Equal(t, "user-1", resp.OwnerID, "derived should inherit ownership from primary")
	assert.Equal(t, "active", resp.Status, "derived should inherit status from primary")
	assert.Equal(t, "My HD Wallet", resp.DisplayName, "derived should inherit display name")
	assert.Equal(t, []string{"trading", "defi"}, resp.Tags, "derived should inherit tags")
}

func TestNewSignerResponse_HDWallet_DerivedLocked(t *testing.T) {
	primaryAddr := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	derivedAddr := "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	mgr := &mockSignerManager{
		hdWalletMgr: &mockHDWalletManager{
			listHDWalletsFn: func() []evmchain.HDWalletInfo {
				return []evmchain.HDWalletInfo{
					{PrimaryAddress: primaryAddr, Locked: true},
				}
			},
		},
	}
	accessSvc := newStrictAccessService(t, nil)

	handler, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	resp := handler.newSignerResponse(context.Background(), types.SignerInfo{
		Address: derivedAddr,
		Type:    string(types.SignerTypeHDWallet),
		Enabled: true,
		Locked:  true,
	})
	assert.True(t, resp.Locked, "derived address of locked wallet should be locked")
	assert.Empty(t, resp.OwnerID, "locked derived should have no ownership")
}

func TestNewSignerResponse_HDWallet_DerivedWithOwnOwnership(t *testing.T) {
	// Derived address that has its OWN ownership record should use its own, not primary's
	primaryAddr := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	derivedAddr := "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	mgr := &mockSignerManager{
		hdWalletMgr: &mockHDWalletManager{
			listHDWalletsFn: func() []evmchain.HDWalletInfo {
				return []evmchain.HDWalletInfo{
					{PrimaryAddress: primaryAddr, Locked: false},
				}
			},
			listDerivedAddrsFn: func(primary string) ([]types.SignerInfo, error) {
				if strings.EqualFold(primary, primaryAddr) {
					return []types.SignerInfo{
						{Address: derivedAddr, Type: string(types.SignerTypeHDWallet), Enabled: true},
					}, nil
				}
				return nil, nil
			},
		},
	}

	accessSvc := newStrictAccessService(t, map[string]*types.SignerOwnership{
		primaryAddr: {
			SignerAddress: primaryAddr,
			OwnerID:       "user-1",
			Status:        types.SignerOwnershipActive,
			DisplayName:   "Primary Wallet",
		},
		derivedAddr: {
			SignerAddress: derivedAddr,
			OwnerID:       "user-2",
			Status:        types.SignerOwnershipActive,
			DisplayName:   "Derived Wallet",
		},
	})

	handler, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	resp := handler.newSignerResponse(context.Background(), types.SignerInfo{
		Address: derivedAddr,
		Type:    string(types.SignerTypeHDWallet),
		Enabled: true,
		Locked:  true,
	})
	assert.False(t, resp.Locked)
	assert.Equal(t, "user-2", resp.OwnerID, "derived with own ownership should use its own")
	assert.Equal(t, "Derived Wallet", resp.DisplayName)
}

func TestNewSignerResponse_HDWallet_MultipleWallets(t *testing.T) {
	primary1 := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	primary2 := "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	derived2 := "0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"

	mgr := &mockSignerManager{
		hdWalletMgr: &mockHDWalletManager{
			listHDWalletsFn: func() []evmchain.HDWalletInfo {
				return []evmchain.HDWalletInfo{
					{PrimaryAddress: primary1, Locked: true},
					{PrimaryAddress: primary2, Locked: false},
				}
			},
			listDerivedAddrsFn: func(primary string) ([]types.SignerInfo, error) {
				if strings.EqualFold(primary, primary2) {
					return []types.SignerInfo{
						{Address: derived2, Type: string(types.SignerTypeHDWallet), Enabled: true},
					}, nil
				}
				return nil, nil
			},
		},
	}

	accessSvc := newStrictAccessService(t, map[string]*types.SignerOwnership{
		primary2: {
			SignerAddress: primary2,
			OwnerID:       "owner-2",
			Status:        types.SignerOwnershipActive,
			DisplayName:   "Wallet 2",
		},
	})

	handler, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	// Derived of unlocked wallet 2
	resp := handler.newSignerResponse(context.Background(), types.SignerInfo{
		Address: derived2,
		Type:    string(types.SignerTypeHDWallet),
		Enabled: true,
		Locked:  true,
	})
	assert.False(t, resp.Locked, "derived of unlocked wallet 2 should be unlocked")
	assert.Equal(t, "owner-2", resp.OwnerID)

	// Primary of locked wallet 1
	resp2 := handler.newSignerResponse(context.Background(), types.SignerInfo{
		Address: primary1,
		Type:    string(types.SignerTypeHDWallet),
		Enabled: true,
		Locked:  true,
	})
	assert.True(t, resp2.Locked, "primary of locked wallet 1 should be locked")
}

func TestNewSignerResponse_HDWallet_ManagerError(t *testing.T) {
	mgr := &mockSignerManager{hdWalletMgrErr: types.ErrHDWalletNotConfigured}
	accessSvc := newStrictAccessService(t, nil)

	handler, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	resp := handler.newSignerResponse(context.Background(), types.SignerInfo{
		Address: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Type:    string(types.SignerTypeHDWallet),
		Enabled: true,
		Locked:  true,
	})
	assert.True(t, resp.Locked, "when HDWalletManager fails, should keep original locked status")
}

func TestNewSignerResponse_HDWallet_CaseInsensitive(t *testing.T) {
	// HDWalletManager stores uppercase, SignerInfo has lowercase → should still match
	hdMgr := &mockHDWalletManager{
		listHDWalletsFn: func() []evmchain.HDWalletInfo {
			return []evmchain.HDWalletInfo{
				{PrimaryAddress: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Locked: false},
			}
		},
		listDerivedAddrsFn: func(_ string) ([]types.SignerInfo, error) {
			return []types.SignerInfo{
				{Address: "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"},
			}, nil
		},
	}

	mgr := &mockSignerManager{hdWalletMgr: hdMgr}
	accessSvc := newStrictAccessService(t, map[string]*types.SignerOwnership{
		"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": {
			SignerAddress: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			OwnerID:       "user-1",
			Status:        types.SignerOwnershipActive,
		},
	})

	handler, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	// Primary with lowercase
	resp := handler.newSignerResponse(context.Background(), types.SignerInfo{
		Address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Type:    string(types.SignerTypeHDWallet),
		Locked:  true,
	})
	assert.False(t, resp.Locked, "case-insensitive match on primary")
	assert.Equal(t, "user-1", resp.OwnerID)

	// Derived with lowercase
	resp2 := handler.newSignerResponse(context.Background(), types.SignerInfo{
		Address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Type:    string(types.SignerTypeHDWallet),
		Locked:  true,
	})
	assert.False(t, resp2.Locked, "case-insensitive match on derived")
	assert.Equal(t, "user-1", resp2.OwnerID, "derived should inherit primary ownership")
}

func TestNewSignerResponse_HDWallet_DerivedHierarchyUsesCanonicalAddressKey(t *testing.T) {
	// GetHDHierarchy keys match normalizeAddress (EIP-55). Signer list may use any casing; lookup must still work.
	primaryAddr := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	derivedLower := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	derivedKey := common.HexToAddress(derivedLower).Hex()

	mgr := &mockSignerManager{
		hdWalletMgr: &mockHDWalletManager{
			listHDWalletsFn: func() []evmchain.HDWalletInfo {
				return []evmchain.HDWalletInfo{
					{PrimaryAddress: primaryAddr, Locked: false},
				}
			},
			listDerivedAddrsFn: func(_ string) ([]types.SignerInfo, error) {
				return []types.SignerInfo{
					{Address: derivedLower, Type: string(types.SignerTypeHDWallet), Enabled: true},
				}, nil
			},
		},
		hdHierarchy: map[string]evmchain.HDHierarchyInfo{
			derivedKey: {
				ParentAddress:   primaryAddr,
				DerivationIndex: 1,
			},
		},
	}

	accessSvc := newStrictAccessService(t, map[string]*types.SignerOwnership{
		primaryAddr: {
			SignerAddress: primaryAddr,
			OwnerID:       "user-1",
			Status:        types.SignerOwnershipActive,
		},
	})

	handler, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	resp := handler.newSignerResponse(context.Background(), types.SignerInfo{
		Address: derivedLower,
		Type:    string(types.SignerTypeHDWallet),
		Enabled: true,
		Locked:  true,
	})
	assert.Equal(t, primaryAddr, resp.PrimaryAddress)
	require.NotNil(t, resp.HDDerivationIndex)
	assert.Equal(t, uint32(1), *resp.HDDerivationIndex)
}

// Regression: the DB-backed signer record lags the live SignerRegistry — it is
// refreshed only on material_check ticks (default 1h). Between ticks an
// Unlock/Lock against the registry must NOT be masked by a stale DB row.
// Before the fix, newSignerResponse overwrote resp.Locked / resp.Enabled with
// the DB record's values, so the HD primary kept reporting locked=true in the
// /signers list even after a successful unlock.
func TestNewSignerResponse_HDWallet_PrimaryUnlocked_StaleDBRecordIgnored(t *testing.T) {
	primaryAddr := "0x21f409aA1a060B22B3ce647d2bDb1C0a9457A0B8"

	mgr := &mockSignerManager{
		hdWalletMgr: &mockHDWalletManager{
			listHDWalletsFn: func() []evmchain.HDWalletInfo {
				return []evmchain.HDWalletInfo{
					{PrimaryAddress: primaryAddr, Locked: false}, // live state: unlocked
				}
			},
			listDerivedAddrsFn: func(_ string) ([]types.SignerInfo, error) { return nil, nil },
		},
	}
	accessSvc := newStrictAccessService(t, nil)
	handler, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	// DB row is still stale from before the unlock (material_check hasn't ticked).
	handler.SetSignerRepo(&stubSignerRepo{records: map[string]*types.Signer{
		primaryAddr: {
			Address:        primaryAddr,
			Type:           types.SignerTypeHDWallet,
			PrimaryAddress: primaryAddr,
			Enabled:        false,
			Locked:         true,
			MaterialStatus: types.SignerMaterialStatusPresent,
		},
	}})

	resp := handler.newSignerResponse(context.Background(), types.SignerInfo{
		Address: primaryAddr,
		Type:    string(types.SignerTypeHDWallet),
		Enabled: true,
		Locked:  false,
	})
	assert.False(t, resp.Locked, "live registry says unlocked; stale DB row must not override")
	assert.True(t, resp.Enabled, "live registry says enabled; stale DB row must not override")
	// Inventory fields from the DB are still applied (they don't reflect live lock state).
	assert.Equal(t, "present", resp.MaterialStatus)
}

// Regression sibling: a derived address must also reflect the live (unlocked)
// state of its parent wallet even when the DB record for the derived address
// is stale. Same root cause, separate code path through the HD hierarchy.
func TestNewSignerResponse_HDWallet_DerivedUnlocked_StaleDBRecordIgnored(t *testing.T) {
	primaryAddr := "0x21f409aA1a060B22B3ce647d2bDb1C0a9457A0B8"
	derivedAddr := "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	mgr := &mockSignerManager{
		hdWalletMgr: &mockHDWalletManager{
			listHDWalletsFn: func() []evmchain.HDWalletInfo {
				return []evmchain.HDWalletInfo{
					{PrimaryAddress: primaryAddr, Locked: false},
				}
			},
			listDerivedAddrsFn: func(primary string) ([]types.SignerInfo, error) {
				if strings.EqualFold(primary, primaryAddr) {
					return []types.SignerInfo{
						{Address: derivedAddr, Type: string(types.SignerTypeHDWallet), Enabled: true},
					}, nil
				}
				return nil, nil
			},
		},
	}
	accessSvc := newStrictAccessService(t, nil)
	handler, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	handler.SetSignerRepo(&stubSignerRepo{records: map[string]*types.Signer{
		derivedAddr: {
			Address:        derivedAddr,
			Type:           types.SignerTypeHDWallet,
			PrimaryAddress: primaryAddr,
			Enabled:        false,
			Locked:         true,
			MaterialStatus: types.SignerMaterialStatusPresent,
		},
	}})

	resp := handler.newSignerResponse(context.Background(), types.SignerInfo{
		Address: derivedAddr,
		Type:    string(types.SignerTypeHDWallet),
		Enabled: true,
		Locked:  true,
	})
	assert.False(t, resp.Locked, "derived of unlocked wallet must be unlocked despite stale DB row")
	assert.True(t, resp.Enabled, "derived of unlocked wallet must be enabled despite stale DB row")
}
