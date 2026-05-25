//go:build integration

package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	// Use unique file per test to avoid cross-test contamination with shared cache
	dbFile := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&types.APIKey{},
		&types.SignerOwnership{},
		&types.SignerAccess{},
	))
	return db
}

func setupAccessService(t *testing.T, db *gorm.DB) (*SignerAccessService, storage.SignerOwnershipRepository, storage.SignerAccessRepository, storage.APIKeyRepository) {
	t.Helper()
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, logger)
	require.NoError(t, err)
	return svc, ownershipRepo, accessRepo, apiKeyRepo
}

// setupTestDBWithWallets includes wallet tables for wallet-based access tests.
func setupTestDBWithWallets(t *testing.T) *gorm.DB {
	t.Helper()
	dbFile := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&types.APIKey{},
		&types.SignerOwnership{},
		&types.SignerAccess{},
		&types.Wallet{},
		&types.WalletMember{},
	))
	return db
}

func setupAccessServiceWithWallet(t *testing.T, db *gorm.DB) (*SignerAccessService, storage.SignerOwnershipRepository, storage.SignerAccessRepository, storage.APIKeyRepository, storage.WalletRepository) {
	t.Helper()
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)
	walletRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, logger)
	require.NoError(t, err)
	svc.SetWalletRepo(walletRepo)
	return svc, ownershipRepo, accessRepo, apiKeyRepo, walletRepo
}

func createTestAPIKey(t *testing.T, repo storage.APIKeyRepository, id, role string) {
	t.Helper()
	err := repo.Create(context.Background(), &types.APIKey{
		ID:        id,
		Name:      "Test " + id,
		Role:      types.APIKeyRole(role),
		Enabled:   true,
		Source:    types.APIKeySourceAPI,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
}

func TestSignerAccessService_SetOwnerAndCheckAccess(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "admin-1", "admin")

	// Set owner
	err := svc.SetOwner(ctx, "0xAABB", "admin-1", types.SignerOwnershipActive)
	require.NoError(t, err)

	// Owner has access
	ok, err := svc.CheckAccess(ctx, "admin-1", "0xAABB")
	require.NoError(t, err)
	assert.True(t, ok)

	// Non-owner has no access
	createTestAPIKey(t, apiKeyRepo, "agent-1", "agent")
	ok, err = svc.CheckAccess(ctx, "agent-1", "0xAABB")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSignerAccessService_GrantAndRevoke(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")
	createTestAPIKey(t, apiKeyRepo, "grantee-1", "agent")

	// Set owner
	require.NoError(t, svc.SetOwner(ctx, "0x1111", "owner-1", types.SignerOwnershipActive))

	// Grantee has no access initially
	ok, err := svc.CheckAccess(ctx, "grantee-1", "0x1111")
	require.NoError(t, err)
	assert.False(t, ok)

	// Grant access
	err = svc.GrantAccess(ctx, "owner-1", "0x1111", "grantee-1")
	require.NoError(t, err)

	// Grantee now has access
	ok, err = svc.CheckAccess(ctx, "grantee-1", "0x1111")
	require.NoError(t, err)
	assert.True(t, ok)

	// List access
	accesses, err := svc.ListAccess(ctx, "owner-1", "0x1111")
	require.NoError(t, err)
	assert.Len(t, accesses, 1)
	assert.Equal(t, "grantee-1", accesses[0].APIKeyID)

	// Revoke access
	err = svc.RevokeAccess(ctx, "owner-1", "0x1111", "grantee-1")
	require.NoError(t, err)

	// Grantee no longer has access
	ok, err = svc.CheckAccess(ctx, "grantee-1", "0x1111")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSignerAccessService_GrantDeniedForNonOwner(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")
	createTestAPIKey(t, apiKeyRepo, "non-owner", "dev")
	createTestAPIKey(t, apiKeyRepo, "grantee-1", "agent")

	require.NoError(t, svc.SetOwner(ctx, "0x2222", "owner-1", types.SignerOwnershipActive))

	// Non-owner cannot grant
	err := svc.GrantAccess(ctx, "non-owner", "0x2222", "grantee-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not the owner")
}

func TestSignerAccessService_PendingApprovalBlocksAccess(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "agent-1", "agent")

	// Set owner with pending_approval status
	require.NoError(t, svc.SetOwner(ctx, "0x3333", "agent-1", types.SignerOwnershipPendingApproval))

	// Owner of pending signer has no access (status is not active)
	ok, err := svc.CheckAccess(ctx, "agent-1", "0x3333")
	require.NoError(t, err)
	assert.False(t, ok)

	// Activate it
	require.NoError(t, svc.SetOwner(ctx, "0x3333", "agent-1", types.SignerOwnershipActive))

	// Now owner has access
	ok, err = svc.CheckAccess(ctx, "agent-1", "0x3333")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestSignerAccessService_IsOwner(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")
	createTestAPIKey(t, apiKeyRepo, "other-1", "dev")

	require.NoError(t, svc.SetOwner(ctx, "0x4444", "owner-1", types.SignerOwnershipActive))

	ok, err := svc.IsOwner(ctx, "owner-1", "0x4444")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = svc.IsOwner(ctx, "other-1", "0x4444")
	require.NoError(t, err)
	assert.False(t, ok)

	// Non-existent signer
	ok, err = svc.IsOwner(ctx, "owner-1", "0x9999")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSignerAccessService_GetOwnedAndAccessibleAddresses(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")
	createTestAPIKey(t, apiKeyRepo, "grantee-1", "agent")

	require.NoError(t, svc.SetOwner(ctx, "0xAAAA", "owner-1", types.SignerOwnershipActive))
	require.NoError(t, svc.SetOwner(ctx, "0xBBBB", "owner-1", types.SignerOwnershipActive))
	require.NoError(t, svc.GrantAccess(ctx, "owner-1", "0xAAAA", "grantee-1"))

	// Owner sees both
	owned, err := svc.GetOwnedAddresses(ctx, "owner-1")
	require.NoError(t, err)
	assert.Len(t, owned, 2)

	// Grantee sees only granted
	accessible, err := svc.GetAccessibleAddresses(ctx, "grantee-1")
	require.NoError(t, err)
	assert.Len(t, accessible, 1)
	assert.Equal(t, "0xAAAA", accessible[0])
}

func TestSignerAccessService_GrantToNonExistentKey(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")
	require.NoError(t, svc.SetOwner(ctx, "0x5555", "owner-1", types.SignerOwnershipActive))

	err := svc.GrantAccess(ctx, "owner-1", "0x5555", "nonexistent-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSignerAccessService_HDWalletDerivedAccess(t *testing.T) {
	db := setupTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Mock HD wallet resolver
	mockHDMgr := &mockHDWalletResolver{
		primaryAddrs: []string{"0xPRIMARY"},
		derived: map[string][]types.SignerInfo{
			"0xPRIMARY": {
				{Address: "0xDERIVED1"},
				{Address: "0xDERIVED2"},
			},
		},
	}

	svc, err := NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, func() (HDWalletParentResolver, error) {
		return mockHDMgr, nil
	}, logger)
	require.NoError(t, err)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")

	// Owner owns the primary address
	require.NoError(t, svc.SetOwner(ctx, "0xPRIMARY", "owner-1", types.SignerOwnershipActive))

	// Owner can access derived addresses
	ok, err := svc.CheckAccess(ctx, "owner-1", "0xDERIVED1")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = svc.CheckAccess(ctx, "owner-1", "0xDERIVED2")
	require.NoError(t, err)
	assert.True(t, ok)

	// Non-owner cannot access derived
	createTestAPIKey(t, apiKeyRepo, "other-1", "agent")
	ok, err = svc.CheckAccess(ctx, "other-1", "0xDERIVED1")
	require.NoError(t, err)
	assert.False(t, ok)

	// Grant access to primary → grantee gets derived access
	require.NoError(t, svc.GrantAccess(ctx, "owner-1", "0xPRIMARY", "other-1"))
	ok, err = svc.CheckAccess(ctx, "other-1", "0xDERIVED1")
	require.NoError(t, err)
	assert.True(t, ok)
}

// IsOwner must resolve HD-wallet derived addresses to the parent
// ownership row. Pre-fix the access mutation endpoints (GrantAccess /
// RevokeAccess / ListAccess / TransferOwnership) all 403'd on a derived
// address because they share this gate.
func TestSignerAccessService_IsOwner_HDDerivedResolvesParent(t *testing.T) {
	db := setupTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	mockHDMgr := &mockHDWalletResolver{
		primaryAddrs: []string{"0xPRIMARY"},
		derived: map[string][]types.SignerInfo{
			"0xPRIMARY": {{Address: "0xDERIVED1"}, {Address: "0xDERIVED2"}},
		},
	}
	svc, err := NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, func() (HDWalletParentResolver, error) {
		return mockHDMgr, nil
	}, logger)
	require.NoError(t, err)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")
	createTestAPIKey(t, apiKeyRepo, "other-1", "agent")
	createTestAPIKey(t, apiKeyRepo, "grantee-1", "agent")
	require.NoError(t, svc.SetOwner(ctx, "0xPRIMARY", "owner-1", types.SignerOwnershipActive))

	// Parent ownership directly: still passes (regression guard).
	ok, err := svc.IsOwner(ctx, "owner-1", "0xPRIMARY")
	require.NoError(t, err)
	assert.True(t, ok)

	// THE BUG: derived address now resolves to parent, owner sees true.
	ok, err = svc.IsOwner(ctx, "owner-1", "0xDERIVED1")
	require.NoError(t, err)
	assert.True(t, ok, "owner of parent must be reported as owner of derived")

	ok, err = svc.IsOwner(ctx, "owner-1", "0xDERIVED2")
	require.NoError(t, err)
	assert.True(t, ok)

	// Other identity must still get false even after parent resolution.
	ok, err = svc.IsOwner(ctx, "other-1", "0xDERIVED1")
	require.NoError(t, err)
	assert.False(t, ok)

	// Unknown address (not in HD tree, no ownership row) — false, not error.
	ok, err = svc.IsOwner(ctx, "owner-1", "0xUNKNOWN")
	require.NoError(t, err)
	assert.False(t, ok)

	// End-to-end mutation flow that the bug actually broke: GrantAccess
	// targeted at a derived address must succeed when the caller owns
	// the parent, then ListAccess + RevokeAccess against the same
	// derived address must round-trip.
	err = svc.GrantAccess(ctx, "owner-1", "0xDERIVED1", "grantee-1")
	require.NoError(t, err, "GrantAccess on derived must work when parent owned")
	grants, err := svc.ListAccess(ctx, "owner-1", "0xDERIVED1")
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, "grantee-1", grants[0].APIKeyID)
	require.NoError(t, svc.RevokeAccess(ctx, "owner-1", "0xDERIVED1", "grantee-1"))

	// And the negative: a stranger can't grant on a derived address.
	err = svc.GrantAccess(ctx, "other-1", "0xDERIVED1", "grantee-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not the owner")
}

// Guard against regression of the "no HD manager wired" path — the old
// code did a single direct lookup and returned (false, nil) on miss.
// New code must keep that behavior when hdWalletMgrFn is nil.
func TestSignerAccessService_IsOwner_NoHDManager_MissReturnsFalse(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()
	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")

	ok, err := svc.IsOwner(ctx, "owner-1", "0xNOTOWNED")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestNewSignerAccessService_Validation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := NewSignerAccessService(nil, nil, nil, nil, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ownership repository")

	db := setupTestDB(t)
	ownershipRepo, _ := storage.NewGormSignerOwnershipRepository(db)

	_, err = NewSignerAccessService(ownershipRepo, nil, nil, nil, logger)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access repository")
}

// mockHDWalletResolver implements HDWalletParentResolver for testing.
type mockHDWalletResolver struct {
	primaryAddrs []string
	derived      map[string][]types.SignerInfo
}

func (m *mockHDWalletResolver) ListPrimaryAddresses() []string {
	return m.primaryAddrs
}

func (m *mockHDWalletResolver) ListDerivedAddresses(primaryAddr string) ([]types.SignerInfo, error) {
	return m.derived[primaryAddr], nil
}

// === Phase 3: Lifecycle Safety tests ===

func TestSignerAccessService_TransferOwnership_ClearsAccess(t *testing.T) {
	db := setupTestDB(t)
	svc, _, accessRepo, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")
	createTestAPIKey(t, apiKeyRepo, "grantee-1", "agent")
	createTestAPIKey(t, apiKeyRepo, "new-owner", "dev")

	require.NoError(t, svc.SetOwner(ctx, "0xAAAA", "owner-1", types.SignerOwnershipActive))
	require.NoError(t, svc.GrantAccess(ctx, "owner-1", "0xAAAA", "grantee-1"))

	// Verify grantee has access before transfer
	ok, err := svc.CheckAccess(ctx, "grantee-1", "0xAAAA")
	require.NoError(t, err)
	assert.True(t, ok)

	// Transfer
	err = svc.TransferOwnership(ctx, "owner-1", "0xAAAA", "new-owner")
	require.NoError(t, err)

	// Access list is cleared
	accesses, err := accessRepo.List(ctx, "0xAAAA")
	require.NoError(t, err)
	assert.Empty(t, accesses, "access list should be empty after transfer")

	// Old owner has no access
	ok, err = svc.CheckAccess(ctx, "owner-1", "0xAAAA")
	require.NoError(t, err)
	assert.False(t, ok, "old owner should have no access")

	// Grantee has no access
	ok, err = svc.CheckAccess(ctx, "grantee-1", "0xAAAA")
	require.NoError(t, err)
	assert.False(t, ok, "grantee should have no access after transfer")

	// New owner has access
	ok, err = svc.CheckAccess(ctx, "new-owner", "0xAAAA")
	require.NoError(t, err)
	assert.True(t, ok, "new owner should have access")
}

func TestSignerAccessService_TransferOwnership_NonOwner(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")
	createTestAPIKey(t, apiKeyRepo, "non-owner", "dev")
	createTestAPIKey(t, apiKeyRepo, "new-owner", "agent")

	require.NoError(t, svc.SetOwner(ctx, "0xBBBB", "owner-1", types.SignerOwnershipActive))

	err := svc.TransferOwnership(ctx, "non-owner", "0xBBBB", "new-owner")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not the owner")
}

func TestSignerAccessService_TransferOwnership_ToSelf(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")

	require.NoError(t, svc.SetOwner(ctx, "0xCCCC", "owner-1", types.SignerOwnershipActive))

	err := svc.TransferOwnership(ctx, "owner-1", "0xCCCC", "owner-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot transfer signer to yourself")
}

func TestSignerAccessService_DeleteSigner_CascadeAccess(t *testing.T) {
	db := setupTestDB(t)
	svc, ownershipRepo, accessRepo, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")
	createTestAPIKey(t, apiKeyRepo, "grantee-1", "agent")

	require.NoError(t, svc.SetOwner(ctx, "0xDDDD", "owner-1", types.SignerOwnershipActive))
	require.NoError(t, svc.GrantAccess(ctx, "owner-1", "0xDDDD", "grantee-1"))

	// Delete
	err := svc.DeleteSigner(ctx, "owner-1", "0xDDDD")
	require.NoError(t, err)

	// Ownership record gone
	_, err = ownershipRepo.Get(ctx, "0xDDDD")
	assert.Error(t, err)
	assert.True(t, types.IsNotFound(err))

	// Access records gone
	accesses, err := accessRepo.List(ctx, "0xDDDD")
	require.NoError(t, err)
	assert.Empty(t, accesses)
}

func TestSignerAccessService_CleanupForDeletedKey(t *testing.T) {
	db := setupTestDB(t)
	// Also migrate rules table for this test
	require.NoError(t, db.AutoMigrate(&types.Rule{}))

	svc, _, accessRepo, apiKeyRepo := setupAccessService(t, db)
	ruleRepo, err := storage.NewGormRuleRepository(db)
	require.NoError(t, err)
	svc.SetRuleRepo(ruleRepo)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "admin-1", "admin")
	createTestAPIKey(t, apiKeyRepo, "key-to-delete", "agent")
	createTestAPIKey(t, apiKeyRepo, "other-key", "dev")

	// Create a rule owned by key-to-delete
	ownedRule := &types.Rule{
		ID:      "rule-owned",
		Name:    "Owned Rule",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Owner:   "key-to-delete",
		AppliedTo: []string{"key-to-delete"},
		Enabled: true,
	}
	require.NoError(t, ruleRepo.Create(ctx, ownedRule))

	// Create a rule that has key-to-delete in applied_to along with other key
	sharedRule := &types.Rule{
		ID:      "rule-shared",
		Name:    "Shared Rule",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Owner:   "other-key",
		AppliedTo: []string{"key-to-delete", "other-key"},
		Enabled: true,
	}
	require.NoError(t, ruleRepo.Create(ctx, sharedRule))

	// Create a rule that only has key-to-delete in applied_to (should be deleted)
	soloRule := &types.Rule{
		ID:      "rule-solo",
		Name:    "Solo Rule",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Owner:   "other-key",
		AppliedTo: []string{"key-to-delete"},
		Enabled: true,
	}
	require.NoError(t, ruleRepo.Create(ctx, soloRule))

	// Grant access from admin signer to key-to-delete
	require.NoError(t, svc.SetOwner(ctx, "0xEEEE", "admin-1", types.SignerOwnershipActive))
	require.NoError(t, svc.GrantAccess(ctx, "admin-1", "0xEEEE", "key-to-delete"))

	// Cleanup
	err = svc.CleanupForDeletedKey(ctx, "key-to-delete")
	require.NoError(t, err)

	// Owned rule deleted
	_, err = ruleRepo.Get(ctx, "rule-owned")
	assert.Error(t, err)
	assert.True(t, types.IsNotFound(err))

	// Shared rule still exists but key-to-delete removed from applied_to
	shared, err := ruleRepo.Get(ctx, "rule-shared")
	require.NoError(t, err)
	assert.Equal(t, []string{"other-key"}, []string(shared.AppliedTo))

	// Solo rule deleted (applied_to became empty)
	_, err = ruleRepo.Get(ctx, "rule-solo")
	assert.Error(t, err)
	assert.True(t, types.IsNotFound(err))

	// Access records deleted
	accesses, err := accessRepo.List(ctx, "0xEEEE")
	require.NoError(t, err)
	assert.Empty(t, accesses)
}

func TestSignerAccessService_CountOwnedSigners(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")

	require.NoError(t, svc.SetOwner(ctx, "0x1111", "owner-1", types.SignerOwnershipActive))
	require.NoError(t, svc.SetOwner(ctx, "0x2222", "owner-1", types.SignerOwnershipActive))

	count, err := svc.CountOwnedSigners(ctx, "owner-1")
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	// Non-existent owner
	count, err = svc.CountOwnedSigners(ctx, "nobody")
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

// ---------------------------------------------------------------------------
// checkWalletAccess tests
// ---------------------------------------------------------------------------

func TestCheckAccess_WalletOwner(t *testing.T) {
	db := setupTestDBWithWallets(t)
	svc, _, _, apiKeyRepo, walletRepo := setupAccessServiceWithWallet(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "wallet-owner", "admin")

	// Create a wallet owned by wallet-owner
	wallet := &types.Wallet{
		ID:      "wallet-1",
		Name:    "Test Wallet",
		OwnerID: "wallet-owner",
	}
	require.NoError(t, walletRepo.Create(ctx, wallet))

	// Add signer to wallet
	require.NoError(t, walletRepo.AddMember(ctx, &types.WalletMember{
		WalletID:      "wallet-1",
		SignerAddress: "0xWALLET",
	}))

	// Set ownership for the signer so checkDirectAccess runs first
	require.NoError(t, svc.SetOwner(ctx, "0xWALLET", "other-owner", types.SignerOwnershipActive))

	// wallet-owner should NOT have direct access (other-owner owns it)
	// but checkWalletAccess should grant access via wallet ownership
	ok, err := svc.CheckAccess(ctx, "wallet-owner", "0xWALLET")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestCheckAccess_WalletMemberAccess(t *testing.T) {
	db := setupTestDBWithWallets(t)
	svc, _, _, apiKeyRepo, walletRepo := setupAccessServiceWithWallet(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "wallet-member", "agent")

	// Create a wallet owned by someone else
	wallet := &types.Wallet{
		ID:      "wallet-2",
		Name:    "Shared Wallet",
		OwnerID: "wallet-owner-2",
	}
	require.NoError(t, walletRepo.Create(ctx, wallet))

	// Add signer to wallet
	require.NoError(t, walletRepo.AddMember(ctx, &types.WalletMember{
		WalletID:      "wallet-2",
		SignerAddress: "0xSHARED",
	}))

	// Set ownership for the signer
	require.NoError(t, svc.SetOwner(ctx, "0xSHARED", "wallet-owner-2", types.SignerOwnershipActive))

	// Grant wallet-member access via wallet_id. Use a different signer_address
	// so HasAccess (signer_address + api_key_id) won't match, forcing the
	// checkWalletAccess → HasAccessViaWallet path.
	err := db.WithContext(ctx).Create(&types.SignerAccess{
		ID:            "access-wm",
		SignerAddress: "0xUNRELATED",
		APIKeyID:      "wallet-member",
		GrantedBy:     "wallet-owner-2",
		WalletID:      "wallet-2",
	}).Error
	require.NoError(t, err)

	ok, err := svc.CheckAccess(ctx, "wallet-member", "0xSHARED")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestCheckAccess_NoWalletAccess(t *testing.T) {
	db := setupTestDBWithWallets(t)
	svc, _, _, apiKeyRepo, walletRepo := setupAccessServiceWithWallet(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "stranger", "agent")

	// Create a wallet
	wallet := &types.Wallet{
		ID:      "wallet-3",
		Name:    "Private Wallet",
		OwnerID: "someone-else",
	}
	require.NoError(t, walletRepo.Create(ctx, wallet))

	// Add signer to wallet
	require.NoError(t, walletRepo.AddMember(ctx, &types.WalletMember{
		WalletID:      "wallet-3",
		SignerAddress: "0xPRIVATE",
	}))

	// Set ownership — stranger does NOT own it
	require.NoError(t, svc.SetOwner(ctx, "0xPRIVATE", "someone-else", types.SignerOwnershipActive))

	ok, err := svc.CheckAccess(ctx, "stranger", "0xPRIVATE")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestCheckAccess_NoWalletsForSigner(t *testing.T) {
	db := setupTestDBWithWallets(t)
	svc, _, _, apiKeyRepo, _ := setupAccessServiceWithWallet(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")

	// Signer has no wallets — ownership check passes directly
	require.NoError(t, svc.SetOwner(ctx, "0xNOWALLET", "owner-1", types.SignerOwnershipActive))

	ok, err := svc.CheckAccess(ctx, "owner-1", "0xNOWALLET")
	require.NoError(t, err)
	assert.True(t, ok)
}
