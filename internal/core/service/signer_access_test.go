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
