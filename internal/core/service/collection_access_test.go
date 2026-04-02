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

func setupCollectionAccessTestDB(t *testing.T) *gorm.DB {
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
		&types.WalletCollection{},
		&types.CollectionMember{},
	))
	return db
}

func setupCollectionAccessService(t *testing.T, db *gorm.DB) (
	*SignerAccessService,
	storage.SignerOwnershipRepository,
	storage.SignerAccessRepository,
	storage.APIKeyRepository,
	storage.CollectionRepository,
) {
	t.Helper()
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)
	collectionRepo, err := storage.NewGormCollectionRepository(db)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, logger)
	require.NoError(t, err)
	svc.SetCollectionRepo(collectionRepo)

	return svc, ownershipRepo, accessRepo, apiKeyRepo, collectionRepo
}

// TestCheckAccess_ViaCollectionOwnership verifies that a collection owner
// has access to all signers that are members of their collection.
func TestCheckAccess_ViaCollectionOwnership(t *testing.T) {
	db := setupCollectionAccessTestDB(t)
	svc, ownershipRepo, _, apiKeyRepo, collectionRepo := setupCollectionAccessService(t, db)
	ctx := context.Background()

	// Create API keys
	ownerKey := &types.APIKey{ID: "owner-1", Name: "Owner", PublicKeyHex: "aa", Role: types.RoleAdmin, Enabled: true}
	require.NoError(t, apiKeyRepo.Create(ctx, ownerKey))

	signerAddr := "0x1111111111111111111111111111111111111111"

	// Create signer ownership by someone else
	require.NoError(t, ownershipRepo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: signerAddr,
		OwnerID:       "other-key",
		Status:        types.SignerOwnershipActive,
	}))

	// Create a collection owned by owner-1
	coll := &types.WalletCollection{Name: "My Collection", OwnerID: "owner-1"}
	require.NoError(t, collectionRepo.Create(ctx, coll))

	// Without collection membership, owner-1 has no access
	allowed, err := svc.CheckAccess(ctx, "owner-1", signerAddr)
	require.NoError(t, err)
	assert.False(t, allowed, "should not have access without collection membership")

	// Add signer to collection
	require.NoError(t, collectionRepo.AddMember(ctx, &types.CollectionMember{
		CollectionID: coll.ID,
		WalletID:     signerAddr,
	}))

	// Now owner-1 should have access via collection ownership
	allowed, err = svc.CheckAccess(ctx, "owner-1", signerAddr)
	require.NoError(t, err)
	assert.True(t, allowed, "should have access via collection ownership")
}

// TestCheckAccess_ViaCollectionGrant verifies that an API key with a signer_access
// grant with wallet_id pointing to a collection can access signers in that collection.
func TestCheckAccess_ViaCollectionGrant(t *testing.T) {
	db := setupCollectionAccessTestDB(t)
	svc, ownershipRepo, accessRepo, apiKeyRepo, collectionRepo := setupCollectionAccessService(t, db)
	ctx := context.Background()

	// Create API keys
	collOwner := &types.APIKey{ID: "coll-owner", Name: "Collection Owner", PublicKeyHex: "aa", Role: types.RoleAdmin, Enabled: true}
	grantee := &types.APIKey{ID: "grantee-1", Name: "Grantee", PublicKeyHex: "bb", Role: types.RoleAgent, Enabled: true}
	require.NoError(t, apiKeyRepo.Create(ctx, collOwner))
	require.NoError(t, apiKeyRepo.Create(ctx, grantee))

	signerAddr := "0x2222222222222222222222222222222222222222"

	// Create signer ownership (owned by someone else)
	require.NoError(t, ownershipRepo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: signerAddr,
		OwnerID:       "third-party",
		Status:        types.SignerOwnershipActive,
	}))

	// Create a collection owned by coll-owner
	coll := &types.WalletCollection{Name: "Shared Collection", OwnerID: "coll-owner"}
	require.NoError(t, collectionRepo.Create(ctx, coll))

	// Add signer to collection
	require.NoError(t, collectionRepo.AddMember(ctx, &types.CollectionMember{
		CollectionID: coll.ID,
		WalletID:     signerAddr,
	}))

	// Without grant, grantee has no access
	allowed, err := svc.CheckAccess(ctx, "grantee-1", signerAddr)
	require.NoError(t, err)
	assert.False(t, allowed, "should not have access without grant")

	// Grant access via wallet_id = collection ID
	require.NoError(t, accessRepo.Grant(ctx, &types.SignerAccess{
		ID:            "grantee-1:" + coll.ID,
		SignerAddress: signerAddr, // placeholder; the key is wallet_id
		APIKeyID:      "grantee-1",
		GrantedBy:     "coll-owner",
		WalletID:      coll.ID,
		CreatedAt:     time.Now(),
	}))

	// Now grantee should have access via collection grant
	allowed, err = svc.CheckAccess(ctx, "grantee-1", signerAddr)
	require.NoError(t, err)
	assert.True(t, allowed, "should have access via collection grant")
}

// TestCheckAccess_DirectAccessStillWorks verifies that direct access
// checks still work when collection repo is set.
func TestCheckAccess_DirectAccessStillWorks(t *testing.T) {
	db := setupCollectionAccessTestDB(t)
	svc, ownershipRepo, _, apiKeyRepo, _ := setupCollectionAccessService(t, db)
	ctx := context.Background()

	ownerKey := &types.APIKey{ID: "direct-owner", Name: "Direct Owner", PublicKeyHex: "aa", Role: types.RoleAdmin, Enabled: true}
	require.NoError(t, apiKeyRepo.Create(ctx, ownerKey))

	signerAddr := "0x3333333333333333333333333333333333333333"

	require.NoError(t, ownershipRepo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: signerAddr,
		OwnerID:       "direct-owner",
		Status:        types.SignerOwnershipActive,
	}))

	allowed, err := svc.CheckAccess(ctx, "direct-owner", signerAddr)
	require.NoError(t, err)
	assert.True(t, allowed, "direct owner should still have access")
}

// TestCheckAccess_NoCollectionRepo verifies that access checks work
// when collection repo is nil (backward compatibility).
func TestCheckAccess_NoCollectionRepo(t *testing.T) {
	db := setupCollectionAccessTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, logger)
	require.NoError(t, err)
	// Note: no SetCollectionRepo call

	ctx := context.Background()
	signerAddr := "0x4444444444444444444444444444444444444444"

	require.NoError(t, apiKeyRepo.Create(ctx, &types.APIKey{
		ID: "key-no-coll", Name: "No Coll", PublicKeyHex: "aa", Role: types.RoleAdmin, Enabled: true,
	}))
	require.NoError(t, ownershipRepo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: signerAddr,
		OwnerID:       "other",
		Status:        types.SignerOwnershipActive,
	}))

	allowed, err := svc.CheckAccess(ctx, "key-no-coll", signerAddr)
	require.NoError(t, err)
	assert.False(t, allowed, "should not have access without collection repo")
}

// TestCheckAccess_CollectionMemberRemoved verifies that removing a member
// from a collection revokes access.
func TestCheckAccess_CollectionMemberRemoved(t *testing.T) {
	db := setupCollectionAccessTestDB(t)
	svc, ownershipRepo, _, apiKeyRepo, collectionRepo := setupCollectionAccessService(t, db)
	ctx := context.Background()

	require.NoError(t, apiKeyRepo.Create(ctx, &types.APIKey{
		ID: "owner-rm", Name: "Owner", PublicKeyHex: "aa", Role: types.RoleAdmin, Enabled: true,
	}))

	signerAddr := "0x5555555555555555555555555555555555555555"
	require.NoError(t, ownershipRepo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: signerAddr,
		OwnerID:       "other",
		Status:        types.SignerOwnershipActive,
	}))

	coll := &types.WalletCollection{Name: "Remove Test", OwnerID: "owner-rm"}
	require.NoError(t, collectionRepo.Create(ctx, coll))
	require.NoError(t, collectionRepo.AddMember(ctx, &types.CollectionMember{
		CollectionID: coll.ID,
		WalletID:     signerAddr,
	}))

	// Has access via collection
	allowed, err := svc.CheckAccess(ctx, "owner-rm", signerAddr)
	require.NoError(t, err)
	assert.True(t, allowed)

	// Remove member
	require.NoError(t, collectionRepo.RemoveMember(ctx, coll.ID, signerAddr))

	// Access revoked
	allowed, err = svc.CheckAccess(ctx, "owner-rm", signerAddr)
	require.NoError(t, err)
	assert.False(t, allowed)
}
