package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

func setupCollectionHandlerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&types.WalletCollection{},
		&types.CollectionMember{},
		&types.SignerOwnership{},
		&types.SignerAccess{},
	))
	return db
}

func TestAddMember_CrossUserPrivilegeEscalation(t *testing.T) {
	db := setupCollectionHandlerTestDB(t)

	collRepo, err := storage.NewGormCollectionRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	logger := slog.Default()
	handler, err := NewCollectionHandler(collRepo, ownershipRepo, accessRepo, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// User A owns wallet 0xAAAA
	walletA := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	require.NoError(t, ownershipRepo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: walletA,
		OwnerID:       "user-a",
		Status:        types.SignerOwnershipActive,
	}))

	// User B creates a collection
	collB := &types.WalletCollection{Name: "User B Collection", OwnerID: "user-b"}
	require.NoError(t, collRepo.Create(ctx, collB))

	// User B tries to add User A's wallet to their collection
	body, _ := json.Marshal(addMemberRequest{WalletID: walletA})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/collections/"+collB.ID+"/members", bytes.NewReader(body))

	// Set User B as the authenticated caller (non-admin)
	apiKeyB := &types.APIKey{ID: "user-b", Name: "User B", Role: types.RoleDev, Enabled: true}
	reqCtx := context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKeyB)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.addMember(rr, req, collB.ID)

	// Should be FORBIDDEN -- User B does not own or have access to User A's wallet
	assert.Equal(t, http.StatusForbidden, rr.Code, "cross-user privilege escalation should be blocked")

	var resp map[string]string
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Contains(t, resp["error"], "unauthorized to add wallet")

	// Verify the wallet was NOT added to the collection
	members, err := collRepo.ListMembers(ctx, collB.ID)
	require.NoError(t, err)
	assert.Len(t, members, 0, "wallet should NOT have been added to the collection")
}

func TestAddMember_OwnerCanAddOwnWallet(t *testing.T) {
	db := setupCollectionHandlerTestDB(t)

	collRepo, err := storage.NewGormCollectionRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	logger := slog.Default()
	handler, err := NewCollectionHandler(collRepo, ownershipRepo, accessRepo, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// User A owns wallet 0xAAAA
	walletA := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	require.NoError(t, ownershipRepo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: walletA,
		OwnerID:       "user-a",
		Status:        types.SignerOwnershipActive,
	}))

	// User A creates a collection
	collA := &types.WalletCollection{Name: "User A Collection", OwnerID: "user-a"}
	require.NoError(t, collRepo.Create(ctx, collA))

	// User A adds their own wallet to their collection
	body, _ := json.Marshal(addMemberRequest{WalletID: walletA})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/collections/"+collA.ID+"/members", bytes.NewReader(body))

	apiKeyA := &types.APIKey{ID: "user-a", Name: "User A", Role: types.RoleDev, Enabled: true}
	reqCtx := context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKeyA)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.addMember(rr, req, collA.ID)

	assert.Equal(t, http.StatusCreated, rr.Code, "owner should be able to add their own wallet")
}

func TestAddMember_AccessGranteeCanAddWallet(t *testing.T) {
	db := setupCollectionHandlerTestDB(t)

	collRepo, err := storage.NewGormCollectionRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	logger := slog.Default()
	handler, err := NewCollectionHandler(collRepo, ownershipRepo, accessRepo, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// User A owns wallet 0xAAAA
	walletA := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	require.NoError(t, ownershipRepo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: walletA,
		OwnerID:       "user-a",
		Status:        types.SignerOwnershipActive,
	}))

	// User A grants access to User B
	require.NoError(t, accessRepo.Grant(ctx, &types.SignerAccess{
		SignerAddress: walletA,
		APIKeyID:      "user-b",
		GrantedBy:     "user-a",
		CreatedAt:     time.Now(),
	}))

	// User B creates a collection
	collB := &types.WalletCollection{Name: "User B Collection", OwnerID: "user-b"}
	require.NoError(t, collRepo.Create(ctx, collB))

	// User B adds a wallet they have access to
	body, _ := json.Marshal(addMemberRequest{WalletID: walletA})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/collections/"+collB.ID+"/members", bytes.NewReader(body))

	apiKeyB := &types.APIKey{ID: "user-b", Name: "User B", Role: types.RoleDev, Enabled: true}
	reqCtx := context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKeyB)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.addMember(rr, req, collB.ID)

	assert.Equal(t, http.StatusCreated, rr.Code, "access grantee should be able to add wallet")
}

func TestAddMember_AdminBypassesOwnershipCheck(t *testing.T) {
	db := setupCollectionHandlerTestDB(t)

	collRepo, err := storage.NewGormCollectionRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	logger := slog.Default()
	handler, err := NewCollectionHandler(collRepo, ownershipRepo, accessRepo, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// User A owns wallet 0xAAAA
	walletA := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	require.NoError(t, ownershipRepo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: walletA,
		OwnerID:       "user-a",
		Status:        types.SignerOwnershipActive,
	}))

	// Admin creates a collection
	collAdmin := &types.WalletCollection{Name: "Admin Collection", OwnerID: "admin-key"}
	require.NoError(t, collRepo.Create(ctx, collAdmin))

	// Admin adds User A's wallet (should be allowed)
	body, _ := json.Marshal(addMemberRequest{WalletID: walletA})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/collections/"+collAdmin.ID+"/members", bytes.NewReader(body))

	adminKey := &types.APIKey{ID: "admin-key", Name: "Admin", Role: types.RoleAdmin, Enabled: true}
	reqCtx := context.WithValue(req.Context(), middleware.APIKeyContextKey, adminKey)
	req = req.WithContext(reqCtx)

	rr := httptest.NewRecorder()
	handler.addMember(rr, req, collAdmin.ID)

	assert.Equal(t, http.StatusCreated, rr.Code, "admin should bypass ownership check")
}
