//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// Wallet error-path tests using in-memory SQLite
// ---------------------------------------------------------------------------

func setupWalletErrorHandlerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&types.Wallet{},
		&types.WalletMember{},
		&types.SignerOwnership{},
		&types.SignerAccess{},
	))
	return db
}

func walletAdminCtx(t *testing.T) context.Context {
	t.Helper()
	return context.WithValue(context.Background(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin, Enabled: true})
}

func TestWallet_createWallet_RepoError(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	// Close DB to simulate repo error
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.Close()

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	body, _ := json.Marshal(createWalletRequest{Name: "Test Wallet"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets", bytes.NewReader(body))
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.createWallet(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to create wallet")
}

func TestWallet_listWallets_RepoError(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.Close()

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.listWallets(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to list wallets")
}

func TestWallet_updateWallet_RepoError(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	defer sqlDB.Close()

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	// Create a wallet first
	ctx := context.Background()
	wallet := &types.Wallet{Name: "Existing Wallet", OwnerID: "admin"}
	require.NoError(t, collRepo.Create(ctx, wallet))

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	// Close DB to simulate repo error on update
	sqlDB.Close()

	name := "Updated Name"
	body, _ := json.Marshal(updateWalletRequest{Name: &name})
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/wallets/"+wallet.ID, bytes.NewReader(body))
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.updateWallet(w, req, wallet)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to update wallet")
}

func TestWallet_deleteWallet_NotFound(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/wallets/nonexistent-id", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.deleteWallet(w, req, "nonexistent-id")

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "wallet not found")
}

func TestWallet_deleteWallet_RepoError(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	// Create wallet
	wallet := &types.Wallet{Name: "To Delete", OwnerID: "admin"}
	require.NoError(t, collRepo.Create(context.Background(), wallet))

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	// Close DB to simulate error
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.Close()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/wallets/"+wallet.ID, nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.deleteWallet(w, req, wallet.ID)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to delete wallet")
}

func TestWallet_listMembers_RepoError(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	wallet := &types.Wallet{Name: "Test Wallet", OwnerID: "admin"}
	require.NoError(t, collRepo.Create(context.Background(), wallet))

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	// Close DB to simulate error
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/"+wallet.ID+"/members", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.listMembers(w, req, wallet.ID)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to list members")
}

func TestWallet_addMember_Unauthorized(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	// No API key in context
	body, _ := json.Marshal(addMemberRequest{SignerAddress: "0x1234567890abcdef1234567890abcdef12345678"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets/wallet-1/members", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.addMember(w, req, "wallet-1")

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestWallet_addMember_EmptySignerAddress(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	body, _ := json.Marshal(addMemberRequest{SignerAddress: ""})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets/wallet-1/members", bytes.NewReader(body))
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.addMember(w, req, "wallet-1")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "signer_address is required")
}

func TestWallet_addMember_RepoError(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	// Close DB to simulate error
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.Close()

	body, _ := json.Marshal(addMemberRequest{SignerAddress: "0x1234567890abcdef1234567890abcdef12345678"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets/wallet-1/members", bytes.NewReader(body))
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.addMember(w, req, "wallet-1")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to add member")
}

func TestWallet_removeMember_NotFound(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/wallets/wallet-1/members/0xdead", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.removeMember(w, req, "wallet-1", "0xdead")

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "member not found")
}

func TestWallet_removeMember_RepoError(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	wallet := &types.Wallet{Name: "Test Wallet", OwnerID: "admin"}
	require.NoError(t, collRepo.Create(context.Background(), wallet))

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	// Close DB to simulate error
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.Close()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/wallets/"+wallet.ID+"/members/0xdead", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.removeMember(w, req, wallet.ID, "0xdead")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "failed to remove member")
}

func TestWallet_ServeWalletHTTP_WalletNotFound(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/nonexistent", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeWalletHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "wallet not found")
}

func TestWallet_ServeWalletHTTP_RepoError(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.Close()

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/some-id", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeWalletHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestWallet_ServeWalletHTTP_NonAdminCannotAccessOthers(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	wallet := &types.Wallet{Name: "User A Wallet", OwnerID: "user-a"}
	require.NoError(t, collRepo.Create(context.Background(), wallet))

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	// User B (non-admin) tries to access User A's wallet
	apiKey := &types.APIKey{ID: "user-b", Role: types.RoleDev, Enabled: true}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/"+wallet.ID, nil)
	req = req.WithContext(context.WithValue(context.Background(), middleware.APIKeyContextKey, apiKey))
	w := httptest.NewRecorder()
	handler.ServeWalletHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWallet_createWallet_InvalidJSON(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets", bytes.NewReader([]byte("not-json")))
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.createWallet(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid request body")
}

func TestWallet_createWallet_EmptyName(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	body, _ := json.Marshal(createWalletRequest{Name: ""})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets", bytes.NewReader(body))
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.createWallet(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "name is required")
}

func TestWallet_createWallet_Unauthorized(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	body, _ := json.Marshal(createWalletRequest{Name: "Test"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.createWallet(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestWallet_updateWallet_InvalidJSON(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/wallets/some-id", bytes.NewReader([]byte("bad-json")))
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.updateWallet(w, req, &types.Wallet{Name: "Test", OwnerID: "admin"})

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid request body")
}

func TestWallet_updateWallet_EmptyName(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	emptyName := ""
	body, _ := json.Marshal(updateWalletRequest{Name: &emptyName})
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/wallets/some-id", bytes.NewReader(body))
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.updateWallet(w, req, &types.Wallet{Name: "Test", OwnerID: "admin"})

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "name cannot be empty")
}

func TestWallet_ServeHTTP_MethodNotAllowed(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/wallets", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestWallet_ServeWalletHTTP_NoID(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeWalletHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "wallet ID required")
}

func TestWallet_ServeWalletHTTP_UnauthorizedNoKey(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/some-id", nil)
	w := httptest.NewRecorder()
	handler.ServeWalletHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestWallet_ServeWalletHTTP_InvalidMemberMethod(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	wallet := &types.Wallet{Name: "Test", OwnerID: "admin"}
	require.NoError(t, collRepo.Create(context.Background(), wallet))

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	// PATCH on /members should be method not allowed (default case)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/wallets/"+wallet.ID+"/members", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeWalletHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestWallet_ServeWalletHTTP_InvalidMemberSignerMethod(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	wallet := &types.Wallet{Name: "Test", OwnerID: "admin"}
	require.NoError(t, collRepo.Create(context.Background(), wallet))

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	// POST on /members/{signer} should be method not allowed
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets/"+wallet.ID+"/members/0xdead", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeWalletHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestWallet_ServeWalletHTTP_InvalidPath(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	wallet := &types.Wallet{Name: "Test", OwnerID: "admin"}
	require.NoError(t, collRepo.Create(context.Background(), wallet))

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	// Unknown path after wallet ID
	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/"+wallet.ID+"/unknown", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeWalletHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWallet_ServeWalletHTTP_WalletMethodNotAllowed(t *testing.T) {
	db := setupWalletErrorHandlerTestDB(t)

	collRepo, err := storage.NewGormWalletRepository(db)
	require.NoError(t, err)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	wallet := &types.Wallet{Name: "Test", OwnerID: "admin"}
	require.NoError(t, collRepo.Create(context.Background(), wallet))

	handler, err := NewWalletHandler(collRepo, ownershipRepo, accessRepo, slog.Default())
	require.NoError(t, err)

	// POST on single wallet (without /members) should be not allowed
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets/"+wallet.ID, nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.ServeWalletHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}
