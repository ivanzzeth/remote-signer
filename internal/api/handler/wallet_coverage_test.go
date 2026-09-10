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
//
// ⚠️ Everything left in this file calls an *unexported* method of WalletHandler
// (createWallet, listWallets, updateWallet, deleteWallet, listMembers,
// addMember, removeMember) with the arguments the dispatcher would have parsed
// out of the path. They were never route tests: they bypass the mux and
// ServeWalletHTTP's own path splitting alike, which is exactly how they reach an
// error branch that a request cannot reach on its own (a closed database, an
// already-resolved *types.Wallet). Routing them through a mux is not something
// that could be done to them, so step S2 did not: only unexported access keeps
// them able to test what they test, and unexported access is what
// `package handler` is.
//
// The ten tests that did go through ServeHTTP / ServeWalletHTTP moved to
// wallet_route_coverage_test.go, in `package handler_test`, where they reach the
// handler through the production route registration. See wallet_routes_test.go
// for why the package boundary is where it is.
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

	body, _ := json.Marshal(CreateWalletRequest{Name: "Test Wallet"})
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
	body, _ := json.Marshal(UpdateWalletRequest{Name: &name})
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
	body, _ := json.Marshal(AddMemberRequest{SignerAddress: "0x1234567890abcdef1234567890abcdef12345678"})
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

	body, _ := json.Marshal(AddMemberRequest{SignerAddress: ""})
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

	body, _ := json.Marshal(AddMemberRequest{SignerAddress: "0x1234567890abcdef1234567890abcdef12345678"})
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

	body, _ := json.Marshal(CreateWalletRequest{Name: ""})
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

	body, _ := json.Marshal(CreateWalletRequest{Name: "Test"})
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
	body, _ := json.Marshal(UpdateWalletRequest{Name: &emptyName})
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/wallets/some-id", bytes.NewReader(body))
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	handler.updateWallet(w, req, &types.Wallet{Name: "Test", OwnerID: "admin"})

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "name cannot be empty")
}
