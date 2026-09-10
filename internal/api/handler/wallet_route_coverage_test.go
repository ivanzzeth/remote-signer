//go:build integration

package handler_test

// The wallet tests that reach the handler through its HTTP entry points, moved
// out of wallet_coverage_test.go by step S2 so that they arrive there through
// the production route registration instead of a direct call. Bodies and
// assertions are unchanged; what changed is the first hop. See
// wallet_routes_test.go for the harness and for what this does and does not
// prove.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func walletAdminCtx(t *testing.T) context.Context {
	t.Helper()
	return context.WithValue(context.Background(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin, Enabled: true})
}

func TestWallet_ServeWalletHTTP_WalletNotFound(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/nonexistent", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "wallet not found")
}

func TestWallet_ServeWalletHTTP_RepoError(t *testing.T) {
	db := walletTestDB(t)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.Close()

	repo, ownershipRepo, accessRepo := walletRepos(t, db)
	mux := walletMux(t, repo, ownershipRepo, accessRepo)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/some-id", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestWallet_ServeWalletHTTP_NonAdminCannotAccessOthers(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)

	wallet := &types.Wallet{Name: "User A Wallet", OwnerID: "user-a"}
	require.NoError(t, repo.Create(context.Background(), wallet))

	// User B (non-admin) tries to access User A's wallet
	apiKey := &types.APIKey{ID: "user-b", Role: types.RoleDev, Enabled: true}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/"+wallet.ID, nil)
	req = req.WithContext(context.WithValue(context.Background(), middleware.APIKeyContextKey, apiKey))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWallet_ServeHTTP_MethodNotAllowed(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/wallets", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestWallet_ServeWalletHTTP_NoID(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "wallet ID required")
}

func TestWallet_ServeWalletHTTP_UnauthorizedNoKey(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/some-id", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestWallet_ServeWalletHTTP_InvalidMemberMethod(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)

	wallet := &types.Wallet{Name: "Test", OwnerID: "admin"}
	require.NoError(t, repo.Create(context.Background(), wallet))

	// PATCH on /members should be method not allowed (default case)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/wallets/"+wallet.ID+"/members", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestWallet_ServeWalletHTTP_InvalidMemberSignerMethod(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)

	wallet := &types.Wallet{Name: "Test", OwnerID: "admin"}
	require.NoError(t, repo.Create(context.Background(), wallet))

	// POST on /members/{signer} should be method not allowed
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets/"+wallet.ID+"/members/0xdead", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestWallet_ServeWalletHTTP_InvalidPath(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)

	wallet := &types.Wallet{Name: "Test", OwnerID: "admin"}
	require.NoError(t, repo.Create(context.Background(), wallet))

	// Unknown path after wallet ID
	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/"+wallet.ID+"/unknown", nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWallet_ServeWalletHTTP_WalletMethodNotAllowed(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)

	wallet := &types.Wallet{Name: "Test", OwnerID: "admin"}
	require.NoError(t, repo.Create(context.Background(), wallet))

	// POST on single wallet (without /members) should be not allowed
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets/"+wallet.ID, nil)
	req = req.WithContext(walletAdminCtx(t))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}
