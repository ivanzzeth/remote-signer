//go:build integration

package handler_test

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
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/api/handler"
	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// walletMuxWithDB is the fixture every test in this file uses. It returns the
// production wallet routes over a mux, the repository (for arranging state that
// the routes are not the subject of), and the database (for the two tests that
// insert a member row directly).
//
// ⚠️ It returns a mux and not a *handler.WalletHandler on purpose: reaching the
// handler is what the mux is for, and handing out the handler as well would put
// the direct-dispatch shortcut back within reach of the next test written here.
func walletMuxWithDB(t *testing.T) (http.Handler, storage.WalletRepository, *gorm.DB) {
	t.Helper()
	db := walletTestDB(t)
	repo, ownershipRepo, accessRepo := walletRepos(t, db)
	return walletMux(t, repo, ownershipRepo, accessRepo), repo, db
}

func walletCtx(keyID, role string) context.Context {
	return context.WithValue(context.Background(), middleware.APIKeyContextKey,
		&types.APIKey{ID: keyID, Role: types.APIKeyRole(role)})
}

func TestNewWalletHandler_NilRepo(t *testing.T) {
	_, err := handler.NewWalletHandler(nil, nil, nil, slog.Default())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "wallet repository is required")
}

func TestNewWalletHandler_NilLogger(t *testing.T) {
	_, err := handler.NewWalletHandler(&mockWalletRepo{}, nil, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

// minimal mock for constructor test
type mockWalletRepo struct{}

func (m *mockWalletRepo) Create(_ context.Context, _ *types.Wallet) error        { return nil }
func (m *mockWalletRepo) Get(_ context.Context, _ string) (*types.Wallet, error) { return nil, nil }
func (m *mockWalletRepo) List(_ context.Context, _ types.WalletFilter) (*types.WalletListResult, error) {
	return nil, nil
}
func (m *mockWalletRepo) Update(_ context.Context, _ *types.Wallet) error          { return nil }
func (m *mockWalletRepo) Delete(_ context.Context, _ string) error                 { return nil }
func (m *mockWalletRepo) AddMember(_ context.Context, _ *types.WalletMember) error { return nil }
func (m *mockWalletRepo) RemoveMember(_ context.Context, _, _ string) error        { return nil }
func (m *mockWalletRepo) ListMembers(_ context.Context, _ string) ([]types.WalletMember, error) {
	return nil, nil
}
func (m *mockWalletRepo) IsMember(_ context.Context, _, _ string) (bool, error) { return false, nil }
func (m *mockWalletRepo) GetWalletsForSigner(_ context.Context, _ string) ([]types.Wallet, error) {
	return nil, nil
}
func (m *mockWalletRepo) GetWalletsForSigners(_ context.Context, _ []string) (map[string][]types.Wallet, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// /api/v1/wallets — list / create routing
// ---------------------------------------------------------------------------

func TestWalletHandler_ServeHTTP_List(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets", nil)
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWalletHandler_ServeHTTP_Create(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)
	body := `{"name": "test wallet"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(walletCtx("creator", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	var resp walletWire
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "test wallet", resp.Name)
	assert.Equal(t, "creator", resp.OwnerID)
	assert.NotEmpty(t, resp.ID)
}

func TestWalletHandler_ServeHTTP_MethodNotAllowed(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/wallets", nil)
			req = req.WithContext(walletCtx("admin", string(types.RoleAdmin)))
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
		})
	}
}

// ---------------------------------------------------------------------------
// createWallet error paths
// ---------------------------------------------------------------------------

func TestWalletHandler_CreateWallet_NoAPIKey(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)
	body := `{"name": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestWalletHandler_CreateWallet_InvalidBody(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets", bytes.NewReader([]byte(`{invalid`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(walletCtx("user", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWalletHandler_CreateWallet_EmptyName(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)
	body := `{"name": ""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(walletCtx("user", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// listWallets
// ---------------------------------------------------------------------------

func TestWalletHandler_ListWallets_NoAPIKey(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestWalletHandler_ListWallets_WithPagination(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)
	// Create wallets
	for i := 0; i < 3; i++ {
		body := bytes.NewReader([]byte(`{"name": "w` + string(rune('0'+i)) + `"}`))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets", body)
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(walletCtx("user", string(types.RoleDev)))
		mux.ServeHTTP(httptest.NewRecorder(), req)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets?offset=0&limit=10", nil)
	req = req.WithContext(walletCtx("user", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp walletListWire
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp.Wallets, 3)
	assert.Equal(t, 3, resp.Total)
}

// ---------------------------------------------------------------------------
// /api/v1/wallets/{id} and below
// ---------------------------------------------------------------------------

func TestWalletHandler_ServeWalletHTTP_GetWallet(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	ctx := context.Background()

	// Create a wallet
	wallet := &types.Wallet{Name: "my wallet", OwnerID: "user-1"}
	err := repo.Create(ctx, wallet)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/"+wallet.ID, nil)
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWalletHandler_ServeWalletHTTP_NotFound(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/no-such-id", nil)
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestWalletHandler_ServeWalletHTTP_NoWalletID asserted 400 before S3, for the
// reason spelled out on TestWallet_ServeWalletHTTP_NoID in
// wallet_route_coverage_test.go: the bare "/api/v1/wallets/" was a prefix
// pattern and reached the handler's own "wallet ID required" guard. No pattern
// claims it now.
func TestWalletHandler_ServeWalletHTTP_NoWalletID(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/", nil)
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.NotContains(t, w.Body.String(), "wallet ID required")
}

func TestWalletHandler_ServeWalletHTTP_NoAPIKey(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/some-id", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestWalletHandler_ServeWalletHTTP_NotOwner(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "owners wallet", OwnerID: "owner-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/"+wallet.ID, nil)
	req = req.WithContext(walletCtx("other-user", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWalletHandler_ServeWalletHTTP_UpdateWallet(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "original", OwnerID: "user-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	body := bytes.NewReader([]byte(`{"name": "updated"}`))
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/wallets/"+wallet.ID, body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWalletHandler_ServeWalletHTTP_UpdateWallet_EmptyName(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "original", OwnerID: "user-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	body := bytes.NewReader([]byte(`{"name": ""}`))
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/wallets/"+wallet.ID, body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWalletHandler_ServeWalletHTTP_InvalidUpdateBody(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "original", OwnerID: "user-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	body := bytes.NewReader([]byte(`{invalid`))
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/wallets/"+wallet.ID, body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWalletHandler_ServeWalletHTTP_DeleteWallet(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "delete-me", OwnerID: "user-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/wallets/"+wallet.ID, nil)
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestWalletHandler_ServeWalletHTTP_DeleteNotFound(t *testing.T) {
	mux, _, _ := walletMuxWithDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/wallets/no-such-id", nil)
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWalletHandler_ServeWalletHTTP_MethodNotAllowedOnWallet(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "w", OwnerID: "user-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets/"+wallet.ID, nil)
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// ---------------------------------------------------------------------------
// Member operations
// ---------------------------------------------------------------------------

func TestWalletHandler_ServeWalletHTTP_ListMembers(t *testing.T) {
	mux, repo, db := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "w", OwnerID: "user-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	// Add a member directly
	member := &types.WalletMember{WalletID: wallet.ID, SignerAddress: "0x123"}
	require.NoError(t, db.Create(member).Error)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/"+wallet.ID+"/members", nil)
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWalletHandler_ServeWalletHTTP_ListMembers_NoMembers(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "empty", OwnerID: "user-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/"+wallet.ID+"/members", nil)
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp membersListWire
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Empty(t, resp.Members)
}

func TestWalletHandler_ServeWalletHTTP_AddMember(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "w", OwnerID: "admin-key"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	body := bytes.NewReader([]byte(`{"signer_address": "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets/"+wallet.ID+"/members", body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(walletCtx("admin-key", string(types.RoleAdmin)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestWalletHandler_ServeWalletHTTP_RemoveMember(t *testing.T) {
	mux, repo, db := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "w", OwnerID: "user-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	member := &types.WalletMember{WalletID: wallet.ID, SignerAddress: "0x123"}
	require.NoError(t, db.Create(member).Error)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/wallets/"+wallet.ID+"/members/0x123", nil)
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestWalletHandler_ServeWalletHTTP_RemoveMember_NotFound(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "w", OwnerID: "user-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/wallets/"+wallet.ID+"/members/0x999", nil)
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestWalletHandler_ServeWalletHTTP_MemberWrongPath(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "w", OwnerID: "user-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets/"+wallet.ID+"/unknown", nil)
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---------------------------------------------------------------------------
// Admin can see all wallets
// ---------------------------------------------------------------------------

func TestWalletHandler_ListWallets_Admin(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	// Create wallets for 2 users
	for _, owner := range []string{"u1", "u2"} {
		wallet := &types.Wallet{Name: "w-" + owner, OwnerID: owner}
		require.NoError(t, repo.Create(context.Background(), wallet))
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets", nil)
	req = req.WithContext(walletCtx("admin", string(types.RoleAdmin)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp walletListWire
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Total)
}

func TestWalletHandler_ListWallets_AdminFilterByOwner(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	for _, owner := range []string{"u1", "u2"} {
		wallet := &types.Wallet{Name: "w-" + owner, OwnerID: owner}
		require.NoError(t, repo.Create(context.Background(), wallet))
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallets?owner_id=u1", nil)
	req = req.WithContext(walletCtx("admin", string(types.RoleAdmin)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp walletListWire
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, 1, resp.Total)
}

// ---------------------------------------------------------------------------
// Update wallet with description
// ---------------------------------------------------------------------------

func TestWalletHandler_UpdateWallet_Description(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "test", OwnerID: "user-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	body := bytes.NewReader([]byte(`{"description": "new desc"}`))
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/wallets/"+wallet.ID, body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp walletWire
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "new desc", resp.Description)
}

// ---------------------------------------------------------------------------
// addMember error paths
// ---------------------------------------------------------------------------

func TestWalletHandler_AddMember_MissingSignerAddress(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "w", OwnerID: "user-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	body := bytes.NewReader([]byte(`{"signer_address": ""}`))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets/"+wallet.ID+"/members", body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWalletHandler_AddMember_InvalidBody(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "w", OwnerID: "user-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets/"+wallet.ID+"/members", bytes.NewReader([]byte(`{bad`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(walletCtx("user-1", string(types.RoleDev)))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWalletHandler_AddMember_NoAPIKey(t *testing.T) {
	mux, repo, _ := walletMuxWithDB(t)
	wallet := &types.Wallet{Name: "w", OwnerID: "user-1"}
	err := repo.Create(context.Background(), wallet)
	require.NoError(t, err)

	body := bytes.NewReader([]byte(`{"signer_address": "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallets/"+wallet.ID+"/members", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
