//go:build integration

package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

func newTxHandlerDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.Transaction{}, &types.SignRequest{}))
	return db
}

func seedTxFixture(t *testing.T, db *gorm.DB) (txAlice, txBob, txOrphan string) {
	t.Helper()
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)
	ctx := context.Background()
	now := time.Now()
	require.NoError(t, reqRepo.Create(ctx, &types.SignRequest{
		ID: "req-alice", APIKeyID: "alice", ChainType: types.ChainTypeEVM,
		ChainID: "1", Status: types.StatusCompleted, CreatedAt: now,
	}))
	require.NoError(t, reqRepo.Create(ctx, &types.SignRequest{
		ID: "req-bob", APIKeyID: "bob", ChainType: types.ChainTypeEVM,
		ChainID: "1", Status: types.StatusCompleted, CreatedAt: now,
	}))
	require.NoError(t, txRepo.Create(ctx, &types.Transaction{
		ID: "tx-alice", SignRequestID: "req-alice", ChainID: "1",
		TxHash: "0xa", Status: types.TxStatusMined, BroadcastedAt: now,
	}))
	require.NoError(t, txRepo.Create(ctx, &types.Transaction{
		ID: "tx-bob", SignRequestID: "req-bob", ChainID: "1",
		TxHash: "0xb", Status: types.TxStatusBroadcasted, BroadcastedAt: now,
	}))
	require.NoError(t, txRepo.Create(ctx, &types.Transaction{
		ID: "tx-orphan", ChainID: "1", TxHash: "0xc",
		Status: types.TxStatusBroadcasted, BroadcastedAt: now,
	}))
	return "tx-alice", "tx-bob", "tx-orphan"
}

func doTxRequest(t *testing.T, h http.Handler, method, path string, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestTransactionsHandler_List_AdminSeesAll(t *testing.T) {
	db := newTxHandlerDB(t)
	_, _, _ = seedTxFixture(t, db)
	repo, _ := storage.NewGormTransactionRepository(db)
	h, err := NewTransactionsHandler(repo, slog.Default())
	require.NoError(t, err)

	admin := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	rec := doTxRequest(t, h, http.MethodGet, "/api/v1/evm/transactions", admin)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp TransactionsListResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 3, resp.Total)
	assert.Len(t, resp.Transactions, 3)
}

func TestTransactionsHandler_List_NonAdminSeesOnlyOwn(t *testing.T) {
	db := newTxHandlerDB(t)
	_, _, _ = seedTxFixture(t, db)
	repo, _ := storage.NewGormTransactionRepository(db)
	h, err := NewTransactionsHandler(repo, slog.Default())
	require.NoError(t, err)

	alice := &types.APIKey{ID: "alice", Role: types.RoleAgent}
	rec := doTxRequest(t, h, http.MethodGet, "/api/v1/evm/transactions", alice)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp TransactionsListResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Transactions, 1)
	assert.Equal(t, "tx-alice", resp.Transactions[0].ID)
}

func TestTransactionsHandler_List_NonAdminCrossKey_403(t *testing.T) {
	db := newTxHandlerDB(t)
	_, _, _ = seedTxFixture(t, db)
	repo, _ := storage.NewGormTransactionRepository(db)
	h, err := NewTransactionsHandler(repo, slog.Default())
	require.NoError(t, err)

	alice := &types.APIKey{ID: "alice", Role: types.RoleAgent}
	// alice tries to peek at bob's txs by hand-rolling api_key_id
	// in the query string. Must 403 — the visibility gate has to
	// pin the value server-side regardless of client input.
	rec := doTxRequest(t, h, http.MethodGet,
		"/api/v1/evm/transactions?api_key_id=bob", alice)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestTransactionsHandler_List_AdminFiltersByAPIKey(t *testing.T) {
	db := newTxHandlerDB(t)
	_, _, _ = seedTxFixture(t, db)
	repo, _ := storage.NewGormTransactionRepository(db)
	h, err := NewTransactionsHandler(repo, slog.Default())
	require.NoError(t, err)

	admin := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	rec := doTxRequest(t, h, http.MethodGet,
		"/api/v1/evm/transactions?api_key_id=bob", admin)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp TransactionsListResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Transactions, 1)
	assert.Equal(t, "tx-bob", resp.Transactions[0].ID)
}

func TestTransactionsHandler_List_FilterStatus(t *testing.T) {
	db := newTxHandlerDB(t)
	_, _, _ = seedTxFixture(t, db)
	repo, _ := storage.NewGormTransactionRepository(db)
	h, err := NewTransactionsHandler(repo, slog.Default())
	require.NoError(t, err)

	admin := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	rec := doTxRequest(t, h, http.MethodGet,
		"/api/v1/evm/transactions?status=broadcasted", admin)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp TransactionsListResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 2, resp.Total) // tx-bob + tx-orphan
}

func TestTransactionsHandler_Get_Admin(t *testing.T) {
	db := newTxHandlerDB(t)
	alice, _, _ := seedTxFixture(t, db)
	repo, _ := storage.NewGormTransactionRepository(db)
	h, err := NewTransactionsHandler(repo, slog.Default())
	require.NoError(t, err)

	admin := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	rec := doTxRequest(t, h, http.MethodGet, "/api/v1/evm/transactions/"+alice, admin)
	require.Equal(t, http.StatusOK, rec.Code)
	var got types.Transaction
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	assert.Equal(t, "tx-alice", got.ID)
}

func TestTransactionsHandler_Get_NonAdminForeignTx_404(t *testing.T) {
	// alice tries to fetch tx-bob by id — must come back as 404,
	// not 403, so a probing attacker can't infer which tx ids
	// exist in another key's set.
	db := newTxHandlerDB(t)
	_, bob, _ := seedTxFixture(t, db)
	repo, _ := storage.NewGormTransactionRepository(db)
	h, err := NewTransactionsHandler(repo, slog.Default())
	require.NoError(t, err)

	alice := &types.APIKey{ID: "alice", Role: types.RoleAgent}
	rec := doTxRequest(t, h, http.MethodGet, "/api/v1/evm/transactions/"+bob, alice)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestTransactionsHandler_Get_UnknownID_404(t *testing.T) {
	db := newTxHandlerDB(t)
	repo, _ := storage.NewGormTransactionRepository(db)
	h, err := NewTransactionsHandler(repo, slog.Default())
	require.NoError(t, err)

	admin := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	rec := doTxRequest(t, h, http.MethodGet, "/api/v1/evm/transactions/no-such-tx", admin)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestTransactionsHandler_Unauthorized(t *testing.T) {
	db := newTxHandlerDB(t)
	repo, _ := storage.NewGormTransactionRepository(db)
	h, err := NewTransactionsHandler(repo, slog.Default())
	require.NoError(t, err)
	rec := doTxRequest(t, h, http.MethodGet, "/api/v1/evm/transactions", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestTransactionsHandler_NonGET(t *testing.T) {
	db := newTxHandlerDB(t)
	repo, _ := storage.NewGormTransactionRepository(db)
	h, err := NewTransactionsHandler(repo, slog.Default())
	require.NoError(t, err)
	admin := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	rec := doTxRequest(t, h, http.MethodPost, "/api/v1/evm/transactions", admin)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}
