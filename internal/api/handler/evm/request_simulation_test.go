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

func newSimHandlerDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.SignRequest{}, &types.RequestSimulation{}))
	return db
}

func seedSimFixture(t *testing.T, db *gorm.DB) {
	t.Helper()
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)
	simRepo, err := storage.NewGormRequestSimulationRepository(db)
	require.NoError(t, err)
	ctx := context.Background()
	now := time.Now()
	require.NoError(t, reqRepo.Create(ctx, &types.SignRequest{
		ID: "req-alice", APIKeyID: "alice", ChainType: types.ChainTypeEVM,
		ChainID: "56", SignType: "transaction", Status: types.StatusAuthorizing,
		CreatedAt: now, UpdatedAt: now,
	}))
	require.NoError(t, reqRepo.Create(ctx, &types.SignRequest{
		ID: "req-bob", APIKeyID: "bob", ChainType: types.ChainTypeEVM,
		ChainID: "56", SignType: "transaction", Status: types.StatusAuthorizing,
		CreatedAt: now, UpdatedAt: now,
	}))
	require.NoError(t, simRepo.Upsert(ctx, &types.RequestSimulation{
		SignRequestID: "req-alice", ChainID: "56", Decision: "allow",
		Success: true, GasUsed: 21_000,
		SimulatedAt: now, UpdatedAt: now,
	}))
}

func doSimRequest(t *testing.T, h http.Handler, requestID string, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/evm/requests/"+requestID+"/simulation", nil)
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func newSimHandler(t *testing.T, db *gorm.DB) *RequestSimulationHandler {
	t.Helper()
	simRepo, err := storage.NewGormRequestSimulationRepository(db)
	require.NoError(t, err)
	reqRepo, err := storage.NewGormRequestRepository(db)
	require.NoError(t, err)
	h, err := NewRequestSimulationHandler(simRepo, reqRepo, slog.Default())
	require.NoError(t, err)
	return h
}

func TestRequestSimulationHandler_OwnerSeesSimulation(t *testing.T) {
	db := newSimHandlerDB(t)
	seedSimFixture(t, db)
	h := newSimHandler(t, db)

	alice := &types.APIKey{ID: "alice", Role: types.RoleAgent}
	rec := doSimRequest(t, h, "req-alice", alice)
	require.Equal(t, http.StatusOK, rec.Code)
	var sim types.RequestSimulation
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&sim))
	assert.Equal(t, "req-alice", sim.SignRequestID)
	assert.Equal(t, "allow", sim.Decision)
}

func TestRequestSimulationHandler_AdminSeesAnyOwners(t *testing.T) {
	db := newSimHandlerDB(t)
	seedSimFixture(t, db)
	h := newSimHandler(t, db)

	admin := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin}
	rec := doSimRequest(t, h, "req-alice", admin)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequestSimulationHandler_NonOwnerForeignRequest_404(t *testing.T) {
	// alice tries to fetch bob's request's simulation. Must be 404
	// not 403 — the response shape mustn't leak whether the id
	// exists at all under another key.
	db := newSimHandlerDB(t)
	seedSimFixture(t, db)
	h := newSimHandler(t, db)

	alice := &types.APIKey{ID: "alice", Role: types.RoleAgent}
	rec := doSimRequest(t, h, "req-bob", alice)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRequestSimulationHandler_NotYetSimulated_404(t *testing.T) {
	// bob has a request but no simulation row yet → 404 with the
	// "not yet available" message the UI uses to render the
	// "evaluating" spinner.
	db := newSimHandlerDB(t)
	seedSimFixture(t, db)
	h := newSimHandler(t, db)

	bob := &types.APIKey{ID: "bob", Role: types.RoleAgent}
	rec := doSimRequest(t, h, "req-bob", bob)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Contains(t, body["error"], "not yet available")
}

func TestRequestSimulationHandler_UnknownRequest_404(t *testing.T) {
	db := newSimHandlerDB(t)
	h := newSimHandler(t, db)
	admin := &types.APIKey{ID: "admin", Role: types.RoleAdmin}
	rec := doSimRequest(t, h, "no-such-request", admin)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestRequestSimulationHandler_Unauthorized(t *testing.T) {
	db := newSimHandlerDB(t)
	h := newSimHandler(t, db)
	rec := doSimRequest(t, h, "req-alice", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequestSimulationHandler_NonGET(t *testing.T) {
	db := newSimHandlerDB(t)
	h := newSimHandler(t, db)
	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/evm/requests/req-alice/simulation", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey,
		&types.APIKey{ID: "admin", Role: types.RoleAdmin}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}
