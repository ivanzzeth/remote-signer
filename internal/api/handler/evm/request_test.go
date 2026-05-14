package evm

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// --- Helpers ---

func doRequestHandlerReq(t *testing.T, handler http.Handler, method, path string, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func reqAdminKey() *types.APIKey {
	return &types.APIKey{ID: "admin-key", Name: "Admin", Role: types.RoleAdmin, Enabled: true}
}

func makeSignRequest(id string, status types.SignRequestStatus) *types.SignRequest {
	return &types.SignRequest{
		ID:            types.SignRequestID(id),
		APIKeyID:      "admin-key",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0x1111111111111111111111111111111111111111",
		SignType:      "transaction",
		Status:        status,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

// --- RequestHandler constructor ---

func TestNewRequestHandler(t *testing.T) {
	t.Run("nil_sign_service", func(t *testing.T) {
		_, err := NewRequestHandler(nil, newMockRuleRepo(), slog.Default())
		require.Error(t, err)
	})

	t.Run("nil_rule_repo", func(t *testing.T) {
		_, err := NewRequestHandler(&mockSignService{}, nil, slog.Default())
		require.Error(t, err)
	})

	t.Run("nil_logger", func(t *testing.T) {
		_, err := NewRequestHandler(&mockSignService{}, newMockRuleRepo(), nil)
		require.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		h, err := NewRequestHandler(&mockSignService{}, newMockRuleRepo(), slog.Default())
		require.NoError(t, err)
		assert.NotNil(t, h)
	})
}

// --- RequestHandler ServeHTTP ---

func TestRequestHandler_Unauthorized(t *testing.T) {
	h, _ := NewRequestHandler(&mockSignService{}, newMockRuleRepo(), slog.Default())
	rec := doRequestHandlerReq(t, h, http.MethodGet, "/api/v1/evm/requests/req-001", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequestHandler_MethodNotAllowed(t *testing.T) {
	h, _ := NewRequestHandler(&mockSignService{}, newMockRuleRepo(), slog.Default())
	rec := doRequestHandlerReq(t, h, http.MethodPost, "/api/v1/evm/requests/req-001", reqAdminKey())
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestRequestHandler_GetSuccess(t *testing.T) {
	signReq := makeSignRequest("req-001", types.StatusCompleted)
	svc := &mockSignService{
		getRequestFn: func(_ context.Context, id types.SignRequestID) (*types.SignRequest, error) {
			if id == "req-001" {
				return signReq, nil
			}
			return nil, types.ErrNotFound
		},
	}
	h, _ := NewRequestHandler(svc, newMockRuleRepo(), slog.Default())
	rec := doRequestHandlerReq(t, h, http.MethodGet, "/api/v1/evm/requests/req-001", reqAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp RequestDetailResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "req-001", resp.ID)
}

func TestRequestHandler_NotFound(t *testing.T) {
	svc := &mockSignService{} // getRequestFn returns ErrNotFound by default
	h, _ := NewRequestHandler(svc, newMockRuleRepo(), slog.Default())
	rec := doRequestHandlerReq(t, h, http.MethodGet, "/api/v1/evm/requests/nonexistent", reqAdminKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// --- ListHandler constructor ---

func TestNewListHandler(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		h, err := NewListHandler(&mockSignService{}, newMockRuleRepo(), slog.Default())
		require.NoError(t, err)
		assert.NotNil(t, h)
	})
}

// --- ListHandler ServeHTTP ---

func TestListHandler_Unauthorized(t *testing.T) {
	h, _ := NewListHandler(&mockSignService{}, newMockRuleRepo(), slog.Default())
	rec := doRequestHandlerReq(t, h, http.MethodGet, "/api/v1/evm/requests", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestListHandler_MethodNotAllowed(t *testing.T) {
	h, _ := NewListHandler(&mockSignService{}, newMockRuleRepo(), slog.Default())
	rec := doRequestHandlerReq(t, h, http.MethodPost, "/api/v1/evm/requests", reqAdminKey())
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestListHandler_Success(t *testing.T) {
	svc := &mockSignService{
		countRequestsFn: func(_ context.Context, _ storage.RequestFilter) (int, error) {
			return 2, nil
		},
		listRequestsFn: func(_ context.Context, _ storage.RequestFilter) ([]*types.SignRequest, error) {
			return []*types.SignRequest{
				makeSignRequest("req-001", types.StatusCompleted),
				makeSignRequest("req-002", types.StatusRejected),
			}, nil
		},
	}
	h, _ := NewListHandler(svc, newMockRuleRepo(), slog.Default())
	rec := doRequestHandlerReq(t, h, http.MethodGet, "/api/v1/evm/requests", reqAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ListRequestsResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 2, resp.Total)
	assert.Len(t, resp.Requests, 2)
}

func TestListHandler_EmptyResults(t *testing.T) {
	svc := &mockSignService{}
	h, _ := NewListHandler(svc, newMockRuleRepo(), slog.Default())
	rec := doRequestHandlerReq(t, h, http.MethodGet, "/api/v1/evm/requests", reqAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}
