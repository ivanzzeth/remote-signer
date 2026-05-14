package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// --- Mock SignService ---

type mockSignService struct {
	signFn              func(ctx context.Context, req *service.SignRequest) (*service.SignResponse, error)
	getRequestFn        func(ctx context.Context, id types.SignRequestID) (*types.SignRequest, error)
	listRequestsFn      func(ctx context.Context, filter storage.RequestFilter) ([]*types.SignRequest, error)
	countRequestsFn     func(ctx context.Context, filter storage.RequestFilter) (int, error)
	processApprovalFn   func(ctx context.Context, requestID types.SignRequestID, req *service.ApprovalRequest) (*service.ApprovalResponse, error)
	previewRuleFn       func(ctx context.Context, requestID types.SignRequestID, opts *rule.RuleGenerateOptions) (*types.Rule, error)
}

func (m *mockSignService) Sign(ctx context.Context, req *service.SignRequest) (*service.SignResponse, error) {
	if m.signFn != nil {
		return m.signFn(ctx, req)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSignService) GetRequest(ctx context.Context, id types.SignRequestID) (*types.SignRequest, error) {
	if m.getRequestFn != nil {
		return m.getRequestFn(ctx, id)
	}
	return nil, types.ErrNotFound
}

func (m *mockSignService) ListRequests(ctx context.Context, filter storage.RequestFilter) ([]*types.SignRequest, error) {
	if m.listRequestsFn != nil {
		return m.listRequestsFn(ctx, filter)
	}
	return nil, nil
}

func (m *mockSignService) CountRequests(ctx context.Context, filter storage.RequestFilter) (int, error) {
	if m.countRequestsFn != nil {
		return m.countRequestsFn(ctx, filter)
	}
	return 0, nil
}

func (m *mockSignService) ProcessApproval(ctx context.Context, requestID types.SignRequestID, req *service.ApprovalRequest) (*service.ApprovalResponse, error) {
	if m.processApprovalFn != nil {
		return m.processApprovalFn(ctx, requestID, req)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockSignService) PreviewRuleForRequest(ctx context.Context, requestID types.SignRequestID, opts *rule.RuleGenerateOptions) (*types.Rule, error) {
	if m.previewRuleFn != nil {
		return m.previewRuleFn(ctx, requestID, opts)
	}
	return nil, fmt.Errorf("not implemented")
}

// --- Helpers ---

func doSignRequest(t *testing.T, h *SignHandler, method, path string, body interface{}, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Buffer
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		buf = bytes.NewBuffer(data)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func signAdminKey() *types.APIKey {
	return &types.APIKey{ID: "admin-key", Name: "Admin", Role: types.RoleAdmin, Enabled: true}
}

func newTestSignHandler(t *testing.T, svc service.SignServiceAPI) *SignHandler {
	t.Helper()
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignHandler(svc, nil, accessSvc, slog.Default())
	require.NoError(t, err)
	return h
}

// --- Constructor tests ---

func TestNewSignHandler(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)

	t.Run("nil_sign_service", func(t *testing.T) {
		_, err := NewSignHandler(nil, nil, accessSvc, slog.Default())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sign service is required")
	})

	t.Run("nil_access_service", func(t *testing.T) {
		_, err := NewSignHandler(&mockSignService{}, nil, nil, slog.Default())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access service is required")
	})

	t.Run("nil_logger", func(t *testing.T) {
		_, err := NewSignHandler(&mockSignService{}, nil, accessSvc, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("valid", func(t *testing.T) {
		h, err := NewSignHandler(&mockSignService{}, nil, accessSvc, slog.Default())
		require.NoError(t, err)
		assert.NotNil(t, h)
	})
}

// --- ServeHTTP tests ---

func TestSignHandler_MethodNotAllowed(t *testing.T) {
	h := newTestSignHandler(t, &mockSignService{})
	rec := doSignRequest(t, h, http.MethodGet, "/api/v1/evm/sign", nil, signAdminKey())
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestSignHandler_Unauthorized(t *testing.T) {
	h := newTestSignHandler(t, &mockSignService{})
	rec := doSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestSignHandler_InvalidBody(t *testing.T) {
	h := newTestSignHandler(t, &mockSignService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/sign", bytes.NewBufferString("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSignHandler_MissingChainID(t *testing.T) {
	h := newTestSignHandler(t, &mockSignService{})
	body := SignRequest{SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "transaction", Payload: json.RawMessage(`{}`)}
	rec := doSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "chain_id")
}

func TestSignHandler_InvalidChainID(t *testing.T) {
	h := newTestSignHandler(t, &mockSignService{})
	body := SignRequest{ChainID: "abc", SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "transaction", Payload: json.RawMessage(`{}`)}
	rec := doSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "chain_id")
}

func TestSignHandler_MissingSignerAddress(t *testing.T) {
	h := newTestSignHandler(t, &mockSignService{})
	body := SignRequest{ChainID: "1", SignType: "transaction", Payload: json.RawMessage(`{}`)}
	rec := doSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "signer_address")
}

func TestSignHandler_InvalidSignerAddress(t *testing.T) {
	h := newTestSignHandler(t, &mockSignService{})
	body := SignRequest{ChainID: "1", SignerAddress: "bad", SignType: "transaction", Payload: json.RawMessage(`{}`)}
	rec := doSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "signer_address")
}

func TestSignHandler_MissingSignType(t *testing.T) {
	h := newTestSignHandler(t, &mockSignService{})
	body := SignRequest{ChainID: "1", SignerAddress: "0x1111111111111111111111111111111111111111", Payload: json.RawMessage(`{}`)}
	rec := doSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "sign_type")
}

func TestSignHandler_InvalidSignType(t *testing.T) {
	h := newTestSignHandler(t, &mockSignService{})
	body := SignRequest{ChainID: "1", SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "invalid", Payload: json.RawMessage(`{}`)}
	rec := doSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "sign_type")
}

// Note: payload-too-large test skipped because JSON marshaling a >2MB payload
// in the test is impractical. This path is covered by e2e tests.

func TestSignHandler_AccessDenied(t *testing.T) {
	// accessService with no ownerships → CheckAccess returns false
	svc := &mockSignService{}
	h := newTestSignHandler(t, svc)
	body := SignRequest{
		ChainID:       "1",
		SignerAddress: "0x1111111111111111111111111111111111111111",
		SignType:      "transaction",
		Payload:       json.RawMessage(`{"to":"0x2222222222222222222222222222222222222222"}`),
	}
	rec := doSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign", body, signAdminKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "not authorized")
}

func TestSignHandler_SignSuccess(t *testing.T) {
	svc := &mockSignService{
		signFn: func(_ context.Context, req *service.SignRequest) (*service.SignResponse, error) {
			return &service.SignResponse{
				RequestID: "req-001",
				Status:    types.StatusCompleted,
				Signature: []byte{0xab, 0xcd},
			}, nil
		},
	}
	accessSvc := newFlexAccessService(t, map[string]string{
		"0x1111111111111111111111111111111111111111": "admin-key",
	})
	h, err := NewSignHandler(svc, nil, accessSvc, slog.Default())
	require.NoError(t, err)

	body := SignRequest{
		ChainID:       "1",
		SignerAddress: "0x1111111111111111111111111111111111111111",
		SignType:      "transaction",
		Payload:       json.RawMessage(`{"to":"0x2222222222222222222222222222222222222222"}`),
	}
	rec := doSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign", body, signAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp SignResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "req-001", resp.RequestID)
	assert.Equal(t, "completed", resp.Status)
	assert.Equal(t, "0xabcd", resp.Signature)
}

func TestSignHandler_SignServiceError(t *testing.T) {
	svc := &mockSignService{
		signFn: func(_ context.Context, _ *service.SignRequest) (*service.SignResponse, error) {
			return nil, fmt.Errorf("internal signing error")
		},
	}
	accessSvc := newFlexAccessService(t, map[string]string{
		"0x1111111111111111111111111111111111111111": "admin-key",
	})
	h, err := NewSignHandler(svc, nil, accessSvc, slog.Default())
	require.NoError(t, err)

	body := SignRequest{
		ChainID:       "1",
		SignerAddress: "0x1111111111111111111111111111111111111111",
		SignType:      "transaction",
		Payload:       json.RawMessage(`{"to":"0x2222222222222222222222222222222222222222"}`),
	}
	rec := doSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign", body, signAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}
