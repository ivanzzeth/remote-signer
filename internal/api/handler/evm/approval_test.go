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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// --- Helpers ---

func doApprovalRequest(t *testing.T, h http.Handler, method, path string, body interface{}, apiKey *types.APIKey) *httptest.ResponseRecorder {
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

func approvalAdminKey() *types.APIKey {
	return &types.APIKey{ID: "owner-key", Name: "Owner", Role: types.RoleAdmin, Enabled: true}
}

func approvalOtherKey() *types.APIKey {
	return &types.APIKey{ID: "other-key", Name: "Other", Role: types.RoleAdmin, Enabled: true}
}

func pendingSignRequest() *types.SignRequest {
	return &types.SignRequest{
		ID:            "req-pending-001",
		APIKeyID:      "owner-key",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0x1111111111111111111111111111111111111111",
		SignType:      "transaction",
		Status:        types.StatusAuthorizing,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

// --- ApprovalHandler constructor ---

func TestNewApprovalHandler(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)

	t.Run("nil_sign_service", func(t *testing.T) {
		_, err := NewApprovalHandler(nil, accessSvc, slog.Default(), false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sign service is required")
	})

	t.Run("nil_access_service", func(t *testing.T) {
		_, err := NewApprovalHandler(&mockSignService{}, nil, slog.Default(), false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access service is required")
	})

	t.Run("nil_logger", func(t *testing.T) {
		_, err := NewApprovalHandler(&mockSignService{}, accessSvc, nil, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "logger is required")
	})

	t.Run("valid", func(t *testing.T) {
		h, err := NewApprovalHandler(&mockSignService{}, accessSvc, slog.Default(), false)
		require.NoError(t, err)
		assert.NotNil(t, h)
	})
}

// --- ApprovalHandler ServeHTTP ---

func TestApprovalHandler_MethodNotAllowed(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, _ := NewApprovalHandler(&mockSignService{}, accessSvc, slog.Default(), false)
	rec := doApprovalRequest(t, h, http.MethodGet, "/api/v1/evm/requests/req-001/approve", nil, approvalAdminKey())
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestApprovalHandler_Unauthorized(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, _ := NewApprovalHandler(&mockSignService{}, accessSvc, slog.Default(), false)
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/req-001/approve", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestApprovalHandler_InvalidBody(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, _ := NewApprovalHandler(&mockSignService{}, accessSvc, slog.Default(), false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/requests/req-001/approve", bytes.NewBufferString("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, approvalAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestApprovalHandler_RequestNotFound(t *testing.T) {
	svc := &mockSignService{} // getRequestFn returns ErrNotFound by default
	accessSvc := newSignerTestAccessService(t)
	h, _ := NewApprovalHandler(svc, accessSvc, slog.Default(), false)

	body := ApprovalAPIRequest{Approved: true}
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/nonexistent/approve", body, approvalAdminKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestApprovalHandler_NotOwner(t *testing.T) {
	signReq := pendingSignRequest()
	svc := &mockSignService{
		getRequestFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
			return signReq, nil
		},
	}
	// Signer owned by "owner-key", but caller is "other-key"
	accessSvc := newFlexAccessService(t, map[string]string{
		"0x1111111111111111111111111111111111111111": "owner-key",
	})
	h, _ := NewApprovalHandler(svc, accessSvc, slog.Default(), false)

	body := ApprovalAPIRequest{Approved: true}
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/req-pending-001/approve", body, approvalOtherKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "signer owner")
}

func TestApprovalHandler_Approve_Success(t *testing.T) {
	signReq := pendingSignRequest()
	svc := &mockSignService{
		getRequestFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
			return signReq, nil
		},
		processApprovalFn: func(_ context.Context, _ types.SignRequestID, req *service.ApprovalRequest) (*service.ApprovalResponse, error) {
			assert.True(t, req.Approved)
			return &service.ApprovalResponse{
				SignResponse: &service.SignResponse{
					RequestID: "req-pending-001",
					Status:    types.StatusCompleted,
					Signature: []byte{0xde, 0xad},
				},
			}, nil
		},
	}
	accessSvc := newFlexAccessService(t, map[string]string{
		"0x1111111111111111111111111111111111111111": "owner-key",
	})
	h, _ := NewApprovalHandler(svc, accessSvc, slog.Default(), false)

	body := ApprovalAPIRequest{Approved: true}
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/req-pending-001/approve", body, approvalAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ApprovalAPIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "req-pending-001", resp.RequestID)
	assert.Equal(t, "completed", resp.Status)
	assert.Equal(t, "0xdead", resp.Signature)
}

func TestApprovalHandler_Reject_Success(t *testing.T) {
	signReq := pendingSignRequest()
	svc := &mockSignService{
		getRequestFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
			return signReq, nil
		},
		processApprovalFn: func(_ context.Context, _ types.SignRequestID, req *service.ApprovalRequest) (*service.ApprovalResponse, error) {
			assert.False(t, req.Approved)
			return &service.ApprovalResponse{
				SignResponse: &service.SignResponse{
					RequestID: "req-pending-001",
					Status:    types.StatusRejected,
					Message:   "rejected by owner",
				},
			}, nil
		},
	}
	accessSvc := newFlexAccessService(t, map[string]string{
		"0x1111111111111111111111111111111111111111": "owner-key",
	})
	h, _ := NewApprovalHandler(svc, accessSvc, slog.Default(), false)

	body := ApprovalAPIRequest{Approved: false}
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/req-pending-001/approve", body, approvalAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ApprovalAPIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "rejected", resp.Status)
}

func TestApprovalHandler_ProcessError(t *testing.T) {
	signReq := pendingSignRequest()
	svc := &mockSignService{
		getRequestFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
			return signReq, nil
		},
		processApprovalFn: func(_ context.Context, _ types.SignRequestID, _ *service.ApprovalRequest) (*service.ApprovalResponse, error) {
			return nil, fmt.Errorf("state machine error")
		},
	}
	accessSvc := newFlexAccessService(t, map[string]string{
		"0x1111111111111111111111111111111111111111": "owner-key",
	})
	h, _ := NewApprovalHandler(svc, accessSvc, slog.Default(), false)

	body := ApprovalAPIRequest{Approved: true}
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/req-pending-001/approve", body, approvalAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestApprovalHandler_RulesReadOnly_BlocksAutoRule(t *testing.T) {
	signReq := pendingSignRequest()
	svc := &mockSignService{
		getRequestFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
			return signReq, nil
		},
	}
	accessSvc := newFlexAccessService(t, map[string]string{
		"0x1111111111111111111111111111111111111111": "owner-key",
	})
	h, _ := NewApprovalHandler(svc, accessSvc, slog.Default(), true) // rulesReadOnly=true

	body := ApprovalAPIRequest{Approved: true, RuleType: "evm_address_list", RuleMode: "whitelist"}
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/req-pending-001/approve", body, approvalAdminKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "readonly")
}

func TestApprovalHandler_InvalidRuleType(t *testing.T) {
	signReq := pendingSignRequest()
	svc := &mockSignService{
		getRequestFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
			return signReq, nil
		},
	}
	accessSvc := newFlexAccessService(t, map[string]string{
		"0x1111111111111111111111111111111111111111": "owner-key",
	})
	h, _ := NewApprovalHandler(svc, accessSvc, slog.Default(), false)

	body := ApprovalAPIRequest{Approved: true, RuleType: "bad_type"}
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/req-pending-001/approve", body, approvalAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "rule_type")
}

// --- PreviewRuleHandler constructor ---

func TestNewPreviewRuleHandler(t *testing.T) {
	t.Run("nil_sign_service", func(t *testing.T) {
		_, err := NewPreviewRuleHandler(nil, slog.Default())
		require.Error(t, err)
	})

	t.Run("nil_logger", func(t *testing.T) {
		_, err := NewPreviewRuleHandler(&mockSignService{}, nil)
		require.Error(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		h, err := NewPreviewRuleHandler(&mockSignService{}, slog.Default())
		require.NoError(t, err)
		assert.NotNil(t, h)
	})
}

// --- PreviewRuleHandler ServeHTTP ---

func TestPreviewRuleHandler_MethodNotAllowed(t *testing.T) {
	h, _ := NewPreviewRuleHandler(&mockSignService{}, slog.Default())
	rec := doApprovalRequest(t, h, http.MethodGet, "/api/v1/evm/requests/req-001/preview-rule", nil, approvalAdminKey())
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPreviewRuleHandler_Unauthorized(t *testing.T) {
	h, _ := NewPreviewRuleHandler(&mockSignService{}, slog.Default())
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/req-001/preview-rule", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPreviewRuleHandler_MissingRuleType(t *testing.T) {
	h, _ := NewPreviewRuleHandler(&mockSignService{}, slog.Default())
	body := PreviewRuleAPIRequest{RuleMode: "whitelist"}
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/req-001/preview-rule", body, approvalAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "rule_type")
}

func TestPreviewRuleHandler_MissingRuleMode(t *testing.T) {
	h, _ := NewPreviewRuleHandler(&mockSignService{}, slog.Default())
	body := PreviewRuleAPIRequest{RuleType: "evm_address_list"}
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/req-001/preview-rule", body, approvalAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "rule_mode")
}

func TestPreviewRuleHandler_InvalidRuleType(t *testing.T) {
	h, _ := NewPreviewRuleHandler(&mockSignService{}, slog.Default())
	body := PreviewRuleAPIRequest{RuleType: "invalid", RuleMode: "whitelist"}
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/req-001/preview-rule", body, approvalAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPreviewRuleHandler_RequestNotFound(t *testing.T) {
	svc := &mockSignService{} // returns ErrNotFound
	h, _ := NewPreviewRuleHandler(svc, slog.Default())
	body := PreviewRuleAPIRequest{RuleType: "evm_address_list", RuleMode: "whitelist"}
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/nonexistent/preview-rule", body, approvalAdminKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPreviewRuleHandler_NotRequestOwner(t *testing.T) {
	signReq := pendingSignRequest() // APIKeyID = "owner-key"
	svc := &mockSignService{
		getRequestFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
			return signReq, nil
		},
	}
	h, _ := NewPreviewRuleHandler(svc, slog.Default())
	body := PreviewRuleAPIRequest{RuleType: "evm_address_list", RuleMode: "whitelist"}
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/req-pending-001/preview-rule", body, approvalOtherKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestPreviewRuleHandler_Success(t *testing.T) {
	signReq := pendingSignRequest()
	ct := types.ChainTypeEVM
	svc := &mockSignService{
		getRequestFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
			return signReq, nil
		},
		previewRuleFn: func(_ context.Context, _ types.SignRequestID, opts *rule.RuleGenerateOptions) (*types.Rule, error) {
			return &types.Rule{
				ID:        "preview-rule-001",
				Name:      "Auto-generated rule",
				Type:      opts.RuleType,
				Mode:      opts.RuleMode,
				ChainType: &ct,
			}, nil
		},
	}
	h, _ := NewPreviewRuleHandler(svc, slog.Default())
	body := PreviewRuleAPIRequest{RuleType: "evm_address_list", RuleMode: "whitelist"}
	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/req-pending-001/preview-rule", body, approvalAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}
