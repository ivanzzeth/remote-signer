package evm

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

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// --- createSigner tests ---

func TestCreateSigner_ReadOnly(t *testing.T) {
	mgr := &signerMockSignerManager{}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), true) // readOnly=true
	require.NoError(t, err)

	body := `{"type":"keystore","keystore":{"password":"test123"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin, Enabled: true}
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "readonly")
}

func TestCreateSigner_Unauthorized(t *testing.T) {
	mgr := &signerMockSignerManager{}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	body := `{"type":"keystore","keystore":{"password":"test123"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	// No API key in context
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestCreateSigner_PermissionDenied(t *testing.T) {
	mgr := &signerMockSignerManager{}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	body := `{"type":"keystore","keystore":{"password":"test123"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	// strategy role doesn't have PermCreateSigners
	apiKey := &types.APIKey{ID: "strategy-key", Role: types.RoleStrategy, Enabled: true}
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCreateSigner_InvalidBody(t *testing.T) {
	mgr := &signerMockSignerManager{}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBufferString("bad json"))
	req.Header.Set("Content-Type", "application/json")
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin, Enabled: true}
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestCreateSigner_Success(t *testing.T) {
	mgr := &signerMockSignerManager{
		createSignerFn: func(_ context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error) {
			return &types.SignerInfo{
				Address: "0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd",
				Type:    string(req.Type),
				Enabled: true,
			}, nil
		},
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	body := `{"type":"keystore","keystore":{"password":"test123"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	apiKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin, Enabled: true}
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)

	var resp CreateSignerResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd", resp.Address)
	assert.Equal(t, "keystore", resp.Type)
	assert.True(t, resp.Enabled)
}
