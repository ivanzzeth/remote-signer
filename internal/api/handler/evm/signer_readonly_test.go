package evm

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestSignerHandler_ReadOnly_CreateBlocked(t *testing.T) {
	sm := &signerMockSignerManager{
		createSignerFn: func(ctx context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error) {
			t.Fatal("createSigner should not be called when readOnly")
			return nil, nil
		},
	}

	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), true)
	require.NoError(t, err)

	body := `{"type":"keystore","keystore":{"password":"test123"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBufferString(body))
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "signers_api_readonly")
}

func TestSignerHandler_ReadOnly_ListAllowed(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(ctx context.Context, filter types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: []types.SignerInfo{{Address: "0x1234", Type: "keystore", Enabled: true}},
				Total:   1,
			}, nil
		},
	}

	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/signers", nil)
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHDWalletHandler_ReadOnly_CreateBlocked(t *testing.T) {
	sm := newMockSignerManagerForHD()

	accessSvc := newTestAccessService(t)
	h, err := NewHDWalletHandler(sm, accessSvc, slog.Default(), true)
	require.NoError(t, err)

	body := `{"action":"create","password":"test123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/hd-wallets", bytes.NewBufferString(body))
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "signers_api_readonly")
}

func TestHDWalletHandler_ReadOnly_DeriveBlocked(t *testing.T) {
	sm := newMockSignerManagerForHD()

	// Grant ownership so access check passes, then readonly check blocks
	ownerships := map[string]*types.SignerOwnership{
		"0x0000000000000000000000000000000000000001": {
			SignerAddress: "0x0000000000000000000000000000000000000001",
			OwnerID:       "admin-key",
			Status:        types.SignerOwnershipActive,
		},
	}
	accessSvc := newTestAccessServiceWithOwnerships(t, ownerships)
	h, err := NewHDWalletHandler(sm, accessSvc, slog.Default(), true)
	require.NoError(t, err)

	body := `{"index":1}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/hd-wallets/0x0000000000000000000000000000000000000001/derive", bytes.NewBufferString(body))
	req = req.WithContext(adminCtx())
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "signers_api_readonly")
}

// newMockSignerManagerForHD creates a minimal mock SignerManager for HD wallet tests.
func newMockSignerManagerForHD() *signerMockSignerManager {
	return &signerMockSignerManager{}
}
