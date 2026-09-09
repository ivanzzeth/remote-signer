package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/config"
)

// ---------------------------------------------------------------------------
// Tests for ACLHandler
// ---------------------------------------------------------------------------

func TestACLHandler_NilConfig(t *testing.T) {
	// When ipWhitelist is nil, ServeHTTP returns disabled defaults.
	h := NewACLHandler(nil)
	require.NotNil(t, h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/acls/ip-whitelist", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp IPWhitelistResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Enabled)
	assert.Nil(t, resp.AllowedIPs)
	assert.False(t, resp.TrustProxy)
	assert.Nil(t, resp.TrustedProxies)
}

func TestACLHandler_WithConfig(t *testing.T) {
	// When ipWhitelist is non-nil, ServeHTTP returns the config values.
	cfg := &config.IPWhitelistConfig{
		Enabled:        true,
		AllowedIPs:     []string{"10.0.0.1", "10.0.0.2"},
		TrustProxy:     true,
		TrustedProxies: []string{"192.168.1.1"},
	}
	h := NewACLHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/acls/ip-whitelist", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp IPWhitelistResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Enabled)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, resp.AllowedIPs)
	assert.True(t, resp.TrustProxy)
	assert.Equal(t, []string{"192.168.1.1"}, resp.TrustedProxies)
}

// TestACLHandler_MethodNotAllowed was removed: its route is method-scoped now (see setupRoutes) and Go's
// ServeMux answers 405 before the handler runs. A test that calls the handler
// directly with the wrong method asserts a check this layer no longer owns —
// and should not own, since the mux cannot forget it.

func TestACLHandler_WrongPath(t *testing.T) {
	h := NewACLHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/acls/ip-whitelist/extra", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestACLHandler_EmptyConfigSlices(t *testing.T) {
	// Empty but non-nil slices should be preserved.
	cfg := &config.IPWhitelistConfig{
		Enabled:        true,
		AllowedIPs:     []string{},
		TrustProxy:     false,
		TrustedProxies: []string{},
	}
	h := NewACLHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/acls/ip-whitelist", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp IPWhitelistResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Enabled)
	assert.Empty(t, resp.AllowedIPs)
	assert.False(t, resp.TrustProxy)
	assert.Empty(t, resp.TrustedProxies)
}
