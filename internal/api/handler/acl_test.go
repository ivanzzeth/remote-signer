package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ivanzzeth/remote-signer/internal/config"
)

func TestNewACLHandler(t *testing.T) {
	h := NewACLHandler(nil)
	assert.NotNil(t, h)

	h = NewACLHandler(&config.IPWhitelistConfig{Enabled: true})
	assert.NotNil(t, h)
}

func TestACLHandler_ServeHTTP_GET_WithWhitelist(t *testing.T) {
	cfg := &config.IPWhitelistConfig{
		Enabled:         true,
		AllowedIPs:      []string{"10.0.0.1", "192.168.1.0/24"},
		TrustProxy:      true,
		TrustedProxies:  []string{"10.0.0.0/8"},
	}
	h := NewACLHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/acls/ip-whitelist", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp IPWhitelistResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp.Enabled)
	assert.Equal(t, []string{"10.0.0.1", "192.168.1.0/24"}, resp.AllowedIPs)
	assert.True(t, resp.TrustProxy)
	assert.Equal(t, []string{"10.0.0.0/8"}, resp.TrustedProxies)
}

func TestACLHandler_ServeHTTP_GET_NilWhitelist(t *testing.T) {
	h := NewACLHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/acls/ip-whitelist", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp IPWhitelistResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.False(t, resp.Enabled)
	assert.Nil(t, resp.AllowedIPs)
	assert.False(t, resp.TrustProxy)
	assert.Nil(t, resp.TrustedProxies)
}

func TestACLHandler_ServeHTTP_GET_EmptyWhitelist(t *testing.T) {
	h := NewACLHandler(&config.IPWhitelistConfig{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/acls/ip-whitelist", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp IPWhitelistResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.False(t, resp.Enabled)
	assert.Nil(t, resp.AllowedIPs)
	assert.False(t, resp.TrustProxy)
	assert.Nil(t, resp.TrustedProxies)
}

func TestACLHandler_ServeHTTP_MethodNotAllowed(t *testing.T) {
	h := NewACLHandler(nil)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/acls/ip-whitelist", nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
		})
	}
}

func TestACLHandler_ServeHTTP_NotFound(t *testing.T) {
	h := NewACLHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/acls/something-else", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
