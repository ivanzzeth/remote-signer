package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHealthHandler(t *testing.T) {
	h := NewHealthHandler("1.0.0")
	assert.NotNil(t, h)
}

func TestHealthHandler_GET(t *testing.T) {
	h := NewHealthHandler("1.2.3")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp HealthResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Status)
	assert.Equal(t, "1.2.3", resp.Version)
}

// TestHealthHandler_MethodNotAllowed was removed: its route is method-scoped now (see setupRoutes) and Go's
// ServeMux answers 405 before the handler runs. A test that calls the handler
// directly with the wrong method asserts a check this layer no longer owns —
// and should not own, since the mux cannot forget it.

func TestHealthHandler_EmptyVersion(t *testing.T) {
	h := NewHealthHandler("")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp HealthResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Status)
	assert.Equal(t, "", resp.Version)
}
