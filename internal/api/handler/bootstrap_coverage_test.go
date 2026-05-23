package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Tests for clientIP helper
// ---------------------------------------------------------------------------

func TestClientIP_WithPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	r.RemoteAddr = "192.168.1.100:54321"
	ip := clientIP(r)
	assert.Equal(t, "192.168.1.100", ip)
}

func TestClientIP_IPv6WithPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	r.RemoteAddr = "[::1]:8080"
	ip := clientIP(r)
	assert.Equal(t, "[::1]", ip)
}

func TestClientIP_NoPort(t *testing.T) {
	// When RemoteAddr has no colon, the full string is returned.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	r.RemoteAddr = "10.0.0.1"
	ip := clientIP(r)
	assert.Equal(t, "10.0.0.1", ip)
}
