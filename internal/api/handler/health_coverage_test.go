package handler

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Tests for HealthHandler.SetSecurityConfig
// ---------------------------------------------------------------------------

func TestSetSecurityConfig_AutoLockDisabled(t *testing.T) {
	h := NewHealthHandler("1.0.0")
	h.SetSecurityConfig(0, 30*time.Second, 7)
	assert.NotNil(t, h.securityConfig)
	assert.Equal(t, "disabled", h.securityConfig.AutoLockTimeout)
}

func TestSetSecurityConfig_AutoLockEnabled(t *testing.T) {
	h := NewHealthHandler("1.0.0")
	h.SetSecurityConfig(5*time.Minute, 30*time.Second, 7)
	assert.Equal(t, "5m0s", h.securityConfig.AutoLockTimeout)
}

func TestSetSecurityConfig_DefaultSignTimeout(t *testing.T) {
	h := NewHealthHandler("1.0.0")
	h.SetSecurityConfig(5*time.Minute, 0, 7)
	assert.Equal(t, "30s", h.securityConfig.SignTimeout)
}

func TestSetSecurityConfig_CustomSignTimeout(t *testing.T) {
	h := NewHealthHandler("1.0.0")
	h.SetSecurityConfig(5*time.Minute, 60*time.Second, 7)
	assert.Equal(t, "1m0s", h.securityConfig.SignTimeout)
}

func TestSetSecurityConfig_RetentionZero(t *testing.T) {
	h := NewHealthHandler("1.0.0")
	h.SetSecurityConfig(5*time.Minute, 30*time.Second, 0)
	assert.Equal(t, 0, h.securityConfig.AuditRetentionDays)
}

func TestSetSecurityConfig_AlwaysSetsContentTypeValidation(t *testing.T) {
	h := NewHealthHandler("1.0.0")
	h.SetSecurityConfig(0, 30*time.Second, 7)
	assert.True(t, h.securityConfig.ContentTypeValidation)
}

func TestSetSecurityConfig_ResponseShape(t *testing.T) {
	// Verify the security config shows up in the health response JSON.
	h := NewHealthHandler("v2.0.0")
	h.SetSecurityConfig(10*time.Minute, 45*time.Second, 30)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	code := w.Code
	assert.Equal(t, 200, code)

	var resp HealthResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.NotNil(t, resp.Security)
	assert.Equal(t, "10m0s", resp.Security.AutoLockTimeout)
	assert.Equal(t, "45s", resp.Security.SignTimeout)
	assert.Equal(t, 30, resp.Security.AuditRetentionDays)
	assert.True(t, resp.Security.ContentTypeValidation)
}
