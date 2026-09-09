package handler

import (
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	_ "modernc.org/sqlite"

	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// ---------------------------------------------------------------------------
// Tests for HealthHandler.SetSecurityConfig
// ---------------------------------------------------------------------------

func TestSetSecurityConfig_AutoLockDisabled(t *testing.T) {
	// The durations are runtime mutable, so they are rendered per request from
	// the settings snapshot rather than baked in at wiring time; the formatting
	// rules are what this asserts.
	var info SecurityConfigInfo
	applySecurityDurations(&info, 0, 30*time.Second)
	assert.Equal(t, "disabled", info.AutoLockTimeout)
}

func TestSetSecurityConfig_AutoLockEnabled(t *testing.T) {
	// The durations are runtime mutable, so they are rendered per request from
	// the settings snapshot rather than baked in at wiring time; the formatting
	// rules are what this asserts.
	var info SecurityConfigInfo
	applySecurityDurations(&info, 5*time.Minute, 30*time.Second)
	assert.Equal(t, "5m0s", info.AutoLockTimeout)
}

func TestSetSecurityConfig_DefaultSignTimeout(t *testing.T) {
	// The durations are runtime mutable, so they are rendered per request from
	// the settings snapshot rather than baked in at wiring time; the formatting
	// rules are what this asserts.
	var info SecurityConfigInfo
	applySecurityDurations(&info, 5*time.Minute, 0)
	assert.Equal(t, "30s", info.SignTimeout)
}

func TestSetSecurityConfig_CustomSignTimeout(t *testing.T) {
	// The durations are runtime mutable, so they are rendered per request from
	// the settings snapshot rather than baked in at wiring time; the formatting
	// rules are what this asserts.
	var info SecurityConfigInfo
	applySecurityDurations(&info, 5*time.Minute, 60*time.Second)
	assert.Equal(t, "1m0s", info.SignTimeout)
}

func TestSetSecurityConfig_RetentionZero(t *testing.T) {
	h := NewHealthHandler("1.0.0")
	h.SetSecurityConfig(0)
	assert.Equal(t, 0, h.securityConfig.AuditRetentionDays)
}

func TestSetSecurityConfig_AlwaysSetsContentTypeValidation(t *testing.T) {
	h := NewHealthHandler("1.0.0")
	h.SetSecurityConfig(7)
	assert.True(t, h.securityConfig.ContentTypeValidation)
}

func TestSetSecurityConfig_ResponseShape(t *testing.T) {
	// /health reports what the daemon is doing *now*, so the two runtime-mutable
	// durations must come from the live settings snapshot rather than from
	// whatever they were at wiring time. Seeding them here and reading them back
	// out of the response body is what makes that claim testable — before
	// 2026-09-10 they were baked in by SetSecurityConfig and the endpoint
	// happily reported a value that had since been changed.
	mgr := settings.NewManager(newHealthTestStore(t), slog.Default())
	sec := settings.DefaultSecurity()
	sec.AutoLockTimeout = 10 * time.Minute
	sec.SignTimeout = 45 * time.Second
	if err := mgr.UpdateSecurity(t.Context(), sec, settings.UpdatedBySystem); err != nil {
		t.Fatalf("update security: %v", err)
	}

	h := NewHealthHandler("v2.0.0")
	h.SetSettingsManager(mgr)
	h.SetSecurityConfig(30)

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

func TestApprovalGuardHealth_FromRuntimeSettings(t *testing.T) {
	mgr := settings.NewManager(newHealthTestStore(t), slog.Default())
	sec := settings.DefaultSecurity()
	sec.ApprovalGuard.Enabled = true
	if err := mgr.UpdateSecurity(t.Context(), sec, settings.UpdatedBySystem); err != nil {
		t.Fatalf("update security: %v", err)
	}

	guard, err := service.NewManualApprovalGuard(service.ManualApprovalGuardConfig{
		Logger:                slog.Default(),
		Window:                time.Minute,
		RejectionThresholdPct: 50,
		MinSamples:            1,
		ResumeAfter:           time.Minute,
	})
	assert.NoError(t, err)
	guard.RecordRuleRejected()

	h := NewHealthHandler("v2.0.0")
	h.SetSecurityConfig(7)
	h.SetSettingsManager(mgr)
	h.SetApprovalGuard(guard)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	var resp HealthResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.NotNil(t, resp.Security)
	assert.NotNil(t, resp.Security.ApprovalGuard)
	assert.True(t, resp.Security.ApprovalGuard.Enabled)
	assert.True(t, resp.Security.ApprovalGuard.Paused)
}

func TestApprovalGuardHealth_DisabledOmitsBlock(t *testing.T) {
	mgr := settings.NewManager(newHealthTestStore(t), slog.Default())

	h := NewHealthHandler("v2.0.0")
	h.SetSecurityConfig(7)
	h.SetSettingsManager(mgr)
	h.SetApprovalGuard(nil)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	var resp HealthResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.NotNil(t, resp.Security)
	assert.Nil(t, resp.Security.ApprovalGuard)
}

func newHealthTestStore(t *testing.T) settings.Store {
	t.Helper()
	db, err := gorm.Open(sqlite.New(sqlite.Config{DSN: ":memory:", DriverName: "sqlite"}), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&settings.Setting{}); err != nil {
		t.Fatal(err)
	}
	store, err := settings.NewGormStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
