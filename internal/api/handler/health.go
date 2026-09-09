package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/settings"
)

// ApprovalGuardHealth reports whether the burst-rejection guard is configured
// and whether it has tripped into a paused state.
type ApprovalGuardHealth struct {
	Enabled bool `json:"enabled"`
	Paused  bool `json:"paused,omitempty"`
}

// SecurityConfigInfo represents security configuration summary in health response.
type SecurityConfigInfo struct {
	AutoLockTimeout       string               `json:"auto_lock_timeout"`       // e.g. "1h0m0s" or "disabled"
	SignTimeout           string               `json:"sign_timeout"`            // e.g. "30s"
	AuditRetentionDays    int                  `json:"audit_retention_days"`    // 0 = disabled
	ContentTypeValidation bool                 `json:"content_type_validation"` // always true (middleware enabled)
	ApprovalGuard         *ApprovalGuardHealth `json:"approval_guard,omitempty"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status   string              `json:"status"`
	Version  string              `json:"version"`
	Security *SecurityConfigInfo `json:"security,omitempty"`
}

// HealthHandler handles health check requests
type HealthHandler struct {
	version        string
	securityConfig *SecurityConfigInfo
	settingsMgr    *settings.Manager
	approvalGuard  *service.ManualApprovalGuard // live instance; nil until wired
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(version string) *HealthHandler {
	return &HealthHandler{
		version: version,
	}
}

// SetSecurityConfig sets the parts of the health response that are not runtime
// mutable. Retention comes from config.yaml and has no settings snapshot field.
//
// ⚠️ AutoLockTimeout and SignTimeout used to be baked in here too. They live in
// settings.SecuritySnapshot, which is reloaded from the database, so /health
// reported whatever they were at boot — an endpoint whose job is to say what
// the daemon is currently doing, answering with a stale value. They are read
// per request now, in securityConfigNow.
func (h *HealthHandler) SetSecurityConfig(retentionDays int) {
	h.securityConfig = &SecurityConfigInfo{
		AuditRetentionDays:    retentionDays,
		ContentTypeValidation: true,
	}
}

// securityConfigNow renders the security block for one response, taking the
// runtime-mutable values from the live snapshot.
func (h *HealthHandler) securityConfigNow() *SecurityConfigInfo {
	if h.securityConfig == nil {
		return nil
	}
	out := *h.securityConfig
	autoLock, signTimeout := time.Duration(0), time.Duration(0)
	if h.settingsMgr != nil {
		if snap := h.settingsMgr.Security(); snap != nil {
			autoLock, signTimeout = snap.AutoLockTimeout, snap.SignTimeout
		}
	}
	applySecurityDurations(&out, autoLock, signTimeout)
	return &out
}

// applySecurityDurations renders the two runtime-mutable durations into the
// health payload. Split out so it can be tested without standing up a settings
// manager — the formatting (0 → "disabled" for auto-lock, 0 → the 30s default
// for sign timeout) is the part with rules in it.
func applySecurityDurations(out *SecurityConfigInfo, autoLock, signTimeout time.Duration) {
	out.AutoLockTimeout = "disabled"
	if autoLock > 0 {
		out.AutoLockTimeout = autoLock.String()
	}
	out.SignTimeout = "30s"
	if signTimeout > 0 {
		out.SignTimeout = signTimeout.String()
	}
}

// SetSettingsManager wires runtime security settings for approval_guard.enabled.
func (h *HealthHandler) SetSettingsManager(mgr *settings.Manager) {
	h.settingsMgr = mgr
}

// SetApprovalGuard updates the live guard instance used for paused state.
func (h *HealthHandler) SetApprovalGuard(guard *service.ManualApprovalGuard) {
	h.approvalGuard = guard
}

func (h *HealthHandler) approvalGuardHealth() *ApprovalGuardHealth {
	enabled := false
	if h.settingsMgr != nil {
		enabled = h.settingsMgr.Security().ApprovalGuard.Enabled
	}
	if !enabled {
		return nil
	}
	paused := false
	if h.approvalGuard != nil {
		paused = h.approvalGuard.IsPaused()
	}
	return &ApprovalGuardHealth{
		Enabled: true,
		Paused:  paused,
	}
}

// ServeHTTP handles GET /health
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	security := h.securityConfigNow()
	if security != nil {
		copied := *security
		if ag := h.approvalGuardHealth(); ag != nil {
			copied.ApprovalGuard = ag
		}
		security = &copied
	}

	// #nosec G104 -- HTTP response write error cannot be meaningfully handled
	_ = json.NewEncoder(w).Encode(HealthResponse{
		Status:   "ok",
		Version:  h.version,
		Security: security,
	})
}
