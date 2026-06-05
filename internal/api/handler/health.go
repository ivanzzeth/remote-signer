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

// SetSecurityConfig sets the security config info for the health response.
func (h *HealthHandler) SetSecurityConfig(autoLockTimeout time.Duration, signTimeout time.Duration, retentionDays int) {
	autoLockStr := "disabled"
	if autoLockTimeout > 0 {
		autoLockStr = autoLockTimeout.String()
	}
	signTimeoutStr := signTimeout.String()
	if signTimeout == 0 {
		signTimeoutStr = "30s"
	}
	h.securityConfig = &SecurityConfigInfo{
		AutoLockTimeout:       autoLockStr,
		SignTimeout:           signTimeoutStr,
		AuditRetentionDays:    retentionDays,
		ContentTypeValidation: true,
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

	security := h.securityConfig
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
