package handler

import (
	"encoding/json"
	"net/http"
	"time"
)

// SecurityConfigInfo represents security configuration summary in health response.
type SecurityConfigInfo struct {
	AutoLockTimeout       string `json:"auto_lock_timeout"`        // e.g. "1h0m0s" or "disabled"
	SignTimeout           string `json:"sign_timeout"`             // e.g. "30s"
	AuditRetentionDays    int    `json:"audit_retention_days"`     // 0 = disabled
	ContentTypeValidation bool   `json:"content_type_validation"`  // always true (middleware enabled)
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

// ServeHTTP handles GET /health
func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// #nosec G104 -- HTTP response write error cannot be meaningfully handled
	json.NewEncoder(w).Encode(HealthResponse{
		Status:   "ok",
		Version:  h.version,
		Security: h.securityConfig,
	})
}
