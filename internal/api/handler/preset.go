package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/preset"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// PresetHandler handles preset list, vars, and apply (admin-only).
type PresetHandler struct {
	presetsDir      string
	db              *gorm.DB
	templateSvc     *service.TemplateService
	readOnly        bool
	logger          *slog.Logger
	auditLogger     *audit.AuditLogger
	requireApproval bool
	apiKeyRepo      storage.APIKeyRepository
}

// PresetHandlerOption is a functional option for PresetHandler.
type PresetHandlerOption func(*PresetHandler)

// WithPresetRequireApproval enables admin approval for agent whitelist rules created via preset.
func WithPresetRequireApproval(v bool) PresetHandlerOption {
	return func(h *PresetHandler) {
		h.requireApproval = v
	}
}

// WithPresetAPIKeyRepo sets the API key repository for applied_to validation.
func WithPresetAPIKeyRepo(repo storage.APIKeyRepository) PresetHandlerOption {
	return func(h *PresetHandler) {
		h.apiKeyRepo = repo
	}
}

// NewPresetHandler creates a preset handler. presetsDir must be absolute. db is required for apply (transaction).
func NewPresetHandler(
	presetsDir string,
	db *gorm.DB,
	templateSvc *service.TemplateService,
	readOnly bool,
	logger *slog.Logger,
	opts ...PresetHandlerOption,
) (*PresetHandler, error) {
	if presetsDir == "" {
		return nil, fmt.Errorf("presets directory is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	h := &PresetHandler{
		presetsDir:  presetsDir,
		db:          db,
		templateSvc: templateSvc,
		readOnly:    readOnly,
		logger:      logger,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h, nil
}

// SetAuditLogger sets the audit logger for recording preset apply events.
func (h *PresetHandler) SetAuditLogger(al *audit.AuditLogger) {
	h.auditLogger = al
}

// ServeHTTP routes /api/v1/presets and /api/v1/presets/{id}/...
func (h *PresetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/presets")
	path = strings.Trim(path, "/")
	if path == "" {
		switch r.Method {
		case http.MethodGet:
			h.list(w, r)
			return
		}
		h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// path is preset id (filename)
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]
	switch {
	case len(parts) == 1:
		h.writeError(w, "not found", http.StatusNotFound)
		return
	case parts[1] == "vars":
		if r.Method != http.MethodGet {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.vars(w, r, id)
		return
	case parts[1] == "apply":
		if r.Method != http.MethodPost {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.apply(w, r, id)
		return
	}
	h.writeError(w, "not found", http.StatusNotFound)
}

func (h *PresetHandler) list(w http.ResponseWriter, _ *http.Request) {
	entries, err := preset.ListPresets(h.presetsDir)
	if err != nil {
		h.logger.Error("list presets failed", "error", err)
		h.writeError(w, "failed to list presets", http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []preset.PresetEntry{}
	}
	out := make([]map[string]interface{}, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]interface{}{
			"id":             e.ID,
			"template_names": e.TemplateNames,
		})
	}
	h.writeJSON(w, map[string]interface{}{"presets": out}, http.StatusOK)
}

func (h *PresetHandler) vars(w http.ResponseWriter, _ *http.Request, id string) {
	data, err := h.readPresetFile(id)
	if err != nil {
		if os.IsNotExist(err) {
			h.writeError(w, "preset not found", http.StatusNotFound)
			return
		}
		h.logger.Error("read preset file failed", "error", err, "preset_id", id)
		h.writeError(w, "invalid preset id", http.StatusBadRequest)
		return
	}
	meta, err := preset.GetPresetMeta(data)
	if err != nil {
		h.writeError(w, fmt.Sprintf("parse preset meta: %s", err.Error()), http.StatusBadRequest)
		return
	}
	h.writeJSON(w, map[string]interface{}{
		"override_hints": meta.OverrideHints,
	}, http.StatusOK)
}

// ApplyPresetRequest is the body for POST /api/v1/presets/:id/apply
type ApplyPresetRequest struct {
	Variables map[string]string `json:"variables"`
	AppliedTo []string          `json:"applied_to,omitempty"`
}

func (h *PresetHandler) apply(w http.ResponseWriter, r *http.Request, id string) {
	// Check apply_preset permission (admin-only)
	apiKey := middleware.GetAPIKey(r.Context())
	if apiKey == nil || !middleware.HasPermission(apiKey.Role, middleware.PermApplyPreset) {
		h.writeError(w, "forbidden: apply_preset permission required", http.StatusForbidden)
		return
	}
	if h.readOnly {
		h.writeError(w, "preset apply is disabled (security.rules_api_readonly)", http.StatusForbidden)
		return
	}
	if h.templateSvc == nil {
		h.writeError(w, "template service not configured", http.StatusServiceUnavailable)
		return
	}
	if h.db == nil {
		h.writeError(w, "database not configured for preset apply", http.StatusServiceUnavailable)
		return
	}
	data, err := h.readPresetFile(id)
	if err != nil {
		if os.IsNotExist(err) {
			h.writeError(w, "preset not found", http.StatusNotFound)
			return
		}
		h.logger.Error("read preset file failed", "error", err, "preset_id", id)
		h.writeError(w, "invalid preset id", http.StatusBadRequest)
		return
	}
	var body ApplyPresetRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.writeError(w, fmt.Sprintf("invalid request body: %s", err.Error()), http.StatusBadRequest)
			return
		}
	}
	if body.Variables == nil {
		body.Variables = make(map[string]string)
	}
	presetRules, err := preset.ParsePresetFile(data, body.Variables)
	if err != nil {
		h.writeError(w, fmt.Sprintf("parse preset: %s", err.Error()), http.StatusBadRequest)
		return
	}
	if len(presetRules) == 0 {
		h.writeError(w, "preset produced no rules", http.StatusBadRequest)
		return
	}
	// Resolve all templates before starting the transaction so we don't need a second DB connection (avoids deadlock with single-conn SQLite).
	type resolvedItem struct {
		tmpl *types.RuleTemplate
		req  *service.CreateInstanceRequest
	}
	var resolved []resolvedItem
	for _, pr := range presetRules {
		req, err := presetRuleToCreateInstanceRequest(pr)
		if err != nil {
			h.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		tmpl, err := h.templateSvc.ResolveTemplate(r.Context(), req)
		if err != nil {
			h.writeError(w, fmt.Sprintf("template %q: %s", pr.TemplateName, err.Error()), http.StatusBadRequest)
			return
		}
		// Apply RBAC ownership to each instance request
		ownership, err := DetermineRuleOwnership(
			r.Context(), apiKey, body.AppliedTo,
			tmpl.Mode, h.requireApproval, h.apiKeyRepo,
		)
		if err != nil {
			h.writeError(w, fmt.Sprintf("RBAC for template %q: %s", pr.TemplateName, err.Error()), http.StatusBadRequest)
			return
		}
		req.Owner = ownership.Owner
		req.AppliedTo = []string(ownership.AppliedTo)
		req.Status = ownership.Status
		resolved = append(resolved, resolvedItem{tmpl: tmpl, req: req})
	}
	var results []map[string]interface{}
	err = h.db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
		ruleRepoTx, errTx := storage.NewGormRuleRepository(tx)
		if errTx != nil {
			return errTx
		}
		budgetRepoTx, errTx := storage.NewGormBudgetRepository(tx)
		if errTx != nil {
			return errTx
		}
		results = make([]map[string]interface{}, 0, len(resolved))
		for _, item := range resolved {
			result, err := h.templateSvc.CreateInstanceFromResolvedWithTx(r.Context(), ruleRepoTx, budgetRepoTx, item.tmpl, item.req)
			if err != nil {
				return fmt.Errorf("create instance for %q: %w", item.req.TemplateName, err)
			}
			// If the template was a bundle, emit one result entry per sub-rule
			if len(result.SubRules) > 0 {
				for i, subRule := range result.SubRules {
					resItem := map[string]interface{}{"rule": subRule}
					if i < len(result.SubBudgets) && result.SubBudgets[i] != nil {
						resItem["budget"] = result.SubBudgets[i]
					}
					results = append(results, resItem)
				}
			} else {
				resItem := map[string]interface{}{"rule": result.Rule}
				if result.Budget != nil {
					resItem["budget"] = result.Budget
				}
				results = append(results, resItem)
			}
		}
		return nil
	})
	if err != nil {
		h.logger.Error("preset apply failed", "error", err, "preset_id", id)
		h.writeError(w, fmt.Sprintf("preset apply failed: %s", err.Error()), http.StatusBadRequest)
		return
	}
	// Audit log: preset applied.
	if h.auditLogger != nil {
		apiKey := middleware.GetAPIKey(r.Context())
		apiKeyID := ""
		if apiKey != nil {
			apiKeyID = apiKey.ID
		}
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogPresetApplied(r.Context(), apiKeyID, clientIP, id, len(results))
	}

	h.writeJSON(w, map[string]interface{}{"results": results}, http.StatusCreated)
}

// readPresetFile resolves id to a file under presetsDir (path safety) and returns file content.
// id is the preset filename; tryPaths: id, id.yaml, id.preset.yaml (same as CLI).
func (h *PresetHandler) readPresetFile(id string) ([]byte, error) {
	cleanID := filepath.Clean(id)
	if cleanID == "" || strings.Contains(cleanID, "..") || filepath.IsAbs(cleanID) {
		return nil, fmt.Errorf("invalid preset id")
	}
	basePath := filepath.Join(h.presetsDir, cleanID)
	absDir, err := filepath.Abs(h.presetsDir)
	if err != nil {
		return nil, err
	}
	tryPaths := []string{basePath}
	if filepath.Ext(basePath) == "" {
		tryPaths = append(tryPaths, basePath+".yaml", basePath+".preset.yaml", basePath+".preset.js.yaml")
	}
	if filepath.Ext(basePath) == ".preset" {
		tryPaths = append(tryPaths, basePath+".yaml")
	}
	if filepath.Ext(basePath) == ".yaml" && !strings.HasSuffix(basePath, ".preset.yaml") {
		tryPaths = append(tryPaths, strings.TrimSuffix(basePath, ".yaml")+".preset.yaml")
	}
	for _, p := range tryPaths {
		absPath, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(absPath, absDir+string(filepath.Separator)) && absPath != absDir {
			continue
		}
		// Resolve symlinks and re-check that the real path is still under presetsDir.
		realPath, err := filepath.EvalSymlinks(absPath)
		if err != nil {
			continue
		}
		if !strings.HasPrefix(realPath, absDir+string(filepath.Separator)) && realPath != absDir {
			continue
		}
		data, err := os.ReadFile(realPath) // #nosec G304 -- path validated under presetsDir after symlink resolution
		if err == nil {
			return data, nil
		}
	}
	return nil, os.ErrNotExist
}

func presetRuleToCreateInstanceRequest(pr preset.PresetRule) (*service.CreateInstanceRequest, error) {
	if pr.TemplateName == "" {
		return nil, fmt.Errorf("preset rule %q has empty template name", pr.Name)
	}
	req := &service.CreateInstanceRequest{
		TemplateName: pr.TemplateName,
		Name:         pr.Name,
		Variables:    pr.Variables,
		ChainType:    strPtr(pr.ChainType),
		ChainID:      strPtr(pr.ChainID),
	}
	if len(pr.Budget) > 0 {
		req.Budget = &service.BudgetConfig{
			MaxTotal:   strFromMap(pr.Budget, "max_total"),
			MaxPerTx:   strFromMap(pr.Budget, "max_per_tx"),
			MaxTxCount: intFromMap(pr.Budget, "max_tx_count"),
			AlertPct:   intFromMap(pr.Budget, "alert_pct"),
		}
	}
	if len(pr.Schedule) > 0 {
		periodStr := strFromMap(pr.Schedule, "period")
		if periodStr != "" {
			d, err := time.ParseDuration(periodStr)
			if err != nil {
				return nil, fmt.Errorf("preset rule %q: invalid schedule period %q: %w", pr.Name, periodStr, err)
			}
			req.Schedule = &service.ScheduleConfig{Period: d}
		}
	}
	return req, nil
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func strFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func intFromMap(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case int:
			return t
		case int64:
			return int(t)
		case float64:
			return int(t)
		default:
			return 0
		}
	}
	return 0
}

func (h *PresetHandler) writeError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write([]byte(fmt.Sprintf(`{"error":%q}`, message))); err != nil {
		h.logger.Error("write error response failed", "error", err)
	}
}

func (h *PresetHandler) writeJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("write JSON failed", "error", err)
	}
}
