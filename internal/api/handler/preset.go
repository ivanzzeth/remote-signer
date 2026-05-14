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

	"gopkg.in/yaml.v3"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/preset"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// PresetHandler handles preset list, detail, and apply (admin-only).
type PresetHandler struct {
	presetsDir      string
	db              *gorm.DB
	templateSvc     *service.TemplateService
	templateRepo    storage.TemplateRepository
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

// WithPresetTemplateRepo wires a template repository so the detail
// endpoint can join each override hint against the variable
// definitions declared in the referenced template(s). Without this the
// detail response degrades to bare hint names — same as the old /vars
// endpoint, no richer.
func WithPresetTemplateRepo(repo storage.TemplateRepository) PresetHandlerOption {
	return func(h *PresetHandler) {
		h.templateRepo = repo
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
	// path is preset id (filename) — optionally followed by a sub-action.
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			h.writeError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.detail(w, r, id)
		return
	}
	switch parts[1] {
	case "apply":
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
			"name":           e.Name,
			"chain_type":     e.ChainType,
			"chain_id":       e.ChainID,
			"template_names": e.TemplateNames,
		})
	}
	h.writeJSON(w, map[string]interface{}{"presets": out}, http.StatusOK)
}

// PresetVariableDetail is the rich shape of one override hint — bare
// name plus type/description joined from the referenced template's
// variable definition. Default value comes from the preset's own
// `variables:` block when set, falling back to the template's
// declared default.
type PresetVariableDetail struct {
	Name         string `json:"name"`
	Type         string `json:"type,omitempty"`
	Description  string `json:"description,omitempty"`
	DefaultValue string `json:"default_value,omitempty"`
	Required     bool   `json:"required"`
}

// PresetDetailResponse is the GET /api/v1/presets/{id} payload.
// Frontend renders this directly; the variables array carries enough
// information to draw a typed form without a second roundtrip.
type PresetDetailResponse struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name,omitempty"`
	ChainType     string                 `json:"chain_type,omitempty"`
	ChainID       string                 `json:"chain_id,omitempty"`
	Enabled       bool                   `json:"enabled"`
	TemplateNames []string               `json:"template_names"`
	Variables     []PresetVariableDetail `json:"variables"`
}

func (h *PresetHandler) detail(w http.ResponseWriter, r *http.Request, id string) {
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

	// Build a lookup table: variable name → definition, drawn from the
	// referenced template(s). When templateRepo isn't wired (test
	// daemons, embedded setups) the detail still works — variables
	// just degrade to bare names like the old /vars endpoint.
	varDefs := h.collectVariableDefs(r, meta)

	hints := make([]PresetVariableDetail, 0, len(meta.OverrideHints))
	for _, name := range meta.OverrideHints {
		def := varDefs[name]
		entry := PresetVariableDetail{Name: name}
		entry.Type = def.Type
		entry.Description = def.Description
		entry.Required = def.Required
		// Default: preset's variables[] wins (operator hand-tuned it),
		// then template's declared default.
		if v, ok := meta.Variables[name]; ok && v != "" {
			entry.DefaultValue = v
		} else {
			entry.DefaultValue = def.Default
		}
		hints = append(hints, entry)
	}

	resp := PresetDetailResponse{
		ID:            id,
		Name:          meta.Name,
		ChainType:     meta.ChainType,
		ChainID:       meta.ChainID,
		Enabled:       meta.Enabled,
		TemplateNames: meta.TemplateNames,
		Variables:     hints,
	}
	if len(resp.TemplateNames) == 0 && meta.Template != "" {
		resp.TemplateNames = []string{meta.Template}
	}
	h.writeJSON(w, resp, http.StatusOK)
}

// templateVarDef is the slimmed-down view we need from a template's
// declared variables — just enough for the detail UI.
type templateVarDef struct {
	Type        string
	Description string
	Required    bool
	Default     string
}

func (h *PresetHandler) collectVariableDefs(r *http.Request, meta preset.PresetMeta) map[string]templateVarDef {
	out := map[string]templateVarDef{}

	// Path 1: read each referenced template file directly off disk.
	// This is the more reliable join — the preset YAML pins exact
	// file paths, and the template files carry the full variable
	// definitions in a fixed shape (`variables: [{name, type,
	// description, required, default}]`). Using the file bypasses
	// any naming drift between the YAML and the DB row's `name`
	// column, which can happen when templates are loaded via
	// templates_dir (display name derived from filename).
	paths := append([]string(nil), meta.TemplatePaths...)
	if meta.TemplatePath != "" {
		paths = append(paths, meta.TemplatePath)
	}
	// Preset paths are repo-relative, conventionally written as
	// "rules/templates/<file>.yaml". The presetsDir typically sits at
	// "<root>/rules/presets/", so the project root is two levels up
	// — but we don't assume the layout. Try each ancestor in turn
	// until the file resolves; pure project-root guessing is wobbly,
	// fallback search is cheap (the tree is small).
	for _, p := range paths {
		if p == "" {
			continue
		}
		if filepath.IsAbs(p) {
			mergeTemplateVarsFromFile(p, out, h.logger)
			continue
		}
		dir := h.presetsDir
		for i := 0; i < 4; i++ {
			candidate := filepath.Join(dir, p)
			if _, err := os.Stat(candidate); err == nil {
				mergeTemplateVarsFromFile(candidate, out, h.logger)
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	// Path 2: fall back to the DB when no template_paths were set or
	// the file read failed. Looks up by name — same caveat as above.
	if h.templateRepo == nil {
		return out
	}
	names := append([]string(nil), meta.TemplateNames...)
	if meta.Template != "" {
		names = append(names, meta.Template)
	}
	for _, tn := range names {
		tmpl, err := h.templateRepo.GetByName(r.Context(), tn)
		if err != nil || tmpl == nil {
			continue
		}
		var vars []types.TemplateVariable
		if len(tmpl.Variables) > 0 {
			if err := json.Unmarshal(tmpl.Variables, &vars); err != nil {
				h.logger.Warn("failed to decode template variables", "template", tn, "error", err)
				continue
			}
		}
		for _, v := range vars {
			if _, ok := out[v.Name]; ok {
				continue // file-based source wins
			}
			out[v.Name] = templateVarDef{
				Type:        v.Type,
				Description: v.Description,
				Required:    v.Required,
				Default:     v.Default,
			}
		}
	}
	return out
}

// buildPresetNamePathMap zips meta.TemplateNames with meta.TemplatePaths
// into a name → path map. The preset YAML's two arrays are positional;
// when only one side exists or the single-template shorthand is used,
// the resulting map degrades gracefully to a partial mapping.
func buildPresetNamePathMap(meta preset.PresetMeta) map[string]string {
	out := map[string]string{}
	n := len(meta.TemplateNames)
	if len(meta.TemplatePaths) < n {
		n = len(meta.TemplatePaths)
	}
	for i := 0; i < n; i++ {
		if meta.TemplateNames[i] != "" && meta.TemplatePaths[i] != "" {
			out[meta.TemplateNames[i]] = meta.TemplatePaths[i]
		}
	}
	if meta.Template != "" && meta.TemplatePath != "" {
		out[meta.Template] = meta.TemplatePath
	}
	return out
}

// loadTemplateFromFile reads a template YAML at path and builds a
// transient *types.RuleTemplate suitable for handing to
// CreateInstanceFromResolvedWithTx. It mirrors the shape config-sync
// produces in the DB: Type=template_bundle, Mode = first sub-rule's
// mode, Config encodes the rules_json marshalled string, Variables
// and BudgetMetering are JSON-encoded.
//
// The name argument is what the preset called the template — we use
// that on the result so downstream messaging stays consistent with
// the operator's mental model.
func (h *PresetHandler) loadTemplateFromFile(relPath, name string) (*types.RuleTemplate, error) {
	resolved := relPath
	if !filepath.IsAbs(resolved) {
		// Same search ladder as the variable-join logic; presetsDir
		// typically sits at "<root>/rules/presets/" but we don't
		// hard-assume the depth.
		dir := h.presetsDir
		for i := 0; i < 4; i++ {
			cand := filepath.Join(dir, relPath)
			if _, err := os.Stat(cand); err == nil {
				resolved = cand
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
		if !filepath.IsAbs(resolved) {
			return nil, fmt.Errorf("template file %q not found under presetsDir ancestors", relPath)
		}
	}
	data, err := os.ReadFile(resolved) // #nosec G304 -- path derived from admin-curated preset YAML
	if err != nil {
		return nil, fmt.Errorf("read template file: %w", err)
	}
	var file struct {
		Variables      []types.TemplateVariable `yaml:"variables"`
		BudgetMetering map[string]interface{}   `yaml:"budget_metering"`
		Rules          []map[string]interface{} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse template file: %w", err)
	}
	if len(file.Rules) == 0 {
		return nil, fmt.Errorf("template file %q has no rules", relPath)
	}
	variablesJSON, _ := json.Marshal(file.Variables)
	var meteringJSON []byte
	if file.BudgetMetering != nil {
		meteringJSON, _ = json.Marshal(file.BudgetMetering)
	}
	rulesJSON, _ := json.Marshal(file.Rules)
	config := map[string]interface{}{"rules_json": string(rulesJSON)}
	configJSON, _ := json.Marshal(config)
	mode, _ := file.Rules[0]["mode"].(string)
	if mode == "" {
		mode = "whitelist"
	}
	return &types.RuleTemplate{
		ID:             "transient_" + name,
		Name:           name,
		Type:           "template_bundle",
		Mode:           types.RuleMode(mode),
		Variables:      variablesJSON,
		Config:         configJSON,
		BudgetMetering: meteringJSON,
		Enabled:        true,
	}, nil
}

// mergeTemplateVarsFromFile reads a template YAML and folds each of its
// declared variables into out. Errors are logged but never bubbled —
// a malformed/missing template degrades to "no description", same as
// the empty-handler case.
func mergeTemplateVarsFromFile(path string, out map[string]templateVarDef, logger *slog.Logger) {
	data, err := os.ReadFile(path) // #nosec G304 -- path derived from admin-curated preset YAML
	if err != nil {
		if logger != nil {
			logger.Debug("preset detail: template file read failed",
				"path", path, "error", err)
		}
		return
	}
	var file struct {
		Variables []types.TemplateVariable `yaml:"variables"`
	}
	if err := yaml.Unmarshal(data, &file); err != nil {
		if logger != nil {
			logger.Warn("preset detail: template file parse failed",
				"path", path, "error", err)
		}
		return
	}
	for _, v := range file.Variables {
		if _, ok := out[v.Name]; ok {
			continue // first match wins (preset's primary template)
		}
		out[v.Name] = templateVarDef{
			Type:        v.Type,
			Description: v.Description,
			Required:    v.Required,
			Default:     v.Default,
		}
	}
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

	// Build a fallback mapping from template name → file path the
	// preset YAML pinned. When ResolveTemplate misses on name — which
	// happens whenever the templates_dir loader derived a name from
	// filename that doesn't match the preset's `template_names:` —
	// we read the template file directly off disk and construct a
	// transient RuleTemplate so the apply still works without forcing
	// the operator to hand-curate cfg.Templates.
	meta, metaErr := preset.GetPresetMeta(data)
	if metaErr != nil {
		h.writeError(w, fmt.Sprintf("parse preset meta: %s", metaErr.Error()), http.StatusBadRequest)
		return
	}
	pathByName := buildPresetNamePathMap(meta)

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
			// Fallback: load the template file directly. The preset's
			// template_paths array pins the source, so we can build a
			// transient RuleTemplate even when the DB row was loaded
			// under a different name.
			if path := pathByName[pr.TemplateName]; path != "" {
				fallback, fbErr := h.loadTemplateFromFile(path, pr.TemplateName)
				if fbErr == nil {
					tmpl = fallback
					h.logger.Debug("preset apply: template resolved via file fallback",
						"name", pr.TemplateName, "path", path)
					err = nil
				} else {
					h.logger.Warn("preset apply: file fallback failed",
						"name", pr.TemplateName, "path", path, "error", fbErr)
				}
			}
		}
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
