package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// strFromMap reads key from m as a fmt-printed string, ""  if absent.
func strFromMap(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// intFromMap reads key from m as an int, 0 if absent or non-numeric.
// YAML unmarshalling into map[string]any commonly yields float64 for
// numeric scalars and int for explicit integers; both are handled.
func intFromMap(m map[string]any, key string) int {
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case int:
			return t
		case int64:
			return int(t)
		case float64:
			return int(t)
		}
	}
	return 0
}

// PresetHandler serves /api/v1/presets backed by the v0.3 preset
// Registry — `presetRepo` is the source of truth, and presets only
// reach this handler via Registry.Sync from a FileSource (or, later, a
// remote source). The legacy filesystem-walking handler that read
// preset YAML on every request is gone in this revision.
//
// Endpoints:
//
//	GET  /api/v1/presets             — list visible presets
//	GET  /api/v1/presets/{id}        — detail, joins variable defs from
//	                                    referenced templates
//	POST /api/v1/presets/{id}/apply  — create rule instance(s), one per
//	                                    template_id, in a single tx
type PresetHandler struct {
	presetRepo      storage.PresetRepository
	templateRepo    storage.TemplateRepository
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

// WithPresetRequireApproval enables admin approval for agent whitelist
// rules created via preset.
func WithPresetRequireApproval(v bool) PresetHandlerOption {
	return func(h *PresetHandler) { h.requireApproval = v }
}

// WithPresetAPIKeyRepo wires the API key repository for applied_to
// validation during DetermineRuleOwnership.
func WithPresetAPIKeyRepo(repo storage.APIKeyRepository) PresetHandlerOption {
	return func(h *PresetHandler) { h.apiKeyRepo = repo }
}

// NewPresetHandler returns a Registry-backed preset handler. presetRepo
// and templateRepo are mandatory; db is required for apply (txn). The
// previous presetsDir constructor argument is gone — presets live in
// the DB after v0.3 Registry sync.
func NewPresetHandler(
	presetRepo storage.PresetRepository,
	templateRepo storage.TemplateRepository,
	db *gorm.DB,
	templateSvc *service.TemplateService,
	readOnly bool,
	logger *slog.Logger,
	opts ...PresetHandlerOption,
) (*PresetHandler, error) {
	if presetRepo == nil {
		return nil, fmt.Errorf("preset repository is required")
	}
	if templateRepo == nil {
		return nil, fmt.Errorf("template repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	h := &PresetHandler{
		presetRepo:   presetRepo,
		templateRepo: templateRepo,
		db:           db,
		templateSvc:  templateSvc,
		readOnly:     readOnly,
		logger:       logger,
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

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

// PresetListItem is one entry in the list response — slim by design so
// the UI can render a directory without a second roundtrip per row.
type PresetListItem struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	ChainType   string   `json:"chain_type,omitempty"`
	ChainID     string   `json:"chain_id,omitempty"`
	TemplateIDs []string `json:"template_ids"`
	Enabled     bool     `json:"enabled"`
}

func (h *PresetHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.presetRepo.List(r.Context(), storage.PresetFilter{})
	if err != nil {
		h.logger.Error("list presets failed", "error", err)
		h.writeError(w, "failed to list presets", http.StatusInternalServerError)
		return
	}
	out := make([]PresetListItem, 0, len(rows))
	for _, p := range rows {
		ids, _ := decodeStringSlice(p.TemplateIDs)
		out = append(out, PresetListItem{
			ID:          p.ID,
			Name:        p.Name,
			Description: p.Description,
			ChainType:   string(p.ChainType),
			ChainID:     p.ChainID,
			TemplateIDs: ids,
			Enabled:     p.Enabled,
		})
	}
	h.writeJSON(w, map[string]interface{}{"presets": out}, http.StatusOK)
}

// ---------------------------------------------------------------------------
// Detail
// ---------------------------------------------------------------------------

// PresetVariableDetail is one entry in the detail response variables
// list. Type/Description/Required come from the joined template
// variable definition; Default is the preset's value if it set one,
// else the template's declared default. Required is the operator-
// override-required flag from the preset (which can independently make
// a variable mandatory at apply time even if the template itself
// declares it optional).
type PresetVariableDetail struct {
	Name         string `json:"name"`
	Type         string `json:"type,omitempty"`
	Description  string `json:"description,omitempty"`
	DefaultValue string `json:"default_value,omitempty"`
	Required     bool   `json:"required"`
}

// PresetDetailResponse is the GET /api/v1/presets/{id} payload.
type PresetDetailResponse struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	ChainType   string                 `json:"chain_type,omitempty"`
	ChainID     string                 `json:"chain_id,omitempty"`
	Enabled     bool                   `json:"enabled"`
	TemplateIDs []string               `json:"template_ids"`
	Variables   []PresetVariableDetail `json:"variables"`
}

func (h *PresetHandler) detail(w http.ResponseWriter, r *http.Request, id string) {
	p, err := h.presetRepo.Get(r.Context(), id)
	if err != nil {
		h.writeError(w, "preset not found", http.StatusNotFound)
		return
	}

	templateIDs, _ := decodeStringSlice(p.TemplateIDs)
	presetVars, _ := decodeAnyMap(p.Variables)
	overrides, _ := decodeOperatorOverrides(p.OperatorOverrides)

	// Build a join table from the referenced templates' variable defs.
	// First match wins — the order of template_ids is the operator's
	// authoring decision, kept as-is here.
	defs := h.collectTemplateVarDefs(r.Context(), templateIDs)

	out := make([]PresetVariableDetail, 0, len(overrides))
	for _, ov := range overrides {
		def := defs[ov.Name]
		entry := PresetVariableDetail{
			Name:        ov.Name,
			Type:        string(def.Type),
			Description: def.Description,
			Required:    ov.Required || def.Required,
		}
		// Default: preset's variables[] wins (operator hand-tuned it),
		// then template's declared default. Value is stringified for
		// wire transport — the typed widget on the UI side reconstructs
		// the natural shape from the Type tag.
		if v, ok := presetVars[ov.Name]; ok && v != nil {
			entry.DefaultValue = fmt.Sprint(v)
		} else if def.Default != nil {
			entry.DefaultValue = fmt.Sprint(def.Default)
		}
		out = append(out, entry)
	}

	h.writeJSON(w, PresetDetailResponse{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		ChainType:   string(p.ChainType),
		ChainID:     p.ChainID,
		Enabled:     p.Enabled,
		TemplateIDs: templateIDs,
		Variables:   out,
	}, http.StatusOK)
}

// collectTemplateVarDefs looks up each template_id in the repo and
// flattens their declared variables into one map keyed by name. First
// occurrence wins so composite presets (multiple templates) get a
// stable ordering driven by template_ids.
func (h *PresetHandler) collectTemplateVarDefs(ctx context.Context, ids []string) map[string]types.TemplateVariable {
	out := make(map[string]types.TemplateVariable)
	for _, id := range ids {
		tmpl, err := h.templateRepo.Get(ctx, id)
		if err != nil || tmpl == nil {
			h.logger.Debug("preset detail: template not found in DB", "template_id", id, "error", err)
			continue
		}
		var vars []types.TemplateVariable
		if len(tmpl.Variables) == 0 {
			continue
		}
		if err := json.Unmarshal(tmpl.Variables, &vars); err != nil {
			h.logger.Warn("preset detail: decode template variables", "template_id", id, "error", err)
			continue
		}
		for _, v := range vars {
			if _, seen := out[v.Name]; seen {
				continue
			}
			out[v.Name] = v
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

// ApplyPresetRequest is the body for POST /api/v1/presets/{id}/apply.
// Variables is the operator-supplied override map; entries not present
// here fall back to the preset's defaults (which themselves fall back
// to the template's declared defaults).
type ApplyPresetRequest struct {
	Variables map[string]string `json:"variables"`
	AppliedTo []string          `json:"applied_to,omitempty"`
}

func (h *PresetHandler) apply(w http.ResponseWriter, r *http.Request, id string) {
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
	p, err := h.presetRepo.Get(r.Context(), id)
	if err != nil {
		h.writeError(w, "preset not found", http.StatusNotFound)
		return
	}
	if !p.Enabled {
		h.writeError(w, "preset is disabled", http.StatusBadRequest)
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

	templateIDs, err := decodeStringSlice(p.TemplateIDs)
	if err != nil || len(templateIDs) == 0 {
		h.writeError(w, "preset has no template_ids", http.StatusBadRequest)
		return
	}
	presetVars, _ := decodeStringMap(p.Variables)
	overrides, _ := decodeOperatorOverrides(p.OperatorOverrides)
	budget, _ := decodeAnyMap(p.Budget)
	schedule, _ := decodeAnyMap(p.Schedule)

	// Required overrides that the operator didn't supply fail apply
	// early — surfaces a clearer error than a deeper template-level
	// "missing variable" later in the substitution path.
	for _, ov := range overrides {
		if !ov.Required {
			continue
		}
		if v, ok := body.Variables[ov.Name]; !ok || v == "" {
			h.writeError(w, fmt.Sprintf("required override %q not supplied", ov.Name), http.StatusBadRequest)
			return
		}
	}

	// Merge: preset defaults < operator overrides. preset variables
	// carry templated values (with ${var} placeholders that will be
	// resolved by the template engine, which sees the merged map).
	mergedVars := make(map[string]string, len(presetVars)+len(body.Variables))
	for k, v := range presetVars {
		mergedVars[k] = v
	}
	for k, v := range body.Variables {
		mergedVars[k] = v
	}

	// Build one CreateInstanceRequest per template_id. They all share
	// the merged variables, budget, schedule, and chain scope — that's
	// the entire point of a multi-template preset.
	resolved, err := h.resolveInstances(r.Context(), apiKey, body.AppliedTo, p, templateIDs, mergedVars, budget, schedule)
	if err != nil {
		h.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	results, err := h.commitInstances(r.Context(), resolved)
	if err != nil {
		h.logger.Error("preset apply failed", "error", err, "preset_id", id)
		h.writeError(w, fmt.Sprintf("preset apply failed: %s", err.Error()), http.StatusBadRequest)
		return
	}

	if h.auditLogger != nil {
		apiKeyID := ""
		if apiKey != nil {
			apiKeyID = apiKey.ID
		}
		clientIP, _ := r.Context().Value(middleware.ClientIPContextKey).(string)
		h.auditLogger.LogPresetApplied(r.Context(), apiKeyID, clientIP, id, len(results))
	}

	h.writeJSON(w, map[string]interface{}{"results": results}, http.StatusCreated)
}

type resolvedInstance struct {
	tmpl *types.RuleTemplate
	req  *service.CreateInstanceRequest
}

// resolveInstances expands the preset's template_ids into one
// CreateInstanceRequest per template, attaching the merged variables /
// budget / schedule and the caller's ownership scope. Templates are
// resolved against the DB up front so the apply transaction doesn't
// fan out into a second connection (single-connection SQLite would
// deadlock).
func (h *PresetHandler) resolveInstances(
	ctx context.Context,
	apiKey *types.APIKey,
	appliedTo []string,
	preset *types.RulePreset,
	templateIDs []string,
	mergedVars map[string]string,
	budget map[string]any,
	schedule map[string]any,
) ([]resolvedInstance, error) {
	out := make([]resolvedInstance, 0, len(templateIDs))
	for _, tid := range templateIDs {
		tmpl, err := h.templateRepo.Get(ctx, tid)
		if err != nil {
			return nil, fmt.Errorf("template %q: %w", tid, err)
		}
		req := &service.CreateInstanceRequest{
			TemplateID:   tmpl.ID,
			TemplateName: tmpl.Name,
			Name:         preset.Name + " — " + tmpl.Name,
			Variables:    cloneStringMap(mergedVars),
			ChainType:    strPtrIfNotEmpty(string(preset.ChainType)),
			ChainID:      strPtrIfNotEmpty(preset.ChainID),
		}
		if len(budget) > 0 {
			req.Budget = &service.BudgetConfig{
				MaxTotal:   strFromMap(budget, "max_total"),
				MaxPerTx:   strFromMap(budget, "max_per_tx"),
				MaxTxCount: intFromMap(budget, "max_tx_count"),
				AlertPct:   intFromMap(budget, "alert_pct"),
			}
			// Note: budget.unit lives on the template's BudgetMetering,
			// not on the per-instance BudgetConfig. The preset YAML's
			// `unit:` field flows through the template substitution at
			// rule-create time, not through this struct.
		}
		if len(schedule) > 0 {
			periodStr := strFromMap(schedule, "period")
			if periodStr != "" {
				d, err := time.ParseDuration(periodStr)
				if err != nil {
					return nil, fmt.Errorf("preset %q: invalid schedule period %q: %w", preset.ID, periodStr, err)
				}
				req.Schedule = &service.ScheduleConfig{Period: d}
			}
		}

		ownership, err := DetermineRuleOwnership(
			ctx, apiKey, appliedTo,
			tmpl.Mode, h.requireApproval, h.apiKeyRepo,
		)
		if err != nil {
			return nil, fmt.Errorf("RBAC for template %q: %w", tid, err)
		}
		req.Owner = ownership.Owner
		req.AppliedTo = []string(ownership.AppliedTo)
		req.Status = ownership.Status
		out = append(out, resolvedInstance{tmpl: tmpl, req: req})
	}
	return out, nil
}

// commitInstances runs the rule + budget creates for every resolved
// item in one transaction. Failure of any single instance rolls back
// the whole apply — partial preset materialisation is worse than no
// materialisation because operators have to manually reconcile.
func (h *PresetHandler) commitInstances(ctx context.Context, resolved []resolvedInstance) ([]map[string]interface{}, error) {
	var results []map[string]interface{}
	err := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
			result, err := h.templateSvc.CreateInstanceFromResolvedWithTx(ctx, ruleRepoTx, budgetRepoTx, item.tmpl, item.req)
			if err != nil {
				return fmt.Errorf("create instance for %q: %w", item.req.TemplateID, err)
			}
			if len(result.SubRules) > 0 {
				for i, subRule := range result.SubRules {
					entry := map[string]interface{}{"rule": subRule}
					if i < len(result.SubBudgets) && result.SubBudgets[i] != nil {
						entry["budget"] = result.SubBudgets[i]
					}
					results = append(results, entry)
				}
				continue
			}
			entry := map[string]interface{}{"rule": result.Rule}
			if result.Budget != nil {
				entry["budget"] = result.Budget
			}
			results = append(results, entry)
		}
		return nil
	})
	return results, err
}

// ---------------------------------------------------------------------------
// JSON column decode helpers
// ---------------------------------------------------------------------------

func decodeStringSlice(b []byte) ([]string, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeStringMap(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return map[string]string{}, nil
	}
	// presetRepo stores Variables as map[string]any; coerce to strings
	// at the API boundary so the rest of the handler stays simple.
	// Numbers/bools survive via fmt.Sprint; nested structures get
	// JSON-encoded so the substituter can still parse them.
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		switch x := v.(type) {
		case string:
			out[k] = x
		case nil:
			out[k] = ""
		default:
			enc, _ := json.Marshal(v)
			out[k] = string(enc)
		}
	}
	return out, nil
}

func decodeAnyMap(b []byte) (map[string]any, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeOperatorOverrides(b []byte) ([]types.OperatorOverride, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var out []types.OperatorOverride
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func strPtrIfNotEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

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
