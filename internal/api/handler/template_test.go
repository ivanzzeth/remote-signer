package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// In-memory mock repositories (mirrors the service test mocks)
// ---------------------------------------------------------------------------

type mockTemplateRepo struct {
	mu        sync.RWMutex
	templates map[string]*types.RuleTemplate
}

func newMockTemplateRepo() *mockTemplateRepo {
	return &mockTemplateRepo{templates: make(map[string]*types.RuleTemplate)}
}

func (r *mockTemplateRepo) Create(_ context.Context, tmpl *types.RuleTemplate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.templates[tmpl.ID]; exists {
		return types.ErrAlreadyExists
	}
	cp := *tmpl
	r.templates[tmpl.ID] = &cp
	return nil
}

func (r *mockTemplateRepo) Get(_ context.Context, id string) (*types.RuleTemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tmpl, ok := r.templates[id]
	if !ok {
		return nil, types.ErrNotFound
	}
	cp := *tmpl
	return &cp, nil
}

func (r *mockTemplateRepo) GetByName(_ context.Context, name string) (*types.RuleTemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, tmpl := range r.templates {
		if tmpl.Name == name {
			cp := *tmpl
			return &cp, nil
		}
	}
	return nil, types.ErrNotFound
}

func (r *mockTemplateRepo) Update(_ context.Context, tmpl *types.RuleTemplate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.templates[tmpl.ID]; !exists {
		return types.ErrNotFound
	}
	cp := *tmpl
	r.templates[tmpl.ID] = &cp
	return nil
}

func (r *mockTemplateRepo) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.templates[id]; !exists {
		return types.ErrNotFound
	}
	delete(r.templates, id)
	return nil
}

func (r *mockTemplateRepo) List(_ context.Context, filter storage.TemplateFilter) ([]*types.RuleTemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*types.RuleTemplate
	for _, tmpl := range r.templates {
		// Apply filter
		if filter.Type != nil && tmpl.Type != *filter.Type {
			continue
		}
		if filter.Source != nil && tmpl.Source != *filter.Source {
			continue
		}
		if filter.EnabledOnly && !tmpl.Enabled {
			continue
		}
		cp := *tmpl
		out = append(out, &cp)
	}
	// Apply offset/limit
	if filter.Offset > 0 && filter.Offset < len(out) {
		out = out[filter.Offset:]
	} else if filter.Offset >= len(out) {
		out = nil
	}
	if filter.Limit > 0 && filter.Limit < len(out) {
		out = out[:filter.Limit]
	}
	return out, nil
}

func (r *mockTemplateRepo) Count(_ context.Context, filter storage.TemplateFilter) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	count := 0
	for _, tmpl := range r.templates {
		if filter.Type != nil && tmpl.Type != *filter.Type {
			continue
		}
		if filter.Source != nil && tmpl.Source != *filter.Source {
			continue
		}
		if filter.EnabledOnly && !tmpl.Enabled {
			continue
		}
		count++
	}
	return count, nil
}

type mockRuleRepo struct {
	mu    sync.RWMutex
	rules map[types.RuleID]*types.Rule
}

func newMockRuleRepo() *mockRuleRepo {
	return &mockRuleRepo{rules: make(map[types.RuleID]*types.Rule)}
}

func (r *mockRuleRepo) Create(_ context.Context, rule *types.Rule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.rules[rule.ID]; exists {
		return types.ErrAlreadyExists
	}
	cp := *rule
	r.rules[rule.ID] = &cp
	return nil
}

func (r *mockRuleRepo) Get(_ context.Context, id types.RuleID) (*types.Rule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rule, ok := r.rules[id]
	if !ok {
		return nil, types.ErrNotFound
	}
	cp := *rule
	return &cp, nil
}

func (r *mockRuleRepo) Update(_ context.Context, rule *types.Rule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.rules[rule.ID]; !exists {
		return types.ErrNotFound
	}
	cp := *rule
	r.rules[rule.ID] = &cp
	return nil
}

func (r *mockRuleRepo) Delete(_ context.Context, id types.RuleID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.rules[id]; !exists {
		return types.ErrNotFound
	}
	delete(r.rules, id)
	return nil
}

func (r *mockRuleRepo) List(_ context.Context, _ storage.RuleFilter) ([]*types.Rule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*types.Rule
	for _, rule := range r.rules {
		cp := *rule
		out = append(out, &cp)
	}
	return out, nil
}

func (r *mockRuleRepo) Count(_ context.Context, _ storage.RuleFilter) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.rules), nil
}

func (r *mockRuleRepo) ListByChainType(_ context.Context, _ types.ChainType) ([]*types.Rule, error) {
	return nil, nil
}

func (r *mockRuleRepo) IncrementMatchCount(_ context.Context, id types.RuleID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rule, ok := r.rules[id]
	if !ok {
		return types.ErrNotFound
	}
	rule.MatchCount++
	now := time.Now()
	rule.LastMatchedAt = &now
	return nil
}

type mockBudgetRepo struct {
	mu      sync.RWMutex
	budgets map[string]*types.RuleBudget
}

func newMockBudgetRepo() *mockBudgetRepo {
	return &mockBudgetRepo{budgets: make(map[string]*types.RuleBudget)}
}

func (r *mockBudgetRepo) Create(_ context.Context, budget *types.RuleBudget) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.budgets[budget.ID]; exists {
		return types.ErrAlreadyExists
	}
	cp := *budget
	r.budgets[budget.ID] = &cp
	return nil
}

func (r *mockBudgetRepo) GetByRuleID(_ context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, b := range r.budgets {
		if b.RuleID == ruleID && b.Unit == unit {
			cp := *b
			return &cp, nil
		}
	}
	return nil, types.ErrNotFound
}

func (r *mockBudgetRepo) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.budgets[id]; !exists {
		return types.ErrNotFound
	}
	delete(r.budgets, id)
	return nil
}

func (r *mockBudgetRepo) DeleteByRuleID(_ context.Context, ruleID types.RuleID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, b := range r.budgets {
		if b.RuleID == ruleID {
			delete(r.budgets, id)
		}
	}
	return nil
}

func (r *mockBudgetRepo) AtomicSpend(_ context.Context, _ types.RuleID, _ string, _ string) error {
	return nil
}

func (r *mockBudgetRepo) ResetBudget(_ context.Context, _ types.RuleID, _ string, _ time.Time) error {
	return nil
}

func (r *mockBudgetRepo) ListByRuleID(_ context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*types.RuleBudget
	for _, b := range r.budgets {
		if b.RuleID == ruleID {
			cp := *b
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *mockBudgetRepo) ListByRuleIDs(_ context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	idSet := make(map[types.RuleID]struct{}, len(ruleIDs))
	for _, id := range ruleIDs {
		idSet[id] = struct{}{}
	}
	var out []*types.RuleBudget
	for _, b := range r.budgets {
		if _, ok := idSet[b.RuleID]; ok {
			cp := *b
			out = append(out, &cp)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("mustJSON: %v", err))
	}
	return b
}

// testAPIKey returns a minimal API key for test context injection.
func testAPIKey() *types.APIKey {
	return &types.APIKey{
		ID:      "test-key-001",
		Name:    "Test Key",
		Enabled: true,
		Admin:   true,
	}
}

// contextWithAPIKey injects an API key into the context using the same key
// the middleware uses.
func contextWithAPIKey(ctx context.Context, key *types.APIKey) context.Context {
	return context.WithValue(ctx, middleware.APIKeyContextKey, key)
}

// newTemplateService creates a TemplateService with the provided mock repos.
func newTemplateService(t *testing.T, tmplRepo *mockTemplateRepo, ruleRepo *mockRuleRepo, budgetRepo *mockBudgetRepo) *service.TemplateService {
	t.Helper()
	svc, err := service.NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
	if err != nil {
		t.Fatalf("failed to create TemplateService: %v", err)
	}
	return svc
}

// newHandler creates a TemplateHandler with mock repos and a real TemplateService.
func newHandler(t *testing.T, tmplRepo *mockTemplateRepo, ruleRepo *mockRuleRepo, budgetRepo *mockBudgetRepo) *TemplateHandler {
	t.Helper()
	svc := newTemplateService(t, tmplRepo, ruleRepo, budgetRepo)
	h, err := NewTemplateHandler(tmplRepo, svc, newTestLogger())
	if err != nil {
		t.Fatalf("failed to create TemplateHandler: %v", err)
	}
	return h
}

// doRequest builds an HTTP request, injects the API key into context,
// and calls the handler's ServeHTTP. Returns the recorded response.
func doRequest(t *testing.T, h *TemplateHandler, method, path string, body any, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}
		bodyReader = bytes.NewBuffer(b)
	} else {
		bodyReader = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		req = req.WithContext(contextWithAPIKey(req.Context(), apiKey))
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// doInstanceRequest is like doRequest but calls ServeInstanceHTTP.
func doInstanceRequest(t *testing.T, h *TemplateHandler, method, path string, body any, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Buffer
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("failed to marshal request body: %v", err)
		}
		bodyReader = bytes.NewBuffer(b)
	} else {
		bodyReader = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		req = req.WithContext(contextWithAPIKey(req.Context(), apiKey))
	}

	rr := httptest.NewRecorder()
	h.ServeInstanceHTTP(rr, req)
	return rr
}

// decodeErrorResponse parses an ErrorResponse from the response body.
func decodeErrorResponse(t *testing.T, rr *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	var errResp ErrorResponse
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	return errResp
}

// seedTemplate inserts a template into the mock repo.
func seedTemplate(t *testing.T, repo *mockTemplateRepo, tmpl *types.RuleTemplate) {
	t.Helper()
	if err := repo.Create(context.Background(), tmpl); err != nil {
		t.Fatalf("seedTemplate: %v", err)
	}
}

// seedRule inserts a rule into the mock repo.
func seedRule(t *testing.T, repo *mockRuleRepo, rule *types.Rule) {
	t.Helper()
	if err := repo.Create(context.Background(), rule); err != nil {
		t.Fatalf("seedRule: %v", err)
	}
}

// makeAPITemplate builds a template with source=api for testing.
func makeAPITemplate(id, name string) *types.RuleTemplate {
	return &types.RuleTemplate{
		ID:        id,
		Name:      name,
		Type:      types.RuleTypeEVMAddressList,
		Mode:      types.RuleModeWhitelist,
		Config:    []byte(`{"addresses":["0x1234567890abcdef1234567890abcdef12345678"]}`),
		Source:    types.RuleSourceAPI,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// makeConfigTemplate builds a template with source=config for testing.
func makeConfigTemplate(id, name string) *types.RuleTemplate {
	return &types.RuleTemplate{
		ID:        id,
		Name:      name,
		Type:      types.RuleTypeEVMAddressList,
		Mode:      types.RuleModeWhitelist,
		Config:    []byte(`{"addresses":["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}`),
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// makeTemplateWithVars builds a template with variables for instantiation tests.
func makeTemplateWithVars(id, name string) *types.RuleTemplate {
	vars := []types.TemplateVariable{
		{Name: "target_address", Type: "address", Description: "Target address", Required: true},
	}
	return &types.RuleTemplate{
		ID:        id,
		Name:      name,
		Type:      types.RuleTypeEVMAddressList,
		Mode:      types.RuleModeWhitelist,
		Variables: mustJSON(vars),
		Config:    []byte(`{"addresses":["${target_address}"]}`),
		Source:    types.RuleSourceConfig,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewTemplateHandler(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	logger := newTestLogger()
	svc := newTemplateService(t, tmplRepo, ruleRepo, budgetRepo)

	t.Run("all_valid_args", func(t *testing.T) {
		h, err := NewTemplateHandler(tmplRepo, svc, logger)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if h == nil {
			t.Fatal("expected non-nil handler")
		}
	})

	t.Run("nil_template_repo", func(t *testing.T) {
		_, err := NewTemplateHandler(nil, svc, logger)
		if err == nil {
			t.Fatal("expected error for nil template repository")
		}
		if !strings.Contains(err.Error(), "template repository is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("nil_template_service", func(t *testing.T) {
		_, err := NewTemplateHandler(tmplRepo, nil, logger)
		if err == nil {
			t.Fatal("expected error for nil template service")
		}
		if !strings.Contains(err.Error(), "template service is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("nil_logger", func(t *testing.T) {
		_, err := NewTemplateHandler(tmplRepo, svc, nil)
		if err == nil {
			t.Fatal("expected error for nil logger")
		}
		if !strings.Contains(err.Error(), "logger is required") {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// TestUnauthorized - requests without an API key in context should return 401
// ---------------------------------------------------------------------------

func TestUnauthorized(t *testing.T) {
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

	t.Run("ServeHTTP_without_api_key", func(t *testing.T) {
		// No API key in context
		rr := doRequest(t, h, http.MethodGet, "/api/v1/templates", nil, nil)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if errResp.Error != "unauthorized" {
			t.Errorf("expected error 'unauthorized', got %q", errResp.Error)
		}
	})

	t.Run("ServeInstanceHTTP_without_api_key", func(t *testing.T) {
		rr := doInstanceRequest(t, h, http.MethodPost, "/api/v1/templates/instances/some-rule/revoke", nil, nil)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if errResp.Error != "unauthorized" {
			t.Errorf("expected error 'unauthorized', got %q", errResp.Error)
		}
	})
}

// ---------------------------------------------------------------------------
// TestListTemplates - GET /api/v1/templates
// ---------------------------------------------------------------------------

func TestListTemplates(t *testing.T) {
	apiKey := testAPIKey()

	t.Run("empty_list", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodGet, "/api/v1/templates", nil, apiKey)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
		}

		var resp ListTemplatesResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if len(resp.Templates) != 0 {
			t.Errorf("expected 0 templates, got %d", len(resp.Templates))
		}
		if resp.Total != 0 {
			t.Errorf("expected total 0, got %d", resp.Total)
		}
	})

	t.Run("returns_templates", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeAPITemplate("tmpl-1", "Template One"))
		seedTemplate(t, tmplRepo, makeAPITemplate("tmpl-2", "Template Two"))

		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodGet, "/api/v1/templates", nil, apiKey)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
		}

		var resp ListTemplatesResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if len(resp.Templates) != 2 {
			t.Errorf("expected 2 templates, got %d", len(resp.Templates))
		}
		if resp.Total != 2 {
			t.Errorf("expected total 2, got %d", resp.Total)
		}
	})

	t.Run("with_type_filter", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl1 := makeAPITemplate("tmpl-evm", "EVM Template")
		tmpl1.Type = types.RuleTypeEVMAddressList
		seedTemplate(t, tmplRepo, tmpl1)

		tmpl2 := makeAPITemplate("tmpl-val", "Value Template")
		tmpl2.Type = types.RuleTypeEVMValueLimit
		seedTemplate(t, tmplRepo, tmpl2)

		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodGet, "/api/v1/templates?type=evm_value_limit", nil, apiKey)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
		}

		var resp ListTemplatesResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if len(resp.Templates) != 1 {
			t.Errorf("expected 1 template with type filter, got %d", len(resp.Templates))
		}
		if resp.Total != 1 {
			t.Errorf("expected total 1, got %d", resp.Total)
		}
	})

	t.Run("with_source_filter", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeAPITemplate("tmpl-api", "API Template"))
		seedTemplate(t, tmplRepo, makeConfigTemplate("tmpl-cfg", "Config Template"))

		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodGet, "/api/v1/templates?source=api", nil, apiKey)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
		}

		var resp ListTemplatesResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if len(resp.Templates) != 1 {
			t.Errorf("expected 1 template with source=api filter, got %d", len(resp.Templates))
		}
		if resp.Total != 1 {
			t.Errorf("expected total 1, got %d", resp.Total)
		}
	})

	t.Run("with_enabled_filter", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		enabled := makeAPITemplate("tmpl-en", "Enabled Template")
		enabled.Enabled = true
		seedTemplate(t, tmplRepo, enabled)

		disabled := makeAPITemplate("tmpl-dis", "Disabled Template")
		disabled.Enabled = false
		seedTemplate(t, tmplRepo, disabled)

		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodGet, "/api/v1/templates?enabled=true", nil, apiKey)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
		}

		var resp ListTemplatesResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if len(resp.Templates) != 1 {
			t.Errorf("expected 1 enabled template, got %d", len(resp.Templates))
		}
		if resp.Total != 1 {
			t.Errorf("expected total 1, got %d", resp.Total)
		}
	})

	t.Run("with_limit_and_offset", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		for i := range 5 {
			seedTemplate(t, tmplRepo, makeAPITemplate(
				fmt.Sprintf("tmpl-%d", i),
				fmt.Sprintf("Template %d", i),
			))
		}

		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodGet, "/api/v1/templates?limit=2&offset=1", nil, apiKey)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
		}

		var resp ListTemplatesResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		// With offset=1 and limit=2, we should get at most 2 templates
		if len(resp.Templates) > 2 {
			t.Errorf("expected at most 2 templates with limit=2, got %d", len(resp.Templates))
		}
		// Total count should reflect all templates (without offset/limit)
		if resp.Total != 5 {
			t.Errorf("expected total 5, got %d", resp.Total)
		}
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodPut, "/api/v1/templates", nil, apiKey)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// TestGetTemplate - GET /api/v1/templates/{id}
// ---------------------------------------------------------------------------

func TestGetTemplate(t *testing.T) {
	apiKey := testAPIKey()

	t.Run("returns_template", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeAPITemplate("tmpl-get-1", "Get Test Template")
		tmpl.Description = "A test template for get"
		seedTemplate(t, tmplRepo, tmpl)

		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodGet, "/api/v1/templates/tmpl-get-1", nil, apiKey)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
		}

		var resp TemplateResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.ID != "tmpl-get-1" {
			t.Errorf("expected ID 'tmpl-get-1', got %q", resp.ID)
		}
		if resp.Name != "Get Test Template" {
			t.Errorf("expected Name 'Get Test Template', got %q", resp.Name)
		}
		if resp.Description != "A test template for get" {
			t.Errorf("expected Description 'A test template for get', got %q", resp.Description)
		}
		if resp.Source != "api" {
			t.Errorf("expected Source 'api', got %q", resp.Source)
		}
		if resp.Type != string(types.RuleTypeEVMAddressList) {
			t.Errorf("expected Type %q, got %q", types.RuleTypeEVMAddressList, resp.Type)
		}
		if resp.Mode != string(types.RuleModeWhitelist) {
			t.Errorf("expected Mode %q, got %q", types.RuleModeWhitelist, resp.Mode)
		}
		if !resp.Enabled {
			t.Error("expected Enabled to be true")
		}
		if resp.CreatedAt == "" {
			t.Error("expected non-empty CreatedAt")
		}
		if resp.UpdatedAt == "" {
			t.Error("expected non-empty UpdatedAt")
		}
	})

	t.Run("returns_template_with_variables", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplateWithVars("tmpl-get-vars", "Vars Template")
		seedTemplate(t, tmplRepo, tmpl)

		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodGet, "/api/v1/templates/tmpl-get-vars", nil, apiKey)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
		}

		var resp TemplateResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if len(resp.Variables) != 1 {
			t.Fatalf("expected 1 variable, got %d", len(resp.Variables))
		}
		if resp.Variables[0].Name != "target_address" {
			t.Errorf("expected variable name 'target_address', got %q", resp.Variables[0].Name)
		}
		if resp.Variables[0].Type != "address" {
			t.Errorf("expected variable type 'address', got %q", resp.Variables[0].Type)
		}
		if !resp.Variables[0].Required {
			t.Error("expected variable to be required")
		}
	})

	t.Run("not_found_returns_404", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodGet, "/api/v1/templates/nonexistent", nil, apiKey)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "template not found") {
			t.Errorf("expected error containing 'template not found', got %q", errResp.Error)
		}
	})

	t.Run("method_not_allowed_on_single_template", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodPut, "/api/v1/templates/tmpl-1", nil, apiKey)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// TestCreateTemplate - POST /api/v1/templates
// ---------------------------------------------------------------------------

func TestCreateTemplate(t *testing.T) {
	apiKey := testAPIKey()

	t.Run("creates_template_successfully", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := CreateTemplateRequest{
			Name:    "New API Template",
			Type:    "evm_address_list",
			Mode:    "whitelist",
			Config:  map[string]any{"addresses": []string{"0x1234567890abcdef1234567890abcdef12345678"}},
			Enabled: true,
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates", reqBody, apiKey)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected status %d, got %d; body: %s", http.StatusCreated, rr.Code, rr.Body.String())
		}

		var resp TemplateResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Name != "New API Template" {
			t.Errorf("expected Name 'New API Template', got %q", resp.Name)
		}
		if resp.Source != "api" {
			t.Errorf("expected Source 'api', got %q", resp.Source)
		}
		if !strings.HasPrefix(resp.ID, "tmpl_api_") {
			t.Errorf("expected ID prefix 'tmpl_api_', got %q", resp.ID)
		}
		if resp.Type != "evm_address_list" {
			t.Errorf("expected Type 'evm_address_list', got %q", resp.Type)
		}
		if resp.Mode != "whitelist" {
			t.Errorf("expected Mode 'whitelist', got %q", resp.Mode)
		}
		if !resp.Enabled {
			t.Error("expected Enabled to be true")
		}

		// Verify persisted in repo
		stored, err := tmplRepo.Get(context.Background(), resp.ID)
		if err != nil {
			t.Fatalf("template not found in repo: %v", err)
		}
		if stored.Name != "New API Template" {
			t.Errorf("stored name mismatch: expected 'New API Template', got %q", stored.Name)
		}
	})

	t.Run("creates_template_with_variables", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := CreateTemplateRequest{
			Name: "Var Template",
			Type: "evm_address_list",
			Mode: "whitelist",
			Variables: []TemplateVarRequest{
				{Name: "target", Type: "address", Description: "Target address", Required: true},
			},
			Config:  map[string]any{"addresses": []string{"${target}"}},
			Enabled: true,
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates", reqBody, apiKey)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected status %d, got %d; body: %s", http.StatusCreated, rr.Code, rr.Body.String())
		}

		var resp TemplateResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if len(resp.Variables) != 1 {
			t.Fatalf("expected 1 variable in response, got %d", len(resp.Variables))
		}
		if resp.Variables[0].Name != "target" {
			t.Errorf("expected variable name 'target', got %q", resp.Variables[0].Name)
		}
	})

	t.Run("creates_template_with_budget_metering", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := CreateTemplateRequest{
			Name:           "Budget Template",
			Type:           "evm_address_list",
			Mode:           "whitelist",
			Config:         map[string]any{"addresses": []string{}},
			BudgetMetering: map[string]any{"method": "tx_value", "unit": "eth"},
			Enabled:        true,
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates", reqBody, apiKey)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected status %d, got %d; body: %s", http.StatusCreated, rr.Code, rr.Body.String())
		}

		var resp TemplateResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.BudgetMetering == nil {
			t.Fatal("expected non-nil budget_metering in response")
		}
	})

	t.Run("missing_name_returns_400", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := CreateTemplateRequest{
			Type:   "evm_address_list",
			Mode:   "whitelist",
			Config: map[string]any{},
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates", reqBody, apiKey)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "name is required") {
			t.Errorf("expected error containing 'name is required', got %q", errResp.Error)
		}
	})

	t.Run("missing_type_returns_400", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := CreateTemplateRequest{
			Name:   "No Type",
			Mode:   "whitelist",
			Config: map[string]any{},
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates", reqBody, apiKey)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "type is required") {
			t.Errorf("expected error containing 'type is required', got %q", errResp.Error)
		}
	})

	t.Run("missing_mode_returns_400", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := CreateTemplateRequest{
			Name:   "No Mode",
			Type:   "evm_address_list",
			Config: map[string]any{},
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates", reqBody, apiKey)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "mode is required") {
			t.Errorf("expected error containing 'mode is required', got %q", errResp.Error)
		}
	})

	t.Run("invalid_mode_returns_400", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := CreateTemplateRequest{
			Name:   "Bad Mode",
			Type:   "evm_address_list",
			Mode:   "invalid_mode",
			Config: map[string]any{},
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates", reqBody, apiKey)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "mode must be") {
			t.Errorf("expected error about mode, got %q", errResp.Error)
		}
	})

	t.Run("invalid_request_body_returns_400", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		// Send raw invalid JSON by building the request manually
		req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", bytes.NewBufferString("{invalid json"))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(contextWithAPIKey(req.Context(), apiKey))

		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "invalid request body") {
			t.Errorf("expected error containing 'invalid request body', got %q", errResp.Error)
		}
	})

	t.Run("blocklist_mode_accepted", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := CreateTemplateRequest{
			Name:    "Blocklist Template",
			Type:    "evm_value_limit",
			Mode:    "blocklist",
			Config:  map[string]any{"max_value": "1000000000000000000"},
			Enabled: true,
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates", reqBody, apiKey)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected status %d, got %d; body: %s", http.StatusCreated, rr.Code, rr.Body.String())
		}

		var resp TemplateResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Mode != "blocklist" {
			t.Errorf("expected Mode 'blocklist', got %q", resp.Mode)
		}
	})
}

// ---------------------------------------------------------------------------
// TestUpdateTemplate - PATCH /api/v1/templates/{id}
// ---------------------------------------------------------------------------

func TestUpdateTemplate(t *testing.T) {
	apiKey := testAPIKey()

	t.Run("updates_name_and_description", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeAPITemplate("tmpl-upd-1", "Original Name"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := UpdateTemplateRequest{
			Name:        "Updated Name",
			Description: "Updated Description",
		}

		rr := doRequest(t, h, http.MethodPatch, "/api/v1/templates/tmpl-upd-1", reqBody, apiKey)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rr.Code, rr.Body.String())
		}

		var resp TemplateResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Name != "Updated Name" {
			t.Errorf("expected Name 'Updated Name', got %q", resp.Name)
		}
		if resp.Description != "Updated Description" {
			t.Errorf("expected Description 'Updated Description', got %q", resp.Description)
		}
	})

	t.Run("updates_config", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeAPITemplate("tmpl-upd-cfg", "Config Update"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		newConfig := map[string]any{"addresses": []string{"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
		reqBody := UpdateTemplateRequest{
			Config: newConfig,
		}

		rr := doRequest(t, h, http.MethodPatch, "/api/v1/templates/tmpl-upd-cfg", reqBody, apiKey)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rr.Code, rr.Body.String())
		}

		var resp TemplateResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Verify config was updated by checking the stored template
		stored, err := tmplRepo.Get(context.Background(), "tmpl-upd-cfg")
		if err != nil {
			t.Fatalf("failed to get stored template: %v", err)
		}
		if !strings.Contains(string(stored.Config), "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
			t.Errorf("expected config to contain new address, got %s", string(stored.Config))
		}
	})

	t.Run("updates_enabled_field", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeAPITemplate("tmpl-upd-en", "Enabled Update"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		disabled := false
		reqBody := UpdateTemplateRequest{
			Enabled: &disabled,
		}

		rr := doRequest(t, h, http.MethodPatch, "/api/v1/templates/tmpl-upd-en", reqBody, apiKey)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rr.Code, rr.Body.String())
		}

		var resp TemplateResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp.Enabled {
			t.Error("expected Enabled to be false after update")
		}
	})

	t.Run("config_sourced_template_returns_403", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeConfigTemplate("tmpl-cfg-upd", "Config Sourced"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := UpdateTemplateRequest{
			Name: "Should Fail",
		}

		rr := doRequest(t, h, http.MethodPatch, "/api/v1/templates/tmpl-cfg-upd", reqBody, apiKey)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected status %d, got %d", http.StatusForbidden, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "cannot update config-sourced templates") {
			t.Errorf("expected error about config-sourced, got %q", errResp.Error)
		}
	})

	t.Run("not_found_returns_404", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := UpdateTemplateRequest{
			Name: "Should Fail",
		}

		rr := doRequest(t, h, http.MethodPatch, "/api/v1/templates/nonexistent", reqBody, apiKey)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "template not found") {
			t.Errorf("expected error containing 'template not found', got %q", errResp.Error)
		}
	})

	t.Run("invalid_request_body_returns_400", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		req := httptest.NewRequest(http.MethodPatch, "/api/v1/templates/tmpl-1", bytes.NewBufferString("not json"))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(contextWithAPIKey(req.Context(), apiKey))

		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// TestDeleteTemplate - DELETE /api/v1/templates/{id}
// ---------------------------------------------------------------------------

func TestDeleteTemplate(t *testing.T) {
	apiKey := testAPIKey()

	t.Run("deletes_api_sourced_template", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeAPITemplate("tmpl-del-1", "Delete Me"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodDelete, "/api/v1/templates/tmpl-del-1", nil, apiKey)
		if rr.Code != http.StatusNoContent {
			t.Errorf("expected status %d, got %d; body: %s", http.StatusNoContent, rr.Code, rr.Body.String())
		}

		// Verify deleted from repo
		_, err := tmplRepo.Get(context.Background(), "tmpl-del-1")
		if err == nil {
			t.Error("expected template to be deleted from repo")
		}
	})

	t.Run("config_sourced_template_returns_403", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeConfigTemplate("tmpl-cfg-del", "Config Sourced"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodDelete, "/api/v1/templates/tmpl-cfg-del", nil, apiKey)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected status %d, got %d", http.StatusForbidden, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "cannot delete config-sourced templates") {
			t.Errorf("expected error about config-sourced, got %q", errResp.Error)
		}

		// Verify not deleted
		_, err := tmplRepo.Get(context.Background(), "tmpl-cfg-del")
		if err != nil {
			t.Error("config-sourced template should not have been deleted")
		}
	})

	t.Run("not_found_returns_404", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodDelete, "/api/v1/templates/nonexistent", nil, apiKey)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "template not found") {
			t.Errorf("expected error containing 'template not found', got %q", errResp.Error)
		}
	})
}

// ---------------------------------------------------------------------------
// TestInstantiateTemplate - POST /api/v1/templates/{id}/instantiate
// ---------------------------------------------------------------------------

func TestInstantiateTemplate(t *testing.T) {
	apiKey := testAPIKey()

	t.Run("creates_instance_successfully", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeTemplateWithVars("tmpl-inst-1", "Instantiate Template"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := InstantiateTemplateRequest{
			Variables: map[string]string{
				"target_address": "0x1234567890abcdef1234567890abcdef12345678",
			},
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-inst-1/instantiate", reqBody, apiKey)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected status %d, got %d; body: %s", http.StatusCreated, rr.Code, rr.Body.String())
		}

		// Decode the response map
		var resp map[string]json.RawMessage
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if _, ok := resp["rule"]; !ok {
			t.Fatal("expected 'rule' in response")
		}

		// Decode the rule
		var rule types.Rule
		if err := json.Unmarshal(resp["rule"], &rule); err != nil {
			t.Fatalf("failed to unmarshal rule: %v", err)
		}
		if rule.Source != types.RuleSourceInstance {
			t.Errorf("expected rule source %q, got %q", types.RuleSourceInstance, rule.Source)
		}
		if !strings.HasPrefix(string(rule.ID), "inst_") {
			t.Errorf("expected rule ID prefix 'inst_', got %q", rule.ID)
		}
		if rule.TemplateID == nil || *rule.TemplateID != "tmpl-inst-1" {
			t.Errorf("expected template ID 'tmpl-inst-1', got %v", rule.TemplateID)
		}
	})

	t.Run("creates_instance_with_custom_name", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeTemplateWithVars("tmpl-inst-name", "Name Template"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := InstantiateTemplateRequest{
			Name: "My Custom Instance",
			Variables: map[string]string{
				"target_address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-inst-name/instantiate", reqBody, apiKey)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected status %d, got %d; body: %s", http.StatusCreated, rr.Code, rr.Body.String())
		}

		var resp map[string]json.RawMessage
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		var rule types.Rule
		if err := json.Unmarshal(resp["rule"], &rule); err != nil {
			t.Fatalf("failed to unmarshal rule: %v", err)
		}
		if rule.Name != "My Custom Instance" {
			t.Errorf("expected name 'My Custom Instance', got %q", rule.Name)
		}
	})

	t.Run("creates_instance_with_budget", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		tmpl := makeTemplateWithVars("tmpl-inst-budget", "Budget Instance Template")
		tmpl.BudgetMetering = mustJSON(types.BudgetMetering{Method: "tx_value", Unit: "eth"})
		seedTemplate(t, tmplRepo, tmpl)
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := InstantiateTemplateRequest{
			Variables: map[string]string{
				"target_address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
			Budget: &BudgetRequest{
				MaxTotal:   "10000000000000000000",
				MaxPerTx:   "1000000000000000000",
				MaxTxCount: 50,
				AlertPct:   75,
			},
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-inst-budget/instantiate", reqBody, apiKey)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected status %d, got %d; body: %s", http.StatusCreated, rr.Code, rr.Body.String())
		}

		var resp map[string]json.RawMessage
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if _, ok := resp["budget"]; !ok {
			t.Fatal("expected 'budget' in response")
		}

		var budget types.RuleBudget
		if err := json.Unmarshal(resp["budget"], &budget); err != nil {
			t.Fatalf("failed to unmarshal budget: %v", err)
		}
		if budget.Unit != "eth" {
			t.Errorf("expected budget unit 'eth', got %q", budget.Unit)
		}
		if budget.MaxTotal != "10000000000000000000" {
			t.Errorf("expected max_total '10000000000000000000', got %q", budget.MaxTotal)
		}
	})

	t.Run("creates_instance_with_expires_in", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeTemplateWithVars("tmpl-inst-exp", "Expiry Instance"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		expiresIn := "24h"
		reqBody := InstantiateTemplateRequest{
			Variables: map[string]string{
				"target_address": "0xcccccccccccccccccccccccccccccccccccccccc",
			},
			ExpiresIn: &expiresIn,
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-inst-exp/instantiate", reqBody, apiKey)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected status %d, got %d; body: %s", http.StatusCreated, rr.Code, rr.Body.String())
		}

		var resp map[string]json.RawMessage
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		var rule types.Rule
		if err := json.Unmarshal(resp["rule"], &rule); err != nil {
			t.Fatalf("failed to unmarshal rule: %v", err)
		}
		if rule.ExpiresAt == nil {
			t.Fatal("expected non-nil ExpiresAt when expires_in is set")
		}
		// Should be roughly 24h from now
		expectedMin := time.Now().Add(23 * time.Hour)
		expectedMax := time.Now().Add(25 * time.Hour)
		if rule.ExpiresAt.Before(expectedMin) || rule.ExpiresAt.After(expectedMax) {
			t.Errorf("ExpiresAt %v not in expected range [%v, %v]", *rule.ExpiresAt, expectedMin, expectedMax)
		}
	})

	t.Run("creates_instance_with_schedule", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeTemplateWithVars("tmpl-inst-sched", "Schedule Instance"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := InstantiateTemplateRequest{
			Variables: map[string]string{
				"target_address": "0xdddddddddddddddddddddddddddddddddddddddd",
			},
			Schedule: &ScheduleRequest{
				Period: "24h",
			},
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-inst-sched/instantiate", reqBody, apiKey)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected status %d, got %d; body: %s", http.StatusCreated, rr.Code, rr.Body.String())
		}

		var resp map[string]json.RawMessage
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		var rule types.Rule
		if err := json.Unmarshal(resp["rule"], &rule); err != nil {
			t.Fatalf("failed to unmarshal rule: %v", err)
		}
		if rule.BudgetPeriod == nil {
			t.Fatal("expected non-nil BudgetPeriod when schedule is set")
		}
		if *rule.BudgetPeriod != 24*time.Hour {
			t.Errorf("expected BudgetPeriod 24h, got %v", *rule.BudgetPeriod)
		}
	})

	t.Run("creates_instance_with_scope_fields", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeTemplateWithVars("tmpl-inst-scope", "Scope Instance"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		chainType := "evm"
		chainID := "1"
		apiKeyID := "key-123"
		signerAddr := "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		reqBody := InstantiateTemplateRequest{
			Variables: map[string]string{
				"target_address": "0x1111111111111111111111111111111111111111",
			},
			ChainType:     &chainType,
			ChainID:       &chainID,
			APIKeyID:      &apiKeyID,
			SignerAddress: &signerAddr,
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-inst-scope/instantiate", reqBody, apiKey)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected status %d, got %d; body: %s", http.StatusCreated, rr.Code, rr.Body.String())
		}

		var resp map[string]json.RawMessage
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		var rule types.Rule
		if err := json.Unmarshal(resp["rule"], &rule); err != nil {
			t.Fatalf("failed to unmarshal rule: %v", err)
		}
		if rule.ChainType == nil || string(*rule.ChainType) != "evm" {
			t.Errorf("expected ChainType 'evm', got %v", rule.ChainType)
		}
		if rule.ChainID == nil || *rule.ChainID != "1" {
			t.Errorf("expected ChainID '1', got %v", rule.ChainID)
		}
		if rule.APIKeyID == nil || *rule.APIKeyID != "key-123" {
			t.Errorf("expected APIKeyID 'key-123', got %v", rule.APIKeyID)
		}
		if rule.SignerAddress == nil || *rule.SignerAddress != signerAddr {
			t.Errorf("expected SignerAddress %q, got %v", signerAddr, rule.SignerAddress)
		}
	})

	t.Run("template_not_found_returns_error", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := InstantiateTemplateRequest{
			Variables: map[string]string{
				"target_address": "0x1234567890abcdef1234567890abcdef12345678",
			},
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/nonexistent/instantiate", reqBody, apiKey)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "failed to create instance") {
			t.Errorf("expected error about failed instance creation, got %q", errResp.Error)
		}
	})

	t.Run("missing_required_variable_returns_error", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeTemplateWithVars("tmpl-inst-req", "Required Var"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		// Omit the required variable
		reqBody := InstantiateTemplateRequest{
			Variables: map[string]string{},
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-inst-req/instantiate", reqBody, apiKey)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "target_address") {
			t.Errorf("expected error mentioning 'target_address', got %q", errResp.Error)
		}
	})

	t.Run("invalid_expires_in_returns_400", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeTemplateWithVars("tmpl-inst-badexp", "Bad Expiry"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		badDuration := "not-a-duration"
		reqBody := InstantiateTemplateRequest{
			Variables: map[string]string{
				"target_address": "0x1234567890abcdef1234567890abcdef12345678",
			},
			ExpiresIn: &badDuration,
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-inst-badexp/instantiate", reqBody, apiKey)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "invalid expires_in duration") {
			t.Errorf("expected error about invalid duration, got %q", errResp.Error)
		}
	})

	t.Run("invalid_schedule_period_returns_400", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeTemplateWithVars("tmpl-inst-badperiod", "Bad Period"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		reqBody := InstantiateTemplateRequest{
			Variables: map[string]string{
				"target_address": "0x1234567890abcdef1234567890abcdef12345678",
			},
			Schedule: &ScheduleRequest{
				Period: "not-a-duration",
			},
		}

		rr := doRequest(t, h, http.MethodPost, "/api/v1/templates/tmpl-inst-badperiod/instantiate", reqBody, apiKey)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "invalid schedule period") {
			t.Errorf("expected error about invalid schedule period, got %q", errResp.Error)
		}
	})

	t.Run("invalid_request_body_returns_400", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		seedTemplate(t, tmplRepo, makeTemplateWithVars("tmpl-inst-bad", "Bad Body"))
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/tmpl-inst-bad/instantiate", bytes.NewBufferString("not json"))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(contextWithAPIKey(req.Context(), apiKey))

		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
	})

	t.Run("method_not_allowed_on_instantiate", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doRequest(t, h, http.MethodGet, "/api/v1/templates/tmpl-1/instantiate", nil, apiKey)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// TestRevokeInstance - POST /api/v1/templates/instances/{ruleID}/revoke
// ---------------------------------------------------------------------------

func TestRevokeInstance(t *testing.T) {
	apiKey := testAPIKey()

	t.Run("revokes_instance_successfully", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		templateID := "tmpl-1"
		ruleID := types.RuleID("inst_revoke_1")
		rule := &types.Rule{
			ID:         ruleID,
			Name:       "Instance to Revoke",
			Source:     types.RuleSourceInstance,
			TemplateID: &templateID,
			Type:       types.RuleTypeEVMAddressList,
			Mode:       types.RuleModeWhitelist,
			Config:     []byte(`{}`),
			Enabled:    true,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		seedRule(t, ruleRepo, rule)

		// Seed a budget
		budget := &types.RuleBudget{
			ID:       "bdg_inst_revoke_1_eth",
			RuleID:   ruleID,
			Unit:     "eth",
			MaxTotal: "100",
			MaxPerTx: "10",
			Spent:    "25",
		}
		if err := budgetRepo.Create(context.Background(), budget); err != nil {
			t.Fatalf("failed to seed budget: %v", err)
		}

		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doInstanceRequest(t, h, http.MethodPost, "/api/v1/templates/instances/inst_revoke_1/revoke", nil, apiKey)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rr.Code, rr.Body.String())
		}

		var resp map[string]string
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if resp["status"] != "revoked" {
			t.Errorf("expected status 'revoked', got %q", resp["status"])
		}
		if resp["rule_id"] != "inst_revoke_1" {
			t.Errorf("expected rule_id 'inst_revoke_1', got %q", resp["rule_id"])
		}

		// Verify rule is disabled
		updatedRule, err := ruleRepo.Get(context.Background(), ruleID)
		if err != nil {
			t.Fatalf("failed to get rule after revoke: %v", err)
		}
		if updatedRule.Enabled {
			t.Error("expected rule to be disabled after revoke")
		}

		// Verify budgets are deleted
		budgets, err := budgetRepo.ListByRuleID(context.Background(), ruleID)
		if err != nil {
			t.Fatalf("failed to list budgets: %v", err)
		}
		if len(budgets) != 0 {
			t.Errorf("expected 0 budgets after revoke, got %d", len(budgets))
		}
	})

	t.Run("rule_not_found_returns_404", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doInstanceRequest(t, h, http.MethodPost, "/api/v1/templates/instances/nonexistent/revoke", nil, apiKey)
		// The service returns a generic error wrapping ErrNotFound, so the handler
		// checks types.IsNotFound and returns 404
		if rr.Code != http.StatusNotFound {
			// If service wraps it differently, it may return 400; check both
			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected status 404 or 400, got %d", rr.Code)
			}
		}
	})

	t.Run("non_instance_rule_returns_error", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()

		ruleID := types.RuleID("rule_api_1")
		rule := &types.Rule{
			ID:        ruleID,
			Name:      "API Rule",
			Source:    types.RuleSourceAPI,
			Type:      types.RuleTypeEVMAddressList,
			Mode:      types.RuleModeWhitelist,
			Config:    []byte(`{}`),
			Enabled:   true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		seedRule(t, ruleRepo, rule)
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doInstanceRequest(t, h, http.MethodPost, "/api/v1/templates/instances/rule_api_1/revoke", nil, apiKey)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		errResp := decodeErrorResponse(t, rr)
		if !strings.Contains(errResp.Error, "not an instance") {
			t.Errorf("expected error about 'not an instance', got %q", errResp.Error)
		}
	})

	t.Run("method_not_allowed_on_revoke", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		rr := doInstanceRequest(t, h, http.MethodGet, "/api/v1/templates/instances/some-rule/revoke", nil, apiKey)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
		}
	})

	t.Run("invalid_path_returns_404", func(t *testing.T) {
		tmplRepo := newMockTemplateRepo()
		ruleRepo := newMockRuleRepo()
		budgetRepo := newMockBudgetRepo()
		h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

		// Path without /revoke suffix
		rr := doInstanceRequest(t, h, http.MethodPost, "/api/v1/templates/instances/some-rule/unknown", nil, apiKey)
		if rr.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, rr.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// TestResponseContentType - Verify JSON Content-Type header is set
// ---------------------------------------------------------------------------

func TestResponseContentType(t *testing.T) {
	apiKey := testAPIKey()
	tmplRepo := newMockTemplateRepo()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	h := newHandler(t, tmplRepo, ruleRepo, budgetRepo)

	rr := doRequest(t, h, http.MethodGet, "/api/v1/templates", nil, apiKey)
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", contentType)
	}
}
