package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// Error-injecting mock template repository
// ---------------------------------------------------------------------------

// errTemplateRepo wraps mockTemplateRepo but can inject errors for specific
// operations. This allows testing error branches in the handler that the
// basic in-memory mock cannot trigger.
type errTemplateRepo struct {
	mu        sync.RWMutex
	templates map[string]*types.RuleTemplate

	listErr   error
	countErr  error
	getErr    error
	createErr error
	updateErr error
	deleteErr error
}

func newErrTemplateRepo() *errTemplateRepo {
	return &errTemplateRepo{templates: make(map[string]*types.RuleTemplate)}
}

func (r *errTemplateRepo) Create(_ context.Context, tmpl *types.RuleTemplate) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.templates[tmpl.ID]; exists {
		return types.ErrAlreadyExists
	}
	cp := *tmpl
	r.templates[tmpl.ID] = &cp
	return nil
}

func (r *errTemplateRepo) Get(_ context.Context, id string) (*types.RuleTemplate, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	tmpl, ok := r.templates[id]
	if !ok {
		return nil, types.ErrNotFound
	}
	cp := *tmpl
	return &cp, nil
}

func (r *errTemplateRepo) GetByName(_ context.Context, name string) (*types.RuleTemplate, error) {
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

func (r *errTemplateRepo) Update(_ context.Context, tmpl *types.RuleTemplate) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.templates[tmpl.ID]; !exists {
		return types.ErrNotFound
	}
	cp := *tmpl
	r.templates[tmpl.ID] = &cp
	return nil
}

func (r *errTemplateRepo) Delete(_ context.Context, id string) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.templates[id]; !exists {
		return types.ErrNotFound
	}
	delete(r.templates, id)
	return nil
}

func (r *errTemplateRepo) List(_ context.Context, filter storage.TemplateFilter) ([]*types.RuleTemplate, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*types.RuleTemplate
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
		cp := *tmpl
		out = append(out, &cp)
	}
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

func (r *errTemplateRepo) Count(_ context.Context, filter storage.TemplateFilter) (int, error) {
	if r.countErr != nil {
		return 0, r.countErr
	}
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

// seed inserts a template directly into the error repo
func (r *errTemplateRepo) seed(tmpl *types.RuleTemplate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *tmpl
	r.templates[tmpl.ID] = &cp
}

// ---------------------------------------------------------------------------
// Helper to build handler with errTemplateRepo
// ---------------------------------------------------------------------------

func newErrHandler(t *testing.T, tmplRepo *errTemplateRepo) *TemplateHandler {
	t.Helper()
	ruleRepo := newMockRuleRepo()
	budgetRepo := newMockBudgetRepo()
	svc, err := service.NewTemplateService(tmplRepo, ruleRepo, budgetRepo, newTestLogger())
	if err != nil {
		t.Fatalf("failed to create TemplateService: %v", err)
	}
	h, err := NewTemplateHandler(tmplRepo, svc, newTestLogger())
	if err != nil {
		t.Fatalf("failed to create TemplateHandler: %v", err)
	}
	return h
}

func doErrRequest(t *testing.T, h *TemplateHandler, method, path string, body any, apiKey *types.APIKey) *httptest.ResponseRecorder {
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
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// Tests: listTemplates error branches
// ---------------------------------------------------------------------------

func TestListTemplates_ListRepoError(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	repo.listErr = fmt.Errorf("connection refused")
	h := newErrHandler(t, repo)

	rr := doErrRequest(t, h, http.MethodGet, "/api/v1/templates", nil, apiKey)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "failed to list templates")
}

func TestListTemplates_CountRepoError(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	// List succeeds but Count fails
	repo.countErr = fmt.Errorf("count query timeout")
	h := newErrHandler(t, repo)

	rr := doErrRequest(t, h, http.MethodGet, "/api/v1/templates", nil, apiKey)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "failed to count templates")
}

func TestListTemplates_LimitClamping(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	h := newErrHandler(t, repo)

	// limit > 1000 should be clamped to 1000
	rr := doErrRequest(t, h, http.MethodGet, "/api/v1/templates?limit=5000", nil, apiKey)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Invalid limit (non-numeric) should use default
	rr2 := doErrRequest(t, h, http.MethodGet, "/api/v1/templates?limit=abc", nil, apiKey)
	assert.Equal(t, http.StatusOK, rr2.Code)

	// Negative limit should use default
	rr3 := doErrRequest(t, h, http.MethodGet, "/api/v1/templates?limit=-1", nil, apiKey)
	assert.Equal(t, http.StatusOK, rr3.Code)

	// Invalid offset (non-numeric) should use default (0)
	rr4 := doErrRequest(t, h, http.MethodGet, "/api/v1/templates?offset=abc", nil, apiKey)
	assert.Equal(t, http.StatusOK, rr4.Code)

	// Negative offset should use default (0)
	rr5 := doErrRequest(t, h, http.MethodGet, "/api/v1/templates?offset=-1", nil, apiKey)
	assert.Equal(t, http.StatusOK, rr5.Code)
}

// ---------------------------------------------------------------------------
// Tests: getTemplate error branches
// ---------------------------------------------------------------------------

func TestGetTemplate_InternalError(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	repo.getErr = fmt.Errorf("database corruption")
	h := newErrHandler(t, repo)

	rr := doErrRequest(t, h, http.MethodGet, "/api/v1/templates/some-id", nil, apiKey)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "failed to get template")
}

// ---------------------------------------------------------------------------
// Tests: createTemplate error branches
// ---------------------------------------------------------------------------

func TestCreateTemplate_InvalidType(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	h := newErrHandler(t, repo)

	reqBody := CreateTemplateRequest{
		Name:   "Bad Type Template",
		Type:   "completely_invalid_type",
		Mode:   "whitelist",
		Config: map[string]any{"key": "value"},
	}

	rr := doErrRequest(t, h, http.MethodPost, "/api/v1/templates", reqBody, apiKey)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "invalid rule type")
}

func TestCreateTemplate_RepoCreateError(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	repo.createErr = fmt.Errorf("disk full")
	h := newErrHandler(t, repo)

	reqBody := CreateTemplateRequest{
		Name:    "Will Fail Template",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Config:  map[string]any{"addresses": []string{}},
		Enabled: true,
	}

	rr := doErrRequest(t, h, http.MethodPost, "/api/v1/templates", reqBody, apiKey)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "failed to create template")
}

func TestCreateTemplate_WithTestVariables(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	h := newErrHandler(t, repo)

	reqBody := CreateTemplateRequest{
		Name:          "Template With Test Vars",
		Type:          "evm_address_list",
		Mode:          "whitelist",
		Config:        map[string]any{"addresses": []string{"${target}"}},
		TestVariables: map[string]string{"target": "0x1234567890abcdef1234567890abcdef12345678"},
		Enabled:       true,
	}

	rr := doErrRequest(t, h, http.MethodPost, "/api/v1/templates", reqBody, apiKey)
	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp TemplateResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.True(t, strings.HasPrefix(resp.ID, "tmpl_api_"))
}

// ---------------------------------------------------------------------------
// Tests: updateTemplate error branches
// ---------------------------------------------------------------------------

func TestUpdateTemplate_InternalGetError(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	repo.getErr = fmt.Errorf("connection reset")
	h := newErrHandler(t, repo)

	reqBody := UpdateTemplateRequest{
		Name: "Updated",
	}

	rr := doErrRequest(t, h, http.MethodPatch, "/api/v1/templates/some-id", reqBody, apiKey)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "failed to get template")
}

func TestUpdateTemplate_RepoUpdateError(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	tmpl := makeAPITemplate("tmpl-upd-fail", "Update Fail")
	repo.seed(tmpl)
	repo.updateErr = fmt.Errorf("constraint violation")
	h := newErrHandler(t, repo)

	reqBody := UpdateTemplateRequest{
		Name: "New Name",
	}

	rr := doErrRequest(t, h, http.MethodPatch, "/api/v1/templates/tmpl-upd-fail", reqBody, apiKey)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "failed to update template")
}

// ---------------------------------------------------------------------------
// Tests: deleteTemplate error branches
// ---------------------------------------------------------------------------

func TestDeleteTemplate_InternalGetError(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	repo.getErr = fmt.Errorf("storage unavailable")
	h := newErrHandler(t, repo)

	rr := doErrRequest(t, h, http.MethodDelete, "/api/v1/templates/some-id", nil, apiKey)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "failed to get template")
}

func TestDeleteTemplate_RepoDeleteError(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	tmpl := makeAPITemplate("tmpl-del-fail", "Delete Fail")
	repo.seed(tmpl)
	repo.deleteErr = fmt.Errorf("foreign key constraint")
	h := newErrHandler(t, repo)

	rr := doErrRequest(t, h, http.MethodDelete, "/api/v1/templates/tmpl-del-fail", nil, apiKey)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "failed to delete template")
}

func TestDeleteTemplate_RepoDeleteNotFoundRace(t *testing.T) {
	// Simulate a race: Get succeeds (template exists) but by the time Delete
	// is called, the template was already deleted by another request.
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	tmpl := makeAPITemplate("tmpl-del-race", "Delete Race")
	repo.seed(tmpl)
	repo.deleteErr = types.ErrNotFound
	h := newErrHandler(t, repo)

	rr := doErrRequest(t, h, http.MethodDelete, "/api/v1/templates/tmpl-del-race", nil, apiKey)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "template not found")
}

// ---------------------------------------------------------------------------
// Tests: instantiateTemplate - invalid body via raw bytes
// ---------------------------------------------------------------------------

func TestInstantiateTemplate_MethodNotAllowedOnInstantiate(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	h := newErrHandler(t, repo)

	// PUT on /instantiate should be method not allowed
	rr := doErrRequest(t, h, http.MethodPut, "/api/v1/templates/some-id/instantiate", nil, apiKey)
	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

// ---------------------------------------------------------------------------
// Tests: toTemplateResponse with budget metering
// ---------------------------------------------------------------------------

func TestTemplateResponse_WithBudgetMetering(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	tmpl := makeAPITemplate("tmpl-bm", "Budget Metering Template")
	tmpl.BudgetMetering = []byte(`{"method":"tx_value","unit":"eth"}`)
	repo.seed(tmpl)
	h := newErrHandler(t, repo)

	rr := doErrRequest(t, h, http.MethodGet, "/api/v1/templates/tmpl-bm", nil, apiKey)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp TemplateResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.NotNil(t, resp.BudgetMetering)

	var bm map[string]string
	require.NoError(t, json.Unmarshal(resp.BudgetMetering, &bm))
	assert.Equal(t, "tx_value", bm["method"])
	assert.Equal(t, "eth", bm["unit"])
}

// ---------------------------------------------------------------------------
// Tests: Verify existing handler functions with edge cases
// ---------------------------------------------------------------------------

func TestCreateTemplate_WithDescriptionField(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	h := newErrHandler(t, repo)

	reqBody := CreateTemplateRequest{
		Name:        "Template With Description",
		Description: "A detailed description for this template",
		Type:        "evm_address_list",
		Mode:        "whitelist",
		Config:      map[string]any{"addresses": []string{"0x1234567890abcdef1234567890abcdef12345678"}},
		Enabled:     true,
	}

	rr := doErrRequest(t, h, http.MethodPost, "/api/v1/templates", reqBody, apiKey)
	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp TemplateResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "A detailed description for this template", resp.Description)
}

func TestUpdateTemplate_InvalidBodyPatch(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	tmpl := makeAPITemplate("tmpl-patch-bad", "Bad Patch")
	repo.seed(tmpl)
	h := newErrHandler(t, repo)

	// Send raw invalid JSON
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/templates/tmpl-patch-bad",
		bytes.NewBufferString("{broken json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	assert.Contains(t, errResp.Error, "invalid request body")
}

// ---------------------------------------------------------------------------
// Tests: Template list with high limit clamping
// ---------------------------------------------------------------------------

func TestListTemplates_HighLimitClampedTo1000(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()

	// Seed some templates
	for i := 0; i < 3; i++ {
		repo.seed(makeAPITemplate(
			fmt.Sprintf("tmpl-clamp-%d", i),
			fmt.Sprintf("Clamp Template %d", i),
		))
	}
	h := newErrHandler(t, repo)

	rr := doErrRequest(t, h, http.MethodGet, "/api/v1/templates?limit=9999", nil, apiKey)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp ListTemplatesResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, 3, len(resp.Templates))
	assert.Equal(t, 3, resp.Total)
}

// ---------------------------------------------------------------------------
// Tests: Template variable handling in toTemplateResponse
// ---------------------------------------------------------------------------

func TestTemplateResponse_VariablesWithInvalidJSON(t *testing.T) {
	// If variables JSON is corrupted, toTemplateResponse should still return
	// a response (just without variables). This covers the Unmarshal error branch.
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	tmpl := makeAPITemplate("tmpl-bad-vars", "Bad Vars Template")
	tmpl.Variables = []byte(`{not valid json}`)
	repo.seed(tmpl)
	h := newErrHandler(t, repo)

	rr := doErrRequest(t, h, http.MethodGet, "/api/v1/templates/tmpl-bad-vars", nil, apiKey)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp TemplateResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "tmpl-bad-vars", resp.ID)
	// Variables should be nil/empty since unmarshal failed
	assert.Nil(t, resp.Variables)
}

func TestTemplateResponse_EmptyVariables(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	tmpl := makeAPITemplate("tmpl-no-vars", "No Vars Template")
	tmpl.Variables = nil
	repo.seed(tmpl)
	h := newErrHandler(t, repo)

	rr := doErrRequest(t, h, http.MethodGet, "/api/v1/templates/tmpl-no-vars", nil, apiKey)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp TemplateResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Nil(t, resp.Variables)
}

func TestTemplateResponse_EmptyBudgetMetering(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	tmpl := makeAPITemplate("tmpl-no-bm", "No Budget Metering")
	tmpl.BudgetMetering = nil
	repo.seed(tmpl)
	h := newErrHandler(t, repo)

	rr := doErrRequest(t, h, http.MethodGet, "/api/v1/templates/tmpl-no-bm", nil, apiKey)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp TemplateResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Nil(t, resp.BudgetMetering)
}

// ---------------------------------------------------------------------------
// Tests: Various createTemplate validation branches
// ---------------------------------------------------------------------------

func TestCreateTemplate_AllValidRuleTypes(t *testing.T) {
	apiKey := testAPIKey()
	validTypes := []string{
		"evm_address_list",
		"evm_value_limit",
		"signer_restriction",
		"chain_restriction",
		"sign_type_restriction",
	}

	for _, ruleType := range validTypes {
		t.Run(ruleType, func(t *testing.T) {
			repo := newErrTemplateRepo()
			h := newErrHandler(t, repo)

			reqBody := CreateTemplateRequest{
				Name:    fmt.Sprintf("Template %s", ruleType),
				Type:    ruleType,
				Mode:    "whitelist",
				Config:  map[string]any{"key": "value"},
				Enabled: true,
			}

			rr := doErrRequest(t, h, http.MethodPost, "/api/v1/templates", reqBody, apiKey)
			assert.Equal(t, http.StatusCreated, rr.Code, "rule type %s should be accepted", ruleType)
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: Template update with only description
// ---------------------------------------------------------------------------

func TestUpdateTemplate_DescriptionOnly(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	tmpl := makeAPITemplate("tmpl-upd-desc", "Desc Update")
	repo.seed(tmpl)
	h := newErrHandler(t, repo)

	reqBody := UpdateTemplateRequest{
		Description: "New description only",
	}

	rr := doErrRequest(t, h, http.MethodPatch, "/api/v1/templates/tmpl-upd-desc", reqBody, apiKey)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp TemplateResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "New description only", resp.Description)
	// Name should remain unchanged
	assert.Equal(t, "Desc Update", resp.Name)
}

// ---------------------------------------------------------------------------
// Tests: Template time fields in response
// ---------------------------------------------------------------------------

func TestTemplateResponse_TimeFieldsFormatted(t *testing.T) {
	apiKey := testAPIKey()
	repo := newErrTemplateRepo()
	fixedTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	tmpl := makeAPITemplate("tmpl-time", "Time Template")
	tmpl.CreatedAt = fixedTime
	tmpl.UpdatedAt = fixedTime.Add(1 * time.Hour)
	repo.seed(tmpl)
	h := newErrHandler(t, repo)

	rr := doErrRequest(t, h, http.MethodGet, "/api/v1/templates/tmpl-time", nil, apiKey)
	assert.Equal(t, http.StatusOK, rr.Code)

	var resp TemplateResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&resp))
	assert.Equal(t, "2024-06-15T10:30:00Z", resp.CreatedAt)
	assert.Equal(t, "2024-06-15T11:30:00Z", resp.UpdatedAt)
}
