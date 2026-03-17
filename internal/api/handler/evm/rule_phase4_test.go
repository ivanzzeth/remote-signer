package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// --- Phase4 mock API key repo ---

type phase4MockAPIKeyRepo struct {
	keys map[string]*types.APIKey
}

func newPhase4MockAPIKeyRepo() *phase4MockAPIKeyRepo {
	return &phase4MockAPIKeyRepo{keys: make(map[string]*types.APIKey)}
}

func (m *phase4MockAPIKeyRepo) Create(_ context.Context, _ *types.APIKey) error { return nil }
func (m *phase4MockAPIKeyRepo) Get(_ context.Context, id string) (*types.APIKey, error) {
	if k, ok := m.keys[id]; ok {
		return k, nil
	}
	return nil, types.ErrNotFound
}
func (m *phase4MockAPIKeyRepo) Update(_ context.Context, _ *types.APIKey) error { return nil }
func (m *phase4MockAPIKeyRepo) Delete(_ context.Context, _ string) error        { return nil }
func (m *phase4MockAPIKeyRepo) List(_ context.Context, _ storage.APIKeyFilter) ([]*types.APIKey, error) {
	return nil, nil
}
func (m *phase4MockAPIKeyRepo) UpdateLastUsed(_ context.Context, _ string) error { return nil }
func (m *phase4MockAPIKeyRepo) Count(_ context.Context, _ storage.APIKeyFilter) (int, error) {
	return 0, nil
}
func (m *phase4MockAPIKeyRepo) DeleteBySourceExcluding(_ context.Context, _ string, _ []string) (int64, error) {
	return 0, nil
}
func (m *phase4MockAPIKeyRepo) BackfillSource(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

// --- Helpers ---

func phase4AgentCtx(keyID string) context.Context {
	return context.WithValue(context.Background(), middleware.APIKeyContextKey, &types.APIKey{
		ID:   keyID,
		Role: types.RoleAgent,
	})
}

func phase4DevCtx(keyID string) context.Context {
	return context.WithValue(context.Background(), middleware.APIKeyContextKey, &types.APIKey{
		ID:   keyID,
		Role: types.RoleDev,
	})
}

func phase4AdminCtx(keyID string) context.Context {
	return context.WithValue(context.Background(), middleware.APIKeyContextKey, &types.APIKey{
		ID:   keyID,
		Role: types.RoleAdmin,
	})
}

func phase4CreateBody(name, ruleType, mode string) string {
	return `{"name":"` + name + `","type":"` + ruleType + `","mode":"` + mode + `","config":{"addresses":["0x0000000000000000000000000000000000000001"]},"enabled":true}`
}

func phase4Do(h http.Handler, method, path string, body string, ctx context.Context) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, bytes.NewBufferString(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// --- Tests: Agent creates declarative rule ---

func TestPhase4_AgentCreatesAddressList_Success(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := phase4CreateBody("test-whitelist", "evm_address_list", "whitelist")
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4AgentCtx("agent-1"))

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp RuleResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.NotNil(t, resp.Owner)
	assert.Equal(t, "agent-1", *resp.Owner)
	assert.Equal(t, []string{"self"}, resp.AppliedTo)
	assert.Equal(t, "active", resp.Status)
}

// --- Tests: Agent blocked rule types ---

func TestPhase4_AgentCreatesEvmJS_Forbidden(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"name":"test","type":"evm_js","mode":"whitelist","config":{"script":"function validate(input) { return {valid:true}; }"},"enabled":true}`
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4AgentCtx("agent-1"))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "evm_js")
}

func TestPhase4_AgentCreatesSolidityExpression_Forbidden(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"name":"test","type":"evm_solidity_expression","mode":"whitelist","config":{"expression":"true"},"enabled":true}`
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4AgentCtx("agent-1"))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "evm_solidity_expression")
}

func TestPhase4_AgentCreatesSignerRestriction_Forbidden(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"name":"test","type":"signer_restriction","mode":"whitelist","config":{"signers":["0x0000000000000000000000000000000000000001"]},"enabled":true}`
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4AgentCtx("agent-1"))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "signer_restriction")
}

// --- Tests: Agent applied_to forced to ["self"] ---

func TestPhase4_AgentAppliedToForcedSelf(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"name":"test","type":"evm_address_list","mode":"whitelist","config":{"addresses":["0x0000000000000000000000000000000000000001"]},"enabled":true,"applied_to":["*"]}`
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4AgentCtx("agent-1"))

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp RuleResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, []string{"self"}, resp.AppliedTo)
}

// --- Tests: Admin creates with applied_to validation ---

func TestPhase4_AdminCreatesWithAppliedToValidKey(t *testing.T) {
	repo := newMockRuleRepo()
	apiKeyRepo := newPhase4MockAPIKeyRepo()
	apiKeyRepo.keys["agent-1"] = &types.APIKey{ID: "agent-1", Role: types.RoleAgent}
	h, err := NewRuleHandler(repo, slog.Default(), WithAPIKeyRepo(apiKeyRepo))
	require.NoError(t, err)

	body := `{"name":"test","type":"evm_address_list","mode":"whitelist","config":{"addresses":["0x0000000000000000000000000000000000000001"]},"enabled":true,"applied_to":["agent-1"]}`
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4AdminCtx("admin-1"))

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp RuleResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, []string{"agent-1"}, resp.AppliedTo)
}

func TestPhase4_AdminCreatesWithAppliedToNonexistentKey_BadRequest(t *testing.T) {
	repo := newMockRuleRepo()
	apiKeyRepo := newPhase4MockAPIKeyRepo()
	h, err := NewRuleHandler(repo, slog.Default(), WithAPIKeyRepo(apiKeyRepo))
	require.NoError(t, err)

	body := `{"name":"test","type":"evm_address_list","mode":"whitelist","config":{"addresses":["0x0000000000000000000000000000000000000001"]},"enabled":true,"applied_to":["nonexistent"]}`
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4AdminCtx("admin-1"))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "not found")
}

// --- Tests: Immutable rules ---

func TestPhase4_ImmutableRuleBlocksModify(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Immutable = true
	rule.Owner = "admin-1"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"name":"updated"}`
	w := phase4Do(h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, phase4AdminCtx("admin-1"))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "immutable")
}

func TestPhase4_ImmutableRuleBlocksDelete(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Immutable = true
	rule.Owner = "admin-1"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	w := phase4Do(h, http.MethodDelete, "/api/v1/evm/rules/"+string(rule.ID), "", phase4AdminCtx("admin-1"))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "immutable")
}

// --- Tests: Ownership check on modify/delete ---

func TestPhase4_AgentCannotModifyOthersRule(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "agent-other"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"name":"hacked"}`
	w := phase4Do(h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, phase4AgentCtx("agent-1"))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "own rules")
}

func TestPhase4_AgentCannotDeleteOthersRule(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "agent-other"
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	w := phase4Do(h, http.MethodDelete, "/api/v1/evm/rules/"+string(rule.ID), "", phase4AgentCtx("agent-1"))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "own rules")
}

// --- Tests: Approve/Reject flow ---

func TestPhase4_ApproveChangesPendingToActive(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "agent-1"
	rule.Status = types.RuleStatusPendingApproval
	rule.AppliedTo = pq.StringArray{"self"}
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/approve", "", phase4AdminCtx("admin-1"))

	assert.Equal(t, http.StatusOK, w.Code)
	var resp RuleResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "active", resp.Status)
	assert.NotNil(t, resp.ApprovedBy)
	assert.Equal(t, "admin-1", *resp.ApprovedBy)
}

func TestPhase4_RejectChangesPendingToRejected(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "agent-1"
	rule.Status = types.RuleStatusPendingApproval
	rule.AppliedTo = pq.StringArray{"self"}
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"reason":"too broad"}`
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/reject", body, phase4AdminCtx("admin-1"))

	assert.Equal(t, http.StatusOK, w.Code)
	var resp RuleResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "rejected", resp.Status)
}

func TestPhase4_ApproveNonPendingRule_BadRequest(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Status = types.RuleStatusActive
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/approve", "", phase4AdminCtx("admin-1"))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "not pending")
}

func TestPhase4_AgentCannotApprove(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Status = types.RuleStatusPendingApproval
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules/"+string(rule.ID)+"/approve", "", phase4AgentCtx("agent-1"))

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// --- Tests: Rule count limit ---

func TestPhase4_RuleCountLimitEnforcedForAgent(t *testing.T) {
	repo := newMockRuleRepo()
	// Pre-populate with 3 rules owned by agent
	for i := 0; i < 3; i++ {
		r := newAPIRule()
		r.ID = types.RuleID("rule_test-" + string(rune('a'+i)))
		r.Owner = "agent-1"
		repo.addRule(r)
	}

	h, err := NewRuleHandler(repo, slog.Default(), WithMaxRulesPerKey(3))
	require.NoError(t, err)

	body := phase4CreateBody("one-too-many", "evm_address_list", "whitelist")
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4AgentCtx("agent-1"))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "rule limit exceeded")
}

func TestPhase4_RuleCountLimitNotEnforcedForAdmin(t *testing.T) {
	repo := newMockRuleRepo()
	// Pre-populate with 3 rules owned by admin
	for i := 0; i < 3; i++ {
		r := newAPIRule()
		r.ID = types.RuleID("rule_test-" + string(rune('a'+i)))
		r.Owner = "admin-1"
		repo.addRule(r)
	}

	h, err := NewRuleHandler(repo, slog.Default(), WithMaxRulesPerKey(3))
	require.NoError(t, err)

	body := phase4CreateBody("admin-rule", "evm_address_list", "whitelist")
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4AdminCtx("admin-1"))

	assert.Equal(t, http.StatusCreated, w.Code)
}

// --- Tests: Approval flow with require_approval config ---

func TestPhase4_RequireApproval_AgentWhitelist_PendingApproval(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default(), WithRequireApproval(true))
	require.NoError(t, err)

	body := phase4CreateBody("whitelist-needs-approval", "evm_address_list", "whitelist")
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4AgentCtx("agent-1"))

	assert.Equal(t, http.StatusAccepted, w.Code)
	var resp RuleResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "pending_approval", resp.Status)
}

func TestPhase4_RequireApproval_AgentBlocklist_ActiveImmediately(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default(), WithRequireApproval(true))
	require.NoError(t, err)

	body := phase4CreateBody("blocklist-always-active", "evm_address_list", "blocklist")
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4AgentCtx("agent-1"))

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp RuleResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "active", resp.Status)
}

// --- Tests: Dev role restrictions ---

func TestPhase4_DevCannotCreateSignerRestriction(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"name":"test","type":"signer_restriction","mode":"whitelist","config":{"signers":["0x0000000000000000000000000000000000000001"]},"enabled":true}`
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4DevCtx("dev-1"))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "signer_restriction")
}

func TestPhase4_DevAppliedToForcedSelf(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"name":"test","type":"evm_address_list","mode":"whitelist","config":{"addresses":["0x0000000000000000000000000000000000000001"]},"enabled":true,"applied_to":["*"]}`
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4DevCtx("dev-1"))

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp RuleResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, []string{"self"}, resp.AppliedTo)
}

// --- Tests: Agent modify to blocked type ---

func TestPhase4_AgentCannotModifyRuleToEvmJS(t *testing.T) {
	repo := newMockRuleRepo()
	rule := newAPIRule()
	rule.Owner = "agent-1"
	rule.AppliedTo = pq.StringArray{"self"}
	repo.addRule(rule)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := `{"type":"evm_js"}`
	w := phase4Do(h, http.MethodPatch, "/api/v1/evm/rules/"+string(rule.ID), body, phase4AgentCtx("agent-1"))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "evm_js")
}

// --- Tests: Admin default applied_to ---

func TestPhase4_AdminCreatesWithDefaultAppliedToWildcard(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := phase4CreateBody("admin-global", "evm_address_list", "whitelist")
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4AdminCtx("admin-1"))

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp RuleResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, []string{"*"}, resp.AppliedTo)
	assert.Equal(t, "admin-1", *resp.Owner)
}

// --- Tests: Owner auto-set ---

func TestPhase4_OwnerAutoSetFromCaller(t *testing.T) {
	repo := newMockRuleRepo()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := phase4CreateBody("test", "evm_address_list", "whitelist")
	w := phase4Do(h, http.MethodPost, "/api/v1/evm/rules", body, phase4AgentCtx("agent-42"))

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp RuleResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "agent-42", *resp.Owner)
}
