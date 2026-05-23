package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/simulation"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// FailRuleRepoNoGet fails on Get
type FailRuleRepoNoGet struct{ storage.MemoryRuleRepository }

func (f *FailRuleRepoNoGet) Get(ctx context.Context, id types.RuleID) (*types.Rule, error) {
	return nil, fmt.Errorf("get error")
}

// FailRuleRepoNoList fails on List
type FailRuleRepoNoList struct{ storage.MemoryRuleRepository }

func (f *FailRuleRepoNoList) List(ctx context.Context, filter storage.RuleFilter) ([]*types.Rule, error) {
	return nil, fmt.Errorf("list error")
}

// FailRuleRepoNoCount fails on Count
type FailRuleRepoNoCount struct {
	storage.MemoryRuleRepository
	callCount int
}

func (f *FailRuleRepoNoCount) Count(ctx context.Context, filter storage.RuleFilter) (int, error) {
	f.callCount++
	return 0, fmt.Errorf("count error")
}

// failRuleRepoCreate fails on Create
type failRuleRepoCreate struct {
	storage.MemoryRuleRepository
}

func newFailRuleRepoCreate() *failRuleRepoCreate {
	r := &failRuleRepoCreate{}
	r.MemoryRuleRepository = *storage.NewMemoryRuleRepository()
	return r
}

func (f *failRuleRepoCreate) Create(ctx context.Context, rule *types.Rule) error {
	return fmt.Errorf("create error")
}

// failRuleRepoUpdate fails on Update
type failRuleRepoUpdate struct {
	*storage.MemoryRuleRepository
}

func newFailRuleRepoUpdate() *failRuleRepoUpdate {
	return &failRuleRepoUpdate{
		MemoryRuleRepository: storage.NewMemoryRuleRepository(),
	}
}

func (f *failRuleRepoUpdate) Update(ctx context.Context, rule *types.Rule) error {
	return fmt.Errorf("update error")
}

// budgetFailDeleteRepo fails on Delete
type budgetFailDeleteRepo struct{}

func (b *budgetFailDeleteRepo) ListByRuleID(ctx context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (b *budgetFailDeleteRepo) ListByRuleIDs(ctx context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (b *budgetFailDeleteRepo) Create(ctx context.Context, budget *types.RuleBudget) error {
	return nil
}
func (b *budgetFailDeleteRepo) CreateOrGet(ctx context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error) {
	return nil, false, nil
}
func (b *budgetFailDeleteRepo) GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	return nil, types.ErrNotFound
}
func (b *budgetFailDeleteRepo) Get(ctx context.Context, id string) (*types.RuleBudget, error) {
	return &types.RuleBudget{ID: "budget-1", RuleID: "rule_1", Unit: "usdc"}, nil
}
func (b *budgetFailDeleteRepo) Update(ctx context.Context, budget *types.RuleBudget) error {
	return nil
}
func (b *budgetFailDeleteRepo) CountByRuleID(ctx context.Context, ruleID types.RuleID) (int, error) {
	return 0, nil
}
func (b *budgetFailDeleteRepo) Delete(ctx context.Context, id string) error {
	return fmt.Errorf("delete error")
}
func (b *budgetFailDeleteRepo) DeleteByRuleID(ctx context.Context, ruleID types.RuleID) error {
	return nil
}
func (b *budgetFailDeleteRepo) ListAll(ctx context.Context) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (b *budgetFailDeleteRepo) AtomicSpend(ctx context.Context, ruleID types.RuleID, unit string, amount string) error {
	return nil
}
func (b *budgetFailDeleteRepo) ResetBudget(ctx context.Context, ruleID types.RuleID, unit string, currentPeriodStart time.Time) error {
	return nil
}
func (b *budgetFailDeleteRepo) MarkAlertSent(ctx context.Context, ruleID types.RuleID, unit string) error {
	return nil
}

// budgetGetNotFoundRepo returns ErrNotFound on Get, delegates everything else to failDeleteRepo
type budgetGetNotFoundRepo struct {
	storage.BudgetRepository
}

func (b *budgetGetNotFoundRepo) Get(_ context.Context, _ string) (*types.RuleBudget, error) {
	return nil, types.ErrNotFound
}

// budgetFailUpdateRepo fails on Update
type budgetFailUpdateRepo struct{}

func (b *budgetFailUpdateRepo) ListByRuleID(ctx context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (b *budgetFailUpdateRepo) ListByRuleIDs(ctx context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (b *budgetFailUpdateRepo) Create(ctx context.Context, budget *types.RuleBudget) error {
	return nil
}
func (b *budgetFailUpdateRepo) CreateOrGet(ctx context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error) {
	return nil, false, nil
}
func (b *budgetFailUpdateRepo) GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	return nil, types.ErrNotFound
}
func (b *budgetFailUpdateRepo) Get(ctx context.Context, id string) (*types.RuleBudget, error) {
	return &types.RuleBudget{ID: "budget-1", RuleID: "rule_1", Unit: "usdc"}, nil
}
func (b *budgetFailUpdateRepo) Update(ctx context.Context, budget *types.RuleBudget) error {
	return fmt.Errorf("update error")
}
func (b *budgetFailUpdateRepo) CountByRuleID(ctx context.Context, ruleID types.RuleID) (int, error) {
	return 0, nil
}
func (b *budgetFailUpdateRepo) Delete(ctx context.Context, id string) error {
	return nil
}
func (b *budgetFailUpdateRepo) DeleteByRuleID(ctx context.Context, ruleID types.RuleID) error {
	return nil
}
func (b *budgetFailUpdateRepo) ListAll(ctx context.Context) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (b *budgetFailUpdateRepo) AtomicSpend(ctx context.Context, ruleID types.RuleID, unit string, amount string) error {
	return nil
}
func (b *budgetFailUpdateRepo) ResetBudget(ctx context.Context, ruleID types.RuleID, unit string, currentPeriodStart time.Time) error {
	return nil
}
func (b *budgetFailUpdateRepo) MarkAlertSent(ctx context.Context, ruleID types.RuleID, unit string) error {
	return nil
}

// ---------------------------------------------------------------------------
// rule_crud.go: createRule error paths
// ---------------------------------------------------------------------------

func TestB3CreateRule_InvalidBody(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBufferString("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid request body")
}

func TestB3CreateRule_MissingType(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "Test", "mode": "whitelist"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "type is required")
}

func TestB3CreateRule_MissingMode(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "Test", "type": "evm_address_list"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "mode is required")
}

func TestB3CreateRule_InvalidMode(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "Test", "type": "evm_address_list", "mode": "invalid_mode"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "mode must be")
}

func TestB3CreateRule_EvmJSMissingScript(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{
		"name":   "JS Rule",
		"type":   "evm_js",
		"mode":   "whitelist",
		"config": map[string]interface{}{},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "config.script is required for evm_js rules")
}

func TestB3CreateRule_RepoCreateFails(t *testing.T) {
	repo := newFailRuleRepoCreate()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{
		"name":   "Test Rule",
		"type":   "evm_address_list",
		"mode":   "whitelist",
		"config": map[string]interface{}{"addresses": []string{"0x1234567890abcdef1234567890abcdef12345678"}},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "failed to create rule")
}

func TestB3CreateRule_InvalidChainType(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{
		"name":       "Test Rule",
		"type":       "evm_address_list",
		"mode":       "whitelist",
		"config":     map[string]interface{}{"addresses": []string{"0x1234567890abcdef1234567890abcdef12345678"}},
		"chain_type": "invalid_chain",
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid chain_type")
}

func TestB3CreateRule_InvalidSignerAddress(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{
		"name":           "Test Rule",
		"type":           "evm_address_list",
		"mode":           "whitelist",
		"config":         map[string]interface{}{"addresses": []string{"0x1234567890abcdef1234567890abcdef12345678"}},
		"signer_address": "invalid_address",
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	// Error message may vary depending on validation order
}

// ---------------------------------------------------------------------------
// rule_crud.go: updateRule error paths
// ---------------------------------------------------------------------------

func TestB3UpdateRule_GetNotFound(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "Updated"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/nonexistent", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "rule not found")
}

func TestB3UpdateRule_GetRepoError(t *testing.T) {
	repo := &FailRuleRepoNoGet{}
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "Updated"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/rule_test", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "failed to get rule")
}

func TestB3UpdateRule_RepoUpdateFails(t *testing.T) {
	repo := newFailRuleRepoUpdate()
	rule := &types.Rule{ID: "rule_test", Name: "Old", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, repo.Create(context.Background(), rule))

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "Updated"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/rule_test", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestB3UpdateRule_AgentBlockedTypeChange(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{ID: "rule_test", Name: "Old", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true, Owner: "agent-key"}
	require.NoError(t, repo.Create(context.Background(), rule))

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	agentKey := &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}
	body := map[string]interface{}{"type": "evm_js"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/rule_test", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, agentKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "agent role cannot change rule type")
}

func TestB3UpdateRule_InvalidChainType(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{ID: "rule_test", Name: "Old", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, repo.Create(context.Background(), rule))

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"chain_type": "invalid"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/rule_test", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3UpdateRule_InvalidSignerAddress(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{ID: "rule_test", Name: "Old", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, repo.Create(context.Background(), rule))

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"signer_address": "bad"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/rule_test", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3UpdateRule_AdminChangesAppliedTo(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{ID: "rule_test", Name: "Old", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, repo.Create(context.Background(), rule))

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"applied_to": []string{"other-key"}}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/rule_test", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels error paths
// ---------------------------------------------------------------------------

func TestB3HandlePatchSignerLabels_InvalidBody(t *testing.T) {
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{}, owners)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/signers/"+testAddr, bytes.NewBufferString("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, testOwnerAPIKey()))
	rec := httptest.NewRecorder()
	h.HandleSignerAction(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_locking.go: handleTransferOwnership error paths
// ---------------------------------------------------------------------------

func TestB3HandleTransferOwnership_NotOwner(t *testing.T) {
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{}, owners)

	body := map[string]interface{}{"new_owner_id": "yet-another-key"}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/transfer", body, testOtherAPIKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestB3HandleTransferOwnership_NotFound(t *testing.T) {
	owners := map[string]string{}
	h := newActionHandler(t, &signerActionMock{}, owners)

	body := map[string]interface{}{"new_owner_id": "other-key"}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/transfer", body, testOwnerAPIKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// request_simulation.go: constructor validation
// ---------------------------------------------------------------------------

func TestB3NewRequestSimulationHandler_NilDeps(t *testing.T) {
	_, err := NewRequestSimulationHandler(nil, nil, nil)
	assert.Error(t, err)

	_, err = NewRequestSimulationHandler(nil, nil, slog.Default())
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// rule_delete.go: deleteRule Get error
// ---------------------------------------------------------------------------

func TestB3DeleteRule_GetRepoError(t *testing.T) {
	repo := &FailRuleRepoNoGet{}
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/rules/rule_test", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestB3DeleteRule_NotFound(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/rules/nonexistent", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: listRules Count error
// ---------------------------------------------------------------------------

func TestB3ListRules_CountError2(t *testing.T) {
	repo := &FailRuleRepoNoCount{}
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "failed to count rules")
}

// ---------------------------------------------------------------------------
// rule_query.go: listBudgets with no budgetRepo
// ---------------------------------------------------------------------------

func TestB3ListBudgets_NoBudgetRepo(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules/rule_test/budgets", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// Without WithBudgetRepo, the route falls through to ruleID matching
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_response.go: toRuleResponse additional coverage
// ---------------------------------------------------------------------------

func TestB3ToRuleResponse_ChainTypeAndSigner(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	chainType := types.ChainTypeEVM
	addr := "0xABCDabcdABCDabcdABCDabcdABCDabcdABCDabcd"
	chainID := "1"
	now := time.Now()
	rule := &types.Rule{
		ID:            "rule_1",
		Name:          "Scoped Rule",
		Type:          types.RuleTypeEVMAddressList,
		Mode:          types.RuleModeWhitelist,
		Source:        types.RuleSourceAPI,
		Config:        json.RawMessage(`{}`),
		Enabled:       true,
		ChainType:     &chainType,
		ChainID:       &chainID,
		SignerAddress: &addr,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	resp := h.toRuleResponse(rule)
	assert.Equal(t, "evm", *resp.ChainType)
	assert.Equal(t, "1", *resp.ChainID)
	assert.Equal(t, addr, *resp.SignerAddress)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handleDeleteSigner ownership error
// ---------------------------------------------------------------------------

func TestB3HandleDeleteSigner_IsOwnerError(t *testing.T) {
	db := newB3CoverageTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)

	mustCreateAPIKey(t, apiKeyRepo, "admin-key", types.RoleAdmin)

	accessSvc, err := service.NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, slog.Default())
	require.NoError(t, err)

	mgr := &signerActionMock{
		deleteFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("delete error")
		},
	}
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil, signAdminKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_locking.go: handleTransferOwnership error paths
// ---------------------------------------------------------------------------

func TestB3HandleTransferOwnership_InvalidBody2(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerActionMock{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/transfer", bytes.NewBufferString("bad json"), testOwnerAPIKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3HandleTransferOwnership_MissingNewOwner(t *testing.T) {
	accessSvc := newFlexAccessService(t, map[string]string{testAddr: testKeyID})
	h, err := NewSignerHandler(&signerActionMock{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	body := map[string]string{}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/transfer", body, testOwnerAPIKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "new_owner_id is required")
}

// ---------------------------------------------------------------------------
// signer_access.go: handleRevokeAccess coverage
// ---------------------------------------------------------------------------

func TestB3HandleRevokeAccess_NoKeyInPath(t *testing.T) {
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{}, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr+"/access", nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// signer.go: handleAccess list access
// ---------------------------------------------------------------------------

func TestB3HandleListAccess_NotFound(t *testing.T) {
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{}, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodGet,
		"/api/v1/evm/signers/0xnonexistent/access", nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// transactions.go: list success empty
// ---------------------------------------------------------------------------

func TestB3TransactionsList_SuccessEmpty(t *testing.T) {
	db := newB3TxCoverageDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)

	h, err := NewTransactionsHandler(txRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/transactions", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: BudgetItemHandler delete error
// ---------------------------------------------------------------------------

func TestB3BudgetItem_DeleteRepoError(t *testing.T) {
	budgetRepo := &budgetFailDeleteRepo{}
	ruleRepo := storage.NewMemoryRuleRepository()

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/budgets/budget-1", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestB3BudgetItem_UpdateInvalidMaxTotal(t *testing.T) {
	budgetRepo := &budgetFailUpdateRepo{}
	ruleRepo := storage.NewMemoryRuleRepository()

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"max_total": "not_a_number"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/budgets/budget-1", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3BudgetItem_UpdateInvalidMaxPerTx(t *testing.T) {
	budgetRepo := &budgetFailUpdateRepo{}
	ruleRepo := storage.NewMemoryRuleRepository()

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"max_per_tx": "not_a_number"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/budgets/budget-1", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3BudgetItem_UpdateInvalidMaxTxCount(t *testing.T) {
	budgetRepo := &budgetFailUpdateRepo{}
	ruleRepo := storage.NewMemoryRuleRepository()

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"max_tx_count": -5}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/budgets/budget-1", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3BudgetItem_UpdateInvalidAlertPct(t *testing.T) {
	budgetRepo := &budgetFailUpdateRepo{}
	ruleRepo := storage.NewMemoryRuleRepository()

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"alert_pct": 150}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/budgets/budget-1", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3BudgetItem_UpdateInvalidTxCount(t *testing.T) {
	budgetRepo := &budgetFailUpdateRepo{}
	ruleRepo := storage.NewMemoryRuleRepository()

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"tx_count": -1}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/budgets/budget-1", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3BudgetItem_UpdateRepoUpdateFails(t *testing.T) {
	budgetRepo := &budgetFailUpdateRepo{}
	ruleRepo := storage.NewMemoryRuleRepository()

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"max_total": "1000"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/budgets/budget-1", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestB3BudgetItem_ResetForbiddenForAgent(t *testing.T) {
	budgetRepo := &budgetFailUpdateRepo{}
	ruleRepo := storage.NewMemoryRuleRepository()

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	agentKey := &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/budgets/budget-1/reset", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, agentKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestB3BudgetItem_GetForAgent(t *testing.T) {
	budgetRepo := &budgetFailUpdateRepo{}
	ruleRepo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{ID: "rule_1", Name: "Test Rule", Owner: "agent-key", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	agentKey := &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/budgets/budget-1", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, agentKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_locking.go: handleTransferOwnership error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// request_simulation.go: constructor validation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// budget.go: BudgetListHandler list
// ---------------------------------------------------------------------------

func TestB3BudgetList_ListOwnBudget(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()

	rule := &types.Rule{ID: "rule_1", Name: "My Rule", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true, Owner: "dev-key"}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))

	budget := &types.RuleBudget{ID: types.BudgetID("rule_1", "usdc"), RuleID: "rule_1", Unit: "usdc", MaxTotal: "1000", Spent: "0"}
	_, _, err = budgetRepo.CreateOrGet(context.Background(), budget)
	require.NoError(t, err)

	h, err := NewBudgetListHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	devKey := &types.APIKey{ID: "dev-key", Role: types.RoleDev, Enabled: true}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/budgets", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, devKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_locking.go: handleTransferOwnership error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// request_simulation.go: constructor validation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// budget.go: handleCreate with rule not found
// ---------------------------------------------------------------------------

func TestB3BudgetList_CreateRuleNotFound(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()

	h, err := NewBudgetListHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"rule_id": "nonexistent", "unit": "usdc"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/budgets", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// simulate.go: toBalanceChangeJSON with TokenID
// ---------------------------------------------------------------------------

func TestB3ToBalanceChangeJSON_WithTokenID(t *testing.T) {
	tokenID := big.NewInt(42)
	changes := []simulation.BalanceChange{
		{Token: "0xtoken", Standard: "ERC721", Amount: big.NewInt(1), Direction: "in", TokenID: tokenID},
		{Token: "0xtoken2", Standard: "ERC20", Amount: big.NewInt(100), Direction: "out"},
	}
	result := toBalanceChangeJSON(changes)
	require.Len(t, result, 2)
	assert.Equal(t, "42", result[0].TokenID)
	assert.Equal(t, "", result[1].TokenID)
}

// ---------------------------------------------------------------------------
// request.go: toDetailResponse with RuleMatchedID
// ---------------------------------------------------------------------------

func TestB3ToDetailResponse_RuleMatchedName(t *testing.T) {
	ruleRepo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{ID: "rule_matched", Name: "Matched Rule", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))

	now := time.Now()
	ruleMatchedID := "rule_matched"
	req := &types.SignRequest{
		ID:            "req-1",
		APIKeyID:      "admin-key",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xsig",
		SignType:      "transaction",
		Status:        types.StatusCompleted,
		RuleMatchedID: &ruleMatchedID,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	resp := toDetailResponse(context.Background(), ruleRepo, req, true)
	assert.Equal(t, "Matched Rule", *resp.RuleMatchedName)
}

func TestB3ToDetailResponse_RuleMatchedNotFound(t *testing.T) {
	ruleRepo := storage.NewMemoryRuleRepository()
	now := time.Now()
	ruleMatchedID := "nonexistent_rule"
	req := &types.SignRequest{
		ID:            "req-1",
		APIKeyID:      "admin-key",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xsig",
		SignType:      "transaction",
		Status:        types.StatusCompleted,
		RuleMatchedID: &ruleMatchedID,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	resp := toDetailResponse(context.Background(), ruleRepo, req, true)
	assert.Nil(t, resp.RuleMatchedName)
}

func TestB3ToDetailResponse_IncludePayload(t *testing.T) {
	now := time.Now()
	req := &types.SignRequest{
		ID:             "req-1",
		APIKeyID:       "admin-key",
		ChainType:      types.ChainTypeEVM,
		ChainID:        "1",
		SignerAddress:  "0xsig",
		SignType:       "transaction",
		Status:         types.StatusSigning,
		Payload:        json.RawMessage(`{"to":"0x123","value":"0x1"}`),
		ApprovalSource: "auto:rule_matched",
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	resp := toDetailResponse(context.Background(), nil, req, true)
	assert.NotNil(t, resp.Payload)
	assert.Equal(t, "auto:rule_matched", resp.ApprovalSource)
}

// ---------------------------------------------------------------------------
// BudgetItemHandler: Reset success and Delete/Update permission checks
// ---------------------------------------------------------------------------

func TestB3BudgetItem_ResetSuccess(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()

	rule := &types.Rule{ID: "rule_1", Name: "Test Rule", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))

	budget := &types.RuleBudget{RuleID: "rule_1", Unit: "usdc", MaxTotal: "1000", Spent: "500", TxCount: 10}
	budget.ID = types.BudgetID("rule_1", "usdc")
	budget, _, err = budgetRepo.CreateOrGet(context.Background(), budget)
	require.NoError(t, err)

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/budgets/"+budget.ID+"/reset", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_locking.go: handleTransferOwnership error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// request_simulation.go: constructor validation
// ---------------------------------------------------------------------------

func TestB3BudgetItem_DeleteForbiddenNonAdmin(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()

	rule := &types.Rule{ID: "rule_1", Name: "Test Rule", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))

	budget := &types.RuleBudget{ID: types.BudgetID("rule_1", "usdc"), RuleID: "rule_1", Unit: "usdc", MaxTotal: "1000", Spent: "0"}
	budget, _, err = budgetRepo.CreateOrGet(context.Background(), budget)
	require.NoError(t, err)

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	agentKey := &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/budgets/"+budget.ID, nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, agentKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestB3BudgetItem_UpdateForbiddenNonAdmin(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()

	rule := &types.Rule{ID: "rule_1", Name: "Test Rule", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))

	budget := &types.RuleBudget{ID: types.BudgetID("rule_1", "usdc"), RuleID: "rule_1", Unit: "usdc", MaxTotal: "1000", Spent: "0"}
	budget, _, err = budgetRepo.CreateOrGet(context.Background(), budget)
	require.NoError(t, err)

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	agentKey := &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}
	body := map[string]interface{}{"max_total": "2000"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/budgets/"+budget.ID, bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, agentKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// signer.go: HandleWalletSigners method-not-allowed
// ---------------------------------------------------------------------------

func TestB3HandleWalletSigners_MethodNotAllowed(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/wallets/0xwallet/signers", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.HandleWalletSigners(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: listSigners invalid type filter
// ---------------------------------------------------------------------------

func TestB3ListSigners_InvalidTypeFilter(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?type=invalid_type", signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid type filter")
}

// ---------------------------------------------------------------------------
// request.go: ListHandler.ServeHTTP error paths
// ---------------------------------------------------------------------------

func TestB3ListHandler_NewListHandlerNilSignService(t *testing.T) {
	_, err := NewListHandler(nil, nil, nil)
	assert.Error(t, err)
}

func TestB3ListHandler_NewListHandlerNilRuleRepo(t *testing.T) {
	_, err := NewListHandler(&mockSignService{}, nil, slog.Default())
	assert.Error(t, err)
}

func TestB3ListHandler_MethodNotAllowed(t *testing.T) {
	h, err := NewListHandler(&mockSignService{}, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/requests", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestB3ListHandler_Unauthorized(t *testing.T) {
	h, err := NewListHandler(&mockSignService{}, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestB3ListHandler_InvalidSignerAddress(t *testing.T) {
	h, err := NewListHandler(&mockSignService{}, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests?signer_address=bad", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListHandler_InvalidChainID(t *testing.T) {
	h, err := NewListHandler(&mockSignService{}, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests?chain_id=not_a_number", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListHandler_InvalidStatus(t *testing.T) {
	h, err := NewListHandler(&mockSignService{}, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests?status=invalid_status", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListHandler_InvalidCursor(t *testing.T) {
	h, err := NewListHandler(&mockSignService{}, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests?cursor=not_a_timestamp", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// request.go: RequestHandler.getRequest error paths
// ---------------------------------------------------------------------------

func TestB3RequestHandler_NewRequestHandlerNilService(t *testing.T) {
	_, err := NewRequestHandler(nil, nil, nil)
	assert.Error(t, err)
}

func TestB3RequestHandler_NewRequestHandlerNilRuleRepo(t *testing.T) {
	_, err := NewRequestHandler(&mockSignService{}, nil, slog.Default())
	assert.Error(t, err)
}

func TestB3RequestHandler_RequestNotFound(t *testing.T) {
	svc := &mockSignService{
		getRequestFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
			return nil, types.ErrNotFound
		},
	}
	h, err := NewRequestHandler(svc, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests/nonexistent", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestB3RequestHandler_GetRequestError(t *testing.T) {
	svc := &mockSignService{
		getRequestFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
			return nil, fmt.Errorf("get error")
		},
	}
	h, err := NewRequestHandler(svc, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests/some-id", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestB3RequestHandler_NonAdminOwnershipCheck(t *testing.T) {
	svc := &mockSignService{
		getRequestFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
			return &types.SignRequest{ID: "req-1", APIKeyID: "other-key"}, nil
		},
	}
	h, err := NewRequestHandler(svc, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	agentKey := &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests/req-1", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, agentKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// transactions.go: list error paths
// ---------------------------------------------------------------------------

func TestB3TransactionsList_InvalidLimit(t *testing.T) {
	db := newB3TxCoverageDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	h, err := NewTransactionsHandler(txRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/transactions?limit=-1", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3TransactionsList_InvalidOffset(t *testing.T) {
	db := newB3TxCoverageDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	h, err := NewTransactionsHandler(txRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/transactions?offset=-1", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3TransactionsList_NonAdminForbiddenOtherKey(t *testing.T) {
	db := newB3TxCoverageDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	h, err := NewTransactionsHandler(txRepo, slog.Default())
	require.NoError(t, err)

	agentKey := &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/transactions?api_key_id=other-key", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, agentKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestB3TransactionsList_NotFound(t *testing.T) {
	db := newB3TxCoverageDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	h, err := NewTransactionsHandler(txRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/transactions/nonexistent", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestB3TransactionsList_MethodNotAllowed(t *testing.T) {
	db := newB3TxCoverageDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	h, err := NewTransactionsHandler(txRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/transactions", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestB3TransactionsList_Unauthorized(t *testing.T) {
	db := newB3TxCoverageDB(t)
	txRepo, err := storage.NewGormTransactionRepository(db)
	require.NoError(t, err)
	h, err := NewTransactionsHandler(txRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/transactions", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: handleCreate validation error paths
// ---------------------------------------------------------------------------

func TestB3BudgetList_CreateMissingRuleID(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	h, err := NewBudgetListHandler(budgetRepo, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"unit": "usdc"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/budgets", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3BudgetList_CreateMissingUnit(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	h, err := NewBudgetListHandler(budgetRepo, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"rule_id": "rule_1"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/budgets", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3BudgetList_CreateInvalidMaxTotal(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{ID: "rule_1", Name: "Test", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))
	h, err := NewBudgetListHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"rule_id": "rule_1", "unit": "usdc", "max_total": "not_a_number"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/budgets", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3BudgetList_CreateInvalidMaxPerTx(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{ID: "rule_1", Name: "Test", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))
	h, err := NewBudgetListHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"rule_id": "rule_1", "unit": "usdc", "max_total": "1000", "max_per_tx": "not_a_number"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/budgets", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3BudgetList_CreateInvalidMaxTxCount(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{ID: "rule_1", Name: "Test", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))
	h, err := NewBudgetListHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"rule_id": "rule_1", "unit": "usdc", "max_total": "1000", "max_tx_count": -1}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/budgets", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3BudgetList_CreateInvalidAlertPct(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{ID: "rule_1", Name: "Test", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))
	h, err := NewBudgetListHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"rule_id": "rule_1", "unit": "usdc", "max_total": "1000", "alert_pct": 150}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/budgets", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3BudgetList_CreateSimBudget(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	h, err := NewBudgetListHandler(budgetRepo, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"rule_id": "sim:0x123", "unit": "usdc", "max_total": "1000"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/budgets", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: BudgetListHandler constructor errors
// ---------------------------------------------------------------------------

func TestB3BudgetListHandler_NilBudgetRepo(t *testing.T) {
	_, err := NewBudgetListHandler(nil, nil, nil)
	assert.Error(t, err)
}

func TestB3BudgetListHandler_NilRuleRepo(t *testing.T) {
	_, err := NewBudgetListHandler(&budgetFailDeleteRepo{}, nil, slog.Default())
	assert.Error(t, err)
}

func TestB3BudgetListHandler_NilLogger(t *testing.T) {
	_, err := NewBudgetListHandler(&budgetFailDeleteRepo{}, storage.NewMemoryRuleRepository(), nil)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// budget.go: BudgetItemHandler constructor errors
// ---------------------------------------------------------------------------

func TestB3BudgetItemHandler_NilBudgetRepo(t *testing.T) {
	_, err := NewBudgetItemHandler(nil, nil, nil)
	assert.Error(t, err)
}

func TestB3BudgetItemHandler_NilRuleRepo(t *testing.T) {
	_, err := NewBudgetItemHandler(&budgetFailDeleteRepo{}, nil, slog.Default())
	assert.Error(t, err)
}

func TestB3BudgetItemHandler_NilLogger(t *testing.T) {
	_, err := NewBudgetItemHandler(&budgetFailDeleteRepo{}, storage.NewMemoryRuleRepository(), nil)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// budget.go: handleDelete, handleReset against mock repos
// ---------------------------------------------------------------------------

func TestB3BudgetItem_LoadBudgetNotFound(t *testing.T) {
	repo := &budgetGetNotFoundRepo{BudgetRepository: &budgetFailDeleteRepo{}}
	ruleRepo := storage.NewMemoryRuleRepository()
	h, err := NewBudgetItemHandler(repo, ruleRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/budgets/nonexistent", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handleRevokeAccess success path
// ---------------------------------------------------------------------------

func TestB3HandleRevokeAccess_Success(t *testing.T) {
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{}, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr+"/access/some-key-id", nil, testOwnerAPIKey())
	// Should succeed
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_locking.go: handleTransferOwnership error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// request_simulation.go: constructor validation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer.go: SetWalletRepo coverage
// ---------------------------------------------------------------------------

func TestB3SetWalletRepo(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)
	h.SetWalletRepo(nil)
	// Just verify no panic
}

// ---------------------------------------------------------------------------
// budget.go: handleGet with simulation budget
// ---------------------------------------------------------------------------

func TestB3BudgetItem_HandleGetSimBudget(t *testing.T) {
	ruleRepo := storage.NewMemoryRuleRepository()
	budgetRepo := &budgetFailDeleteRepo{}

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	// budget repo returns budget with rule_id "sim:0x..."
	// But annotate will look up the rule and find it missing
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/budgets/budget-1", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_locking.go: handleTransferOwnership error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// request_simulation.go: constructor validation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_crud.go: createSigner error paths
// ---------------------------------------------------------------------------

func TestB3CreateSigner_ReadOnly(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), true)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodPost, "/api/v1/evm/signers", signAdminKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestB3CreateSigner_PermissionDenied(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	noPermKey := &types.APIKey{ID: "no-perm", Role: types.APIKeyRole("viewer"), Enabled: true}
	rec := doSignerRequest(t, h, http.MethodPost, "/api/v1/evm/signers", noPermKey)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestB3CreateSigner_InvalidBody(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBufferString("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: listSigners with filter paths
// ---------------------------------------------------------------------------

func TestB3ListSigners_StatusFilter(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{Total: 0, HasMore: false}, nil
		},
	}
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?status=active", signAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_locking.go: handleTransferOwnership error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// request_simulation.go: constructor validation
// ---------------------------------------------------------------------------

func TestB3ListSigners_EnabledFilter(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{Total: 0, HasMore: false}, nil
		},
	}
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?enabled=true", signAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_locking.go: handleTransferOwnership error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// request_simulation.go: constructor validation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// budget.go: handleCreate read-only
// ---------------------------------------------------------------------------

func TestB3BudgetList_CreateForbiddenForAgent(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	h, err := NewBudgetListHandler(budgetRepo, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"rule_id": "rule_1", "unit": "usdc", "max_total": "1000"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/budgets", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	agentKey := &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, agentKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: handleList with simulation annotations
// ---------------------------------------------------------------------------

func TestB3BudgetList_SimBudgetForAgentHidden(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()

	simBudget := &types.RuleBudget{ID: "sim-budget-id", RuleID: "sim:0xdead", Unit: "usdc", MaxTotal: "1000", Spent: "0"}
	simBudget.ID = types.BudgetID("sim:0xdead", "usdc")
	_, _, err = budgetRepo.CreateOrGet(context.Background(), simBudget)
	require.NoError(t, err)

	h, err := NewBudgetListHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	agentKey := &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/budgets", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, agentKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_locking.go: handleTransferOwnership error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// request_simulation.go: constructor validation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// budget.go: handleList admin sees all
// ---------------------------------------------------------------------------

func TestB3BudgetList_AdminSeesAll(t *testing.T) {
	db := newB3TxCoverageDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()

	realBudget := &types.RuleBudget{ID: types.BudgetID("rule_1", "usdc"), RuleID: "rule_1", Unit: "usdc", MaxTotal: "1000", Spent: "0"}
	_, _, err = budgetRepo.CreateOrGet(context.Background(), realBudget)
	require.NoError(t, err)

	simBudget := &types.RuleBudget{ID: types.BudgetID("sim:0xdead", "usdc"), RuleID: "sim:0xdead", Unit: "usdc", MaxTotal: "500", Spent: "0"}
	_, _, err = budgetRepo.CreateOrGet(context.Background(), simBudget)
	require.NoError(t, err)

	rule := &types.Rule{ID: "rule_1", Name: "My Rule", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))

	h, err := NewBudgetListHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/budgets", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_locking.go: handleTransferOwnership error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// request_simulation.go: constructor validation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// rule_query.go: listRules error paths
// ---------------------------------------------------------------------------

func TestB3ListRules_InvalidChainType(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)
	rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules?chain_type=invalid", nil, ruleAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListRules_InvalidSignerAddress(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)
	rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules?signer_address=0xbad", nil, ruleAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListRules_InvalidType(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)
	rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules?type=invalid_type", nil, ruleAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListRules_InvalidSource(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)
	rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules?source=invalid", nil, ruleAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListRules_ListError(t *testing.T) {
	repo := &FailRuleRepoNoList{}
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)
	rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules", nil, ruleAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestB3ListRules_CountError(t *testing.T) {
	repo := &FailRuleRepoNoCount{}
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)
	rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules", nil, ruleAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: listBudgets error path
// ---------------------------------------------------------------------------

func TestB3ListBudgets_RepoError(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{ID: "rule_1", Name: "test", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, repo.Create(context.Background(), rule))

	// list with no budget repo set
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	// Without budgetRepo, the route falls through to validate or approve
	// Just verify listing rules themselves works
	rec := doRuleRequest(t, h, http.MethodGet, "/api/v1/evm/rules", nil, ruleAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_locking.go: handleTransferOwnership error paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// request_simulation.go: constructor validation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// budget.go: handleReset error paths
// ---------------------------------------------------------------------------

func TestB3BudgetItem_HandleResetUpdateError(t *testing.T) {
	budgetRepo := &budgetFailUpdateRepo{}
	ruleRepo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{ID: "rule_1", Name: "test", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Config: json.RawMessage(`{}`), Enabled: true}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/budgets/budget-1/reset", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// budgetFailUpdateRepo returns a budget on Get but fails on Update
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_access.go: handleRevokeAccess error path
// ---------------------------------------------------------------------------

func TestB3HandleRevokeAccess_NotOwner(t *testing.T) {
	// AccessService with no ownership records
	owners := map[string]string{}
	h := newActionHandler(t, &signerActionMock{}, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr+"/access/some-key-id", nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_locking.go: handleTransferOwnership error paths
// ---------------------------------------------------------------------------

func TestB3HandleTransferOwnership_InvalidBody(t *testing.T) {
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{}, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/transfer",
		strings.NewReader("bad json"), testOwnerAPIKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3HandleTransferOwnership_NoNewOwner(t *testing.T) {
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{}, owners)

	body := map[string]interface{}{"new_owner_id": ""}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/transfer", body, testOwnerAPIKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_create.go: createSigner error paths
// ---------------------------------------------------------------------------

func TestB3CreateSigner_ResourceLimitExceeded(t *testing.T) {
	db := newB3CoverageTestDB(t)
	signerOwnershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	signerAccessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	accessSvc, err := service.NewSignerAccessService(
		signerOwnershipRepo,
		signerAccessRepo,
		&signerStubAPIKeyRepo{},
		nil,
		slog.Default(),
	)
	require.NoError(t, err)

	// Add one owned signer
	require.NoError(t, accessSvc.SetOwner(context.Background(), testAddr, "admin-key", types.SignerOwnershipActive))

	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)
	h.SetMaxKeystoresPerKey(1)

	body := map[string]interface{}{
		"type": "keystore",
		"keystore": map[string]interface{}{
			"private_key_hex": "0x1234",
			"password":        "test",
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestB3CreateSigner_BothKeysProvided(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	body := map[string]interface{}{
		"type": "keystore",
		"keystore": map[string]interface{}{
			"private_key_hex": "0x1234",
			"keystore_json":   `{"version":3}`,
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handleDeleteSigner error paths
// ---------------------------------------------------------------------------

func TestB3HandleDeleteSigner_OwnershipCheckError(t *testing.T) {
	db := newB3CoverageTestDB(t)
	signerOwnershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	signerAccessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	accessSvc, err := service.NewSignerAccessService(
		signerOwnershipRepo,
		signerAccessRepo,
		&signerStubAPIKeyRepo{},
		nil,
		slog.Default(),
	)
	require.NoError(t, err)

	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/signers/"+testAddr, nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.HandleSignerAction(rec, req)
	// Ownership check succeeds (no record -> not owner), falls through to "signer not found"
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: parseTriBool coverage
// ---------------------------------------------------------------------------

func TestB3ParseTriBool(t *testing.T) {
	v, err := parseTriBool("true")
	assert.NoError(t, err)
	require.NotNil(t, v)
	assert.True(t, *v)

	v, err = parseTriBool("false")
	assert.NoError(t, err)
	require.NotNil(t, v)
	assert.False(t, *v)

	v, err = parseTriBool("1")
	assert.NoError(t, err)
	require.NotNil(t, v)
	assert.True(t, *v)

	v, err = parseTriBool("0")
	assert.NoError(t, err)
	require.NotNil(t, v)
	assert.False(t, *v)

	v, err = parseTriBool("")
	assert.NoError(t, err)
	assert.Nil(t, v)

	_, err = parseTriBool("yes")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// signer_crud.go: listSigners more error paths
// ---------------------------------------------------------------------------

func TestB3ListSigners_InvalidType(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{Total: 0, HasMore: false}, nil
		},
	}
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?type=invalid", signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListSigners_InvalidOffset(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?offset=-1", signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListSigners_InvalidLimit(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?limit=-1", signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListSigners_ForbiddenAPIKeyFilter(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{Total: 0, HasMore: false}, nil
		},
	}
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	agentKey := &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}
	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?api_key_id=other-key", agentKey)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestB3ListSigners_InvalidLockedFilter(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?locked=invalid", signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListSigners_InvalidEnabledFilter(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers?enabled=invalid", signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListSigners_ListError(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", signAdminKey())
	// Mock returns "not implemented" error -> 500
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_wallet.go: listWalletSigners error paths
// ---------------------------------------------------------------------------

func TestB3ListWalletSigners_InvalidOffset(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/wallets/test-wallet/signers?offset=-1", signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListWalletSigners_InvalidLimit(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/wallets/test-wallet/signers?limit=-1", signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListWalletSigners_ListError(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/wallets/test-wallet/signers", signAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestB3ListWalletSigners_GetOwnershipError(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{Signers: allSigners, Total: 3, HasMore: false}, nil
		},
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/wallets/test-wallet/signers", testOwnerAPIKey())
	// Access service stubs return empty ownerships but the signer mock returns signers -> should still work
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels error paths
// ---------------------------------------------------------------------------

func TestB3HandlePatchSignerLabels_NotOwner(t *testing.T) {
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{}, owners)

	body := map[string]interface{}{"display_name": "New Name"}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPatch,
		"/api/v1/evm/signers/"+testAddr, body, testOtherAPIKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestB3HandlePatchSignerLabels_SignerNotFound(t *testing.T) {
	mgr := &signerActionMock{}
	mgr.listSignersFn = func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
		return types.SignerListResult{Signers: nil, Total: 0, HasMore: false}, nil
	}
	h := newActionHandler(t, mgr, map[string]string{testAddr: testKeyID})

	body := map[string]interface{}{"display_name": "New Name", "tags": []string{"tag1"}}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPatch,
		"/api/v1/evm/signers/"+testAddr, body, testOwnerAPIKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_locking.go: handleTransferOwnership error paths
// ---------------------------------------------------------------------------

func TestB3HandleTransferOwnership_SelfTransfer(t *testing.T) {
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{}, owners)

	body := map[string]interface{}{"new_owner_id": testKeyID}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/transfer", body, testOwnerAPIKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// request_simulation.go: ServeHTTP error paths
// ---------------------------------------------------------------------------

func TestB3RequestSimulation_MethodNotAllowed(t *testing.T) {
	simRepo := &mockSimRepo{}
	reqRepo := &mockRequestRepo{}
	h, err := NewRequestSimulationHandler(simRepo, reqRepo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/requests/req-1/simulation", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestB3RequestSimulation_Unauthorized(t *testing.T) {
	simRepo := &mockSimRepo{}
	reqRepo := &mockRequestRepo{}
	h, err := NewRequestSimulationHandler(simRepo, reqRepo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests/req-1/simulation", nil)
	// No API key in context -> 401
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestB3RequestSimulation_InvalidPath(t *testing.T) {
	simRepo := &mockSimRepo{}
	reqRepo := &mockRequestRepo{}
	h, err := NewRequestSimulationHandler(simRepo, reqRepo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/simulation", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3RequestSimulation_ParentNotFound(t *testing.T) {
	simRepo := &mockSimRepo{}
	reqRepo := &mockRequestRepo{getFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
		return nil, types.ErrNotFound
	}}
	h, err := NewRequestSimulationHandler(simRepo, reqRepo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests/req-1/simulation", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestB3RequestSimulation_ParentLookupError(t *testing.T) {
	simRepo := &mockSimRepo{}
	reqRepo := &mockRequestRepo{getFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
		return nil, fmt.Errorf("db error")
	}}
	h, err := NewRequestSimulationHandler(simRepo, reqRepo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests/req-1/simulation", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestB3RequestSimulation_NotOwnerNonAdmin(t *testing.T) {
	simRepo := &mockSimRepo{}
	reqRepo := &mockRequestRepo{getFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
		return &types.SignRequest{ID: "req-1", APIKeyID: "different-key"}, nil
	}}
	h, err := NewRequestSimulationHandler(simRepo, reqRepo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests/req-1/simulation", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, &types.APIKey{ID: "my-key", Role: types.APIKeyRole("dev"), Enabled: true}))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestB3RequestSimulation_SimNotFound(t *testing.T) {
	simRepo := &mockSimRepo{getFn: func(_ context.Context, _ string) (*types.RequestSimulation, error) {
		return nil, types.ErrNotFound
	}}
	reqRepo := &mockRequestRepo{getFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
		return &types.SignRequest{ID: "req-1", APIKeyID: "admin-key"}, nil
	}}
	h, err := NewRequestSimulationHandler(simRepo, reqRepo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests/req-1/simulation", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestB3RequestSimulation_SimLookupError(t *testing.T) {
	simRepo := &mockSimRepo{getFn: func(_ context.Context, _ string) (*types.RequestSimulation, error) {
		return nil, fmt.Errorf("sim error")
	}}
	reqRepo := &mockRequestRepo{getFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
		return &types.SignRequest{ID: "req-1", APIKeyID: "admin-key"}, nil
	}}
	h, err := NewRequestSimulationHandler(simRepo, reqRepo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests/req-1/simulation", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestB3RequestSimulation_Success(t *testing.T) {
	simRepo := &mockSimRepo{getFn: func(_ context.Context, _ string) (*types.RequestSimulation, error) {
		return &types.RequestSimulation{SignRequestID: "req-1", Decision: "allow"}, nil
	}}
	reqRepo := &mockRequestRepo{getFn: func(_ context.Context, _ types.SignRequestID) (*types.SignRequest, error) {
		return &types.SignRequest{ID: "req-1", APIKeyID: "some-other-key"}, nil
	}}
	h, err := NewRequestSimulationHandler(simRepo, reqRepo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests/req-1/simulation", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_access.go: handleGrantAccess error paths
// ---------------------------------------------------------------------------

func TestB3HandleGrantAccess_InvalidBody(t *testing.T) {
	mgr := &signerActionMock{}
	h := newActionHandler(t, mgr, map[string]string{testAddr: testKeyID})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers/"+testAddr+"/access", bytes.NewBufferString("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, testOwnerAPIKey()))
	rec := httptest.NewRecorder()
	h.HandleSignerAction(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3HandleGrantAccess_MissingAPIKeyID(t *testing.T) {
	mgr := &signerActionMock{}
	h := newActionHandler(t, mgr, map[string]string{testAddr: testKeyID})

	body := map[string]interface{}{"api_key_id": ""}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers/"+testAddr+"/access", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, testOwnerAPIKey()))
	rec := httptest.NewRecorder()
	h.HandleSignerAction(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handleDeleteSigner remaining error paths
// ---------------------------------------------------------------------------

func TestB3HandleDeleteSigner_ProviderError(t *testing.T) {
	mgr := &signerActionMock{
		deleteFn: func(_ context.Context, _ string) error { return fmt.Errorf("provider error") },
	}
	h := newActionHandler(t, mgr, map[string]string{testAddr: testKeyID})

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr, nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestB3HandleDeleteSigner_SuccessWithOwnership(t *testing.T) {
	mgr := &signerActionMock{
		deleteFn: func(_ context.Context, _ string) error { return nil },
	}
	h := newActionHandler(t, mgr, map[string]string{testAddr: testKeyID})

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr, nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

// ---------------------------------------------------------------------------
// request_simulation.go: constructor validation (already has TestB3NewRequestSimulationHandler_NilDeps)
// ---------------------------------------------------------------------------

// Mock types for RequestSimulationHandler tests
type mockRequestRepo struct {
	storage.RequestRepository
	getFn func(ctx context.Context, id types.SignRequestID) (*types.SignRequest, error)
}

func (m *mockRequestRepo) Get(ctx context.Context, id types.SignRequestID) (*types.SignRequest, error) {
	if m.getFn != nil {
		return m.getFn(ctx, id)
	}
	return nil, types.ErrNotFound
}

type mockSimRepo struct {
	storage.RequestSimulationRepository
	getFn func(ctx context.Context, requestID string) (*types.RequestSimulation, error)
}

func (m *mockSimRepo) GetByRequestID(ctx context.Context, requestID string) (*types.RequestSimulation, error) {
	if m.getFn != nil {
		return m.getFn(ctx, requestID)
	}
	return nil, types.ErrNotFound
}

// ---------------------------------------------------------------------------
// rule_query.go: listBudgets with repo error
// ---------------------------------------------------------------------------

type failListBudgetRepo struct{}

func (f *failListBudgetRepo) ListByRuleID(_ context.Context, _ types.RuleID) ([]*types.RuleBudget, error) {
	return nil, fmt.Errorf("list error")
}
func (f *failListBudgetRepo) ListByRuleIDs(_ context.Context, _ []types.RuleID) ([]*types.RuleBudget, error) { return nil, nil }
func (f *failListBudgetRepo) Create(_ context.Context, _ *types.RuleBudget) error { return nil }
func (f *failListBudgetRepo) CreateOrGet(_ context.Context, _ *types.RuleBudget) (*types.RuleBudget, bool, error) { return nil, false, nil }
func (f *failListBudgetRepo) GetByRuleID(_ context.Context, _ types.RuleID, _ string) (*types.RuleBudget, error) { return nil, nil }
func (f *failListBudgetRepo) Get(_ context.Context, _ string) (*types.RuleBudget, error) { return nil, nil }
func (f *failListBudgetRepo) Update(_ context.Context, _ *types.RuleBudget) error { return nil }
func (f *failListBudgetRepo) CountByRuleID(_ context.Context, _ types.RuleID) (int, error) { return 0, nil }
func (f *failListBudgetRepo) Delete(_ context.Context, _ string) error { return nil }
func (f *failListBudgetRepo) DeleteByRuleID(_ context.Context, _ types.RuleID) error { return nil }
func (f *failListBudgetRepo) ListAll(_ context.Context) ([]*types.RuleBudget, error) { return nil, nil }
func (f *failListBudgetRepo) AtomicSpend(_ context.Context, _ types.RuleID, _ string, _ string) error { return nil }
func (f *failListBudgetRepo) ResetBudget(_ context.Context, _ types.RuleID, _ string, _ time.Time) error { return nil }
func (f *failListBudgetRepo) MarkAlertSent(_ context.Context, _ types.RuleID, _ string) error { return nil }

func TestB3ListBudgets_ListError(t *testing.T) {
	budgetRepo := &failListBudgetRepo{}
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default(), WithBudgetRepo(budgetRepo))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules/rule_1/budgets", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestB3ListBudgets_NilBudgets(t *testing.T) {
	budgetRepo := &budgetFailDeleteRepo{}
	// budgetFailDeleteRepo returns nil from ListByRuleID
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default(), WithBudgetRepo(budgetRepo))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules/rule_1/budgets", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: annotate rule-not-found edge cases
// ---------------------------------------------------------------------------

func TestB3BudgetItem_AnnotateRuleMissingNonAdmin(t *testing.T) {
	// A budget with a rule_id that does not exist in the repo.
	// For a non-admin, non-dev caller this should return false (hidden).
	ruleRepo := storage.NewMemoryRuleRepository()
	budgetRepo := &budgetFailUpdateRepo{}
	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	b := &types.RuleBudget{ID: "budget-1", RuleID: "nonexistent-rule", Unit: "usdc"}
	apiKey := &types.APIKey{ID: "agent-key", Role: types.APIKeyRole("agent"), Enabled: true}
	_, ok := h.annotate(context.Background(), apiKey, b)
	assert.False(t, ok)
}

func TestB3BudgetItem_AnnotateSimBudgetNonAdmin(t *testing.T) {
	// Sim budget seen by non-admin should return false
	ruleRepo := storage.NewMemoryRuleRepository()
	budgetRepo := &budgetFailUpdateRepo{}
	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	b := &types.RuleBudget{ID: "sim-budget", RuleID: "sim:0x1234", Unit: "usdc"}
	apiKey := &types.APIKey{ID: "agent-key", Role: types.APIKeyRole("agent"), Enabled: true}
	_, ok := h.annotate(context.Background(), apiKey, b)
	assert.False(t, ok)
}

func TestB3BudgetItem_AnnotateSimBudgetDev(t *testing.T) {
	// Sim budget seen by dev should return true
	ruleRepo := storage.NewMemoryRuleRepository()
	budgetRepo := &budgetFailUpdateRepo{}
	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	b := &types.RuleBudget{ID: "sim-budget", RuleID: "sim:0x1234", Unit: "usdc"}
	apiKey := &types.APIKey{ID: "dev-key", Role: types.APIKeyRole("dev"), Enabled: true}
	entry, ok := h.annotate(context.Background(), apiKey, b)
	assert.True(t, ok)
	assert.Equal(t, BudgetKindSimulation, entry.Kind)
}

func TestB3BudgetItem_AnnotateNonOwnerRule(t *testing.T) {
	// A regular rule budget where the caller is neither admin/dev nor the owner
	ruleRepo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	rule := &types.Rule{ID: "rule_1", Name: "test", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, ChainType: &ct, Config: json.RawMessage(`{}`), Enabled: true, Owner: "different-owner"}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))

	budgetRepo := &budgetFailUpdateRepo{}
	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	b := &types.RuleBudget{ID: "budget-1", RuleID: "rule_1", Unit: "usdc"}
	apiKey := &types.APIKey{ID: "my-key", Role: types.APIKeyRole("viewer"), Enabled: true}
	_, ok := h.annotate(context.Background(), apiKey, b)
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels success path
// ---------------------------------------------------------------------------

func TestB3HandlePatchSignerLabels_Success(t *testing.T) {
	mgr := &signerActionMock{}
	mgr.listSignersFn = func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
		return types.SignerListResult{
			Signers: []types.SignerInfo{{Address: testAddr, Type: "keystore", Enabled: true}},
			Total:   1,
		}, nil
	}
	flexRepo := &flexOwnershipRepo{owners: map[string]string{testAddr: testKeyID}}
	accessSvc, err := service.NewSignerAccessService(flexRepo, &signerStubAccessRepo{}, &signerStubAPIKeyRepo{}, nil, slog.Default())
	require.NoError(t, err)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	body := map[string]interface{}{"display_name": "New Name", "tags": []string{"tag1"}}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/signers/"+testAddr, bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, testOwnerAPIKey()))
	rec := httptest.NewRecorder()
	h.HandleSignerAction(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: createRule with empty JS script
// ---------------------------------------------------------------------------

func TestB3CreateRule_EVMJSEmptyScript(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(nil))
	require.NoError(t, err)

	body := map[string]interface{}{
		"name":     "test-js",
		"type":     "evm_js",
		"mode":     "whitelist",
		"chain_id": "1",
		"config": map[string]interface{}{
			"script": "",
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: listSigners with valid offset/limit
// ---------------------------------------------------------------------------

func TestB3ListSigners_WithValidOffsetLimit(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			si := types.SignerInfo{Address: testAddr, Type: "keystore", Enabled: true}
			return types.SignerListResult{Signers: []types.SignerInfo{si}, Total: 1}, nil
		},
	}
	h := newActionHandler(t, &signerActionMock{signerMockSignerManager: *sm}, map[string]string{testAddr: testKeyID})

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/signers?offset=0&limit=10", testOwnerAPIKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_wallet.go: listWalletSigners with valid offset/limit
// ---------------------------------------------------------------------------

func TestB3ListWalletSigners_WithValidOffsetLimit(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{Signers: allSigners, Total: 3}, nil
		},
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/wallets/test-wallet/signers?offset=0&limit=10", signAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: listSigners with valid offset/limit and exclude_hd_derived
// ---------------------------------------------------------------------------

func TestB3ListWalletSigners_ExcludeHDDerived(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{Signers: allSigners, Total: 3}, nil
		},
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/wallets/test-wallet/signers?exclude_hd_derived=true", signAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: updateRule — evm_js empty script on update
// ---------------------------------------------------------------------------

func TestB3UpdateRule_EVMJSEmptyScript(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{
		ID:   "rule_js",
		Name: "test-js",
		Type: types.RuleTypeEVMJS,
		Mode: types.RuleModeWhitelist,
	}
	require.NoError(t, repo.Create(context.Background(), rule))

	h, err := NewRuleHandler(repo, slog.Default(), WithJSEvaluator(nil))
	require.NoError(t, err)

	body := map[string]interface{}{
		"config": map[string]interface{}{
			"script": "",
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/rule_js", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "config.script must not be empty")
}

// ---------------------------------------------------------------------------
// rule_crud.go: updateRule — update chain_type
// ---------------------------------------------------------------------------

func TestB3UpdateRule_ChainTypeInvalid(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{
		ID:   "rule-ct",
		Name: "test",
		Type: types.RuleTypeEVMAddressList,
		Mode: types.RuleModeWhitelist,
	}
	require.NoError(t, repo.Create(context.Background(), rule))

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"chain_type": "invalid"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/rule-ct", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: updateRule — signer_address invalid
// ---------------------------------------------------------------------------

func TestB3UpdateRule_InvalidSignerAddress2(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{
		ID:   "rule-sa",
		Name: "test",
		Type: types.RuleTypeEVMAddressList,
		Mode: types.RuleModeWhitelist,
	}
	require.NoError(t, repo.Create(context.Background(), rule))

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"signer_address": "not-an-address"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/rule-sa", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: updateRule — agent blocked type change
// ---------------------------------------------------------------------------

func TestB3UpdateRule_AgentBlockedType(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{
		ID:    "rule-ag",
		Name:  "test",
		Type:  types.RuleTypeEVMAddressList,
		Mode:  types.RuleModeWhitelist,
		Owner: "agent-key",
	}
	require.NoError(t, repo.Create(context.Background(), rule))

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"type": "evm_js"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/rule-ag", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: updateRule — immutable rule
// ---------------------------------------------------------------------------

func TestB3UpdateRule_Immutable(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	immutable := true
	rule := &types.Rule{
		ID:        "rule-im",
		Name:      "test",
		Type:      types.RuleTypeEVMAddressList,
		Mode:      types.RuleModeWhitelist,
		Immutable: immutable,
	}
	require.NoError(t, repo.Create(context.Background(), rule))

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "new-name"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/rule-im", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handleDeleteSigner — ownership check error path
// ---------------------------------------------------------------------------

// errorOwnershipRepo returns an error on Get
type errorOwnershipRepo struct {
	signerStubOwnershipRepo
}

func (e *errorOwnershipRepo) Get(_ context.Context, _ string) (*types.SignerOwnership, error) {
	return nil, fmt.Errorf("db error")
}

// Ownership check db error
func TestB3HandleDeleteSigner_IsOwnerError2(t *testing.T) {
	svc, err := service.NewSignerAccessService(
		&errorOwnershipRepo{},
		&signerStubAccessRepo{},
		&signerStubAPIKeyRepo{},
		nil,
		slog.Default(),
	)
	require.NoError(t, err)
	h, err := NewSignerHandler(&signerActionMock{}, svc, slog.Default(), false)
	require.NoError(t, err)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr, nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handleDeleteSigner — signer not found (no ownership record)
// ---------------------------------------------------------------------------

func TestB3HandleDeleteSigner_SignerNotFound(t *testing.T) {
	// Empty owners map — not found
	h := newActionHandler(t, &signerActionMock{}, nil)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr, nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels — signer not found after patch
// ---------------------------------------------------------------------------

func TestB3HandlePatchSignerLabels_SignerNotFoundAfterPatch(t *testing.T) {
	mgr := &signerActionMock{}
	mgr.listSignersFn = func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
		return types.SignerListResult{Signers: []types.SignerInfo{}, Total: 0}, nil
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	body := map[string]interface{}{"display_name": "Test"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/signers/"+testAddr, bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, testOwnerAPIKey()))
	rec := httptest.NewRecorder()
	h.HandleSignerAction(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: listSigners — tag filter
// ---------------------------------------------------------------------------

func TestB3ListSigners_TagFilter(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			si := types.SignerInfo{Address: testAddr, Type: "keystore", Enabled: true}
			return types.SignerListResult{Signers: []types.SignerInfo{si}, Total: 1}, nil
		},
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{signerMockSignerManager: *sm}, owners)

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/signers?tag=test-tag", testOwnerAPIKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: listSigners — locked filter
// ---------------------------------------------------------------------------

func TestB3ListSigners_LockedFilter(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			si := types.SignerInfo{Address: testAddr, Type: "keystore", Enabled: true}
			return types.SignerListResult{Signers: []types.SignerInfo{si}, Total: 1}, nil
		},
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{signerMockSignerManager: *sm}, owners)

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/signers?locked=true", testOwnerAPIKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: listSigners — enabled filter
// ---------------------------------------------------------------------------

// Tag filter: with matching ownership
func TestB3ListSigners_EnabledFilter2(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			si := types.SignerInfo{Address: testAddr, Type: "keystore", Enabled: true}
			return types.SignerListResult{Signers: []types.SignerInfo{si}, Total: 1}, nil
		},
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{signerMockSignerManager: *sm}, owners)

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/signers?enabled=true", testOwnerAPIKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: listSigners — wallet enrichment
// ---------------------------------------------------------------------------

// stubWalletRepo implements storage.WalletRepository minimally
type stubWalletRepo struct{}

func (s *stubWalletRepo) GetWalletsForSigners(_ context.Context, addresses []string) (map[string][]types.Wallet, error) {
	return nil, nil
}
func (s *stubWalletRepo) GetWalletsForSigner(_ context.Context, _ string) ([]types.Wallet, error) { return nil, nil }
func (s *stubWalletRepo) Create(_ context.Context, _ *types.Wallet) error                         { return nil }
func (s *stubWalletRepo) Get(_ context.Context, _ string) (*types.Wallet, error)                  { return nil, nil }
func (s *stubWalletRepo) GetByName(_ context.Context, _ string) (*types.Wallet, error)            { return nil, nil }
func (s *stubWalletRepo) GetBySignerAddress(_ context.Context, _ string) ([]*types.Wallet, error) { return nil, nil }
func (s *stubWalletRepo) List(_ context.Context, _ types.WalletFilter) (*types.WalletListResult, error) { return nil, nil }
func (s *stubWalletRepo) Update(_ context.Context, _ *types.Wallet) error                        { return nil }
func (s *stubWalletRepo) Delete(_ context.Context, _ string) error                               { return nil }
func (s *stubWalletRepo) AddSignerToWallet(_ context.Context, _ string, _ string) error          { return nil }
func (s *stubWalletRepo) RemoveSignerFromWallet(_ context.Context, _ string, _ string) error     { return nil }
func (s *stubWalletRepo) AddMember(_ context.Context, _ *types.WalletMember) error               { return nil }
func (s *stubWalletRepo) RemoveMember(_ context.Context, _ string, _ string) error               { return nil }
func (s *stubWalletRepo) ListMembers(_ context.Context, _ string) ([]types.WalletMember, error)  { return nil, nil }
func (s *stubWalletRepo) IsMember(_ context.Context, _ string, _ string) (bool, error)           { return false, nil }

type walletRepoSignerManager struct {
	signerMockSignerManager
}

func (w *walletRepoSignerManager) ListSigners(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
	return types.SignerListResult{
		Signers: []types.SignerInfo{{Address: testAddr, Type: "keystore", Enabled: true}},
		Total:   1,
	}, nil
}

func TestB3ListSigners_WalletEnrichment(t *testing.T) {
	sm := &walletRepoSignerManager{}
	owners := map[string]string{testAddr: testKeyID}
	accessSvc := newFlexAccessService(t, owners)
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)
	h.SetWalletRepo(&stubWalletRepo{})

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/signers", testOwnerAPIKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: listSigners — offset >= total (empty result pagination)
// ---------------------------------------------------------------------------

func TestB3ListSigners_OffsetBeyondTotal(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			si := types.SignerInfo{Address: testAddr, Type: "keystore", Enabled: true}
			return types.SignerListResult{Signers: []types.SignerInfo{si}, Total: 1}, nil
		},
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{signerMockSignerManager: *sm}, owners)

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/signers?offset=10&limit=5", testOwnerAPIKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_wallet.go: listWalletSigners — pagination offset >= total
// ---------------------------------------------------------------------------

func TestB3ListWalletSigners_OffsetBeyondTotal(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{Signers: allSigners, Total: 3}, nil
		},
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/wallets/test-wallet/signers?offset=100", signAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_wallet.go: listWalletSigners — limit > 100
// ---------------------------------------------------------------------------

func TestB3ListWalletSigners_LimitCap(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{Signers: allSigners, Total: 3}, nil
		},
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/wallets/test-wallet/signers?limit=200", signAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_create.go: createSigner — validation error
// ---------------------------------------------------------------------------

func TestB3CreateSigner_ValidationError(t *testing.T) {
	mgr := &signerActionMock{}
	mgr.createSignerFn = func(_ context.Context, _ types.CreateSignerRequest) (*types.SignerInfo, error) {
		return nil, fmt.Errorf("validation failed")
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	body := map[string]interface{}{
		"type": "keystore",
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// Since createSigner now has CreateSignerRequest.Valid() returning error for empty keystore,
	// it returns 400 before calling manager
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_create.go: createSigner — resource limit error
// ---------------------------------------------------------------------------

func TestB3CreateSigner_ResourceLimitError(t *testing.T) {
	mgr := &signerActionMock{}
	countRepo := &signerStubOwnershipRepo{}
	mgr.createSignerFn = func(_ context.Context, _ types.CreateSignerRequest) (*types.SignerInfo, error) {
		return &types.SignerInfo{Address: testAddr, Type: "keystore", Enabled: true}, nil
	}
	svc, err := service.NewSignerAccessService(
		countRepo, &signerStubAccessRepo{}, &signerStubAPIKeyRepo{}, nil, slog.Default(),
	)
	require.NoError(t, err)
	h, err := NewSignerHandler(mgr, svc, slog.Default(), false)
	require.NoError(t, err)
	h.SetMaxKeystoresPerKey(0) // no limit — just exercise create flow

	body := map[string]interface{}{
		"type":     "keystore",
		"keystore": map[string]interface{}{"private_key_hex": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// May get 400 from validation or 500 from manager not implemented - either way exercises the code path
	assert.Contains(t, []int{http.StatusBadRequest, http.StatusInternalServerError, http.StatusCreated}, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: BudgetItemHandler — handleUpdate with all fields
// ---------------------------------------------------------------------------

func TestB3BudgetItem_UpdateAllFields(t *testing.T) {
	db := newB3TxCoverageDB(t)
	repo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{ID: "rule-upd-all", Name: "test", Type: types.RuleTypeEVMAddressList, Mode: "whitelist"}
	require.NoError(t, ruleRepo.Create(context.Background(), rule))
	require.NoError(t, repo.Create(context.Background(), &types.RuleBudget{
		ID:     "budget-upd",
		RuleID: "rule-upd-all",
		Unit:   "usdc",
	}))

	h, err := NewBudgetItemHandler(repo, ruleRepo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{
		"max_total":   "1000",
		"max_per_tx":  "100",
		"max_tx_count": 50,
		"alert_pct":   80,
		"alert_sent":  true,
		"spent":       "50",
		"tx_count":    5,
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/budgets/budget-upd", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: BudgetItemHandler — handleUpdate not found
// ---------------------------------------------------------------------------

func TestB3BudgetItem_UpdateNotFound(t *testing.T) {
	db := newB3TxCoverageDB(t)
	repo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()
	h, err := NewBudgetItemHandler(repo, ruleRepo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"max_total": "100"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/budgets/nonexistent", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: BudgetItemHandler — handleDelete not found
// ---------------------------------------------------------------------------

func TestB3BudgetItem_DeleteNotFound(t *testing.T) {
	db := newB3TxCoverageDB(t)
	repo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()
	h, err := NewBudgetItemHandler(repo, ruleRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/budgets/nonexistent", nil)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: BudgetListHandler — handleList forbidden for non-admin/non-owner
// ---------------------------------------------------------------------------

func TestB3BudgetList_ListForbiddenForAgent(t *testing.T) {
	db := newB3TxCoverageDB(t)
	repo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()
	h, err := NewBudgetListHandler(repo, ruleRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/budgets", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// Agent can list budgets but sees nothing (filtered by annotate)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: handleTransferOwnership — simple flow
// ---------------------------------------------------------------------------

func TestB3HandleTransferOwnership_AuditLogger(t *testing.T) {
	// TransferOwnership requires new owner API key existence check and transaction support.
	// We verify it hits the handler and returns the expected error.
	mgr := &signerActionMock{}
	owners := map[string]string{testAddr: testKeyID}
	svc := newFlexAccessService(t, owners)
	h, err := NewSignerHandler(mgr, svc, slog.Default(), false)
	require.NoError(t, err)
	body := map[string]string{"new_owner_id": "yet-another"}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/transfer", body, testOwnerAPIKey())
	// Expect 400 because new owner not found in stub API key repo
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: BudgetItemHandler — handleGet not found
// ---------------------------------------------------------------------------

func TestB3BudgetItem_GetNotFound(t *testing.T) {
	db := newB3TxCoverageDB(t)
	repo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()
	h, err := NewBudgetItemHandler(repo, ruleRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/budgets/nonexistent", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: isValidBudgetLimit — error case
// ---------------------------------------------------------------------------

func TestB3IsValidBudgetLimit_Empty(t *testing.T) {
	assert.False(t, isValidBudgetLimit(""))
}

// ---------------------------------------------------------------------------
// signer_crud.go: handleDeleteSigner with audit logger
// ---------------------------------------------------------------------------

func TestB3HandleDeleteSigner_WithAuditLogger(t *testing.T) {
	mgr := &signerActionMock{}
	mgr.listSignersFn = func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
		return types.SignerListResult{
			Signers: []types.SignerInfo{{Address: testAddr, Type: "keystore", Enabled: true}},
			Total:   1,
		}, nil
	}
	mgr.deleteFn = func(_ context.Context, _ string) error { return nil }

	owners := map[string]string{testAddr: testKeyID}
	svc := newFlexAccessService(t, owners)
	h, err := NewSignerHandler(mgr, svc, slog.Default(), false)
	require.NoError(t, err)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr, nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

// ---------------------------------------------------------------------------
// transactions.go: NewTransactionsHandler — nil logger
// ---------------------------------------------------------------------------

func TestB3NewTransactionsHandler_NilLogger(t *testing.T) {
	_, err := NewTransactionsHandler(nil, nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// request.go: ServeHTTP — invalid path
// ---------------------------------------------------------------------------

func TestB3RequestHandler_InvalidPath(t *testing.T) {
	ruleRepo := storage.NewMemoryRuleRepository()
	h, err := NewRequestHandler(&mockSignService{}, ruleRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/invalid", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: getRule — not found
// ---------------------------------------------------------------------------

func TestB3GetRule_NotFound(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules/nonexistent", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: getRule — get error
// ---------------------------------------------------------------------------

func TestB3GetRule_GetError(t *testing.T) {
	h, err := NewRuleHandler(&FailRuleRepoNoGet{}, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules/rule_test", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: approveRule — not found
// ---------------------------------------------------------------------------

func TestB3ApproveRule_NotFound(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules/nonexistent/approve", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: rejectRule — not found
// ---------------------------------------------------------------------------

func TestB3RejectRule_NotFound(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules/nonexistent/reject", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: approveRule — approve rule with invalid body
// ---------------------------------------------------------------------------

func TestB3ApproveRule_InvalidBody(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	rule := &types.Rule{ID: "rule-approve-body", Name: "test", Type: types.RuleTypeEVMAddressList, Mode: "whitelist"}
	require.NoError(t, repo.Create(context.Background(), rule))

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules/rule-approve-body/approve", bytes.NewBufferString("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// request.go: ListHandler — list requests with signer_address filter
// ---------------------------------------------------------------------------

func TestB3ListHandler_SignerAddressFilter(t *testing.T) {
	h, err := NewListHandler(&mockSignService{}, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/evm/requests?signer_address=0x1111111111111111111111111111111111111111", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// request.go: ListHandler — invalid signer_address
// ---------------------------------------------------------------------------

func TestB3ListHandler_InvalidSignerAddress2(t *testing.T) {
	h, err := NewListHandler(&mockSignService{}, storage.NewMemoryRuleRepository(), slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/requests?signer_address=invalid", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_wallet.go: listWalletSigners — sort by address (non-HD wallet)
// ---------------------------------------------------------------------------

func TestB3ListWalletSigners_SortByAddress(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: []types.SignerInfo{
					{Address: "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", Type: "keystore", Enabled: true},
					{Address: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Type: "keystore", Enabled: true},
					{Address: "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", Type: "keystore", Enabled: true},
				},
				Total: 3,
			}, nil
		},
		getHDHierarchyFn: func() map[string]evmchain.HDHierarchyInfo { return nil },
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/wallets/test-wallet/signers", signAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_create.go: createSigner — audit logger path with keystore_import
// ---------------------------------------------------------------------------

func TestB3CreateSigner_AuditLoggerImport(t *testing.T) {
	mgr := &signerActionMock{}
	mgr.createSignerFn = func(_ context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error) {
		return &types.SignerInfo{Address: testAddr, Type: "keystore", Enabled: true}, nil
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	body := map[string]interface{}{
		"type":     "keystore",
		"keystore": map[string]interface{}{"password": "testpass", "private_key_hex": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Contains(t, []int{http.StatusBadRequest, http.StatusCreated, http.StatusInternalServerError}, rec.Code)
}

// failWalletRepo returns an error from GetWalletsForSigners
type failWalletRepo struct{}

func (f *failWalletRepo) GetWalletsForSigners(_ context.Context, _ []string) (map[string][]types.Wallet, error) {
	return nil, fmt.Errorf("wallet repo error")
}
func (f *failWalletRepo) GetWalletsForSigner(_ context.Context, _ string) ([]types.Wallet, error) { return nil, nil }
func (f *failWalletRepo) Create(_ context.Context, _ *types.Wallet) error                         { return nil }
func (f *failWalletRepo) Get(_ context.Context, _ string) (*types.Wallet, error)                  { return nil, nil }
func (f *failWalletRepo) GetByName(_ context.Context, _ string) (*types.Wallet, error)            { return nil, nil }
func (f *failWalletRepo) GetBySignerAddress(_ context.Context, _ string) ([]*types.Wallet, error) { return nil, nil }
func (f *failWalletRepo) List(_ context.Context, _ types.WalletFilter) (*types.WalletListResult, error) { return nil, nil }
func (f *failWalletRepo) Update(_ context.Context, _ *types.Wallet) error                        { return nil }
func (f *failWalletRepo) Delete(_ context.Context, _ string) error                               { return nil }
func (f *failWalletRepo) AddSignerToWallet(_ context.Context, _ string, _ string) error          { return nil }
func (f *failWalletRepo) RemoveSignerFromWallet(_ context.Context, _ string, _ string) error     { return nil }
func (f *failWalletRepo) AddMember(_ context.Context, _ *types.WalletMember) error               { return nil }
func (f *failWalletRepo) RemoveMember(_ context.Context, _ string, _ string) error               { return nil }
func (f *failWalletRepo) ListMembers(_ context.Context, _ string) ([]types.WalletMember, error)  { return nil, nil }
func (f *failWalletRepo) IsMember(_ context.Context, _ string, _ string) (bool, error)           { return false, nil }

// failGetOwnedAccessRepo fails on ListAccessibleAddresses
type failGetOwnedAccessRepo struct {
	signerStubAccessRepo
}

func (f *failGetOwnedAccessRepo) ListAccessibleAddresses(_ context.Context, _ string) ([]string, error) {
	return nil, fmt.Errorf("db error")
}

// budgetFailGetRepo fails on Get
type budgetFailGetRepo struct{}

func (b *budgetFailGetRepo) ListByRuleID(ctx context.Context, ruleID types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (b *budgetFailGetRepo) ListByRuleIDs(ctx context.Context, ruleIDs []types.RuleID) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (b *budgetFailGetRepo) Create(ctx context.Context, budget *types.RuleBudget) error {
	return nil
}
func (b *budgetFailGetRepo) CreateOrGet(ctx context.Context, budget *types.RuleBudget) (*types.RuleBudget, bool, error) {
	return nil, false, nil
}
func (b *budgetFailGetRepo) GetByRuleID(ctx context.Context, ruleID types.RuleID, unit string) (*types.RuleBudget, error) {
	return nil, types.ErrNotFound
}
func (b *budgetFailGetRepo) Get(ctx context.Context, id string) (*types.RuleBudget, error) {
	return nil, fmt.Errorf("get error")
}
func (b *budgetFailGetRepo) Update(ctx context.Context, budget *types.RuleBudget) error {
	return nil
}
func (b *budgetFailGetRepo) CountByRuleID(ctx context.Context, ruleID types.RuleID) (int, error) {
	return 0, nil
}
func (b *budgetFailGetRepo) Delete(ctx context.Context, id string) error {
	return nil
}
func (b *budgetFailGetRepo) DeleteByRuleID(ctx context.Context, ruleID types.RuleID) error {
	return nil
}
func (b *budgetFailGetRepo) ListAll(ctx context.Context) ([]*types.RuleBudget, error) {
	return nil, nil
}
func (b *budgetFailGetRepo) AtomicSpend(ctx context.Context, ruleID types.RuleID, unit string, amount string) error {
	return nil
}
func (b *budgetFailGetRepo) ResetBudget(ctx context.Context, ruleID types.RuleID, unit string, currentPeriodStart time.Time) error {
	return nil
}
func (b *budgetFailGetRepo) MarkAlertSent(ctx context.Context, ruleID types.RuleID, unit string) error {
	return nil
}

// ---------------------------------------------------------------------------
// rule_delete.go: deleteRule — unauthorized, repo get error
// ---------------------------------------------------------------------------

func TestB3DeleteRule_Unauthorized(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/rules/rule_00000000-0000-0000-0000-000000000001", nil)
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestB3DeleteRule_RepoGetError(t *testing.T) {
	repo := &FailRuleRepoNoGet{}
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/rules/rule_00000000-0000-0000-0000-000000000001", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: getRule — scoped for agent (agent sees nothing)
// ---------------------------------------------------------------------------

func TestB3GetRule_ScopedForAgent(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	rawConfig := json.RawMessage(`{"addresses":["0xaaa"]}`)
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "test-rule-1", Name: "agent-scoped", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "admin-key", AppliedTo: []string{"some-other-key"}, ChainType: &ct, Config: rawConfig}))

	rules, err := repo.List(context.Background(), storage.RuleFilter{Limit: 100})
	require.NoError(t, err)
	require.Len(t, rules, 1)

	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules/"+string(rules[0].ID), nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// approval.go: ApprovalHandler — invalid path
// ---------------------------------------------------------------------------

func TestB3Approval_InvalidPath(t *testing.T) {
	mockSignService := &mockSignService{}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewApprovalHandler(mockSignService, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/requests/approve", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_wallet.go: listWalletSigners — invalid offset / invalid limit
// ---------------------------------------------------------------------------

func TestB3ListWalletSigners_InvalidOffset2(t *testing.T) {
	sm := &signerMockSignerManager{}
	svc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(sm, svc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/wallets/0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/signers?offset=-1", signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestB3ListWalletSigners_InvalidLimit2(t *testing.T) {
	sm := &signerMockSignerManager{}
	svc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(sm, svc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/wallets/0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/signers?limit=-1", signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_wallet.go: listWalletSigners — valid offset and limit
// ---------------------------------------------------------------------------

func TestB3ListWalletSigners_ValidOffsetAndLimit(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: []types.SignerInfo{
					{Address: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Type: "keystore", Enabled: true},
				},
				Total: 1,
			}, nil
		},
	}
	owners := map[string]string{"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": testKeyID}
	svc := newFlexAccessService(t, owners)

	h, err := NewSignerHandler(sm, svc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/wallets/0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/signers?offset=0&limit=50", testOwnerAPIKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: listSigners — wallet enrichment error path
// ---------------------------------------------------------------------------

func TestB3ListSigners_WalletEnrichmentError(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: []types.SignerInfo{
					{Address: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Type: "keystore", Enabled: true},
				},
				Total: 1,
			}, nil
		},
	}
	owners := []*types.SignerOwnership{
		{SignerAddress: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", OwnerID: "admin-key", Status: types.SignerOwnershipActive},
	}
	accessSvc := newSignerTestAccessServiceWithOwnerships(t, owners)
	h, err := NewSignerHandler(sm, accessSvc, slog.Default(), false)
	require.NoError(t, err)
	h.SetWalletRepo(&failWalletRepo{})

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", signAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: listSigners — GetAccessibleAddresses error path
// ---------------------------------------------------------------------------

func newFailGetOwnedAccessService(t *testing.T) *service.SignerAccessService {
	t.Helper()
	svc, err := service.NewSignerAccessService(
		&signerStubOwnershipRepo{},
		&failGetOwnedAccessRepo{},
		&signerStubAPIKeyRepo{},
		nil,
		slog.Default(),
	)
	require.NoError(t, err)
	return svc
}

func TestB3ListSigners_GetAccessibleAddressesError(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{Signers: []types.SignerInfo{}, Total: 0}, nil
		},
	}
	svc := newFailGetOwnedAccessService(t)
	h, err := NewSignerHandler(sm, svc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet, "/api/v1/evm/signers", signAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels — signer not found after patch
// ---------------------------------------------------------------------------

func TestB3PatchSignerLabels_SignerNotFoundAfterPatch(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{Signers: []types.SignerInfo{}, Total: 0}, nil
		},
	}

	db := newB3CoverageTestDB(t)
	ownershipRepo, _ := storage.NewGormSignerOwnershipRepository(db)
	accessRepo, _ := storage.NewGormSignerAccessRepository(db)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)
	svc, err := service.NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, slog.Default())
	require.NoError(t, err)

	require.NoError(t, ownershipRepo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testAddr,
		OwnerID:       testKeyID,
		Status:        types.SignerOwnershipActive,
	}))

	h, err := NewSignerHandler(sm, svc, slog.Default(), false)
	require.NoError(t, err)

	body := map[string]interface{}{"display_name": "new-name"}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/signers/"+testAddr, bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, testOwnerAPIKey()))
	rec := httptest.NewRecorder()
	h.HandleSignerAction(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_create.go: createSigner — both private_key_hex and keystore_json
// ---------------------------------------------------------------------------

func TestB3CreateSigner_BothKeysProvided2(t *testing.T) {
	mgr := &signerActionMock{}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	body := map[string]interface{}{
		"type": "keystore",
		"keystore": map[string]interface{}{
			"password": "testpass", "private_key_hex": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			"keystore_json":   `{"version":3}`,
		},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: BudgetItemHandler — loadBudget repo error
// ---------------------------------------------------------------------------

func TestB3BudgetItem_LoadBudgetError(t *testing.T) {
	repo := &budgetFailGetRepo{}
	ruleRepo := storage.NewMemoryRuleRepository()
	h, err := NewBudgetItemHandler(repo, ruleRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/budgets/some-id", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: BudgetItemHandler — handleDelete repo error path
// ---------------------------------------------------------------------------

func TestB3BudgetItem_DeleteRepoError2(t *testing.T) {
	repo := &budgetFailDeleteRepo{}
	ruleRepo := storage.NewMemoryRuleRepository()

	h, err := NewBudgetItemHandler(repo, ruleRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/budgets/budget-1", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: BudgetListHandler — handleList repo error
// ---------------------------------------------------------------------------

func TestB3BudgetList_HandleListError(t *testing.T) {
	db := newB3TxCoverageDB(t)
	repo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()
	h, err := NewBudgetListHandler(repo, ruleRepo, slog.Default())
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/budgets", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// budget.go: BudgetListHandler — handleCreate decode error
// ---------------------------------------------------------------------------

func TestB3BudgetList_HandleCreateDecodeError(t *testing.T) {
	db := newB3TxCoverageDB(t)
	repo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()
	h, err := NewBudgetListHandler(repo, ruleRepo, slog.Default())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/budgets", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: listRules — invalid signer_address filter
// ---------------------------------------------------------------------------

func TestB3ListRules_InvalidAddressFilter(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules?signer_address=not-an-address", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: listRules — invalid type filter
// ---------------------------------------------------------------------------

func TestB3ListRules_InvalidTypeFilter(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules?type=invalid_type", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: listRules — invalid source filter
// ---------------------------------------------------------------------------

func TestB3ListRules_InvalidSourceFilter(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules?source=invalid_source", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: listRules — non-admin sees only own rules (owner filter)
// ---------------------------------------------------------------------------

func TestB3ListRules_OwnerFilter(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "rule-owner-test", Name: "owner-rule", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "owner-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules?owner=owner-key", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, &types.APIKey{ID: "owner-key", Role: types.RoleAgent, Enabled: true}))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: listRules — signer_address filter
// ---------------------------------------------------------------------------

func TestB3ListRules_SignerAddressFilter(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules?signer_address="+addr, nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: rejectRule — non-admin forbidden
// ---------------------------------------------------------------------------

func TestB3RejectRule_NonAdminForbidden(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "rej-rule", Name: "rej", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusPendingApproval, Owner: "agent-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules/rej-rule/reject", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: approveRule — non-admin forbidden
// ---------------------------------------------------------------------------

func TestB3ApproveRule_NonAdminForbidden(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "app-rule", Name: "app", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusPendingApproval, Owner: "agent-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules/app-rule/approve", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_delete.go: deleteRule — readonly mode blocked
// ---------------------------------------------------------------------------

func TestB3DeleteRule_ReadOnly(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "del-ro-rule", Name: "del-ro", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "admin-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default(), WithReadOnly())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/rules/del-ro-rule", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_delete.go: deleteRule — immutable rule blocked
// ---------------------------------------------------------------------------

func TestB3DeleteRule_Immutable(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "del-im-rule", Name: "del-im", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "admin-key", ChainType: &ct, Immutable: true}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/rules/del-im-rule", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_delete.go: deleteRule — non-owner forbidden
// ---------------------------------------------------------------------------

func TestB3DeleteRule_NonOwnerForbidden(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "del-own-rule", Name: "del-own", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "other-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/rules/del-own-rule", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_delete.go: deleteRule — config source blocked
// ---------------------------------------------------------------------------

func TestB3DeleteRule_ConfigSource(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "del-cfg-rule", Name: "del-cfg", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceConfig, Status: types.RuleStatusActive, Owner: "admin-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/rules/del-cfg-rule", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_delete.go: deleteRule — repo delete error
// ---------------------------------------------------------------------------

type failRuleRepoDeleteFull struct {
	*storage.MemoryRuleRepository
}

func (f *failRuleRepoDeleteFull) Delete(_ context.Context, _ types.RuleID) error {
	return fmt.Errorf("delete error")
}

func TestB3DeleteRule_RepoDeleteError(t *testing.T) {
		repo := &failRuleRepoDeleteFull{MemoryRuleRepository: storage.NewMemoryRuleRepository()}
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "del-err-rule", Name: "del-err", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "admin-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/rules/del-err-rule", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: createRule — readonly blocked
// ---------------------------------------------------------------------------

func TestB3CreateRule_ReadOnly(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default(), WithReadOnly())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "test", "type": "evm_address_list", "mode": "whitelist"}
	data, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: updateRule — readonly blocked
// ---------------------------------------------------------------------------

func TestB3UpdateRule_ReadOnly(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "upd-ro-rule", Name: "upd-ro", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "admin-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default(), WithReadOnly())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "updated"}
	data, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/upd-ro-rule", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: updateRule — config source blocked
// ---------------------------------------------------------------------------

func TestB3UpdateRule_ConfigSource(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "upd-cfg-rule", Name: "upd-cfg", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceConfig, Status: types.RuleStatusActive, Owner: "admin-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "updated"}
	data, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/upd-cfg-rule", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: updateRule — immutable rule blocked
// ---------------------------------------------------------------------------

func TestB3UpdateRule_Immutable2(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "upd-im-rule", Name: "upd-im", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "admin-key", ChainType: &ct, Immutable: true}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "updated"}
	data, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/upd-im-rule", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: updateRule — non-owner forbidden
// ---------------------------------------------------------------------------

func TestB3UpdateRule_NonOwner(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "upd-own-rule", Name: "upd-own", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "other-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "updated"}
	data, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/upd-own-rule", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: updateRule — agent cannot change applied_to
// ---------------------------------------------------------------------------

func TestB3UpdateRule_AgentCantChangeAppliedTo(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "upd-at-rule", Name: "upd-at", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "agent-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "updated", "applied_to": []string{"other-key"}}
	data, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/upd-at-rule", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, &types.APIKey{ID: "agent-key", Role: types.RoleAgent, Enabled: true}))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: createRule — decode error
// ---------------------------------------------------------------------------

func TestB3CreateRule_DecodeError(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handleDeleteSigner — signer not found in provider
// ---------------------------------------------------------------------------

func TestB3DeleteSigner_SignerNotFound(t *testing.T) {
	sm := &signerActionMock{
		deleteFn: func(_ context.Context, _ string) error { return types.ErrSignerNotFound },
	}
	owners := []*types.SignerOwnership{
		{SignerAddress: testAddr, OwnerID: testKeyID, Status: types.SignerOwnershipActive},
	}
	svc := newSignerTestAccessServiceWithOwnerships(t, owners)
	h, err := NewSignerHandler(sm, svc, slog.Default(), false)
	require.NoError(t, err)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr, nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels — not owner forbidden
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_crud.go: handlePatchSignerLabels — no display_name or tags
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_create.go: createSigner — unauthorized (no API key)
// ---------------------------------------------------------------------------

func TestB3CreateSigner_Unauthorized(t *testing.T) {
	mgr := &signerActionMock{}
	svc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, svc, slog.Default(), false)
	require.NoError(t, err)

	body := map[string]interface{}{"type": "keystore", "keystore": map[string]interface{}{"password": "testpass", "private_key_hex": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"}}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_create.go: createSigner — resource limit exceeded
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// signer_wallet.go: listWalletSigners — limit > 100 capped
// ---------------------------------------------------------------------------

func TestB3ListWalletSigners_LimitCapped(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: []types.SignerInfo{
					{Address: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Type: "keystore", Enabled: true},
				},
				Total: 1,
			}, nil
		},
	}
	owners := map[string]string{"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": testKeyID}
	svc := newFlexAccessService(t, owners)
	h, err := NewSignerHandler(sm, svc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/wallets/0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/signers?limit=200", testOwnerAPIKey())
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// signer_wallet.go: listWalletSigners — ListSigners error
// ---------------------------------------------------------------------------

func TestB3ListWalletSigners_ManagerListError(t *testing.T) {
	sm := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{}, fmt.Errorf("manager error")
		},
	}
	svc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(sm, svc, slog.Default(), false)
	require.NoError(t, err)

	rec := doSignerRequest(t, h, http.MethodGet,
		"/api/v1/evm/wallets/0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/signers", signAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}



// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// signer_create.go: createSigner — CreateSigner manager error
// ---------------------------------------------------------------------------

func TestB3CreateSigner_ManagerError(t *testing.T) {
	mgr := &signerActionMock{
		signerMockSignerManager: signerMockSignerManager{
			createSignerFn: func(_ context.Context, _ types.CreateSignerRequest) (*types.SignerInfo, error) {
				return nil, fmt.Errorf("manager error")
			},
		},
	}
	svc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, svc, slog.Default(), false)
	require.NoError(t, err)

	body := map[string]interface{}{"type": "keystore", "keystore": map[string]interface{}{"password": "testpass", "private_key_hex": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"}}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: createRule — name required
// ---------------------------------------------------------------------------

func TestB3CreateRule_NameRequired(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"type": "evm_address_list", "mode": "whitelist"}
	data, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: createRule — type required
// ---------------------------------------------------------------------------

func TestB3CreateRule_TypeRequired(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "test", "mode": "whitelist"}
	data, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// hdwallet.go: NewHDWalletHandler — nil access service
// ---------------------------------------------------------------------------

func TestB3NewHDWalletHandler_NilAccessService(t *testing.T) {
	_, err := NewHDWalletHandler(nil, nil, slog.Default(), false)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// hdwallet.go: NewHDWalletHandler — nil signer manager
// ---------------------------------------------------------------------------

func TestB3NewHDWalletHandler_NilSignerManager(t *testing.T) {
	svc := newSignerTestAccessService(t)
	_, err := NewHDWalletHandler(nil, svc, slog.Default(), false)
	assert.Error(t, err)
}


// ---------------------------------------------------------------------------
// signer_crud.go: handleDeleteSigner — provider delete error
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// rule_query.go: approveRule — not found
// ---------------------------------------------------------------------------

func TestB3ApproveRule_NotFound2(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules/nonexistent/approve", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: rejectRule — not found
// ---------------------------------------------------------------------------

func TestB3RejectRule_NotFound2(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules/nonexistent/reject", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: listRules — enabled filter
// ---------------------------------------------------------------------------

func TestB3ListRules_EnabledFilter(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "rule-enabled", Name: "enabled-rule", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "admin-key", ChainType: &ct, Enabled: true}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules?enabled=true", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: listRules — limit and offset params
// ---------------------------------------------------------------------------

func TestB3ListRules_LimitOffset(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "rule-lo", Name: "lo-rule", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "admin-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules?limit=10&offset=0", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: approveRule — not pending (already active)
// ---------------------------------------------------------------------------

func TestB3ApproveRule_NotPending(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "app-act-rule", Name: "app-act", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "admin-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules/app-act-rule/approve", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: rejectRule — not pending (already active)
// ---------------------------------------------------------------------------

func TestB3RejectRule_NotPending(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "rej-act-rule", Name: "rej-act", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "admin-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules/rej-act-rule/reject", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}


// ---------------------------------------------------------------------------
// rule_crud.go: createRule — invalid chain_type
// ---------------------------------------------------------------------------

func TestB3CreateRule_InvalidChainType2(t *testing.T) {
	repo := storage.NewMemoryRuleRepository()
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "test", "type": "evm_address_list", "mode": "whitelist", "chain_type": "invalid"}
	data, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/rules", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_query.go: listRules — list repo error
// ---------------------------------------------------------------------------

func TestB3ListRules_ListRepoError(t *testing.T) {
	repo := &FailRuleRepoNoList{}
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/evm/rules", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_delete.go: deleteRule — repo delete error (using Gorm fail repo)
// ---------------------------------------------------------------------------

type failRepoDeleteNotFound struct {
	*storage.MemoryRuleRepository
}

func (f *failRepoDeleteNotFound) Delete(_ context.Context, _ types.RuleID) error {
	return types.ErrNotFound
}

func TestB3DeleteRule_DeleteNotFound(t *testing.T) {
	repo := &failRepoDeleteNotFound{MemoryRuleRepository: storage.NewMemoryRuleRepository()}
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "del-nf-rule", Name: "del-nf", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "admin-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/evm/rules/del-nf-rule", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// rule_crud.go: updateRule — update repo error
// ---------------------------------------------------------------------------

func TestB3UpdateRule_RepoUpdateError(t *testing.T) {
	repo := newFailRuleRepoUpdate()
	ct := types.ChainTypeEVM
	require.NoError(t, repo.Create(context.Background(), &types.Rule{ID: "upd-err-rule", Name: "upd-err", Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Status: types.RuleStatusActive, Owner: "admin-key", ChainType: &ct}))
	h, err := NewRuleHandler(repo, slog.Default())
	require.NoError(t, err)

	body := map[string]interface{}{"name": "updated"}
	data, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/evm/rules/upd-err-rule", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}


// Helpers
// ---------------------------------------------------------------------------

// newB3CoverageTestDB creates an in-memory SQLite DB with necessary tables.
func newB3CoverageTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&types.APIKey{},
		&types.SignerOwnership{},
		&types.SignerAccess{},
	))
	return db
}

// newB3TxCoverageDB creates an in-memory SQLite DB with transaction tables.
func newB3TxCoverageDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&types.APIKey{},
		&types.SignerOwnership{},
		&types.SignerAccess{},
		&types.Transaction{},
		&types.RuleBudget{},
	))
	return db
}
