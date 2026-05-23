package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/api/middleware"
	"github.com/ivanzzeth/remote-signer/internal/audit"
	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// Mock rule engine for batch sign handler tests
// ---------------------------------------------------------------------------

type mockRuleEngine struct {
	evaluateFn func(ctx context.Context, req *types.SignRequest, parsed *types.ParsedPayload) (*types.RuleID, string, error)
}

func (m *mockRuleEngine) Evaluate(ctx context.Context, req *types.SignRequest, parsed *types.ParsedPayload) (*types.RuleID, string, error) {
	if m.evaluateFn != nil {
		return m.evaluateFn(ctx, req, parsed)
	}
	rid := types.RuleID("rule_mock")
	return &rid, "matched", nil
}

func (m *mockRuleEngine) EvaluateWithResult(ctx context.Context, req *types.SignRequest, parsed *types.ParsedPayload) (*rule.EvaluationResult, error) {
	return &rule.EvaluationResult{Allowed: true}, nil
}

func (m *mockRuleEngine) RegisterEvaluator(evaluator rule.RuleEvaluator) {}

// ---------------------------------------------------------------------------
// Mock batch sign service
// ---------------------------------------------------------------------------

type mockBatchSignService struct {
	mockSignService
	overriddenSignFn func(ctx context.Context, req *service.SignRequest) (*service.SignResponse, error)
}

func (m *mockBatchSignService) Sign(ctx context.Context, req *service.SignRequest) (*service.SignResponse, error) {
	if m.overriddenSignFn != nil {
		return m.overriddenSignFn(ctx, req)
	}
	return &service.SignResponse{
		RequestID: "batch-req-123",
		Status:    types.StatusCompleted,
		Signature: []byte{0x01, 0x02, 0x03},
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newBatchSignHandler(t *testing.T, cfg BatchSignHandlerConfig) *BatchSignHandler {
	t.Helper()
	h, err := NewBatchSignHandler(cfg)
	require.NoError(t, err)
	return h
}

func doBatchSignRequest(t *testing.T, h *BatchSignHandler, method, path string, body interface{}, apiKey *types.APIKey) *httptest.ResponseRecorder {
	t.Helper()
	var buf *bytes.Buffer
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		buf = bytes.NewBuffer(data)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, apiKey))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// mockAccessRepoWithAccess is a signerStubAccessRepo variant that returns HasAccess=true.
type mockAccessRepoWithAccess struct {
	signerStubAccessRepo
}

func (m *mockAccessRepoWithAccess) HasAccess(_ context.Context, _, _ string) (bool, error) {
	return true, nil
}

// mockOwnershipOk returns active ownership for any address.
type mockOwnershipOk struct {
	signerStubOwnershipRepo
}

func (m *mockOwnershipOk) Get(_ context.Context, addr string) (*types.SignerOwnership, error) {
	return &types.SignerOwnership{
		SignerAddress: addr,
		OwnerID:       "admin-key",
		Status:        types.SignerOwnershipActive,
	}, nil
}

// BatchSignHandler constructor tests
// ---------------------------------------------------------------------------

func TestNewBatchSignHandler_NilSignService(t *testing.T) {
	_, err := NewBatchSignHandler(BatchSignHandlerConfig{
		SignService:   nil,
		AccessService: &service.SignerAccessService{},
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sign service")
}

func TestNewBatchSignHandler_NilAccessService(t *testing.T) {
	_, err := NewBatchSignHandler(BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: nil,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access service")
}

func TestNewBatchSignHandler_NilRuleEngine(t *testing.T) {
	_, err := NewBatchSignHandler(BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: &service.SignerAccessService{},
		RuleEngine:    nil,
		Logger:        slog.Default(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rule engine")
}

func TestNewBatchSignHandler_NilLogger(t *testing.T) {
	_, err := NewBatchSignHandler(BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: &service.SignerAccessService{},
		RuleEngine:    &mockRuleEngine{},
		Logger:        nil,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger")
}

func TestNewBatchSignHandler_Valid(t *testing.T) {
	h, err := NewBatchSignHandler(BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: &service.SignerAccessService{},
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	require.NoError(t, err)
	require.NotNil(t, h)
}

// ---------------------------------------------------------------------------
// BatchSignHandler ServeHTTP tests
// ---------------------------------------------------------------------------

func TestBatchSignHandler_MethodNotAllowed(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: accessSvc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	rec := doBatchSignRequest(t, h, http.MethodGet, "/api/v1/evm/sign/batch", nil, signAdminKey())
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestBatchSignHandler_Unauthorized(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: accessSvc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestBatchSignHandler_InvalidBody(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: accessSvc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/sign/batch", bytes.NewBufferString("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, signAdminKey()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBatchSignHandler_EmptyRequests(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: accessSvc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	body := BatchSignRequest{Requests: []BatchSignItem{}}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBatchSignHandler_TooManyRequests(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: accessSvc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	items := make([]BatchSignItem, 21)
	for i := range items {
		items[i] = BatchSignItem{
			ChainID:       "1",
			SignerAddress: "0x1111111111111111111111111111111111111111",
			SignType:      "transaction",
			Transaction:   json.RawMessage(`{}`),
		}
	}
	body := BatchSignRequest{Requests: items}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBatchSignHandler_Validation_MissingChainID(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: accessSvc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	body := BatchSignRequest{
		Requests: []BatchSignItem{
			{ChainID: "", SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
		},
	}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBatchSignHandler_Validation_InvalidChainID(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: accessSvc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	body := BatchSignRequest{
		Requests: []BatchSignItem{
			{ChainID: "abc", SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
		},
	}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBatchSignHandler_Validation_MissingSignerAddress(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: accessSvc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	body := BatchSignRequest{
		Requests: []BatchSignItem{
			{ChainID: "1", SignerAddress: "", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
		},
	}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBatchSignHandler_Validation_InvalidSignerAddress(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: accessSvc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	body := BatchSignRequest{
		Requests: []BatchSignItem{
			{ChainID: "1", SignerAddress: "invalid", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
		},
	}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBatchSignHandler_Validation_MissingSignType(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: accessSvc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	body := BatchSignRequest{
		Requests: []BatchSignItem{
			{ChainID: "1", SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "", Transaction: json.RawMessage(`{}`)},
		},
	}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBatchSignHandler_Validation_InvalidSignType(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: accessSvc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	body := BatchSignRequest{
		Requests: []BatchSignItem{
			{ChainID: "1", SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "hash", Transaction: json.RawMessage(`{}`)},
		},
	}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestBatchSignHandler_Validation_MissingTransaction is intentionally omitted.
// json.RawMessage(nil) marshals as JSON null, not an empty/absent field,
// so the len(item.Transaction) == 0 check can never fire through normal
// request deserialization.

func TestBatchSignHandler_Validation_ChainIDMismatch(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: accessSvc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	body := BatchSignRequest{
		Requests: []BatchSignItem{
			{ChainID: "1", SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
			{ChainID: "137", SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
		},
	}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBatchSignHandler_Validation_SignerMismatch(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: accessSvc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	body := BatchSignRequest{
		Requests: []BatchSignItem{
			{ChainID: "1", SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
			{ChainID: "1", SignerAddress: "0x2222222222222222222222222222222222222222", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
		},
	}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBatchSignHandler_AccessDenied(t *testing.T) {
	// Use default access service that denies all access
	accessSvc := newSignerTestAccessService(t)
	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: accessSvc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	body := BatchSignRequest{
		Requests: []BatchSignItem{
			{ChainID: "1", SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
		},
	}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestBatchSignHandler_Success(t *testing.T) {
	svc, err := service.NewSignerAccessService(
		&mockOwnershipOk{},
		&mockAccessRepoWithAccess{},
		&signerStubAPIKeyRepo{},
		nil,
		slog.Default(),
	)
	require.NoError(t, err)

	signSvc := &mockBatchSignService{
		overriddenSignFn: func(_ context.Context, req *service.SignRequest) (*service.SignResponse, error) {
			return &service.SignResponse{
				RequestID: "batch-req-ok",
				Status:    types.StatusCompleted,
				Signature: []byte{0xDE, 0xAD, 0xBE, 0xEF},
			}, nil
		},
	}

	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   signSvc,
		AccessService: svc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})

	txData, _ := json.Marshal(map[string]interface{}{
		"to":    "0x2222222222222222222222222222222222222222",
		"value": "0x1",
		"data":  "0x",
		"gas":   21000,
	})
	body := BatchSignRequest{
		Requests: []BatchSignItem{
			{ChainID: "1", SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "transaction", Transaction: txData},
		},
	}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp BatchSignResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Results, 1)
	assert.Equal(t, 0, resp.Results[0].Index)
	assert.Equal(t, "batch-req-ok", resp.Results[0].RequestID)
	assert.Contains(t, resp.Results[0].Signature, "0x")
}

func TestBatchSignHandler_SignServiceError(t *testing.T) {
	svc, err := service.NewSignerAccessService(
		&mockOwnershipOk{},
		&mockAccessRepoWithAccess{},
		&signerStubAPIKeyRepo{},
		nil,
		slog.Default(),
	)
	require.NoError(t, err)

	signSvc := &mockBatchSignService{
		overriddenSignFn: func(_ context.Context, req *service.SignRequest) (*service.SignResponse, error) {
			return nil, errors.New("sign failed")
		},
	}

	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   signSvc,
		AccessService: svc,
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})

	body := BatchSignRequest{
		Requests: []BatchSignItem{
			{ChainID: "1", SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
		},
	}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestBatchSignHandler_RuleBlocked(t *testing.T) {
	svc, err := service.NewSignerAccessService(
		&mockOwnershipOk{},
		&mockAccessRepoWithAccess{},
		&signerStubAPIKeyRepo{},
		nil,
		slog.Default(),
	)
	require.NoError(t, err)

	eng := &mockRuleEngine{
		evaluateFn: func(_ context.Context, req *types.SignRequest, parsed *types.ParsedPayload) (*types.RuleID, string, error) {
			return nil, "", &rule.BlockedError{RuleID: "rule_1", RuleName: "Test Rule", Reason: "blocked by test"}
		},
	}

	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: svc,
		RuleEngine:    eng,
		Logger:        slog.Default(),
	})

	body := BatchSignRequest{
		Requests: []BatchSignItem{
			{ChainID: "1", SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
		},
	}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "blocked by rule")
}

func TestBatchSignHandler_NoMatchNoSimulation(t *testing.T) {
	svc, err := service.NewSignerAccessService(
		&mockOwnershipOk{},
		&mockAccessRepoWithAccess{},
		&signerStubAPIKeyRepo{},
		nil,
		slog.Default(),
	)
	require.NoError(t, err)

	eng := &mockRuleEngine{
		evaluateFn: func(_ context.Context, req *types.SignRequest, parsed *types.ParsedPayload) (*types.RuleID, string, error) {
			return nil, "", nil // no match, no error
		},
	}

	h := newBatchSignHandler(t, BatchSignHandlerConfig{
		SignService:    &mockBatchSignService{},
		AccessService:  svc,
		RuleEngine:     eng,
		SimulationRule: nil,
		Logger:         slog.Default(),
	})

	body := BatchSignRequest{
		Requests: []BatchSignItem{
			{ChainID: "1", SignerAddress: "0x1111111111111111111111111111111111111111", SignType: "transaction", Transaction: json.RawMessage(`{}`)},
		},
	}
	rec := doBatchSignRequest(t, h, http.MethodPost, "/api/v1/evm/sign/batch", body, signAdminKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "no matching rule")
}

func TestBatchSignHandler_BatchSignSetters(t *testing.T) {
	h, err := NewBatchSignHandler(BatchSignHandlerConfig{
		SignService:   &mockBatchSignService{},
		AccessService: &service.SignerAccessService{},
		RuleEngine:    &mockRuleEngine{},
		Logger:        slog.Default(),
	})
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		h.SetAlertService(nil)
		h.SetSignTimeout(0)
	})
}

// ---------------------------------------------------------------------------
// decimalToHex tests
// ---------------------------------------------------------------------------

func TestDecimalToHex(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "0x0"},
		{"0", "0x0"},
		{"10", "0xa"},
		{"255", "0xff"},
		{"0xFF", "0xFF"},
		{"0xff", "0xff"},
	}
	for _, tc := range tests {
		result := decimalToHex(tc.input)
		assert.Equal(t, tc.expected, result, "decimalToHex(%q)", tc.input)
	}
}

// ---------------------------------------------------------------------------
// bigIntToString tests
// ---------------------------------------------------------------------------

func TestBigIntToString(t *testing.T) {
	assert.Equal(t, "0", bigIntToString(nil))
	assert.Equal(t, "100", bigIntToString(big.NewInt(100)))
	assert.Equal(t, "0", bigIntToString(big.NewInt(0)))
}

// ---------------------------------------------------------------------------
// SignHandler setter tests (0% coverage lines in sign.go)
// ---------------------------------------------------------------------------

func TestSignHandler_Setters(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignHandler(&mockSignService{}, nil, accessSvc, slog.Default())
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		h.SetAlertService(nil)
		h.SetSignTimeout(10 * time.Second)
		h.SetSignerRepo(&stubSignerRepo{})
	})
}

// ---------------------------------------------------------------------------
// SignerHandler setter tests (0% coverage lines in signer.go)
// ---------------------------------------------------------------------------

func TestSignerHandler_Setters(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		h.SetAuditLogger(&audit.AuditLogger{})
		h.SetMaxKeystoresPerKey(5)
		h.SetSignerRepo(&stubSignerRepo{})
	})
}

// ---------------------------------------------------------------------------
// HDWalletHandler setter tests (0% coverage lines in hdwallet.go)
// ---------------------------------------------------------------------------

func TestHDWalletHandler_Setters(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewHDWalletHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		h.SetAuditLogger(&audit.AuditLogger{})
		h.SetMaxHDWalletsPerKey(3)
	})
}

// ---------------------------------------------------------------------------
// BudgetListHandler setter tests (0% coverage lines in budget.go)
// ---------------------------------------------------------------------------

func TestBudgetListHandler_SetAuditLogger(t *testing.T) {
	db := newCoverageTestDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()

	h, err := NewBudgetListHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		h.SetAuditLogger(&audit.AuditLogger{})
	})
}

func TestBudgetItemHandler_SetAuditLogger(t *testing.T) {
	db := newCoverageTestDB(t)
	budgetRepo, err := storage.NewGormBudgetRepository(db)
	require.NoError(t, err)
	ruleRepo := storage.NewMemoryRuleRepository()

	h, err := NewBudgetItemHandler(budgetRepo, ruleRepo, slog.Default())
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		h.SetAuditLogger(&audit.AuditLogger{})
	})
}

// ---------------------------------------------------------------------------
// handleApproveSigner tests (signer_locking.go:131 - 0% coverage)
// ---------------------------------------------------------------------------

func TestHandleApproveSigner_AdminRequired(t *testing.T) {
	db := newCoverageTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)

	mustCreateAPIKey(t, apiKeyRepo, "dev-key", types.RoleDev)
	mustCreateAPIKey(t, apiKeyRepo, "admin-key", types.RoleAdmin)
	mustCreateSignerOwnership(t, ownershipRepo, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "dev-key", types.SignerOwnershipPendingApproval)

	accessSvc, err := service.NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, slog.Default())
	require.NoError(t, err)

	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	devKey := &types.APIKey{ID: "dev-key", Role: types.RoleDev, Enabled: true}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/approve", nil, devKey)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "admin access required")
}

func TestHandleApproveSigner_NotFound(t *testing.T) {
	db := newCoverageTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)

	mustCreateAPIKey(t, apiKeyRepo, "admin-key", types.RoleAdmin)

	accessSvc, err := service.NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, slog.Default())
	require.NoError(t, err)

	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	adminKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin, Enabled: true}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/approve", nil, adminKey)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleApproveSigner_AlreadyActive(t *testing.T) {
	db := newCoverageTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)

	mustCreateAPIKey(t, apiKeyRepo, "admin-key", types.RoleAdmin)
	mustCreateSignerOwnership(t, ownershipRepo, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "admin-key", types.SignerOwnershipActive)

	accessSvc, err := service.NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, slog.Default())
	require.NoError(t, err)

	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	adminKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin, Enabled: true}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/approve", nil, adminKey)
	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestHandleApproveSigner_Success(t *testing.T) {
	db := newCoverageTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)

	mustCreateAPIKey(t, apiKeyRepo, "admin-key", types.RoleAdmin)
	mustCreateSignerOwnership(t, ownershipRepo, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "dev-key", types.SignerOwnershipPendingApproval)

	accessSvc, err := service.NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, slog.Default())
	require.NoError(t, err)

	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	adminKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin, Enabled: true}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/approve", nil, adminKey)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "approved", resp["status"])
}

func TestHandleApproveSigner_MethodNotAllowed(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	adminKey := &types.APIKey{ID: "admin-key", Role: types.RoleAdmin, Enabled: true}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodGet,
		"/api/v1/evm/signers/0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/approve", nil, adminKey)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ---------------------------------------------------------------------------
// handleTransferOwnership tests (signer_locking.go:167 - 0% coverage)
// ---------------------------------------------------------------------------

func TestHandleTransferOwnership_MissingNewOwner(t *testing.T) {
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{}, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/transfer", map[string]string{"new_owner_id": ""}, testOwnerAPIKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleTransferOwnership_NotOwner(t *testing.T) {
	db := newCoverageTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)

	mustCreateAPIKey(t, apiKeyRepo, "owner-key", types.RoleAdmin)
	mustCreateAPIKey(t, apiKeyRepo, "stranger-key", types.RoleDev)
	mustCreateSignerOwnership(t, ownershipRepo, testAddr, "owner-key", types.SignerOwnershipActive)

	accessSvc, err := service.NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, slog.Default())
	require.NoError(t, err)

	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	strangerKey := &types.APIKey{ID: "stranger-key", Role: types.RoleDev, Enabled: true}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/transfer", map[string]string{"new_owner_id": "new-owner"}, strangerKey)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandleTransferOwnership_Success(t *testing.T) {
	db := newCoverageTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)

	mustCreateAPIKey(t, apiKeyRepo, "owner-key", types.RoleAdmin)
	mustCreateAPIKey(t, apiKeyRepo, "new-owner", types.RoleAdmin)
	mustCreateSignerOwnership(t, ownershipRepo, testAddr, "owner-key", types.SignerOwnershipActive)

	accessSvc, err := service.NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, slog.Default())
	require.NoError(t, err)

	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	ownerKey := &types.APIKey{ID: "owner-key", Role: types.RoleAdmin, Enabled: true}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/transfer", map[string]string{"new_owner_id": "new-owner"}, ownerKey)
	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())

	var resp map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "transferred", resp["status"])
	assert.Equal(t, testAddr, resp["signer_address"])
	assert.Equal(t, "new-owner", resp["new_owner_id"])
}

func TestHandleTransferOwnership_MethodNotAllowed(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(&signerMockSignerManager{}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodGet,
		"/api/v1/evm/signers/"+testAddr+"/transfer", nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ---------------------------------------------------------------------------
// handleLock additional coverage tests (signer_locking.go:81)
// ---------------------------------------------------------------------------

func TestHandleLock_AlreadyLocked(t *testing.T) {
	mgr := &signerActionMock{
		lockFn: func(_ context.Context, addr string) (*types.SignerInfo, error) {
			return nil, types.ErrSignerLocked
		},
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/lock", nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestHandleLock_SignerNotFound(t *testing.T) {
	mgr := &signerActionMock{
		lockFn: func(_ context.Context, addr string) (*types.SignerInfo, error) {
			return nil, types.ErrSignerNotFound
		},
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/lock", nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleLock_InternalError(t *testing.T) {
	mgr := &signerActionMock{
		lockFn: func(_ context.Context, addr string) (*types.SignerInfo, error) {
			return nil, errors.New("internal error")
		},
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/lock", nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---------------------------------------------------------------------------
// handleUnlock additional coverage tests (signer_locking.go:19)
// ---------------------------------------------------------------------------

func TestHandleUnlock_AlreadyUnlocked(t *testing.T) {
	mgr := &signerActionMock{
		unlockFn: func(_ context.Context, addr, pwd string) (*types.SignerInfo, error) {
			return nil, types.ErrSignerNotLocked
		},
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	body := map[string]string{"password": "secret123"}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/unlock", body, testOwnerAPIKey())
	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestHandleUnlock_SignerNotFound(t *testing.T) {
	mgr := &signerActionMock{
		unlockFn: func(_ context.Context, addr, pwd string) (*types.SignerInfo, error) {
			return nil, types.ErrSignerNotFound
		},
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	body := map[string]string{"password": "secret123"}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/unlock", body, testOwnerAPIKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleUnlock_InternalError(t *testing.T) {
	mgr := &signerActionMock{
		unlockFn: func(_ context.Context, addr, pwd string) (*types.SignerInfo, error) {
			return nil, errors.New("internal error")
		},
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	body := map[string]string{"password": "secret123"}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPost,
		"/api/v1/evm/signers/"+testAddr+"/unlock", body, testOwnerAPIKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestHandleUnlock_InvalidBody(t *testing.T) {
	mgr := &signerActionMock{}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/evm/signers/"+testAddr+"/unlock", bytes.NewBufferString("bad json"))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), middleware.APIKeyContextKey, testOwnerAPIKey()))
	rec := httptest.NewRecorder()
	h.HandleSignerAction(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---------------------------------------------------------------------------
// handleDeleteSigner additional coverage tests (signer_crud.go:269)
// ---------------------------------------------------------------------------

func TestHandleDeleteSigner_InternalError(t *testing.T) {
	mgr := &signerActionMock{
		deleteFn: func(_ context.Context, addr string) error {
			return errors.New("delete error")
		},
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr, nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestHandleDeleteSigner_SignerNotFound(t *testing.T) {
	mgr := &signerActionMock{
		deleteFn: func(_ context.Context, addr string) error {
			return types.ErrSignerNotFound
		},
	}
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, mgr, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodDelete,
		"/api/v1/evm/signers/"+testAddr, nil, testOwnerAPIKey())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// signerInfoByAddress tests (signer_wallet.go:164 - 0% coverage)
// ---------------------------------------------------------------------------

func TestSignerInfoByAddress_Found(t *testing.T) {
	mgr := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: allSigners,
				Total:   3,
			}, nil
		},
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	info, err := h.signerInfoByAddress(context.Background(), "0x1111111111111111111111111111111111111111")
	require.NoError(t, err)
	assert.Equal(t, "0x1111111111111111111111111111111111111111", info.Address)
	assert.Equal(t, "keystore", info.Type)
}

func TestSignerInfoByAddress_NotFound(t *testing.T) {
	mgr := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{
				Signers: allSigners,
				Total:   3,
			}, nil
		},
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	_, err = h.signerInfoByAddress(context.Background(), "0x9999999999999999999999999999999999999999")
	assert.ErrorIs(t, err, types.ErrSignerNotFound)
}

func TestSignerInfoByAddress_ListError(t *testing.T) {
	mgr := &signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{}, errors.New("list failed")
		},
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	_, err = h.signerInfoByAddress(context.Background(), "0x1111111111111111111111111111111111111111")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// handlePatchSignerLabels tests (signer_crud.go:355)
// ---------------------------------------------------------------------------

func TestHandlePatchSignerLabels_NoDisplayNameOrTags(t *testing.T) {
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{}, owners)

	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPatch,
		"/api/v1/evm/signers/"+testAddr, map[string]interface{}{}, testOwnerAPIKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandlePatchSignerLabels_NotOwner(t *testing.T) {
	owners := map[string]string{testAddr: testKeyID}
	h := newActionHandler(t, &signerActionMock{}, owners)

	body := map[string]interface{}{"display_name": "New Name"}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPatch,
		"/api/v1/evm/signers/"+testAddr, body, testOtherAPIKey())
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandlePatchSignerLabels_SignerNotFoundViaInfo(t *testing.T) {
	db := newCoverageTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)

	mustCreateAPIKey(t, apiKeyRepo, "owner-key", types.RoleAdmin)
	mustCreateSignerOwnership(t, ownershipRepo, testAddr, "owner-key", types.SignerOwnershipActive)

	accessSvc, err := service.NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, slog.Default())
	require.NoError(t, err)

	// Provide a listSignersFn that succeeds but doesn't include testAddr.
	// signerInfoByAddress calls ListSigners and then searches by address.
	h, err := NewSignerHandler(&signerMockSignerManager{
		listSignersFn: func(_ context.Context, _ types.SignerFilter) (types.SignerListResult, error) {
			return types.SignerListResult{Signers: nil, Total: 0}, nil
		},
	}, accessSvc, slog.Default(), false)
	require.NoError(t, err)

	ownerKey := &types.APIKey{ID: "owner-key", Role: types.RoleAdmin, Enabled: true}
	body := map[string]interface{}{"display_name": "New Name"}
	rec := doActionRequest(t, h.HandleSignerAction, http.MethodPatch,
		"/api/v1/evm/signers/"+testAddr, body, ownerKey)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---------------------------------------------------------------------------
// signerIsHDDerivedNonPrimary edge cases (signer_crud.go:398)
// ---------------------------------------------------------------------------

func TestSignerIsHDDerivedNonPrimary_NilManager(t *testing.T) {
	h := &SignerHandler{signerManager: nil}
	assert.False(t, h.signerIsHDDerivedNonPrimary("0x1111"))
}

func TestSignerIsHDDerivedNonPrimary_EmptyHierarchy(t *testing.T) {
	mgr := &signerMockSignerManager{
		getHDHierarchyFn: func() map[string]evmchain.HDHierarchyInfo {
			return nil
		},
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)
	assert.False(t, h.signerIsHDDerivedNonPrimary("0x1111"))
}

func TestSignerIsHDDerivedNonPrimary_NotInHierarchy(t *testing.T) {
	mgr := &signerMockSignerManager{
		getHDHierarchyFn: func() map[string]evmchain.HDHierarchyInfo {
			return map[string]evmchain.HDHierarchyInfo{
				"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {DerivationIndex: 0},
			}
		},
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)
	assert.False(t, h.signerIsHDDerivedNonPrimary("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"))
}

func TestSignerIsHDDerivedNonPrimary_IsDerived(t *testing.T) {
	// signerIsHDDerivedNonPrimary uses common.HexToAddress().Hex() which
	// produces EIP-55 checksummed addresses. The hierarchy keys must
	// match the EIP-55 checksummed form of the input addresses.
	mgr := &signerMockSignerManager{
		getHDHierarchyFn: func() map[string]evmchain.HDHierarchyInfo {
			return map[string]evmchain.HDHierarchyInfo{
				"0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa": {DerivationIndex: 0}, // checksum of 0xaaa...aaa
				"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB": {DerivationIndex: 1}, // checksum of 0xbbb...bbb
			}
		},
	}
	accessSvc := newSignerTestAccessService(t)
	h, err := NewSignerHandler(mgr, accessSvc, slog.Default(), false)
	require.NoError(t, err)
	// Pass lowercase; the handler normalizes via HexToAddress().Hex()
	assert.True(t, h.signerIsHDDerivedNonPrimary("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	assert.False(t, h.signerIsHDDerivedNonPrimary("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
}

// ---------------------------------------------------------------------------
// RuleHandler option/setter tests (rule.go:53 - 0% coverage)
// WithSolidityValidator and WithAuditLogger
// ---------------------------------------------------------------------------

func TestRuleHandler_WithSolidityValidator(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default(), WithSolidityValidator(nil))
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Nil(t, h.solidityValidator)
}

func TestRuleHandler_WithAuditLogger(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default(), WithAuditLogger(nil))
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.Nil(t, h.auditLogger)
}

func TestRuleHandler_WithReadOnly(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default(), WithReadOnly())
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.True(t, h.readOnly)
}

func TestRuleHandler_WithRequireApproval(t *testing.T) {
	h, err := NewRuleHandler(newMockRuleRepo(), slog.Default(), WithRequireApproval(true))
	require.NoError(t, err)
	require.NotNil(t, h)
	assert.True(t, h.requireApproval)
}

// ---------------------------------------------------------------------------
// helper: newCoverageTestDB - named differently to avoid conflict with
// newSignerAccessTestDB in signer_access_test.go
// ---------------------------------------------------------------------------

func newCoverageTestDB(t *testing.T) *gorm.DB {
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

func mustCreateSignerOwnership(t *testing.T, repo storage.SignerOwnershipRepository, address, ownerID string, status types.SignerOwnershipStatus) {
	t.Helper()
	require.NoError(t, repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: address,
		OwnerID:       ownerID,
		Status:        status,
	}))
}
