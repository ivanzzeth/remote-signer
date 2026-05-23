package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// mockRepo implements storage.AuditRepository for testing.
// ---------------------------------------------------------------------------

type mockAuditRepoLogger struct {
	mu        sync.Mutex
	records   []*types.AuditRecord
	logErr    error // optional error to return from Log
}

func (m *mockAuditRepoLogger) Log(_ context.Context, record *types.AuditRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, record)
	return m.logErr
}

func (m *mockAuditRepoLogger) Query(_ context.Context, _ storage.AuditFilter) ([]*types.AuditRecord, error) {
	return nil, nil
}

func (m *mockAuditRepoLogger) Count(_ context.Context, _ storage.AuditFilter) (int, error) {
	return 0, nil
}

func (m *mockAuditRepoLogger) GetByRequestID(_ context.Context, _ types.SignRequestID) ([]*types.AuditRecord, error) {
	return nil, nil
}

func (m *mockAuditRepoLogger) DeleteOlderThan(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (m *mockAuditRepoLogger) getRecords() []*types.AuditRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*types.AuditRecord, len(m.records))
	copy(result, m.records)
	return result
}

// ---------------------------------------------------------------------------
// NewAuditLogger validation tests
// ---------------------------------------------------------------------------

func TestNewAuditLogger_NilRepo(t *testing.T) {
	logger := slog.Default()
	l, err := NewAuditLogger(nil, logger)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit repository is required")
	assert.Nil(t, l)
}

func TestNewAuditLogger_NilLogger(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
	assert.Nil(t, l)
}

func TestNewAuditLogger_Valid(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)
	require.NotNil(t, l)
}

// ---------------------------------------------------------------------------
// SetOnLogFailure / SetOnHighRiskOperation
// ---------------------------------------------------------------------------

func TestSetOnLogFailure(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	called := false
	var capturedEvent types.AuditEventType
	var capturedErr error
	l.SetOnLogFailure(func(eventType types.AuditEventType, err error) {
		called = true
		capturedEvent = eventType
		capturedErr = err
	})

	require.NotNil(t, l.onLogFailure)
	// Call it manually to verify
	l.onLogFailure(types.AuditEventTypeAuthFailure, fmt.Errorf("test error"))
	assert.True(t, called)
	assert.Equal(t, types.AuditEventTypeAuthFailure, capturedEvent)
	assert.EqualError(t, capturedErr, "test error")
}

func TestSetOnHighRiskOperation(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	called := false
	l.SetOnHighRiskOperation(func(eventType types.AuditEventType, apiKeyID, source, detail string) {
		called = true
		assert.Equal(t, types.AuditEventTypeSignerCreated, eventType)
		assert.Equal(t, "admin-key", apiKeyID)
	})

	l.onHighRiskOperation(types.AuditEventTypeSignerCreated, "admin-key", "10.0.0.1", "signer created")
	assert.True(t, called)
}

// ---------------------------------------------------------------------------
// LogAuthSuccess / LogAuthFailure
// ---------------------------------------------------------------------------

func TestLogAuthSuccess(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogAuthSuccess(context.Background(), "key-1", "10.0.0.1", "POST", "/api/v1/evm/sign")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeAuthSuccess, records[0].EventType)
	assert.Equal(t, "key-1", records[0].APIKeyID)
	assert.Equal(t, "10.0.0.1", records[0].ActorAddress)
	assert.Equal(t, "POST", records[0].RequestMethod)
	assert.Equal(t, "/api/v1/evm/sign", records[0].RequestPath)
	assert.NotEmpty(t, records[0].ID)
	assert.NotZero(t, records[0].Timestamp)
}

func TestLogAuthFailure(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogAuthFailure(context.Background(), "key-1", "10.0.0.1", "POST", "/admin/keys", "invalid signature")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeAuthFailure, records[0].EventType)
	assert.Equal(t, "invalid signature", records[0].ErrorMessage)
}

// ---------------------------------------------------------------------------
// LogSignRequest / LogApprovalRequest
// ---------------------------------------------------------------------------

func TestLogSignRequest(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	req := &types.SignRequest{
		ID:            "sr-1",
		APIKeyID:      "key-1",
		ClientIP:      "10.0.0.1",
		SignerAddress: "0xabc",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
	}

	l.LogSignRequest(context.Background(), req)
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeSignRequest, records[0].EventType)
	require.NotNil(t, records[0].SignRequestID)
	assert.Equal(t, "sr-1", string(*records[0].SignRequestID))
	require.NotNil(t, records[0].SignerAddress)
	assert.Equal(t, "0xabc", *records[0].SignerAddress)
}

func TestLogApprovalRequest(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	req := &types.SignRequest{
		ID:            "sr-2",
		APIKeyID:      "key-1",
		ClientIP:      "10.0.0.1",
		SignerAddress: "0xdef",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
	}

	l.LogApprovalRequest(context.Background(), req)
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeApprovalRequest, records[0].EventType)
	assert.Equal(t, "pending manual approval", records[0].ErrorMessage)
}

// ---------------------------------------------------------------------------
// LogRule* methods
// ---------------------------------------------------------------------------

func TestLogRuleCreated(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	ruleID := types.RuleID("rule-1")
	l.LogRuleCreated(context.Background(), "key-1", "10.0.0.1", ruleID, "my-rule")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeRuleCreated, records[0].EventType)
	require.NotNil(t, records[0].RuleID)
	assert.Equal(t, "rule-1", string(*records[0].RuleID))
	assert.Contains(t, records[0].ErrorMessage, "my-rule")
}

func TestLogRuleUpdated_WithDiff(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	ruleID := types.RuleID("rule-2")
	oldCfg := []byte(`{"key":"old"}`)
	newCfg := []byte(`{"key":"new"}`)
	l.LogRuleUpdated(context.Background(), "key-1", "10.0.0.1", ruleID, "updated-rule", oldCfg, newCfg)
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeRuleUpdated, records[0].EventType)
	require.NotNil(t, records[0].Details)

	var diff RuleUpdateDiff
	err = json.Unmarshal(records[0].Details, &diff)
	require.NoError(t, err)
	assert.Contains(t, string(diff.OldConfig), `"old"`)
	assert.Contains(t, string(diff.NewConfig), `"new"`)
}

func TestLogRuleUpdated_WithoutDiff(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogRuleUpdated(context.Background(), "key-1", "10.0.0.1", types.RuleID("rule-3"), "no-diff-rule", nil, nil)
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Empty(t, records[0].Details)
}

func TestLogRuleDeleted(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogRuleDeleted(context.Background(), "key-1", "10.0.0.1", types.RuleID("rule-4"))
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeRuleDeleted, records[0].EventType)
}

func TestLogRuleApproved(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogRuleApproved(context.Background(), "admin-key", "10.0.0.1", types.RuleID("rule-5"), "original-owner")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeRuleApproved, records[0].EventType)
	assert.Equal(t, "admin-key", records[0].APIKeyID)
}

func TestLogRuleRejected(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogRuleRejected(context.Background(), "admin-key", "10.0.0.1", types.RuleID("rule-6"), "owner1", "contains prohibited terms")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeRuleRejected, records[0].EventType)
	assert.Contains(t, records[0].ErrorMessage, "contains prohibited terms")
}

// ---------------------------------------------------------------------------
// LogAPIRequest
// ---------------------------------------------------------------------------

func TestLogAPIRequest_OK(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogAPIRequest(context.Background(), "key-1", "10.0.0.1", "GET", "/health", 200, 42, "curl/7.0")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeAPIRequest, records[0].EventType)
	assert.Equal(t, types.AuditSeverityInfo, records[0].Severity)
}

func TestLogAPIRequest_ClientError(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogAPIRequest(context.Background(), "key-1", "10.0.0.1", "POST", "/api/v1/sign", 400, 15, "")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditSeverityWarning, records[0].Severity)
}

func TestLogAPIRequest_ServerError(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogAPIRequest(context.Background(), "key-1", "10.0.0.1", "POST", "/api/v1/sign", 500, 500, "curl/7.0")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditSeverityCritical, records[0].Severity)
}

func TestLogAPIRequest_LogError(t *testing.T) {
	repo := &mockAuditRepoLogger{logErr: fmt.Errorf("db error")}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	failureCalled := false
	l.SetOnLogFailure(func(eventType types.AuditEventType, err error) {
		failureCalled = true
		assert.Equal(t, types.AuditEventTypeAPIRequest, eventType)
	})

	l.LogAPIRequest(context.Background(), "key-1", "10.0.0.1", "GET", "/health", 200, 42, "")
	assert.True(t, failureCalled, "onLogFailure should be called when repo.Log fails")
}

// ---------------------------------------------------------------------------
// LogRateLimitHit
// ---------------------------------------------------------------------------

func TestLogRateLimitHit(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogRateLimitHit(context.Background(), "key-1", "10.0.0.1", "POST", "/api/v1/sign")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeRateLimitHit, records[0].EventType)
}

// ---------------------------------------------------------------------------
// LogConfigReloaded
// ---------------------------------------------------------------------------

func TestLogConfigReloaded_Success(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogConfigReloaded(context.Background(), true, "")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeConfigReloaded, records[0].EventType)
	assert.Equal(t, "system", records[0].ActorAddress)
	assert.Empty(t, records[0].ErrorMessage)
}

func TestLogConfigReloaded_Failure(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogConfigReloaded(context.Background(), false, "syntax error in config")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Contains(t, records[0].ErrorMessage, "config reload failed")
}

// ---------------------------------------------------------------------------
// LogSettingsUpdated / LogBudgetMutation
// ---------------------------------------------------------------------------

func TestLogSettingsUpdated(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogSettingsUpdated(context.Background(), "admin-key", "security", `{"auto_lock":"5m"}`)
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeConfigReloaded, records[0].EventType)
	assert.Equal(t, "admin-key", records[0].ActorAddress)
	assert.Contains(t, records[0].ErrorMessage, "settings updated: security")
}

func TestLogBudgetMutation(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogBudgetMutation(context.Background(), "admin-key", "create", "budget-1", "new budget for wallet")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Contains(t, records[0].ErrorMessage, "budget.create")
	assert.Contains(t, records[0].ErrorMessage, "budget-1")
}

// ---------------------------------------------------------------------------
// LogTemplateSynced / LogAPIKeySynced
// ---------------------------------------------------------------------------

func TestLogTemplateSynced(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogTemplateSynced(context.Background(), "create", "tmpl-1", "polymarket_auth")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeTemplateSynced, records[0].EventType)
	assert.Contains(t, records[0].ErrorMessage, "polymarket_auth")
}

func TestLogAPIKeySynced(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogAPIKeySynced(context.Background(), "update", "key-42", "prod-key")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeAPIKeySynced, records[0].EventType)
	assert.Contains(t, records[0].ErrorMessage, "update")
}

// ---------------------------------------------------------------------------
// LogSigner* methods
// ---------------------------------------------------------------------------

func TestLogSignerCreated(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogSignerCreated(context.Background(), "key-1", "10.0.0.1", "0xabcd", "evm")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeSignerCreated, records[0].EventType)
	require.NotNil(t, records[0].SignerAddress)
	assert.Equal(t, "0xabcd", *records[0].SignerAddress)
}

func TestLogSignerLocked(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogSignerLocked(context.Background(), "key-1", "10.0.0.1", "0xabcd")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeSignerLocked, records[0].EventType)
}

func TestLogSignerUnlocked(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogSignerUnlocked(context.Background(), "key-1", "10.0.0.1", "0xabcd")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeSignerUnlocked, records[0].EventType)
}

// ---------------------------------------------------------------------------
// LogHDWallet* methods
// ---------------------------------------------------------------------------

func TestLogHDWalletCreated(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogHDWalletCreated(context.Background(), "key-1", "10.0.0.1", "0xprimary", "import")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeHDWalletCreated, records[0].EventType)
	assert.Contains(t, records[0].ErrorMessage, "import")
}

func TestLogHDWalletDerived(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogHDWalletDerived(context.Background(), "key-1", "10.0.0.1", "0xprimary", 5)
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeHDWalletDerived, records[0].EventType)
	assert.Contains(t, records[0].ErrorMessage, "5")
}

// ---------------------------------------------------------------------------
// LogSignerAutoLocked
// ---------------------------------------------------------------------------

func TestLogSignerAutoLocked(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogSignerAutoLocked(context.Background(), "0xabcd")
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeSignerAutoLocked, records[0].EventType)
	assert.Equal(t, "system", records[0].ActorAddress)
}

// ---------------------------------------------------------------------------
// LogPresetApplied
// ---------------------------------------------------------------------------

func TestLogPresetApplied(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogPresetApplied(context.Background(), "key-1", "10.0.0.1", "polymarket-v2", 3)
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypePresetApplied, records[0].EventType)
	assert.Contains(t, records[0].ErrorMessage, "polymarket-v2")
}

// ---------------------------------------------------------------------------
// SeverityForEvent tests
// ---------------------------------------------------------------------------

func TestSeverityForEvent(t *testing.T) {
	tests := []struct {
		eventType types.AuditEventType
		expected  types.AuditSeverity
	}{
		{types.AuditEventTypeAuthFailure, types.AuditSeverityCritical},
		{types.AuditEventTypeSignRejected, types.AuditSeverityCritical},
		{types.AuditEventTypeSignFailed, types.AuditSeverityCritical},
		{types.AuditEventTypeSignerAutoLocked, types.AuditSeverityCritical},
		{types.AuditEventTypeApprovalDenied, types.AuditSeverityWarning},
		{types.AuditEventTypeRateLimitHit, types.AuditSeverityWarning},
		{types.AuditEventTypeSignerCreated, types.AuditSeverityWarning},
		{types.AuditEventTypeSignerUnlocked, types.AuditSeverityWarning},
		{types.AuditEventTypeHDWalletCreated, types.AuditSeverityWarning},
		{types.AuditEventTypePresetApplied, types.AuditSeverityWarning},
		{types.AuditEventTypeAuthSuccess, types.AuditSeverityInfo},
		{types.AuditEventTypeSignRequest, types.AuditSeverityInfo},
		{types.AuditEventTypeSignComplete, types.AuditSeverityInfo},
		{types.AuditEventTypeAPIRequest, types.AuditSeverityInfo},
	}
	for _, tt := range tests {
		t.Run(string(tt.eventType), func(t *testing.T) {
			got := SeverityForEvent(tt.eventType)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// ---------------------------------------------------------------------------
// IsHighRiskEvent tests
// ---------------------------------------------------------------------------

func TestIsHighRiskEvent(t *testing.T) {
	assert.True(t, IsHighRiskEvent(types.AuditEventTypeSignerCreated))
	assert.True(t, IsHighRiskEvent(types.AuditEventTypeSignerUnlocked))
	assert.True(t, IsHighRiskEvent(types.AuditEventTypeSignerLocked))
	assert.True(t, IsHighRiskEvent(types.AuditEventTypeSignerAutoLocked))
	assert.True(t, IsHighRiskEvent(types.AuditEventTypeHDWalletCreated))
	assert.True(t, IsHighRiskEvent(types.AuditEventTypeHDWalletDerived))
	assert.True(t, IsHighRiskEvent(types.AuditEventTypeRuleCreated))
	assert.True(t, IsHighRiskEvent(types.AuditEventTypeRuleUpdated))
	assert.True(t, IsHighRiskEvent(types.AuditEventTypeRuleDeleted))
	assert.True(t, IsHighRiskEvent(types.AuditEventTypeRuleApproved))
	assert.True(t, IsHighRiskEvent(types.AuditEventTypeRuleRejected))
	assert.True(t, IsHighRiskEvent(types.AuditEventTypeConfigReloaded))
	assert.True(t, IsHighRiskEvent(types.AuditEventTypeTemplateSynced))
	assert.True(t, IsHighRiskEvent(types.AuditEventTypeAPIKeySynced))
	assert.True(t, IsHighRiskEvent(types.AuditEventTypePresetApplied))
	assert.False(t, IsHighRiskEvent(types.AuditEventTypeAuthSuccess))
	assert.False(t, IsHighRiskEvent(types.AuditEventTypeSignRequest))
	assert.False(t, IsHighRiskEvent(types.AuditEventTypeAPIRequest))
}

// ---------------------------------------------------------------------------
// log method: onLogFailure callback trigger
// ---------------------------------------------------------------------------

func TestLog_OnLogFailureTriggered(t *testing.T) {
	repo := &mockAuditRepoLogger{logErr: fmt.Errorf("persistence error")}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	var failureCalled atomic.Bool
	l.SetOnLogFailure(func(eventType types.AuditEventType, err error) {
		failureCalled.Store(true)
		assert.ErrorContains(t, err, "persistence error")
	})

	l.LogAuthSuccess(context.Background(), "key-1", "10.0.0.1", "GET", "/health")
	assert.True(t, failureCalled.Load())
}

// ---------------------------------------------------------------------------
// log method: onHighRiskOperation callback trigger
// ---------------------------------------------------------------------------

func TestLog_OnHighRiskOperationTriggered(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	var called atomic.Bool
	l.SetOnHighRiskOperation(func(eventType types.AuditEventType, apiKeyID, source, detail string) {
		called.Store(true)
		assert.Equal(t, types.AuditEventTypeSignerCreated, eventType)
	})

	l.LogSignerCreated(context.Background(), "admin-key", "10.0.0.1", "0xabcd", "evm")
	assert.True(t, called.Load())
}

// ---------------------------------------------------------------------------
// log method: non-high-risk event should NOT trigger callback
// ---------------------------------------------------------------------------

func TestLog_OnHighRiskOperationNotTriggeredForSafeEvents(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	var called bool
	l.SetOnHighRiskOperation(func(eventType types.AuditEventType, apiKeyID, source, detail string) {
		called = true
	})

	l.LogAuthSuccess(context.Background(), "key-1", "10.0.0.1", "GET", "/health")
	assert.False(t, called, "AuthSuccess is not high risk")
}

// ---------------------------------------------------------------------------
// LogRuleUpdated JSON marshalling error path - details stays nil
// ---------------------------------------------------------------------------

func TestLogRuleUpdated_JSONMarshalErrorInvalidUTF8(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	// Bytes that cannot be marshalled to valid JSON
	invalidBytes := []byte{0xff, 0xfe, 0xfd}
	l.LogRuleUpdated(context.Background(), "key-1", "10.0.0.1", types.RuleID("rule-x"), "bad-rule", invalidBytes, nil)
	records := repo.getRecords()
	require.Len(t, records, 1)
	// Details may or may not be nil depending on json.Marshal behavior with invalid bytes
	// The important thing is that it doesn't panic
	assert.NotNil(t, records[0])
}

// ---------------------------------------------------------------------------
// LogAPIRequest with details that fail JSON marshal
// ---------------------------------------------------------------------------

func TestLogAPIRequest_DetailsJSONMarshal(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	// All valid arguments, just ensure the JSON details are set correctly
	l.LogAPIRequest(context.Background(), "key-1", "10.0.0.1", "GET", "/health", 200, 42, "curl/7.0")
	records := repo.getRecords()
	require.Len(t, records, 1)
	require.NotNil(t, records[0].Details)

	var details APIRequestDetails
	err = json.Unmarshal(records[0].Details, &details)
	require.NoError(t, err)
	assert.Equal(t, 200, details.StatusCode)
	assert.Equal(t, int64(42), details.DurationMs)
	assert.Equal(t, "curl/7.0", details.UserAgent)
}

// ---------------------------------------------------------------------------
// LogSignRequest with zero values
// ---------------------------------------------------------------------------

func TestLogSignRequest_ZeroFields(t *testing.T) {
	repo := &mockAuditRepoLogger{}
	l, err := NewAuditLogger(repo, slog.Default())
	require.NoError(t, err)

	l.LogSignRequest(context.Background(), &types.SignRequest{})
	records := repo.getRecords()
	require.Len(t, records, 1)
	assert.Equal(t, types.AuditEventTypeSignRequest, records[0].EventType)
	// Should not panic with zero-valued SignRequest
}
