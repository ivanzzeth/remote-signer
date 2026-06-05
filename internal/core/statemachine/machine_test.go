package statemachine

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// --- mocks ---

type mockRequestRepo struct {
	requests map[types.SignRequestID]*types.SignRequest
	getErr   error
	casErr   error
}

func newMockRequestRepo() *mockRequestRepo {
	return &mockRequestRepo{requests: make(map[types.SignRequestID]*types.SignRequest)}
}

func (m *mockRequestRepo) Create(ctx context.Context, req *types.SignRequest) error {
	return errors.New("not implemented")
}

func (m *mockRequestRepo) Get(ctx context.Context, id types.SignRequestID) (*types.SignRequest, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	req, ok := m.requests[id]
	if !ok {
		return nil, types.ErrNotFound
	}
	// Return a copy so that mutation by transition() doesn't affect the stored copy
	cp := *req
	return &cp, nil
}

func (m *mockRequestRepo) Update(ctx context.Context, req *types.SignRequest) error {
	return errors.New("not implemented")
}

func (m *mockRequestRepo) CompareAndUpdate(ctx context.Context, req *types.SignRequest, expectedStatus types.SignRequestStatus) error {
	if m.casErr != nil {
		return m.casErr
	}
	existing, ok := m.requests[req.ID]
	if !ok {
		return types.ErrNotFound
	}
	if existing.Status != expectedStatus {
		return storage.ErrStateConflict
	}
	m.requests[req.ID] = req
	return nil
}

func (m *mockRequestRepo) List(ctx context.Context, filter storage.RequestFilter) ([]*types.SignRequest, error) {
	return nil, errors.New("not implemented")
}

func (m *mockRequestRepo) Count(ctx context.Context, filter storage.RequestFilter) (int, error) {
	return 0, errors.New("not implemented")
}

func (m *mockRequestRepo) UpdateStatus(ctx context.Context, id types.SignRequestID, status types.SignRequestStatus) error {
	return errors.New("not implemented")
}

func (m *mockRequestRepo) UpdateLastNoMatchReason(ctx context.Context, id types.SignRequestID, reason string) error {
	return errors.New("not implemented")
}

func (m *mockRequestRepo) LookupBySignedData(ctx context.Context, signedData []byte) (*types.SignRequest, error) {
	return nil, errors.New("not implemented")
}

func (m *mockRequestRepo) SetTransactionID(ctx context.Context, id types.SignRequestID, transactionID string) error {
	return errors.New("not implemented")
}

type mockAuditRepo struct {
	logErr error
}

func newMockAuditRepo() *mockAuditRepo {
	return &mockAuditRepo{}
}

func (m *mockAuditRepo) Log(ctx context.Context, record *types.AuditRecord) error {
	return m.logErr
}

func (m *mockAuditRepo) Query(ctx context.Context, filter storage.AuditFilter) ([]*types.AuditRecord, error) {
	return nil, errors.New("not implemented")
}

func (m *mockAuditRepo) Count(ctx context.Context, filter storage.AuditFilter) (int, error) {
	return 0, errors.New("not implemented")
}

func (m *mockAuditRepo) GetByRequestID(ctx context.Context, requestID types.SignRequestID) ([]*types.AuditRecord, error) {
	return nil, errors.New("not implemented")
}

func (m *mockAuditRepo) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	return 0, errors.New("not implemented")
}

// --- helpers ---

func newTestSM(t *testing.T, reqRepo *mockRequestRepo, auditRepo *mockAuditRepo) *StateMachine {
	t.Helper()
	sm, err := NewStateMachine(reqRepo, auditRepo, testLogger())
	require.NoError(t, err)
	return sm
}

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func makeRequest(id types.SignRequestID, status types.SignRequestStatus) *types.SignRequest {
	now := time.Now()
	return &types.SignRequest{
		ID:            id,
		Status:        status,
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xtest",
		APIKeyID:      "test-key",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func TestNewStateMachine_NilRepo(t *testing.T) {
	_, err := NewStateMachine(nil, newMockAuditRepo(), testLogger())
	assert.ErrorContains(t, err, "request repository is required")
}

func TestNewStateMachine_NilAudit(t *testing.T) {
	_, err := NewStateMachine(newMockRequestRepo(), nil, testLogger())
	assert.ErrorContains(t, err, "audit repository is required")
}

func TestNewStateMachine_NilLogger(t *testing.T) {
	_, err := NewStateMachine(newMockRequestRepo(), newMockAuditRepo(), nil)
	assert.ErrorContains(t, err, "logger is required")
}

func TestNewStateMachine_Success(t *testing.T) {
	sm, err := NewStateMachine(newMockRequestRepo(), newMockAuditRepo(), testLogger())
	require.NoError(t, err)
	require.NotNil(t, sm)
}

// --- IsValidTransition ---

func TestIsValidTransition(t *testing.T) {
	tests := []struct {
		from types.SignRequestStatus
		to   types.SignRequestStatus
		exp  bool
	}{
		// Valid
		{types.StatusPending, types.StatusAuthorizing, true},
		{types.StatusPending, types.StatusRejected, true},
		{types.StatusAuthorizing, types.StatusSigning, true},
		{types.StatusAuthorizing, types.StatusRejected, true},
		{types.StatusSigning, types.StatusCompleted, true},
		{types.StatusSigning, types.StatusFailed, true},
		// Invalid from pending
		{types.StatusPending, types.StatusSigning, false},
		{types.StatusPending, types.StatusCompleted, false},
		{types.StatusPending, types.StatusFailed, false},
		// Invalid from authorizing
		{types.StatusAuthorizing, types.StatusPending, false},
		{types.StatusAuthorizing, types.StatusCompleted, false},
		{types.StatusAuthorizing, types.StatusFailed, false},
		// Invalid from signing
		{types.StatusSigning, types.StatusPending, false},
		{types.StatusSigning, types.StatusAuthorizing, false},
		{types.StatusSigning, types.StatusRejected, false},
		// Terminal states - no transitions
		{types.StatusCompleted, types.StatusPending, false},
		{types.StatusCompleted, types.StatusSigning, false},
		{types.StatusRejected, types.StatusPending, false},
		{types.StatusRejected, types.StatusSigning, false},
		{types.StatusFailed, types.StatusPending, false},
		{types.StatusFailed, types.StatusSigning, false},
		// Self-transitions (not in valid transitions map)
		{types.StatusPending, types.StatusPending, false},
		{types.StatusCompleted, types.StatusCompleted, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.from)+"_to_"+string(tt.to), func(t *testing.T) {
			got := IsValidTransition(tt.from, tt.to)
			assert.Equal(t, tt.exp, got)
		})
	}
}

func TestIsValidTransition_UnknownFrom(t *testing.T) {
	assert.False(t, IsValidTransition("unknown", types.StatusPending))
}

// --- ValidateAndStartAuthorizing ---

func TestValidateAndStartAuthorizing_Success(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusPending)
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	result, err := sm.ValidateAndStartAuthorizing(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, types.StatusPending, result.PreviousStatus)
	assert.Equal(t, types.StatusAuthorizing, result.NewStatus)

	updated := reqRepo.requests[id]
	assert.Equal(t, types.StatusAuthorizing, updated.Status)
}

func TestValidateAndStartAuthorizing_NotFound(t *testing.T) {
	reqRepo := newMockRequestRepo()
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.ValidateAndStartAuthorizing(context.Background(), "nonexistent")
	assert.ErrorContains(t, err, "failed to get request")
}

func TestValidateAndStartAuthorizing_WrongStatus(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusAuthorizing)
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.ValidateAndStartAuthorizing(context.Background(), id)
	assert.ErrorContains(t, err, "invalid state transition")
}

// --- RejectOnValidation ---

func TestRejectOnValidation_Success(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusPending)
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	result, err := sm.RejectOnValidation(context.Background(), id, "bad payload")
	require.NoError(t, err)
	assert.Equal(t, types.StatusRejected, result.NewStatus)
	assert.Equal(t, "bad payload", result.Reason)

	updated := reqRepo.requests[id]
	assert.Equal(t, types.StatusRejected, updated.Status)
	assert.Equal(t, "bad payload", updated.ErrorMessage)
	assert.NotNil(t, updated.CompletedAt)
}

func TestRejectOnValidation_NotFound(t *testing.T) {
	reqRepo := newMockRequestRepo()
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.RejectOnValidation(context.Background(), "nonexistent", "reason")
	assert.ErrorContains(t, err, "failed to get request")
}

func TestRejectOnValidation_WrongStatus(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusSigning)
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.RejectOnValidation(context.Background(), id, "reason")
	assert.ErrorContains(t, err, "invalid state transition")
}

// --- ApproveForSigning ---

func TestApproveForSigning_Success(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusAuthorizing)
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	ruleID := types.RuleID("rule-allow-all")
	result, err := sm.ApproveForSigning(context.Background(), id, &ruleID, nil, "rule matched")
	require.NoError(t, err)
	assert.Equal(t, types.StatusSigning, result.NewStatus)
	assert.Equal(t, "rule matched", result.Reason)

	updated := reqRepo.requests[id]
	assert.Equal(t, types.StatusSigning, updated.Status)
	assert.NotNil(t, updated.ApprovedAt)
	assert.Equal(t, "rule-allow-all", *updated.RuleMatchedID)
	assert.Equal(t, types.ApprovalSourceRule, updated.ApprovalSource)
}

func TestApproveForSigning_Manual(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusAuthorizing)
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	by := "admin"
	result, err := sm.ApproveForSigning(context.Background(), id, nil, &by, "manual approval")
	require.NoError(t, err)
	assert.Equal(t, types.StatusSigning, result.NewStatus)
	assert.Equal(t, "admin", *reqRepo.requests[id].ApprovedBy)
	assert.Equal(t, types.ApprovalSourceManual, reqRepo.requests[id].ApprovalSource)
}

func TestApproveForSigning_NotFound(t *testing.T) {
	reqRepo := newMockRequestRepo()
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.ApproveForSigning(context.Background(), "nonexistent", nil, nil, "reason")
	assert.ErrorContains(t, err, "failed to get request")
}

func TestApproveForSigning_WrongStatus(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusPending)
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.ApproveForSigning(context.Background(), id, nil, nil, "reason")
	assert.ErrorContains(t, err, "invalid state transition")
}

// --- RejectOnAuthorization ---

func TestRejectOnAuthorization_Success(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusAuthorizing)
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	result, err := sm.RejectOnAuthorization(context.Background(), id, "reviewer", "bad tx")
	require.NoError(t, err)
	assert.Equal(t, types.StatusRejected, result.NewStatus)

	updated := reqRepo.requests[id]
	assert.Equal(t, types.StatusRejected, updated.Status)
	assert.Equal(t, "bad tx", updated.ErrorMessage)
	assert.NotNil(t, updated.CompletedAt)
}

func TestRejectOnAuthorization_NotFound(t *testing.T) {
	reqRepo := newMockRequestRepo()
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.RejectOnAuthorization(context.Background(), "nonexistent", "reviewer", "reason")
	assert.ErrorContains(t, err, "failed to get request")
}

func TestRejectOnAuthorization_WrongStatus(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusPending)
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.RejectOnAuthorization(context.Background(), id, "reviewer", "reason")
	assert.ErrorContains(t, err, "cannot reject from")
}

// --- CompleteSign ---

func TestCompleteSign_Success(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusSigning)
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	sig := []byte("signature")
	data := []byte("signed_data")
	result, err := sm.CompleteSign(context.Background(), id, sig, data)
	require.NoError(t, err)
	assert.Equal(t, types.StatusCompleted, result.NewStatus)

	updated := reqRepo.requests[id]
	assert.Equal(t, types.StatusCompleted, updated.Status)
	assert.Equal(t, sig, updated.Signature)
	assert.Equal(t, data, updated.SignedData)
	assert.NotNil(t, updated.CompletedAt)
}

func TestCompleteSign_NotFound(t *testing.T) {
	reqRepo := newMockRequestRepo()
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.CompleteSign(context.Background(), "nonexistent", []byte("sig"), nil)
	assert.ErrorContains(t, err, "failed to get request")
}

func TestCompleteSign_WrongStatus(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusPending)
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.CompleteSign(context.Background(), id, []byte("sig"), nil)
	assert.ErrorContains(t, err, "cannot complete from")
}

// --- RevertSigningToAuthorizing ---

func TestRevertSigningToAuthorizing_Success(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	req := makeRequest(id, types.StatusSigning)
	req.ErrorMessage = "transient error"
	req.Signature = []byte("stale_sig")
	req.SignedData = []byte("stale_data")
	req.ApprovedAt = &time.Time{}
	req.CompletedAt = &time.Time{}
	reqRepo.requests[id] = req

	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	result, err := sm.RevertSigningToAuthorizing(context.Background(), id, "signer locked")
	require.NoError(t, err)
	assert.Equal(t, types.StatusAuthorizing, result.NewStatus)

	updated := reqRepo.requests[id]
	assert.Equal(t, types.StatusAuthorizing, updated.Status)
	assert.Equal(t, "signer locked", updated.ErrorMessage)
	assert.Nil(t, updated.Signature)
	assert.Nil(t, updated.SignedData)
	assert.Nil(t, updated.ApprovedAt)
	assert.Nil(t, updated.CompletedAt)
}

func TestRevertSigningToAuthorizing_NotFound(t *testing.T) {
	reqRepo := newMockRequestRepo()
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.RevertSigningToAuthorizing(context.Background(), "nonexistent", "reason")
	assert.ErrorContains(t, err, "failed to get request")
}

func TestRevertSigningToAuthorizing_WrongStatus(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusCompleted)
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.RevertSigningToAuthorizing(context.Background(), id, "reason")
	assert.ErrorContains(t, err, "cannot revert to authorizing from")
}

// --- FailSign ---

func TestFailSign_Success(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusSigning)
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	result, err := sm.FailSign(context.Background(), id, "RPC error")
	require.NoError(t, err)
	assert.Equal(t, types.StatusFailed, result.NewStatus)
	assert.Equal(t, "RPC error", result.Reason)

	updated := reqRepo.requests[id]
	assert.Equal(t, types.StatusFailed, updated.Status)
	assert.Equal(t, "RPC error", updated.ErrorMessage)
	assert.NotNil(t, updated.CompletedAt)
}

func TestFailSign_NotFound(t *testing.T) {
	reqRepo := newMockRequestRepo()
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.FailSign(context.Background(), "nonexistent", "error")
	assert.ErrorContains(t, err, "failed to get request")
}

func TestFailSign_WrongStatus(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusPending)
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.FailSign(context.Background(), id, "error")
	assert.ErrorContains(t, err, "cannot fail from")
}

// --- transition error ---

func TestTransition_CASConflict(t *testing.T) {
	reqRepo := newMockRequestRepo()
	id := types.SignRequestID("req-1")
	reqRepo.requests[id] = makeRequest(id, types.StatusPending)
	// Simulate concurrent modification by having CAS expect different status
	reqRepo.casErr = storage.ErrStateConflict
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.ValidateAndStartAuthorizing(context.Background(), id)
	assert.ErrorContains(t, err, "failed to update request")
}

func TestTransition_GetError(t *testing.T) {
	reqRepo := newMockRequestRepo()
	reqRepo.getErr = errors.New("db down")
	sm := newTestSM(t, reqRepo, newMockAuditRepo())

	_, err := sm.ValidateAndStartAuthorizing(context.Background(), "req-1")
	assert.ErrorContains(t, err, "failed to get request")
}
