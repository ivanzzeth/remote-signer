package client

import (
	"context"
	"sync"
)

// MockClient is a mock implementation of ClientInterface for testing.
type MockClient struct {
	mu sync.RWMutex

	// Function fields for mocking each method
	HealthFunc           func(ctx context.Context) (*HealthResponse, error)
	SignFunc             func(ctx context.Context, req *SignRequest) (*SignResponse, error)
	SignWithOptionsFunc  func(ctx context.Context, req *SignRequest, waitForApproval bool) (*SignResponse, error)
	GetRequestFunc       func(ctx context.Context, requestID string) (*RequestStatus, error)
	ListRequestsFunc     func(ctx context.Context, filter *ListRequestsFilter) (*ListRequestsResponse, error)
	ApproveSignRequestFunc func(ctx context.Context, requestID string, req *ApproveRequest) (*ApproveResponse, error)
	PreviewRuleFunc      func(ctx context.Context, requestID string, req *PreviewRuleRequest) (*PreviewRuleResponse, error)
	ListRulesFunc        func(ctx context.Context, filter *ListRulesFilter) (*ListRulesResponse, error)
	GetRuleFunc          func(ctx context.Context, ruleID string) (*Rule, error)
	CreateRuleFunc       func(ctx context.Context, req *CreateRuleRequest) (*Rule, error)
	UpdateRuleFunc       func(ctx context.Context, ruleID string, req *UpdateRuleRequest) (*Rule, error)
	DeleteRuleFunc       func(ctx context.Context, ruleID string) error
	ToggleRuleFunc       func(ctx context.Context, ruleID string, enabled bool) (*Rule, error)
	ListAuditRecordsFunc func(ctx context.Context, filter *ListAuditFilter) (*ListAuditResponse, error)
	ListSignersFunc      func(ctx context.Context, filter *ListSignersFilter) (*ListSignersResponse, error)
	CreateSignerFunc     func(ctx context.Context, req *CreateSignerRequest) (*Signer, error)

	// Call tracking
	Calls map[string][]any
}

// NewMockClient creates a new mock client with default no-op implementations.
func NewMockClient() *MockClient {
	return &MockClient{
		Calls: make(map[string][]any),
	}
}

// recordCall records a method call for verification.
func (m *MockClient) recordCall(method string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls[method] = append(m.Calls[method], args)
}

// GetCalls returns the recorded calls for a method.
func (m *MockClient) GetCalls(method string) []any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Calls[method]
}

// ResetCalls clears all recorded calls.
func (m *MockClient) ResetCalls() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = make(map[string][]any)
}

// Health implements ClientInterface.
func (m *MockClient) Health(ctx context.Context) (*HealthResponse, error) {
	m.recordCall("Health")
	if m.HealthFunc != nil {
		return m.HealthFunc(ctx)
	}
	return &HealthResponse{Status: "healthy"}, nil
}

// Sign implements ClientInterface.
func (m *MockClient) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	m.recordCall("Sign", req)
	if m.SignFunc != nil {
		return m.SignFunc(ctx, req)
	}
	return &SignResponse{}, nil
}

// SignWithOptions implements ClientInterface.
func (m *MockClient) SignWithOptions(ctx context.Context, req *SignRequest, waitForApproval bool) (*SignResponse, error) {
	m.recordCall("SignWithOptions", req, waitForApproval)
	if m.SignWithOptionsFunc != nil {
		return m.SignWithOptionsFunc(ctx, req, waitForApproval)
	}
	return &SignResponse{}, nil
}

// GetRequest implements ClientInterface.
func (m *MockClient) GetRequest(ctx context.Context, requestID string) (*RequestStatus, error) {
	m.recordCall("GetRequest", requestID)
	if m.GetRequestFunc != nil {
		return m.GetRequestFunc(ctx, requestID)
	}
	return &RequestStatus{}, nil
}

// ListRequests implements ClientInterface.
func (m *MockClient) ListRequests(ctx context.Context, filter *ListRequestsFilter) (*ListRequestsResponse, error) {
	m.recordCall("ListRequests", filter)
	if m.ListRequestsFunc != nil {
		return m.ListRequestsFunc(ctx, filter)
	}
	return &ListRequestsResponse{Requests: []RequestStatus{}}, nil
}

// ApproveSignRequest implements ClientInterface.
func (m *MockClient) ApproveSignRequest(ctx context.Context, requestID string, req *ApproveRequest) (*ApproveResponse, error) {
	m.recordCall("ApproveSignRequest", requestID, req)
	if m.ApproveSignRequestFunc != nil {
		return m.ApproveSignRequestFunc(ctx, requestID, req)
	}
	return &ApproveResponse{}, nil
}

// PreviewRule implements ClientInterface.
func (m *MockClient) PreviewRule(ctx context.Context, requestID string, req *PreviewRuleRequest) (*PreviewRuleResponse, error) {
	m.recordCall("PreviewRule", requestID, req)
	if m.PreviewRuleFunc != nil {
		return m.PreviewRuleFunc(ctx, requestID, req)
	}
	return &PreviewRuleResponse{}, nil
}

// ListRules implements ClientInterface.
func (m *MockClient) ListRules(ctx context.Context, filter *ListRulesFilter) (*ListRulesResponse, error) {
	m.recordCall("ListRules", filter)
	if m.ListRulesFunc != nil {
		return m.ListRulesFunc(ctx, filter)
	}
	return &ListRulesResponse{Rules: []Rule{}}, nil
}

// GetRule implements ClientInterface.
func (m *MockClient) GetRule(ctx context.Context, ruleID string) (*Rule, error) {
	m.recordCall("GetRule", ruleID)
	if m.GetRuleFunc != nil {
		return m.GetRuleFunc(ctx, ruleID)
	}
	return &Rule{}, nil
}

// CreateRule implements ClientInterface.
func (m *MockClient) CreateRule(ctx context.Context, req *CreateRuleRequest) (*Rule, error) {
	m.recordCall("CreateRule", req)
	if m.CreateRuleFunc != nil {
		return m.CreateRuleFunc(ctx, req)
	}
	return &Rule{}, nil
}

// UpdateRule implements ClientInterface.
func (m *MockClient) UpdateRule(ctx context.Context, ruleID string, req *UpdateRuleRequest) (*Rule, error) {
	m.recordCall("UpdateRule", ruleID, req)
	if m.UpdateRuleFunc != nil {
		return m.UpdateRuleFunc(ctx, ruleID, req)
	}
	return &Rule{}, nil
}

// DeleteRule implements ClientInterface.
func (m *MockClient) DeleteRule(ctx context.Context, ruleID string) error {
	m.recordCall("DeleteRule", ruleID)
	if m.DeleteRuleFunc != nil {
		return m.DeleteRuleFunc(ctx, ruleID)
	}
	return nil
}

// ToggleRule implements ClientInterface.
func (m *MockClient) ToggleRule(ctx context.Context, ruleID string, enabled bool) (*Rule, error) {
	m.recordCall("ToggleRule", ruleID, enabled)
	if m.ToggleRuleFunc != nil {
		return m.ToggleRuleFunc(ctx, ruleID, enabled)
	}
	return &Rule{}, nil
}

// ListAuditRecords implements ClientInterface.
func (m *MockClient) ListAuditRecords(ctx context.Context, filter *ListAuditFilter) (*ListAuditResponse, error) {
	m.recordCall("ListAuditRecords", filter)
	if m.ListAuditRecordsFunc != nil {
		return m.ListAuditRecordsFunc(ctx, filter)
	}
	return &ListAuditResponse{Records: []AuditRecord{}}, nil
}

// ListSigners implements ClientInterface.
func (m *MockClient) ListSigners(ctx context.Context, filter *ListSignersFilter) (*ListSignersResponse, error) {
	m.recordCall("ListSigners", filter)
	if m.ListSignersFunc != nil {
		return m.ListSignersFunc(ctx, filter)
	}
	return &ListSignersResponse{Signers: []Signer{}}, nil
}

// CreateSigner implements ClientInterface.
func (m *MockClient) CreateSigner(ctx context.Context, req *CreateSignerRequest) (*Signer, error) {
	m.recordCall("CreateSigner", req)
	if m.CreateSignerFunc != nil {
		return m.CreateSignerFunc(ctx, req)
	}
	return &Signer{}, nil
}

// Ensure MockClient implements ClientInterface
var _ ClientInterface = (*MockClient)(nil)
