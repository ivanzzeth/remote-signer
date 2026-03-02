// Package mock provides per-resource mock implementations for testing.
package mock

import (
	"context"
	"sync"

	"github.com/ivanzzeth/remote-signer/pkg/client/audit"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/pkg/client/templates"
)

// SignService is a mock implementation of evm.SignAPI.
type SignService struct {
	mu                sync.RWMutex
	ExecuteFunc       func(ctx context.Context, req *evm.SignRequest) (*evm.SignResponse, error)
	ExecuteAsyncFunc  func(ctx context.Context, req *evm.SignRequest) (*evm.SignResponse, error)
	Calls             map[string][]any
}

func NewSignService() *SignService {
	return &SignService{Calls: make(map[string][]any)}
}

func (m *SignService) recordCall(method string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls[method] = append(m.Calls[method], args)
}

func (m *SignService) Execute(ctx context.Context, req *evm.SignRequest) (*evm.SignResponse, error) {
	m.recordCall("Execute", req)
	if m.ExecuteFunc != nil {
		return m.ExecuteFunc(ctx, req)
	}
	return &evm.SignResponse{}, nil
}

func (m *SignService) ExecuteAsync(ctx context.Context, req *evm.SignRequest) (*evm.SignResponse, error) {
	m.recordCall("ExecuteAsync", req)
	if m.ExecuteAsyncFunc != nil {
		return m.ExecuteAsyncFunc(ctx, req)
	}
	return &evm.SignResponse{}, nil
}

var _ evm.SignAPI = (*SignService)(nil)

// RequestService is a mock implementation of evm.RequestAPI.
type RequestService struct {
	mu              sync.RWMutex
	GetFunc         func(ctx context.Context, requestID string) (*evm.RequestStatus, error)
	ListFunc        func(ctx context.Context, filter *evm.ListRequestsFilter) (*evm.ListRequestsResponse, error)
	ApproveFunc     func(ctx context.Context, requestID string, req *evm.ApproveRequest) (*evm.ApproveResponse, error)
	PreviewRuleFunc func(ctx context.Context, requestID string, req *evm.PreviewRuleRequest) (*evm.PreviewRuleResponse, error)
	Calls           map[string][]any
}

func NewRequestService() *RequestService {
	return &RequestService{Calls: make(map[string][]any)}
}

func (m *RequestService) recordCall(method string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls[method] = append(m.Calls[method], args)
}

func (m *RequestService) Get(ctx context.Context, requestID string) (*evm.RequestStatus, error) {
	m.recordCall("Get", requestID)
	if m.GetFunc != nil {
		return m.GetFunc(ctx, requestID)
	}
	return &evm.RequestStatus{}, nil
}

func (m *RequestService) List(ctx context.Context, filter *evm.ListRequestsFilter) (*evm.ListRequestsResponse, error) {
	m.recordCall("List", filter)
	if m.ListFunc != nil {
		return m.ListFunc(ctx, filter)
	}
	return &evm.ListRequestsResponse{Requests: []evm.RequestStatus{}}, nil
}

func (m *RequestService) Approve(ctx context.Context, requestID string, req *evm.ApproveRequest) (*evm.ApproveResponse, error) {
	m.recordCall("Approve", requestID, req)
	if m.ApproveFunc != nil {
		return m.ApproveFunc(ctx, requestID, req)
	}
	return &evm.ApproveResponse{}, nil
}

func (m *RequestService) PreviewRule(ctx context.Context, requestID string, req *evm.PreviewRuleRequest) (*evm.PreviewRuleResponse, error) {
	m.recordCall("PreviewRule", requestID, req)
	if m.PreviewRuleFunc != nil {
		return m.PreviewRuleFunc(ctx, requestID, req)
	}
	return &evm.PreviewRuleResponse{}, nil
}

var _ evm.RequestAPI = (*RequestService)(nil)

// RuleService is a mock implementation of evm.RuleAPI.
type RuleService struct {
	mu         sync.RWMutex
	ListFunc   func(ctx context.Context, filter *evm.ListRulesFilter) (*evm.ListRulesResponse, error)
	GetFunc    func(ctx context.Context, ruleID string) (*evm.Rule, error)
	CreateFunc func(ctx context.Context, req *evm.CreateRuleRequest) (*evm.Rule, error)
	UpdateFunc func(ctx context.Context, ruleID string, req *evm.UpdateRuleRequest) (*evm.Rule, error)
	DeleteFunc func(ctx context.Context, ruleID string) error
	ToggleFunc func(ctx context.Context, ruleID string, enabled bool) (*evm.Rule, error)
	Calls      map[string][]any
}

func NewRuleService() *RuleService {
	return &RuleService{Calls: make(map[string][]any)}
}

func (m *RuleService) recordCall(method string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls[method] = append(m.Calls[method], args)
}

func (m *RuleService) List(ctx context.Context, filter *evm.ListRulesFilter) (*evm.ListRulesResponse, error) {
	m.recordCall("List", filter)
	if m.ListFunc != nil {
		return m.ListFunc(ctx, filter)
	}
	return &evm.ListRulesResponse{Rules: []evm.Rule{}}, nil
}

func (m *RuleService) Get(ctx context.Context, ruleID string) (*evm.Rule, error) {
	m.recordCall("Get", ruleID)
	if m.GetFunc != nil {
		return m.GetFunc(ctx, ruleID)
	}
	return &evm.Rule{}, nil
}

func (m *RuleService) Create(ctx context.Context, req *evm.CreateRuleRequest) (*evm.Rule, error) {
	m.recordCall("Create", req)
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, req)
	}
	return &evm.Rule{}, nil
}

func (m *RuleService) Update(ctx context.Context, ruleID string, req *evm.UpdateRuleRequest) (*evm.Rule, error) {
	m.recordCall("Update", ruleID, req)
	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, ruleID, req)
	}
	return &evm.Rule{}, nil
}

func (m *RuleService) Delete(ctx context.Context, ruleID string) error {
	m.recordCall("Delete", ruleID)
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, ruleID)
	}
	return nil
}

func (m *RuleService) Toggle(ctx context.Context, ruleID string, enabled bool) (*evm.Rule, error) {
	m.recordCall("Toggle", ruleID, enabled)
	if m.ToggleFunc != nil {
		return m.ToggleFunc(ctx, ruleID, enabled)
	}
	return &evm.Rule{}, nil
}

var _ evm.RuleAPI = (*RuleService)(nil)

// SignerService is a mock implementation of evm.SignerAPI.
type SignerService struct {
	mu         sync.RWMutex
	ListFunc   func(ctx context.Context, filter *evm.ListSignersFilter) (*evm.ListSignersResponse, error)
	CreateFunc func(ctx context.Context, req *evm.CreateSignerRequest) (*evm.Signer, error)
	Calls      map[string][]any
}

func NewSignerService() *SignerService {
	return &SignerService{Calls: make(map[string][]any)}
}

func (m *SignerService) recordCall(method string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls[method] = append(m.Calls[method], args)
}

func (m *SignerService) List(ctx context.Context, filter *evm.ListSignersFilter) (*evm.ListSignersResponse, error) {
	m.recordCall("List", filter)
	if m.ListFunc != nil {
		return m.ListFunc(ctx, filter)
	}
	return &evm.ListSignersResponse{Signers: []evm.Signer{}}, nil
}

func (m *SignerService) Create(ctx context.Context, req *evm.CreateSignerRequest) (*evm.Signer, error) {
	m.recordCall("Create", req)
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, req)
	}
	return &evm.Signer{}, nil
}

var _ evm.SignerAPI = (*SignerService)(nil)

// HDWalletService is a mock implementation of evm.HDWalletAPI.
type HDWalletService struct {
	mu                sync.RWMutex
	CreateFunc        func(ctx context.Context, req *evm.CreateHDWalletRequest) (*evm.HDWalletResponse, error)
	ImportFunc        func(ctx context.Context, req *evm.CreateHDWalletRequest) (*evm.HDWalletResponse, error)
	ListFunc          func(ctx context.Context) (*evm.ListHDWalletsResponse, error)
	DeriveAddressFunc func(ctx context.Context, primaryAddr string, req *evm.DeriveAddressRequest) (*evm.DeriveAddressResponse, error)
	ListDerivedFunc   func(ctx context.Context, primaryAddr string) (*evm.ListDerivedAddressesResponse, error)
	GetSignerFunc     func(ctx context.Context, primaryAddr string, chainID string, index uint32) (*evm.RemoteSigner, error)
	GetSignersFunc    func(ctx context.Context, primaryAddr string, chainID string, start, count uint32) ([]*evm.RemoteSigner, error)
	Calls             map[string][]any
}

func NewHDWalletService() *HDWalletService {
	return &HDWalletService{Calls: make(map[string][]any)}
}

func (m *HDWalletService) recordCall(method string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls[method] = append(m.Calls[method], args)
}

func (m *HDWalletService) Create(ctx context.Context, req *evm.CreateHDWalletRequest) (*evm.HDWalletResponse, error) {
	m.recordCall("Create", req)
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, req)
	}
	return &evm.HDWalletResponse{}, nil
}

func (m *HDWalletService) Import(ctx context.Context, req *evm.CreateHDWalletRequest) (*evm.HDWalletResponse, error) {
	m.recordCall("Import", req)
	if m.ImportFunc != nil {
		return m.ImportFunc(ctx, req)
	}
	return &evm.HDWalletResponse{}, nil
}

func (m *HDWalletService) List(ctx context.Context) (*evm.ListHDWalletsResponse, error) {
	m.recordCall("List")
	if m.ListFunc != nil {
		return m.ListFunc(ctx)
	}
	return &evm.ListHDWalletsResponse{}, nil
}

func (m *HDWalletService) DeriveAddress(ctx context.Context, primaryAddr string, req *evm.DeriveAddressRequest) (*evm.DeriveAddressResponse, error) {
	m.recordCall("DeriveAddress", primaryAddr, req)
	if m.DeriveAddressFunc != nil {
		return m.DeriveAddressFunc(ctx, primaryAddr, req)
	}
	return &evm.DeriveAddressResponse{}, nil
}

func (m *HDWalletService) ListDerived(ctx context.Context, primaryAddr string) (*evm.ListDerivedAddressesResponse, error) {
	m.recordCall("ListDerived", primaryAddr)
	if m.ListDerivedFunc != nil {
		return m.ListDerivedFunc(ctx, primaryAddr)
	}
	return &evm.ListDerivedAddressesResponse{}, nil
}

func (m *HDWalletService) GetSigner(ctx context.Context, primaryAddr string, chainID string, index uint32) (*evm.RemoteSigner, error) {
	m.recordCall("GetSigner", primaryAddr, chainID, index)
	if m.GetSignerFunc != nil {
		return m.GetSignerFunc(ctx, primaryAddr, chainID, index)
	}
	return nil, nil
}

func (m *HDWalletService) GetSigners(ctx context.Context, primaryAddr string, chainID string, start, count uint32) ([]*evm.RemoteSigner, error) {
	m.recordCall("GetSigners", primaryAddr, chainID, start, count)
	if m.GetSignersFunc != nil {
		return m.GetSignersFunc(ctx, primaryAddr, chainID, start, count)
	}
	return nil, nil
}

var _ evm.HDWalletAPI = (*HDWalletService)(nil)

// GuardService is a mock implementation of evm.GuardAPI.
type GuardService struct {
	mu         sync.RWMutex
	ResumeFunc func(ctx context.Context) error
	Calls      map[string][]any
}

func NewGuardService() *GuardService {
	return &GuardService{Calls: make(map[string][]any)}
}

func (m *GuardService) recordCall(method string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls[method] = append(m.Calls[method], args)
}

func (m *GuardService) Resume(ctx context.Context) error {
	m.recordCall("Resume")
	if m.ResumeFunc != nil {
		return m.ResumeFunc(ctx)
	}
	return nil
}

var _ evm.GuardAPI = (*GuardService)(nil)

// AuditService is a mock implementation of audit.API.
type AuditService struct {
	mu       sync.RWMutex
	ListFunc func(ctx context.Context, filter *audit.ListFilter) (*audit.ListResponse, error)
	Calls    map[string][]any
}

func NewAuditService() *AuditService {
	return &AuditService{Calls: make(map[string][]any)}
}

func (m *AuditService) recordCall(method string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls[method] = append(m.Calls[method], args)
}

func (m *AuditService) List(ctx context.Context, filter *audit.ListFilter) (*audit.ListResponse, error) {
	m.recordCall("List", filter)
	if m.ListFunc != nil {
		return m.ListFunc(ctx, filter)
	}
	return &audit.ListResponse{Records: []audit.Record{}}, nil
}

var _ audit.API = (*AuditService)(nil)

// TemplateService is a mock implementation of templates.API.
type TemplateService struct {
	mu                  sync.RWMutex
	ListFunc            func(ctx context.Context, filter *templates.ListFilter) (*templates.ListResponse, error)
	GetFunc             func(ctx context.Context, templateID string) (*templates.Template, error)
	CreateFunc          func(ctx context.Context, req *templates.CreateRequest) (*templates.Template, error)
	UpdateFunc          func(ctx context.Context, templateID string, req *templates.UpdateRequest) (*templates.Template, error)
	DeleteFunc          func(ctx context.Context, templateID string) error
	InstantiateFunc     func(ctx context.Context, templateID string, req *templates.InstantiateRequest) (*templates.InstantiateResponse, error)
	RevokeInstanceFunc  func(ctx context.Context, ruleID string) (*templates.RevokeInstanceResponse, error)
	Calls               map[string][]any
}

func NewTemplateService() *TemplateService {
	return &TemplateService{Calls: make(map[string][]any)}
}

func (m *TemplateService) recordCall(method string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls[method] = append(m.Calls[method], args)
}

func (m *TemplateService) List(ctx context.Context, filter *templates.ListFilter) (*templates.ListResponse, error) {
	m.recordCall("List", filter)
	if m.ListFunc != nil {
		return m.ListFunc(ctx, filter)
	}
	return &templates.ListResponse{Templates: []templates.Template{}}, nil
}

func (m *TemplateService) Get(ctx context.Context, templateID string) (*templates.Template, error) {
	m.recordCall("Get", templateID)
	if m.GetFunc != nil {
		return m.GetFunc(ctx, templateID)
	}
	return &templates.Template{}, nil
}

func (m *TemplateService) Create(ctx context.Context, req *templates.CreateRequest) (*templates.Template, error) {
	m.recordCall("Create", req)
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, req)
	}
	return &templates.Template{}, nil
}

func (m *TemplateService) Update(ctx context.Context, templateID string, req *templates.UpdateRequest) (*templates.Template, error) {
	m.recordCall("Update", templateID, req)
	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, templateID, req)
	}
	return &templates.Template{}, nil
}

func (m *TemplateService) Delete(ctx context.Context, templateID string) error {
	m.recordCall("Delete", templateID)
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, templateID)
	}
	return nil
}

func (m *TemplateService) Instantiate(ctx context.Context, templateID string, req *templates.InstantiateRequest) (*templates.InstantiateResponse, error) {
	m.recordCall("Instantiate", templateID, req)
	if m.InstantiateFunc != nil {
		return m.InstantiateFunc(ctx, templateID, req)
	}
	return &templates.InstantiateResponse{}, nil
}

func (m *TemplateService) RevokeInstance(ctx context.Context, ruleID string) (*templates.RevokeInstanceResponse, error) {
	m.recordCall("RevokeInstance", ruleID)
	if m.RevokeInstanceFunc != nil {
		return m.RevokeInstanceFunc(ctx, ruleID)
	}
	return &templates.RevokeInstanceResponse{}, nil
}

var _ templates.API = (*TemplateService)(nil)
