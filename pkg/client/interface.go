package client

import "context"

// ClientInterface defines the interface for the remote-signer client.
// This interface is used for mocking in tests.
type ClientInterface interface {
	// Health checks the health of the remote-signer service.
	Health(ctx context.Context) (*HealthResponse, error)

	// Sign submits a signing request and returns the result.
	Sign(ctx context.Context, req *SignRequest) (*SignResponse, error)

	// SignWithOptions submits a signing request with options.
	SignWithOptions(ctx context.Context, req *SignRequest, waitForApproval bool) (*SignResponse, error)

	// GetRequest gets the status of a signing request.
	GetRequest(ctx context.Context, requestID string) (*RequestStatus, error)

	// ListRequests lists signing requests with optional filters.
	ListRequests(ctx context.Context, filter *ListRequestsFilter) (*ListRequestsResponse, error)

	// ApproveSignRequest approves or rejects a pending signing request.
	ApproveSignRequest(ctx context.Context, requestID string, req *ApproveRequest) (*ApproveResponse, error)

	// PreviewRule previews the rule that would be generated for a pending request.
	PreviewRule(ctx context.Context, requestID string, req *PreviewRuleRequest) (*PreviewRuleResponse, error)

	// ListRules lists authorization rules with optional filters.
	ListRules(ctx context.Context, filter *ListRulesFilter) (*ListRulesResponse, error)

	// GetRule retrieves a specific rule by ID.
	GetRule(ctx context.Context, ruleID string) (*Rule, error)

	// CreateRule creates a new authorization rule.
	CreateRule(ctx context.Context, req *CreateRuleRequest) (*Rule, error)

	// UpdateRule updates an existing authorization rule.
	UpdateRule(ctx context.Context, ruleID string, req *UpdateRuleRequest) (*Rule, error)

	// DeleteRule deletes a rule by ID.
	DeleteRule(ctx context.Context, ruleID string) error

	// ToggleRule enables or disables a rule.
	ToggleRule(ctx context.Context, ruleID string, enabled bool) (*Rule, error)

	// ListAuditRecords lists audit records with optional filters.
	ListAuditRecords(ctx context.Context, filter *ListAuditFilter) (*ListAuditResponse, error)

	// ListSigners lists available signers with optional filters.
	ListSigners(ctx context.Context, filter *ListSignersFilter) (*ListSignersResponse, error)

	// CreateSigner creates a new signer (admin only).
	CreateSigner(ctx context.Context, req *CreateSignerRequest) (*Signer, error)

	// ListTemplates lists rule templates with optional filters.
	ListTemplates(ctx context.Context, filter *ListTemplatesFilter) (*ListTemplatesResponse, error)

	// GetTemplate retrieves a specific template by ID.
	GetTemplate(ctx context.Context, templateID string) (*Template, error)

	// CreateTemplate creates a new rule template (admin only).
	CreateTemplate(ctx context.Context, req *CreateTemplateRequest) (*Template, error)

	// UpdateTemplate updates an existing template (admin only).
	UpdateTemplate(ctx context.Context, templateID string, req *UpdateTemplateRequest) (*Template, error)

	// DeleteTemplate deletes a template by ID (admin only).
	DeleteTemplate(ctx context.Context, templateID string) error

	// InstantiateTemplate creates a rule instance from a template (admin only).
	InstantiateTemplate(ctx context.Context, templateID string, req *InstantiateTemplateRequest) (*InstantiateTemplateResponse, error)

	// RevokeInstance revokes a rule instance created from a template (admin only).
	RevokeInstance(ctx context.Context, ruleID string) (*RevokeInstanceResponse, error)
}

// Ensure Client implements ClientInterface
var _ ClientInterface = (*Client)(nil)
