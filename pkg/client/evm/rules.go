package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// RuleService handles rule CRUD operations.
type RuleService struct {
	transport *transport.Transport
}

// List lists authorization rules with optional filters.
func (s *RuleService) List(ctx context.Context, filter *ListRulesFilter) (*ListRulesResponse, error) {
	path := "/api/v1/evm/rules"
	params := make([]string, 0)

	if filter != nil {
		if filter.ChainType != "" {
			params = append(params, fmt.Sprintf("chain_type=%s", filter.ChainType))
		}
		if filter.SignerAddress != "" {
			params = append(params, fmt.Sprintf("signer_address=%s", filter.SignerAddress))
		}
		if filter.APIKeyID != "" {
			params = append(params, fmt.Sprintf("api_key_id=%s", filter.APIKeyID))
		}
		if filter.Type != "" {
			params = append(params, fmt.Sprintf("type=%s", filter.Type))
		}
		if filter.Mode != "" {
			params = append(params, fmt.Sprintf("mode=%s", filter.Mode))
		}
		if filter.Enabled != nil {
			params = append(params, fmt.Sprintf("enabled=%t", *filter.Enabled))
		}
		if filter.Limit > 0 {
			params = append(params, fmt.Sprintf("limit=%d", filter.Limit))
		}
		if filter.Offset > 0 {
			params = append(params, fmt.Sprintf("offset=%d", filter.Offset))
		}
	}

	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	var listResp ListRulesResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &listResp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &listResp, nil
}

// Get retrieves a specific rule by ID.
func (s *RuleService) Get(ctx context.Context, ruleID string) (*Rule, error) {
	path := fmt.Sprintf("/api/v1/evm/rules/%s", ruleID)
	var rule Rule
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &rule, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

// Create creates a new authorization rule.
func (s *RuleService) Create(ctx context.Context, req *CreateRuleRequest) (*Rule, error) {
	var rule Rule
	err := s.transport.Request(ctx, http.MethodPost, "/api/v1/evm/rules", req, &rule,
		http.StatusOK, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

// Update updates an existing authorization rule.
func (s *RuleService) Update(ctx context.Context, ruleID string, req *UpdateRuleRequest) (*Rule, error) {
	path := fmt.Sprintf("/api/v1/evm/rules/%s", ruleID)
	var rule Rule
	err := s.transport.Request(ctx, http.MethodPatch, path, req, &rule, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

// Delete deletes a rule by ID.
func (s *RuleService) Delete(ctx context.Context, ruleID string) error {
	path := fmt.Sprintf("/api/v1/evm/rules/%s", ruleID)
	return s.transport.Request(ctx, http.MethodDelete, path, nil, nil,
		http.StatusOK, http.StatusNoContent)
}

// Toggle enables or disables a rule.
func (s *RuleService) Toggle(ctx context.Context, ruleID string, enabled bool) (*Rule, error) {
	path := fmt.Sprintf("/api/v1/evm/rules/%s", ruleID)
	body := map[string]bool{"enabled": enabled}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	var rule Rule
	// Use RequestRaw for toggle since body is not a struct
	respBytes, err := s.transport.RequestRaw(ctx, http.MethodPatch, path, bodyBytes, http.StatusOK)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(respBytes, &rule); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &rule, nil
}

// ListBudgets returns budgets for a rule (GET /api/v1/evm/rules/{ruleID}/budgets).
func (s *RuleService) ListBudgets(ctx context.Context, ruleID string) ([]RuleBudget, error) {
	path := fmt.Sprintf("/api/v1/evm/rules/%s/budgets", ruleID)
	var budgets []RuleBudget
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &budgets, http.StatusOK)
	if err != nil {
		return nil, err
	}
	if budgets == nil {
		budgets = []RuleBudget{}
	}
	return budgets, nil
}
