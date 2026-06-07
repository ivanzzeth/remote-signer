package evm

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// BudgetService handles standalone budget CRUD operations.
type BudgetService struct {
	transport *transport.Transport
}

// NewBudgetService creates a new budget service.
func NewBudgetService(t *transport.Transport) *BudgetService {
	return &BudgetService{transport: t}
}

// List lists all budgets with optional filters.
func (s *BudgetService) List(ctx context.Context, filter *BudgetListFilter) (*ListBudgetsResponse, error) {
	path := "/api/v1/evm/budgets"
	params := make([]string, 0)

	if filter != nil {
		if filter.RuleID != "" {
			params = append(params, fmt.Sprintf("rule_id=%s", filter.RuleID))
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

	var resp ListBudgetsResponse
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &resp, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Create creates a budget for an existing rule.
func (s *BudgetService) Create(ctx context.Context, req *CreateBudgetRequest) (*Budget, error) {
	var budget Budget
	err := s.transport.Request(ctx, http.MethodPost, "/api/v1/evm/budgets", req, &budget,
		http.StatusOK, http.StatusCreated)
	if err != nil {
		return nil, err
	}
	return &budget, nil
}

// Get retrieves a budget by ID.
func (s *BudgetService) Get(ctx context.Context, id string) (*Budget, error) {
	path := fmt.Sprintf("/api/v1/evm/budgets/%s", id)
	var budget Budget
	err := s.transport.Request(ctx, http.MethodGet, path, nil, &budget, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &budget, nil
}

// Update updates a budget by ID.
func (s *BudgetService) Update(ctx context.Context, id string, req *UpdateBudgetRequest) (*Budget, error) {
	path := fmt.Sprintf("/api/v1/evm/budgets/%s", id)
	var budget Budget
	err := s.transport.Request(ctx, http.MethodPatch, path, req, &budget, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &budget, nil
}

// Delete deletes a budget by ID.
func (s *BudgetService) Delete(ctx context.Context, id string) error {
	path := fmt.Sprintf("/api/v1/evm/budgets/%s", id)
	return s.transport.Request(ctx, http.MethodDelete, path, nil, nil, http.StatusOK, http.StatusNoContent)
}

// DeleteByRuleID deletes all budget rows for a rule_id (orphan cleanup).
func (s *BudgetService) DeleteByRuleID(ctx context.Context, ruleID string) error {
	path := fmt.Sprintf("/api/v1/evm/budgets/by-rule/%s", ruleID)
	return s.transport.Request(ctx, http.MethodDelete, path, nil, nil, http.StatusOK, http.StatusNoContent)
}

// Reset resets a budget counter.
func (s *BudgetService) Reset(ctx context.Context, id string) (*Budget, error) {
	path := fmt.Sprintf("/api/v1/evm/budgets/%s/reset", id)
	var budget Budget
	err := s.transport.Request(ctx, http.MethodPost, path, nil, &budget, http.StatusOK)
	if err != nil {
		return nil, err
	}
	return &budget, nil
}
