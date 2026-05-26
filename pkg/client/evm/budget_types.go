package evm

// Budget represents a budget record.
type Budget struct {
	ID         string `json:"id"`
	RuleID     string `json:"rule_id"`
	Name       string `json:"name,omitempty"`
	MaxTotal   string `json:"max_total"`
	MaxPerTx   string `json:"max_per_tx"`
	MaxTxCount int    `json:"max_tx_count,omitempty"`
	AlertPct   int    `json:"alert_pct,omitempty"`
	Period     string `json:"period,omitempty"`
	StartAt    string `json:"start_at,omitempty"`
	SpentTotal string `json:"spent_total"`
	SpentCount int    `json:"spent_count"`
	CreatedAt  string `json:"created_at,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

// ListBudgetsResponse represents the response from listing budgets.
type ListBudgetsResponse struct {
	Budgets []Budget `json:"budgets"`
	Total   int      `json:"total"`
}

// BudgetListFilter contains filter options for listing budgets.
type BudgetListFilter struct {
	RuleID string
	Limit  int
	Offset int
}

// CreateBudgetRequest represents a request to create a budget for an existing rule.
type CreateBudgetRequest struct {
	RuleID     string `json:"rule_id"`
	Name       string `json:"name,omitempty"`
	MaxTotal   string `json:"max_total"`
	MaxPerTx   string `json:"max_per_tx"`
	MaxTxCount int    `json:"max_tx_count,omitempty"`
	AlertPct   int    `json:"alert_pct,omitempty"`
	Period     string `json:"period,omitempty"`
	StartAt    string `json:"start_at,omitempty"`
}

// UpdateBudgetRequest represents a request to update a budget.
type UpdateBudgetRequest struct {
	MaxTotal   string `json:"max_total,omitempty"`
	MaxPerTx   string `json:"max_per_tx,omitempty"`
	MaxTxCount int    `json:"max_tx_count,omitempty"`
	AlertPct   int    `json:"alert_pct,omitempty"`
	Period     string `json:"period,omitempty"`
}
