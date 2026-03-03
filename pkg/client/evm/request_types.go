package evm

// ListRequestsResponse represents the response from listing requests.
type ListRequestsResponse struct {
	Requests     []RequestStatus `json:"requests"`
	Total        int             `json:"total"`
	NextCursor   *string         `json:"next_cursor,omitempty"`
	NextCursorID *string         `json:"next_cursor_id,omitempty"`
	HasMore      bool            `json:"has_more"`
}

// ListRequestsFilter contains filter options for listing requests.
type ListRequestsFilter struct {
	Status        string
	SignerAddress string
	ChainID       string
	Limit         int
	Cursor        *string
	CursorID      *string
}

// ApproveRequest represents a request to approve a signing request.
type ApproveRequest struct {
	Approved bool   `json:"approved"`
	RuleType string `json:"rule_type,omitempty"`
	RuleMode string `json:"rule_mode,omitempty"`
	RuleName string `json:"rule_name,omitempty"`
	MaxValue string `json:"max_value,omitempty"`
}

// ApproveResponse represents the response from an approval request.
type ApproveResponse struct {
	RequestID     string `json:"request_id"`
	Status        string `json:"status"`
	Signature     string `json:"signature,omitempty"`
	SignedData    string `json:"signed_data,omitempty"`
	Message       string `json:"message,omitempty"`
	GeneratedRule *Rule  `json:"generated_rule,omitempty"`
}

// PreviewRuleRequest represents a request to preview a rule for approval.
type PreviewRuleRequest struct {
	RuleType string `json:"rule_type"`
	RuleMode string `json:"rule_mode"`
	RuleName string `json:"rule_name,omitempty"`
	MaxValue string `json:"max_value,omitempty"`
}

// PreviewRuleResponse represents a rule preview for an approval.
type PreviewRuleResponse struct {
	Rule Rule `json:"rule"`
}
