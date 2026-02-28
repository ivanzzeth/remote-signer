package audit

import (
	"encoding/json"
	"time"
)

// Record represents an audit log entry.
type Record struct {
	ID            string          `json:"id"`
	EventType     string          `json:"event_type"`
	Severity      string          `json:"severity"`
	Timestamp     time.Time       `json:"timestamp"`
	APIKeyID      string          `json:"api_key_id,omitempty"`
	ActorAddress  string          `json:"actor_address,omitempty"`
	SignRequestID *string         `json:"sign_request_id,omitempty"`
	SignerAddress *string         `json:"signer_address,omitempty"`
	ChainType     *string         `json:"chain_type,omitempty"`
	ChainID       *string         `json:"chain_id,omitempty"`
	RuleID        *string         `json:"rule_id,omitempty"`
	Details       json.RawMessage `json:"details,omitempty"`
	ErrorMessage  string          `json:"error_message,omitempty"`
	RequestMethod string          `json:"request_method,omitempty"`
	RequestPath   string          `json:"request_path,omitempty"`
}

// ListResponse represents the response from listing audit records.
type ListResponse struct {
	Records      []Record `json:"records"`
	Total        int      `json:"total"`
	NextCursor   *string  `json:"next_cursor,omitempty"`
	NextCursorID *string  `json:"next_cursor_id,omitempty"`
	HasMore      bool     `json:"has_more"`
}

// ListFilter contains filter options for listing audit records.
type ListFilter struct {
	EventType     string
	Severity      string
	APIKeyID      string
	SignerAddress string
	ChainType     string
	ChainID       string
	StartTime     *time.Time
	EndTime       *time.Time
	Limit         int
	Cursor        *string
	CursorID      *string
}
