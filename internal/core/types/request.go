package types

import "time"

// SignRequestID is a unique identifier for sign requests
type SignRequestID string

// SignRequestStatus represents the current state of a sign request
type SignRequestStatus string

const (
	StatusPending     SignRequestStatus = "pending"
	StatusAuthorizing SignRequestStatus = "authorizing"
	StatusSigning     SignRequestStatus = "signing"
	StatusCompleted   SignRequestStatus = "completed"
	StatusRejected    SignRequestStatus = "rejected"
	StatusFailed      SignRequestStatus = "failed"
)

// SignRequest is chain-agnostic; payload is chain-specific JSON
type SignRequest struct {
	ID        SignRequestID `json:"id" gorm:"primaryKey;type:varchar(64)"`
	APIKeyID  string        `json:"api_key_id" gorm:"index;type:varchar(64)"`

	// Chain identification
	ChainType ChainType `json:"chain_type" gorm:"index;type:varchar(32)"` // "evm", "solana", etc.
	ChainID   string    `json:"chain_id" gorm:"type:varchar(32)"`         // e.g., "1" for Ethereum mainnet

	SignerAddress string `json:"signer_address" gorm:"index;type:varchar(128)"`
	SignType      string `json:"sign_type" gorm:"type:varchar(32)"`  // chain-specific sign type
	Payload       []byte `json:"payload" gorm:"type:jsonb"`          // chain-specific payload

	Status SignRequestStatus `json:"status" gorm:"index;type:varchar(16)"`

	// Authorization
	RuleMatchedID *string    `json:"rule_matched_id,omitempty" gorm:"type:varchar(64)"`
	ApprovedBy    *string    `json:"approved_by,omitempty" gorm:"type:varchar(128)"`
	ApprovedAt    *time.Time `json:"approved_at,omitempty"`

	// Result
	Signature    []byte `json:"signature,omitempty" gorm:"type:bytea"`
	SignedData   []byte `json:"signed_data,omitempty" gorm:"type:bytea"` // e.g., signed tx
	ErrorMessage string `json:"error_message,omitempty" gorm:"type:text"`

	// Timestamps
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// TableName specifies the table name for GORM
func (SignRequest) TableName() string {
	return "sign_requests"
}

// SignResponse represents the API response for a sign request
type SignResponse struct {
	RequestID  SignRequestID     `json:"request_id"`
	Status     SignRequestStatus `json:"status"`
	Signature  *SignatureResult  `json:"signature,omitempty"`
	SignedData []byte            `json:"signed_data,omitempty"`
	Error      *SignError        `json:"error,omitempty"`
}

// SignatureResult contains the signature components
type SignatureResult struct {
	Raw        string `json:"raw"`         // hex encoded, 0x prefixed
	R          string `json:"r,omitempty"` // hex encoded, 0x prefixed
	S          string `json:"s,omitempty"` // hex encoded, 0x prefixed
	V          uint8  `json:"v,omitempty"` // 27 or 28
	RecoveryID uint8  `json:"recovery_id"` // 0 or 1
}

// SignError represents a signing error
type SignError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Details string    `json:"details,omitempty"`
}

// ErrorCode represents error types
type ErrorCode string

const (
	ErrorCodeInvalidRequest  ErrorCode = "INVALID_REQUEST"
	ErrorCodeUnauthorized    ErrorCode = "UNAUTHORIZED"
	ErrorCodeForbidden       ErrorCode = "FORBIDDEN"
	ErrorCodeRuleViolation   ErrorCode = "RULE_VIOLATION"
	ErrorCodeSignerNotFound  ErrorCode = "SIGNER_NOT_FOUND"
	ErrorCodeSigningFailed   ErrorCode = "SIGNING_FAILED"
	ErrorCodeTimeout         ErrorCode = "TIMEOUT"
	ErrorCodeRateLimited     ErrorCode = "RATE_LIMITED"
	ErrorCodeInternalError   ErrorCode = "INTERNAL_ERROR"
	ErrorCodeRequestExpired  ErrorCode = "REQUEST_EXPIRED"
	ErrorCodePendingApproval ErrorCode = "PENDING_APPROVAL"
)
