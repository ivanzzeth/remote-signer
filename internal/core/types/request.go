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

// ApprovalSource enumerates how a request transitioned from authorizing
// to signing. It's a denormalised attribution column on SignRequest so
// the UI doesn't have to infer it from a combination of empty/nil
// fields. New code should always set this; legacy rows may leave it
// blank — see DeriveApprovalSource.
const (
	ApprovalSourceManual     = "manual"
	ApprovalSourceRule       = "rule"
	ApprovalSourceSimulation = "simulation"
)

// DeriveApprovalSource recovers an attribution string from the fields
// already on a SignRequest. Used both at write time (state machine) and
// at read time (handler) so rows persisted before ApprovalSource
// existed still display the same way as new ones.
func DeriveApprovalSource(ruleMatchedID *string, approvedBy *string) string {
	if approvedBy != nil && *approvedBy != "" {
		return ApprovalSourceManual
	}
	if ruleMatchedID != nil && *ruleMatchedID != "" {
		return ApprovalSourceRule
	}
	return ApprovalSourceSimulation
}

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

	ClientIP string `json:"client_ip" gorm:"type:varchar(64)"` // source IP of the sign request (set from context)

	Status SignRequestStatus `json:"status" gorm:"index;type:varchar(16)"`

	// Authorization
	RuleMatchedID *string    `json:"rule_matched_id,omitempty" gorm:"type:varchar(64)"`
	ApprovedBy    *string    `json:"approved_by,omitempty" gorm:"type:varchar(128)"`
	ApprovedAt    *time.Time `json:"approved_at,omitempty"`
	// ApprovalSource records which gate let this request through:
	// "manual" (admin clicked Approve), "rule" (a whitelist rule
	// matched), or "simulation" (the simulation fallback budgeted it).
	// Empty on rows persisted before this field was introduced;
	// callers should derive from RuleMatchedID/ApprovedBy in that case.
	ApprovalSource string `json:"approval_source,omitempty" gorm:"type:varchar(16);index"`

	// Result
	Signature    []byte `json:"signature,omitempty" gorm:"type:bytea"`
	SignedData   []byte `json:"signed_data,omitempty" gorm:"type:bytea"` // e.g., signed tx
	ErrorMessage string `json:"error_message,omitempty" gorm:"type:text"`
	// TransactionID is the FK into the transactions table — set once
	// the wallet RPC proxy observes an eth_sendRawTransaction whose
	// payload matches this request's SignedData. Nullable: not every
	// SignRequest is a transaction (personal_sign / typed_data
	// requests never get one) and a freshly-signed tx hasn't been
	// broadcast yet. The transactions row owns all chain-side state
	// (hash, status, receipt) so this column stays narrow.
	TransactionID *string `json:"transaction_id,omitempty" gorm:"type:varchar(64);index"`
	// LastNoMatchReason captures the reason text the whitelist engine
	// would have logged when NO rule matched this request. Populated
	// only when Status transitions to "authorizing" / "pending" via the
	// no-match path; empty when a rule auto-approved the request. The
	// activity-drawer reads this to surface "why didn't my rule fire?"
	// directly in the popup instead of forcing operators to grep
	// server logs.
	LastNoMatchReason string `json:"last_no_match_reason,omitempty" gorm:"type:text"`

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
