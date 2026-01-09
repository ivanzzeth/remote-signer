package types

import "time"

// AuditID is a unique identifier for audit records
type AuditID string

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	// Authentication events
	AuditEventTypeAuthSuccess AuditEventType = "auth_success"
	AuditEventTypeAuthFailure AuditEventType = "auth_failure"

	// Signing events
	AuditEventTypeSignRequest  AuditEventType = "sign_request"
	AuditEventTypeSignComplete AuditEventType = "sign_complete"
	AuditEventTypeSignFailed   AuditEventType = "sign_failed"
	AuditEventTypeSignRejected AuditEventType = "sign_rejected"

	// Authorization events
	AuditEventTypeRuleMatched      AuditEventType = "rule_matched"
	AuditEventTypeApprovalRequest  AuditEventType = "approval_request"
	AuditEventTypeApprovalGranted  AuditEventType = "approval_granted"
	AuditEventTypeApprovalDenied   AuditEventType = "approval_denied"

	// Rule management events
	AuditEventTypeRuleCreated AuditEventType = "rule_created"
	AuditEventTypeRuleUpdated AuditEventType = "rule_updated"
	AuditEventTypeRuleDeleted AuditEventType = "rule_deleted"

	// Security events
	AuditEventTypeRateLimitHit AuditEventType = "rate_limit_hit"
)

// AuditSeverity represents the severity level of an audit event
type AuditSeverity string

const (
	AuditSeverityInfo     AuditSeverity = "info"
	AuditSeverityWarning  AuditSeverity = "warning"
	AuditSeverityCritical AuditSeverity = "critical"
)

// AuditRecord represents a complete audit log entry
type AuditRecord struct {
	ID        AuditID        `json:"id" gorm:"primaryKey;type:varchar(64)"`
	EventType AuditEventType `json:"event_type" gorm:"index;type:varchar(32)"`
	Severity  AuditSeverity  `json:"severity" gorm:"type:varchar(16)"`
	Timestamp time.Time      `json:"timestamp" gorm:"index"`

	// Actor information
	APIKeyID     string `json:"api_key_id,omitempty" gorm:"index;type:varchar(64)"`
	ActorAddress string `json:"actor_address,omitempty" gorm:"type:varchar(64)"` // IP or identifier

	// Target information
	SignRequestID *SignRequestID `json:"sign_request_id,omitempty" gorm:"type:varchar(64)"`
	SignerAddress *string        `json:"signer_address,omitempty" gorm:"type:varchar(128)"`
	ChainType     *ChainType     `json:"chain_type,omitempty" gorm:"type:varchar(32)"`
	ChainID       *string        `json:"chain_id,omitempty" gorm:"type:varchar(32)"`
	RuleID        *RuleID        `json:"rule_id,omitempty" gorm:"type:varchar(64)"`

	// Event details
	Details      []byte `json:"details,omitempty" gorm:"type:jsonb"`
	ErrorMessage string `json:"error_message,omitempty" gorm:"type:text"`

	// Request context
	RequestMethod string `json:"request_method,omitempty" gorm:"type:varchar(16)"`
	RequestPath   string `json:"request_path,omitempty" gorm:"type:varchar(255)"`
}

// TableName specifies the table name for GORM
func (AuditRecord) TableName() string {
	return "audit_records"
}
