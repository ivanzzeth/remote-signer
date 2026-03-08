package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// AuditLogger wraps AuditRepository with typed convenience methods
// that enforce correct severity levels. Logging errors are non-fatal
// (logged via slog but never propagate to callers).
type AuditLogger struct {
	repo   storage.AuditRepository
	logger *slog.Logger
}

// NewAuditLogger creates a new AuditLogger.
func NewAuditLogger(repo storage.AuditRepository, logger *slog.Logger) (*AuditLogger, error) {
	if repo == nil {
		return nil, fmt.Errorf("audit repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &AuditLogger{repo: repo, logger: logger}, nil
}

// SeverityForEvent returns the appropriate severity for each event type.
func SeverityForEvent(eventType types.AuditEventType) types.AuditSeverity {
	switch eventType {
	case types.AuditEventTypeAuthFailure, types.AuditEventTypeSignRejected, types.AuditEventTypeSignFailed:
		return types.AuditSeverityCritical
	case types.AuditEventTypeApprovalDenied, types.AuditEventTypeRateLimitHit:
		return types.AuditSeverityWarning
	default:
		return types.AuditSeverityInfo
	}
}

// LogAuthSuccess logs a successful authentication event.
func (a *AuditLogger) LogAuthSuccess(ctx context.Context, apiKeyID, clientIP, method, path string) {
	a.log(ctx, &types.AuditRecord{
		EventType:     types.AuditEventTypeAuthSuccess,
		APIKeyID:      apiKeyID,
		ActorAddress:  clientIP,
		RequestMethod: method,
		RequestPath:   path,
	})
}

// LogAuthFailure logs a failed authentication event.
func (a *AuditLogger) LogAuthFailure(ctx context.Context, apiKeyID, clientIP, method, path, errMsg string) {
	a.log(ctx, &types.AuditRecord{
		EventType:     types.AuditEventTypeAuthFailure,
		APIKeyID:      apiKeyID,
		ActorAddress:  clientIP,
		RequestMethod: method,
		RequestPath:   path,
		ErrorMessage:  errMsg,
	})
}

// LogSignRequest logs a new sign request creation.
func (a *AuditLogger) LogSignRequest(ctx context.Context, req *types.SignRequest) {
	a.log(ctx, &types.AuditRecord{
		EventType:     types.AuditEventTypeSignRequest,
		APIKeyID:      req.APIKeyID,
		ActorAddress:  req.ClientIP,
		SignRequestID: &req.ID,
		SignerAddress: &req.SignerAddress,
		ChainType:     &req.ChainType,
		ChainID:       &req.ChainID,
	})
}

// LogApprovalRequest logs a manual approval request.
func (a *AuditLogger) LogApprovalRequest(ctx context.Context, req *types.SignRequest) {
	a.log(ctx, &types.AuditRecord{
		EventType:     types.AuditEventTypeApprovalRequest,
		APIKeyID:      req.APIKeyID,
		ActorAddress:  req.ClientIP,
		SignRequestID: &req.ID,
		SignerAddress: &req.SignerAddress,
		ChainType:     &req.ChainType,
		ChainID:       &req.ChainID,
		ErrorMessage:  "pending manual approval",
	})
}

// LogRuleCreated logs a rule creation event.
func (a *AuditLogger) LogRuleCreated(ctx context.Context, apiKeyID, clientIP string, ruleID types.RuleID, ruleName string) {
	a.log(ctx, &types.AuditRecord{
		EventType:    types.AuditEventTypeRuleCreated,
		APIKeyID:     apiKeyID,
		ActorAddress: clientIP,
		RuleID:       &ruleID,
		ErrorMessage: fmt.Sprintf("rule created: %s", ruleName),
	})
}

// LogRuleUpdated logs a rule update event.
func (a *AuditLogger) LogRuleUpdated(ctx context.Context, apiKeyID, clientIP string, ruleID types.RuleID, ruleName string) {
	a.log(ctx, &types.AuditRecord{
		EventType:    types.AuditEventTypeRuleUpdated,
		APIKeyID:     apiKeyID,
		ActorAddress: clientIP,
		RuleID:       &ruleID,
		ErrorMessage: fmt.Sprintf("rule updated: %s", ruleName),
	})
}

// LogRuleDeleted logs a rule deletion event.
func (a *AuditLogger) LogRuleDeleted(ctx context.Context, apiKeyID, clientIP string, ruleID types.RuleID) {
	a.log(ctx, &types.AuditRecord{
		EventType:    types.AuditEventTypeRuleDeleted,
		APIKeyID:     apiKeyID,
		ActorAddress: clientIP,
		RuleID:       &ruleID,
		ErrorMessage: fmt.Sprintf("rule deleted: %s", string(ruleID)),
	})
}

// APIRequestDetails contains metadata for an API request audit record.
type APIRequestDetails struct {
	StatusCode int    `json:"status_code"`
	DurationMs int64  `json:"duration_ms"`
	UserAgent  string `json:"user_agent,omitempty"`
}

// LogAPIRequest logs every API request with its outcome for full timeline reconstruction.
func (a *AuditLogger) LogAPIRequest(ctx context.Context, apiKeyID, clientIP, method, path string, statusCode int, durationMs int64, userAgent string) {
	details := APIRequestDetails{
		StatusCode: statusCode,
		DurationMs: durationMs,
		UserAgent:  userAgent,
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = nil
	}

	// Determine severity from status code
	severity := types.AuditSeverityInfo
	if statusCode >= 400 && statusCode < 500 {
		severity = types.AuditSeverityWarning
	} else if statusCode >= 500 {
		severity = types.AuditSeverityCritical
	}

	record := &types.AuditRecord{
		EventType:     types.AuditEventTypeAPIRequest,
		APIKeyID:      apiKeyID,
		ActorAddress:  clientIP,
		RequestMethod: method,
		RequestPath:   path,
		Details:       detailsJSON,
	}
	record.ID = types.AuditID(uuid.New().String())
	record.Timestamp = time.Now()
	record.Severity = severity

	if logErr := a.repo.Log(ctx, record); logErr != nil {
		a.logger.Error("failed to log api_request audit record",
			"error", logErr,
			"method", method,
			"path", path,
		)
	}
}

// LogRateLimitHit logs a rate limit event.
func (a *AuditLogger) LogRateLimitHit(ctx context.Context, apiKeyID, clientIP, method, path string) {
	a.log(ctx, &types.AuditRecord{
		EventType:     types.AuditEventTypeRateLimitHit,
		APIKeyID:      apiKeyID,
		ActorAddress:  clientIP,
		RequestMethod: method,
		RequestPath:   path,
	})
}

// log persists an audit record with auto-generated ID, timestamp, and severity.
func (a *AuditLogger) log(ctx context.Context, record *types.AuditRecord) {
	record.ID = types.AuditID(uuid.New().String())
	record.Timestamp = time.Now()
	record.Severity = SeverityForEvent(record.EventType)

	if err := a.repo.Log(ctx, record); err != nil {
		a.logger.Error("failed to log audit record",
			"error", err,
			"event_type", record.EventType,
			"api_key_id", record.APIKeyID,
		)
	}
}
