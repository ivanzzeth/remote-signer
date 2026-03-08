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
	case types.AuditEventTypeSignerCreated, types.AuditEventTypeSignerUnlocked, types.AuditEventTypeHDWalletCreated:
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

// LogConfigReloaded logs a SIGHUP config reload event.
func (a *AuditLogger) LogConfigReloaded(ctx context.Context, success bool, errMsg string) {
	record := &types.AuditRecord{
		EventType:    types.AuditEventTypeConfigReloaded,
		ActorAddress: "system",
		ErrorMessage: errMsg,
	}
	if !success {
		record.ErrorMessage = fmt.Sprintf("config reload failed: %s", errMsg)
	}
	a.log(ctx, record)
}

// LogTemplateSynced logs a template sync event (create/update/delete from config).
func (a *AuditLogger) LogTemplateSynced(ctx context.Context, action, templateID, templateName string) {
	a.log(ctx, &types.AuditRecord{
		EventType:    types.AuditEventTypeTemplateSynced,
		ActorAddress: "config-sync",
		ErrorMessage: fmt.Sprintf("template %s: %s (%s)", action, templateName, templateID),
	})
}

// LogAPIKeySynced logs an API key sync event (create/update from config).
func (a *AuditLogger) LogAPIKeySynced(ctx context.Context, action, keyID, keyName string) {
	a.log(ctx, &types.AuditRecord{
		EventType:    types.AuditEventTypeAPIKeySynced,
		APIKeyID:     keyID,
		ActorAddress: "config-sync",
		ErrorMessage: fmt.Sprintf("apikey %s: %s", action, keyName),
	})
}

// LogSignerCreated logs a signer creation event.
func (a *AuditLogger) LogSignerCreated(ctx context.Context, apiKeyID, clientIP, address, signerType string) {
	addr := address
	a.log(ctx, &types.AuditRecord{
		EventType:    types.AuditEventTypeSignerCreated,
		APIKeyID:     apiKeyID,
		ActorAddress: clientIP,
		SignerAddress: &addr,
		ErrorMessage: fmt.Sprintf("signer created: type=%s", signerType),
	})
}

// LogSignerLocked logs a signer lock event.
func (a *AuditLogger) LogSignerLocked(ctx context.Context, apiKeyID, clientIP, address string) {
	addr := address
	a.log(ctx, &types.AuditRecord{
		EventType:    types.AuditEventTypeSignerLocked,
		APIKeyID:     apiKeyID,
		ActorAddress: clientIP,
		SignerAddress: &addr,
	})
}

// LogSignerUnlocked logs a signer unlock event.
func (a *AuditLogger) LogSignerUnlocked(ctx context.Context, apiKeyID, clientIP, address string) {
	addr := address
	a.log(ctx, &types.AuditRecord{
		EventType:    types.AuditEventTypeSignerUnlocked,
		APIKeyID:     apiKeyID,
		ActorAddress: clientIP,
		SignerAddress: &addr,
	})
}

// LogHDWalletCreated logs an HD wallet create/import event.
func (a *AuditLogger) LogHDWalletCreated(ctx context.Context, apiKeyID, clientIP, primaryAddress, action string) {
	addr := primaryAddress
	a.log(ctx, &types.AuditRecord{
		EventType:    types.AuditEventTypeHDWalletCreated,
		APIKeyID:     apiKeyID,
		ActorAddress: clientIP,
		SignerAddress: &addr,
		ErrorMessage: fmt.Sprintf("hdwallet %s", action),
	})
}

// LogHDWalletDerived logs an HD wallet derive event.
func (a *AuditLogger) LogHDWalletDerived(ctx context.Context, apiKeyID, clientIP, primaryAddress string, count int) {
	addr := primaryAddress
	a.log(ctx, &types.AuditRecord{
		EventType:    types.AuditEventTypeHDWalletDerived,
		APIKeyID:     apiKeyID,
		ActorAddress: clientIP,
		SignerAddress: &addr,
		ErrorMessage: fmt.Sprintf("derived %d addresses", count),
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
