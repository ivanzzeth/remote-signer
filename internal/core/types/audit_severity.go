package types

// SeverityForEvent returns the severity that belongs to each audit event type.
//
// It lives with the event types rather than with the audit logger because it is
// a classification of the events, not a behaviour of the sink: the state machine
// needs it to decide how loudly to report a transition, and it had to import
// internal/audit — an adapter — for a switch statement over constants declared
// right here.
func SeverityForEvent(eventType AuditEventType) AuditSeverity {
	switch eventType {
	case AuditEventTypeAuthFailure, AuditEventTypeSignRejected, AuditEventTypeSignFailed:
		return AuditSeverityCritical
	case AuditEventTypeApprovalDenied, AuditEventTypeRateLimitHit:
		return AuditSeverityWarning
	case AuditEventTypeSignerAutoLocked:
		return AuditSeverityCritical
	case AuditEventTypeSignerCreated, AuditEventTypeSignerUnlocked, AuditEventTypeHDWalletCreated, AuditEventTypePresetApplied:
		return AuditSeverityWarning
	default:
		return AuditSeverityInfo
	}
}
