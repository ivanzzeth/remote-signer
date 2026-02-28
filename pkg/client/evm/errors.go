package evm

import "errors"

// Common errors returned by EVM services.
var (
	ErrUnauthorized    = errors.New("unauthorized: invalid or expired API key/signature")
	ErrNotFound        = errors.New("not found")
	ErrSignerNotFound  = errors.New("signer not found")
	ErrInvalidPayload  = errors.New("invalid payload")
	ErrRateLimited     = errors.New("rate limited")
	ErrPendingApproval = errors.New("pending manual approval")
	ErrRejected        = errors.New("request rejected")
	ErrBlocked         = errors.New("request blocked by rule")
	ErrTimeout         = errors.New("timeout waiting for approval")
)
