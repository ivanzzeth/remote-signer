package types

import (
	"errors"
	"fmt"
)

// Common errors
var (
	ErrNotFound           = errors.New("not found")
	ErrAlreadyExists      = errors.New("already exists")
	ErrInvalidInput       = errors.New("invalid input")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrRateLimited        = errors.New("rate limited")
	ErrInternalError      = errors.New("internal error")
	ErrInvalidState       = errors.New("invalid state transition")
	ErrSignerNotFound     = errors.New("signer not found")
	ErrChainNotSupported  = errors.New("chain type not supported")
	ErrInvalidPayload     = errors.New("invalid payload")
	ErrSigningFailed      = errors.New("signing failed")
	ErrPendingApproval    = errors.New("pending manual approval")
	ErrRequestExpired     = errors.New("request expired")

	// Signer state errors
	ErrSignerLocked    = errors.New("signer is locked")
	ErrSignerNotLocked = errors.New("signer is not locked")

	// Signer creation errors
	ErrMissingSignerType              = errors.New("signer type is required")
	ErrUnsupportedSignerType          = errors.New("unsupported signer type")
	ErrMissingKeystoreParams          = errors.New("keystore parameters are required")
	ErrMissingHDWalletParams          = errors.New("hd_wallet parameters are required")
	ErrEmptyPassword                  = errors.New("password cannot be empty")
	ErrPrivateKeyCreationNotSupported = errors.New("private key creation via API is not supported")
	ErrHDWalletNotConfigured          = errors.New("HD wallet provider is not configured")
)

// TypedError provides structured error information
type TypedError struct {
	Code    ErrorCode
	Message string
	Cause   error
}

// Error implements the error interface
func (e *TypedError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *TypedError) Unwrap() error {
	return e.Cause
}

// NewTypedError creates a new typed error
func NewTypedError(code ErrorCode, message string, cause error) *TypedError {
	return &TypedError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// IsNotFound checks if the error is a not found error
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsUnauthorized checks if the error is an unauthorized error
func IsUnauthorized(err error) bool {
	return errors.Is(err, ErrUnauthorized)
}

// IsForbidden checks if the error is a forbidden error
func IsForbidden(err error) bool {
	return errors.Is(err, ErrForbidden)
}

// IsRateLimited checks if the error is a rate limited error
func IsRateLimited(err error) bool {
	return errors.Is(err, ErrRateLimited)
}

// IsSignerNotFound checks if the error is a signer not found error
func IsSignerNotFound(err error) bool {
	return errors.Is(err, ErrSignerNotFound)
}

// IsInvalidPayload checks if the error is an invalid payload error
func IsInvalidPayload(err error) bool {
	return errors.Is(err, ErrInvalidPayload)
}

// IsPendingApproval checks if the error indicates pending approval
func IsPendingApproval(err error) bool {
	return errors.Is(err, ErrPendingApproval)
}

// IsSignerLocked checks if the error is a signer locked error
func IsSignerLocked(err error) bool {
	return errors.Is(err, ErrSignerLocked)
}
