package client

import (
	"errors"
	"fmt"
)

// Common errors returned by the client.
var (
	// ErrUnauthorized is returned when authentication fails.
	ErrUnauthorized = errors.New("unauthorized: invalid or expired API key/signature")

	// ErrNotFound is returned when the requested resource is not found.
	ErrNotFound = errors.New("not found")

	// ErrSignerNotFound is returned when the requested signer is not available.
	ErrSignerNotFound = errors.New("signer not found")

	// ErrInvalidPayload is returned when the signing payload is invalid.
	ErrInvalidPayload = errors.New("invalid payload")

	// ErrRateLimited is returned when too many requests are made.
	ErrRateLimited = errors.New("rate limited")

	// ErrPendingApproval is returned when a request requires manual approval.
	ErrPendingApproval = errors.New("pending manual approval")

	// ErrRejected is returned when a request is rejected.
	ErrRejected = errors.New("request rejected")

	// ErrBlocked is returned when a request is blocked by a blocklist rule.
	ErrBlocked = errors.New("request blocked by rule")

	// ErrTimeout is returned when polling for a result times out.
	ErrTimeout = errors.New("timeout waiting for approval")
)

// APIError represents an error returned by the remote-signer API.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("API error %d (%s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Code)
}

// Is implements errors.Is for APIError.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrUnauthorized:
		return e.StatusCode == 401
	case ErrNotFound:
		return e.StatusCode == 404
	case ErrSignerNotFound:
		return e.Code == "signer_not_found"
	case ErrInvalidPayload:
		return e.Code == "invalid_payload" || e.Code == "invalid_request"
	case ErrRateLimited:
		return e.StatusCode == 429
	case ErrRejected:
		return e.Code == "rejected"
	case ErrBlocked:
		return e.Code == "blocked"
	}
	return false
}

// SignError represents an error during the signing process.
type SignError struct {
	RequestID string
	Status    string
	Message   string
}

// Error implements the error interface.
func (e *SignError) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("sign error [%s] status=%s: %s", e.RequestID, e.Status, e.Message)
	}
	return fmt.Sprintf("sign error status=%s: %s", e.Status, e.Message)
}

// Is implements errors.Is for SignError.
func (e *SignError) Is(target error) bool {
	switch target {
	case ErrPendingApproval:
		return e.Status == StatusAuthorizing
	case ErrRejected:
		return e.Status == StatusRejected
	}
	return false
}
