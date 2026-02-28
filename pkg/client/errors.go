package client

import (
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// SignError represents an error during the signing process.
type SignError = evm.SignError

// APIError represents an error returned by the remote-signer API.
type APIError = transport.APIError

// ErrorResponse represents an error response from the API.
type ErrorResponse = transport.ErrorResponse

// Re-export sentinel errors from the evm package.
var (
	ErrUnauthorized    = evm.ErrUnauthorized
	ErrNotFound        = evm.ErrNotFound
	ErrSignerNotFound  = evm.ErrSignerNotFound
	ErrInvalidPayload  = evm.ErrInvalidPayload
	ErrRateLimited     = evm.ErrRateLimited
	ErrPendingApproval = evm.ErrPendingApproval
	ErrRejected        = evm.ErrRejected
	ErrBlocked         = evm.ErrBlocked
	ErrTimeout         = evm.ErrTimeout
)
