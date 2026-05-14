package evm

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// SignErrorResult holds the sanitized HTTP response for a sign error.
type SignErrorResult struct {
	StatusCode int
	Message    string
}

// categorizeSignError inspects a sign-service error and returns a sanitized
// HTTP status code and user-facing message. Internal details are never leaked.
// signerAddress is used to build helpful messages for locked/not-found cases.
func categorizeSignError(err error, signerAddress string) SignErrorResult {
	if types.IsSignerLocked(err) {
		return SignErrorResult{
			StatusCode: http.StatusForbidden,
			Message:    fmt.Sprintf("signer is locked: %s — unlock via POST /api/v1/evm/signers/%s/unlock", signerAddress, signerAddress),
		}
	}
	if types.IsNotFound(err) || types.IsSignerNotFound(err) {
		return SignErrorResult{
			StatusCode: http.StatusNotFound,
			Message:    fmt.Sprintf("signer not found: %s", signerAddress),
		}
	}
	if errors.Is(err, types.ErrInvalidPayload) {
		return SignErrorResult{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
	}
	if errors.Is(err, service.ErrManualApprovalDisabled) {
		return SignErrorResult{
			StatusCode: http.StatusForbidden,
			Message:    "no matching rule and manual approval is disabled",
		}
	}
	// Catch-all: never expose internal error details
	return SignErrorResult{
		StatusCode: http.StatusInternalServerError,
		Message:    "sign request failed",
	}
}
