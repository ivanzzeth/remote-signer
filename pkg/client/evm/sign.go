package evm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ivanzzeth/remote-signer/pkg/client/internal/transport"
)

// SignService handles signing operations.
type SignService struct {
	transport *transport.Transport

	// PollInterval is the interval between status checks when waiting for approval.
	PollInterval time.Duration

	// PollTimeout is the maximum time to wait for approval.
	PollTimeout time.Duration
}

// SetPolling configures polling parameters.
func (s *SignService) SetPolling(interval, timeout time.Duration) {
	s.PollInterval = interval
	s.PollTimeout = timeout
}

// Execute submits a signing request and waits for the result.
// If the request requires manual approval, this method will poll until completed or timeout.
func (s *SignService) Execute(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	return s.signWithOptions(ctx, req, true)
}

// ExecuteAsync submits a signing request and returns immediately.
// If the request requires approval, returns the pending status with a SignError.
func (s *SignService) ExecuteAsync(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	return s.signWithOptions(ctx, req, false)
}

func (s *SignService) signWithOptions(ctx context.Context, req *SignRequest, waitForApproval bool) (*SignResponse, error) {
	var signResp SignResponse
	err := s.transport.Request(ctx, http.MethodPost, "/api/v1/evm/sign", req, &signResp,
		http.StatusOK, http.StatusCreated, http.StatusAccepted)
	if err != nil {
		return nil, err
	}

	if signResp.Status == StatusCompleted {
		return &signResp, nil
	}

	if signResp.Status == StatusRejected || signResp.Status == StatusFailed {
		return nil, &SignError{
			RequestID: signResp.RequestID,
			Status:    signResp.Status,
			Message:   signResp.Message,
		}
	}

	if waitForApproval && (signResp.Status == StatusPending || signResp.Status == StatusAuthorizing) {
		return s.pollForResult(ctx, signResp.RequestID)
	}

	return &signResp, &SignError{
		RequestID: signResp.RequestID,
		Status:    signResp.Status,
		Message:   signResp.Message,
	}
}

func (s *SignService) pollForResult(ctx context.Context, requestID string) (*SignResponse, error) {
	deadline := time.Now().Add(s.PollTimeout)
	ticker := time.NewTicker(s.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil, ErrTimeout
			}

			var status RequestStatus
			path := fmt.Sprintf("/api/v1/evm/requests/%s", url.PathEscape(requestID))
			err := s.transport.Request(ctx, http.MethodGet, path, nil, &status, http.StatusOK)
			if err != nil {
				return nil, err
			}

			switch status.Status {
			case StatusCompleted:
				return &SignResponse{
					RequestID:   status.ID,
					Status:      status.Status,
					Signature:   status.Signature,
					SignedData:  status.SignedData,
					RuleMatched: ptrToString(status.RuleMatchedID),
				}, nil
			case StatusRejected, StatusFailed:
				return nil, &SignError{
					RequestID: status.ID,
					Status:    status.Status,
					Message:   status.ErrorMessage,
				}
			}
		}
	}
}

func ptrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
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
