package evm

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestBatchApprovalHandler_EmptyIDs(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	h, err := NewBatchApprovalHandler(&mockSignService{}, accessSvc, testLogger())
	require.NoError(t, err)

	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/batch-approve", BatchApprovalAPIRequest{
		RequestIDs: []string{},
		Approved:   true,
	}, approvalAdminKey())
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestBatchApprovalHandler_PartialSuccess(t *testing.T) {
	accessSvc := newSignerTestAccessService(t)
	svc := &mockSignService{
		processApprovalFn: func(_ context.Context, id types.SignRequestID, req *service.ApprovalRequest) (*service.ApprovalResponse, error) {
			if id == "ok" {
				return &service.ApprovalResponse{
					SignResponse: &service.SignResponse{
						RequestID: id,
						Status:    types.StatusCompleted,
					},
				}, nil
			}
			return nil, service.ErrApprovalConflict
		},
	}
	h, err := NewBatchApprovalHandler(svc, accessSvc, testLogger())
	require.NoError(t, err)

	rec := doApprovalRequest(t, h, http.MethodPost, "/api/v1/evm/requests/batch-approve", BatchApprovalAPIRequest{
		RequestIDs: []string{"ok", "bad"},
		Approved:   true,
	}, approvalAdminKey())
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp BatchApprovalAPIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 2, resp.Summary.Total)
	assert.Equal(t, 1, resp.Summary.Succeeded)
	assert.Equal(t, 1, resp.Summary.Failed)
}

func testLogger() *slog.Logger {
	return slog.Default()
}
