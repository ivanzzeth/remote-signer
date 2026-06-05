package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestResolveApprovalIdempotency_RejectReplay(t *testing.T) {
	req := &types.SignRequest{
		ID:     "req-1",
		Status: types.StatusRejected,
	}
	resp, handled, err := resolveApprovalIdempotency(req, false)
	if err != nil || !handled || resp == nil || !resp.Idempotent {
		t.Fatalf("expected idempotent reject replay, got handled=%v err=%v resp=%v", handled, err, resp)
	}
	if resp.SignResponse.Status != types.StatusRejected {
		t.Fatalf("status=%s", resp.SignResponse.Status)
	}
}

func TestResolveApprovalIdempotency_ApproveCompleted(t *testing.T) {
	req := &types.SignRequest{
		ID:     "req-1",
		Status: types.StatusCompleted,
	}
	resp, handled, err := resolveApprovalIdempotency(req, true)
	if err != nil || !handled || resp == nil || !resp.Idempotent {
		t.Fatalf("expected idempotent approve on completed, got handled=%v err=%v", handled, err)
	}
}

func TestResolveApprovalIdempotency_ApproveRejectedConflict(t *testing.T) {
	req := &types.SignRequest{ID: "req-1", Status: types.StatusRejected}
	_, handled, err := resolveApprovalIdempotency(req, true)
	if !handled || err == nil || !errors.Is(err, ErrApprovalConflict) {
		t.Fatalf("expected conflict, handled=%v err=%v", handled, err)
	}
}

func TestProcessBatchApproval_DedupesIDs(t *testing.T) {
	ctx := context.Background()
	f := newSignServiceFixture(t)
	svc := f.build(t)

	req := &types.SignRequest{
		ID:        "req-reject",
		ChainType: types.ChainTypeEVM,
		Status:    types.StatusAuthorizing,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := f.requestRepo.Create(ctx, req); err != nil {
		t.Fatalf("seed: %v", err)
	}

	batch, err := svc.ProcessBatchApproval(ctx, []types.SignRequestID{"req-reject", "req-reject"}, &ApprovalRequest{
		Approved:   false,
		ApprovedBy: "admin",
	})
	if err != nil {
		t.Fatalf("ProcessBatchApproval: %v", err)
	}
	if batch.Summary.Total != 1 {
		t.Fatalf("total=%d want 1", batch.Summary.Total)
	}
	if batch.Summary.Succeeded != 1 {
		t.Fatalf("succeeded=%d", batch.Summary.Succeeded)
	}

	// Replay reject via batch — idempotent success.
	batch2, err := svc.ProcessBatchApproval(ctx, []types.SignRequestID{"req-reject"}, &ApprovalRequest{
		Approved:   false,
		ApprovedBy: "admin",
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if batch2.Summary.Idempotent != 1 {
		t.Fatalf("idempotent=%d want 1", batch2.Summary.Idempotent)
	}
}

func TestProcessBatchApproval_EmptyIDs(t *testing.T) {
	f := newSignServiceFixture(t)
	svc := f.build(t)
	_, err := svc.ProcessBatchApproval(context.Background(), nil, &ApprovalRequest{Approved: true, ApprovedBy: "admin"})
	if err == nil {
		t.Fatal("expected error for empty ids")
	}
}
