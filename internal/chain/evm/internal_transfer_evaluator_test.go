package evm

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

const (
	testSenderAddr    = "0x1234567890abcdef1234567890abcdef12345678"
	testRecipientAddr = "0xabcdef1234567890abcdef1234567890abcdef12"
)

type mockOwnershipRepo struct {
	ownerships map[string]*types.SignerOwnership
}

func newMockOwnershipRepo() *mockOwnershipRepo {
	return &mockOwnershipRepo{
		ownerships: make(map[string]*types.SignerOwnership),
	}
}

func (m *mockOwnershipRepo) Upsert(ctx context.Context, ownership *types.SignerOwnership) error {
	m.ownerships[ownership.SignerAddress] = ownership
	return nil
}

func (m *mockOwnershipRepo) GetBySignerAddress(ctx context.Context, address string) (*types.SignerOwnership, error) {
	ownership, exists := m.ownerships[address]
	if !exists {
		return nil, types.ErrNotFound
	}
	return ownership, nil
}

func (m *mockOwnershipRepo) CountByOwner(ctx context.Context, ownerID string) (int64, error) {
	var count int64
	for _, ownership := range m.ownerships {
		if ownership.OwnerID == ownerID {
			count++
		}
	}
	return count, nil
}

func (m *mockOwnershipRepo) CountByOwnerAndType(ctx context.Context, ownerID string, signerType types.SignerType) (int64, error) {
	var count int64
	for _, ownership := range m.ownerships {
		if ownership.OwnerID == ownerID {
			count++
		}
	}
	return count, nil
}

func (m *mockOwnershipRepo) Delete(ctx context.Context, signerAddress string) error {
	delete(m.ownerships, signerAddress)
	return nil
}

func (m *mockOwnershipRepo) Get(ctx context.Context, signerAddress string) (*types.SignerOwnership, error) {
	return m.GetBySignerAddress(ctx, signerAddress)
}

func (m *mockOwnershipRepo) GetBoth(ctx context.Context, senderAddress, recipientAddress string) (*types.SignerOwnership, *types.SignerOwnership, error) {
	sender, err1 := m.GetBySignerAddress(ctx, senderAddress)
	recipient, err2 := m.GetBySignerAddress(ctx, recipientAddress)
	if err1 != nil && err1 != types.ErrNotFound {
		return nil, nil, err1
	}
	if err2 != nil && err2 != types.ErrNotFound {
		return nil, nil, err2
	}
	return sender, recipient, nil
}

func (m *mockOwnershipRepo) GetByOwner(ctx context.Context, ownerID string) ([]*types.SignerOwnership, error) {
	return m.GetByOwnerID(ctx, ownerID)
}

func (m *mockOwnershipRepo) GetByStatus(_ context.Context, status types.SignerOwnershipStatus) ([]*types.SignerOwnership, error) {
	var result []*types.SignerOwnership
	for _, ownership := range m.ownerships {
		if ownership.Status == status {
			result = append(result, ownership)
		}
	}
	return result, nil
}

func (m *mockOwnershipRepo) UpdateOwner(ctx context.Context, signerAddress, newOwnerID string) error {
	ownership, exists := m.ownerships[signerAddress]
	if !exists {
		return types.ErrNotFound
	}
	ownership.OwnerID = newOwnerID
	return nil
}

func (m *mockOwnershipRepo) GetByOwnerID(ctx context.Context, ownerID string) ([]*types.SignerOwnership, error) {
	var result []*types.SignerOwnership
	for _, ownership := range m.ownerships {
		if ownership.OwnerID == ownerID {
			result = append(result, ownership)
		}
	}
	return result, nil
}

func TestNewInternalTransferEvaluator_NilRepo(t *testing.T) {
		eval, err := NewInternalTransferEvaluator(nil)
		assert.NotNil(t, eval)
		assert.NoError(t, err)
	}

func TestETHTransfer_SameOwner(t *testing.T) {
	// Setup: two signers owned by same owner
	repo := newMockOwnershipRepo()
	ownerID := "api-key-admin"

	_ = repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testSenderAddr,
		OwnerID:       ownerID,
		Status:        types.SignerOwnershipActive,
	})
	_ = repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testRecipientAddr,
		OwnerID:       ownerID,
		Status:        types.SignerOwnershipActive,
	})

	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	// ETH transfer (no calldata)
	recipient := testRecipientAddr
	rule := &types.Rule{
		Mode:   types.RuleModeWhitelist,
		Config: json.RawMessage(`{}`),
	}
	req := &types.SignRequest{
		SignerAddress: testSenderAddr,
		SignType:      "transaction",
	}
	parsed := &types.ParsedPayload{
		Recipient: &recipient,
		RawData:   nil, // ETH transfer has no calldata
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.True(t, matched)
	assert.Contains(t, reason, "internal transfer")
	// SECURITY: reason should NOT contain owner_id (info disclosure fix)
	assert.NotContains(t, reason, ownerID)
}

func TestETHTransfer_DifferentOwner(t *testing.T) {
	// Setup: two signers owned by different owners
	repo := newMockOwnershipRepo()

	_ = repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testSenderAddr,
		OwnerID:       "api-key-admin",
		Status:        types.SignerOwnershipActive,
	})
	_ = repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testRecipientAddr,
		OwnerID:       "api-key-agent", // Different owner
		Status:        types.SignerOwnershipActive,
	})

	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	recipient := testRecipientAddr
	rule := &types.Rule{
		Mode:   types.RuleModeWhitelist,
		Config: json.RawMessage(`{}`),
	}
	req := &types.SignRequest{
		SignerAddress: testSenderAddr,
		SignType:      "transaction",
	}
	parsed := &types.ParsedPayload{
		Recipient: &recipient,
		RawData:   nil,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.False(t, matched)
	assert.Empty(t, reason)
}

func TestETHTransfer_NoOwnership(t *testing.T) {
	// Setup: empty repo (no ownership records)
	repo := newMockOwnershipRepo()

	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	recipient := testRecipientAddr
	rule := &types.Rule{
		Mode:   types.RuleModeWhitelist,
		Config: json.RawMessage(`{}`),
	}
	req := &types.SignRequest{
		SignerAddress: testSenderAddr,
		SignType:      "transaction",
	}
	parsed := &types.ParsedPayload{
		Recipient: &recipient,
		RawData:   nil,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.False(t, matched)
	assert.Empty(t, reason)
}

func TestETHTransfer_NilRecipient(t *testing.T) {
	repo := newMockOwnershipRepo()
	_ = repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testSenderAddr,
		OwnerID:       "api-key-admin",
		Status:        types.SignerOwnershipActive,
	})

	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	rule := &types.Rule{
		Mode:   types.RuleModeWhitelist,
		Config: json.RawMessage(`{}`),
	}
	req := &types.SignRequest{
		SignerAddress: testSenderAddr,
		SignType:      "transaction",
	}
	parsed := &types.ParsedPayload{
		Recipient: nil, // No recipient
		RawData:   nil,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.False(t, matched)
	assert.Empty(t, reason)
}
