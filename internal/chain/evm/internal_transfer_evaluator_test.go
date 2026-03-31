package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// mockOwnershipRepo is a mock implementation of SignerOwnershipRepository for testing
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

func (m *mockOwnershipRepo) Get(ctx context.Context, signerAddress string) (*types.SignerOwnership, error) {
	// Normalize address for lookup
	for addr, ownership := range m.ownerships {
		if equalAddress(addr, signerAddress) {
			return ownership, nil
		}
	}
	return nil, types.ErrNotFound
}

func (m *mockOwnershipRepo) GetByOwner(ctx context.Context, ownerID string) ([]*types.SignerOwnership, error) {
	var result []*types.SignerOwnership
	for _, ownership := range m.ownerships {
		if ownership.OwnerID == ownerID {
			result = append(result, ownership)
		}
	}
	return result, nil
}

func (m *mockOwnershipRepo) Delete(ctx context.Context, signerAddress string) error {
	delete(m.ownerships, signerAddress)
	return nil
}

func (m *mockOwnershipRepo) UpdateOwner(ctx context.Context, signerAddress, newOwnerID string) error {
	for addr, ownership := range m.ownerships {
		if equalAddress(addr, signerAddress) {
			ownership.OwnerID = newOwnerID
			return nil
		}
	}
	return types.ErrNotFound
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

// CountByOwnerAndType counts signers by owner and type (stub for tests)
func (m *mockOwnershipRepo) CountByOwnerAndType(ctx context.Context, ownerID string, signerType types.SignerType) (int64, error) {
	var count int64
	for _, ownership := range m.ownerships {
		if ownership.OwnerID == ownerID && ownership.SignerType == signerType {
			count++
		}
	}
	return count, nil
}

// GetBoth atomically fetches ownership records for two addresses.
// This prevents TOCTOU race conditions in tests.
func (m *mockOwnershipRepo) GetBoth(ctx context.Context, senderAddress, recipientAddress string) (*types.SignerOwnership, *types.SignerOwnership, error) {
	var senderOwnership, recipientOwnership *types.SignerOwnership

	// Normalize addresses for lookup
	senderLower := strings.ToLower(senderAddress)
	recipientLower := strings.ToLower(recipientAddress)

	for addr, ownership := range m.ownerships {
		addrLower := strings.ToLower(addr)
		if addrLower == senderLower {
			senderOwnership = ownership
		} else if addrLower == recipientLower {
			recipientOwnership = ownership
		}
	}

	return senderOwnership, recipientOwnership, nil
}

// Helper to compare addresses case-insensitively
func equalAddress(a, b string) bool {
	// Simple case-insensitive comparison for Ethereum addresses
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32 // to lowercase
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32 // to lowercase
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// Valid hex addresses for testing
const (
	testSenderAddr    = "0x1111111111111111111111111111111111111111"
	testRecipientAddr = "0x2222222222222222222222222222222222222222"
	testFromAddr      = "0x3333333333333333333333333333333333333333"
	testToAddr        = "0x4444444444444444444444444444444444444444"
	testExternalAddr  = "0x5555555555555555555555555555555555555555"
	testTokenContract = "0x6666666666666666666666666666666666666666"
)

func TestInternalTransferEvaluator_Type(t *testing.T) {
	eval, err := NewInternalTransferEvaluator(newMockOwnershipRepo())
	require.NoError(t, err)
	assert.Equal(t, types.RuleTypeEVMInternalTransfer, eval.Type())
}

func TestInternalTransferEvaluator_NewEvaluator_NilRepo(t *testing.T) {
	// Nil repo is allowed for validation-only scenarios
	eval, err := NewInternalTransferEvaluator(nil)
	require.NoError(t, err)
	require.NotNil(t, eval)

	// But evaluation should fail when repo is nil
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
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	assert.Error(t, err)
	assert.False(t, matched)
	assert.Empty(t, reason)
	assert.Contains(t, err.Error(), "ownership repository not configured")
}

func TestETHTransfer_SameOwner(t *testing.T) {
	// Setup: two signers owned by same owner
	repo := newMockOwnershipRepo()
	ownerID := "api-key-admin"

	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testSenderAddr,
		OwnerID:       ownerID,
		Status:        types.SignerOwnershipActive,
	})
	repo.Upsert(context.Background(), &types.SignerOwnership{
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

	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testSenderAddr,
		OwnerID:       "api-key-admin",
		Status:        types.SignerOwnershipActive,
	})
	repo.Upsert(context.Background(), &types.SignerOwnership{
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
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.False(t, matched) // Neutral - different owner
	assert.Empty(t, reason)
}

func TestERC20Transfer_SameOwner(t *testing.T) {
	// Setup: two signers owned by same owner
	repo := newMockOwnershipRepo()
	ownerID := "api-key-admin"

	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testSenderAddr,
		OwnerID:       ownerID,
		Status:        types.SignerOwnershipActive,
	})
	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testRecipientAddr,
		OwnerID:       ownerID,
		Status:        types.SignerOwnershipActive,
	})

	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	// ERC20 transfer(address,uint256) calldata
	// selector: 0xa9059cbb
	// recipient: 32-byte padded address at offset 4
	recipientHex := "000000000000000000000000" + testRecipientAddr[2:] // Remove 0x and pad to 32 bytes
	calldata, err := hex.DecodeString("a9059cbb" + recipientHex + "00000000000000000000000000000000000000000000000000000000000003e8")
	require.NoError(t, err, "calldata should be valid hex")

	recipient := testTokenContract // Token contract, not the actual recipient
	methodSig := "0xa9059cbb"
	rule := &types.Rule{
		Mode:   types.RuleModeWhitelist,
		Config: json.RawMessage(`{}`),
	}
	req := &types.SignRequest{
		SignerAddress: testSenderAddr,
		SignType:      "transaction",
	}
	parsed := &types.ParsedPayload{
		Recipient: &recipient, // Token contract address
		MethodSig: &methodSig,
		RawData:   calldata,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.True(t, matched)
	assert.Contains(t, reason, "internal transfer")
}

func TestERC721SafeTransfer_SameOwner(t *testing.T) {
	// Setup: two signers owned by same owner
	repo := newMockOwnershipRepo()
	ownerID := "api-key-admin"

	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testSenderAddr,
		OwnerID:       ownerID,
		Status:        types.SignerOwnershipActive,
	})
	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testToAddr,
		OwnerID:       ownerID,
		Status:        types.SignerOwnershipActive,
	})

	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	// ERC721 safeTransferFrom(address,address,uint256) calldata
	// selector: 0x42842e0e
	// from: 32-byte padded address at offset 4
	// to (recipient): 32-byte padded address at offset 36
	calldata, err := hex.DecodeString(
		"42842e0e" + // selector
			"000000000000000000000000" + testSenderAddr[2:] + // from address
			"000000000000000000000000" + testToAddr[2:] + // to address
			"0000000000000000000000000000000000000000000000000000000000000001", // tokenId
	)
	require.NoError(t, err, "calldata should be valid hex")

	recipient := testTokenContract
	methodSig := "0x42842e0e"
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
		MethodSig: &methodSig,
		RawData:   calldata,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.True(t, matched)
	assert.Contains(t, reason, "internal transfer")
}

func TestERC1155BatchTransfer_SameOwner(t *testing.T) {
	// Setup: two signers owned by same owner
	repo := newMockOwnershipRepo()
	ownerID := "api-key-admin"

	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testSenderAddr,
		OwnerID:       ownerID,
		Status:        types.SignerOwnershipActive,
	})
	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testToAddr,
		OwnerID:       ownerID,
		Status:        types.SignerOwnershipActive,
	})

	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	// ERC1155 safeBatchTransferFrom(address,address,uint256[],uint256[],bytes) calldata
	// selector: 0x2eb2c2d6
	// from: at offset 4
	// to (recipient): at offset 36
	calldata, err := hex.DecodeString(
		"2eb2c2d6" + // selector
			"000000000000000000000000" + testSenderAddr[2:] + // from address
			"000000000000000000000000" + testToAddr[2:], // to address (just the minimum for parsing)
	)
	require.NoError(t, err, "calldata should be valid hex")

	recipient := testTokenContract
	methodSig := "0x2eb2c2d6"
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
		MethodSig: &methodSig,
		RawData:   calldata,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.True(t, matched)
	assert.Contains(t, reason, "internal transfer")
}

func TestTransfer_ToExternalAddress(t *testing.T) {
	// Setup: sender is managed, recipient is NOT in ownership DB
	repo := newMockOwnershipRepo()

	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testSenderAddr,
		OwnerID:       "api-key-admin",
		Status:        types.SignerOwnershipActive,
	})
	// External address NOT in DB

	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	recipient := testExternalAddr
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
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.False(t, matched) // Neutral - external address
	assert.Empty(t, reason)
}

func TestTransfer_ToPendingSigner(t *testing.T) {
	// Setup: recipient is pending_approval (not active)
	repo := newMockOwnershipRepo()

	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testSenderAddr,
		OwnerID:       "api-key-admin",
		Status:        types.SignerOwnershipActive,
	})
	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testRecipientAddr,
		OwnerID:       "api-key-admin",
		Status:        types.SignerOwnershipPendingApproval, // Pending!
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
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.False(t, matched) // Neutral - pending signer
	assert.Empty(t, reason)
}

func TestNonTransaction_Neutral(t *testing.T) {
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
		SignType:      "typed_data", // Not transaction
	}
	parsed := &types.ParsedPayload{
		Recipient: &recipient,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.False(t, matched) // Neutral
	assert.Empty(t, reason)
}

func TestMalformedCalldata_Neutral(t *testing.T) {
	// Setup: calldata is too short to contain a valid address
	repo := newMockOwnershipRepo()

	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testSenderAddr,
		OwnerID:       "api-key-admin",
		Status:        types.SignerOwnershipActive,
	})
	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testRecipientAddr,
		OwnerID:       "api-key-admin",
		Status:        types.SignerOwnershipActive,
	})

	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	// Truncated calldata (only selector, no address)
	calldata, _ := hex.DecodeString("a9059cbb") // Just 4 bytes

	recipient := testTokenContract
	methodSig := "0xa9059cbb"
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
		MethodSig: &methodSig,
		RawData:   calldata,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	// With truncated calldata, it should fall back to parsed.Recipient (token contract)
	// which is not in ownership DB, so neutral
	assert.False(t, matched)
	assert.Empty(t, reason)
}

func TestTransfer_DifferentOwner_ERC20(t *testing.T) {
	// ERC20 transfer between different owners
	repo := newMockOwnershipRepo()

	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testSenderAddr,
		OwnerID:       "api-key-admin",
		Status:        types.SignerOwnershipActive,
	})
	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testRecipientAddr,
		OwnerID:       "api-key-agent", // Different owner
		Status:        types.SignerOwnershipActive,
	})

	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	// ERC20 transfer calldata
	recipientHex := "000000000000000000000000" + testRecipientAddr[2:]
	calldata, err := hex.DecodeString("a9059cbb" + recipientHex + "00000000000000000000000000000000000000000000000000000000000003e8")
	require.NoError(t, err, "calldata should be valid hex")

	recipient := testTokenContract
	methodSig := "0xa9059cbb"
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
		MethodSig: &methodSig,
		RawData:   calldata,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.False(t, matched) // Neutral - different owner
	assert.Empty(t, reason)
}

func TestTransferFrom_SameOwner(t *testing.T) {
	// ERC20/ERC721 transferFrom(address,address,uint256)
	// The actual recipient is the second address parameter
	repo := newMockOwnershipRepo()
	ownerID := "api-key-admin"

	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testSenderAddr,
		OwnerID:       ownerID,
		Status:        types.SignerOwnershipActive,
	})
	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testToAddr,
		OwnerID:       ownerID,
		Status:        types.SignerOwnershipActive,
	})

	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	// transferFrom(address,address,uint256) calldata
	// selector: 0x23b872dd
	// from: at offset 4
	// to (recipient): at offset 36
	calldata, err := hex.DecodeString(
		"23b872dd"+
			"000000000000000000000000"+testFromAddr[2:]+
			"000000000000000000000000"+testToAddr[2:]+
			"0000000000000000000000000000000000000000000000000000000000000001",
	)
	require.NoError(t, err, "calldata should be valid hex")

	recipient := testTokenContract
	methodSig := "0x23b872dd"
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
		MethodSig: &methodSig,
		RawData:   calldata,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.True(t, matched)
	assert.Contains(t, reason, "internal transfer")
}

func TestNilParsedPayload_Neutral(t *testing.T) {
	repo := newMockOwnershipRepo()
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

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.False(t, matched)
	assert.Empty(t, reason)
}

func TestNilRecipient_Neutral(t *testing.T) {
	repo := newMockOwnershipRepo()
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
		Recipient: nil,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.False(t, matched)
	assert.Empty(t, reason)
}

func TestInvalidConfig_Error(t *testing.T) {
	repo := newMockOwnershipRepo()
	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	recipient := testRecipientAddr
	rule := &types.Rule{
		Mode:   types.RuleModeWhitelist,
		Config: json.RawMessage(`{invalid json}`),
	}
	req := &types.SignRequest{
		SignerAddress: testSenderAddr,
		SignType:      "transaction",
	}
	parsed := &types.ParsedPayload{
		Recipient: &recipient,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	assert.Error(t, err)
	assert.False(t, matched)
	assert.Empty(t, reason)
	assert.Contains(t, err.Error(), "invalid internal transfer config")
}

func TestUnsupportedMatchMode_Error(t *testing.T) {
	repo := newMockOwnershipRepo()
	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	recipient := testRecipientAddr
	rule := &types.Rule{
		Mode:   types.RuleModeWhitelist,
		Config: json.RawMessage(`{"match_mode":"user_id"}`),
	}
	req := &types.SignRequest{
		SignerAddress: testSenderAddr,
		SignType:      "transaction",
	}
	parsed := &types.ParsedPayload{
		Recipient: &recipient,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	assert.Error(t, err)
	assert.False(t, matched)
	assert.Empty(t, reason)
	assert.Contains(t, err.Error(), "unsupported match_mode")
}

func TestTransfer_SenderNotInDB_Neutral(t *testing.T) {
	// Sender is not in ownership DB (shouldn't happen in normal operation)
	repo := newMockOwnershipRepo()

	// Only recipient in DB
	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testRecipientAddr,
		OwnerID:       "api-key-admin",
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
		SignerAddress: testSenderAddr, // Not in DB
		SignType:      "transaction",
	}
	parsed := &types.ParsedPayload{
		Recipient: &recipient,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.False(t, matched) // Neutral - sender not in DB
	assert.Empty(t, reason)
}

func TestExtractRecipientFromCalldata_AllSelectors(t *testing.T) {
	repo := newMockOwnershipRepo()
	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	// Use a valid Ethereum address (40 hex chars)
	testAddr := "0x1234567890abcdef1234567890abcdef12345678"
	testAddrPadded := "000000000000000000000000" + testAddr[2:]

	tests := []struct {
		name     string
		selector string
		offset   int
	}{
		{"ERC20 transfer", "0xa9059cbb", 4},
		{"ERC20/721 transferFrom", "0x23b872dd", 36},
		{"ERC721 safeTransferFrom", "0x42842e0e", 36},
		{"ERC721 safeTransferFrom with bytes", "0xb88d4fde", 36},
		{"ERC1155 safeTransferFrom", "0xf242432a", 36},
		{"ERC1155 safeBatchTransferFrom", "0x2eb2c2d6", 36},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build calldata with address at the expected offset
			// For offset 4 (ERC20 transfer): just selector + address
			// For offset 36 (transferFrom): selector + 32 bytes padding + address

			var calldataHex string
			if tt.offset == 4 {
				// ERC20 transfer(address,uint256) - recipient right after selector
				calldataHex = tt.selector[2:] + testAddrPadded + "00000000000000000000000000000000000000000000000000000000000003e8"
			} else {
				// transferFrom variants - need 32 bytes padding before recipient
				// selector + from_address (32 bytes) + to_address (32 bytes)
				calldataHex = tt.selector[2:] +
					"0000000000000000000000000000000000000000000000000000000000000000" + // dummy from address
					testAddrPadded +
					"00000000000000000000000000000000000000000000000000000000000003e8"
			}

			calldata, err := hex.DecodeString(calldataHex)
			require.NoError(t, err, "calldata should be valid hex")
			methodSig := tt.selector

			parsed := &types.ParsedPayload{
				MethodSig: &methodSig,
				RawData:   calldata,
			}

			result := eval.extractRecipientFromCalldata(parsed)
			// Compare case-insensitively - convert both to lowercase
			assert.Equal(t, strings.ToLower(testAddr), strings.ToLower(result), "extracted address should match")
		})
	}
}

func TestExtractRecipientFromCalldata_ZeroAddress(t *testing.T) {
	// SECURITY: Zero address should return empty string (prevent burns/errors)
	repo := newMockOwnershipRepo()
	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	// Zero address padded to 32 bytes
	zeroAddrPadded := "0000000000000000000000000000000000000000000000000000000000000000"

	// ERC20 transfer to zero address
	calldataHex := "a9059cbb" + zeroAddrPadded + "00000000000000000000000000000000000000000000000000000000000003e8"
	calldata, err := hex.DecodeString(calldataHex)
	require.NoError(t, err, "calldata should be valid hex")

	selector := "0xa9059cbb"
	parsed := &types.ParsedPayload{
		MethodSig: &selector,
		RawData:   calldata,
	}

	result := eval.extractRecipientFromCalldata(parsed)
	// SECURITY: Zero address should return empty string, not the zero address
	assert.Empty(t, result, "zero address should return empty string")
}

func TestERC20Transfer_ToZeroAddress_Neutral(t *testing.T) {
	// SECURITY: Transfers to zero address should be neutral (not auto-approved)
	repo := newMockOwnershipRepo()
	ownerID := "api-key-admin"

	repo.Upsert(context.Background(), &types.SignerOwnership{
		SignerAddress: testSenderAddr,
		OwnerID:       ownerID,
		Status:        types.SignerOwnershipActive,
	})

	eval, err := NewInternalTransferEvaluator(repo)
	require.NoError(t, err)

	// ERC20 transfer to zero address (burn)
	zeroAddrPadded := "0000000000000000000000000000000000000000000000000000000000000000"
	calldata, err := hex.DecodeString("a9059cbb" + zeroAddrPadded + "00000000000000000000000000000000000000000000000000000000000003e8")
	require.NoError(t, err, "calldata should be valid hex")

	recipient := testTokenContract
	methodSig := "0xa9059cbb"
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
		MethodSig: &methodSig,
		RawData:   calldata,
	}

	matched, reason, err := eval.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	// SECURITY: Zero address transfer should be neutral, not matched
	assert.False(t, matched)
	assert.Empty(t, reason)
}
