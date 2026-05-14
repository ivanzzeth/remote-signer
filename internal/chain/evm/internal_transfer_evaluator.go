package evm

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// InternalTransferEvaluator checks if a transfer is between signers owned by the same owner.
// This enables multi-tenant custodial signing where each tenant's signers are isolated.
// It supports ETH transfers AND token transfers (ERC20/721/1155).
type InternalTransferEvaluator struct {
	ownershipRepo storage.SignerOwnershipRepository
}

// InternalTransferConfig defines the configuration for internal transfer rules.
type InternalTransferConfig struct {
	MatchMode string `json:"match_mode,omitempty"` // "owner_id" (default) | "user_id" (future)
}

// NewInternalTransferEvaluator creates a new internal transfer evaluator.
// ownershipRepo can be nil for config validation scenarios (only config parsing will work).
func NewInternalTransferEvaluator(ownershipRepo storage.SignerOwnershipRepository) (*InternalTransferEvaluator, error) {
	// Allow nil repo for validation-only scenarios
	return &InternalTransferEvaluator{ownershipRepo: ownershipRepo}, nil
}

// Type returns the rule type this evaluator handles.
func (e *InternalTransferEvaluator) Type() types.RuleType {
	return types.RuleTypeEVMInternalTransfer
}

// Evaluate checks if the transfer is between signers owned by the same owner.
// Returns:
//   - (true, reason, nil) if recipient is a signer with the same owner (match)
//   - (false, "", nil) for neutral cases (non-transaction, external address, different owner, etc.)
//   - (false, "", error) for unexpected errors
func (e *InternalTransferEvaluator) Evaluate(ctx context.Context, r *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	// Only applies to transaction sign type
	if req.SignType != "transaction" {
		return false, "", nil
	}

	// Must have a recipient (parsed.To)
	if parsed == nil || parsed.Recipient == nil {
		return false, "", nil
	}

	// Parse config (optional - defaults to "owner_id")
	var config InternalTransferConfig
	if len(r.Config) > 0 {
		if err := json.Unmarshal(r.Config, &config); err != nil {
			return false, "", fmt.Errorf("invalid internal transfer config: %w", err)
		}
	}
	if config.MatchMode == "" {
		config.MatchMode = "owner_id"
	}

	// Currently only "owner_id" mode is supported
	if config.MatchMode != "owner_id" {
		return false, "", fmt.Errorf("unsupported match_mode: %s (only 'owner_id' is currently supported)", config.MatchMode)
	}

	// Need ownership repo for runtime lookups
	if e.ownershipRepo == nil {
		return false, "", fmt.Errorf("ownership repository not configured")
	}

	// Extract the actual recipient address from calldata if it's a token transfer
	recipientAddress := e.extractRecipientFromCalldata(parsed)
	if recipientAddress == "" {
		// Fallback to parsed.Recipient for ETH transfers
		recipientAddress = *parsed.Recipient
	}

	// SECURITY: Normalize addresses to lowercase for consistent lookup
	recipientAddress = strings.ToLower(recipientAddress)
	senderAddress := strings.ToLower(req.SignerAddress)

	// SECURITY: Use atomic GetBoth to prevent TOCTOU race condition
	// This fetches both ownership records in a single query
	senderOwnership, recipientOwnership, err := e.ownershipRepo.GetBoth(ctx, senderAddress, recipientAddress)
	if err != nil {
		return false, "", fmt.Errorf("failed to get ownership records: %w", err)
	}

	// Check recipient ownership
	if recipientOwnership == nil {
		// Recipient is not a managed signer - neutral
		return false, "", nil
	}

	// Check recipient status - must be active
	if recipientOwnership.Status != types.SignerOwnershipActive {
		// Recipient is pending or other status - neutral (security measure)
		return false, "", nil
	}

	// Check sender ownership
	if senderOwnership == nil {
		// Sender is not in ownership DB - neutral (shouldn't happen in normal operation)
		return false, "", nil
	}

	// Match: same owner
	// SECURITY: Do not include owner_id in reason to prevent information disclosure
	if senderOwnership.OwnerID == recipientOwnership.OwnerID {
		return true, "internal transfer: same owner", nil
	}

	// Different owners - neutral
	return false, "", nil
}

// Compile-time check
var _ rule.RuleEvaluator = (*InternalTransferEvaluator)(nil)

// Token transfer selectors and their recipient offset (in bytes from calldata start)
var transferSelectors = map[string]int{
	// ERC20 transfer(address,uint256) - recipient at bytes 4-36
	"0xa9059cbb": 4,
	// ERC20/ERC721 transferFrom(address,address,uint256) - recipient at bytes 36-68
	"0x23b872dd": 36,
	// ERC721 safeTransferFrom(address,address,uint256) - recipient at bytes 36-68
	"0x42842e0e": 36,
	// ERC721 safeTransferFrom(address,address,uint256,bytes) - recipient at bytes 36-68
	"0xb88d4fde": 36,
	// ERC1155 safeTransferFrom(address,address,uint256,uint256,bytes) - recipient at bytes 36-68
	"0xf242432a": 36,
	// ERC1155 safeBatchTransferFrom(address,address,uint256[],uint256[],bytes) - recipient at bytes 36-68
	"0x2eb2c2d6": 36,
}

// zeroAddress is the zero address (20 bytes of zeros)
var zeroAddress = make([]byte, 20)

// extractRecipientFromCalldata parses calldata for known token transfer selectors
// and extracts the actual recipient address.
// Returns empty string if not a known token transfer or calldata is malformed.
func (e *InternalTransferEvaluator) extractRecipientFromCalldata(parsed *types.ParsedPayload) string {
	// Need method selector and raw calldata
	if parsed.MethodSig == nil || parsed.RawData == nil {
		return ""
	}

	selector := strings.ToLower(*parsed.MethodSig)
	offset, isTokenTransfer := transferSelectors[selector]
	if !isTokenTransfer {
		return ""
	}

	// SECURITY: Check for integer overflow
	// offset is guaranteed to be small (4 or 36), but check anyway
	requiredLen := offset + 32
	if requiredLen < offset { // Overflow check
		return ""
	}

	// Need at least offset + 32 bytes for the address
	if len(parsed.RawData) < requiredLen {
		// Malformed calldata - neutral
		return ""
	}

	// Extract 20 bytes address from the 32-byte word
	// Solidity pads address to 32 bytes, address is in the last 20 bytes
	addressBytes := parsed.RawData[offset+12 : offset+32]

	// SECURITY: Validate extracted address is not zero address
	// Transfers to zero address are typically burns or errors
	if bytes.Equal(addressBytes, zeroAddress) {
		return ""
	}

	return "0x" + hex.EncodeToString(addressBytes)
}
