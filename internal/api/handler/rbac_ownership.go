package handler

import (
	"context"
	"fmt"
	"regexp"

	"github.com/lib/pq"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// appliedToKeyIDPattern validates API key ID format (SA-6).
var appliedToKeyIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// RuleOwnershipParams contains the RBAC-determined ownership fields for a rule.
type RuleOwnershipParams struct {
	Owner     string
	AppliedTo pq.StringArray
	Status    types.RuleStatus
}

// DetermineRuleOwnership computes owner, applied_to, and status for a new rule
// based on the caller's API key role. This is the single source of truth for
// RBAC ownership logic across rule creation, template instantiation, and preset apply.
//
// Logic:
//   - Owner = apiKey.ID always
//   - Admin + requestedAppliedTo provided → use it (validate key IDs via apiKeyRepo)
//   - Admin + no requestedAppliedTo → ["*"]
//   - Non-admin → force ["self"]
//   - Agent + whitelist + requireApproval → pending_approval
//   - Otherwise → active
func DetermineRuleOwnership(
	ctx context.Context,
	apiKey *types.APIKey,
	requestedAppliedTo []string,
	ruleMode types.RuleMode,
	requireApproval bool,
	apiKeyRepo storage.APIKeyRepository,
) (*RuleOwnershipParams, error) {
	if apiKey == nil {
		return nil, fmt.Errorf("API key is required")
	}

	result := &RuleOwnershipParams{
		Owner:  apiKey.ID,
		Status: types.RuleStatusActive,
	}

	// Determine applied_to based on role
	if apiKey.IsAdmin() {
		if len(requestedAppliedTo) > 0 {
			result.AppliedTo = pq.StringArray(requestedAppliedTo)
		} else {
			result.AppliedTo = pq.StringArray{"*"}
		}
		// Validate non-wildcard key IDs exist (SA-6)
		if apiKeyRepo != nil {
			for _, keyID := range result.AppliedTo {
				if keyID == "*" || keyID == "self" {
					continue
				}
				if !appliedToKeyIDPattern.MatchString(keyID) {
					return nil, fmt.Errorf("invalid applied_to key ID format: %q", keyID)
				}
				if _, err := apiKeyRepo.Get(ctx, keyID); err != nil {
					if types.IsNotFound(err) {
						return nil, fmt.Errorf("applied_to key ID not found: %q", keyID)
					}
					return nil, fmt.Errorf("failed to validate applied_to key ID %q: %w", keyID, err)
				}
			}
		}
	} else {
		// Non-admin: force applied_to = ["self"]
		result.AppliedTo = pq.StringArray{"self"}
	}

	// Determine status based on role and config
	if apiKey.IsAgent() && requireApproval && ruleMode == types.RuleModeWhitelist {
		result.Status = types.RuleStatusPendingApproval
	}
	// Agent blocklist rules are always active immediately (self-restriction is safe)

	return result, nil
}
