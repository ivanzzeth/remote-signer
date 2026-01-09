package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// AddressListEvaluator checks if tx.To is in the address list
// Behavior depends on rule mode:
// - Whitelist mode: returns true if address IS in list (allow)
// - Blocklist mode: returns true if address IS in list (block)
type AddressListEvaluator struct{}

// NewAddressListEvaluator creates a new address list evaluator
func NewAddressListEvaluator() (*AddressListEvaluator, error) {
	return &AddressListEvaluator{}, nil
}

// Type returns the rule type this evaluator handles
func (e *AddressListEvaluator) Type() types.RuleType {
	return types.RuleTypeEVMAddressList
}

// Evaluate checks if the recipient address is in the list
// For whitelist mode: returns true if address IS in list (allow transaction)
// For blocklist mode: returns true if address IS in list (block transaction)
func (e *AddressListEvaluator) Evaluate(ctx context.Context, r *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	if parsed == nil || parsed.Recipient == nil {
		return false, "", nil
	}

	var config AddressListConfig
	if err := json.Unmarshal(r.Config, &config); err != nil {
		return false, "", fmt.Errorf("invalid address list config: %w", err)
	}

	recipientLower := strings.ToLower(*parsed.Recipient)
	for _, addr := range config.Addresses {
		if strings.ToLower(addr) == recipientLower {
			if r.Mode == types.RuleModeBlocklist {
				return true, fmt.Sprintf("recipient %s in blocklist", *parsed.Recipient), nil
			}
			return true, fmt.Sprintf("recipient %s in whitelist", *parsed.Recipient), nil
		}
	}

	return false, "", nil
}

// Compile-time check
var _ rule.RuleEvaluator = (*AddressListEvaluator)(nil)

// ContractMethodEvaluator checks if the method selector matches allowed methods for a contract
type ContractMethodEvaluator struct{}

// NewContractMethodEvaluator creates a new contract method evaluator
func NewContractMethodEvaluator() (*ContractMethodEvaluator, error) {
	return &ContractMethodEvaluator{}, nil
}

// Type returns the rule type this evaluator handles
func (e *ContractMethodEvaluator) Type() types.RuleType {
	return types.RuleTypeEVMContractMethod
}

// Evaluate checks if the contract and method selector are allowed
func (e *ContractMethodEvaluator) Evaluate(ctx context.Context, r *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	if parsed == nil || parsed.Contract == nil || parsed.MethodSig == nil {
		return false, "", nil
	}

	var config ContractMethodConfig
	if err := json.Unmarshal(r.Config, &config); err != nil {
		return false, "", fmt.Errorf("invalid contract method config: %w", err)
	}

	// Check if contract matches
	if strings.ToLower(config.Contract) != strings.ToLower(*parsed.Contract) {
		return false, "", nil
	}

	// Check if method selector is allowed
	methodSigLower := strings.ToLower(*parsed.MethodSig)
	for _, allowedSig := range config.MethodSigs {
		if strings.ToLower(allowedSig) == methodSigLower {
			return true, fmt.Sprintf("method %s on contract %s allowed", *parsed.MethodSig, *parsed.Contract), nil
		}
	}

	return false, "", nil
}

// Compile-time check
var _ rule.RuleEvaluator = (*ContractMethodEvaluator)(nil)

// ValueLimitEvaluator checks if the transaction value is within/exceeds the limit
// Behavior depends on rule mode:
// - Whitelist mode: returns true if value <= limit (allow small transactions)
// - Blocklist mode: returns true if value > limit (block large transactions)
type ValueLimitEvaluator struct{}

// NewValueLimitEvaluator creates a new value limit evaluator
func NewValueLimitEvaluator() (*ValueLimitEvaluator, error) {
	return &ValueLimitEvaluator{}, nil
}

// Type returns the rule type this evaluator handles
func (e *ValueLimitEvaluator) Type() types.RuleType {
	return types.RuleTypeEVMValueLimit
}

// Evaluate checks the transaction value against the limit
// For blocklist mode: returns true if value EXCEEDS limit (violation)
// For whitelist mode: returns true if value is WITHIN limit (allowed)
func (e *ValueLimitEvaluator) Evaluate(ctx context.Context, r *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	if parsed == nil || parsed.Value == nil {
		// No value to check - for blocklist, no violation; for whitelist, no match
		return false, "", nil
	}

	var config ValueLimitConfig
	if err := json.Unmarshal(r.Config, &config); err != nil {
		return false, "", fmt.Errorf("invalid value limit config: %w", err)
	}

	// Parse the max value
	maxValue := new(big.Int)
	if _, ok := maxValue.SetString(config.MaxValue, 10); !ok {
		return false, "", fmt.Errorf("invalid max_value in config: %s", config.MaxValue)
	}

	// Parse the transaction value
	txValue := new(big.Int)
	if _, ok := txValue.SetString(*parsed.Value, 10); !ok {
		return false, "", fmt.Errorf("invalid transaction value: %s", *parsed.Value)
	}

	// Check based on rule mode
	if r.Mode == types.RuleModeBlocklist {
		// Blocklist mode: fire (return true) if value EXCEEDS limit
		if txValue.Cmp(maxValue) > 0 {
			return true, fmt.Sprintf("value %s exceeds limit %s", *parsed.Value, config.MaxValue), nil
		}
		return false, "", nil
	}

	// Whitelist mode (default): fire if value is within limit
	if txValue.Cmp(maxValue) <= 0 {
		return true, fmt.Sprintf("value %s within limit %s", *parsed.Value, config.MaxValue), nil
	}

	return false, "", nil
}

// Compile-time check
var _ rule.RuleEvaluator = (*ValueLimitEvaluator)(nil)

// SignerRestrictionEvaluator checks if the signer is allowed for the API key
type SignerRestrictionEvaluator struct{}

// NewSignerRestrictionEvaluator creates a new signer restriction evaluator
func NewSignerRestrictionEvaluator() (*SignerRestrictionEvaluator, error) {
	return &SignerRestrictionEvaluator{}, nil
}

// Type returns the rule type this evaluator handles
func (e *SignerRestrictionEvaluator) Type() types.RuleType {
	return types.RuleTypeSignerRestriction
}

// SignerRestrictionConfig defines the configuration for signer restrictions
type SignerRestrictionConfig struct {
	AllowedSigners []string `json:"allowed_signers"` // List of allowed signer addresses
}

// Evaluate checks if the signer is in the allowed list
func (e *SignerRestrictionEvaluator) Evaluate(ctx context.Context, r *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	var config SignerRestrictionConfig
	if err := json.Unmarshal(r.Config, &config); err != nil {
		return false, "", fmt.Errorf("invalid signer restriction config: %w", err)
	}

	signerLower := strings.ToLower(req.SignerAddress)
	for _, allowed := range config.AllowedSigners {
		if strings.ToLower(allowed) == signerLower {
			return true, fmt.Sprintf("signer %s is allowed", req.SignerAddress), nil
		}
	}

	return false, "", nil
}

// Compile-time check
var _ rule.RuleEvaluator = (*SignerRestrictionEvaluator)(nil)

// SignTypeRestrictionEvaluator checks if the sign type is allowed
type SignTypeRestrictionEvaluator struct{}

// NewSignTypeRestrictionEvaluator creates a new sign type restriction evaluator
func NewSignTypeRestrictionEvaluator() (*SignTypeRestrictionEvaluator, error) {
	return &SignTypeRestrictionEvaluator{}, nil
}

// Type returns the rule type this evaluator handles
func (e *SignTypeRestrictionEvaluator) Type() types.RuleType {
	return types.RuleTypeSignTypeRestriction
}

// SignTypeRestrictionConfig defines the configuration for sign type restrictions
type SignTypeRestrictionConfig struct {
	AllowedSignTypes []string `json:"allowed_sign_types"` // List of allowed sign types
}

// Evaluate checks if the sign type is in the allowed list
func (e *SignTypeRestrictionEvaluator) Evaluate(ctx context.Context, r *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	var config SignTypeRestrictionConfig
	if err := json.Unmarshal(r.Config, &config); err != nil {
		return false, "", fmt.Errorf("invalid sign type restriction config: %w", err)
	}

	signTypeLower := strings.ToLower(req.SignType)
	for _, allowed := range config.AllowedSignTypes {
		if strings.ToLower(allowed) == signTypeLower {
			return true, fmt.Sprintf("sign type %s is allowed", req.SignType), nil
		}
	}

	return false, "", nil
}

// Compile-time check
var _ rule.RuleEvaluator = (*SignTypeRestrictionEvaluator)(nil)
