// Package ruleconfig provides strict format validation for rule configuration only.
// Used by API (create/update rule), config load (rule_init), and validate-rules CLI.
// For request/query/enum validation (address, sign_type, mode, chain_type, etc.) use internal/validate.
package ruleconfig

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

var methodSigRegex = regexp.MustCompile(`^0x[0-9a-fA-F]{8}$`)

const maxExpressionLength = 10 * 1024

var dangerousSolidityPatterns = regexp.MustCompile(`(?i)\b(selfdestruct|delegatecall|create2|suicide)\b`)

// ValidateRuleConfig validates config map for the given rule type.
// Returns an error if format is wrong (e.g. allowed_sign_types as string instead of array,
// or sign_type_filter with invalid tokens). Call this before persisting rules from API or config.
func ValidateRuleConfig(ruleType string, config map[string]interface{}) error {
	t := types.RuleType(validate.NormalizeRuleType(ruleType))
	if _, ok := types.LookupRuleType(t); !ok {
		return fmt.Errorf("unknown rule type: %s", ruleType)
	}
	if check := configValidators[t]; check != nil {
		return check(config)
	}
	// Declared, but its config needs no shape check beyond being a map.
	return nil
}

// configValidators maps a rule type to the shape check for its config block.
//
// ⚠️ A table rather than a switch, because a switch's default answers two
// different questions with one branch: "this type does not exist" and "this
// type needs no config check". They were conflated here, and adding
// evm_internal_transfer to the rule-type table would have made it fail as an
// unknown type — the engine has been registered in four places since it was
// written, with nothing able to create a rule for it.
//
// ⛔ A type absent from this map is valid with an unchecked config. If a new
// engine needs its config checked, the entry goes here; if it does not, leave
// it out deliberately rather than adding a no-op.
var configValidators = map[types.RuleType]func(map[string]interface{}) error{
	types.RuleTypeEVMAddressList:        validateAddressListConfig,
	types.RuleTypeEVMValueLimit:         validateValueLimitConfig,
	types.RuleTypeSignerRestriction:     validateSignerRestrictionConfig,
	types.RuleTypeSignTypeRestriction:   validateSignTypeRestrictionConfig,
	types.RuleTypeEVMSolidityExpression: validateSolidityExpressionConfig,
	types.RuleTypeEVMContractMethod:     validateContractMethodConfig,
	types.RuleTypeEVMJS:                 validateJSRuleConfig,
	types.RuleTypeEVMDynamicBlocklist:   validateDynamicBlocklistConfig,

	// chain_restriction, message_pattern and evm_internal_transfer take no
	// config shape this layer can check: the first two carry only scope fields
	// the evaluator reads directly, and the third has one optional match_mode.
}

func validateAddressListConfig(config map[string]interface{}) error {
	raw, ok := config["addresses"]
	if !ok {
		return fmt.Errorf("config.addresses is required for evm_address_list rules")
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return fmt.Errorf("config.addresses must be an array (got %T)", raw)
	}
	if len(arr) == 0 {
		return fmt.Errorf("config.addresses must not be empty")
	}
	for i, v := range arr {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("config.addresses[%d] must be a string", i)
		}
		if !validate.IsValidEthereumAddress(s) {
			return fmt.Errorf("config.addresses[%d] is not a valid Ethereum address: %s", i, s)
		}
	}
	return nil
}

func validateValueLimitConfig(config map[string]interface{}) error {
	raw, ok := config["max_value"]
	if !ok {
		return fmt.Errorf("config.max_value is required for evm_value_limit rules")
	}
	s, ok := raw.(string)
	if !ok {
		return fmt.Errorf("config.max_value must be a string (wei value), got %T", raw)
	}
	if !validate.IsValidWeiDecimal(s) {
		return fmt.Errorf("config.max_value must be a non-empty decimal string, got: %s", s)
	}
	return nil
}

func validateSignerRestrictionConfig(config map[string]interface{}) error {
	raw, ok := config["allowed_signers"]
	if !ok {
		return fmt.Errorf("config.allowed_signers is required for signer_restriction rules")
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return fmt.Errorf("config.allowed_signers must be an array (got %T)", raw)
	}
	if len(arr) == 0 {
		return fmt.Errorf("config.allowed_signers must not be empty")
	}
	for i, v := range arr {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("config.allowed_signers[%d] must be a string", i)
		}
		if !validate.IsValidEthereumAddress(s) {
			return fmt.Errorf("config.allowed_signers[%d] is not a valid Ethereum address: %s", i, s)
		}
	}
	return nil
}

// validateSignTypeRestrictionConfig enforces allowed_sign_types as array of valid strings.
// Rejects comma-separated string (e.g. "personal,transaction") so the rule cannot silently
// fail to match and allow requests via other rules.
func validateSignTypeRestrictionConfig(config map[string]interface{}) error {
	raw, ok := config["allowed_sign_types"]
	if !ok {
		return fmt.Errorf("config.allowed_sign_types is required for sign_type_restriction rules")
	}
	// Explicitly reject string (e.g. YAML "personal,transaction" or typo)
	if _, isString := raw.(string); isString {
		return fmt.Errorf("config.allowed_sign_types must be an array of strings, not a comma-separated string; use YAML list form")
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return fmt.Errorf("config.allowed_sign_types must be an array (got %T)", raw)
	}
	if len(arr) == 0 {
		return fmt.Errorf("config.allowed_sign_types must not be empty")
	}
	for i, v := range arr {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("config.allowed_sign_types[%d] must be a string", i)
		}
		if !validate.ValidSignTypes[s] {
			return fmt.Errorf("config.allowed_sign_types[%d] is not a valid sign type: %s (allowed: personal, typed_data, transaction, hash, raw_message, eip191)", i, s)
		}
	}
	return nil
}

func validateSolidityExpressionConfig(config map[string]interface{}) error {
	for _, key := range []string{"expression", "typed_data_expression", "functions", "typed_data_functions"} {
		if v, ok := config[key].(string); ok {
			if len(v) > maxExpressionLength {
				return fmt.Errorf("%s is too long (max %d bytes)", key, maxExpressionLength)
			}
			if dangerousSolidityPatterns.MatchString(v) {
				return fmt.Errorf("%s contains dangerous patterns (selfdestruct, delegatecall, create2 not allowed)", key)
			}
		}
	}
	return nil
}

func validateContractMethodConfig(config map[string]interface{}) error {
	raw, ok := config["method_sigs"]
	if !ok {
		return fmt.Errorf("config.method_sigs is required for evm_contract_method rules")
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return fmt.Errorf("config.method_sigs must be an array (got %T)", raw)
	}
	if len(arr) == 0 {
		return fmt.Errorf("config.method_sigs must not be empty")
	}
	for i, v := range arr {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("config.method_sigs[%d] must be a string (0x + 8 hex chars)", i)
		}
		if !methodSigRegex.MatchString(s) {
			return fmt.Errorf("config.method_sigs[%d] must be a 4-byte method selector (0x + 8 hex chars), got: %s", i, s)
		}
	}
	return nil
}

// ValidateJSRuleTestCasesRequirement enforces the same rule as Solidity: at least one positive
// and one negative test case. Call when validating evm_js rules that have test_cases.
// positiveCount and negativeCount are the number of test cases with expect_pass true/false.
func ValidateJSRuleTestCasesRequirement(positiveCount, negativeCount int) error {
	if positiveCount < 1 {
		return fmt.Errorf("evm_js rules require at least one positive test case (expect_pass: true)")
	}
	if negativeCount < 1 {
		return fmt.Errorf("evm_js rules require at least one negative test case (expect_pass: false)")
	}
	return nil
}

// validateJSRuleConfig validates evm_js config. sign_type_filter, if present, must be a
// comma-separated string of valid sign types (evm_js only supports string form; array would
// unmarshal as empty and cause rule to apply to all sign types = silent pass).
const maxJSScriptLength = 64 * 1024 // 64KB

func validateJSRuleConfig(config map[string]interface{}) error {
	raw, ok := config["script"]
	if !ok {
		return fmt.Errorf("config.script is required for evm_js rules")
	}
	script, ok := raw.(string)
	if !ok {
		return fmt.Errorf("config.script must be a string")
	}
	if strings.TrimSpace(script) == "" {
		return fmt.Errorf("config.script must not be empty")
	}
	if len(script) > maxJSScriptLength {
		return fmt.Errorf("config.script exceeds maximum size (%d bytes, max %d)", len(script), maxJSScriptLength)
	}
	// Static security check: block dangerous JS patterns (prototype pollution, sandbox escape, etc.)
	if err := validate.ValidateJSCodeSecurity(script); err != nil {
		return fmt.Errorf("config.script security check failed: %w", err)
	}
	if v, ok := config["sign_type_filter"]; ok && v != nil {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("config.sign_type_filter must be a comma-separated string (e.g. \"typed_data,transaction\"), not an array")
		}
		for _, part := range strings.Split(s, ",") {
			token := strings.TrimSpace(strings.ToLower(part))
			if token == "" {
				continue
			}
			if token == "personal_sign" || token == "eip191" {
				continue
			}
			if !validate.ValidSignTypes[token] {
				return fmt.Errorf("config.sign_type_filter contains invalid sign type: %q (allowed: personal, typed_data, transaction, hash, raw_message, eip191)", token)
			}
		}
	}
	return nil
}

func validateDynamicBlocklistConfig(config map[string]interface{}) error {
	// At minimum, one of check_recipient or check_verifying_contract must be true.
	cr, _ := config["check_recipient"].(bool)
	cv, _ := config["check_verifying_contract"].(bool)
	if !cr && !cv {
		return fmt.Errorf("config must have check_recipient and/or check_verifying_contract set to true")
	}
	return nil
}
