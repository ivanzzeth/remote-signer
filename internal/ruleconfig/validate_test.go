package ruleconfig

import (
	"strings"
	"testing"
)

func TestValidateSignTypeRestrictionConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid array",
			config: map[string]interface{}{
				"allowed_sign_types": []interface{}{"personal", "transaction"},
			},
			wantErr: false,
		},
		{
			name: "missing allowed_sign_types",
			config: map[string]interface{}{},
			wantErr: true,
			errMsg: "required",
		},
		{
			name: "allowed_sign_types as string (comma-separated) rejected",
			config: map[string]interface{}{
				"allowed_sign_types": "personal,transaction",
			},
			wantErr: true,
			errMsg:  "must be an array",
		},
		{
			name: "allowed_sign_types as string single",
			config: map[string]interface{}{
				"allowed_sign_types": "personal",
			},
			wantErr: true,
			errMsg:  "must be an array",
		},
		{
			name: "empty array rejected",
			config: map[string]interface{}{
				"allowed_sign_types": []interface{}{},
			},
			wantErr: true,
			errMsg:  "must not be empty",
		},
		{
			name: "invalid sign type in array",
			config: map[string]interface{}{
				"allowed_sign_types": []interface{}{"personal", "invalid_type"},
			},
			wantErr: true,
			errMsg:  "not a valid sign type",
		},
		{
			name: "non-string element rejected",
			config: map[string]interface{}{
				"allowed_sign_types": []interface{}{"personal", 123},
			},
			wantErr: true,
			errMsg:  "must be a string",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuleConfig("sign_type_restriction", tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRuleConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateRuleConfig() error = %v, want message containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestValidateEVMJSConfig_SignTypeFilter(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid script only",
			config: map[string]interface{}{
				"script": "function validate(i){ return { valid: true }; }",
			},
			wantErr: false,
		},
		{
			name: "valid script with sign_type_filter string",
			config: map[string]interface{}{
				"script":            "function validate(i){ return { valid: true }; }",
				"sign_type_filter": "typed_data,transaction",
			},
			wantErr: false,
		},
		{
			name: "sign_type_filter as array rejected",
			config: map[string]interface{}{
				"script": "function validate(i){ return { valid: true }; }",
				"sign_type_filter": []interface{}{"typed_data", "transaction"},
			},
			wantErr: true,
			errMsg:  "comma-separated string",
		},
		{
			name: "sign_type_filter invalid token",
			config: map[string]interface{}{
				"script":            "function validate(i){ return { valid: true }; }",
				"sign_type_filter": "typed_data,invalid",
			},
			wantErr: true,
			errMsg:  "invalid sign type",
		},
		{
			name: "missing script",
			config: map[string]interface{}{
				"sign_type_filter": "personal",
			},
			wantErr: true,
			errMsg:  "script is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuleConfig("evm_js", tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRuleConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateRuleConfig() error = %v, want message containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestValidateAddressListConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid",
			config: map[string]interface{}{
				"addresses": []interface{}{"0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"},
			},
			wantErr: false,
		},
		{
			name: "addresses as string rejected",
			config: map[string]interface{}{
				"addresses": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
			},
			wantErr: true,
			errMsg:  "must be an array",
		},
		{
			name: "invalid address",
			config: map[string]interface{}{
				"addresses": []interface{}{"not-an-address"},
			},
			wantErr: true,
			errMsg:  "not a valid Ethereum address",
		},
		{
			name: "missing addresses",
			config: map[string]interface{}{},
			wantErr: true,
			errMsg:  "addresses is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuleConfig("evm_address_list", tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRuleConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateRuleConfig() error = %v, want message containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestValidateValueLimitConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid",
			config: map[string]interface{}{
				"max_value": "100000000000000000000",
			},
			wantErr: false,
		},
		{
			name: "max_value as int rejected",
			config: map[string]interface{}{
				"max_value": 1000000,
			},
			wantErr: true,
			errMsg:  "must be a string",
		},
		{
			name: "missing max_value",
			config: map[string]interface{}{},
			wantErr: true,
			errMsg:  "max_value is required",
		},
		{
			name: "empty max_value",
			config: map[string]interface{}{
				"max_value": "",
			},
			wantErr: true,
			errMsg:  "non-empty decimal",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuleConfig("evm_value_limit", tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRuleConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateRuleConfig() error = %v, want message containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestValidateContractMethodConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid",
			config: map[string]interface{}{
				"method_sigs": []interface{}{"0xa9059cbb", "0x095ea7b3"},
			},
			wantErr: false,
		},
		{
			name: "method_sigs as string rejected",
			config: map[string]interface{}{
				"method_sigs": "0xa9059cbb",
			},
			wantErr: true,
			errMsg:  "must be an array",
		},
		{
			name: "invalid selector length",
			config: map[string]interface{}{
				"method_sigs": []interface{}{"0xa9059cbb", "0x095ea7b3ab"}, // 10 hex chars
			},
			wantErr: true,
			errMsg:  "4-byte",
		},
		{
			name: "missing method_sigs",
			config: map[string]interface{}{},
			wantErr: true,
			errMsg:  "method_sigs is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuleConfig("evm_contract_method", tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRuleConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateRuleConfig() error = %v, want message containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestValidateUnknownRuleType(t *testing.T) {
	err := ValidateRuleConfig("unknown_type", map[string]interface{}{"x": 1})
	if err == nil {
		t.Error("expected error for unknown rule type")
	}
	if !strings.Contains(err.Error(), "unknown rule type") {
		t.Errorf("error = %v", err)
	}
}

// ---------- validateSignerRestrictionConfig (was 0%) ----------

func TestValidateSignerRestrictionConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid single signer",
			config: map[string]interface{}{
				"allowed_signers": []interface{}{"0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"},
			},
			wantErr: false,
		},
		{
			name: "valid multiple signers",
			config: map[string]interface{}{
				"allowed_signers": []interface{}{
					"0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
					"0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2",
				},
			},
			wantErr: false,
		},
		{
			name: "missing allowed_signers",
			config: map[string]interface{}{},
			wantErr: true,
			errMsg:  "allowed_signers is required",
		},
		{
			name: "allowed_signers as string rejected",
			config: map[string]interface{}{
				"allowed_signers": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
			},
			wantErr: true,
			errMsg:  "must be an array",
		},
		{
			name: "empty array rejected",
			config: map[string]interface{}{
				"allowed_signers": []interface{}{},
			},
			wantErr: true,
			errMsg:  "must not be empty",
		},
		{
			name: "non-string element rejected",
			config: map[string]interface{}{
				"allowed_signers": []interface{}{42},
			},
			wantErr: true,
			errMsg:  "must be a string",
		},
		{
			name: "invalid ethereum address",
			config: map[string]interface{}{
				"allowed_signers": []interface{}{"not-an-address"},
			},
			wantErr: true,
			errMsg:  "not a valid Ethereum address",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuleConfig("signer_restriction", tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRuleConfig(signer_restriction) error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error = %v, want message containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

// ---------- validateSolidityExpressionConfig (was 0%) ----------

func TestValidateSolidityExpressionConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty config is valid (no required fields)",
			config:  map[string]interface{}{},
			wantErr: false,
		},
		{
			name: "valid expression",
			config: map[string]interface{}{
				"expression": "value < 1 ether",
			},
			wantErr: false,
		},
		{
			name: "valid typed_data_expression",
			config: map[string]interface{}{
				"typed_data_expression": "amount < 100",
			},
			wantErr: false,
		},
		{
			name: "valid functions key",
			config: map[string]interface{}{
				"functions": "function check() pure returns (bool) { return true; }",
			},
			wantErr: false,
		},
		{
			name: "valid typed_data_functions key",
			config: map[string]interface{}{
				"typed_data_functions": "function check() pure returns (bool) { return true; }",
			},
			wantErr: false,
		},
		{
			name: "expression too long",
			config: map[string]interface{}{
				"expression": strings.Repeat("x", maxExpressionLength+1),
			},
			wantErr: true,
			errMsg:  "too long",
		},
		{
			name: "typed_data_expression too long",
			config: map[string]interface{}{
				"typed_data_expression": strings.Repeat("a", maxExpressionLength+1),
			},
			wantErr: true,
			errMsg:  "too long",
		},
		{
			name: "functions too long",
			config: map[string]interface{}{
				"functions": strings.Repeat("b", maxExpressionLength+1),
			},
			wantErr: true,
			errMsg:  "too long",
		},
		{
			name: "typed_data_functions too long",
			config: map[string]interface{}{
				"typed_data_functions": strings.Repeat("c", maxExpressionLength+1),
			},
			wantErr: true,
			errMsg:  "too long",
		},
		{
			name: "expression contains selfdestruct",
			config: map[string]interface{}{
				"expression": "selfdestruct(addr)",
			},
			wantErr: true,
			errMsg:  "dangerous patterns",
		},
		{
			name: "expression contains delegatecall",
			config: map[string]interface{}{
				"expression": "addr.delegatecall(data)",
			},
			wantErr: true,
			errMsg:  "dangerous patterns",
		},
		{
			name: "expression contains create2",
			config: map[string]interface{}{
				"expression": "create2(0, ptr, size, salt)",
			},
			wantErr: true,
			errMsg:  "dangerous patterns",
		},
		{
			name: "typed_data_expression dangerous pattern",
			config: map[string]interface{}{
				"typed_data_expression": "suicide(addr)",
			},
			wantErr: true,
			errMsg:  "dangerous patterns",
		},
		{
			name: "functions with dangerous delegatecall",
			config: map[string]interface{}{
				"functions": "function f() { delegatecall(data); }",
			},
			wantErr: true,
			errMsg:  "dangerous patterns",
		},
		{
			name: "non-string key ignored (no error)",
			config: map[string]interface{}{
				"expression": 12345, // not a string, so .(string) fails => skipped
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuleConfig("evm_solidity_expression", tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRuleConfig(evm_solidity_expression) error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error = %v, want message containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

// ---------- ValidateJSRuleTestCasesRequirement (was 0%) ----------

func TestValidateJSRuleTestCasesRequirement(t *testing.T) {
	tests := []struct {
		name     string
		positive int
		negative int
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "both counts satisfied",
			positive: 1,
			negative: 1,
			wantErr:  false,
		},
		{
			name:     "multiple counts satisfied",
			positive: 3,
			negative: 2,
			wantErr:  false,
		},
		{
			name:     "zero positive",
			positive: 0,
			negative: 1,
			wantErr:  true,
			errMsg:   "positive test case",
		},
		{
			name:     "zero negative",
			positive: 1,
			negative: 0,
			wantErr:  true,
			errMsg:   "negative test case",
		},
		{
			name:     "both zero",
			positive: 0,
			negative: 0,
			wantErr:  true,
			errMsg:   "positive test case",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJSRuleTestCasesRequirement(tt.positive, tt.negative)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJSRuleTestCasesRequirement(%d,%d) error = %v, wantErr %v",
					tt.positive, tt.negative, err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error = %v, want message containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

// ---------- ValidateRuleConfig dispatch branches (was 72.7%) ----------

func TestValidateRuleConfig_PassthroughTypes(t *testing.T) {
	// chain_restriction and message_pattern return nil without config validation
	for _, ruleType := range []string{"chain_restriction", "message_pattern"} {
		t.Run(ruleType, func(t *testing.T) {
			err := ValidateRuleConfig(ruleType, map[string]interface{}{"anything": true})
			if err != nil {
				t.Errorf("ValidateRuleConfig(%s) expected nil, got %v", ruleType, err)
			}
		})
	}
}

// ---------- validateAddressListConfig missing branches (was 86.7%) ----------

func TestValidateAddressListConfig_EmptyArray(t *testing.T) {
	err := ValidateRuleConfig("evm_address_list", map[string]interface{}{
		"addresses": []interface{}{},
	})
	if err == nil {
		t.Error("expected error for empty addresses array")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("error = %v, want 'must not be empty'", err)
	}
}

func TestValidateAddressListConfig_NonStringElement(t *testing.T) {
	err := ValidateRuleConfig("evm_address_list", map[string]interface{}{
		"addresses": []interface{}{123},
	})
	if err == nil {
		t.Error("expected error for non-string element")
	}
	if !strings.Contains(err.Error(), "must be a string") {
		t.Errorf("error = %v, want 'must be a string'", err)
	}
}

// ---------- validateContractMethodConfig missing branches (was 86.7%) ----------

func TestValidateContractMethodConfig_EmptyArray(t *testing.T) {
	err := ValidateRuleConfig("evm_contract_method", map[string]interface{}{
		"method_sigs": []interface{}{},
	})
	if err == nil {
		t.Error("expected error for empty method_sigs array")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("error = %v, want 'must not be empty'", err)
	}
}

func TestValidateContractMethodConfig_NonStringElement(t *testing.T) {
	err := ValidateRuleConfig("evm_contract_method", map[string]interface{}{
		"method_sigs": []interface{}{true},
	})
	if err == nil {
		t.Error("expected error for non-string element")
	}
	if !strings.Contains(err.Error(), "must be a string") {
		t.Errorf("error = %v, want 'must be a string'", err)
	}
}

// ---------- validateJSRuleConfig missing branches (was 78.3%) ----------

func TestValidateJSRuleConfig_ExtraBranches(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "script not a string",
			config: map[string]interface{}{
				"script": 42,
			},
			wantErr: true,
			errMsg:  "script must be a string",
		},
		{
			name: "script is whitespace only",
			config: map[string]interface{}{
				"script": "   \t\n  ",
			},
			wantErr: true,
			errMsg:  "script must not be empty",
		},
		{
			name: "script exceeds max size",
			config: map[string]interface{}{
				"script": strings.Repeat("x", maxJSScriptLength+1),
			},
			wantErr: true,
			errMsg:  "exceeds maximum size",
		},
		{
			name: "sign_type_filter with personal_sign alias accepted",
			config: map[string]interface{}{
				"script":           "function validate(i){ return { valid: true }; }",
				"sign_type_filter": "personal_sign",
			},
			wantErr: false,
		},
		{
			name: "sign_type_filter with eip191 alias accepted",
			config: map[string]interface{}{
				"script":           "function validate(i){ return { valid: true }; }",
				"sign_type_filter": "eip191",
			},
			wantErr: false,
		},
		{
			name: "sign_type_filter nil is ignored",
			config: map[string]interface{}{
				"script":           "function validate(i){ return { valid: true }; }",
				"sign_type_filter": nil,
			},
			wantErr: false,
		},
		{
			name: "sign_type_filter with empty tokens between commas",
			config: map[string]interface{}{
				"script":           "function validate(i){ return { valid: true }; }",
				"sign_type_filter": "personal,,transaction",
			},
			wantErr: false,
		},
		{
			name: "sign_type_filter with whitespace tokens",
			config: map[string]interface{}{
				"script":           "function validate(i){ return { valid: true }; }",
				"sign_type_filter": " personal , transaction ",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRuleConfig("evm_js", tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRuleConfig(evm_js) error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error = %v, want message containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

// ---------- validateSignTypeRestrictionConfig: non-array non-string type (was 94.1%) ----------

// ---------- V3-4: validateJSRuleConfig calls ValidateJSCodeSecurity ----------

func TestValidateJSRuleConfig_DangerousPatternsRejected(t *testing.T) {
	tests := []struct {
		name   string
		script string
		errMsg string
	}{
		{
			name:   "__proto__ manipulation",
			script: `function validate(i){ i.__proto__.polluted = true; return { valid: true }; }`,
			errMsg: "dangerous pattern",
		},
		{
			name:   "constructor.constructor escape",
			script: `function validate(i){ return "".constructor.constructor("return this")(); }`,
			errMsg: "dangerous pattern",
		},
		{
			name:   "Object.defineProperty hijacking",
			script: `function validate(i){ Object.defineProperty({}, 'x', {get: function(){}}); return { valid: true }; }`,
			errMsg: "dangerous pattern",
		},
		{
			name:   "Object.getPrototypeOf exploration",
			script: `function validate(i){ Object.getPrototypeOf({}); return { valid: true }; }`,
			errMsg: "dangerous pattern",
		},
		{
			name:   "Object.setPrototypeOf modification",
			script: `function validate(i){ Object.setPrototypeOf({}, null); return { valid: true }; }`,
			errMsg: "dangerous pattern",
		},
		{
			name:   "new Function() code execution",
			script: `function validate(i){ var f = Function("return 1"); return { valid: true }; }`,
			errMsg: "dangerous pattern",
		},
		{
			name:   "dynamic import()",
			script: `function validate(i){ import("os"); return { valid: true }; }`,
			errMsg: "dangerous pattern",
		},
		{
			name:   "child_process module",
			script: `function validate(i){ require("child_process"); return { valid: true }; }`,
			errMsg: "dangerous pattern",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := map[string]interface{}{
				"script": tt.script,
			}
			err := ValidateRuleConfig("evm_js", config)
			if err == nil {
				t.Errorf("expected error for dangerous pattern in script %q", tt.name)
				return
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error = %v, want message containing %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestValidateJSRuleConfig_SafeScriptAccepted(t *testing.T) {
	config := map[string]interface{}{
		"script": `function validate(input) {
			if (input.value > 1000000000000000000) {
				return { valid: false, reason: "value too high" };
			}
			return { valid: true };
		}`,
	}
	err := ValidateRuleConfig("evm_js", config)
	if err != nil {
		t.Errorf("expected no error for safe script, got: %v", err)
	}
}

func TestValidateSignTypeRestrictionConfig_NonArrayNonString(t *testing.T) {
	err := ValidateRuleConfig("sign_type_restriction", map[string]interface{}{
		"allowed_sign_types": 12345,
	})
	if err == nil {
		t.Error("expected error for non-array, non-string type")
	}
	if !strings.Contains(err.Error(), "must be an array") {
		t.Errorf("error = %v, want 'must be an array'", err)
	}
}
