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
