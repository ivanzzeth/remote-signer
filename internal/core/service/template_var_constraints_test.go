package service

import (
	"strings"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func ptr(s string) *string { return &s }

// TestValidateVariableConstraints covers the four fields that shipped
// documented as enforced and were read by nothing until 2026-09-10.
func TestValidateVariableConstraints(t *testing.T) {
	for _, tc := range []struct {
		name    string
		def     types.TemplateVariable
		value   string
		wantErr string // substring; empty means the value must be accepted
	}{
		{
			name:  "empty value skips every constraint",
			def:   types.TemplateVariable{Name: "v", Type: types.VarTypeBigInt, Min: ptr("10")},
			value: "",
		},
		{
			name:    "options reject a value outside the set",
			def:     types.TemplateVariable{Name: "mode", Type: types.VarTypeEnum, Options: []string{"strict", "lax"}},
			value:   "off",
			wantErr: "not one of strict, lax",
		},
		{
			name:  "options accept a value in the set",
			def:   types.TemplateVariable{Name: "mode", Type: types.VarTypeEnum, Options: []string{"strict", "lax"}},
			value: "lax",
		},
		{
			name:    "enum with no options is a broken template",
			def:     types.TemplateVariable{Name: "mode", Type: types.VarTypeEnum},
			value:   "anything",
			wantErr: "no options",
		},
		{
			name:    "pattern rejects a non-match",
			def:     types.TemplateVariable{Name: "tag", Type: types.VarTypeString, Pattern: `^v\d+$`},
			value:   "release",
			wantErr: "does not match pattern",
		},
		{
			name:  "pattern accepts a match",
			def:   types.TemplateVariable{Name: "tag", Type: types.VarTypeString, Pattern: `^v\d+$`},
			value: "v2",
		},
		{
			name:    "an uncompilable pattern fails closed",
			def:     types.TemplateVariable{Name: "tag", Type: types.VarTypeString, Pattern: `([`},
			value:   "anything",
			wantErr: "invalid pattern",
		},
		{
			// The regression this ordering exists for: compared as strings,
			// "9" > "1000", and a spending cap would admit 9 wei... or 9e18.
			name:  "bigint max compares numerically, not lexicographically",
			def:   types.TemplateVariable{Name: "cap", Type: types.VarTypeBigInt, Max: ptr("1000")},
			value: "9",
		},
		{
			name:    "bigint above max is rejected",
			def:     types.TemplateVariable{Name: "cap", Type: types.VarTypeBigInt, Max: ptr("1000")},
			value:   "1001",
			wantErr: "above max",
		},
		{
			name:    "bigint below min is rejected",
			def:     types.TemplateVariable{Name: "cap", Type: types.VarTypeBigInt, Min: ptr("10")},
			value:   "9",
			wantErr: "below min",
		},
		{
			name:  "bigint at the bound is accepted",
			def:   types.TemplateVariable{Name: "cap", Type: types.VarTypeBigInt, Min: ptr("10"), Max: ptr("10")},
			value: "10",
		},
		{
			name:    "duration above max is rejected",
			def:     types.TemplateVariable{Name: "period", Type: types.VarTypeDuration, Max: ptr("24h")},
			value:   "48h",
			wantErr: "above max",
		},
		{
			name:  "duration below max is accepted",
			def:   types.TemplateVariable{Name: "period", Type: types.VarTypeDuration, Max: ptr("24h")},
			value: "1h30m",
		},
		{
			name:    "min/max on a type with no ordering is refused, not ignored",
			def:     types.TemplateVariable{Name: "who", Type: types.VarTypeAddress, Max: ptr("0xff")},
			value:   "0x1111111111111111111111111111111111111111",
			wantErr: "not supported for type",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateVariableConstraints(tc.def, tc.value)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want accepted, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestValidateVariableType_PreviouslyUnvalidatedKinds: bool, bytes, bytes4,
// duration and json were listed as legal variable types and fell through to
// "unknown type, skip validation".
func TestValidateVariableType_PreviouslyUnvalidatedKinds(t *testing.T) {
	for _, tc := range []struct {
		varType types.VariableType
		value   string
		ok      bool
	}{
		{types.VarTypeBool, "true", true},
		{types.VarTypeBool, "false", true},
		{types.VarTypeBool, "yes", false},
		{types.VarTypeBytes, "0xdeadbeef", true},
		{types.VarTypeBytes, "0xabc", false},    // odd length
		{types.VarTypeBytes, "deadbeef", false}, // no 0x
		{types.VarTypeBytes4, "0xa9059cbb", true},
		{types.VarTypeBytes4, "0xa9059c", false},
		{types.VarTypeDuration, "30m", true},
		{types.VarTypeDuration, "30 minutes", false},
		{types.VarTypeJSON, `{"a":1}`, true},
		{types.VarTypeJSON, `{"a":`, false},
	} {
		err := validateVariableType("v", tc.varType, tc.value)
		if tc.ok && err != nil {
			t.Errorf("%s %q: want accepted, got %v", tc.varType, tc.value, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s %q: want rejected, got nil", tc.varType, tc.value)
		}
	}
}
