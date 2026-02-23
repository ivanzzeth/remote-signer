package config

import (
	"os"
	"strings"
	"testing"
)

// TestSubstituteVarsInString covers substituteVarsInString: happy path, edge cases, error path, empty.
func TestSubstituteVarsInString(t *testing.T) {
	tests := []struct {
		name    string
		s       string
		vars    map[string]string
		want    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "happy path - single var",
			s:       "chain_id is ${chain_id}",
			vars:    map[string]string{"chain_id": "137"},
			want:    "chain_id is 137",
			wantErr: false,
		},
		{
			name:    "happy path - multiple vars",
			s:       "a=${a} b=${b}",
			vars:    map[string]string{"a": "1", "b": "2"},
			want:    "a=1 b=2",
			wantErr: false,
		},
		{
			name:    "happy path - same var twice",
			s:       "${x} and ${x}",
			vars:    map[string]string{"x": "v"},
			want:    "v and v",
			wantErr: false,
		},
		{
			name:    "empty vars - no placeholders",
			s:       "no placeholders",
			vars:    map[string]string{},
			want:    "no placeholders",
			wantErr: false,
		},
		{
			name:    "empty string input",
			s:       "",
			vars:    map[string]string{"a": "1"},
			want:    "",
			wantErr: false,
		},
		{
			name:    "nil/empty vars with placeholder - error",
			s:       "value=${missing}",
			vars:    map[string]string{},
			wantErr: true,
			errMsg:  "unresolved template variable",
		},
		{
			name:    "unresolved variable - error",
			s:       "a=${a} b=${b}",
			vars:    map[string]string{"a": "1"},
			wantErr: true,
			errMsg:  "unresolved template variable",
		},
		{
			name:    "env var syntax with colon - left as-is (no error)",
			s:       "path=${HOME:-/default}",
			vars:    map[string]string{},
			want:    "path=${HOME:-/default}",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := substituteVarsInString(tt.s, tt.vars)
			if (err != nil) != tt.wantErr {
				t.Errorf("substituteVarsInString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.errMsg != "" && err != nil && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("substituteVarsInString() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}
			if got != tt.want {
				t.Errorf("substituteVarsInString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestExpandInstanceRules_ErrorPaths covers ExpandInstanceRules error cases.
func TestExpandInstanceRules_ErrorPaths(t *testing.T) {
	templates := []TemplateConfig{
		{
			Name: "T",
			Type: "template_bundle",
			Config: map[string]interface{}{
				"rules_json": `[{"name":"R","type":"evm_solidity_expression","mode":"whitelist","config":{},"enabled":true}]`,
			},
			Enabled: true,
		},
	}

	t.Run("missing template in config", func(t *testing.T) {
		rules := []RuleConfig{
			{
				Name: "Instance",
				Type: "instance",
				Mode: "whitelist",
				Config: map[string]interface{}{
					"variables": map[string]interface{}{"x": "1"},
				},
				Enabled: true,
			},
		}
		_, err := ExpandInstanceRules(rules, templates)
		if err == nil {
			t.Fatal("expected error when template key missing")
		}
		if !strings.Contains(err.Error(), "template") {
			t.Errorf("error should mention template: %v", err)
		}
	})

	t.Run("template not found", func(t *testing.T) {
		rules := []RuleConfig{
			{
				Name: "Instance",
				Type: "instance",
				Mode: "whitelist",
				Config: map[string]interface{}{
					"template":  "NonExistent",
					"variables": map[string]interface{}{"x": "1"},
				},
				Enabled: true,
			},
		}
		_, err := ExpandInstanceRules(rules, templates)
		if err == nil {
			t.Fatal("expected error when template not found")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("error should mention not found: %v", err)
		}
	})

	t.Run("unresolved variable in rules_json", func(t *testing.T) {
		tmplWithPlaceholder := []TemplateConfig{
			{
				Name: "T",
				Type: "template_bundle",
				Config: map[string]interface{}{
					"rules_json": `[{"name":"R","type":"evm_solidity_expression","mode":"whitelist","config":{"x":"${missing_var}"},"enabled":true}]`,
				},
				Enabled: true,
			},
		}
		rules := []RuleConfig{
			{
				Name: "Instance",
				Type: "instance",
				Mode: "whitelist",
				Config: map[string]interface{}{
					"template":  "T",
					"variables": map[string]interface{}{"other": "1"},
				},
				Enabled: true,
			},
		}
		_, err := ExpandInstanceRules(rules, tmplWithPlaceholder)
		if err == nil {
			t.Fatal("expected error when variable unresolved")
		}
		if !strings.Contains(err.Error(), "unresolved") && !strings.Contains(err.Error(), "substitution") {
			t.Errorf("error should mention unresolved or substitution: %v", err)
		}
	})
}

// TestExpandInstanceRules_NonInstancePassthrough verifies non-instance rules are passed through unchanged.
func TestExpandInstanceRules_NonInstancePassthrough(t *testing.T) {
	rules := []RuleConfig{
		{
			Name: "File Rule",
			Type: "file",
			Mode: "whitelist",
			Config: map[string]interface{}{"path": "rules/foo.yaml"},
			Enabled: true,
		},
	}
	templates := []TemplateConfig{}
	got, err := ExpandInstanceRules(rules, templates)
	if err != nil {
		t.Fatalf("ExpandInstanceRules: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(got))
	}
	if got[0].Type != "file" || got[0].Name != "File Rule" {
		t.Errorf("rule passed through incorrectly: %+v", got[0])
	}
}

// TestExpandInstanceRules_EmptyRules returns empty slice without error.
func TestExpandInstanceRules_EmptyRules(t *testing.T) {
	got, err := ExpandInstanceRules(nil, []TemplateConfig{{Name: "T"}})
	if err != nil {
		t.Fatalf("ExpandInstanceRules: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 rules, got %d", len(got))
	}
}

// TestExpandTemplatesFromFiles_FileNotFound ensures missing template file returns error.
func TestExpandTemplatesFromFiles_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	templates := []TemplateConfig{
		{
			Name: "Missing",
			Type: TemplateFileType,
			Config: map[string]interface{}{
				"path": "nonexistent.yaml",
			},
			Enabled: true,
		},
	}
	_, err := ExpandTemplatesFromFiles(templates, dir, nil)
	if err == nil {
		t.Fatal("expected error when template file missing")
	}
	if !strings.Contains(err.Error(), "nonexistent") && !strings.Contains(err.Error(), "no such file") {
		t.Errorf("error should mention missing file: %v", err)
	}
}

// TestExpandTemplatesFromFiles_EmptyList returns empty without error.
func TestExpandTemplatesFromFiles_EmptyList(t *testing.T) {
	got, err := ExpandTemplatesFromFiles(nil, os.TempDir(), nil)
	if err != nil {
		t.Fatalf("ExpandTemplatesFromFiles: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 templates, got %d", len(got))
	}
}

// TestExpandTemplatesFromFiles_NonFilePassthrough verifies non-file template is passed through.
func TestExpandTemplatesFromFiles_NonFilePassthrough(t *testing.T) {
	templates := []TemplateConfig{
		{
			Name:    "Inline",
			Type:    "template_bundle",
			Config:  map[string]interface{}{"rules_json": "[]"},
			Enabled: true,
		},
	}
	got, err := ExpandTemplatesFromFiles(templates, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("ExpandTemplatesFromFiles: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 template, got %d", len(got))
	}
	if got[0].Name != "Inline" || got[0].Type != "template_bundle" {
		t.Errorf("template passed through incorrectly: %+v", got[0])
	}
}

// TestLoadTemplateFromFileStatic_MissingPath returns error when path missing in config.
func TestLoadTemplateFromFileStatic_MissingPath(t *testing.T) {
	fileCfg := TemplateConfig{
		Name:    "T",
		Type:    TemplateFileType,
		Config:  map[string]interface{}{}, // no "path"
		Enabled: true,
	}
	_, err := loadTemplateFromFileStatic(fileCfg, t.TempDir(), nil)
	if err == nil {
		t.Fatal("expected error when path missing")
	}
	if !strings.Contains(err.Error(), "path") {
		t.Errorf("error should mention path: %v", err)
	}
}

// TestLoadTemplateFromFileStatic_InvalidPathType returns error when path is not string.
func TestLoadTemplateFromFileStatic_InvalidPathType(t *testing.T) {
	fileCfg := TemplateConfig{
		Name:   "T",
		Type:   TemplateFileType,
		Config: map[string]interface{}{"path": 123},
		Enabled: true,
	}
	_, err := loadTemplateFromFileStatic(fileCfg, t.TempDir(), nil)
	if err == nil {
		t.Fatal("expected error when path is not string")
	}
	if !strings.Contains(err.Error(), "path") {
		t.Errorf("error should mention path: %v", err)
	}
}

func TestSubstituteInMappingVarsToIdentifiers(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"replace in(expr, ${var})", "in(txTo, ${allowed_safe_addresses})", "in(txTo, allowed_safe_addresses)"},
		{"no match", "in(txTo, 0xa, 0xb)", "in(txTo, 0xa, 0xb)"},
		{"unchanged", "require(true);", "require(true);"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := substituteInMappingVarsToIdentifiers(tt.in)
			if got != tt.want {
				t.Errorf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestFillInMappingArrays(t *testing.T) {
	variables := map[string]string{"allowed_safe_addresses": "0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837, 0x1234567890123456789012345678901234567890"}
	rule := &RuleConfig{
		Name: "R",
		Config: map[string]interface{}{
			"functions": "require(in(txTo, allowed_safe_addresses), \"bad\");",
		},
	}
	err := fillInMappingArrays(rule, variables)
	if err != nil {
		t.Fatalf("fillInMappingArrays: %v", err)
	}
	v, ok := rule.Config["in_mapping_arrays"].(map[string][]string)
	if !ok {
		t.Fatalf("in_mapping_arrays not set or wrong type: %T", rule.Config["in_mapping_arrays"])
	}
	addrs, ok := v["allowed_safe_addresses"]
	if !ok || len(addrs) != 2 {
		t.Errorf("allowed_safe_addresses: got %v", addrs)
	}
}
