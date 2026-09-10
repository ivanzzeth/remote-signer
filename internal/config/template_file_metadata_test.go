package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTemplateFile drops a template file in a temp dir and returns the
// TemplateConfig entry LoadTemplatesFromDir would synthesize for it.
func writeTemplateFile(t *testing.T, body string) (TemplateConfig, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "t.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return TemplateConfig{
		Name:    "Derived From Filename",
		Type:    TemplateFileType,
		Enabled: true, // what LoadTemplatesFromDir hardcodes for every file it finds
		Config:  map[string]interface{}{"path": "t.yaml"},
	}, dir
}

// TestTemplateFile_DisabledInFileIsHonoured is the bug this parser consolidation
// was chasing.
//
// templates_dir is enumerated into `type: file` entries and loaded through
// loadTemplateFromFileStatic, while the daemon's registry parses the same files
// with its own struct. The registry read `enabled:` and this path did not, so a
// template switched off on purpose was registered as enabled — the two loaders
// disagreed about the same file on disk.
func TestTemplateFile_DisabledInFileIsHonoured(t *testing.T) {
	fileCfg, dir := writeTemplateFile(t, `
name: "Real Name"
description: "from the file"
chain_type: "evm"
enabled: false
variables:
  - name: token_address
    type: address
    required: true
rules:
  - id: r1
    name: R1
    type: evm_js
    mode: whitelist
`)
	got, err := loadTemplateFromFileStatic(fileCfg, dir, testLogger())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 template, got %d", len(got))
	}
	if got[0].Enabled {
		t.Error("template declares enabled: false and must not be loaded as enabled")
	}
	if got[0].Name != "Real Name" {
		t.Errorf("file name must win over the filename-derived one, got %q", got[0].Name)
	}
	if got[0].Description != "from the file" {
		t.Errorf("description dropped, got %q", got[0].Description)
	}
	if got[0].ChainType != "evm" {
		t.Errorf("chain_type dropped, got %q", got[0].ChainType)
	}
}

// TestTemplateFile_DisabledInConfigStillWins: enabled is the one field where the
// file does not simply win. Either side switching the template off switches it
// off, so an operator disabling it in config.yaml is not overridden by a file
// that says nothing, or says true.
func TestTemplateFile_DisabledInConfigStillWins(t *testing.T) {
	fileCfg, dir := writeTemplateFile(t, `
name: "Real Name"
enabled: true
rules:
  - id: r1
    name: R1
    type: evm_js
    mode: whitelist
`)
	fileCfg.Enabled = false
	got, err := loadTemplateFromFileStatic(fileCfg, dir, testLogger())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got[0].Enabled {
		t.Error("config.yaml disabled this template; the file must not re-enable it")
	}
}

// TestTemplateFile_UnsetEnabledDefaultsToOn keeps the common case working: most
// template files carry no enabled: key at all.
func TestTemplateFile_UnsetEnabledDefaultsToOn(t *testing.T) {
	fileCfg, dir := writeTemplateFile(t, `
rules:
  - id: r1
    name: R1
    type: evm_js
    mode: whitelist
`)
	got, err := loadTemplateFromFileStatic(fileCfg, dir, testLogger())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !got[0].Enabled {
		t.Error("a file with no enabled: key must stay enabled")
	}
	if got[0].Name != "Derived From Filename" {
		t.Errorf("with no name: in the file the derived name must survive, got %q", got[0].Name)
	}
}

// TestTemplateVarDefault_PointerIsNotRenderedAsAnAddress guards the widening of
// TemplateVarConfig.Default from *string to any. fmt.Sprint on a *string yields
// something like "0xc000060910" — which in this codebase reads exactly like an
// Ethereum address, and would be substituted into a rule as one.
func TestTemplateVarDefault_PointerIsNotRenderedAsAnAddress(t *testing.T) {
	s := "0xdeadbeef"
	for name, in := range map[string]any{
		"string":    "0xdeadbeef",
		"stringPtr": &s,
		"nilPtr":    (*string)(nil),
	} {
		got := renderVarDefault(in)
		if name == "nilPtr" {
			if got != "" {
				t.Errorf("%s: want empty, got %q", name, got)
			}
			continue
		}
		if got != "0xdeadbeef" {
			t.Errorf("%s: want 0xdeadbeef, got %q", name, got)
		}
	}
}
