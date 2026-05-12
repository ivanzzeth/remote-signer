//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidate_Help asserts that `remote-signer validate -h` exits 0 and
// prints a recognisable usage block. The validate subcommand is the only
// one that does its own flag parsing (DisableFlagParsing on the cobra
// wrapper) so a bug there shows up as a non-zero exit or empty output.
func TestValidate_Help(t *testing.T) {
	stdout, stderr, err := cli(t, "validate", "-h")
	if err != nil {
		t.Fatalf("validate -h: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	out := stdout + stderr
	if !strings.Contains(out, "Usage:") {
		t.Errorf("validate -h missing Usage block:\n%s", out)
	}
	if !strings.Contains(out, "remote-signer validate") {
		t.Errorf("validate -h Usage should mention the subcommand:\n%s", out)
	}
}

// TestValidate_Version pins `validate -version` against drift — it must
// agree with the binary's own version (and with the unified internal/version
// constant by extension).
func TestValidate_Version(t *testing.T) {
	stdout, _, err := cli(t, "validate", "-version")
	if err != nil {
		t.Fatalf("validate -version: %v", err)
	}
	versionOut, _, err := cli(t, "version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	vTag := strings.TrimPrefix(strings.TrimSpace(versionOut), "remote-signer ")
	if !strings.Contains(stdout, vTag) {
		t.Errorf("validate -version (%q) does not contain unified version %q", stdout, vTag)
	}
}

// TestValidate_RuleFile feeds the validator a declarative rule file and
// expects a zero exit code with a "validated successfully" summary. Uses an
// evm_address_list rule which doesn't require Foundry — the heavier
// Solidity/JS paths have their own coverage in internal/cli/validate.
func TestValidate_RuleFile(t *testing.T) {
	ruleFile := filepath.Join(t.TempDir(), "ok.yaml")
	const ruleYAML = `rules:
  - id: test-allow-list
    name: test allow list
    type: evm_address_list
    mode: whitelist
    enabled: true
    description: integration validate fixture
    config:
      addresses:
        - "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
`
	if err := os.WriteFile(ruleFile, []byte(ruleYAML), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := cli(t, "validate", ruleFile)
	if err != nil {
		t.Fatalf("validate %s: %v\nstdout: %s\nstderr: %s", ruleFile, err, stdout, stderr)
	}
	if !strings.Contains(stdout, "validated successfully") {
		t.Errorf("expected success summary, got: %s", stdout)
	}
}

// TestValidate_RuleFileBadConfig pins the error path: an evm_value_limit
// rule without max_value must fail validation and the process must exit
// non-zero. Guards against accidental "always green" regressions in the
// rule type schemas.
func TestValidate_RuleFileBadConfig(t *testing.T) {
	ruleFile := filepath.Join(t.TempDir(), "bad.yaml")
	const ruleYAML = `rules:
  - id: bad-value-limit
    name: bad rule
    type: evm_value_limit
    mode: whitelist
    enabled: true
    config: {}
`
	if err := os.WriteFile(ruleFile, []byte(ruleYAML), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := cli(t, "validate", ruleFile)
	if err == nil {
		t.Fatalf("expected non-zero exit for invalid rule, got success\nstdout: %s\nstderr: %s", stdout, stderr)
	}
}

// TestValidate_NoArgsRejects checks that running validate with neither
// -config nor a rule file errors out instead of silently exiting 0 (which
// would be a UX trap).
func TestValidate_NoArgsRejects(t *testing.T) {
	stdout, stderr, err := cli(t, "validate")
	if err == nil {
		t.Fatalf("expected non-zero exit when no args provided\nstdout: %s\nstderr: %s", stdout, stderr)
	}
}
